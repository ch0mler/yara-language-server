''' Implements the language server for YARA '''
import asyncio
from copy import deepcopy
import importlib
from itertools import chain
import json
import logging
from pathlib import Path
import re
import sys

from .base import protocol as lsp
from .base import errors as ce
from .base.server import LanguageServer, RouteType
from . import helpers

try:
    # asyncio exceptions changed from 3.6 > 3.7 > 3.8
    # so try to keep this compatible regardless of Python version 3.6+
    # https://medium.com/@jflevesque/asyncio-exceptions-changes-from-python-3-6-to-3-7-to-3-8-cancellederror-timeouterror-f79945ead378
    from asyncio import CancelledError, TimeoutError as AsyncTimeoutError
except ImportError:
    from concurrent.futures import CancelledError, TimeoutError as AsyncTimeoutError


# extra YARA module data from this path
SCHEMA = Path(__file__).parent.joinpath("data", "modules.json").resolve()


class YaraLanguageServer(LanguageServer):
    ''' Implements the language server for YARA '''
    # variable symbols have a few possible first characters
    _varchar = ["$", "#", "@", "!"]
    hover_langs = [lsp.MarkupKind.Markdown, lsp.MarkupKind.Plaintext]
    modules = json.loads(SCHEMA.read_text())
    TASK_TIMEOUT = 2.0

    def __init__(self):
        ''' Handle the particulars of the server's YARA implementation '''
        super().__init__()
        self._logger = logging.getLogger("yara")
        self.workspace = False
        self.route("initialize", self.initialize, request_type=RouteType.FEATURE)
        self.route("shutdown", self.shutdown, request_type=RouteType.FEATURE)
        self.route("workspace/executeCommand", self.execute_command, request_type=RouteType.FEATURE)
        self.route("textDocument/completion", self.provide_code_completion, request_type=RouteType.FEATURE)
        self.route("textDocument/definition", self.provide_definition, request_type=RouteType.FEATURE)
        self.route("textDocument/formatting", self.provide_formatting, request_type=RouteType.FEATURE)
        self.route("textDocument/documentHighlight", self.provide_highlight, request_type=RouteType.FEATURE)
        self.route("textDocument/hover", self.provide_hover, request_type=RouteType.FEATURE)
        self.route("textDocument/references", self.provide_reference, request_type=RouteType.FEATURE)
        self.route("textDocument/rename", self.provide_rename, request_type=RouteType.FEATURE)
        self.route("textDocument/didChange", self.event_did_change, request_type=RouteType.EVENT)
        self.route("textDocument/didClose", self.event_did_close, request_type=RouteType.EVENT)
        self.route("textDocument/didSave", self.event_did_save, request_type=RouteType.EVENT)
        self.route("exit", self.event_exit, request_type=RouteType.EVENT)
        self.route("$/cancelRequest", self.event_cancel, request_type=RouteType.EVENT)

    def _is_module_installed(self, module_name) -> bool:
        ''' Check if the given module has been installed '''
        has_module = False
        try:
            if module_name in sys.modules:
                self._logger.debug("'%s' module already imported", module_name)
            else:
                self._logger.debug("Importing '%s' module", module_name)
                importlib.import_module(module_name)
            has_module = True
        except (ModuleNotFoundError, ImportError):
            has_module = False
        return has_module

    def _get_document(self, file_uri: str, dirty_files: dict) -> str:
        ''' Return the document text for a given file URI either from disk or memory '''
        if file_uri in dirty_files:
            return dirty_files[file_uri]
        file_path = helpers.parse_uri(file_uri, encoding=self.ENCODING)
        with open(file_path, "r") as rule_file:
            return rule_file.read()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        '''React and respond to client messages

        :reader: asyncio StreamReader. The connected client will write to this stream
        :writer: asyncio.StreamWriter. The connected client will read from this stream
        '''
        config = {}
        # file_uri => contents
        dirty_files = {}
        has_started = False
        self._logger.info("Client connected")
        self.num_clients += 1
        while True:
            try:
                # first check if this client is still sending messages
                if reader.at_eof():
                    self._logger.info("Client has closed")
                    self.num_clients -= 1
                    break
                elif self.num_clients <= 0:
                    # clear out memory
                    dirty_files.clear()
                    # remove connected clients
                    await self.remove_client(writer)
                # finally read our data
                message = await self.read_request(reader)
                # this matches some kind of JSON-RPC message
                if "jsonrpc" in message:
                    method = message.get("method", "")
                    self._logger.debug("Client sent a '%s' message", method)
                    # if an id is present, this is a JSON-RPC request
                    if "id" in message:
                        # TODO: Only send writer to functions that want it OR rewrite functions to not use writer
                        params = {
                            "has_started": has_started,
                            "dirty_files": dirty_files
                        }
                        await self.execute_method(method, message, writer, **params)
                    # if no id is present, this is a JSON-RPC notification
                    else:
                        if method in self.event_handlers:
                            # TODO: Only send writer to event handlers that want it OR rewrite handlers to not use writer
                            await self.event_handlers[method](has_started, message=message, config=config, dirty_files=dirty_files, writer=writer)
                        elif not has_started and method == "initialized":
                            # special type of event that just confirms response to 'initialize' request
                            # ... local variable has_started needs to be modified in this function's context,
                            # ... so it's easier to handle here instead of spinning it off to its own handler
                            self._logger.info("Client has been successfully initialized")
                            has_started = True
                            params = {"type": lsp.MessageType.INFO, "message": "Successfully connected"}
                            await self.send_notification("window/showMessageRequest", params, writer)
                        elif has_started and method == "workspace/didChangeConfiguration":
                            # special type of event that modifies the client's tracked configuration
                            # ... local variable config needs to be modified in this function's context,
                            # ... so it's easier to handle here instead of spinning it off to its own handler
                            config = message.get("params", {}).get("settings", {}).get("yara", {})
                            self._logger.debug("Changed workspace config to %s", json.dumps(config))
                        else:
                            # TODO: Figure out what else needs to be done when an unknown event is encountered
                            self._logger.warning("Encountered an unknown notification type '%s'. Ignoring.", method)
            except ce.NoDependencyFound as warn:
                self._logger.warning(warn)
                params = {
                    "type": lsp.MessageType.WARNING,
                    "message": str(warn)
                }
                await self.send_notification("window/showMessage", params, writer)
            except (ce.CodeCompletionError, ce.DefinitionError, ce.DiagnosticError, ce.HighlightError, \
                    ce.HoverError, ce.RenameError, ce.SymbolReferenceError) as err:
                self._logger.error(err)
                params = {
                    "type": lsp.MessageType.ERROR,
                    "message": str(err)
                }
                await self.send_notification("window/showMessage", params, writer)

    async def initialize(self, message: dict, has_started: bool, **kwargs) -> dict:
        '''Announce language support methods

        :client_options: Dictionary of registration options that the client supports
        :has_started: Boolean indicating whether this method has been called before
        :writer: StreamWriter to send messages back to the client
        '''
        # pylint: disable=W0613
        if not has_started:
            rootdir = helpers.parse_uri(message["params"]["rootUri"], encoding=self.ENCODING)
            if rootdir:
                self.workspace = Path(rootdir)
                self._logger.info("Client workspace folder: %s", self.workspace)
            else:
                self._logger.info("No client workspace specified")
                self.workspace = False

            client_options = message.get("params", {}).get("capabilities", {})
            doc_options = client_options.get("textDocument", {})
            ws_options = client_options.get("workspace", {})
            server_options = {}
            if doc_options.get("completion", {}).get("dynamicRegistration", False):
                server_options["completionProvider"] = {
                    # The server does not provide support to resolve additional information for a completion item
                    "resolveProvider": False,
                    "triggerCharacters": ["."]
                }
            if doc_options.get("definition", {}).get("dynamicRegistration", False):
                server_options["definitionProvider"] = True
            # if doc_options.get("documentHighlight", {}).get("dynamicRegistration", False):
            #     server_options["documentHighlightProvider"] = True
            if doc_options.get("hover", {}).get("dynamicRegistration", False):
                server_options["hoverProvider"] = True
                self.hover_langs = doc_options.get("hover", {}).get("contentFormat", self.hover_langs)
            if ws_options.get("executeCommand", {}).get("dynamicRegistration", False):
                server_options["executeCommandProvider"] = {
                    "commands": []
                }
                has_yara = self._is_module_installed("yara")
                if has_yara:
                    server_options["executeCommandProvider"]["commands"].append("yara.CompileRule")
                    server_options["executeCommandProvider"]["commands"].append("yara.CompileAllRules")
                else:
                    # TODO: Notify user and ask if they would like to install it
                    self._logger.warning("yara-python is not installed. Diagnostics and Compile commands are disabled")
            if doc_options.get("formatting", {}).get("dynamicRegistration", False):
                server_options["documentFormattingProvider"] = True
            if doc_options.get("references", {}).get("dynamicRegistration", False):
                server_options["referencesProvider"] = True
            if doc_options.get("rename", {}).get("dynamicRegistration", False):
                server_options["renameProvider"] = True
            if doc_options.get("synchronization", {}).get("dynamicRegistration", False):
                # Documents are synced by always sending the full content of the document
                server_options["textDocumentSync"] = lsp.TextSyncKind.FULL
            return {"capabilities": server_options}

    # @self.route("textDocument/didSave", request_type=RouteType.EVENT)
    async def event_did_save(self, has_started: bool, **kwargs):
        '''Overrides the base server's event_did_save()
            If file was previously tracked as 'dirty', remove tracking.
            If 'compile_on_save' is True, analyze saved document and publish diagnostics
        '''
        # first make sure the file is no longer tracked as dirty
        await super().event_did_save(has_started, **kwargs)
        message = kwargs.pop("message", {})
        params = message.get("params", {})
        file_uri = params.get("textDocument", {}).get("uri", "")
        # then do the YARA-specific functionality of publishing diagnostics if configuration is set
        if has_started and file_uri:
            config = kwargs.pop("config", {})
            writer = kwargs.pop("writer")
            if config.get("compile_on_save", False):
                file_path = helpers.parse_uri(file_uri)
                with open(file_path, "rb") as ifile:
                    document = ifile.read().decode(self.ENCODING)
                diagnostics = await self.provide_diagnostic(document)
            else:
                diagnostics = []
            params = {
                "uri": file_uri,
                "diagnostics": diagnostics
            }
            await self.send_notification("textDocument/publishDiagnostics", params, writer)

    async def execute_command(self, message: dict, has_started: bool, **kwargs) -> dict:
        '''Execute the specified command

        Returns any results from the command
        '''
        try:
            if has_started:
                response = {"result": None}
                cmd = message.get("params", {}).get("command", "")
                args = message.get("params", {}).get("arguments", [])
                dirty_files = kwargs.pop("dirty_files", {})
                if cmd == "yara.CompileRule":
                    writer = kwargs.pop("writer")
                    self._logger.info("Compiling rule per user's request")
                elif cmd == "yara.CompileAllRules":
                    writer = kwargs.pop("writer")
                    for result in await self._compile_all_rules(dirty_files, self.workspace):
                        await self.send_notification("textDocument/publishDiagnostics", result, writer)
                    # done with diagnostics - nothing needs to be returned
                else:
                    self._logger.warning("Unknown command: %s [%s]", cmd, ",".join(args))
        except CancelledError as err:
            raise err
        except (ce.DiagnosticError,) as err:
            # only add an error code if we see one
            response = {
                "result": None,
                "error": lsp.ResponseError.convert_exception(err)
            }
        return response

    async def execute_method(self, method: str, message: dict, writer: asyncio.StreamWriter, **params):
        '''Execute a method, such as a definiton or hover provider, as an asynchronous task
           and write back a response to the client or cancel if it is not completed within self.TASK_TIMEOUT seconds

        :method: Provider method to call, such as 'textDocument/definition'
        :message: Message from client to parse and execute
        :writer: Transport stream to write responses to
        :params: Additional parameters to be passed to the coroutine
        '''
        try:
            msg_id = message.get("id")
            # trying to generically handle JSON-RPC requests
            # by sending the full request message to each method
            if int(msg_id) >= 0 and method in self.request_handlers:
                coroutine = self.request_handlers[method]
                response = await asyncio.wait_for(coroutine(message=message, writer=writer, **params), self.TASK_TIMEOUT)
                # if the method is either of these, the writer has been closed
                # ... and the client is not reading messages anymore
                if method not in ("shutdown", "exit"):
                    await self.send_response(msg_id, response, writer)
            else:
                self._logger.error("Encountered an unknown request method '%s'. No associated method listed in routes", method)
                await self.send_response(msg_id, None, writer)
        except AsyncTimeoutError:
            self._logger.warning("Task for message %d timed out! %s", msg_id, message)
            # always need to send a response to requests, even if it's just null
            await self.send_response(msg_id, None, writer)

    # @self.route("yara.CompileAllRules", request_type=RouteType.COMMAND)
    async def _compile_all_rules(self, dirty_files: dict, workspace=None) -> list:
        # temp copy of filenames => contents
        # do a deep copy in order to not mess with dirty file contents
        diagnostics = []
        documents = deepcopy(dirty_files)
        if workspace:
            self._logger.info("Compiling all rules in %s per user's request", workspace)
            for file_path in chain(workspace.glob("**/*.yara"), workspace.glob("**/*.yar")):
                file_uri = helpers.create_file_uri(file_path)
                documents[file_uri] = self._get_document(file_uri, dirty_files)
        else:
            self._logger.warning("No workspace specified. CompileAllRules will only work on open docs")
            self._logger.info("Compiling all unsaved files per user's request")
            documents = dirty_files
        # documents should be a list of file contents
        for file_uri, document in documents.items():
            diagnostic = await self.provide_diagnostic(document)
            if diagnostic:
                diagnostics.append({
                    "uri": file_uri,
                    "diagnostics": diagnostic
                })
        return diagnostics

    async def provide_code_completion(self, message: dict, has_started: bool, **kwargs) -> list:
        '''Respond to the completionItem/resolve request

        Returns a (possibly empty) list of completion items
        '''
        try:
            params = message.get("params", {})
            file_uri = params.get("textDocument", {}).get("uri", None)
            if has_started and file_uri:
                results = []
                dirty_files = kwargs.pop("dirty_files", {})
                document = self._get_document(file_uri, dirty_files)
                trigger = params.get("context", {}).get("triggerCharacter", ".")
                # typically the trigger is at the end of a line, so subtract one to avoid an IndexError
                pos = lsp.Position(line=params["position"]["line"], char=params["position"]["character"]-1)
                symbol = helpers.resolve_symbol(document, pos)
                if not symbol:
                    return []
                # split up the symbols into component parts, leaving off the last trigger character
                symbols = symbol.split(trigger)
                schema = self.modules
                for depth, symbol in enumerate(symbols):
                    # if we're at the last symbol, return completion items
                    if depth == len(symbols) - 1:
                        possible_terms = list(filter(lambda k: str(k).startswith(symbol), schema))
                        for term in possible_terms:
                            completion_items = schema.get(term, {})
                            # if we're at the bottom of the modules list construct a dictionary
                            # so we can treat these the same as at any other point in the schema
                            # ... it's confusing and terrible. I'm sorry
                            if isinstance(completion_items, str):
                                completion_items = {term: completion_items}
                            # some module items are dictionaries with pre-set keys, such as pe.version_info
                            # we define these in the schema as a list of such keys
                            if isinstance(completion_items, list):
                                # ... and we create a snippetstring to show the user all available options
                                # desired output: pe.version_info["CompanyName"]
                                for label in completion_items:
                                    snippet = "{}[\"{}\"]".format(term, label)
                                    detail = trigger.join(symbols[:depth] + [snippet])
                                    results.append(lsp.CompletionItem(label, lsp.CompletionItemKind.INTERFACE, detail=detail, insertText=snippet))
                            elif isinstance(completion_items, dict):
                                for label, item_type in completion_items.items():
                                    # desired output: cuckoo.filesystem.
                                    detail = trigger.join(symbols + [label])
                                    if str(item_type).lower() == "enum":
                                        detail = trigger.join(symbols[:depth] + [label])
                                        results.append(lsp.CompletionItem(label, lsp.CompletionItemKind.ENUM, detail=detail))
                                    elif str(item_type).lower() == "property":
                                        detail = trigger.join(symbols[:depth] + [label])
                                        results.append(lsp.CompletionItem(label, lsp.CompletionItemKind.PROPERTY, detail=detail))
                                    elif str(item_type).lower() == "function":
                                        snippet = "{}()".format(label)
                                        detail = trigger.join(symbols[:depth] + [snippet])
                                        results.append(lsp.CompletionItem(label, lsp.CompletionItemKind.FUNCTION, insertText=snippet, detail=detail))
                                    else:
                                        results.append(lsp.CompletionItem(label, lsp.CompletionItemKind.CLASS, detail=detail))
                    else:
                        schema = schema[symbol]
                return results
        except CancelledError as err:
            raise err
        except Exception as err:
            self._logger.error(err)
            raise ce.CodeCompletionError("Could not offer completion items: {}".format(err))

    async def provide_definition(self, message: dict, has_started: bool, **kwargs) -> list:
        '''Respond to the textDocument/definition request

        Returns a (possibly empty) list of symbol Locations
        '''
        try:
            symbol = None
            params = message.get("params", {})
            file_uri = params.get("textDocument", {}).get("uri", None)
            if has_started and file_uri:
                results = []
                dirty_files = kwargs.pop("dirty_files", {})
                document = self._get_document(file_uri, dirty_files)
                # the try/except statement after this uses the 'symbol' variable in the exception block
                # so we need to separate the code before 'symbol' is instantiated from the code after
                # there's probably a better way to do this
                line = params.get("position", {}).get("line", None)
                char = params.get("position", {}).get("character", None)
                pos = lsp.Position(line=line, char=char)
                symbol = helpers.resolve_symbol(document, pos)
                if not symbol:
                    return []
            try:
                # check to see if the symbol is a variable or a rule name (currently the only valid symbols)
                if symbol[0] in self._varchar:
                    pattern = "\\${} =\\s".format("".join(symbol[1:]))
                    rule_range = helpers.get_rule_range(document, pos)
                    match_lines = document.split("\n")[rule_range.start.line:rule_range.end.line+1]
                    rel_offset = rule_range.start.line
                    # ignore the "$" variable identifier at the beginning of the match
                    char_start_offset = 1
                # else assume this is a rule symbol
                else:
                    pattern = "\\brule {}\\b".format(symbol)
                    match_lines = document.split("\n")
                    rel_offset = 0
                    # ignore the "rule " string at the beginning of the match
                    char_start_offset = 5

                for index, line in enumerate(match_lines):
                    for match in re.finditer(pattern, line):
                        if match:
                            offset = rel_offset + index
                            locrange = lsp.Range(
                                start=lsp.Position(line=offset, char=match.start() + char_start_offset),
                                end=lsp.Position(line=offset, char=match.end())
                            )
                            results.append(lsp.Location(locrange, file_uri))
                return results
            except re.error:
                self._logger.debug("Error building regex pattern: %s", pattern)
                return []
        except CancelledError as err:
            raise err
        except Exception as err:
            self._logger.error(err)
            if symbol:
                raise ce.DefinitionError("Could not offer definition for symbol '{}': {}".format(symbol, err))
            else:
                raise ce.DefinitionError("Could not find symbol for definition request")

    async def provide_diagnostic(self, document: str) -> list:
        ''' Respond to the textDocument/publishDiagnostics request

        :document: Contents of YARA rule file
        '''
        diagnostics = []
        if self._is_module_installed("yara"):
            # weird way to get around Python compiler that thinks yara is not installed
            yara = importlib.import_module('yara')
            try:
                yara.compile(source=document)
            except yara.SyntaxError as error:
                line_no, msg = helpers.parse_result(str(error))
                # VSCode is zero-indexed
                line_no -= 1
                first_char = helpers.get_first_non_whitespace_index(document.split("\n")[line_no])
                symbol_range = lsp.Range(
                    start=lsp.Position(line_no, first_char),
                    end=lsp.Position(line_no, self.MAX_LINE)
                )
                diagnostics.append(
                    lsp.Diagnostic(
                        locrange=symbol_range,
                        severity=lsp.DiagnosticSeverity.ERROR,
                        message=msg
                    )
                )
            except yara.WarningError as warning:
                line_no, msg = helpers.parse_result(str(warning))
                # VSCode is zero-indexed
                line_no -= 1
                first_char = helpers.get_first_non_whitespace_index(document.split("\n")[line_no])
                symbol_range = lsp.Range(
                    start=lsp.Position(line_no, first_char),
                    end=lsp.Position(line_no, self.MAX_LINE)
                )
                diagnostics.append(
                    lsp.Diagnostic(
                        locrange=symbol_range,
                        severity=lsp.DiagnosticSeverity.WARNING,
                        message=msg
                    )
                )
            except CancelledError as err:
                raise err
            except Exception as err:
                self._logger.error(err)
                raise ce.DiagnosticError("Could not compile rule: {}".format(err))
        else:
            raise ce.NoDependencyFound("yara-python is not installed. Diagnostics and Compile commands are disabled")
        return diagnostics

    async def provide_formatting(self, message: dict, has_started: bool, **kwargs) -> list:
        '''Respond to the textDocument/formatting request

        Returns a (possibly empty) list of text edits for the client to make
        '''
        edits = []
        if self._is_module_installed("plyara"):
            try:
                plyara = importlib.import_module('plyara')
                plyara_utils = importlib.import_module('plyara.utils', package='plyara')
                params = message.get("params", {})
                file_uri = params.get("textDocument", {}).get("uri", None)
                if has_started and file_uri:
                    dirty_files = kwargs.pop("dirty_files", {})
                    document = self._get_document(file_uri, dirty_files)
                    # parse options
                    options = params.get("options", {})
                    # extra check in case "options" key exists but is not a dictionary
                    if not isinstance(options, dict):
                        options = {}
                    tab_size = options.get("tabSize", 4)                            # Size of a tab in spaces
                    insert_spaces = options.get("insertSpaces", True)               # Prefer spaces over tabs
                    trim_whitespaces = options.get("trimTrailingWhitespace", True)  # Trim trailing whitespace on a line
                    insert_newline = options.get("insertFinalNewline", False)       # Insert a newline character at the end of the file if one does not exist
                    trim_newlines = options.get("trimFinalNewlines", True)          # Trim all newlines after the final newline at the end of the file
                    parser = plyara.Plyara(store_raw_sections=True)
                    contents = parser.parse_string(document)
                    # plyara parses out each rule individually from the document
                    for rule in contents:
                        self._logger.debug("Received formatting request for '%s'", rule["rule_name"])
                        if rule.get("imports"):
                            del rule["imports"]
                        # easy mode: rebuild rules with plyara too and post-process based on format options
                        formatted_text = plyara_utils.rebuild_yara_rule(rule)
                        # by default plyara appends a newline - remove it here and post-process later
                        formatted_text = formatted_text.rstrip("\n")
                        # post-process - insert spaces instead of tabs
                        # ... by default, plyara uses tabs
                        if insert_spaces:
                            formatted_text = formatted_text.expandtabs(tab_size)
                        # post-process - re-add whitespace if desired
                        if not trim_whitespaces:
                            self._logger.warning("The YARA language server does not currently support keeping whitespaces during formatting")
                            # extra_spaces = filter(lambda x: x.endswith(" "), document.splitlines())
                            # for line in extra_spaces:
                            #     self._logger.debug("Supposed to keep whitespaces for %r", line)
                        # post-process - port newlines from raw document into formatted rule
                        if not trim_newlines and document.endswith("\n"):
                            # in order to add blank newlines, another newline must be present on the last line
                            num_newlines = 1 + len(list(filter(lambda x: x == "", document.splitlines())))
                            self._logger.debug("Keeping %d newlines at end of rule", num_newlines)
                            formatted_text += "\n"*num_newlines
                        # post-process - add a newline if desired (only applies if we are not also preserving newlines)
                        elif insert_newline:
                            formatted_text += "\n"
                       # vscode uses 0-based indices for lines, while plyara uses 1-based indices
                       # ... so we need to subtract one from each line for the range
                        document_range = lsp.Range(
                            start=lsp.Position(line=rule["start_line"]-1, char=0),
                            end=lsp.Position(line=rule["stop_line"]-1, char=self.MAX_LINE)
                        )
                        edits.append(lsp.TextEdit(document_range, formatted_text))
            except CancelledError as err:
                raise err
            except plyara.exceptions.ParseTypeError as err:
                writer = kwargs.pop("writer")
                msg = "Could not format {} due to parsing error: {}".format(file_uri, err)
                self._logger.warning(msg)
                # notify user
                if writer is not None:
                    params = {"type": lsp.MessageType.ERROR, "message": msg}
                    await self.send_notification("window/showMessage", params, writer)
            except Exception as err:
                self._logger.exception(err)
                raise ce.FormatError("Could not format document: {}".format(message))
        else:
            raise ce.NoDependencyFound("plyara is not installed. Formatting is disabled")
        return edits

    async def provide_highlight(self, message: dict, has_started: bool, **kwargs) -> list:
        ''' Respond to the textDocument/documentHighlight request '''
        # pylint: disable=W0613
        try:
            params = message.get("params", {})
            file_uri = params.get("textDocument", {}).get("uri", None)
            if has_started and file_uri:
                results = []
                # TODO: Add document highlighting
                self._logger.warning("provide_highlight() is not implemented")
                return results
        except CancelledError as err:
            raise err
        except Exception as err:
            self._logger.error(err)
            raise ce.HighlightError("Could not offer code highlighting: {}".format(err))

    async def provide_hover(self, message: dict, has_started: bool, **kwargs) -> lsp.Hover:
        ''' Respond to the textDocument/hover request '''
        try:
            params = message.get("params", {})
            file_uri = params.get("textDocument", {}).get("uri", None)
            if has_started and file_uri:
                dirty_files = kwargs.pop("dirty_files", {})
                document = self._get_document(file_uri, dirty_files)
                definitions = await self.provide_definition(message, has_started, dirty_files=dirty_files)
                if len(definitions) > 0:
                    # only care about the first definition; although there shouldn't be more
                    definition = definitions[0]
                    line = document.split("\n")[definition.range.start.line]
                    try:
                        words = line.split(" = ")
                        if len(words) > 1:
                            contents = lsp.MarkupContent(lsp.MarkupKind.Plaintext, content=words[1])
                            return lsp.Hover(contents)
                    except IndexError as err:
                        self._logger.warning(words)
                        self._logger.warning("IndexError at line %d: '%s'", definition.range.start.line, line)
        except CancelledError as err:
            raise err
        except Exception as err:
            self._logger.error(err)
            raise ce.HoverError("Could not offer definition hover: {}".format(err))

    async def provide_reference(self, message: dict, has_started: bool, **kwargs) -> list:
        '''The references request is sent from the client to the server to resolve
        project-wide references for the symbol denoted by the given text document position

        Returns a (possibly empty) list of symbol Locations
        '''
        try:
            params = message.get("params", {})
            file_uri = params.get("textDocument", {}).get("uri", None)
            if has_started and file_uri:
                results = []
                dirty_files = kwargs.pop("dirty_files", {})
                document = self._get_document(file_uri, dirty_files)
                pos = lsp.Position(line=params["position"]["line"], char=params["position"]["character"])
                symbol = helpers.resolve_symbol(document, pos)
                if not symbol:
                    return []
                # gotta match the wildcard variables first to build the correct regex pattern
                # I don't think wildcards are technially supposed to work for rules, but a diagnostic
                # will appear to the user if YARA can't compile it, so I won't worry too much
                wildcard_found = ("*" in symbol)
                if wildcard_found:
                    # remove parentheses and replace the YARA wildcard with a Python re equivalent
                    symbol = symbol.replace("*", ".*?").strip("()")
                # check to see if the symbol is a variable or a rule name (currently the only valid symbols)
                if symbol[0] in self._varchar:
                    # any possible first character matching self._varchar must be treated as a reference
                    pattern = "[{}]{}\\b".format("".join(self._varchar), "".join(symbol[1:]))
                    rule_range = helpers.get_rule_range(document, pos)
                    rule_lines = document.split("\n")[rule_range.start.line:rule_range.end.line+1]
                    rel_offset = rule_range.start.line
                    char_start_offset = 1
                    if wildcard_found:
                        # only search strings section if this is a wildcard variable
                        # figure out the bounds of the strings section
                        strings_start = [idx for idx, line in enumerate(rule_lines) if "strings:" in line][0]
                        strings_end = [idx for idx, line in enumerate(rule_lines) if "condition:" in line][0]
                        rule_lines = rule_lines[strings_start:strings_end]
                        rel_offset += strings_start
                else:
                    rel_offset = 0
                    pattern = "{}\\b".format(symbol)
                    rule_lines = document.split("\n")
                    char_start_offset = 0

                for index, line in enumerate(rule_lines):
                    for match in re.finditer(pattern, line):
                        if match:
                            # index corresponds to line no. within each rule, not within file
                            offset = rel_offset + index
                            locrange = lsp.Range(
                                start=lsp.Position(line=offset, char=match.start() + char_start_offset),
                                end=lsp.Position(line=offset, char=match.end())
                            )
                            results.append(lsp.Location(locrange, file_uri))
                return results
        except CancelledError as err:
            raise err
        except re.error:
            self._logger.debug("Error building regex pattern: %s", pattern)
            return []
        except Exception as err:
            self._logger.error(err)
            raise ce.SymbolReferenceError("Could not find references for '{}': {}".format(symbol, err))

    async def provide_rename(self, message: dict, has_started: bool, **kwargs) -> list:
        ''' Respond to the textDocument/rename request '''
        try:
            params = message.get("params", {})
            file_uri = params.get("textDocument", {}).get("uri", None)
            if has_started and file_uri:
                dirty_files = kwargs.pop("dirty_files", {})
                document = self._get_document(file_uri, dirty_files)
                results = lsp.WorkspaceEdit(file_uri=file_uri, changes=[])
                pos = lsp.Position(line=params["position"]["line"], char=params["position"]["character"])
                old_text = helpers.resolve_symbol(document, pos)
                new_text = params.get("newName", None)
                if new_text is None:
                    self._logger.warning("No text to rename symbol to. Skipping")
                elif new_text == old_text:
                    self._logger.warning("New rename symbol is the same as the old. Skipping")
                elif old_text.endswith("*"):
                    self._logger.warning("Cannot rename wildcard symbols. Skipping")
                # let provide_reference() determine symbol or rule
                # and therefore what scope to look into
                refs = await self.provide_reference(message, has_started, dirty_files=dirty_files)
                for ref in refs:
                    new_range = lsp.Range(
                        lsp.Position(ref.range.start.line, ref.range.start.char),
                        lsp.Position(ref.range.end.line, ref.range.end.char)
                    )
                    results.append(lsp.TextEdit(new_range, new_text))
                if len(results.changes) <= 0:
                    self._logger.warning("No symbol references found to rename. Skipping")
                return results
        except CancelledError as err:
            raise err
        except Exception as err:
            self._logger.error(err)
            raise ce.RenameError("Could not rename symbol: {}".format(err))
