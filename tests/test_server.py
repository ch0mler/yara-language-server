''' Tests for yarals.yarals module '''
import json
import logging

import pytest
from yarals import helpers
from yarals.base import protocol

# don't care about pylint(protected-access) warnings since these are just tests
# pylint: disable=W0212

try:
    # asyncio exceptions changed from 3.6 > 3.7 > 3.8
    # so try to keep this compatible regardless of Python version 3.6+
    # https://medium.com/@jflevesque/asyncio-exceptions-changes-from-python-3-6-to-3-7-to-3-8-cancellederror-timeouterror-f79945ead378
    from asyncio.exceptions import CancelledError
except ImportError:
    from concurrent.futures import CancelledError


@pytest.mark.skip(reason="not implemented")
@pytest.mark.command
def test_cmd_compile_rule():
    ''' Ensure CompileRule compiles the currently-active YARA rule file using the "executeCommand" action '''
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "workspace/executeCommand",
        "params": {
            "command": "yara.CompileRule",
            "arguments": []
        }
    }
    assert request is False

@pytest.mark.asyncio
@pytest.mark.command
async def test_cmd_compile_all_rules(initialize_msg, initialized_msg, open_streams, test_rules, yara_server):
    ''' Ensure CompileAllRules compiles all YARA rule files in the given workspace using the "executeCommand" action '''
    expected = {"result": None}
    execute_cmd = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "workspace/executeCommand",
        "params": {
            "command": "yara.CompileAllRules",
            "arguments": []
        }
    }
    # change workspace from non-existant test workspace to our test_rules
    # to ensure YARA rules actually get properly identified
    init_ws = json.loads(initialize_msg)
    init_ws["params"]["rootPath"] = str(test_rules)
    init_ws["params"]["rootUri"] = helpers.create_file_uri(str(test_rules))
    init_ws["params"]["workspaceFolders"] = [{
        "uri": init_ws["params"]["rootUri"],
        "name": test_rules.name
    }]
    # initialize server with the workspace we want to work from
    reader, writer = open_streams
    await yara_server.write_data(json.dumps(init_ws), writer)
    await yara_server.read_request(reader)
    await yara_server.write_data(initialized_msg, writer)
    await yara_server.read_request(reader)
    # finally, execute command
    await yara_server.write_data(json.dumps(execute_cmd), writer)
    response = await yara_server.read_request(reader)
    # diagnostics are sent as notifications, and there may be an arbitrary number depending on test files
    while response.get("method") == "textDocument/publishDiagnostics":
        response = await yara_server.read_request(reader)
    # once all the diagnostics are finished, we should get our final response, which should be null
    assert response.get("result", {}) == expected

@pytest.mark.asyncio
@pytest.mark.command
async def test_cmd_compile_all_rules_no_workspace(initialize_msg, initialized_msg, open_streams, test_rules, yara_server):
    ''' Ensure CompileAllRules only compiles opened files when no workspace is specified '''
    notifications = []
    expected = {"result": None}
    expected_msg = "wrong usage of identifier \"cuckoo\""
    file_path = test_rules.joinpath("code_completion.yara").resolve()
    contents = open(file_path, "r").read().replace("ModuleCompletionExample", "ModifiedExample")
    did_change = {
        "jsonrpc":"2.0",
        "method":"textDocument/didChange",
        "params": {
            "textDocument":{
                "uri": helpers.create_file_uri(file_path),
                "version":42
            },
            "contentChanges":[{"text": contents}]
        }
    }
    execute_cmd = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "workspace/executeCommand",
        "params": {
            "command": "yara.CompileAllRules",
            "arguments": []
        }
    }
    # keep non-existant test workspace
    # to ensure YARA rules actually get properly identified
    init_ws = json.loads(initialize_msg)
    init_ws["params"]["rootPath"] = None
    init_ws["params"]["rootUri"] = None
    init_ws["params"]["workspaceFolders"] = []
    # initialize server with the workspace we want to work from
    reader, writer = open_streams
    await yara_server.write_data(json.dumps(init_ws), writer)
    await yara_server.read_request(reader)
    await yara_server.write_data(initialized_msg, writer)
    await yara_server.read_request(reader)
    # notify the server of a file change
    await yara_server.write_data(json.dumps(did_change), writer)
    # finally, execute command
    await yara_server.write_data(json.dumps(execute_cmd), writer)
    response = await yara_server.read_request(reader)
    while response.get("method") == "textDocument/publishDiagnostics":
        notifications.append(response["params"])
        response = await yara_server.read_request(reader)
    assert response["result"] == expected
    assert len(notifications) == 1
    assert notifications[0]["uri"] == helpers.create_file_uri(file_path)
    assert len(notifications[0]["diagnostics"]) == 1
    assert notifications[0]["diagnostics"][0]["message"] == expected_msg

@pytest.mark.asyncio
@pytest.mark.server
async def test__compile_all_rules_no_dirty_files(test_rules, yara_server):
    ''' Ensure the _compile_all_rules function returns the appropriate number of diagnostics when no workspace files are dirty '''
    expected = [
        {
            "uri": helpers.create_file_uri(str(test_rules.joinpath("peek_rules.yara").resolve())),
            "diagnostics": [
                protocol.Diagnostic(
                    protocol.Range(protocol.Position(line=17, char=8), protocol.Position(line=17, char=yara_server.MAX_LINE)),
                    severity=protocol.DiagnosticSeverity.ERROR,
                    message="syntax error, unexpected <true>, expecting text string"
                )
            ]
        },
        {
            "uri": helpers.create_file_uri(str(test_rules.joinpath("code_completion.yara").resolve())),
            "diagnostics": [
                protocol.Diagnostic(
                    protocol.Range(protocol.Position(line=10, char=0), protocol.Position(line=10, char=yara_server.MAX_LINE)),
                    severity=protocol.DiagnosticSeverity.ERROR,
                    message="wrong usage of identifier \"cuckoo\""
                )
            ]
        },
        {
            "uri": helpers.create_file_uri(str(test_rules.joinpath("simple_mistake.yar").resolve())),
            "diagnostics": [
                protocol.Diagnostic(
                    protocol.Range(protocol.Position(line=4, char=0), protocol.Position(line=4, char=yara_server.MAX_LINE)),
                    severity=protocol.DiagnosticSeverity.ERROR,
                    message="undefined string \"$true\""
                )
            ]
        }
    ]
    results = await yara_server._compile_all_rules({}, workspace=test_rules)
    assert len(results) == len(expected)
    assert all(result in expected for result in results)

@pytest.mark.asyncio
@pytest.mark.server
async def test__compile_all_rules_with_dirty_files(test_rules, yara_server):
    ''' Ensure the _compile_all_rules function returns the appropriate number of diagnostics when workspace files have unsaved content '''
    expected = [
        {
            "uri": helpers.create_file_uri(str(test_rules.joinpath("peek_rules.yara").resolve())),
            "diagnostics": [
                protocol.Diagnostic(
                    protocol.Range(protocol.Position(line=17, char=8), protocol.Position(line=17, char=yara_server.MAX_LINE)),
                    severity=protocol.DiagnosticSeverity.ERROR,
                    message="syntax error, unexpected <true>, expecting text string"
                )
            ]
        },
        {
            "uri": helpers.create_file_uri(str(test_rules.joinpath("code_completion.yara").resolve())),
            "diagnostics": [
                protocol.Diagnostic(
                    protocol.Range(protocol.Position(line=10, char=0), protocol.Position(line=10, char=yara_server.MAX_LINE)),
                    severity=protocol.DiagnosticSeverity.ERROR,
                    message="wrong usage of identifier \"cuckoo\""
                )
            ]
        },
        {
            "uri": helpers.create_file_uri(str(test_rules.joinpath("simple_mistake.yar").resolve())),
            "diagnostics": [
                protocol.Diagnostic(
                    protocol.Range(protocol.Position(line=4, char=0), protocol.Position(line=4, char=yara_server.MAX_LINE)),
                    severity=protocol.DiagnosticSeverity.ERROR,
                    message="undefined string \"$true\""
                )
            ]
        }
    ]
    # files won't actually be changed, so the diagnostics should reflect the "no_dirty_files" test
    dirty_files = {}
    for filename in ["peek_rules.yara", "simple_mistake.yar", "code_completion.yara"]:
        dirty_path = str(test_rules.joinpath(filename).resolve())
        dirty_files[helpers.create_file_uri(dirty_path)] = yara_server._get_document(dirty_path, dirty_files={})
    results = await yara_server._compile_all_rules(dirty_files, workspace=test_rules)
    assert len(results) == len(expected)
    assert all(result in expected for result in results)

@pytest.mark.asyncio
@pytest.mark.server
async def test_code_completion_regular(test_rules, yara_server):
    ''' Ensure code completion works with functions defined in modules schema '''
    actual = []
    code_completion = str(test_rules.joinpath("code_completion.yara").resolve())
    expected = ["network", "registry", "filesystem", "sync"]
    file_uri = helpers.create_file_uri(code_completion)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 9, "character": 15}
        }
    }
    result = await yara_server.provide_code_completion(message, True)
    assert len(result) == 4
    for completion in result:
        assert isinstance(completion, protocol.CompletionItem) is True
        actual.append(completion.label)
    assert actual == expected

@pytest.mark.asyncio
@pytest.mark.server
async def test_code_completion_overflow(test_rules, yara_server):
    ''' Ensure code completion doesn't return items or error out when a position doesn't exist in the file '''
    code_completion = str(test_rules.joinpath("code_completion.yara").resolve())
    file_uri = helpers.create_file_uri(code_completion)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 9, "character": 25}
        }
    }
    result = await yara_server.provide_code_completion(message, True)
    assert result == []

@pytest.mark.asyncio
@pytest.mark.server
async def test_code_completion_unexpected(test_rules, yara_server):
    ''' Ensure code completion doesn't return items or error out when a symbol does not have any items to be completed '''
    code_completion = str(test_rules.joinpath("code_completion.yara").resolve())
    file_uri = helpers.create_file_uri(code_completion)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 8, "character": 25}
        }
    }
    result = await yara_server.provide_code_completion(message, True)
    assert result == []

@pytest.mark.asyncio
@pytest.mark.server
async def test_definitions_rules(test_rules, yara_server):
    ''' Ensure definition is provided for a rule name '''
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 42, "character": 12}
        }
    }
    result = await yara_server.provide_definition(message, True)
    assert len(result) == 1
    assert isinstance(result[0], protocol.Location) is True
    assert result[0].uri == file_uri
    assert result[0].range.start.line == 5
    assert result[0].range.start.char == 5
    assert result[0].range.end.line == 5
    assert result[0].range.end.char == 18

@pytest.mark.asyncio
@pytest.mark.server
async def test_definitions_private_rules(test_rules, yara_server):
    ''' Ensure definition is provided for a private rule name '''
    private_goto_rules = str(test_rules.joinpath("private_rule_goto.yara").resolve())
    file_uri = helpers.create_file_uri(private_goto_rules)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 9, "character": 14}
        }
    }
    result = await yara_server.provide_definition(message, True)
    assert len(result) == 1
    assert isinstance(result[0], protocol.Location) is True
    assert result[0].uri == file_uri
    assert result[0].range.start.line == 0
    assert result[0].range.start.char == 13
    assert result[0].range.end.line == 0
    assert result[0].range.end.char == 28

@pytest.mark.asyncio
@pytest.mark.server
async def test_definitions_variables_count(test_rules, yara_server):
    ''' Ensure definition is provided for a variable with count modifier (#) '''
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 28, "character": 12}
        }
    }
    result = await yara_server.provide_definition(message, True)
    assert len(result) == 1
    assert isinstance(result[0], protocol.Location) is True
    assert result[0].uri == file_uri
    assert result[0].range.start.line == 21
    assert result[0].range.start.char == 9
    assert result[0].range.end.line == 21
    assert result[0].range.end.char == 19

@pytest.mark.asyncio
@pytest.mark.server
async def test_definitions_variables_length(test_rules, yara_server):
    ''' Ensure definition is provided for a variable with length modifier (!) '''
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 42, "character": 32}
        }
    }
    result = await yara_server.provide_definition(message, True)
    assert len(result) == 1
    assert isinstance(result[0], protocol.Location) is True
    assert result[0].uri == file_uri
    assert result[0].range.start.line == 40
    assert result[0].range.start.char == 9
    assert result[0].range.end.line == 40
    assert result[0].range.end.char == 22

@pytest.mark.asyncio
@pytest.mark.server
async def test_definitions_variables_location(test_rules, yara_server):
    ''' Ensure definition is provided for a variable with location modifier (@) '''
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 29, "character": 12}
        }
    }
    result = await yara_server.provide_definition(message, True)
    assert len(result) == 1
    assert isinstance(result[0], protocol.Location) is True
    assert result[0].uri == file_uri
    assert result[0].range.start.line == 21
    assert result[0].range.start.char == 9
    assert result[0].range.end.line == 21
    assert result[0].range.end.char == 19

@pytest.mark.asyncio
@pytest.mark.server
async def test_definitions_variables_regular(test_rules, yara_server):
    ''' Ensure definition is provided for a normal variable '''
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 24, "character": 12}
        }
    }
    result = await yara_server.provide_definition(message, True)
    assert len(result) == 1
    assert isinstance(result[0], protocol.Location) is True
    assert result[0].uri == file_uri
    assert result[0].range.start.line == 19
    assert result[0].range.start.char == 9
    assert result[0].range.end.line == 19
    assert result[0].range.end.char == 22

@pytest.mark.asyncio
@pytest.mark.server
async def test_no_definitions(test_rules, yara_server):
    ''' Ensure no definition is provided for symbols that are not variables or rules '''
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 27, "character": 12},
            "context": {"includeDeclaration": True}
        }
    }
    result = await yara_server.provide_definition(message, True)
    assert result == []

@pytest.mark.asyncio
@pytest.mark.server
async def test_diagnostics(yara_server):
    ''' Ensure a diagnostic error message is provided when appropriate '''
    document = "rule OneDiagnostic { condition: $true }"
    result = await yara_server.provide_diagnostic(document)
    assert len(result) == 1
    diagnostic = result[0]
    assert isinstance(diagnostic, protocol.Diagnostic) is True
    assert diagnostic.severity == 1
    assert diagnostic.message == "undefined string \"$true\""
    assert diagnostic.range.start.line == 0
    assert diagnostic.range.end.line == 0

@pytest.mark.asyncio
@pytest.mark.server
async def test_no_diagnostics(yara_server):
    ''' Ensure no diagnostics are provided when rules are successfully compiled '''
    document = "rule NoDiagnostics { condition: true }"
    result = await yara_server.provide_diagnostic(document)
    assert result == []

@pytest.mark.asyncio
@pytest.mark.server
async def test_dirty_files(test_rules, yara_server):
    ''' Ensure server prefers versions of dirty files over those backed by file path '''
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    unsaved_changes = "rule ResolveSymbol {\n strings:\n  $a = \"test\"\n condition:\n  #a > 3\n}\n"
    dirty_files = {
        file_uri: unsaved_changes
    }
    document = yara_server._get_document(file_uri, dirty_files)
    assert document == unsaved_changes

@pytest.mark.asyncio
@pytest.mark.server
async def test_exceptions_handled(initialize_msg, initialized_msg, open_streams, test_rules, yara_server):
    ''' Ensure server notifies user when errors are encountered '''
    expected = {
        "jsonrpc": "2.0", "method": "window/showMessage",
        "params": {"type": 1, "message": "Could not find symbol for definition request"}
    }
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    error_request = json.dumps({
        "jsonrpc": "2.0", "id": 1,    # the initialize message takes id 0
        "method": "textDocument/definition",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {}
        }
    })
    reader, writer = open_streams
    await yara_server.write_data(initialize_msg, writer)
    await yara_server.read_request(reader)
    await yara_server.write_data(initialized_msg, writer)
    await yara_server.read_request(reader)
    await yara_server.write_data(error_request, writer)
    response = await yara_server.read_request(reader)
    assert response == expected
    writer.close()
    await writer.wait_closed()

@pytest.mark.asyncio
@pytest.mark.server
async def test_exit(caplog, initialize_msg, initialized_msg, open_streams, shutdown_msg, yara_server):
    ''' Ensure the server shuts down when given the proper shutdown/exit sequence '''
    exit_msg = json.dumps({"jsonrpc":"2.0","method":"exit","params":None})
    reader, writer = open_streams
    with pytest.raises(CancelledError):
        with caplog.at_level(logging.DEBUG, "yara"):
            await yara_server.write_data(initialize_msg, writer)
            await yara_server.read_request(reader)
            await yara_server.write_data(initialized_msg, writer)
            await yara_server.read_request(reader)
            await yara_server.write_data(shutdown_msg, writer)
            await yara_server.read_request(reader)
            await yara_server.write_data(exit_msg, writer)
            await yara_server.read_request(reader)
            assert ("yara", logging.INFO, "Disconnected client") in caplog.record_tuples
            assert ("yara", logging.INFO, "Server exiting process per client request") in caplog.record_tuples
    writer.close()
    await writer.wait_closed()

@pytest.mark.asyncio
@pytest.mark.server
async def test_format_no_results(test_rules, yara_server):
    ''' Ensure a text edit is provided on format '''
    apt_alienspy_rat = str(test_rules.joinpath("apt_alienspy_rat.yara").resolve())
    file_uri = helpers.create_file_uri(apt_alienspy_rat)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 29, "character": 12}
        }
    }
    result = await yara_server.provide_formatting(message, True)
    assert len(result) == 0

@pytest.mark.asyncio
@pytest.mark.server
async def test_format(test_rules, yara_server):
    ''' Ensure a text edit is provided on format '''
    apt_alienspy_rat = str(test_rules.joinpath("apt_alienspy_rat.yara").resolve())
    file_uri = helpers.create_file_uri(apt_alienspy_rat)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 29, "character": 12}
        }
    }
    result = await yara_server.provide_formatting(message, True)
    assert len(result) == 1
    edit = result[0]
    assert isinstance(edit, protocol.TextEdit) is True
    assert False

@pytest.mark.skip(reason="not implemented")
@pytest.mark.server
def test_highlights():
    ''' TBD '''
    assert False is True

@pytest.mark.asyncio
@pytest.mark.server
async def test_hover(test_rules, yara_server):
    ''' Ensure a variable's value is provided on hover '''
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 29, "character": 12}
        }
    }
    result = await yara_server.provide_hover(message, True)
    assert isinstance(result, protocol.Hover) is True
    assert result.contents.kind == protocol.MarkupKind.Plaintext
    assert result.contents.value == "\"double string\" wide nocase fullword"

@pytest.mark.asyncio
@pytest.mark.server
async def test_hover_dirty_file(initialize_msg, initialized_msg, open_streams, test_rules, yara_server):
    ''' Ensure a variable's value is provided on hover for a dirty file '''
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    unsaved_changes = "rule ResolveSymbol {\n strings:\n  $a = \"test\"\n condition:\n  #a > 3\n}\n"
    did_change_msg = json.dumps({
        "jsonrpc": "2.0", "method": "textDocument/didChange",
        "params": {
            "textDocument": {"uri": file_uri},
            "contentChanges": [{"text": unsaved_changes}]
        }
    })
    hover_msg = json.dumps({
        "jsonrpc": "2.0", "method": "textDocument/hover", "id": 2,
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 4, "character": 3}
        }
    })
    reader, writer = open_streams
    await yara_server.write_data(initialize_msg, writer)
    await yara_server.read_request(reader)
    await yara_server.write_data(initialized_msg, writer)
    await yara_server.read_request(reader)
    await yara_server.write_data(did_change_msg, writer)
    await yara_server.write_data(hover_msg, writer)
    response = await yara_server.read_request(reader)
    # TODO: build JSON decoder to convert JSON objects to protocol objects
    assert response["result"]["contents"]["kind"] == "plaintext"
    assert response["result"]["contents"]["value"] == "\"test\""
    writer.close()
    await writer.wait_closed()

@pytest.mark.asyncio
@pytest.mark.server
async def test_no_hover(test_rules, yara_server):
    ''' Ensure non-variables do not return hovers '''
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 25, "character": 12}
        }
    }
    result = await yara_server.provide_hover(message, True)
    assert result is None

@pytest.mark.asyncio
@pytest.mark.server
async def test_initialize(initialize_msg, initialized_msg, open_streams, yara_server):
    ''' Ensure server responds with appropriate initialization handshake '''
    expected_initialize = {
        "jsonrpc": "2.0", "id": 0, "result":{
            "capabilities": {
                "completionProvider":{"resolveProvider": False, "triggerCharacters": ["."]},
                "definitionProvider": True, "hoverProvider": True, "renameProvider": True,
                "referencesProvider": True, "textDocumentSync": 1,
                "executeCommandProvider": {"commands": ["yara.CompileRule", "yara.CompileAllRules"]}
            }
        }
    }
    expected_initialized = {
        "jsonrpc": "2.0", "method": "window/showMessageRequest",
        "params": {"type": 3, "message": "Successfully connected"}
    }
    reader, writer = open_streams
    # write_data and read_request are just helpers for formatting JSON-RPC messages appropriately
    # despite using a second YaraLanguageServer, these will route through the one in local_server
    # because we pass the related reader & writer objects to these functions
    await yara_server.write_data(initialize_msg, writer)
    response = await yara_server.read_request(reader)
    assert response == expected_initialize
    await yara_server.write_data(initialized_msg, writer)
    response = await yara_server.read_request(reader)
    assert response == expected_initialized
    writer.close()
    await writer.wait_closed()

@pytest.mark.asyncio
@pytest.mark.server
async def test_no_references(test_rules, yara_server):
    ''' Ensure server does not return references if none are found '''
    alienspy = str(test_rules.joinpath("apt_alienspy_rat.yar").resolve())
    file_uri = helpers.create_file_uri(alienspy)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 47, "character": 99},
        }
    }
    result = await yara_server.provide_reference(message, True)
    assert result == []

@pytest.mark.asyncio
@pytest.mark.server
async def test_references_rules(test_rules, yara_server):
    ''' Ensure references to rules are returned at the start of the rule name '''
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 42, "character": 12},
            "context": {"includeDeclaration": True}
        }
    }
    result = await yara_server.provide_reference(message, True)
    assert len(result) == 2
    for index, location in enumerate(result):
        assert isinstance(location, protocol.Location) is True
        assert location.uri == file_uri
        if index == 0:
            assert location.range.start.line == 5
            assert location.range.start.char == 5
            assert location.range.end.line == 5
            assert location.range.end.char == 18
        elif index == 1:
            assert location.range.start.line == 42
            assert location.range.start.char == 8
            assert location.range.end.line == 42
            assert location.range.end.char == 21

@pytest.mark.asyncio
@pytest.mark.server
async def test_references_variable(test_rules, yara_server):
    ''' Ensure references to variables are returned at the start of the variable name '''
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 28, "character": 12},
            "context": {"includeDeclaration": True}
        }
    }
    result = await yara_server.provide_reference(message, True)
    assert len(result) == 3
    for index, location in enumerate(result):
        assert isinstance(location, protocol.Location) is True
        assert location.uri == file_uri
        if index == 0:
            assert location.range.start.line == 21
            assert location.range.start.char == 9
            assert location.range.end.line == 21
            assert location.range.end.char == 16
        elif index == 1:
            assert location.range.start.line == 28
            assert location.range.start.char == 9
            assert location.range.end.line == 28
            assert location.range.end.char == 16
        elif index == 2:
            assert location.range.start.line == 29
            assert location.range.start.char == 9
            assert location.range.end.line == 29
            assert location.range.end.char == 16

@pytest.mark.asyncio
@pytest.mark.server
async def test_references_wildcard(test_rules, yara_server):
    ''' Ensure wildcard variables return references to all possible variables within rule they are found '''
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 30, "character": 11},
            "context": {"includeDeclaration": True}
        }
    }
    result = await yara_server.provide_reference(message, True)
    assert len(result) == 2
    for index, location in enumerate(result):
        assert isinstance(location, protocol.Location) is True
        assert location.uri == file_uri
        if index == 0:
            assert location.range.start.line == 19
            assert location.range.start.char == 9
            assert location.range.end.line == 19
            assert location.range.end.char == 19
        elif index == 1:
            assert location.range.start.line == 20
            assert location.range.start.char == 9
            assert location.range.end.line == 20
            assert location.range.end.char == 20

@pytest.mark.asyncio
@pytest.mark.server
async def test_renames(test_rules, yara_server):
    ''' Ensure variables can be renamed '''
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    # @dstring[1]: Line 30, Col 12
    new_text = "test_rename"
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 29, "character": 12},
            "newName": new_text
        }
    }
    result = await yara_server.provide_rename(message, True)
    assert isinstance(result, protocol.WorkspaceEdit) is True
    assert len(result.changes) == 3
    acceptable_lines = [21, 28, 29]
    for edit in result.changes:
        assert isinstance(edit, protocol.TextEdit) is True
        assert edit.newText == new_text
        assert edit.range.start.line in acceptable_lines

@pytest.mark.asyncio
@pytest.mark.server
async def test_shutdown(caplog, initialize_msg, initialized_msg, open_streams, shutdown_msg, yara_server):
    ''' Ensure server logs appropriate response to shutdown '''
    reader, writer = open_streams
    with caplog.at_level(logging.DEBUG, "yara"):
        await yara_server.write_data(initialize_msg, writer)
        await yara_server.read_request(reader)
        await yara_server.write_data(initialized_msg, writer)
        await yara_server.read_request(reader)
        await yara_server.write_data(shutdown_msg, writer)
        await yara_server.read_request(reader)
        assert ("yara", logging.INFO, "Client requested shutdown") in caplog.record_tuples
    writer.close()
    await writer.wait_closed()
