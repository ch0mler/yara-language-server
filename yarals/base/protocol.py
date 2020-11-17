''' Language Server Protocol Definitions

For more info: https://microsoft.github.io/language-server-protocol/specification
'''
from enum import Enum, IntEnum
import json
from typing import List

from . import errors as ce

EOL: list = ["\n", "\r\n", "\r"]


# Protocol Constants
class CompletionTriggerKind(IntEnum):
    # Completion was triggered by typing an identifier (24x7 code
	# complete), manual invocation (e.g Ctrl+Space) or via API.
    INVOKED = 1
    # Completion was triggered by a trigger character specified by
	# the `triggerCharacters` properties of the `CompletionRegistrationOptions`
    CHARACTER = 2
    # Completion was re-triggered as the current completion list is incomplete.
    INCOMPLETE = 3

class JsonRPCError(IntEnum):
    # Defined by JSON RPC
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    SERVER_ERROR_START = -32099
    SERVER_ERROR_END = -32000
    SERVER_NOT_INITIALIZED = -32002
    UNKNOWN_ERROR_CODE = -32001
    # Defined by the protocol
    REQUEST_CANCELLED = -32800
    CONTENT_MODIFIED = -32801

class CompletionItemKind(IntEnum):
    METHOD = 2
    CLASS = 7
    PROPERTY = 10
    ENUM = 13

class DiagnosticSeverity(IntEnum):
    ERROR = 1
    WARNING = 2
    INFO = 3
    HINT = 4

class MarkupKind(Enum):
    Markdown = "markdown"
    Plaintext = "plaintext"

class MessageType(IntEnum):
    ERROR = 1
    WARNING = 2
    INFO = 3
    LOG = 4

class TextSyncKind(IntEnum):
    NONE = 0
    FULL = 1
    INCREMENTAL = 2

class Position():
    def __init__(self, line: int, char: int):
        ''' Line position in a document (zero-based)

        Character offset on a line in a document (zero-based). Assuming that the line is
        represented as a string, the `character` value represents the gap between the
        `character` and `character + 1`.

        If the character value is greater than the line length it defaults back to the
        line length.
        '''
        # rely on Python's runtime type conversions to ensure valid values are used
        self.line = int(line)
        self.char = int(char)

    def __repr__(self):
        return "<Position(line={:d}, char={:d})>".format(self.line, self.char)

class Range():
    def __init__(self, start: Position, end: Position):
        ''' A range in a text document expressed as (zero-based) start and end positions

        A range is comparable to a selection in an editor. Therefore the end position is exclusive
        '''
        if not isinstance(start, Position):
            raise TypeError("Start position cannot be {}. Must be Position".format(type(start)))
        elif not isinstance(end, Position):
            raise TypeError("End position cannot be {}. Must be Position".format(type(end)))
        self.start = start
        self.end = end

    def __repr__(self):
        return "<Range(start={}, end={})>".format(self.start, self.end)

class CompletionItem():
    def __init__(self, label: str, kind=CompletionItemKind.CLASS):
        ''' Suggested items for the programmer '''
        self.label = str(label)
        self.kind = int(kind)

    def __repr__(self):
        return "<CompletionItem(label={}, kind={:d})>".format(self.label, self.kind)

class Diagnostic():
    def __init__(self, locrange: Range, severity: int, message: str, relatedInformation: list=[]):
        ''' Represents a diagnostic, such as a compiler error or warning

        Diagnostic objects are only valid in the scope of a resource.
        '''
        self.message = str(message)
        if not isinstance(locrange, Range):
            raise TypeError("Location range cannot be {}. Must be Range".format(type(locrange)))
        self.range = locrange
        if not isinstance(relatedInformation, list):
            raise TypeError("Location range cannot be {}. Must be a list of strings".format(type(relatedInformation)))
        self.relatedInformation = relatedInformation
        self.severity = int(severity)

    def __repr__(self):
        return "<Diagnostic(severity={:d}, message={})>".format(self.severity, self.message)

class Location():
    def __init__(self, locrange: Range, uri: str):
        ''' Represents a location inside a resource
        such as a line inside a text file
        '''
        if not isinstance(locrange, Range):
            raise TypeError("Location range cannot be {}. Must be Range".format(type(locrange)))
        self.range = locrange
        self.uri = str(uri)

    def __repr__(self):
        return "<Location(range={}, uri={})>".format(self.range, self.uri)

class MarkupContent():
    def __init__(self, kind: MarkupKind, content: str):
        ''' Represents a string value which content
        is interpreted base on its kind flag
        '''
        if not isinstance(kind, MarkupKind):
            raise TypeError("Markup kind cannot be {}. Must be MarkupKind".format(type(kind)))
        self.kind = kind
        self.value = str(content)

    def __repr__(self):
        return "<MarkupContent(value={}, kind={:d})>".format(self.value, self.kind)

class Hover():
    def __init__(self, contents: MarkupContent, locrange: Range=None):
        ''' Represents hover information at
        a given text document position
        '''
        if locrange:
            if not isinstance(locrange, Range):
                raise TypeError("Location range cannot be {}. Must be Range".format(type(locrange)))
            self.range = locrange
        if not isinstance(contents, MarkupContent):
            raise TypeError("Contents cannot be {}. Must be MarkupContent".format(type(contents)))
        self.contents = contents

class ResponseError():
    ''' The error object in case a request fails '''
    def __init__(self, code: int, message: str, data=None):
        '''
        :code: A number indicating the error type that occurred (Check JsonRPCError for valid codes).
        :message: A string providing a short description of the error.
        :data: A primitive or structured value that contains additional information about the error. Can be omitted.
        '''
        self.code = code
        self.message = message
        self.data = data

    @staticmethod
    def convert_exception(exception: Exception):
        ''' Convert an exception object into a ResponseError '''
        code = JsonRPCError.UNKNOWN_ERROR_CODE
        if isinstance(exception, AttributeError):
            code = JsonRPCError.INVALID_PARAMS
        elif isinstance(exception, NameError):
            code = JsonRPCError.METHOD_NOT_FOUND
        elif isinstance(exception, ce.ServerExit):
            code = JsonRPCError.SERVER_ERROR_END
        elif isinstance(exception, (RuntimeError, ce.CodeCompletionError, ce.DefinitionError, ce.DiagnosticError,
                                    ce.HighlightError,ce.HoverError, ce.NoYaraPython, ce.RenameError, ce.SymbolReferenceError)):
            code = JsonRPCError.INTERNAL_ERROR
        return ResponseError(code=code, message=exception.args[0])

    def __repr__(self):
        return "<ResponseError(code={:d}, message={})>".format(self.code, self.message)

class TextEdit():
    ''' A textual edit applicable to a text document. '''
    def __init__(self, locrange: Range, newText: str):
        if not isinstance(locrange, Range):
            raise TypeError("Location range cannot be {}. Must be Range".format(type(locrange)))
        self.range = locrange
        if not isinstance(newText, str):
            raise TypeError("NewText cannot be {}. Must be a plaintext string".format(type(newText)))
        self.newText = newText

    def __repr__(self):
        return "<TextEdit(newText={})>".format(self.newText)

class WorkspaceEdit():
    def __init__(self, file_uri, changes: List=None):
        '''Represents changes to many resources
        managed in the workspace

        This object can be treated like a list, so
        use the .append() and .remove() methods to
        modify the workspace changes
        '''
        if not isinstance(changes, list):
            raise TypeError("Changes cannot be {}. Must be a list of TextEdits".format(type(changes)))
        self.changes = changes if changes is not None else []
        self.uri = file_uri

    def append(self, change: TextEdit):
        ''' Add a TextEdit to the list of changes to make '''
        if not isinstance(change, TextEdit):
            raise TypeError("Change cannot be {}. Must be TextEdit".format(type(change)))
        return self.changes.append(change)

    def __repr__(self):
        return "<WorkspaceEdit(changes={:d})>".format(len(self.changes))

class JSONEncoder(json.JSONEncoder):
    ''' Custom JSON encoder '''
    def default(self, o):
        final_dict = {}
        if isinstance(o, CompletionItem):
            final_dict = {
                "label": o.label,
                "kind": o.kind
            }
        elif isinstance(o, Diagnostic):
            final_dict = {
                "message": o.message,
                "range": o.range,
                "relatedInformation": o.relatedInformation,
                "severity": o.severity
            }
        elif isinstance(o, Hover):
            if hasattr(o, "range"):
                final_dict = {
                    "range": o.range,
                    "contents": o.contents
                }
            else:
                final_dict = {
                    "contents": o.contents
                }
        elif isinstance(o, Location):
            final_dict = {
                "range": o.range,
                "uri": o.uri
            }
        elif isinstance(o, MarkupContent):
            final_dict = {
                "kind": o.kind,
                "value": o.value
            }
        elif isinstance(o, MarkupKind):
            return o.value
        elif isinstance(o, Position):
            final_dict = {
                "line": o.line,
                "character": o.char
            }
        elif isinstance(o, Range):
            final_dict = {
                "start": o.start,
                "end": o.end
            }
        elif isinstance(o, ResponseError):
            final_dict = {
                "code": o.code,
                "message": o.message,
                "data": o.data
            }
        elif isinstance(o, TextEdit):
            final_dict = {
                "range": o.range,
                "newText": o.newText
            }
        elif isinstance(o, WorkspaceEdit):
            final_dict = {
                "changes": {
                    o.uri: o.changes
                }
            }
        else:
            # if we get down here a TypeError will be thrown by the base class
            # because this encoder doesn't recognize the type
            super().default(o)
        return final_dict