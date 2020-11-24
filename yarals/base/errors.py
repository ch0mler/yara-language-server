''' Errors specific to the Language Server Protocol '''

class CodeCompletionError(Exception):
    ''' Custom error for code completion feature '''

class DefinitionError(Exception):
    ''' Custom error for definition feature '''

class DiagnosticError(Exception):
    ''' Custom error for diagnostics feature '''

class FormatError(Exception):
    ''' Custom error for formatting feature '''

class HighlightError(Exception):
    ''' Custom error for highlight feature '''

class HoverError(Exception):
    ''' Custom error for hover feature '''

class NoDependencyFound(Exception):
    ''' Custom error for when a dependency was not found '''

class RenameError(Exception):
    ''' Custom error for symbol rename feature '''

class ServerExit(Exception):
    ''' Custom error for server exit '''

class SymbolReferenceError(Exception):
    ''' Custom error for symbol reference feature '''
