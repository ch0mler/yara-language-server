''' Tests for yarals.protocol module '''
import json

import pytest
from yarals import protocol
from yarals import custom_err as ce


@pytest.mark.protocol
def test_diagnostic():
    ''' Ensure Diagnostic is properly encoded to JSON dictionaries '''
    pos_dict = {"line": 10, "character": 15}
    pos = protocol.Position(line=pos_dict["line"], char=pos_dict["character"])
    rg_dict = {"start": pos_dict, "end": pos_dict}
    rg_obj = protocol.Range(start=pos, end=pos)
    diag_dict = {
        "message": "Test Diagnostic",
        "range": rg_dict,
        "relatedInformation": [],
        "severity": 1
    }
    diag = protocol.Diagnostic(
        locrange=rg_obj,
        message=diag_dict["message"],
        severity=diag_dict["severity"]
    )
    assert json.dumps(diag, cls=protocol.JSONEncoder) == json.dumps(diag_dict)

@pytest.mark.protocol
def test_completionitem():
    ''' Ensure CompletionItem is properly encoded to JSON dictionaries '''
    comp_dict = {"label": "test", "kind": protocol.CompletionItemKind.CLASS}
    comp = protocol.CompletionItem(label=comp_dict["label"], kind=comp_dict["kind"])
    assert json.dumps(comp, cls=protocol.JSONEncoder) == json.dumps(comp_dict)

@pytest.mark.protocol
def test_location():
    ''' Ensure Location is properly encoded to JSON dictionaries '''
    pos_dict = {"line": 10, "character": 15}
    pos = protocol.Position(line=pos_dict["line"], char=pos_dict["character"])
    rg_dict = {"start": pos_dict, "end": pos_dict}
    rg_obj = protocol.Range(start=pos, end=pos)
    loc_dict = {"range": rg_dict, "uri": "fake:///one/two/three/four.path"}
    loc = protocol.Location(
        locrange=rg_obj,
        uri=loc_dict["uri"]
    )
    assert json.dumps(loc, cls=protocol.JSONEncoder) == json.dumps(loc_dict)

@pytest.mark.protocol
def test_position():
    ''' Ensure Position is properly encoded to JSON dictionaries '''
    pos_dict = {"line": 10, "character": 15}
    pos = protocol.Position(line=pos_dict["line"], char=pos_dict["character"])
    assert json.dumps(pos, cls=protocol.JSONEncoder) == json.dumps(pos_dict)

@pytest.mark.protocol
def test_range():
    ''' Ensure Range is properly encoded to JSON dictionaries '''
    pos_dict = {"line": 10, "character": 15}
    pos = protocol.Position(line=pos_dict["line"], char=pos_dict["character"])
    rg_dict = {"start": pos_dict, "end": pos_dict}
    rg_obj = protocol.Range(
        start=pos,
        end=pos
    )
    assert json.dumps(rg_obj, cls=protocol.JSONEncoder) == json.dumps(rg_dict)

@pytest.mark.protocol
def test_responseerror():
    ''' Ensure ResponseError is properly encoded to JSON dictionaries '''
    err_dict = {"code": protocol.JsonRPCError.UNKNOWN_ERROR_CODE, "message": "Test exception", "data": None}
    err = protocol.ResponseError(code=err_dict["code"], message=err_dict["message"])
    assert json.dumps(err, cls=protocol.JSONEncoder) == json.dumps(err_dict)

@pytest.mark.protocol
def test_responseerror_convert_exception():
    ''' Ensure ResponseError.convert_exception converts error codes correctly '''
    msg = "Test exception"
    # renaming just to make these easier to type
    res_err = protocol.ResponseError
    errors = protocol.JsonRPCError
    encoder = protocol.JSONEncoder
    assert json.dumps(res_err.convert_exception(Exception(msg)), cls=encoder) == json.dumps(res_err(errors.UNKNOWN_ERROR_CODE, msg), cls=encoder)
    assert json.dumps(res_err.convert_exception((AttributeError(msg))), cls=encoder) == json.dumps(res_err(errors.INVALID_PARAMS, msg), cls=encoder)
    assert json.dumps(res_err.convert_exception((NameError(msg))), cls=encoder) == json.dumps(res_err(errors.METHOD_NOT_FOUND, msg), cls=encoder)
    assert json.dumps(res_err.convert_exception((ce.ServerExit(msg))), cls=encoder) == json.dumps(res_err(errors.SERVER_ERROR_END, msg), cls=encoder)
    assert json.dumps(res_err.convert_exception(RuntimeError(msg)), cls=encoder) == json.dumps(res_err(errors.INTERNAL_ERROR, msg), cls=encoder)
    assert json.dumps(res_err.convert_exception((ce.CodeCompletionError(msg))), cls=encoder) == json.dumps(res_err(errors.INTERNAL_ERROR, msg), cls=encoder)
    assert json.dumps(res_err.convert_exception((ce.DefinitionError(msg))), cls=encoder) == json.dumps(res_err(errors.INTERNAL_ERROR, msg), cls=encoder)
    assert json.dumps(res_err.convert_exception((ce.DiagnosticError(msg))), cls=encoder) == json.dumps(res_err(errors.INTERNAL_ERROR, msg), cls=encoder)
    assert json.dumps(res_err.convert_exception((ce.HighlightError(msg))), cls=encoder) == json.dumps(res_err(errors.INTERNAL_ERROR, msg), cls=encoder)
    assert json.dumps(res_err.convert_exception((ce.HoverError(msg))), cls=encoder) == json.dumps(res_err(errors.INTERNAL_ERROR, msg), cls=encoder)
    assert json.dumps(res_err.convert_exception((ce.NoYaraPython(msg))), cls=encoder) == json.dumps(res_err(errors.INTERNAL_ERROR, msg), cls=encoder)
    assert json.dumps(res_err.convert_exception((ce.RenameError(msg))), cls=encoder) == json.dumps(res_err(errors.INTERNAL_ERROR, msg), cls=encoder)
    assert json.dumps(res_err.convert_exception((ce.SymbolReferenceError(msg))), cls=encoder) == json.dumps(res_err(errors.INTERNAL_ERROR, msg), cls=encoder)
