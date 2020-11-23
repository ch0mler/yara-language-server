''' Tests for yarals.protocol module '''
from copy import deepcopy
import json

import pytest
from yarals.base import protocol
from yarals.base import errors as ce


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
def test_diagnostic_comparisons():
    ''' Ensure Diagnostics can be properly compared '''
    pos_dict = {"line": 10, "character": 15}
    pos = protocol.Position(line=pos_dict["line"], char=pos_dict["character"])
    rg_dict = {"start": pos_dict, "end": pos_dict}
    rg_obj = protocol.Range(start=pos, end=pos)
    diag_dict = {
        "message": "Test Diagnostic",
        "range": rg_dict,
        "relatedInformation": [],
        "severity": protocol.DiagnosticSeverity.ERROR
    }
    diag = protocol.Diagnostic(
        locrange=rg_obj,
        message=diag_dict["message"],
        severity=diag_dict["severity"]
    )
    diag_same = deepcopy(diag)
    assert diag == diag_same
    diag_msg = deepcopy(diag)
    diag_msg.message = "Different Message Diagnostic"
    assert diag != diag_msg
    diag_sev = deepcopy(diag)
    diag_sev.severity = protocol.DiagnosticSeverity.WARNING
    assert diag != diag_sev
    diag_rinfo = deepcopy(diag)
    diag_rinfo.relatedInformation = ["New Information"]
    assert diag != diag_rinfo
    diag_rg = deepcopy(diag)
    new_pos = deepcopy(pos)
    new_pos.line = 0
    new_pos.char = 0
    diag_rg.range = protocol.Range(start=new_pos, end=new_pos)
    assert diag != diag_rg

@pytest.mark.protocol
def test_completionitem():
    ''' Ensure CompletionItem is properly encoded to JSON dictionaries '''
    comp_dict = {"label": "test", "kind": protocol.CompletionItemKind.CLASS}
    comp = protocol.CompletionItem(label=comp_dict["label"], kind=comp_dict["kind"])
    assert json.dumps(comp, cls=protocol.JSONEncoder) == json.dumps(comp_dict)

@pytest.mark.protocol
def test_completionitem_comparisons():
    ''' Ensure Comp letionItems can be properly compared '''
    comp = protocol.CompletionItem(label="Test CompletionItem", kind=protocol.CompletionItemKind.CLASS)
    comp_same = deepcopy(comp)
    assert comp == comp_same
    comp_label = deepcopy(comp)
    comp_label.label = "Different CompletionItem"
    assert comp != comp_label
    comp_kind = deepcopy(comp)
    comp_kind.kind = protocol.CompletionItemKind.METHOD
    assert comp != comp_kind

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
def test_location_comparisons():
    ''' Ensure Locations can be properly compared '''
    pos = protocol.Position(line=10, char=15)
    rg_obj = protocol.Range(start=pos, end=pos)
    loc = protocol.Location(locrange=rg_obj, uri="fake:///one/two/three/four.path")
    loc_same = deepcopy(loc)
    assert loc == loc_same
    loc_range = deepcopy(loc)
    new_pos = deepcopy(pos)
    new_pos.line = 0
    new_range = protocol.Range(start=new_pos, end=new_pos)
    loc_range.range = new_range
    assert loc != loc_range
    loc_uri = deepcopy(loc)
    loc_uri.uri = "fake:///five/six/seven/eight.path"
    assert loc != loc_uri

@pytest.mark.protocol
def test_position():
    ''' Ensure Positions is properly encoded to JSON dictionaries '''
    pos_dict = {"line": 10, "character": 15}
    pos = protocol.Position(line=pos_dict["line"], char=pos_dict["character"])
    assert json.dumps(pos, cls=protocol.JSONEncoder) == json.dumps(pos_dict)

@pytest.mark.protocol
def test_position_comparisons():
    ''' Ensure Position can be properly compared '''
    pos = protocol.Position(line=10, char=15)
    pos_same = deepcopy(pos)
    assert pos == pos_same
    pos_line = deepcopy(pos)
    pos_line.line = 0
    assert pos != pos_line
    pos_char = deepcopy(pos)
    pos_char.char = 0
    assert pos != pos_char

@pytest.mark.protocol
def test_range():
    ''' Ensure Ranges is properly encoded to JSON dictionaries '''
    pos_dict = {"line": 10, "character": 15}
    pos = protocol.Position(line=pos_dict["line"], char=pos_dict["character"])
    rg_dict = {"start": pos_dict, "end": pos_dict}
    rg_obj = protocol.Range(
        start=pos,
        end=pos
    )
    assert json.dumps(rg_obj, cls=protocol.JSONEncoder) == json.dumps(rg_dict)

@pytest.mark.protocol
def test_range_comparisons():
    ''' Ensure Range can be properly compared '''
    pos = protocol.Position(line=10, char=15)
    rg_obj = protocol.Range(start=pos, end=pos)
    rg_same = deepcopy(rg_obj)
    assert rg_obj == rg_same
    rg_start = deepcopy(rg_obj)
    new_end = deepcopy(pos)
    new_end.line = 0
    rg_start.start = new_end
    assert rg_obj != rg_start
    rg_end = deepcopy(rg_obj)
    new_end = deepcopy(pos)
    new_end.line = 0
    rg_end.end = new_end
    assert rg_obj != rg_end

@pytest.mark.protocol
def test_responseerror():
    ''' Ensure ResponseError is properly encoded to JSON dictionaries '''
    err_dict = {"code": protocol.JsonRPCError.UNKNOWN_ERROR_CODE, "message": "Test exception", "data": None}
    err = protocol.ResponseError(code=err_dict["code"], message=err_dict["message"])
    assert json.dumps(err, cls=protocol.JSONEncoder) == json.dumps(err_dict)

@pytest.mark.protocol
def test_responseerror_comparisons():
    ''' Ensure ResponseError can be properly compared '''
    err = protocol.ResponseError(code=protocol.JsonRPCError.UNKNOWN_ERROR_CODE, message="Text exception")
    err_same = deepcopy(err)
    assert err == err_same
    err_code = deepcopy(err)
    err_code.code = protocol.JsonRPCError.SERVER_ERROR_END
    assert err != err_code
    err_msg = deepcopy(err)
    err_msg.message = "Different exception"
    assert err != err_msg

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
    assert json.dumps(res_err.convert_exception((ce.FormatError(msg))), cls=encoder) == json.dumps(res_err(errors.INTERNAL_ERROR, msg), cls=encoder)
    assert json.dumps(res_err.convert_exception((ce.HighlightError(msg))), cls=encoder) == json.dumps(res_err(errors.INTERNAL_ERROR, msg), cls=encoder)
    assert json.dumps(res_err.convert_exception((ce.HoverError(msg))), cls=encoder) == json.dumps(res_err(errors.INTERNAL_ERROR, msg), cls=encoder)
    assert json.dumps(res_err.convert_exception((ce.NoYaraPython(msg))), cls=encoder) == json.dumps(res_err(errors.INTERNAL_ERROR, msg), cls=encoder)
    assert json.dumps(res_err.convert_exception((ce.RenameError(msg))), cls=encoder) == json.dumps(res_err(errors.INTERNAL_ERROR, msg), cls=encoder)
    assert json.dumps(res_err.convert_exception((ce.SymbolReferenceError(msg))), cls=encoder) == json.dumps(res_err(errors.INTERNAL_ERROR, msg), cls=encoder)
