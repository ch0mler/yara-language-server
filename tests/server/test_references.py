''' Reference Provider Tests '''
import pytest
from yarals import helpers
from yarals.base import protocol

# don't care about pylint(protected-access) warnings since these are just tests
# pylint: disable=W0212


@pytest.mark.asyncio
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
