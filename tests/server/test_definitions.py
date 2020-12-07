''' Definition Provider Tests '''

import pytest
from yarals import helpers
from yarals.base import protocol

# don't care about pylint(protected-access) warnings since these are just tests
# pylint: disable=W0212


@pytest.mark.asyncio
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
