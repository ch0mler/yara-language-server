''' Completion Provider Tests '''

import pytest
from yarals import helpers
from yarals.base import protocol
from yarals.base import errors as ce

# don't care about pylint(protected-access) warnings since these are just tests
# pylint: disable=W0212


@pytest.mark.asyncio
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
