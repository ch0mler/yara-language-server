''' Completion Provider Tests '''

import pytest
from yarals import helpers
from yarals.base import protocol

# don't care about pylint(protected-access) warnings since these are just tests
# pylint: disable=W0212


@pytest.mark.asyncio
async def test_code_completion_regular(test_rules, yara_server):
    ''' Ensure code completion works with functions defined in modules schema '''
    actual = []
    code_completion = str(test_rules.joinpath("code_completion.yara").resolve())
    expected = sorted(["network", "registry", "filesystem", "sync"])
    file_uri = helpers.create_file_uri(code_completion)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 10, "character": 15}
        }
    }
    result = await yara_server.provide_code_completion(message, True)
    assert len(result) == len(expected)
    for completion in result:
        assert isinstance(completion, protocol.CompletionItem)
        actual.append(completion.insertText)
    assert sorted(actual) == expected

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

@pytest.mark.asyncio
async def test_code_completion_module_dictionary(test_rules, yara_server):
    ''' Ensure code completion returns a properly-formatted list of strings when a module entry is a list of dictionary keys '''
    actual = []
    options = [
        "Comments", "CompanyName", "FileDescription", "FileVersion", "InternalName",
        "LegalCopyright", "LegalTrademarks", "OriginalFilename", "ProductName", "ProductVersion"
    ]
    expected = sorted(map(lambda option: f"version_info[\"{option}\"]", options))
    code_completion = str(test_rules.joinpath("code_completion.yara").resolve())
    file_uri = helpers.create_file_uri(code_completion)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 18, "character": 15}
        }
    }
    result = await yara_server.provide_code_completion(message, True)
    assert len(result) == len(expected)
    for completion in result:
        assert isinstance(result[0], protocol.CompletionItem)
        actual.append(completion.insertText)
    assert sorted(actual) == expected

@pytest.mark.asyncio
async def test_code_completion_module_method(test_rules, yara_server):
    ''' Ensure code completion returns a properly-formatted snippet string when a module entry is a method '''
    expected_snippet = "is_dll()"
    code_completion = str(test_rules.joinpath("code_completion.yara").resolve())
    file_uri = helpers.create_file_uri(code_completion)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 26, "character": 17}
        }
    }
    result = await yara_server.provide_code_completion(message, True)
    assert len(result) == 1
    assert isinstance(result[0], protocol.CompletionItem)
    assert result[0].insertText == expected_snippet
