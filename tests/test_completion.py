''' Completion Provider Tests '''

import pytest
from yarals import helpers
from yarals.base import protocol

# don't care about pylint(protected-access) warnings since these are just tests
# pylint: disable=W0212


@pytest.mark.asyncio
async def test_code_completion_regular(test_rules, yara_server):
    ''' Ensure code completion works with functions defined in modules schema '''
    code_completion = str(test_rules.joinpath("code_completion.yara").resolve())
    expected = [
        protocol.CompletionItem("network", protocol.CompletionItemKind.CLASS, detail="cuckoo.network"),
        protocol.CompletionItem("registry", protocol.CompletionItemKind.CLASS, detail="cuckoo.registry"),
        protocol.CompletionItem("filesystem", protocol.CompletionItemKind.CLASS, detail="cuckoo.filesystem"),
        protocol.CompletionItem("sync", protocol.CompletionItemKind.CLASS, detail="cuckoo.sync")
    ]
    file_uri = helpers.create_file_uri(code_completion)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 10, "character": 15}
        }
    }
    actual = await yara_server.provide_code_completion(message, True)
    assert len(actual) == len(expected)
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

@pytest.mark.asyncio
async def test_code_completion_module_dictionary(test_rules, yara_server):
    ''' Ensure code completion returns a properly-formatted list of strings when a module entry is a list of dictionary keys '''
    actual = []
    expected = []
    options = [
        "Comments", "CompanyName", "FileDescription", "FileVersion", "InternalName",
        "LegalCopyright", "LegalTrademarks", "OriginalFilename", "ProductName", "ProductVersion"
    ]
    for option in options:
        snippet = "version_info[\"{}\"]".format(option)
        detail = "pe.{}".format(snippet)
        expected.append(protocol.CompletionItem(option, protocol.CompletionItemKind.INTERFACE, detail=detail, insertText=snippet))
    code_completion = str(test_rules.joinpath("code_completion.yara").resolve())
    file_uri = helpers.create_file_uri(code_completion)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 18, "character": 15}
        }
    }
    actual = await yara_server.provide_code_completion(message, True)
    assert len(actual) == len(expected)
    assert actual == expected

@pytest.mark.asyncio
async def test_code_completion_module_method(test_rules, yara_server):
    ''' Ensure code completion returns a properly-formatted snippet string when a module entry is a method '''
    expected = [
        protocol.CompletionItem("is_dll", protocol.CompletionItemKind.METHOD, detail="pe.is_dll()", insertText="is_dll()")
    ]
    code_completion = str(test_rules.joinpath("code_completion.yara").resolve())
    file_uri = helpers.create_file_uri(code_completion)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 26, "character": 17}
        }
    }
    result = await yara_server.provide_code_completion(message, True)
    assert len(result) == len(expected)
    assert result == expected
