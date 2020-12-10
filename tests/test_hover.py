''' Hover Provider Tests '''
import json

import pytest
from yarals import helpers
from yarals.base import protocol

# don't care about pylint(protected-access) warnings since these are just tests
# pylint: disable=W0212


@pytest.mark.asyncio
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
@pytest.mark.integration
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
