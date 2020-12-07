''' Rename Provider Tests '''
import pytest
from yarals import helpers
from yarals.base import protocol
from yarals.base import errors as ce

# don't care about pylint(protected-access) warnings since these are just tests
# pylint: disable=W0212


@pytest.mark.asyncio
async def test_renames(test_rules, yara_server):
    ''' Ensure variables can be renamed '''
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    # @dstring[1]: Line 30, Col 12
    new_text = "test_rename"
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 29, "character": 12},
            "newName": new_text
        }
    }
    result = await yara_server.provide_rename(message, True)
    assert isinstance(result, protocol.WorkspaceEdit) is True
    assert len(result.changes) == 3
    expected = protocol.WorkspaceEdit(file_uri, changes=[
        protocol.TextEdit(protocol.Range(protocol.Position(line=21, char=9), protocol.Position(line=21, char=16)), newText=new_text),
        protocol.TextEdit(protocol.Range(protocol.Position(line=28, char=9), protocol.Position(line=28, char=16)), newText=new_text),
        protocol.TextEdit(protocol.Range(protocol.Position(line=29, char=9), protocol.Position(line=29, char=16)), newText=new_text),
    ])
    assert result == expected
