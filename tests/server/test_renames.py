''' Rename Provider Tests '''
import pytest
from yarals import helpers
from yarals.base import protocol
from yarals.base import errors as ce

# don't care about pylint(protected-access) warnings since these are just tests
# pylint: disable=W0212

try:
    # asyncio exceptions changed from 3.6 > 3.7 > 3.8
    # so try to keep this compatible regardless of Python version 3.6+
    # https://medium.com/@jflevesque/asyncio-exceptions-changes-from-python-3-6-to-3-7-to-3-8-cancellederror-timeouterror-f79945ead378
    from asyncio.exceptions import CancelledError
except ImportError:
    from concurrent.futures import CancelledError



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
    acceptable_lines = [21, 28, 29]
    for edit in result.changes:
        assert isinstance(edit, protocol.TextEdit) is True
        assert edit.newText == new_text
        assert edit.range.start.line in acceptable_lines
        # TODO: check that the character indexes are correct
