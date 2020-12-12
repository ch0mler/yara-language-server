''' Format Provider Tests '''
from textwrap import dedent

import pytest
from yarals import helpers
from yarals.base import protocol
from yarals.base import errors as ce

# don't care about pylint(protected-access) warnings since these are just tests
# pylint: disable=W0212


@pytest.mark.asyncio
async def test_format(format_options, test_rules, yara_server):
    ''' Ensure a text edit is provided on format with explicit options '''
    expected = dedent("""\
    rule Oneline : test
    {
        strings:
            $a = "test"

        condition:
            $a
    }""")
    oneline = str(test_rules.joinpath("oneline.yar").resolve())
    file_uri = helpers.create_file_uri(oneline)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 29, "character": 12},
            "options": format_options
        }
    }
    result = await yara_server.provide_formatting(message, True)
    assert len(result) == 1
    edit = result[0]
    assert isinstance(edit, protocol.TextEdit) is True
    assert edit.newText == expected

@pytest.mark.asyncio
async def test_format_default_options(test_rules, yara_server):
    ''' Ensure a text edit is provided on format with implicit options '''
    expected = dedent("""\
    rule Oneline : test
    {
        strings:
            $a = "test"

        condition:
            $a
    }""")
    oneline = str(test_rules.joinpath("oneline.yar").resolve())
    file_uri = helpers.create_file_uri(oneline)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 29, "character": 12}
        }
    }
    result = await yara_server.provide_formatting(message, True)
    assert len(result) == 1
    edit = result[0]
    assert isinstance(edit, protocol.TextEdit) is True
    assert edit.newText == expected

@pytest.mark.asyncio
async def test_format_alt_tabsize(test_rules, yara_server):
    ''' Ensure a text edit is provided on format with tabSize set '''
    expected = dedent("""\
    rule Oneline : test
    {
      strings:
        $a = "test"

      condition:
        $a
    }""")
    oneline = str(test_rules.joinpath("oneline.yar").resolve())
    file_uri = helpers.create_file_uri(oneline)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 29, "character": 12},
            "options": {"tabSize": 2}
        }
    }
    result = await yara_server.provide_formatting(message, True)
    assert len(result) == 1
    edit = result[0]
    assert isinstance(edit, protocol.TextEdit) is True
    assert edit.newText == expected

@pytest.mark.asyncio
async def test_format_insert_tabs(test_rules, yara_server):
    ''' Ensure a text edit is provided that uses tabs instead of spaces '''
    expected = dedent("""\
    rule Oneline : test
    {
    	strings:
    		$a = "test"

    	condition:
    		$a
    }""")
    oneline = str(test_rules.joinpath("oneline.yar").resolve())
    file_uri = helpers.create_file_uri(oneline)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 29, "character": 12},
            "options": {"insertSpaces": False}
        }
    }
    result = await yara_server.provide_formatting(message, True)
    assert len(result) == 1
    edit = result[0]
    assert isinstance(edit, protocol.TextEdit) is True
    assert edit.newText == expected

@pytest.mark.skip(reason="not implemented")
@pytest.mark.asyncio
async def test_format_keep_whitespace(test_rules, yara_server):
    ''' Ensure a text edit is provided with untrimmed whitespace '''
    expected = dedent("""\
    rule Oneline : test 
    { 
        strings: 
            $a = "test" 

        condition: 
            $a 
    }""")
    oneline = str(test_rules.joinpath("oneline.yar").resolve())
    file_uri = helpers.create_file_uri(oneline)
    # spacing should be preserved
    dirty_files = {
        file_uri: expected
    }
    file_uri = helpers.create_file_uri(oneline)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 29, "character": 12},
            "options": {"trimTrailingWhitespace": False}
        }
    }
    result = await yara_server.provide_formatting(message, True, dirty_files=dirty_files)
    assert len(result) == 1
    edit = result[0]
    assert isinstance(edit, protocol.TextEdit) is True
    assert edit.newText == expected

@pytest.mark.asyncio
async def test_format_insert_newline(test_rules, yara_server):
    ''' Ensure a text edit is provided with an extra newline inserted '''
    expected = dedent("""\
    rule Oneline : test
    {
        strings:
            $a = "test"

        condition:
            $a
    }
    """)
    oneline = str(test_rules.joinpath("oneline.yar").resolve())
    file_uri = helpers.create_file_uri(oneline)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 29, "character": 12},
            "options": {"insertFinalNewline": True}
        }
    }
    result = await yara_server.provide_formatting(message, True)
    assert len(result) == 1
    edit = result[0]
    assert isinstance(edit, protocol.TextEdit) is True
    assert edit.newText == expected

@pytest.mark.asyncio
async def test_format_keep_newlines(test_rules, yara_server):
    ''' Ensure a text edit is provided with extra newlines '''
    expected = dedent("""\
    rule Oneline : test
    {
        strings:
            $a = "test"

        condition:
            $a
    }


    """)
    oneline = str(test_rules.joinpath("oneline.yar").resolve())
    with open(oneline) as ifile:
        file_uri = helpers.create_file_uri(oneline)
        dirty_files = {
            file_uri: "%s\n\n\n" % ifile.read()
        }
        message = {
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 29, "character": 12},
                "options": {"trimFinalNewlines": False}
            }
        }
        result = await yara_server.provide_formatting(message, True, dirty_files=dirty_files)
        assert len(result) == 1
        edit = result[0]
        assert isinstance(edit, protocol.TextEdit) is True
        assert edit.newText == expected

@pytest.mark.asyncio
@pytest.mark.xfail(reason="package installation issues")
async def test_format_notify_user(test_rules, uninstall_pkg, yara_server):
    ''' Ensure the formatter notifies the user if plyara is not installed '''
    expected_msg = "plyara is not installed. Formatting is disabled"
    oneline = str(test_rules.joinpath("oneline.yar").resolve())
    file_uri = helpers.create_file_uri(oneline)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 29, "character": 12}
        }
    }
    await uninstall_pkg("plyara")
    with pytest.raises(ce.NoDependencyFound) as excinfo:
        await yara_server.provide_formatting(message, True)
    assert expected_msg == str(excinfo.value)

@pytest.mark.asyncio
async def test_format_no_imports(test_rules, yara_server):
    ''' Ensure imports are removed from provided rules. They should not be affected by formatter '''
    rulefile = str(test_rules.joinpath("code_completion.yara").resolve())
    file_uri = helpers.create_file_uri(rulefile)
    message = {
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 9, "character": 12}
        }
    }
    result = await yara_server.provide_formatting(message, True)
    assert len(result) == 3
    assert all([isinstance(edit, protocol.TextEdit) for edit in result])
    full_text = "\n".join([edit.newText for edit in result])
    # should only be two imports - one for cuckoo and one for pe
    assert full_text.count("import ") == 0
