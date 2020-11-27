''' Tests for yarals.helpers module '''
from textwrap import dedent
from urllib.parse import quote

import pytest
from yarals import helpers
from yarals.base import protocol

# don't care about pylint(protected-access) warnings since these are just tests
# pylint: disable=W0621


@pytest.fixture(scope="module")
def plyara_rule():
    ''' YARA rule parsed by plyara '''
    return {
            "strings": [
                {
                    "name": "$a",
                    "value": "test",
                    "type": "text"
                }
            ],
            "metadata": [
                {
                    "author": "test",
                    "reference": "github.com",
                }
            ],
            "rule_name": "Oneline",
            "start_line": 1,
            "stop_line": 1,
            "raw_strings": "strings: $a=\"test\" ",
            "raw_condition": "condition: $a ",
            "condition_terms": [
                "$a"
            ],
            "tags": [
                "test"
            ]
        }

@pytest.mark.helpers
def test_create_file_uri(test_rules):
    ''' Ensure file URIs are generated from paths '''
    test_rule_path = str(test_rules)
    expected = "file://{}".format(quote(test_rule_path.replace("\\", "/"), safe="/\\"))
    output = helpers.create_file_uri(test_rule_path)
    assert output == expected

@pytest.mark.helpers
def test_format_rule(plyara_rule, format_options):
    ''' Ensure plyara rules are formatted appropriately '''
    expected = dedent("""\
    rule Oneline : test
    {
        meta:
            author = "test"
            reference = "github.com"
        strings:
            $a = "test"
        condition:
            $a
    }""")
    kwargs = {
        "tab_size": format_options["tabSize"],
        "insert_spaces": format_options["insertSpaces"],
        "trim_whitespaces": format_options["trimTrailingWhitespace"],
        "insert_newline": format_options["insertFinalNewline"],
        "trim_newlines": format_options["trimFinalNewlines"],
    }
    actual = helpers.format_rule(plyara_rule, **kwargs)
    print("expected: %r" % expected)
    print("actual: %r" % actual)
    assert actual == expected

@pytest.mark.helpers
def test_format_alt_tab_size(plyara_rule, format_options):
    ''' Ensure a rule is formatted appropriately with a non-default tabSize '''
    expected = dedent("""\
    rule Oneline : test
    {
      meta:
        author = "test"
        reference = "github.com"
      strings:
        $a = "test"
      condition:
        $a
    }""")
    kwargs = {
        "tab_size": 2,
        "insert_spaces": format_options["insertSpaces"],
        "trim_whitespaces": format_options["trimTrailingWhitespace"],
        "insert_newline": format_options["insertFinalNewline"],
        "trim_newlines": format_options["trimFinalNewlines"],
    }
    actual = helpers.format_rule(plyara_rule, **kwargs)
    print("expected: %r" % expected)
    print("actual: %r" % actual)
    assert actual == expected

@pytest.mark.helpers
def test_format_insert_tabs(plyara_rule, format_options):
    ''' Ensure a rule is formatted appropriately with tabs instead of spaces '''
    expected = dedent("""\
    rule Oneline : test
    {
    	meta:
    		author = "test"
    		reference = "github.com"
    	strings:
    		$a = "test"
    	condition:
    		$a
    }""")
    kwargs = {
        "tab_size": format_options["tabSize"],
        "insert_spaces": False,
        "trim_whitespaces": format_options["trimTrailingWhitespace"],
        "insert_newline": format_options["insertFinalNewline"],
        "trim_newlines": format_options["trimFinalNewlines"],
    }
    actual = helpers.format_rule(plyara_rule, **kwargs)
    print("expected: %r" % expected)
    print("actual: %r" % actual)
    assert actual == expected

@pytest.mark.helpers
def test_format_no_trim_whitespace(plyara_rule, format_options):
    ''' Ensure a rule is formatted appropriately with whitespace left on each line '''
    expected = dedent("""\
    rule Oneline : test
    { 
        meta: 
            author = "test" 
            reference = "github.com" 
        strings: 
            $a = "test" 
        condition: 
            $a 
    }""")
    kwargs = {
        "tab_size": format_options["tabSize"],
        "insert_spaces": format_options["insertSpaces"],
        "trim_whitespaces": False,
        "insert_newline": format_options["insertFinalNewline"],
        "trim_newlines": format_options["trimFinalNewlines"],
    }
    actual = helpers.format_rule(plyara_rule, **kwargs)
    print("expected: %r" % expected)
    print("actual: %r" % actual)
    assert actual == expected

@pytest.mark.helpers
def test_format_with_final_newline(plyara_rule, format_options):
    ''' Ensure a rule is formatted appropriately with a newline appended '''
    expected = dedent("""\
    rule Oneline : test
    {
        meta:
            author = "test"
            reference = "github.com"
        strings:
            $a = "test"
        condition:
            $a
    }
    """)
    kwargs = {
        "tab_size": format_options["tabSize"],
        "insert_spaces": format_options["insertSpaces"],
        "trim_whitespaces": format_options["trimTrailingWhitespace"],
        "insert_newline": True,
        "trim_newlines": format_options["trimFinalNewlines"],
    }
    actual = helpers.format_rule(plyara_rule, **kwargs)
    print("expected: %r" % expected)
    print("actual: %r" % actual)
    assert actual == expected

@pytest.mark.helpers
def test_format_with_trimmed_newline(plyara_rule, format_options):
    ''' Ensure a rule is formatted appropriately with all extra newlines trimmed '''
    expected = dedent("""\
    rule Oneline : test
    {
        meta:
            author = "test"
            reference = "github.com"
        strings:
            $a = "test"
        condition:
            $a
    }


    """)
    kwargs = {
        "tab_size": format_options["tabSize"],
        "insert_spaces": format_options["insertSpaces"],
        "trim_whitespaces": format_options["trimTrailingWhitespace"],
        "insert_newline": format_options["insertFinalNewline"],
        "trim_newlines": True,
    }
    actual = helpers.format_rule(plyara_rule, **kwargs)
    print("expected: %r" % expected)
    print("actual: %r" % actual)
    assert actual == expected

@pytest.mark.helpers
def test_format_with_both_newline_options(plyara_rule, format_options):
    ''' Ensure a rule is formatted appropriately with all extra newlines trimmed and a final newline '''
    expected = dedent("""\
    rule Oneline : test
    {
        meta:
            author = "test"
            reference = "github.com"
        strings:
            $a = "test"
        condition:
            $a
    }
    """)
    kwargs = {
        "tab_size": format_options["tabSize"],
        "insert_spaces": format_options["insertSpaces"],
        "trim_whitespaces": format_options["trimTrailingWhitespace"],
        "insert_newline": True,
        "trim_newlines": True,
    }
    actual = helpers.format_rule(plyara_rule, **kwargs)
    print("expected: %r" % expected)
    print("actual: %r" % actual)
    assert actual == expected

@pytest.mark.helpers
def test_get_first_non_whitespace_index():
    ''' Ensure the index of the first non-whitespace is extracted from a string '''
    index = helpers.get_first_non_whitespace_index("    test")
    assert index == 4

@pytest.mark.helpers
def test_get_rule_range(test_rules):
    ''' Ensure YARA rules are parsed out and their range is returned '''
    peek_rules = test_rules.joinpath("peek_rules.yara").resolve()
    rules = peek_rules.read_text()
    pos = protocol.Position(line=42, char=12)
    result = helpers.get_rule_range(rules, pos)
    assert isinstance(result, protocol.Range) is True
    assert result.start.line == 33
    assert result.start.char == 0
    assert result.end.line == 43
    assert result.end.char == 0

@pytest.mark.helpers
def test_parse_result():
    ''' Ensure the parse_result() function properly parses a given diagnostic '''
    result = "line 14: syntax error, unexpected <true>, expecting text string"
    line_no, message = helpers.parse_result(result)
    assert line_no == 14
    assert message == "syntax error, unexpected <true>, expecting text string"

@pytest.mark.helpers
def test_parse_result_multicolon():
    ''' Sometimes results have colons in the messages - ensure this doesn't affect things '''
    result = "line 15: invalid hex string \"$hex_string\": syntax error"
    line_no, message = helpers.parse_result(result)
    assert line_no == 15
    assert message == "invalid hex string \"$hex_string\": syntax error"

@pytest.mark.helpers
@pytest.mark.skipif('sys.platform == "win32"')
def test_parse_uri():
    ''' Ensure paths are properly parsed '''
    path = "/one/two/three/four.txt"
    file_uri = "file://{}".format(path)
    # leading forward slash should be added for non-Windows systems
    assert helpers.parse_uri(file_uri) == path

@pytest.mark.helpers
@pytest.mark.skipif('sys.platform != "win32"')
def test_parse_uri_windows():
    ''' Ensure paths are properly parsed for Windows '''
    path = "c:/one/two/three/four.txt"
    # on Windows, Python will capitalize the drive letter and use opposite slashes as everywhere else
    expected = "C:\\one\\two\\three\\four.txt"
    file_uri = "file:///{}".format(path)
    assert helpers.parse_uri(file_uri) == expected

@pytest.mark.helpers
def test_resolve_symbol():
    ''' Ensure symbols are properly resolved '''
    document = "rule ResolveSymbol {\n strings:\n  $a = \"test\"\n condition:\n  #a > 3\n}\n"
    pos = protocol.Position(line=4, char=4)
    symbol = helpers.resolve_symbol(document, pos)
    assert symbol == "#a"
