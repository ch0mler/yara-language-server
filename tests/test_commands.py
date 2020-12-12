''' Command Tests '''
import json

import pytest
from yarals import helpers
from yarals.base import protocol

# don't care about pylint(protected-access) warnings since these are just tests
# pylint: disable=W0212


@pytest.mark.skip(reason="not implemented")
@pytest.mark.integration
def test_cmd_compile_rule():
    ''' Ensure CompileRule compiles the currently-active YARA rule file using the "executeCommand" action '''
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "workspace/executeCommand",
        "params": {
            "command": "yara.CompileRule",
            "arguments": []
        }
    }
    assert request is False

@pytest.mark.asyncio
@pytest.mark.integration
async def test_cmd_compile_all_rules(initialize_msg, initialized_msg, open_streams, test_rules, yara_server):
    ''' Ensure CompileAllRules compiles all YARA rule files in the given workspace using the "executeCommand" action '''
    expected = {"result": None}
    execute_cmd = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "workspace/executeCommand",
        "params": {
            "command": "yara.CompileAllRules",
            "arguments": []
        }
    }
    # change workspace from non-existant test workspace to our test_rules
    # to ensure YARA rules actually get properly identified
    init_ws = json.loads(initialize_msg)
    init_ws["params"]["rootPath"] = str(test_rules)
    init_ws["params"]["rootUri"] = helpers.create_file_uri(str(test_rules))
    init_ws["params"]["workspaceFolders"] = [{
        "uri": init_ws["params"]["rootUri"],
        "name": test_rules.name
    }]
    # initialize server with the workspace we want to work from
    reader, writer = open_streams
    await yara_server.write_data(json.dumps(init_ws), writer)
    await yara_server.read_request(reader)
    await yara_server.write_data(initialized_msg, writer)
    await yara_server.read_request(reader)
    # finally, execute command
    await yara_server.write_data(json.dumps(execute_cmd), writer)
    response = await yara_server.read_request(reader)
    # diagnostics are sent as notifications, and there may be an arbitrary number depending on test files
    while response.get("method") == "textDocument/publishDiagnostics":
        response = await yara_server.read_request(reader)
    # once all the diagnostics are finished, we should get our final response, which should be null
    assert response.get("result", {}) == expected

@pytest.mark.asyncio
@pytest.mark.integration
async def test_cmd_compile_all_rules_no_workspace(initialize_msg, initialized_msg, open_streams, test_rules, yara_server):
    ''' Ensure CompileAllRules only compiles opened files when no workspace is specified '''
    notifications = []
    expected = {"result": None}
    expected_msg = "wrong usage of identifier \"cuckoo\""
    file_path = test_rules.joinpath("code_completion.yara").resolve()
    contents = open(file_path, "r").read().replace("ModuleCompletionExample", "ModifiedExample")
    did_change = {
        "jsonrpc":"2.0",
        "method":"textDocument/didChange",
        "params": {
            "textDocument":{
                "uri": helpers.create_file_uri(file_path),
                "version":42
            },
            "contentChanges":[{"text": contents}]
        }
    }
    execute_cmd = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "workspace/executeCommand",
        "params": {
            "command": "yara.CompileAllRules",
            "arguments": []
        }
    }
    # keep non-existant test workspace
    # to ensure YARA rules actually get properly identified
    init_ws = json.loads(initialize_msg)
    init_ws["params"]["rootPath"] = None
    init_ws["params"]["rootUri"] = None
    init_ws["params"]["workspaceFolders"] = []
    # initialize server with the workspace we want to work from
    reader, writer = open_streams
    await yara_server.write_data(json.dumps(init_ws), writer)
    await yara_server.read_request(reader)
    await yara_server.write_data(initialized_msg, writer)
    await yara_server.read_request(reader)
    # notify the server of a file change
    await yara_server.write_data(json.dumps(did_change), writer)
    # finally, execute command
    await yara_server.write_data(json.dumps(execute_cmd), writer)
    response = await yara_server.read_request(reader)
    while response.get("method") == "textDocument/publishDiagnostics":
        notifications.append(response["params"])
        response = await yara_server.read_request(reader)
    assert response["result"] == expected
    assert len(notifications) == 1
    assert notifications[0]["uri"] == helpers.create_file_uri(file_path)
    assert len(notifications[0]["diagnostics"]) == 1
    assert notifications[0]["diagnostics"][0]["message"] == expected_msg

@pytest.mark.asyncio
async def test__compile_all_rules_no_dirty_files(test_rules, yara_server):
    ''' Ensure the _compile_all_rules function returns the appropriate number of diagnostics when no workspace files are dirty '''
    expected = [
        {
            "uri": helpers.create_file_uri(str(test_rules.joinpath("peek_rules.yara").resolve())),
            "diagnostics": [
                protocol.Diagnostic(
                    protocol.Range(protocol.Position(line=17, char=8), protocol.Position(line=17, char=yara_server.MAX_LINE)),
                    severity=protocol.DiagnosticSeverity.ERROR,
                    message="syntax error, unexpected <true>, expecting text string"
                )
            ]
        },
        {
            "uri": helpers.create_file_uri(str(test_rules.joinpath("code_completion.yara").resolve())),
            "diagnostics": [
                protocol.Diagnostic(
                    protocol.Range(protocol.Position(line=10, char=0), protocol.Position(line=10, char=yara_server.MAX_LINE)),
                    severity=protocol.DiagnosticSeverity.ERROR,
                    message="wrong usage of identifier \"cuckoo\""
                )
            ]
        },
        {
            "uri": helpers.create_file_uri(str(test_rules.joinpath("simple_mistake.yar").resolve())),
            "diagnostics": [
                protocol.Diagnostic(
                    protocol.Range(protocol.Position(line=4, char=0), protocol.Position(line=4, char=yara_server.MAX_LINE)),
                    severity=protocol.DiagnosticSeverity.ERROR,
                    message="undefined string \"$true\""
                )
            ]
        }
    ]
    results = await yara_server._compile_all_rules({}, workspace=test_rules)
    assert len(results) == len(expected)
    assert all(result in expected for result in results)

@pytest.mark.asyncio
async def test__compile_all_rules_with_dirty_files(test_rules, yara_server):
    ''' Ensure the _compile_all_rules function returns the appropriate number of diagnostics when workspace files have unsaved content '''
    expected = [
        {
            "uri": helpers.create_file_uri(str(test_rules.joinpath("peek_rules.yara").resolve())),
            "diagnostics": [
                protocol.Diagnostic(
                    protocol.Range(protocol.Position(line=17, char=8), protocol.Position(line=17, char=yara_server.MAX_LINE)),
                    severity=protocol.DiagnosticSeverity.ERROR,
                    message="syntax error, unexpected <true>, expecting text string"
                )
            ]
        },
        {
            "uri": helpers.create_file_uri(str(test_rules.joinpath("code_completion.yara").resolve())),
            "diagnostics": [
                protocol.Diagnostic(
                    protocol.Range(protocol.Position(line=10, char=0), protocol.Position(line=10, char=yara_server.MAX_LINE)),
                    severity=protocol.DiagnosticSeverity.ERROR,
                    message="wrong usage of identifier \"cuckoo\""
                )
            ]
        },
        {
            "uri": helpers.create_file_uri(str(test_rules.joinpath("simple_mistake.yar").resolve())),
            "diagnostics": [
                protocol.Diagnostic(
                    protocol.Range(protocol.Position(line=4, char=0), protocol.Position(line=4, char=yara_server.MAX_LINE)),
                    severity=protocol.DiagnosticSeverity.ERROR,
                    message="undefined string \"$true\""
                )
            ]
        }
    ]
    # files won't actually be changed, so the diagnostics should reflect the "no_dirty_files" test
    dirty_files = {}
    for filename in ["peek_rules.yara", "simple_mistake.yar", "code_completion.yara"]:
        dirty_path = str(test_rules.joinpath(filename).resolve())
        dirty_files[helpers.create_file_uri(dirty_path)] = yara_server._get_document(dirty_path, dirty_files={})
    results = await yara_server._compile_all_rules(dirty_files, workspace=test_rules)
    assert len(results) == len(expected)
    assert all(result in expected for result in results)