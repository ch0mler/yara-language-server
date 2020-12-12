''' General YaraLanguageServer Tests '''
import json
import logging

import pytest
from yarals import helpers

# don't care about pylint(protected-access) warnings since these are just tests
# pylint: disable=W0212

try:
    # asyncio exceptions changed from 3.6 > 3.7 > 3.8
    # so try to keep this compatible regardless of Python version 3.6+
    # https://medium.com/@jflevesque/asyncio-exceptions-changes-from-python-3-6-to-3-7-to-3-8-cancellederror-timeouterror-f79945ead378
    from asyncio import CancelledError
except ImportError:
    from concurrent.futures import CancelledError


@pytest.mark.skip(reason="not implemented")
@pytest.mark.asyncio
@pytest.mark.integration
async def test_cancel(initialize_msg, initialized_msg, open_streams, test_rules, yara_server):
    ''' Ensure a task can be cancelled before it returns '''
    # initialize the server
    reader, writer = open_streams
    await yara_server.write_data(initialize_msg, writer)
    await yara_server.read_request(reader)
    await yara_server.write_data(initialized_msg, writer)
    await yara_server.read_request(reader)
    # execute a task that shouldn't complete on its own
    alienspy = str(test_rules.joinpath("apt_alienspy_rat.yar").resolve())
    file_uri = helpers.create_file_uri(alienspy)
    msg_id = 1
    message = {
        "jsonrpc": "2.0",
        "id": msg_id,
        "method": "textDocument/hover",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 38, "character": 15}
        }
    }
    await yara_server.write_data(json.dumps(message), writer)
    await yara_server.read_request(reader)
    # cancel that task
    cancel = {
        "jsonrpc": "2.0",
        "method": "$/cancelRequest",
        "params": {
            "id": msg_id
        }
    }
    await yara_server.write_data(json.dumps(cancel), writer)
    response = await yara_server.read_request(reader)
    print(response)

@pytest.mark.asyncio
async def test_dirty_files(test_rules, yara_server):
    ''' Ensure server prefers versions of dirty files over those backed by file path '''
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    unsaved_changes = "rule ResolveSymbol {\n strings:\n  $a = \"test\"\n condition:\n  #a > 3\n}\n"
    dirty_files = {
        file_uri: unsaved_changes
    }
    document = yara_server._get_document(file_uri, dirty_files)
    assert document == unsaved_changes

@pytest.mark.asyncio
@pytest.mark.integration
async def test_exceptions_handled(initialize_msg, initialized_msg, open_streams, test_rules, yara_server):
    ''' Ensure server notifies user when errors are encountered '''
    expected = {
        "jsonrpc": "2.0", "method": "window/showMessage",
        "params": {"type": 1, "message": "Could not find symbol for definition request"}
    }
    peek_rules = str(test_rules.joinpath("peek_rules.yara").resolve())
    file_uri = helpers.create_file_uri(peek_rules)
    error_request = json.dumps({
        "jsonrpc": "2.0", "id": 1,    # the initialize message takes id 0
        "method": "textDocument/definition",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {}
        }
    })
    reader, writer = open_streams
    await yara_server.write_data(initialize_msg, writer)
    await yara_server.read_request(reader)
    await yara_server.write_data(initialized_msg, writer)
    await yara_server.read_request(reader)
    await yara_server.write_data(error_request, writer)
    response = await yara_server.read_request(reader)
    assert response == expected
    writer.close()
    await writer.wait_closed()

@pytest.mark.asyncio
@pytest.mark.integration
async def test_exit(caplog, initialize_msg, initialized_msg, open_streams, shutdown_msg, yara_server):
    ''' Ensure the server shuts down when given the proper shutdown/exit sequence '''
    exit_msg = json.dumps({"jsonrpc":"2.0","method":"exit","params":None})
    reader, writer = open_streams
    with pytest.raises(CancelledError):
        with caplog.at_level(logging.DEBUG, "yara"):
            await yara_server.write_data(initialize_msg, writer)
            await yara_server.read_request(reader)
            await yara_server.write_data(initialized_msg, writer)
            await yara_server.read_request(reader)
            await yara_server.write_data(shutdown_msg, writer)
            await yara_server.read_request(reader)
            await yara_server.write_data(exit_msg, writer)
            await yara_server.read_request(reader)
            assert ("yara", logging.INFO, "Disconnected client") in caplog.record_tuples
            assert ("yara", logging.INFO, "Server exiting process per client request") in caplog.record_tuples
    writer.close()
    await writer.wait_closed()

@pytest.mark.skip(reason="not implemented")
def test_highlights():
    ''' TBD '''
    assert False is True

@pytest.mark.asyncio
@pytest.mark.integration
async def test_initialize(initialize_msg, initialized_msg, open_streams, yara_server):
    ''' Ensure server responds with appropriate initialization handshake '''
    expected_initialize = {
        "jsonrpc": "2.0", "id": 0, "result":{
            "capabilities": {
                "completionProvider":{"resolveProvider": False, "triggerCharacters": ["."]},
                "definitionProvider": True, "documentFormattingProvider": True, "hoverProvider": True,
                "renameProvider": True, "referencesProvider": True, "textDocumentSync": 1,
                "executeCommandProvider": {"commands": ["yara.CompileRule", "yara.CompileAllRules"]}
            }
        }
    }
    expected_initialized = {
        "jsonrpc": "2.0", "method": "window/showMessageRequest",
        "params": {"type": 3, "message": "Successfully connected"}
    }
    reader, writer = open_streams
    # write_data and read_request are just helpers for formatting JSON-RPC messages appropriately
    # despite using a second YaraLanguageServer, these will route through the one in local_server
    # because we pass the related reader & writer objects to these functions
    await yara_server.write_data(initialize_msg, writer)
    response = await yara_server.read_request(reader)
    assert response == expected_initialize
    await yara_server.write_data(initialized_msg, writer)
    response = await yara_server.read_request(reader)
    assert response == expected_initialized
    writer.close()
    await writer.wait_closed()

@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.skipif('sys.platform == "win32"')  # subprocess support is weird on Windows
async def test_initialize_without_plyara(initialize_msg, initialized_msg, open_streams, uninstall_pkg, yara_server):
    '''Ensure server responds with appropriate initialization handshake without plyara installed

        Note: The formatter command should always be enabled by the server,
            but if plyara is not installed the user should get a notification about it
    '''
    expected_initialize = {
        "jsonrpc": "2.0", "id": 0, "result":{
            "capabilities": {
                "completionProvider":{"resolveProvider": False, "triggerCharacters": ["."]},
                "definitionProvider": True, "documentFormattingProvider": True, "hoverProvider": True,
                "renameProvider": True, "referencesProvider": True, "textDocumentSync": 1,
                "executeCommandProvider": {"commands": ["yara.CompileRule", "yara.CompileAllRules"]}
            }
        }
    }
    expected_initialized = {
        "jsonrpc": "2.0", "method": "window/showMessageRequest",
        "params": {"type": 3, "message": "Successfully connected"}
    }
    await uninstall_pkg("plyara")
    reader, writer = open_streams
    await yara_server.write_data(initialize_msg, writer)
    response = await yara_server.read_request(reader)
    assert response == expected_initialize
    await yara_server.write_data(initialized_msg, writer)
    response = await yara_server.read_request(reader)
    writer.close()
    await writer.wait_closed()
    assert response == expected_initialized

@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.skipif('sys.platform == "win32"')  # subprocess support is weird on Windows
# @pytest.mark.xfail(reason="package installation issues")
async def test_initialize_without_yara(initialize_msg, initialized_msg, open_streams, uninstall_pkg, yara_server):
    ''' Ensure server responds with appropriate initialization handshake without yara-python installed '''
    expected_initialize = {
        "jsonrpc": "2.0", "id": 0, "result":{
            "capabilities": {
                "completionProvider":{"resolveProvider": False, "triggerCharacters": ["."]},
                "definitionProvider": True, "documentFormattingProvider": True, "hoverProvider": True,
                "renameProvider": True, "referencesProvider": True, "textDocumentSync": 1,
                "executeCommandProvider": {"commands": []}
            }
        }
    }
    expected_initialized = {
        "jsonrpc": "2.0", "method": "window/showMessageRequest",
        "params": {"type": 3, "message": "Successfully connected"}
    }
    await uninstall_pkg("yara-python")
    reader, writer = open_streams
    await yara_server.write_data(initialize_msg, writer)
    response = await yara_server.read_request(reader)
    assert response == expected_initialize
    await yara_server.write_data(initialized_msg, writer)
    response = await yara_server.read_request(reader)
    writer.close()
    await writer.wait_closed()
    assert response == expected_initialized

@pytest.mark.asyncio
def test__is_module_installed(yara_server):
    ''' Ensure module detection is working '''
    # tests should generally have these two installed as part of requirements.txt
    assert yara_server._is_module_installed("yara") is True
    assert yara_server._is_module_installed("plyara") is True
    assert yara_server._is_module_installed("nonexistant") is False

@pytest.mark.asyncio
@pytest.mark.integration
async def test_shutdown(caplog, initialize_msg, initialized_msg, open_streams, shutdown_msg, yara_server):
    ''' Ensure server logs appropriate response to shutdown '''
    reader, writer = open_streams
    with caplog.at_level(logging.DEBUG, "yara"):
        await yara_server.write_data(initialize_msg, writer)
        await yara_server.read_request(reader)
        await yara_server.write_data(initialized_msg, writer)
        await yara_server.read_request(reader)
        await yara_server.write_data(shutdown_msg, writer)
        await yara_server.read_request(reader)
        assert ("yara", logging.INFO, "Client requested shutdown") in caplog.record_tuples
    writer.close()
    await writer.wait_closed()

@pytest.mark.asyncio
@pytest.mark.integration
async def test_task_timeout(caplog, initialize_msg, initialized_msg, open_streams, test_rules, yara_server):
    ''' Ensure a task will cancel itself if it is taking too long '''
    # set a constant for the server's timeout period
    yara_server.TASK_TIMEOUT = 0.0
    # initialize the server
    reader, writer = open_streams
    with caplog.at_level(logging.DEBUG, "yara"):
        await yara_server.write_data(initialize_msg, writer)
        await yara_server.read_request(reader)
        await yara_server.write_data(initialized_msg, writer)
        await yara_server.read_request(reader)
        # execute a task that shouldn't complete on its own
        alienspy = str(test_rules.joinpath("apt_alienspy_rat.yar").resolve())
        file_uri = helpers.create_file_uri(alienspy)
        msg_id = 1
        message = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 38, "character": 15}
            }
        }
        await yara_server.write_data(json.dumps(message), writer)
        response = await yara_server.read_request(reader)
        expected = {"jsonrpc": "2.0", "id": msg_id, "result": None}
        expected_log = "Task for message {:d} timed out! {}".format(msg_id, message)
        assert ("yara", logging.WARNING, expected_log) in caplog.record_tuples
        assert response == expected
