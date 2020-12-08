''' Reusable test fixtures '''
import asyncio
import json
from pathlib import Path
from sys import executable as python_path

import pytest
from yarals import yarals

# pylint: disable=W0621


def pytest_configure(config):
    ''' Registering custom markers '''
    config.addinivalue_line("markers", "integration: Run integration tests that require setting up a networked server instance")
    config.addinivalue_line("markers", "command: Run executeCommand integration tests")
    config.addinivalue_line("markers", "config: Run config unittests")
    config.addinivalue_line("markers", "helpers: Run helper function unittests")
    config.addinivalue_line("markers", "protocol: Run language server protocol unittests")
    config.addinivalue_line("markers", "transport: Run network transport unittests")

@pytest.fixture
def event_loop():
    ''' force asyncio to use this event loop regardless of OS
        to avoid RunTimeError "Event loop is closed" on Windows
        also seen in: https://github.com/aio-libs/aiohttp/issues/4324
    '''
    loop = asyncio.SelectorEventLoop()
    yield loop
    loop.close()

@pytest.fixture(scope="function")
def yara_server():
    ''' Generate an instance of the YARA language server '''
    return yarals.YaraLanguageServer()

@pytest.fixture(scope="function")
async def open_streams(unused_tcp_port, yara_server):
    ''' Set up a local asyncio network server

    :param unused_tcp_port: Random TCP port to bind server to. Provided by pytest-asyncio
    :return: Read/Write streams to interact with server
    '''
    addr = "localhost"
    port = unused_tcp_port
    server = await asyncio.start_server(
        client_connected_cb=yara_server.handle_client,
        host=addr,
        port=port,
        start_serving=True
    )
    reader, writer = await asyncio.open_connection(addr, port)
    yield reader, writer
    server.close()
    await server.wait_closed()

@pytest.fixture(scope="function")
async def init_server(initialize_msg, initialized_msg):
    ''' Start the given language server with the standard init sequence '''
    async def _init_server(reader, writer, yara_server):
        await yara_server.write_data(initialize_msg, writer)
        await yara_server.read_request(reader)
        await yara_server.write_data(initialized_msg, writer)
        await yara_server.read_request(reader)
    return _init_server

@pytest.fixture(scope="function")
def test_rules():
    ''' Resolve full path to the test YARA rules '''
    rules_path = Path(__file__).parent.joinpath("rules")
    return rules_path.resolve()

@pytest.fixture(scope="module")
def initialize_msg():
    ''' Hardcoded 'initialize' message to start handshake with server '''
    json_path = Path(__file__).parent.joinpath("initialize_msg.json").resolve()
    with json_path.open() as init:
        return json.dumps(json.load(init))

@pytest.fixture(scope="module")
def initialized_msg():
    ''' Hardcoded 'initialized' message to complete client setup with server '''
    return json.dumps({"jsonrpc": "2.0", "method": "initialized", "params": {}})

@pytest.fixture(scope="module")
def shutdown_msg():
    ''' Hardcoded 'initialized' message to complete client setup with server '''
    return json.dumps({"jsonrpc":"2.0","id":1,"method":"shutdown","params":None})

@pytest.fixture(scope="module")
def format_options():
    ''' Default documentFormatting options '''
    return {
        "tabSize": 4,
        "insertSpaces": True,
        "trimTrailingWhitespace": True,
        "insertFinalNewline": False,
        "trimFinalNewlines": True
    }

@pytest.fixture(scope="function")
async def uninstall_pkg():
    ''' Uninstall the given Python package before running a test, then reinstall when test is finished '''
    module = None
    async def _uninstall_pkg(pkg):
        nonlocal module
        module = pkg
        proc = await asyncio.create_subprocess_shell(" ".join([python_path, "-m", "pip", "uninstall", "-y", pkg]))
        await proc.communicate()
    yield _uninstall_pkg
    if module:
        proc = await asyncio.create_subprocess_shell(" ".join([python_path, "-m", "pip", "install", module]))
        await proc.communicate()
