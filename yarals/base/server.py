'''
A basic implementation of the Language Server Protocol
    https://microsoft.github.io/language-server-protocol/
'''
import asyncio
import json
import logging
from functools import wraps

from . import errors as ce
from . import protocol as lsp


def route(request):
    '''
    Decorator to route JSON-RPC requests to the appropriate method

    Usage:
        @server.route("textDocument/completion")
        def provide_code_completion(self, *args, **kwargs)
    '''
    def wrapper(func):
        @wraps(func)
        def _wrap_route(self, *args, **kwargs):
            logging.info("@server.route('%s'): %s, %s", request, args, kwargs)
            return func(self, *args, **kwargs)
        return _wrap_route
    return wrapper

class LanguageServer():
    '''
    Abstracts some of the functions needed to build a JSON-RPC language server
        that is compatible with the Language Server Protocol
    '''
    MAX_LINE = 10000

    def __init__(self):
        ''' Handle the details of the Language Server Protocol '''
        asyncio.get_event_loop().set_exception_handler(self._exc_handler)
        self._encoding = "utf-8"
        self._eol=b"\r\n"
        self._logger = logging.getLogger(__name__)
        self.num_clients = 0

    def _exc_handler(self, loop, context: dict):
        ''' Appropriately handle exceptions '''
        try:
            future = context.get("future")
            if future:
                future.result()
        except (ce.ServerExit, KeyboardInterrupt) as err:
            self._logger.error(err)
            # drop all clients
            self.num_clients = 0
            # ... and cancel all running tasks
            if not future.done():
                future.cancel()
            for task in asyncio.all_tasks(loop):
                task.cancel()
        except ConnectionResetError:
            self._logger.error("Client disconnected unexpectedly. Removing client")
            if not future.done():
                future.cancel()
            self.num_clients -= 1
        except Exception as err:
            self._logger.critical("Unknown exception encountered. Continuing on")
            self._logger.exception(err)

    async def read_request(self, reader: asyncio.StreamReader) -> dict:
        ''' Read data from the client '''
        # we don't want handle_client() to deal with anything other than dicts
        request = {}
        data = await reader.readline()
        if data:
            # self._logger.debug("header <= %r", data)
            key, value = tuple(data.decode(self._encoding).strip().split(" "))
            # read the extra separator after the initial header
            await reader.readuntil(separator=self._eol)
            if key == "Content-Length:":
                data = await reader.readexactly(int(value))
            else:
                data = await reader.readline()
            self._logger.debug("input <= %r", data)
            request = json.loads(data.decode(self._encoding))
        return request

    async def remove_client(self, writer: asyncio.StreamWriter):
        ''' Close the cient input & output streams '''
        if writer.can_write_eof():
            writer.write_eof()
        writer.close()
        await writer.wait_closed()
        self._logger.info("Disconnected client")

    async def send_error(self, code: int, curr_id: int, msg: str, writer: asyncio.StreamWriter):
        ''' Write back a JSON-RPC error message to the client '''
        message = json.dumps({
            "jsonrpc": "2.0",
            "id": curr_id,
            "error": {
                "code": code,
                "message": msg
            }
        }, cls=lsp.JSONEncoder)
        await self.write_data(message, writer)

    async def send_notification(self, method: str, params: dict, writer: asyncio.StreamWriter):
        ''' Write back a JSON-RPC notification to the client '''
        message = json.dumps({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }, cls=lsp.JSONEncoder)
        await self.write_data(message, writer)

    async def send_response(self, curr_id: int, response: dict, writer: asyncio.StreamWriter):
        ''' Write back a JSON-RPC response to the client '''
        message = json.dumps({
            "jsonrpc": "2.0",
            "id": curr_id,
            "result": response,
        }, cls=lsp.JSONEncoder)
        await self.write_data(message, writer)

    async def write_data(self, message: str, writer: asyncio.StreamWriter):
        ''' Write a JSON-RPC message to the given stream with the proper encoding and formatting '''
        self._logger.debug("output => %r", message.encode(self._encoding))
        writer.write("Content-Length: {:d}\r\n\r\n{:s}".format(len(message), message).encode(self._encoding))
        await writer.drain()
