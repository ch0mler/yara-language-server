'''
A basic implementation of the Language Server Protocol
    https://microsoft.github.io/language-server-protocol/
'''
import asyncio
from enum import IntEnum
import json
import logging

from . import errors as ce
from . import protocol as lsp


class RouteType(IntEnum):
    ''' Type of request being routed '''
    FEATURE = 0     # Language server feature to provide
    EVENT = 1       # Event notification from the client, such as 'didChange', 'didSave', etc.
    COMMAND = 2     # Command to provide

class LanguageServer():
    '''
    Abstracts some of the functions needed to build a JSON-RPC language server
        that is compatible with the Language Server Protocol
    '''
    ENCODING = "utf-8"
    EOL=b"\r\n"
    MAX_LINE = 10000

    def __init__(self):
        ''' Handle the details of the Language Server Protocol '''
        asyncio.get_event_loop().set_exception_handler(self._exc_handler)
        self._logger = logging.getLogger(__name__)
        self.num_clients = 0
        self.command_handlers = {}
        self.event_handlers = {}
        self.request_handlers = {}
        self.running_tasks = {}

    def _exc_handler(self, loop, context: dict):
        ''' Appropriately handle exceptions '''
        try:
            future = context.get("future")
            if future:
                future.result()
        except (ce.ServerExit, KeyboardInterrupt) as err:
            # if one of these two exceptions are encountered
            # then this was an intentional action
            # and it should be reported as informational, not an error
            self._logger.info(err)
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

    def execute_method(self, msg_id: int, method: str, **params) -> asyncio.Task:
        '''Execute a method, such as a definiton or hover provider, as an asynchronous task

        :msg_id: JSON-RPC message ID to map task to
        :method: Provider method to call, such as 'textDocument/definition'
        :params: Additional parameters to be passed to the coroutine

        Returns the task that was created and queued
        '''
        coroutine = self.request_handlers[method]
        task = asyncio.create_task(coroutine(**params))
        self.running_tasks[msg_id] = task
        return task

    async def event_cancel(self, has_started: bool, **kwargs):
        ''' Ignore cancellation requests for now until I can figure out how to cancel tasks '''
        try:
            if has_started:
                message = kwargs.pop("message", {})
                params = message.get("params", {})
                msg_id = int(params.get("id"))
                if msg_id in self.running_tasks:
                    task = self.running_tasks[msg_id]
                    # TODO: figure out the real way to do this
                    # ... I believe I'll just cancel 'event_cancel' every time
                    self._logger.debug("Client requested cancellation for message %d => %s", msg_id, task)
                else:
                    self._logger.debug("Client requested cancellation for message %d, but it is not running", msg_id)
        except ValueError as err:
            self._logger.warning("Could not convert message ID to integer: %s", err)
        except Exception as err:
            self._logger.warning("Ignoring error that occurred during task cancellation: %s", err)

    async def event_did_change(self, has_started: bool, **kwargs):
        '''If file has new unsaved changes, start tracking it as dirty,
           so other commands will continue to work with appropriate text locations
        '''
        message = kwargs.pop("message", {})
        params = message.get("params", {})
        file_uri = params.get("textDocument", {}).get("uri", None)
        if has_started and file_uri:
            self._logger.debug("Adding %s to dirty files list", file_uri)
            dirty_files = kwargs.pop("dirty_files", {})
            for changes in params.get("contentChanges", []):
                # full text is submitted with each change
                change = changes.get("text", None)
                if change:
                    dirty_files[file_uri] = change

    async def event_did_close(self, has_started: bool, **kwargs):
        ''' If file was previously tracked as 'dirty', remove tracking. '''
        message = kwargs.pop("message", {})
        params = message.get("params", {})
        file_uri = params.get("textDocument", {}).get("uri", "")
        if has_started and file_uri:
            dirty_files = kwargs.pop("dirty_files", {})
            # file is no longer dirty after closing
            if file_uri in dirty_files:
                del dirty_files[file_uri]
                self._logger.debug("Removed %s from dirty files list", file_uri)

    async def event_did_save(self, has_started: bool, **kwargs):
        '''If file was previously tracked as 'dirty', remove tracking.
           If 'compile_on_save' is True, analyze saved document and publish diagnostics
        '''
        message = kwargs.pop("message", {})
        params = message.get("params", {})
        file_uri = params.get("textDocument", {}).get("uri", "")
        if has_started and file_uri:
            dirty_files = kwargs.pop("dirty_files", {})
            # file is no longer dirty after saving
            if file_uri in dirty_files:
                del dirty_files[file_uri]
                self._logger.debug("Removed %s from dirty files list", file_uri)

    async def event_exit(self, has_started: bool, **kwargs):
        ''' Remove client (StreamWriter) from the list of tracked clients and exit process '''
        if has_started:
            # first remove the client associated with this handler
            writer = kwargs.pop("writer")
            await self.remove_client(writer)
            raise ce.ServerExit("Server exiting process per client request")

    async def read_request(self, reader: asyncio.StreamReader) -> dict:
        ''' Read data from the client '''
        # we don't want handle_client() to deal with anything other than dicts
        request = {}
        data = await reader.readline()
        if data:
            # self._logger.debug("header <= %r", data)
            key, value = tuple(data.decode(self.ENCODING).strip().split(" "))
            # read the extra separator after the initial header
            await reader.readuntil(separator=self.EOL)
            if key == "Content-Length:":
                data = await reader.readexactly(int(value))
            else:
                data = await reader.readline()
            self._logger.debug("input <= %r", data)
            request = json.loads(data.decode(self.ENCODING))
        return request

    async def remove_client(self, writer: asyncio.StreamWriter):
        ''' Close the cient input & output streams '''
        if writer.can_write_eof():
            writer.write_eof()
        writer.close()
        await writer.wait_closed()
        self._logger.info("Disconnected client")

    def resolve_tasks(self):
        ''' Remove cancelled or finished tasks from the running tasks list '''
        self._logger.debug("running tasks before cleanup: %s", self.running_tasks)
        completed_tasks = []
        for msg_id, task in self.running_tasks.items():
            if task.done():
                self._logger.debug("Task %s has finished. Removing from running tasks", task)
                completed_tasks.append(msg_id)
            elif task.cancelled():
                self._logger.debug("Task %s has been cancelled. Removing from running tasks", task)
                completed_tasks.append(msg_id)
            else:
                self._logger.debug("Task %s is still running. Doing nothing", task)
        for msg_id in completed_tasks:
            del self.running_tasks[msg_id]
        self._logger.debug("running tasks after cleanup: %s", self.running_tasks)

    def route(self, request: str, method, request_type: RouteType=RouteType.FEATURE):
        '''Route JSON-RPC requests to the appropriate method

        :request: string. Request type being sent by client
        :method: function. Method to call when request is encountered
        :request_type: string. Type of request being handled.
        '''
        method_object_name = method.__self__.__class__.__name__
        logging.debug("Routing '%s' to '%s.%s()'", request, method_object_name, method.__name__)
        if request_type == RouteType.EVENT:
            self.event_handlers[request] = method
        elif request_type == RouteType.COMMAND:
            self.command_handlers[request] = method
        elif request_type == RouteType.FEATURE:
            self.request_handlers[request] = method

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
        self._logger.debug("output => %r", message.encode(self.ENCODING))
        writer.write("Content-Length: {:d}\r\n\r\n{:s}".format(len(message), message).encode(self.ENCODING))
        await writer.drain()
