''' Example script for running the YARA Language Server on a specific host/port '''
#!/usr/bin/env python3
import argparse
import asyncio
import logging
import logging.handlers
from os import environ
from pathlib import Path

from yarals.yarals import YaraLanguageServer

try:
    # asyncio exceptions changed from 3.6 > 3.7 > 3.8
    # so try to keep this compatible regardless of Python version 3.6+
    # https://medium.com/@jflevesque/asyncio-exceptions-changes-from-python-3-6-to-3-7-to-3-8-cancellederror-timeouterror-f79945ead378
    from asyncio import CancelledError
except ImportError:
    from concurrent.futures import CancelledError


def _build_cli():
    # default log file path is ~/.yara.log
    default_log_path = str(Path(environ.get("HOME")).joinpath(".yara.log"))
    parser = argparse.ArgumentParser(description="Start the YARA language server")
    parser.add_argument("host", help="Interface to bind server to")
    parser.add_argument("port", type=int, help="Port to bind server to")
    parser.add_argument("--log", "-l", default=default_log_path, help="Path to the log file")
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Controls the verbosity of logs sent to the screen. All messages are sent to log file")
    return parser.parse_args()

def _build_logger(log_file: str, verbosity: int=0):
    ''' Configure the loggers appropriately '''
    # rename all the levels to align with the language client's logging format
    for lvl in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        logging.addLevelName(getattr(logging, lvl), lvl.capitalize())
    yara_logger = logging.getLogger("yara")
    screen_hdlr = logging.StreamHandler()
    screen_fmt = logging.Formatter("[%(levelname)-5s - %(asctime)s] %(name)s.%(module)s : %(message)s", datefmt="%-H:%M:%S %p")
    screen_hdlr.setFormatter(screen_fmt)
    screen_log_lvl = logging.ERROR
    if verbosity == 1:
        screen_log_lvl = logging.WARNING
    elif verbosity == 2:
        screen_log_lvl = logging.INFO
    elif verbosity >= 3:
        screen_log_lvl = logging.DEBUG
    screen_hdlr.setLevel(screen_log_lvl)
    file_hdlr = logging.handlers.RotatingFileHandler(filename=log_file, backupCount=1, maxBytes=100000)
    file_hdlr.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s | %(message)s"))
    file_hdlr.setLevel(logging.DEBUG)
    yara_logger.addHandler(screen_hdlr)
    yara_logger.addHandler(file_hdlr)
    yara_logger.setLevel(logging.DEBUG)
    return yara_logger

async def run_server():
    ''' Program entrypoint '''
    args = _build_cli()
    logger = _build_logger(args.log, args.verbose)
    try:
        yarals = YaraLanguageServer()
        logger.info("Starting YARA IO language server")
        socket_server = await asyncio.start_server(
            client_connected_cb=yarals.handle_client,
            host=args.host,
            port=args.port,
            start_serving=False
        )
        servhost, servport = socket_server.sockets[0].getsockname()
        logger.info("Serving on tcp://%s:%d", servhost, servport)
        try:
            async with socket_server:
                await socket_server.serve_forever()
        except CancelledError:
            logger.info("Server has successfully shutdown")
    except KeyboardInterrupt:
        logger.info("Ending per user request")

def main():
    ''' A wrapper to launch main() as a coroutine '''
    asyncio.run(run_server(), debug=True)


if __name__ == "__main__":
    run_server()
