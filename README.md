# YARA Language Server

![build_badge](https://github.com/ch0mler/yara-language-server/workflows/build/badge.svg)

An implementation of the Language Server Protocol for the YARA pattern-matching language.

## Features

### Diagnostics

The extension will compile workspace rules in the background and return errors and warnings as you type.

### Definition Provider and Peeking

Allows peeking and Ctrl+clicking to jump to a rule definition. This applies to both rule names and variables.

### Reference Provider

Shows the locations of a given symbol (rule name, variable, constant, etc.).

### Code Completion

Provides completion suggestions for standard YARA modules, including `pe`, `elf`, `math`, and all the others available in the official documentation: http://yara.readthedocs.io/en/v3.7.0/modules.html

## Requirements
Python 3.7 or higher is required due to the heavy use of the `asyncio` library and specific APIs available only since v3.7.

In addition, `yara-python` should be installed. If it is not installed, Diagnostics and Compile commands will not be available.

**Note:** If you are on Windows, you might have to set the `$INCLUDE` environment variable before building this environment, so that when `yara-python` is compiled for your local system, Python knows where to find the appropriate DLLs.
On Windows 10, this would probably look like:
```sh
set INCLUDE="C:\Program Files (x86)\Windows Kits\10\Include" && python3 -m pip install yara-python
```

## Problems?
If you encounter an issue, please feel free to create an issue or pull request!

## YARA Documentation
* [YARA Documentation](https://yara.readthedocs.io/)

## Language Server Protocol
* [JSON RPC Specification](https://www.jsonrpc.org/specification)
* [Language Server Protocol Specification](https://microsoft.github.io/language-server-protocol/specification)
* [VSCode Example Language Server](https://code.visualstudio.com/docs/extensions/example-language-server)