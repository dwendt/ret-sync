#!/usr/bin/env python3

"""
Copyright (C) 2020, Alexandre Gazet.

This file is part of ret-sync plugin for Binary Ninja.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import pathlib
import tempfile

import binaryninja

# networking settings
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 9100

DEFAULT_TRACE_COLOR = "green"

# debugging settings
# enable/disable logging JSON received in the IDA output window
DEBUG_JSON = False

# global log level (console output)
DEFAULT_LOG_LEVEL = binaryninja.log.LogLevel.InfoLog

# log prefix to identify plugin
LOG_PREFIX = "retsync"

DEFAULT_LOG_FILE = pathlib.Path(tempfile.gettempdir()) / f"{LOG_PREFIX}.log"

# dialects to translate debugger commands (breakpoint, step into/over, etc.)
DBG_DIALECTS = {
    "windbg": {
        "prefix": "!",
        "si": "t",
        "so": "p",
        "go": "g",
        "bp": "bp ",
        "hbp": "ba e 1 ",
        "bp1": "bp /1 ",
        "hbp1": "ba e 1 /1 ",
    },
    "gdb": {
        "prefix": "",
        "si": "si",
        "so": "ni",
        "go": "continue",
        "bp": "b *",
        "hbp": "hb *",
        "bp1": "tb *",
        "hbp1": "thb *",
    },
    "lldb": {
        "prefix": "",
        "si": "si",
        "so": "ni",
        "go": "continue",
        "run": "run",
        "bp": "b *",
        "hbp": "xxx",
        "bp1": "tb *",
        "hbp1": "xxx",
    },
    "ollydbg2": {
        "prefix": "",
        "si": "si",
        "so": "so",
        "go": "go",
        "bp": "bp ",
        "hbp": "xxx ",
        "bp1": "xxx ",
        "hbp1": "xxx ",
    },
    "x64_dbg": {
        "prefix": "!",
        "si": "sti",
        "so": "sto",
        "go": "go",
        "bp": "bp ",
        "hbp": "bph ",
        "bp1": "bp ",
        "hbp1": "bph ",
        "oneshot_post": ",ss",
    },
}
