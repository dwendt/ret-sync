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

import binaryninja

if not binaryninja.core_ui_enabled:
    raise RuntimeError("UI only")

if not binaryninja.core_version_info().major < 4:
    raise RuntimeError("Binary Ninja 4.x+ required")

from binaryninjaui import Sidebar

from .retsync.config import (
    DEFAULT_HOST,
    DEFAULT_LOG_FILE,
    DEFAULT_PORT,
    DEFAULT_TRACE_COLOR,
    LOG_LEVEL,
    rs_debug,
)
from .retsync.ui import SyncSidebarWidgetType

# TODO
# - fix tab switch
# - better tests
# - better icons


def register_retsync_settings() -> None:
    all_settings: dict[str, str] = {
        "ServerHost": f"""{{ "title" : "TCP Listen Host", "description" : "Interface to listen on", "type" : "string", "default" : "{DEFAULT_HOST}", "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]}}""",
        "ServerPort": f"""{{ "title" : "TCP Listen Port", "description" : "TCP port to listen on", "type" : "number", "minValue": 1, "maxValue": 65535,  "default" : {DEFAULT_PORT}, "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]}}""",
        "TraceColor": f"""{{ "title" : "Current Instruction Color", "description" : "When synchronized, use the following color for highlight the current instruction. The valid values are: none, blue, cyan, red, magenta, yellow, orange, white, black", "type" : "string", "default" : "{DEFAULT_TRACE_COLOR}", "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]}}""",
        "Aliases": """{ "title" : "Module name aliases", "description" : "List of all aliases to bind the modules. This is useful when debugged modules have a different name from their image. The syntax for each item: 'imagename:aliasname' (e.g. aliasing ntkrnlmp to ntoskrnl would become 'ntkrnlmp.exe:ntoskrnl.exe' )", "type" : "array", "elementType": "string", "sorted": true, "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]}""",
        "LogFile": f"""{{ "title" : "Write logs to file", "description" : "Write RetSync logs to the given file", "type" : "string", "defaults":"{DEFAULT_LOG_FILE}", "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]}}""",
    }

    settings = binaryninja.Settings()
    if not settings.register_group("retsync", "retsync"):
        raise RuntimeWarning("Failed to register group setting")

    for name, value in all_settings.items():
        if not settings.register_setting(f"retsync.{name}", value):
            raise RuntimeWarning(f"Failed to register setting {name}")


register_retsync_settings()

if logfile := binaryninja.Settings().get_string("retsync.LogFile"):
    binaryninja.log.log_to_file(LOG_LEVEL, logfile, True)

rs_debug("Loading RetSync sidebar")
st = SyncSidebarWidgetType()
Sidebar.addSidebarWidgetType(st)
