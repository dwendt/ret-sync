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

from .retsync.config import LOG_LEVEL, LOG_TO_FILE_ENABLE, rs_info

# TODO
# - require Binja 4.x+
# - better sync / tab mgmt
# - better tests
# - better icons

if binaryninja.core_ui_enabled:
    from binaryninjaui import Sidebar

    from .retsync.ui import SyncSidebarWidgetType

    if LOG_TO_FILE_ENABLE:
        log_fpath = pathlib.Path(tempfile.gettempdir()) / "retsync.log"
        binaryninja.log.log_to_file(LOG_LEVEL, str(log_fpath.absolute()), True)

    rs_info("Loading RetSync")
    st = SyncSidebarWidgetType()
    Sidebar.addSidebarWidgetType(st)
