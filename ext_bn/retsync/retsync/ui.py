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

import enum
import pathlib

import binaryninja
from binaryninjaui import (
    SidebarContextSensitivity,
    SidebarWidget,
    SidebarWidgetLocation,
    SidebarWidgetType,
    UIActionHandler,
)
from PySide6 import QtCore
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QIcon, QImage, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QToolBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ..sync import SyncPlugin
from .log import rs_debug

CURRENT_FILE = pathlib.Path(__file__)
CURRENT_FOLDER = CURRENT_FILE.parent
ASSETS_FOLDER = CURRENT_FOLDER / "assets"


class SyncStatus(enum.IntEnum):
    IDLE = 1
    LISTENING = 2
    CONNECTED = 3


class SyncWidget(QWidget):
    def __init__(self, parent: QWidget):
        QWidget.__init__(self, parent)

        rs_debug("building SyncWidget()")
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel("Status: "))
        self.status = QLabel("idle")
        status_layout.addWidget(self.status)
        status_layout.setAlignment(QtCore.Qt.AlignCenter)

        client_dbg_layout = QHBoxLayout()
        client_dbg_layout.addWidget(QLabel("Client debugger: "))
        self.client_dbg = QLabel("n/a")
        client_dbg_layout.addWidget(self.client_dbg)
        client_dbg_layout.setAlignment(QtCore.Qt.AlignCenter)

        client_pgm_layout = QHBoxLayout()
        client_pgm_layout.addWidget(QLabel("Currently debugged module: "))
        self.client_pgm = QLabel("n/a")
        client_pgm_layout.addWidget(self.client_pgm)
        client_pgm_layout.setAlignment(QtCore.Qt.AlignCenter)

        layout = QVBoxLayout()
        layout.addStretch()
        layout.addLayout(status_layout)
        layout.addLayout(client_dbg_layout)
        layout.addLayout(client_pgm_layout)
        layout.addStretch()
        self.setLayout(layout)

    def set_status(self, status: SyncStatus):
        match status:
            case SyncStatus.CONNECTED:
                self.status.setStyleSheet("color: green")
            case SyncStatus.LISTENING:
                self.status.setStyleSheet("color: blue")
            case _:
                self.status.setStyleSheet("")

        self.status.setText(status.name)

    def set_connected(self, dialect: str):
        self.set_status(SyncStatus.CONNECTED)
        self.client_dbg.setText(dialect)

    def set_program(self, pgm: pathlib.Path):
        text = pgm.name
        aliases = dict(
            [
                x.split(":", 1)
                for x in binaryninja.Settings().get_string_list("retsync.Aliases")
            ]
        )
        for original_module_name, aliased_module_name in aliases.items():
            if text == aliased_module_name:
                text += f" (alias for {original_module_name})"
                break
        self.client_pgm.setText(text)

    def reset_client(self):
        self.set_status(SyncStatus.LISTENING)
        self.client_pgm.setText("n/a")
        self.client_dbg.setText("n/a")

    def reset_status(self):
        self.set_status(SyncStatus.IDLE)
        self.client_pgm.setText("n/a")
        self.client_dbg.setText("n/a")


def open_file_as_icon(path: pathlib.Path) -> QImage:
    pixmap = QPixmap(path)
    icon = QIcon()
    icon.addPixmap(pixmap, QIcon.Normal)
    icon.addPixmap(pixmap, QIcon.Disabled)
    return icon


class SyncControlWidget(QWidget):
    def __init__(self, parent: QWidget, plugin: SyncPlugin):
        QWidget.__init__(self, parent)
        self.parent = parent
        self.rs: SyncPlugin = plugin

        self.toolbar = QToolBar(self, parent)
        self.toolbar.setStyleSheet("QToolBar{spacing:0px;}")
        maxheight = 24

        # ----
        self.toolbar.btnStart = QToolButton(self.toolbar)
        self.toolbar.btnStart.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.toolbar.btnStart.setMaximumHeight(maxheight)

        self.toolbar.btnStart.actionStart = QAction("Start Sync", self.toolbar)
        self.toolbar.btnStart.actionStart.triggered.connect(self.rs.cmd_sync)
        self.toolbar.btnStart.actionStart.setIcon(
            open_file_as_icon(ASSETS_FOLDER / "icon.svg")
        )

        self.toolbar.btnStart.setDefaultAction(self.toolbar.btnStart.actionStart)
        self.toolbar.addWidget(self.toolbar.btnStart)
        # ----

        # ----
        self.toolbar.btnStopInto = QToolButton(self.toolbar)
        self.toolbar.btnStopInto.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.toolbar.btnStopInto.setMaximumHeight(maxheight)

        self.toolbar.btnStopInto.actionStep = QAction("Stop Sync", self.toolbar)
        self.toolbar.btnStopInto.actionStep.triggered.connect(self.rs.cmd_syncoff)
        self.toolbar.btnStopInto.actionStep.setIcon(
            open_file_as_icon(ASSETS_FOLDER / "icon.svg")
        )

        self.toolbar.btnStopInto.setDefaultAction(self.toolbar.btnStopInto.actionStep)
        self.toolbar.addWidget(self.toolbar.btnStopInto)
        # ----

        # TODO handle the other commands from `SyncPlugin`

        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        self.layout = QVBoxLayout()
        self.layout.addWidget(self.toolbar)
        self.setLayout(self.layout)

    def stateInit(self, arch, state):
        pass

    def stateReset(self):
        pass

    def stateUpdate(self, state):
        pass

    def notifytab(self, newName):
        pass

    def notifyOffsetChanged(self, offset):
        pass

    def shouldBeVisible(self, view_frame):
        return view_frame is not None


class SyncSideBarWidget(SidebarWidget):
    initSignal = QtCore.Signal(object, object)

    def __init__(self, name, _frame, _data):
        SidebarWidget.__init__(self, name)
        self.initSignal.connect(self.stateInit)
        self.rs = SyncPlugin()
        self.control_widget = SyncControlWidget(self, self.rs)
        self.info_widget = SyncWidget(self)
        self.rs.widget = self.info_widget

        self.layout = QVBoxLayout()
        self.layout.addWidget(self.control_widget)
        self.layout.addWidget(self.info_widget)
        self.layout.setSpacing(0)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(self.layout)

    def stateInit(self):
        self.info_widget.reset_status()
        rs_debug(
            f"[stateInit] {self.info_widget.client_dbg=} , {self.info_widget.client_pgm=}"
        )

    def notifyViewChanged(self, view_frame):
        new_name: str = view_frame.getTabName() if view_frame else ""
        new_bv = view_frame.getCurrentBinaryView() if view_frame else None

        rs_debug(f"[notifyViewChanged] {new_name=} , {new_bv=}")
        self.rs.update_view(new_bv, new_name)


class SyncSidebarWidgetType(SidebarWidgetType):
    name = "RetSync Manager"

    def __init__(self):
        path_icon = ASSETS_FOLDER / "icon.svg"

        renderer = QSvgRenderer(path_icon.as_posix())
        icon = QImage(56, 56, QImage.Format_ARGB32)
        icon.fill(0x463F3F)

        p = QPainter(icon)
        renderer.render(p)
        p.end()
        SidebarWidgetType.__init__(self, icon, SyncSidebarWidgetType.name)

    def contextSensitivity(self):
        return SidebarContextSensitivity.SelfManagedSidebarContext

    def defaultLocation(self):
        return SidebarWidgetLocation.RightContent

    def createWidget(self, frame, data):
        return SyncSideBarWidget(SyncSidebarWidgetType.name, frame, data)
