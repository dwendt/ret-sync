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
import binaryninjaui
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
        # self.actionHandler = UIActionHandler()
        # self.actionHandler.setupActionHandler(self)

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
    def __init__(self, parent: QWidget):
        QWidget.__init__(self, parent)

        assert isinstance(parent, SyncSideBarWidget)
        self.rs: SyncPlugin = self.parent().rs

        self._toolbar = QToolBar(self)
        self._toolbar.setStyleSheet("QToolBar{spacing:0px;}")
        maxheight = 24

        # Start Sync button
        self._toolbar.btnStart = QToolButton(self._toolbar)
        self._toolbar.btnStart.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self._toolbar.btnStart.setMaximumHeight(maxheight)
        self._toolbar.btnStart.actionStart = QAction("Start Sync", self._toolbar)
        self._toolbar.btnStart.actionStart.triggered.connect(self.rs.cmd_sync)
        self._toolbar.btnStart.actionStart.setIcon(
            open_file_as_icon(ASSETS_FOLDER / "icon.svg")
        )
        self._toolbar.btnStart.setDefaultAction(self._toolbar.btnStart.actionStart)
        self._toolbar.addWidget(self._toolbar.btnStart)

        # Stop Sync button
        self._toolbar.btnStopInto = QToolButton(self._toolbar)
        self._toolbar.btnStopInto.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self._toolbar.btnStopInto.setMaximumHeight(maxheight)
        self._toolbar.btnStopInto.actionStop = QAction("Stop Sync", self._toolbar)
        self._toolbar.btnStopInto.actionStop.triggered.connect(self.rs.cmd_syncoff)
        self._toolbar.btnStopInto.actionStop.setIcon(
            open_file_as_icon(ASSETS_FOLDER / "icon.svg")
        )
        self._toolbar.btnStopInto.setDefaultAction(self._toolbar.btnStopInto.actionStop)
        self._toolbar.addWidget(self._toolbar.btnStopInto)

        # Step Into button
        self._toolbar.btnStepInto = QToolButton(self._toolbar)
        self._toolbar.btnStepInto.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self._toolbar.btnStepInto.setMaximumHeight(maxheight)
        self._toolbar.btnStepInto.actionStep = QAction("Step Info", self._toolbar)
        self._toolbar.btnStepInto.actionStep.triggered.connect(self.rs.cmd_si)
        self._toolbar.btnStepInto.actionStep.setIcon(
            open_file_as_icon(ASSETS_FOLDER / "icon.svg")
        )
        self._toolbar.btnStepInto.setDefaultAction(self._toolbar.btnStepInto.actionStep)
        self._toolbar.addWidget(self._toolbar.btnStepInto)

        # Step Over button
        self._toolbar.btnStepOver = QToolButton(self._toolbar)
        self._toolbar.btnStepOver.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self._toolbar.btnStepOver.setMaximumHeight(maxheight)
        self._toolbar.btnStepOver.actionStep = QAction("Step Over", self._toolbar)
        self._toolbar.btnStepOver.actionStep.triggered.connect(self.rs.cmd_so)
        self._toolbar.btnStepOver.actionStep.setIcon(
            open_file_as_icon(ASSETS_FOLDER / "icon.svg")
        )
        self._toolbar.btnStepOver.setDefaultAction(self._toolbar.btnStepInto.actionStep)
        self._toolbar.addWidget(self._toolbar.btnStepOver)

        # Go button
        self._toolbar.btnGo = QToolButton(self._toolbar)
        self._toolbar.btnGo.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self._toolbar.btnGo.setMaximumHeight(maxheight)
        self._toolbar.btnGo.actionGo = QAction("Go", self._toolbar)
        self._toolbar.btnGo.actionGo.triggered.connect(self.rs.cmd_go)
        self._toolbar.btnGo.actionGo.setIcon(
            open_file_as_icon(ASSETS_FOLDER / "icon.svg")
        )
        self._toolbar.btnGo.setDefaultAction(self._toolbar.btnGo.actionGo)
        self._toolbar.addWidget(self._toolbar.btnGo)

        self._layout = QVBoxLayout()
        self._layout.addWidget(self._toolbar)
        self.setLayout(self._layout)


class SyncSideBarWidget(SidebarWidget):
    """See https://github.com/Vector35/binaryninja-api/blob/3659134a2c19191991c582f96fa762599f4def67/python/examples/hellosidebar.py#L36"""

    def __init__(self, name, _frame, _data):
        SidebarWidget.__init__(self, name)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)
        self.rs = SyncPlugin()
        self.control_widget = SyncControlWidget(self)
        self.info_widget = SyncWidget(self)
        self.info_widget.reset_status()
        self.rs.widget = self.info_widget

        self.layout = QVBoxLayout()
        self.layout.addWidget(self.control_widget)
        self.layout.addWidget(self.info_widget)
        self.layout.setSpacing(0)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(self.layout)

    def notifyViewChanged(self, view_frame: binaryninjaui.ViewFrame):
        if not view_frame:
            return
        new_name: str = view_frame.getTabName()
        new_bv: binaryninja.BinaryView = view_frame.getCurrentBinaryView()
        self.rs.update_view(new_bv, new_name)


class SyncSidebarWidgetType(SidebarWidgetType):
    """See https://github.com/Vector35/binaryninja-api/blob/3659134a2c19191991c582f96fa762599f4def67/python/examples/hellosidebar.py#L83"""

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
