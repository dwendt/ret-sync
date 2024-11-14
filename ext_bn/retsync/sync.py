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
from typing import TYPE_CHECKING, Any
import binaryninja
import binaryninjaui
import PySide6

from PySide6.QtCore import Qt

from binaryninjaui import DockHandler
from binaryninjaui import UIActionHandler, UIContext, UIContextNotification

from collections import OrderedDict
import socket
import io
import sys
import asyncore
import threading
import json
import base64

from pathlib import Path as RemotePath
from dataclasses import dataclass
from binaryninja import BinaryView

if TYPE_CHECKING:
    from .retsync.rswidget import SyncWidget

from .retsync import rsconfig as rsconfig
from .retsync.rsconfig import (
    rs_encode,
    rs_decode,
    rs_log,
    rs_debug,
    load_configuration,
    rs_warn,
)


class SyncHandler(object):

    # location request, update disassembly view
    def req_loc(self, sync):
        offset, base = sync["offset"], sync.get("base")
        self.plugin.goto(base, offset)

    def req_rbase(self, sync):
        self.plugin.set_remote_base(sync["rbase"])

    def req_cmt(self, sync):
        offset, base, cmt = sync["offset"], sync.get("base"), sync["msg"]
        self.plugin.add_cmt(base, offset, cmt)

    def req_fcmt(self, sync):
        offset, base, cmt = sync["offset"], sync.get("base"), sync["msg"]
        self.plugin.add_fcmt(base, offset, cmt)

    def req_rcmt(self, sync):
        offset, base = sync["offset"], sync.get("base")
        self.plugin.reset_cmt(base, offset)

    def req_cmd(self, sync):
        msg_b64, offset, base = sync["msg"], sync["offset"], sync["base"]
        cmt = rs_decode(base64.b64decode(msg_b64))
        self.plugin.add_cmt(base, offset, cmt)

    def req_cursor(self, sync):
        cursor_addr = self.get_cursor()
        if cursor_addr:
            self.client.send(rs_encode(hex(cursor_addr)))
        else:
            rs_log("failed to get cursor location")

    def req_not_implemented(self, sync):
        rs_log(f"request type {sync['type']} not implemented")

    def parse(self, client, sync):
        self.client = client
        stype = sync["type"]
        if stype not in self.req_handlers:
            rs_log("unknown sync request: %s" % stype)
            return

        if not self.plugin.sync_enabled:
            rs_debug("[-] %s request droped because no program is enabled" % stype)
            return

        req_handler = self.req_handlers[stype]
        req_handler(sync)

    def __init__(self, plugin):
        self.plugin = plugin
        self.client = None
        self.req_handlers = {
            "loc": self.req_loc,
            "rbase": self.req_rbase,
            "cmd": self.req_cmd,
            "cmt": self.req_cmt,
            "rcmt": self.req_rcmt,
            "fcmt": self.req_fcmt,
            "cursor": self.req_cursor,
            "raddr": self.req_not_implemented,
            "patch": self.req_not_implemented,
            "rln": self.req_not_implemented,
            "rrln": self.req_not_implemented,
            "lbl": self.req_not_implemented,
            "bps_get": self.req_not_implemented,
            "bps_set": self.req_not_implemented,
            "modcheck": self.req_not_implemented,
        }


class NoticeHandler(object):

    def is_windows_dbg(self, dialect):
        return dialect in ["windbg", "x64_dbg", "ollydbg2"]

    def req_new_dbg(self, notice):
        dialect = notice["dialect"]
        rs_log(f"new_dbg: {notice['msg']}")
        self.plugin.bootstrap(dialect)

        if sys.platform.startswith("linux") or sys.platform == "darwin":
            if self.is_windows_dbg(dialect):
                global RemotePath
                from pathlib import PureWindowsPath as RemotePath

    def req_dbg_quit(self, notice):
        self.plugin.reset_client()

    def req_dbg_err(self, notice):
        self.plugin.sync_enabled = False
        rs_log("dbg err: disabling current program")

    def req_module(self, notice):
        pgm: RemotePath = RemotePath(notice["path"])
        if not self.plugin.sync_mode_auto:
            rs_log(f"sync mod auto off, dropping mod request ({pgm})")
        else:
            self.plugin.set_program(pgm)

    def req_idb_list(self, notice):
        output = "open program(s):\n"
        for i, pgm in enumerate(self.plugin.pgm_mgr.as_list()):
            is_active = " (*)" if pgm.path.name == self.plugin.current_pgm else ""
            output += f"[{i}] {str(pgm.path.name)} {is_active}\n"

        self.plugin.broadcast(output)

    def req_idb_n(self, notice):
        idb = notice["idb"]
        try:
            idbn = int(idb)
        except (TypeError, ValueError):
            self.plugin.broadcast("> index error: n should be a decimal value")
            return

        self.plugin.set_program_id(idbn)

    def req_sync_mode(self, notice):
        mode = notice["auto"]
        rs_log(f"sync mode auto: {mode}")
        if mode == "on":
            self.plugin.sync_mode_auto = True
        elif mode == "off":
            self.plugin.sync_mode_auto = False
        else:
            rs_log(f"sync mode unknown: {mode}")

    def req_bc(self, notice):
        action = notice["msg"]

        if action == "on":
            self.plugin.cb_trace_enabled = True
            rs_log("color trace enabled")
        elif action == "off":
            self.plugin.cb_trace_enabled = False
            rs_log("color trace disabled")
        elif action == "oneshot":
            self.plugin.cb_trace_enabled = True

    def parse(self, notice):
        ntype = notice["type"]
        if ntype not in self.req_handlers:
            rs_log(f"unknown notice request: {str(ntype)}")
            return

        req_handler = self.req_handlers[ntype]
        req_handler(notice)

    def __init__(self, plugin):
        self.plugin = plugin
        self.req_handlers = {
            "new_dbg": self.req_new_dbg,
            "dbg_quit": self.req_dbg_quit,
            "dbg_err": self.req_dbg_err,
            "module": self.req_module,
            "idb_list": self.req_idb_list,
            "sync_mode": self.req_sync_mode,
            "idb_n": self.req_idb_n,
            "bc": self.req_bc,
        }


class RequestType(object):
    NOTICE = "[notice]"
    SYNC = "[sync]"

    @staticmethod
    def extract(request):
        if request.startswith(RequestType.NOTICE):
            return RequestType.NOTICE
        elif request.startswith(RequestType.SYNC):
            return RequestType.SYNC
        else:
            return None

    @staticmethod
    def normalize(request, tag):
        request = request[len(tag) :]
        request = request.replace("\\", "\\\\")
        request = request.replace("\n", "")
        return request.strip()


class RequestHandler(object):

    def __init__(self, plugin):
        self.plugin = plugin
        self.client_lock = threading.Lock()
        self.notice_handler = NoticeHandler(plugin)
        self.sync_handler = SyncHandler(plugin)

    def safe_parse(self, client, request):
        self.client_lock.acquire()
        self.parse(client, request)
        self.client_lock.release()

    def parse(self, client, request):
        req_type = RequestType.extract(request)

        if not req_type:
            rs_log("unknown request type")
            return

        payload = RequestType.normalize(request, req_type)

        try:
            req_obj = json.loads(payload)
        except ValueError:
            rs_log("failed to parse request JSON\n %s\n" % payload)
            return

        rs_debug(f"REQUEST{req_type}:{req_obj['type']}")

        if req_type == RequestType.NOTICE:
            self.notice_handler.parse(req_obj)
        elif req_type == RequestType.SYNC:
            self.sync_handler.parse(client, req_obj)


class ClientHandler(asyncore.dispatcher_with_send):

    def __init__(self, sock, request_handler):
        asyncore.dispatcher_with_send.__init__(self, sock)
        self.request_handler = request_handler

    def handle_read(self):
        data = rs_decode(self.recv(8192))

        if data and data != "":
            fd = io.StringIO(data)
            batch = fd.readlines()

            for request in batch:
                self.request_handler.safe_parse(self, request)
        else:
            rs_debug("handler lost client")
            self.close()

    def handle_expt(self):
        rs_log("client error")
        self.close()

    def handle_close(self):
        rs_log("client quit")
        self.close()


class ClientListener(asyncore.dispatcher):

    def __init__(self, plugin: "SyncPlugin"):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind((plugin.user_conf.host, plugin.user_conf.port))
        self.listen(1)
        self.plugin = plugin

    def handle_accept(self):
        pair = self.accept()
        if not pair:
            return

        sock, addr = pair
        rs_log(f"incoming connection from {addr!r}")
        self.plugin.client = ClientHandler(sock, self.plugin.request_handler)

    def handle_expt(self):
        rs_log("listener error")
        self.close()

    def handle_close(self):
        rs_log("listener close")
        self.close()


class ClientListenerTask(threading.Thread):

    def __init__(self, plugin: "SyncPlugin"):
        threading.Thread.__init__(self)
        self.plugin = plugin
        self.server = None

    def is_port_available(self, host: str, port: int):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if sys.platform == "win32":
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind((host, port))
            return True
        except Exception as e:
            rs_log(f"bind() failed, reason: {str(e)}")
            return False
        finally:
            sock.close()

    def run(self):
        if not self.is_port_available(
            self.plugin.user_conf.host, self.plugin.user_conf.port
        ):
            rs_log(f"aborting, port {self.plugin.user_conf.port} already in use")
            self.plugin.cmd_syncoff()
            return

        rs_debug(
            f"starting server on {self.plugin.user_conf.host}:{self.plugin.user_conf.port}"
        )

        try:
            self.server = ClientListener(self.plugin)
            self.plugin.reset_client()
            rs_log("server started")
            asyncore.loop()
        except Exception as e:
            rs_log(f"server initialization failed, reason: {str(e)}")
            self.cancel()
            self.plugin.cmd_syncoff()

    def cancel(self):
        if self.server:
            rs_log("server shutdown")
            asyncore.close_all()
            self.server.close()
            self.server = None


@dataclass
class Program:
    path: pathlib.Path
    base: int = None
    refcount: int = 1

    def lock(self):
        self.refcount += 1

    def release(self):
        self.refcount -= 1
        return self.refcount == 0


# ProgramManager is used to keep track of opened tabs
# and programs' state (e.g. base address)
class ProgramManager(object):
    def __init__(self):
        self.opened: OrderedDict[pathlib.Path, Program] = OrderedDict()

    def add(self, fpath: pathlib.Path):
        if fpath.name in self.opened:
            rs_log(
                f'name collision ({fpath.name}):\n  - new:      "{fpath}"\n  - existing: "{self.opened[fpath.name].path}"'
            )
            rs_log("warning, tab switching may not work as expected")
            self.opened[fpath].lock()
        else:
            self.opened[fpath] = Program(fpath)

    def remove(self, fpath: pathlib.Path):
        if fpath not in self.opened:
            return
        if self.opened[fpath].release():
            del self.opened[fpath]

    def exists(self, pgm: pathlib.Path):
        return pgm.name in self.opened

    def reset_bases(self):
        for _, pgm in self.opened.items():
            pgm.base = None

    def get_base(
        self,
        pgm: pathlib.Path,
    ):
        if self.exists(pgm):
            return self.opened[pgm].base

    def set_base(self, pgm: pathlib.Path, base: int):
        if self.exists(pgm):
            self.opened[pgm].base = base

    def get_at(self, index: int) -> pathlib.Path | None:
        if len(self.opened) > index:
            return list(self.opened)[index]
        else:
            return None

    def as_list(self) -> OrderedDict[pathlib.Path, Program]:
        return self.opened.values()

    def list_dyn(self):
        self.opened = {}
        ctx: binaryninjaui.UIContext = binaryninjaui.UIContext.activeContext()
        for path_str, bv in ctx.getAvailableBinaryViews():
            assert isinstance(path_str, str)
            assert isinstance(bv, binaryninja.BinaryView)
            self.add(path_str)
        return self.opened


class SyncPlugin:

    def __init__(self):
        # UIContextNotification.__init__(self)
        # UIContext.registerNotification(self)

        self.request_handler = RequestHandler(self)
        self.client_listener = None
        self.client = None
        self.user_conf = None
        self.next_tab_lock = threading.Event()
        self.pgm_mgr = ProgramManager()

        # binary ninja objects
        self.widget: "SyncWidget" | None = None
        self.view_frame = None
        self.view = None
        self.binary_view: BinaryView | None = None
        self.frame = None

        # context
        self.current_tab = None
        self.current_pgm = None
        self.target_tab = None
        self.base: int | None = None
        self.base_remote: int | None = None
        self.sync_enabled = False
        self.sync_mode_auto = True
        self.cb_trace_enabled = False
        self.data: Any | None = None
        self.dbg_dialect: dict[str, dict[str, str]] = {}

    def update_view(self, bv: BinaryView, tab_name: str):
        rs_debug(f"[SyncPlugin::update_view] {bv=} {tab_name=}")

        # if there's no view, do nothing
        if not bv:
            return

        # if the view is the same, do nothing
        if bv == self.binary_view:
            return

        # if the view is not in the program manager, add it
        fname = bv.file.original_filename
        fpath = pathlib.Path(fname)
        if not self.pgm_mgr.exists(fpath):
            self.pgm_mgr.add(fpath)

        self.binary_view = bv
        self.current_tab = fpath.name
        self.base = self.binary_view.start
        self.base_remote = self.pgm_mgr.get_base(self.current_tab)
        if self.base_remote:
            rs_log(f"setting remote base to {self.base_remote:#x}")

        self.pgm_target()

    def bootstrap(self, dialect: str):
        self.pgm_mgr.reset_bases()
        self.widget.set_connected(dialect)

        if dialect in rsconfig.DBG_DIALECTS:
            self.dbg_dialect = rsconfig.DBG_DIALECTS[dialect]
            rs_log("set debugger dialect to %s, enabling hotkeys" % dialect)

    def reset_client(self):
        self.sync_enabled = False
        self.cb_trace_enabled = False
        self.current_pgm = None
        self.widget.reset_client()

    def broadcast(self, msg):
        self.client.send(rs_encode(msg))
        rs_log(msg)

    def set_program(self, pgm: pathlib.Path):
        self.widget.set_program(pgm)
        if not self.pgm_mgr.exists(pgm):
            return
        self.sync_enabled = True
        self.current_pgm = pgm
        rs_log(f"set current program: {pgm}")
        self.pgm_target_with_lock(pgm)

    def set_program_id(self, index: int):
        pgm = self.pgm_mgr.get_at(index)
        if pgm:
            self.broadcast(f'> active program is now "{pgm}" ({index})')
            self.pgm_target_with_lock(pgm)
        else:
            self.broadcast(f"> idb_n error: index {index} is invalid (see idblist)")

    def pgm_target_with_lock(self, pgm=None):
        self.next_tab_lock.clear()
        self.pgm_target(pgm)
        self.next_tab_lock.wait()

    def restore_tab(self):
        if self.current_tab == self.current_pgm:
            return True

        if not self.pgm_mgr.exists(self.current_pgm):
            return False
        else:
            self.pgm_target_with_lock(self.current_pgm)
            return True

    def pgm_target(self, pgm=None):
        if pgm:
            self.target_tab = pgm

        if not self.target_tab:
            return

        try:
            if self.target_tab != self.current_tab:
                self.trigger_action("Next Tab")
            else:
                self.target_tab = None
                self.next_tab_lock.set()
        except Exception as e:
            rs_log(f"error while switching tabs, reason: {str(e)}")

    def trigger_action(self, action: str):
        handler = UIActionHandler().actionHandlerFromWidget(
            DockHandler.getActiveDockHandler().parent()
        )
        handler.executeAction(action)

    # check if address is within a valid segment
    def is_safe(self, offset):
        return self.binary_view.is_valid_offset(offset)

    # rebase (and update) address with respect to local image base
    def rebase(self, base: int, offset: int) -> None | int:
        if base is not None:
            # check for non-compliant debugger client
            if base > offset:
                rs_log(f"unsafe addr: {base=:#x} > {offset=:#x}")
                return None

            # update base address of remote module
            if self.base_remote != base:
                self.pgm_mgr.set_base(self.current_tab, base)
                self.base_remote = base

            dest = self.rebase_local(offset)
            assert isinstance(dest, int)

        if not self.is_safe(dest):
            rs_log(f"unsafe addr: {dest:#x} not in valid segment")
            return None

        return dest

    # rebase address with respect to local image base
    def rebase_local(self, offset: int):
        if not (self.base == self.base_remote):
            offset = (offset - self.base_remote) + self.base

        return offset

    # rebase address with respect to remote image base
    def rebase_remote(self, offset):
        if not (self.base == self.base_remote):
            offset = (offset - self.base) + self.base_remote

        return offset

    def set_remote_base(self, rbase):
        self.pgm_mgr.set_base(self.current_tab, rbase)
        self.base_remote = rbase

    def goto(self, base, offset):
        if not self.sync_enabled:
            return

        if self.restore_tab():
            goto_addr = self.rebase(base, offset)
            view = self.binary_view.view
            if not self.binary_view.navigate(view, goto_addr):
                rs_log(f"goto {hex(goto_addr)} error")

            if self.cb_trace_enabled:
                self.color_callback(goto_addr)
        else:
            rs_log("goto: no view available")

    def color_callback(self, hglt_addr):
        blocks = self.binary_view.get_basic_blocks_at(hglt_addr)
        for block in blocks:
            block.function.set_user_instr_highlight(hglt_addr, rsconfig.CB_TRACE_COLOR)

    def get_cursor(self):
        if not self.view_frame:
            return None
        offset = self.view_frame.getCurrentOffset()
        return self.rebase_remote(offset)

    def add_cmt(self, base: int, offset: int, cmt: str):
        cmt_addr = self.rebase(base, offset)
        if cmt_addr:
            in_place = self.binary_view.get_comment_at(cmt_addr)
            if in_place:
                cmt = f"{in_place}\n{cmt}"

            self.binary_view.set_comment_at(cmt_addr, cmt)

    def reset_cmt(self, base, offset):
        cmt_addr = self.rebase(base, offset)
        if cmt_addr:
            self.binary_view.set_comment_at(cmt_addr, "")

    def add_fcmt(self, base, offset, cmt):
        if not self.binary_view:
            return

        cmt_addr = self.rebase(base, offset)
        for fn in self.binary_view.get_functions_containing(cmt_addr):
            fn.comment = cmt

    def commands_available(self):
        if self.sync_enabled and self.dbg_dialect:
            return True

        rs_log("commands not available")
        return False

    # send a command to the debugger
    def send_cmd(self, cmd, args, oneshot=False):
        if not self.commands_available():
            return

        if cmd not in self.dbg_dialect:
            rs_log(f"{cmd}: unknown command in dialect")
            return

        cmdline = self.dbg_dialect[cmd]
        if args and args != "":
            cmdline += args
        if oneshot and ("oneshot_post" in self.dbg_dialect):
            cmdline += self.dbg_dialect["oneshot_post"]

        self.client.send(rs_encode(cmdline))

    def send_cmd_raw(
        self,
        cmd,
        args,
    ):
        if not self.commands_available():
            return

        if "prefix" in self.dbg_dialect:
            cmd_pre = self.dbg_dialect["prefix"]
        else:
            cmd_pre = ""

        cmdline = f"{cmd_pre}{cmd} {args}"
        self.client.send(rs_encode(cmdline))

    def send_simple_cmd(self, cmd):
        self.send_cmd(cmd, "")

    def generic_bp(self, bp_cmd: str, oneshot=False):
        ui_addr = self.view_frame.getCurrentOffset()
        if not ui_addr:
            rs_log("failed to get cursor location")
            return

        if not self.base_remote:
            rs_log(
                f"{bp_cmd} failed, remote base of {self.current_pgm} program unknown"
            )
            return

        remote_addr = self.rebase_remote(ui_addr)
        self.send_cmd(bp_cmd, hex(remote_addr), oneshot)

    def cmd_go(self, ctx=None):
        self.send_simple_cmd("go")

    def cmd_si(self, ctx=None):
        self.send_simple_cmd("si")

    def cmd_so(self, ctx=None):
        self.send_simple_cmd("so")

    def cmd_translate(self, ctx=None):
        ui_addr = self.view_frame.getCurrentOffset()
        if not ui_addr:
            rs_log("failed to get cursor location")
            return

        rs_debug(f"translate address {hex(ui_addr)}")
        args = f"{hex(self.base)} {hex(ui_addr)} {self.current_pgm}"
        self.send_cmd_raw("translate", args)

    def cmd_bp(self, ctx=None):
        self.generic_bp("bp")

    def cmd_hwbp(self, ctx=None):
        self.generic_bp("hbp")

    def cmd_bp1(self, ctx=None):
        self.generic_bp("bp1", True)

    def cmd_hwbp1(self, ctx=None):
        self.generic_bp("hbp1", True)

    def cmd_sync(self, ctx=None):
        rs_debug("received command `cmd_sync`")
        if not self.pgm_mgr.opened:
            rs_warn("please open a tab first")
            return

        if self.client_listener:
            rs_warn("already listening")
            return

        self.user_conf = load_configuration()
        self.client_listener = ClientListenerTask(self)
        self.client_listener.start()

    def cmd_syncoff(self, _=None):
        rs_debug("received command `cmd_syncoff`")
        if not self.client_listener:
            rs_warn("not listening")
            return

        self.client_listener.cancel()
        self.client_listener = None
        self.widget.reset_status()
