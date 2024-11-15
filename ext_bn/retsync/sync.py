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

import asyncore
import base64
import io
import json
import pathlib
import socket
import sys
import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path as RemotePath
from typing import TYPE_CHECKING, Any

import binaryninja
import binaryninjaui
from binaryninja import BinaryView, HighlightColor, HighlightStandardColor

if TYPE_CHECKING:
    from .retsync.ui import SyncWidget

from .retsync import config as config
from .retsync.config import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_TRACE_COLOR,
    rs_decode,
    rs_encode,
)
from .retsync.log import rs_debug, rs_log, rs_warn


class SyncHandler(object):
    # location request, update disassembly view
    def req_loc(self, sync):
        offset, base = sync["offset"], sync.get("base")
        rs_log(f"in SyncHandler::req_loc({base=:#}, {offset=:#x})")
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
        rs_log(f"Request type {sync['type']} not implemented")

    def parse(self, sync):
        # self.client = client
        stype = sync["type"]
        if stype not in self.req_handlers:
            rs_log("Unknown sync request: {stype}")
            return

        if not self.plugin.sync_enabled:
            rs_log(f"[-] {stype} request dropped because no program is enabled")
            return

        rs_log(f"[+] calling {stype} request handler")
        req_handler = self.req_handlers[stype]
        req_handler(sync)

    def __init__(self, plugin: "SyncPlugin"):
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
        fname = notice["path"]
        aliases = dict(
            [
                x.split(":", 1)
                for x in binaryninja.Settings().get_string_list("retsync.Aliases")
            ]
        )

        if fname in aliases:
            rs_debug(f"Resolved alias images {fname } -> { aliases[fname]}")
            fname = aliases[fname]

        pgm = RemotePath(fname)
        if not self.plugin.sync_mode_auto:
            rs_warn(f"sync mod auto off, dropping mod request ({pgm})")
            return

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
    def extract(request: str) -> None | str:
        rs_log(f"received request '{request}'")
        if request.startswith(RequestType.NOTICE):
            return RequestType.NOTICE
        elif request.startswith(RequestType.SYNC):
            return RequestType.SYNC
        else:
            return None

    @staticmethod
    def normalize(request: str, tag: str) -> str:
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
            self.sync_handler.parse(req_obj)


class ClientHandler(asyncore.dispatcher_with_send):
    def __init__(self, sock: "socket.socket", request_handler: "RequestHandler"):
        asyncore.dispatcher_with_send.__init__(self, sock)
        self.request_handler = request_handler

    def handle_read(self):
        data = rs_decode(self.recv(8192))

        if data:
            fd = io.StringIO(data)
            batch = fd.readlines()

            for request in batch:
                self.request_handler.safe_parse(self, request)
        else:
            rs_warn("handler lost client")
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
        settings = binaryninja.Settings()
        host = settings.get_string("retsync.ServerHost") or DEFAULT_HOST
        port = settings.get_integer("retsync.ServerPort") or DEFAULT_PORT
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind((host, port))
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
        self.plugin: "SyncPlugin" = plugin
        self.server: ClientListener | None = None

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
        settings = binaryninja.Settings()
        host = settings.get_string("retsync.ServerHost") or DEFAULT_HOST
        port = settings.get_integer("retsync.ServerPort") or DEFAULT_PORT
        if not self.is_port_available(host, port):
            rs_log(f"aborting, port {port} already in use")
            self.plugin.cmd_syncoff()
            return

        rs_debug(f"starting server on {host}:{port}")

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


class ProgramManager(object):
    """ProgramManager is used to keep track of opened tabs and programs' state (e.g. base address)"""

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
        return pgm in self.opened

    def __contains__(self, pgm: pathlib.Path):
        return self.exists(pgm)

    def reset_bases(self):
        for _, pgm in self.opened.items():
            pgm.base = None

    def get_base_for_program(
        self,
        pgm: pathlib.Path,
    ):
        return self.opened[pgm].base if self.exists(pgm) else None

    def set_base_for_program(self, pgm: pathlib.Path, base: int):
        if not self.exists(pgm):
            rs_warn(f"{pgm} is not handled")
            return
        self.opened[pgm].base = base

    def get_at(self, index: int) -> pathlib.Path | None:
        if index >= len(self.opened):
            return None
        return list(self.opened)[index]

    def __getitem__(self, index: int):
        item = self.get_at(index)
        if not item:
            raise IndexError
        return item

    def as_list(self) -> OrderedDict[pathlib.Path, Program]:
        return self.opened.values()

    def list_dyn(self):
        self.opened = {}
        ctx: binaryninjaui.UIContext = binaryninjaui.UIContext.activeContext()
        for path_str, bv in ctx.getAvailableBinaryViews():
            assert isinstance(path_str, str)
            assert isinstance(bv, binaryninja.BinaryView)
            self.add(pathlib.Path(path_str))
        return self.opened

    def __repr__(self) -> str:
        return f"ProgramManager(opened={self.opened})"


class SyncPlugin:
    def __init__(self):
        self.request_handler = RequestHandler(self)
        self.client_listener: ClientListener | None = None
        self.client: ClientHandler | None = None
        self.next_tab_lock = threading.Event()
        self.pgm_mgr = ProgramManager()

        # binary ninja objects
        self.widget: "SyncWidget" | None = None
        self.view_frame: binaryninjaui.ViewFrame | None = None
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

        # get filename, handling the case of projects
        fname = (
            bv.project_file.name.replace(".bndb", "")
            if bv.project and bv.project.is_open
            else bv.file.original_filename
        )

        rs_log(f"{fname=}")

        if not fname:
            return

        # handle image aliases
        aliases = dict(
            [
                x.split(":", 1)
                for x in binaryninja.Settings().get_string_list("retsync.Aliases")
            ]
        )
        if fname in aliases:
            rs_log(f"fix alias {fname} -> {aliases[fname]} ")
            fname = aliases[fname]

        # if the view is not in the program manager, add it
        pgm = pathlib.Path(fname)
        if not self.pgm_mgr.exists(pgm):
            self.pgm_mgr.add(pgm)
            rs_log(f"Added {pgm}, currently opened {self.pgm_mgr.opened}")

        self.binary_view = bv
        self.current_tab = pgm.name
        self.base = self.binary_view.start
        self.base_remote = self.pgm_mgr.get_base_for_program(pgm)
        if self.base_remote:
            rs_log(f"Setting remote base to {self.base_remote:#x}")

        # mark it as active
        self.set_program(pgm)

    def bootstrap(self, dialect: str):
        self.pgm_mgr.reset_bases()
        self.widget.set_connected(dialect)

        if dialect in config.DBG_DIALECTS:
            self.dbg_dialect = config.DBG_DIALECTS[dialect]
            rs_log(f"set debugger dialect to {dialect}, enabling hotkeys")

    def reset_client(self):
        self.sync_enabled = False
        self.cb_trace_enabled = False
        self.current_pgm = None
        self.widget.reset_client()

    def broadcast(self, msg):
        self.client.send(rs_encode(msg))
        rs_log(msg)

    def set_program(self, pgm: pathlib.Path):
        rs_log(f"Setting active program to {pgm}")
        self.widget.set_program(pgm)
        if not self.pgm_mgr.exists(pgm):
            rs_warn(f"{pgm} is not opened")
            return
        self.sync_enabled = True
        self.current_pgm = pgm
        rs_log(f"Current program set to {pgm}")
        # self.pgm_target_with_lock(pgm)

    def set_program_id(self, index: int):
        pgm = self.pgm_mgr.get_at(index)
        if pgm:
            self.broadcast(f'> active program is now "{pgm}" ({index})')
            # self.pgm_target_with_lock(pgm)
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
            # self.pgm_target_with_lock(self.current_pgm)
            return True

    # def pgm_target(self, pgm=None):
    #     if pgm:
    #         self.target_tab = pgm

    #     if not self.target_tab:
    #         return

    #     try:
    #         if self.target_tab != self.current_tab:
    #             self.trigger_action("Next Tab")
    #         else:
    #             self.target_tab = None
    #             self.next_tab_lock.set()
    #     except Exception as e:
    #         rs_log(f"error while switching tabs, reason: {str(e)}")

    # def trigger_action(self, action: str):
    #     handler = UIActionHandler().actionHandlerFromWidget(self.plugin)
    #     handler.executeAction(action)

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
                self.pgm_mgr.set_base_for_program(self.current_tab, base)
                self.base_remote = base

            dest = self.rebase_local(offset)
            assert isinstance(dest, int)

        if not self.is_safe(dest):
            rs_log(f"unsafe addr: {dest:#x} not in valid segment")
            return None

        return dest

    def rebase_local(self, offset: int):
        "rebase address with respect to local image base"
        if not (self.base == self.base_remote):
            offset = (offset - self.base_remote) + self.base

        return offset

    def rebase_remote(self, offset):
        "rebase address with respect to remote image base"
        if not (self.base == self.base_remote):
            offset = (offset - self.base) + self.base_remote

        return offset

    def set_remote_base(self, rbase: int):
        self.pgm_mgr.set_base_for_program(self.current_tab, rbase)
        self.base_remote = rbase

    def goto(self, base: int, offset: int):
        rs_log(f"SyncPlugin::goto({base=:#x}, {offset=:#x})")
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

    def color_callback(self, hglt_addr: int):
        color_str = (
            binaryninja.Settings().get_string("retsync.TraceColor")
            or DEFAULT_TRACE_COLOR
        ).lower()
        match color_str:
            case "none":
                color = HighlightStandardColor.NoHighlightColor
            case "blue":
                color = HighlightStandardColor.BlueHighlightColor
            case "cyan":
                color = HighlightStandardColor.CyanHighlightColor
            case "red":
                color = HighlightStandardColor.RedHighlightColor
            case "magenta":
                color = HighlightStandardColor.MagentaHighlightColor
            case "yellow":
                color = HighlightStandardColor.YellowHighlightColor
            case "orange":
                color = HighlightStandardColor.OrangeHighlightColor
            case "white":
                color = HighlightStandardColor.WhiteHighlightColor
            case "black":
                color = HighlightStandardColor.BlackHighlightColor
            case _:
                color = HighlightStandardColor.GreenHighlightColor

        color_hl = HighlightColor(color, alpha=192)
        blocks = self.binary_view.get_basic_blocks_at(hglt_addr)
        for block in blocks:
            block.function.set_user_instr_highlight(hglt_addr, color_hl)

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
