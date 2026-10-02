# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise real FS functions with synthetic backing; never execute owner I/O."""
import ast
import ctypes
from pathlib import Path
import struct
import tempfile
import threading

SOURCE = Path(__file__).parents[1] / "src/mtk_ccci_userspace/mdinit.py"


def sandbox(root):
    tree = ast.parse(SOURCE.read_text())
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            nodes.append(node)
        elif isinstance(node, ast.FunctionDef):
            nodes.append(node)
        elif isinstance(node, ast.Assign) and not any(
                isinstance(value, ast.Call) for value in ast.walk(node.value)):
            nodes.append(node)
    namespace = {"__name__": "fs_contract", "__file__": str(SOURCE)}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), "exec"), namespace)
    directories = {
        "Z": root / "nvdata/md", "X": root / "protect_f/md",
        "Y": root / "protect_s/md", "S": root / "nvcfg",
        "R": root / "vendor/etc/md", "W": root / "vendor/firmware",
        "V": root / "nvdata/md_cmn",
    }
    for directory in directories.values():
        directory.mkdir(parents=True)
    overlay = root / "overlay"
    overlay.mkdir()
    namespace.update(
        FSD_DIRS={key: str(value) for key, value in directories.items()},
        OVERLAY=str(overlay), EVID=str(root / "evidence"),
        WH_DIR=str(overlay / ".wh"), hlock=threading.Lock(),
        libc=ctypes.CDLL("libc.so.6", use_errno=True), log=lambda message: None,
    )
    return namespace


def request(op, blocks):
    body = struct.pack("<II", op, len(blocks))
    for block in blocks:
        body += struct.pack("<I", len(block)) + block + b"\0" * ((-len(block)) & 3)
    return struct.pack("<IIII", 0, len(body) + 16, 14 | (0x1234 << 16), 2) + body


def test_frames_and_path_guards():
    with tempfile.TemporaryDirectory() as directory:
        ns = sandbox(Path(directory))
        original = request(0x1001, ["Z:/example".encode("utf-16-le") + b"\0\0"])
        reply = ns["build_reply"](original, 0x1001, [b"abc"])
        assert struct.unpack_from("<I", reply, 4)[0] == len(reply)
        assert struct.unpack_from("<I", reply, 12)[0] == 2
        assert reply[16:20] == struct.pack("<I", 0xFFFF1001)
        for path in ("Z:/../../outside", "Z:relative", "Z:/bad\0name"):
            assert ns["map_md_path"](path)[0] is None
        outside = Path(directory) / "outside"
        outside.write_bytes(b"UNCHANGED")
        (Path(ns["FSD_DIRS"]["Z"]) / "escape").symlink_to(outside)
        assert ns["map_md_path"]("Z:/escape")[0] is None


def test_cmpt_writes_only_overlay():
    with tempfile.TemporaryDirectory() as directory:
        ns = sandbox(Path(directory))
        backing = Path(ns["FSD_DIRS"]["X"]) / "example"
        backing.write_bytes(b"BASE" * 64)
        before = backing.read_bytes()
        descriptor = struct.pack("<11I", 0x35, 0, 0, 0x10000, 8, 0, 0, 3,
                                 0xFFFFFFFF, 0, 0)
        blocks, _ = ns["do_cmpt_write"]("X:/example", descriptor, b"NEW")
        assert struct.unpack("<Ii", blocks[0]) == (0x35, 0)
        assert struct.unpack("<I", blocks[2])[0] == 3
        assert backing.read_bytes() == before
        resolved, present, _, _ = ns["resolve_ro_path"]("X:/example")
        assert present and Path(ns["OVERLAY"]) in Path(resolved).parents
        assert Path(resolved).read_bytes()[8:11] == b"NEW"


def test_private_drive_and_missing_ota():
    with tempfile.TemporaryDirectory() as directory:
        ns = sandbox(Path(directory))
        ns["FSD_DIRS"]["T"] = str(Path(directory) / "missing-ota")
        ns["FSD_DIRS"]["Q"] = str(Path(directory) / "missing-private")
        assert ns["do_getfiledetail"]("T:/nonexistent")[0] == -9
        assert ns["do_mkdir"]("Q:/cacerts")[0] == 0
        assert (Path(ns["OVERLAY"]) / "Q/cacerts").is_dir()
        assert not Path(ns["FSD_DIRS"]["Q"]).exists()
