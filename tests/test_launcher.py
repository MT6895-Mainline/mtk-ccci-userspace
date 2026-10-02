import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile


MODULE = Path(__file__).parents[1] / "src/mtk_ccci_userspace/start_owner.py"
spec = importlib.util.spec_from_file_location("start_owner", MODULE)
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)


def test_cli_help_is_offline():
    result = subprocess.run([sys.executable, str(MODULE), "--help"], capture_output=True)
    assert result.returncode == 0
    assert b"--check" in result.stdout


def test_writable_mount_is_rejected():
    good = {"filesystems": [{"target": "/example/nvdata", "source": "/dev/example",
                             "options": "ro,relatime"}]}
    owner.validate_mount(good, "/example/nvdata", "/dev/example")
    for options in ("rw,relatime", ""):
        bad = {"filesystems": [dict(good["filesystems"][0], options=options)]}
        try:
            owner.validate_mount(bad, "/example/nvdata", "/dev/example")
        except RuntimeError:
            continue
        raise AssertionError("writable or unknown mount accepted")


def test_wrong_mount_is_rejected():
    bad = {"filesystems": [{"target": "/example/nvdata", "source": "/dev/other",
                            "options": "ro"}]}
    try:
        owner.validate_mount(bad, "/example/nvdata", "/dev/example")
    except RuntimeError:
        return
    raise AssertionError("wrong protected device accepted")


def test_write_root_cannot_overlap_backing():
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory) / "backing"
        base.mkdir()
        for path in (base, base / "overlay", base.parent):
            try:
                owner.validate_write_root(path, [base])
            except RuntimeError:
                continue
            raise AssertionError("overlapping write root accepted")
        owner.validate_write_root(Path(directory) / "private-overlay", [base])
