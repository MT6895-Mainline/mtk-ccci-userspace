# SPDX-License-Identifier: GPL-2.0-or-later
"""Fail-closed launcher; imports the experimental owner only after preflight."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

PROTECTED = {
    "nvdata": "nvdata", "nvcfg": "nvcfg", "protect_f": "protect1",
    "protect_s": "protect2", "mcf_ota": "mcf_ota_a",
}


def validate_mount(info, target, device):
    filesystems = info.get("filesystems", [])
    if len(filesystems) != 1:
        raise RuntimeError(f"missing exact mount: {target}")
    mount = filesystems[0]
    if (mount.get("target") != str(target) or
            "ro" not in mount.get("options", "").split(",") or
            os.path.realpath(mount.get("source", "")) != os.path.realpath(device)):
        raise RuntimeError(f"protected mount not the expected read-only device: {target}")


def validate_write_root(path, protected):
    if not Path(path).is_absolute():
        raise RuntimeError("write root must be absolute")
    resolved = Path(path).resolve()
    if not resolved.is_absolute() or resolved == Path("/"):
        raise RuntimeError("write root must be a private absolute directory")
    for base in protected:
        base = Path(base).resolve()
        if resolved == base or base in resolved.parents or resolved in base.parents:
            raise RuntimeError(f"write root overlaps protected backing: {path}")


def preflight():
    if os.geteuid() != 0:
        raise RuntimeError("modem owner requires root")
    if os.environ.get("MTK_CCCI_BOARD") != "qqcandy":
        raise RuntimeError("only the explicitly selected qqcandy profile is supported")
    expected_release = os.environ.get("MTK_CCCI_EXPECTED_KERNEL", "")
    expected_notes = os.environ.get("MTK_CCCI_EXPECTED_NOTES_SHA256", "")
    if not expected_release or len(expected_notes) != 64:
        raise RuntimeError("kernel release and notes SHA256 must be explicitly pinned")
    if Path("/proc/sys/kernel/osrelease").read_text().strip() != expected_release:
        raise RuntimeError("running kernel differs from the pinned board integration")
    if hashlib.sha256(Path("/sys/kernel/notes").read_bytes()).hexdigest() != expected_notes:
        raise RuntimeError("running kernel notes differ from the pinned board integration")
    # PEARL-MDRECOVER-10: bring a non-idle modem back to md1:0 instead of
    # refusing to start.  Without this, any abnormal owner exit leaves the modem
    # in BOOTING/EXCEPTION and every subsequent start needs a full device reboot.
    # CCCI_IOC_DO_STOP_MD = _IO('C', 12) = 0x430C; fsm_routine_stop() accepts
    # EXCEPTION and ends at CCCI_FSM_GATED (md1:0).
    try:
        _st = Path("/sys/kernel/ccci/boot").read_text().split("|", 1)[0].strip()
        if _st != "md1:0":
            import fcntl as _f, struct as _s, time as _t
            print("owner: modem is %s -> issuing DO_STOP_MD to return to idle" % _st,
                  file=sys.stderr)
            def _idle():
                return Path("/sys/kernel/ccci/boot").read_text().split(
                    "|", 1)[0].strip() == "md1:0"

            _fd = os.open("/dev/ccci_monitor", os.O_RDWR)
            try:
                # Escalating recovery.  From BOOTING(1)/EXCEPTION(5) a plain
                # DO_STOP_MD does not return the FSM to GATED, so try the reset
                # paths the MDRECOVER work established, then stop again.
                #   CCCI_IOC_DO_STOP_MD      = _IO('C', 12) = 0x430C
                #   CCCI_IOC_MD_RESET        = _IO('C',  0) = 0x4300
                #   CCCI_IOC_DO_MD_RST       = _IO('C',  6) = 0x4306
                #   RESET_MD1_MD3_PCCIF      = _IO('C', 45) = 0x432D
                for _name, _cmd in (("DO_STOP_MD", 0x430C),
                                    ("MD_RESET", 0x4300),
                                    ("DO_MD_RST", 0x4306),
                                    ("RESET_MD1_MD3_PCCIF", 0x432D),
                                    ("DO_STOP_MD#2", 0x430C)):
                    if _idle():
                        break
                    try:
                        _b = bytearray(_s.pack("<I", 0))
                        _f.ioctl(_fd, _cmd, _b, True)
                        print("owner: recovery ioctl %s ok" % _name,
                              file=sys.stderr)
                    except OSError as _e:
                        print("owner: recovery ioctl %s failed: %s" % (_name, _e),
                              file=sys.stderr)
                    for _i in range(20):
                        if _idle():
                            break
                        _t.sleep(0.5)
            finally:
                os.close(_fd)
            for _i in range(40):
                if _idle():
                    break
                _t.sleep(0.5)
            print("owner: modem now %s" %
                  Path("/sys/kernel/ccci/boot").read_text().split("|", 1)[0].strip(),
                  file=sys.stderr)
    except Exception as _e:
        print("owner: non-idle recovery error: %s" % _e, file=sys.stderr)

    state = Path("/sys/kernel/ccci/boot").read_text().split("|", 1)[0].strip()
    if state != "md1:0":
        raise RuntimeError(f"refusing to boot a non-idle or already-owned modem: {state}")
    for name in ("ccci_monitor", "ccci_fs", "ccci_rpc", "ccci_ccb_ctrl"):
        if not Path("/dev", name).exists():
            raise RuntimeError(f"missing device node: {name}")

    vendor = Path(os.environ.get("MTK_CCCI_VENDOR_ROOT", "/mnt/vendor"))
    protected = [vendor / name for name in PROTECTED]
    for name, label in PROTECTED.items():
        target = vendor / name
        result = subprocess.run(
            ["findmnt", "--json", "--output", "TARGET,SOURCE,OPTIONS", "--mountpoint", str(target)],
            capture_output=True, text=True, check=True,
        )
        validate_mount(json.loads(result.stdout), target, Path("/dev/disk/by-partlabel") / label)
    for variable in ("MDINIT_OVERLAY_ROOT", "CCCI_EVIDENCE_DIR", "MTK_CCCI_PRIVATE_ROOT"):
        value = os.environ.get(variable, "")
        if not value or not Path(value).is_absolute():
            raise RuntimeError(f"an explicit absolute {variable} is required")
        validate_write_root(value, protected)
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate deployment without starting MD")
    parser.add_argument("--version", action="version", version="mtk-ccci-userspace 0.1.0")
    args = parser.parse_args(argv)
    try:
        boot = preflight()
        if args.check:
            print(f"preflight passed for boot {boot}; modem not started")
            return 0
        os.umask(0o077)
        runtime = Path("/run/mtk-ccci")
        runtime.mkdir(mode=0o700, exist_ok=True)
        with (runtime / "owner.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if preflight() != boot:
                raise RuntimeError("boot changed after preflight")
            sys.argv = [str(Path(__file__).with_name("mdinit.py"))]
            runpy.run_path(sys.argv[0], run_name="__main__")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"CCCI owner refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
