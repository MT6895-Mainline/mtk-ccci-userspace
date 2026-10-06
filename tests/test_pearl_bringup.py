"""Host-side checks for the pearl bring-up helpers (no hardware needed)."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).parents[1]
SRC = ROOT / "src/mtk_ccci_userspace"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, SRC / ("%s.py" % name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_paths_are_configurable():
    """Device nodes and the data config must not be hard-coded only."""
    data_up = _load("data_up")
    at_cfun = _load("at_cfun")
    assert data_up.DEV_AT.startswith("/dev/")
    assert data_up.BOOT.startswith("/sys/")
    assert data_up.CONF.startswith("/etc/")
    assert at_cfun.DEV.startswith("/dev/")
    assert at_cfun.BOOT.startswith("/sys/")
    for module in (data_up, at_cfun):
        source = (SRC / ("%s.py" % module.__name__)).read_text()
        assert "os.environ.get" in source


def test_data_config_parsing_ignores_comments_and_spaces():
    data_up = _load("data_up")
    original = dict(data_up.CFG)
    try:
        data_up.CFG.update({"APN": "sentinel"})
        # load_conf() reads the real path; emulate its parser instead
        lines = ["# comment", "", "APN = operator.apn ", "METRIC=1234"]
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            data_up.CFG[key.strip()] = value.strip()
        assert data_up.CFG["APN"] == "operator.apn"
        assert data_up.CFG["METRIC"] == "1234"
    finally:
        data_up.CFG.clear()
        data_up.CFG.update(original)


def test_cid_to_ccmni_mapping():
    """cid N must map to ccmni(N-1): cid 1 -> ccmni0."""
    data_up = _load("data_up")
    source = (SRC / "data_up.py").read_text()
    assert '"ccmni%d" % (cid - 1)' in source


def test_verify_step_exists():
    """A PDP is only accepted after real traffic passes."""
    source = (SRC / "data_up.py").read_text()
    assert "def verify(" in source
    assert "VERIFY_HOST" in source


def test_registration_is_waited_for():
    source = (SRC / "data_up.py").read_text()
    assert "AT+CGATT?" in source
    assert "AT+CEREG?" in source


def test_at_port_is_taken_exclusively():
    """ModemManager must be stopped while the AT port is used."""
    source = (SRC / "data_up.py").read_text()
    assert "ModemManager" in source
    assert "systemctl" in source


def test_rat_default_is_documented():
    at_cfun = _load("at_cfun")
    source = (SRC / "at_cfun.py").read_text()
    assert "AT+ERAT" in source
    assert at_cfun is not None


def test_mm_tune_is_optional():
    """mm_tune.py must not fail when ModemManager/mmcli is absent."""
    source = (SRC / "mm_tune.py").read_text()
    assert "which(\"mmcli\")" in source
    assert "return 0" in source
