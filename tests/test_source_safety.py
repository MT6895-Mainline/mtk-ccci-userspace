from pathlib import Path


ROOT = Path(__file__).parents[1]
SOURCE = "\n".join(
    path.read_text(errors="replace")
    for path in (ROOT / "src").rglob("*.py")
)


def test_no_credentials_or_device_identity():
    forbidden = (
        "sshpass",
        "password=",
        "BEGIN PRIVATE KEY",
        "AT+CIMI",
        "AT+CGSN",
        "ICCID",
        "IMSI",
    )
    assert not any(token in SOURCE for token in forbidden)


def test_private_paths_are_configurable():
    assert "MDINIT_OVERLAY_ROOT" in SOURCE
    assert "CCCI_EVIDENCE_DIR" in SOURCE
    assert "MTK_CCCI_PROPERTY_TABLE" in SOURCE
