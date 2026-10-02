import importlib.util
from pathlib import Path
import tempfile
import struct


MODULE = Path(__file__).parents[1] / "src/mtk_ccci_userspace/qqc_rpc_sar.py"
spec = importlib.util.spec_from_file_location("rpc_sar", MODULE)
rpc_sar = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rpc_sar)


def frame(op, blocks):
    body = op.to_bytes(4, "little") + len(blocks).to_bytes(4, "little")
    for block in blocks:
        body += len(block).to_bytes(4, "little") + block
        body += b"\0" * ((-len(block)) & 3)
    return (
        (0).to_bytes(4, "little")
        + (16 + len(body)).to_bytes(4, "little")
        + (32).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + body
    )


def test_sar_reply_uses_stock_no_match_sentinel():
    reply, note = rpc_sar.rpc_reply(frame(rpc_sar.SAR_QUERY, [b"\0\0\0\0"]))
    assert "0xffff" in note
    assert reply[16:20] == (rpc_sar.SAR_QUERY | 0xFFFF0000).to_bytes(4, "little")


def test_rpc_property_and_unknown():
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "properties.conf"
        path.write_text("# synthetic fixture\nexample.property=test\n")
        before = rpc_sar.PROP_TABLE
        rpc_sar.PROP_TABLE = str(path)
        try:
            reply, _ = rpc_sar.rpc_reply(frame(rpc_sar.QUERY_PROP, [b"example.property\0"]))
            assert struct.unpack_from("<i", reply, 28)[0] == 4
            assert reply[36:41] == b"test\0"
            assert rpc_sar.rpc_reply(frame(0x1234, [])) is None
        finally:
            rpc_sar.PROP_TABLE = before


def test_rpc_invalid_frames():
    cases = [b"", frame(rpc_sar.SAR_QUERY, [b"\0"]), frame(rpc_sar.QUERY_PROP, [])]
    for request in cases:
        try:
            rpc_sar.rpc_reply(request)
        except ValueError:
            continue
        raise AssertionError("malformed request accepted")
