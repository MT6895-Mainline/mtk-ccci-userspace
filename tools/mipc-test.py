#!/usr/bin/env python3
"""手动跟模组做一次 MIPC 握手，验证 /dev/ttyCMIPC1 这条 direct-IP 通道能不能用。

帧格式（mm-mtk-mipc.c，小端）：
  [0:4]   magic 0x24541984   [4:8] 0   [8] ps   [9] 0
  [10:12] message_id  [12:14] transaction_id  [14:16] payload_len
载荷是 TLV：kind(u16) len(u16) value，整块按 8 字节对齐。
"""
import os
import select
import struct
import sys
import time

PORT = os.environ.get("MTK_MIPC_PORT", "/dev/ttyCMIPC1")
MAGIC = 0x24541984

TEST_REQ, TEST_CNF = 0x0305, 0x0306
OPEN_REQ, OPEN_CNF = 0x0301, 0x0302
DATA_ACT_REQ, DATA_ACT_CNF = 0x0201, 0x0202
DATA_LIST_REQ, DATA_LIST_CNF = 0x020f, 0x0210

MIPC_VERSION = 2
TX_TEST, TX_OPEN, TX_ACT, TX_LIST = 0, 1, 2, 4

TLV = {
    "APN": 0x0101, "APN_TYPE": 0x0102, "PDP_TYPE": 0x0103, "ROAMING": 0x0104,
    "AUTH_TYPE": 0x0105, "USERID": 0x8106, "PASSWORD": 0x8107,
    "IPV4V6_FB": 0x0108, "BEARER": 0x0109, "REUSE": 0x010a, "APN_INDEX": 0x010c,
    "URSP_DESC": 0x010d, "URSP_EVAL": 0x010f,
    "RESULT": 0x0000, "CALL_ID": 0x0100, "MTU": 0x0123, "IFACE_ID": 0x0125,
    "TRANS_IFACE_ID": 0x012a, "IPV4_PREFIX": 0x0128, "IPV4_ADDR": 0x8104,
    "IPV4_GW": 0x8121, "DNS1": 0x810e, "DNS2": 0x810f,
}

APN = os.environ.get("MTK_MIPC_APN", "cmnet.mnc000.mcc460.gprs")


def tlv(kind, value):
    block = 4 + len(value)
    pad = (8 - (block % 8)) % 8
    return struct.pack("<HH", kind, len(value)) + value + b"\x00" * pad


def frame(msg_id, ps, txid, payload=b""):
    return (struct.pack("<I", MAGIC) + b"\x00" * 4 + bytes([ps, 0]) +
            struct.pack("<HHH", msg_id, txid, len(payload)) + payload)


def parse_tlvs(payload):
    out, off = [], 0
    while off + 4 <= len(payload):
        kind, length = struct.unpack_from("<HH", payload, off)
        value = payload[off + 4:off + 4 + length]
        out.append((kind, value))
        block = 4 + length
        off += block + ((8 - (block % 8)) % 8)
    return out


def show(name, tlvs):
    for kind, value in tlvs:
        label = next((k for k, v in TLV.items() if v == kind), "0x%04x" % kind)
        if kind in (TLV["IPV4_ADDR"], TLV["IPV4_GW"], TLV["DNS1"], TLV["DNS2"]) \
                and len(value) == 4:
            shown = "%d.%d.%d.%d" % tuple(value)
        elif len(value) <= 4:
            shown = value.hex() + (" (u32=%d)" % struct.unpack("<I", value.ljust(4, b"\0"))[0]
                                   if len(value) == 4 else "")
        else:
            shown = "%d 字节: %s" % (len(value), value[:24].hex())
        print("    %-14s = %s" % (label, shown))


class Mipc:
    def __init__(self, path):
        self.fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        self.buf = b""

    def close(self):
        os.close(self.fd)

    def send(self, data):
        os.write(self.fd, data)

    def read_frame(self, timeout):
        """按 16 字节头 + payload_len 收一帧。"""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if len(self.buf) >= 16:
                magic, = struct.unpack_from("<I", self.buf, 0)
                msg_id, txid, plen = struct.unpack_from("<HHH", self.buf, 10)
                if magic == MAGIC and len(self.buf) >= 16 + plen:
                    ps = self.buf[8]
                    payload = self.buf[16:16 + plen]
                    self.buf = self.buf[16 + plen:]
                    return ps, msg_id, txid, payload
            r, _, _ = select.select([self.fd], [], [], 0.25)
            if r:
                try:
                    chunk = os.read(self.fd, 8192)
                except OSError:
                    break
                if not chunk:
                    break
                self.buf += chunk
        return None

    def exchange(self, msg_id, ps, txid, expect, payload=b"", timeout=15.0):
        self.send(frame(msg_id, ps, txid, payload))
        while True:
            got = self.read_frame(timeout)
            if got is None:
                print("    ✗ 超时：没等到 0x%04x（ps=%s txid=%d）" % (expect, ps, txid))
                return None
            rps, rmsg, rtxid, rpayload = got
            print("    ← 收到 msg=0x%04x ps=%d txid=%d len=%d" % (rmsg, rps, rtxid, len(rpayload)))
            if rmsg == expect:
                return rpayload
            print("      （不是期待的应答，继续等）")


def main():
    print("== 打开 %s ==" % PORT)
    try:
        mipc = Mipc(PORT)
    except OSError as exc:
        print("  ✗ 打不开: %s" % exc)
        return 1

    try:
        print("\n== 1) TEST_REQ (0x0305) ps=0xff ==")
        p = mipc.exchange(TEST_REQ, 0xff, TX_TEST, TEST_CNF, timeout=5.0)
        if p is not None:
            show("TEST_CNF", parse_tlvs(p))

        print("\n== 2) OPEN_REQ (0x0301) ps=0xff ==")
        payload = (tlv(TLV["APN"], struct.pack("<I", MIPC_VERSION)) +
                   tlv(TLV["APN"], PORT.encode() + b"\x00") +
                   tlv(TLV["APN_TYPE"], b"\x01"))
        # 0x0100=version, 0x0101=client name, 0x0102=usir
        payload = (tlv(0x0100, struct.pack("<I", MIPC_VERSION)) +
                   tlv(0x0101, PORT.encode() + b"\x00") +
                   tlv(0x0102, b"\x01"))
        p = mipc.exchange(OPEN_REQ, 0xff, TX_OPEN, OPEN_CNF, payload, timeout=5.0)
        if p is not None:
            show("OPEN_CNF", parse_tlvs(p))

        print("\n== 3) DATA_GET_CALL_LIST_REQ (0x020f) ==")
        for slot in (1, 0):
            p = mipc.exchange(DATA_LIST_REQ, slot, TX_LIST, DATA_LIST_CNF, timeout=8.0)
            if p is not None:
                show("CALL_LIST slot=%d" % slot, parse_tlvs(p))
                break

        print("\n== 4) DATA_ACT_REQ (0x0201) APN=%s ==" % APN)
        desc = bytearray(672)
        desc[1] = len(APN)
        desc[4:4 + len(APN)] = APN.encode()
        desc[414] = 0xff
        act = (tlv(TLV["USERID"], b"\x00") +
               tlv(TLV["URSP_EVAL"], struct.pack("<I", 0)) +
               tlv(TLV["PASSWORD"], b"\x00") +
               tlv(TLV["IPV4V6_FB"], bytes([127])) +
               tlv(TLV["APN"], APN.encode() + b"\x00") +
               tlv(TLV["BEARER"], struct.pack("<I", 0x7FFDFFFF)) +
               tlv(TLV["APN_TYPE"], struct.pack("<I", 1)) +
               tlv(TLV["REUSE"], bytes([0])) +
               tlv(TLV["PDP_TYPE"], bytes([3])) +
               tlv(TLV["APN_INDEX"], struct.pack("<I", 0)) +
               tlv(TLV["ROAMING"], bytes([3])) +
               tlv(TLV["URSP_DESC"], bytes(desc)) +
               tlv(TLV["AUTH_TYPE"], bytes([0])))
        for slot in (1, 0, 0xff):
            print("  --- 试 slot(ps)=%d ---" % slot)
            p = mipc.exchange(DATA_ACT_REQ, slot, TX_ACT, DATA_ACT_CNF, act, timeout=20.0)
            if p is None:
                continue
            tlvs = parse_tlvs(p)
            show("DATA_ACT_CNF", tlvs)
            result = next((struct.unpack("<I", v.ljust(4, b"\0"))[0]
                           for k, v in tlvs if k == TLV["RESULT"]), None)
            if result == 0:
                print("\n  ★★★ MIPC direct-IP 激活成功！★★★")
                return 0
            print("    result=0x%08x" % (result or 0))
    finally:
        mipc.close()
    return 1


if __name__ == "__main__":
    sys.exit(main())
