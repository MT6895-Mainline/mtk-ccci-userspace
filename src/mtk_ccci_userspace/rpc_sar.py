#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Minimal qqcandy userspace RPC endpoint for the two kernel-routed opcodes.

Reference SHA256: 65f1588e32596c543b0f72a3a8bc50167ff70936b7426346060d62d9638f09b7
(vendor.img:/bin/ccci_rpcd).  The kernel routes IPC_RPC_QUERY_AP_SYS_PROPERTY
(0x400f) and IPC_RPC_SAR_TABLE_IDX_QUERY_OP (0x4010) to userspace
(port/port_rpc.c:1955).  Both are answered here exactly as the reference does.

0x4010 (0x7624 -> 0x78fc -> 0x7b68): initialize index 0xffff and return
status 0, retaining the sentinel when ro.product.hw is absent from the 104-model
table.  The same-device working getprop has hw=22823, which is absent (verified
by extract_sar_reference.py).  This endpoint does not set a radio power level or
select a made-up SAR table: it returns the stock no-match result, which the modem
consumes as its normal default-table selection.

0x400f (0x7634 -> 0x7640): NUL-terminate the request's property name, call
`property_get(name, value)`, and reply with two blocks
    {4B int32 property_get_return}{strlen(value)+1 bytes: value incl. NUL}
There is no Android property service in this mainline AP, so an absent property
is answered exactly as Android property_get answers an unset property: return 0
and an empty (NUL-only) string.  A value can be supplied without code changes
via `/etc/mtk-ccci/md_sys_props.conf` (`name=value` lines).

No NV/filesystem writes except bounded diagnostic packet evidence under EVID.
Unknown RPCs are captured but deliberately not given fabricated replies.
"""
import os
import struct

QUERY_PROP = 0x400F
SAR_QUERY = 0x4010
SAR_NO_OPERATOR = 0xffff
PROP_TABLE = os.environ.get(
    'MTK_CCCI_PROPERTY_TABLE',
    '/etc/mtk-ccci/md_sys_props.conf',
)
RPC_RX = 32
RPC_TX = 33


def _parse_rpc(request):
    """Return (data0, channel, reserved, op, count, blocks) or raise ValueError."""
    if len(request) < 24:
        raise ValueError('short RPC frame')
    data0, length, channel, reserved, op, count = struct.unpack_from('<6I', request)
    if length != len(request) or channel & 0xffff != RPC_RX:
        raise ValueError('RPC header length/channel mismatch')
    off, blocks = 24, []
    for _ in range(count):
        if off + 4 > len(request):
            raise ValueError('truncated RPC block list')
        n = struct.unpack_from('<I', request, off)[0]
        off += 4
        if n > len(request) - off:
            raise ValueError('truncated RPC block data')
        blocks.append(request[off:off + n])
        off += (n + 3) & ~3
    return data0, channel, reserved, op, count, blocks


def _frame(request, channel, data0, reserved, op, blocks):
    body = struct.pack('<II', op | 0xFFFF0000, len(blocks))
    for b in blocks:
        body += struct.pack('<I', len(b)) + b + b'\x00' * ((-len(b)) & 3)
    hdr = struct.pack('<4I', data0, 16 + len(body),
                      (channel & 0xffff0000) | RPC_TX, reserved)
    return hdr + body


def _property_get(name):
    """Android property_get semantics; value excludes the terminating NUL."""
    try:
        with open(PROP_TABLE) as fh:
            for line in fh:
                line = line.rstrip('\n')
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, val = line.split('=', 1)
                if key.strip() == name:
                    return val
    except OSError:
        pass
    return ''


def _prop_reply(request, data0, channel, reserved, op, blocks):
    if len(blocks) != 1:
        raise ValueError('property query must carry exactly one name block')
    name = blocks[0].split(b'\x00', 1)[0].decode('utf-8', 'replace')
    value = _property_get(name)
    raw = value.encode('utf-8')
    out = [struct.pack('<i', len(raw)), raw + b'\x00']
    reply = _frame(request, channel, data0, reserved, op, out)
    return reply, 'property=%r value=%r ret=%d' % (name, value, len(raw))


def _sar_reply(request, data0, channel, reserved, op, blocks):
    if len(blocks) != 1 or len(blocks[0]) != 4:
        raise ValueError('SAR query must have one 4-byte argument')
    body = struct.pack('<II', op | 0xFFFF0000, 2) + \
        struct.pack('<I', 4) + struct.pack('<i', 0) + \
        struct.pack('<I', 4) + struct.pack('<I', SAR_NO_OPERATOR)
    hdr = struct.pack('<4I', data0, 16 + len(body),
                      (channel & 0xffff0000) | RPC_TX, reserved)
    return hdr + body, 'status=0 index=0xffff stock_hw=22823 no-table-match'


def rpc_reply(request):
    """Return (reply_bytes, note) or None when the opcode is not serviced."""
    data0, channel, reserved, op, count, blocks = _parse_rpc(request)
    if op == SAR_QUERY:
        return _sar_reply(request, data0, channel, reserved, op, blocks)
    if op == QUERY_PROP:
        return _prop_reply(request, data0, channel, reserved, op, blocks)
    return None


def rpc_reader(fd, evidence_dir, log):
    n = 0
    while True:
        try:
            raw = os.read(fd, 4096)
        except InterruptedError:
            continue
        except OSError as exc:
            log('RPC reader stopped: %r' % exc)
            return
        if not raw:
            log('RPC reader EOF')
            return
        n += 1
        path = os.path.join(evidence_dir, 'rpc_req_%03d.bin' % n)
        with open(path, 'wb') as out:
            out.write(raw)
        op = struct.unpack_from('<I', raw, 16)[0] if len(raw) >= 20 else -1
        log('RPC-REQ #%d len=%d op=0x%x raw=%s' % (n, len(raw), op, raw.hex()))
        try:
            result = rpc_reply(raw)
        except ValueError as exc:
            log('RPC-REJECT #%d %s' % (n, exc))
            continue
        if result is None:
            log('RPC-UNHANDLED #%d op=0x%x (no synthetic response)' % (n, op))
            continue
        reply, note = result
        with open(os.path.join(evidence_dir, 'rpc_rep_%03d.bin' % n), 'wb') as out:
            out.write(reply)
        try:
            sent = os.write(fd, reply)
        except OSError as exc:
            log('RPC-REPLY #%d write FAILED: %r' % (n, exc))
            return
        if sent != len(reply):
            log('RPC-REPLY #%d short write %d/%d; stopped' % (n, sent, len(reply)))
            return
        log('RPC-REPLY #%d op=0xffff%04x %s bytes=%d raw=%s'
            % (n, op, note, sent, reply.hex()))
