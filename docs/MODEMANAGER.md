# ModemManager integration (pearl, MT6895)

Two ways to run the modem with ModemManager on pearl.  Both were exercised on
hardware; the plugin path is the one in use.

## A. `mtk-soc` plugin (native, recommended)

`MT6895-Mainline/modemmanager-mtk-soc` is an upstream ModemManager 1.24.2 fork
with the MediaTek SoC plugin.  The plugin owns the control plane (AT port, SIM
slots, registration, signal, SMS) **and** the data plane through **MIPC
direct-IP**: it opens `/dev/ttyCMIPC1`, runs TEST/OPEN, issues DATA_ACT and
hands the resulting static IPv4 configuration to ModemManager, which
NetworkManager then applies to the `ccmni` interface.  The AT port is never
used for data.

### Hardware contract

| endpoint | provided by |
| --- | --- |
| `/dev/ttyCCCI0` | kernel `port/port_tty.c` (the tty driver added for this port) |
| `ccmni0..N` | kernel CCMNI |
| `/dev/ttyCMIPC1` | kernel `port_cfg.c` MIPC0..9 entries (`char_port_ops`) |

All three exist on pearl.  `tools/mipc-test.py` reproduces the handshake
standalone (no ModemManager needed) and is the quickest way to prove the
channel is alive:

```
TEST_REQ  (0x0305, ps=0xff) -> TEST_CNF   result=21 (informational)
OPEN_REQ  (0x0301, ps=0xff) -> OPEN_CNF   result=0
CALL_LIST (0x020f)          -> CALL_LIST_CNF
DATA_ACT  (0x0201, ps=slot) -> DATA_ACT_CNF
    RESULT=0 CALL_ID=1 IPV4_ADDR=... GW=... PREFIX=30 DNS1/DNS2 TRANS_IFACE_ID=100
```

Frame: `magic 0x24541984 | 4 zero | ps | 0 | msg_id u16 | txid u16 | len u16`
followed by 8-byte aligned TLVs (`kind u16 | len u16 | value`), all
little-endian.  `ps` is the SIM slot for DATA_ACT.

### Build

```sh
meson setup build --prefix=/usr --buildtype=release \
  -Dplugin_mtk_soc=enabled -Dqmi=false -Dqrtr=false -Dmbim=false
ninja -C build && meson test -C build && ninja -C build install
```

Trimmed images may be missing development files; observed on pearl:

| symptom | fix |
| --- | --- |
| `cannot find /usr/lib/libc_nonshared.a` | reinstall `glibc` |
| `glib-object.h` / `gudev.h` missing | reinstall `glib2`, `libgudev`, `polkit` |
| `linux/limits.h` missing | install `linux-api-headers` |
| `systemd/sd-journal.h` missing (and the `systemd` package cannot be reinstalled because of version pins) | configure the build with `-Dsystemd_journal=false`, or extract the header from the `systemd-libs` package |

### udev — the two traps

1. The plugin's own rule matches `DRIVERS=="ccci_tty"`, but this kernel calls
   the driver **`ccci_at_tty`**, and **`ninja install` overwrites that rule
   file**, so patching it does not survive.  Tag the port from our own rule
   instead.
2. `ccmni*` needs `ID_MM_DEVICE_PROCESS=1` (explicit allowlist) as well as
   `ID_MM_MTK_SOC`; without it ModemManager logs
   `Failed to find a data port in the modem` and falls back to the `generic`
   plugin with a single AT port.

`udev/99-mtk-ccci-at.rules` and `udev/98-mtk-ccci-net.rules` in this repository
are the working set.

### Ordering

`systemd/ModemManager.service.d-10-pearl-ccci.conf.example` orders ModemManager
after the owner and the AT bring-up.  It must **not** pull
`mtk-ccci-data.service`: that service takes the AT port and fights the plugin.

## B. Stock ModemManager + `data_up.py` (fallback)

Without the plugin, ModemManager only sees the AT port and would use PPP, which
MTK does not implement, so the PDP has to be activated outside ModemManager.
That is what `data_up.py` does: it stops ModemManager, waits for registration,
activates a PDP with the operator APN, maps `cid N` to `ccmni(N-1)`,
configures address/route/DNS, verifies with a ping and walks up to four cids if
the first data path is dead.

Use it when the plugin is unavailable; do not run both at once.

## Verified on hardware

Cold boot, plugin path: ModemManager reports `plugin: mtk-soc`,
`state: connected`, `access tech: 5gnr`, 22 ports (`ttyCCCI0` plus the `ccmni`
netdevs), NetworkManager configures `ccmni0` from the MIPC confirmation and
traffic flows (HTTP 200, ICMP 3/3 ~25 ms), including with WiFi off.
