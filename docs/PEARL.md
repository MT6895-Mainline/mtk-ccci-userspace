# pearl (Redmi Note 12T Pro, MT6895) — modem bring-up notes

Board integration notes for `MTK_CCCI_BOARD=pearl`, collected while bringing the
MD1 modem up on mainline Linux (7.2) plus Arch Linux ARM.  Everything here was
observed on hardware; anything not verified is marked as such.

## 1. Boot chain

```
mtk-ccci-owner.service      userspace owner (mdinit/fsd/rpc)  -> MD boots, md1:4 READY
mtk-ccci-at-cfun.service    AT+CFUN=1 (+RAT)                  -> SIM powered, registered
mtk-ccci-data.service       PDP activate + ccmni config       -> mobile data usable
ModemManager.service        stock MM, no source changes       -> SIM/registration/signal
mtk-ccci-mm-tune.service    mmcli --signal-setup=30           -> signal reported
```

The modem comes up in `CFUN=0` (minimum functionality): the SIM is not powered
and `AT+CPIN?` answers `ERROR`, which makes ModemManager report `sim-missing`.
`AT+CFUN=1` is mandatory.

Ordering alone is not enough: NetworkManager talks to ModemManager over D-Bus
early in boot and can start it before our units run.  `data_up.py` therefore
stops ModemManager itself while it owns the AT port and starts it again
afterwards.  Measured effect of not doing this: every AT query times out and a
PDP gets created before registration completes (see §3.3).

## 2. Kernel requirements

Required options (see the kernel patches in the mainline tree):

| option | why |
| --- | --- |
| `CONFIG_MTK_CCCI_MAINLINE=y` | CCCI core, `/sys/kernel/ccci/boot` |
| `CONFIG_MTK_CCMNI=y` | `ccmni*` netdevs |
| `CONFIG_MTK_CCCI_MAINLINE_DATAPATH_HIF=y` | CLDMA + DPMAIF; **without it mobile data has TX only** |
| the AT-port tty driver (`port/port_tty.c`) | exposes `/dev/ttyCCCI0` as a real tty with a platform parent |

Two kernel-side details that are easy to get wrong:

* `MD1_NET_HIF` is `DPMAIF_HIF_ID` on this generation.  With the data-path HIFs
  not built, `ccmni0` accepts TX packets, the DPMAIF queue counters even look
  alive, and RX stays at zero forever.  Symptom in the kernel log:
  `[ccci1/net]ccmni0(1,1), irat_MD1, rx=(0,0,0), tx=(...)`.
* ModemManager refuses a tty that lives under `/sys/devices/virtual/`
  ("port filtered: virtual device") and refuses ports whose driver it cannot
  resolve.  Registering the AT tty through `tty_port_register_device()` with a
  real platform parent fixes both; the udev rule then only has to set MM's
  documented properties.

## 3. Mobile data

MTK data is **not** PPP.  The AP must activate a PDP over AT and configure the
matching `ccmni` netdev: `cid N` maps to `ccmni(N-1)`, so `cid 1` is `ccmni0`.

### 3.1 Root causes found (in the order they bite)

1. **Data-path HIF missing** — see §2.  This was the original "no RX" bug.
2. **Wrong APN** — the network here hands out `cmnet.mnc000.mcc460.gprs`; the
   generic `cmnet` is rejected with `+CME ERROR: 5848` and
   `AT+CEER` → `63,CM_SER_UNAVAILABLE`.
3. **Activating before registration** — `AT+CGACT` right after `md1:4` can
   succeed and return an IP while the data path is bound to nothing.  The PDP
   looks fine and carries zero packets.  Always wait for `AT+CGATT?` → 1 and
   `AT+CEREG?` → `0,1|0,5`, and **verify with a real packet** afterwards.
4. **A dead first PDP** — even when registered, the first activation after boot
   occasionally lands on a dead data path.  `data_up.py` therefore walks up to
   four cids and keeps the first one that passes a ping test.
5. **NetworkManager** — NM creates a `gsm` connection for the modem and keeps
   reconnecting it through MM (which speaks PPP and fails).  Set the modem
   device unmanaged and/or `connection.autoconnect no`, otherwise the churn
   takes the PDP down.

### 3.2 Working sequence

```
AT+CGDCONT=1,"IP","cmnet.mnc000.mcc460.gprs"   -> OK
AT+CGACT=1,1                                   -> OK
AT+CGPADDR=1                                   -> +CGPADDR: 1,"10.x.x.x",""
ip link set ccmni0 up
ip addr add 10.x.x.x/24 dev ccmni0
ip route replace default dev ccmni0 metric 1000
```

Verified on hardware: `ping -I ccmni0 223.5.5.5` 3/3, `curl http://www.baidu.com`
→ 200, and with WiFi radio off the mobile route takes over automatically.

### 3.3 Route metric

`METRIC=1000` keeps the mobile default route behind WiFi (NetworkManager uses
600), so the phone only uses cellular when WiFi is gone.  `ip route get` after a
cold boot with WiFi up resolves via `wlan1`, with WiFi down via `ccmni0`.

## 4. ModemManager

ModemManager is **stock** — no source changes, no plugin.  Integration is:

* `udev/99-mtk-ccci-at.rules` sets `ID_MM_CANDIDATE`, `ID_MM_DEVICE_PROCESS`,
  `ID_MM_PORT_TYPE_AT_PRIMARY`, `ID_MM_TTY_FLOW_CONTROL` (documented MM
  properties for non-USB ports).  `ENV{DRIVER}` must not be used: udev rejects
  it and the whole rule file becomes invalid.
* `systemd/ModemManager.service.d-10-pearl-ccci.conf.example` orders MM after
  the bring-up units.
* `mm_tune.py` turns on signal polling (MM defaults to rate 0).

With this, MM reports `state: registered`, `operator: China Mobile`,
`access tech: lte|5gnr`, `packet service: attached` and signal quality.

The `mtk-soc` plugin from `MT6895-Mainline/modemmanager-mtk-soc` now owns both
the control plane and the data plane: it activates the PDP over **MIPC
direct-IP** (`/dev/ttyCMIPC1`), which is an independent CCCI channel, and hands
the static IPv4 configuration to NetworkManager.  Verified on hardware:
`plugin: mtk-soc`, `state: connected`, 22 ports, `ccmni0` configured by NM,
traffic flowing with WiFi off.  `data_up.py` remains as the fallback for a
stock ModemManager; see `docs/MODEMANAGER.md`.

## 5. RAT and 5G

* `AT+ERAT?` on this firmware: `+ERAT: 7,0,22,128,0` (2G/3G/4G).
* `AT+ERAT=15` was accepted and the modem re-registered with
  `access tech: 5gnr`, data unaffected — this is what `MTK_CCCI_RAT=15`
  (default in `at_cfun.py`) does at boot.  `AT+ERAT=23` is rejected
  (`+CME ERROR: 4`); the field encoding is not documented and was not
  reverse-engineered further.
* ModemManager cannot set modes on this modem: `--set-allowed-modes` returns
  `Unsupported: Setting allowed modes not supported` (the generic plugin has no
  mapping for MTK's RAT command).  Use `AT+ERAT` (or the config above) instead.

## 6. Voice and IMS — not working, and why

Status: **no calls in or out, no VoLTE**.  Findings:

* `AT+EIMS?` and `AT+ECSFB?` → `+CME ERROR: 100` (not supported by this AT
  surface); `AT+CIREG?` → `+CIREG: 2,0,0` (IMS not registered).
* A network scan in this location lists only LTE/NR cells — no GSM/UMTS.  With
  no 2G/3G there is no CS domain to fall back to, so circuit-switched calls are
  impossible regardless of AP-side work.
* VoLTE therefore requires an IMS stack on the AP side (MTK vendors ship one;
  it is not part of mainline and is not in this repository).
* Even with a registered IMS bearer, call audio needs the CCCI audio/PCM path
  routed into ALSA — a separate piece of work, currently absent.

MM does expose a call list (`mmcli -m 0 --voice-list-calls` returns an empty
list rather than "unsupported"), so the AT plumbing is there; the network/IMS
side is what is missing.

## 7. Troubleshooting checklist

| symptom | check |
| --- | --- |
| `md1:0` and the owner keeps restarting | `MTK_CCCI_EXPECTED_NOTES_SHA256` must equal `sha256sum /sys/kernel/notes` — **every kernel rebuild changes it** |
| `AT+CPIN?` → ERROR, MM says sim-missing | modem still in `CFUN=0`; `mtk-ccci-at-cfun` did not run |
| `ccmni0` has an IP but no traffic | data-path HIF not built (§2), or the PDP was activated before registration (§3.1.3) |
| `AT+CGACT` → `+CME ERROR: 5848` | wrong APN; use the operator-provided one |
| every AT query times out at boot | ModemManager holds the port; `data_up.py` must stop it first |
| MM logs "port filtered: virtual device" | tty has no real parent device (§2) or the udev rule is invalid |
| PDP disappears minutes after coming up | NetworkManager reconnecting the modem (§3.1.5) |

## 8. Not verified / risks

* Data stability over hours and across cell handovers was not measured.
* Deactivating a PDP (`AT+CGACT=0,<cid>`) or bouncing a `ccmni` netdev has
  twice left the device unresponsive and needed a power cycle.  The scripts
  only ever activate and re-activate on a new cid; treat teardown as untested.
* 5G attachment was observed but not load-tested.
* Everything here was validated on one pearl unit with a China Mobile SIM.
