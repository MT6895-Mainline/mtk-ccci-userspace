# MTK CCCI Userspace

Userspace support for bringing up a MediaTek MT6895 modem over Linux CCCI.

This repository uses Qualcomm's separate remote-filesystem daemon and
ModemManager integration as a layering reference. Protocols and ownership
are not identical: this experimental owner also starts MD and retains its
monitor descriptor. It is not a port of Qualcomm rmtfs.

## Scope

- CCCI modem-owner lifecycle.
- CCCI FS request/reply handling with isolated overlay storage.
- Kernel-routed RPC handlers whose behavior is independently verified.
- systemd integration examples and protocol tests.

The ModemManager `mtk-soc` plugin is maintained separately. The modem firmware,
vendor Android libraries, NV data, COW snapshots, device logs, and credentials
are intentionally excluded.

## Status

This is an early device-specific implementation for the MT6895 qqcandy
platform. It is not yet a generic multi-board daemon. IMS/VoLTE and long-term
data reliability remain separate validation work.

The publication copy passes 12 host checks for FS, RPC, source hygiene and
launcher guards, plus Meson staging-install/entrypoint checks. It has not
replaced the live bring-up owner and is not a validated automatic boot service.

## Board: pearl (MT6895 / Redmi Note 12T Pro)

This branch carries the pearl integration: the AT bring-up (`at_cfun.py`),
mobile-data bring-up (`data_up.py`, MTK ccmni + PDP, not PPP), ModemManager
signal polling (`mm_tune.py`), the matching systemd/udev examples, and
`docs/PEARL.md` with the observed root causes (data-path HIF, APN, activation
timing, NetworkManager churn) plus the current voice/IMS status.

Set `MTK_CCCI_BOARD=pearl`, `MTK_CCCI_RAT=15` (enables NR on this firmware) and
configure `/etc/mtk-ccci/data.conf` with the operator APN.

## Layout

```text
src/mtk_ccci_userspace/  owner daemon and protocol responders
systemd/                 service templates
config/                  environment template
docs/                    architecture and deployment contract
tests/                   host-side safety checks
```

## Configuration

The owner uses environment variables instead of hard-coded private paths:

- `MDINIT_OVERLAY_ROOT`
- `CCCI_EVIDENCE_DIR`
- `MTK_CCCI_VENDOR_ROOT`
- `MTK_CCCI_VENDOR_ETC_ROOT`
- `MTK_CCCI_PRIVATE_ROOT`
- `MTK_CCCI_PROPERTY_TABLE`
- `MTK_CCCI_BOARD` (currently only `qqcandy`)
- `MTK_CCCI_EXPECTED_KERNEL`
- `MTK_CCCI_EXPECTED_NOTES_SHA256`
- `MTK_CCCI_ENABLE_MDLOG` (disabled by default)

Build and install with Meson:

```sh
meson setup build --prefix=/usr --libexecdir=libexec
meson compile -C build
meson test -C build
meson install -C build
```

Only the Python sources and example configurations are installed. The service
is not automatically enabled. See `docs/DEPLOYMENT.md` before attempting to
start the experimental owner; the board readiness gate is external.

Protected modem partitions must be mounted read-only by the deployment layer.
The owner must run under a dedicated systemd unit so closing its monitor file
descriptor cannot silently stop the modem.

## License

The original implementation in this repository is released under
GPL-2.0-or-later. Kernel and ModemManager dependencies retain their upstream
licenses. See `LICENSE`.
