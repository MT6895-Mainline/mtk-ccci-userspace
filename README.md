# MTK CCCI Userspace

Userspace support for bringing up a MediaTek MT6895 modem over Linux CCCI.

This repository follows the same boundary used by Qualcomm's Linux modem
stack: the kernel owns transport and device nodes, a small userspace owner
speaks the modem-side CCCI contracts, and ModemManager remains a separate
control-plane integration.

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

## Layout

```text
src/mtk_ccci_userspace/  owner daemon and protocol responders
systemd/                 service templates
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

Protected modem partitions must be mounted read-only by the deployment layer.
The owner must run under a dedicated systemd unit so closing its monitor file
descriptor cannot silently stop the modem.

## License

The original implementation in this repository is released under
GPL-2.0-or-later. Kernel and ModemManager dependencies retain their upstream
licenses. See `LICENSE`.
