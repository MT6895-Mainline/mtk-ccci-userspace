# Deployment Contract

This repository contains source and examples, not a turnkey flashing package.

Before starting the owner, the board integration must verify:

- `/dev/ccci_monitor`, `/dev/ccci_fs`, and `/dev/ccci_rpc` exist.
- CCCI modules match `uname -r`.
- CCCI modules are loaded, but MD remains idle (`md1:0`) before its owner starts.
- protected modem partitions are mounted read-only.
- `MDINIT_OVERLAY_ROOT` points to a private writable directory.
- `CCCI_EVIDENCE_DIR` is bounded and not a persistent NV location.

The owner starts MD; wait for READY before starting ModemManager, not before
starting the owner. `Before=ModemManager.service` orders service launches only;
it does not signal MD readiness. The example is not installed or enabled
automatically. The board integration must implement and verify that readiness
gate, module loading, and protected read-only mounts.

Configure a pinned kernel release and notes SHA256. The launcher refuses
missing pins, writable/wrong protected mounts, overlapping write roots, or an
already active modem. It does not load modules or mount partitions itself.

MDLOG access is disabled by default. Do not enable it on hardware where its
channel can trigger an assert. The owner still contains diagnostic readers;
generated packets/journal data can contain private NV contents and must not
be uploaded. FS/RPC capture is still the imported experimental behavior;
its cumulative size is not internally capped. Use a quota-limited private
runtime filesystem and journal limits. Source-only installation has not
been hardware-validated.

Closing the owner can stop MD. Never hot-restart it or unload CCCI modules
while MD is active. Only change the module set across a controlled shutdown.
No boot partition, NV partition, or firmware image is modified by this
repository.
