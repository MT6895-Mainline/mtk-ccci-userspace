# Deployment Contract

This repository contains source and examples, not a turnkey flashing package.

Before starting the owner, the board integration must verify:

- `/dev/ccci_monitor`, `/dev/ccci_fs`, and `/dev/ccci_rpc` exist.
- CCCI modules match `uname -r`.
- the modem kernel state reports the expected ready state.
- protected modem partitions are mounted read-only.
- `MDINIT_OVERLAY_ROOT` points to a private writable directory.
- `CCCI_EVIDENCE_DIR` is bounded and not a persistent NV location.

The service should be stopped before changing the kernel or CCCI module set.
No boot partition, NV partition, or firmware image is modified by this
repository.
