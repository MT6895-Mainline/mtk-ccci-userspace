# Architecture

## Layers

```text
Linux kernel
  CCCI / CCIF / DPMAIF / ttyCCCI / ccmni / XFRM
        |
mtk-ccci-userspace
  modem owner, CCCI FS, kernel-routed RPC
        |
ModemManager mtk-soc plugin
  AT, SIM, registration, SMS, MIPC data and IMS control
        |
NetworkManager / desktop services
```

The owner daemon does not implement ModemManager's D-Bus API. The
ModemManager plugin does not load kernel modules or own the modem monitor
lifecycle. This keeps the transport/owner boundary stable and permits the
plugin to move toward the upstream ModemManager tree independently.

## Safety contract

The deployment layer is responsible for:

1. Matching the running kernel, CCCI module vermagic, and device tree.
2. Loading modules in the board-approved order.
3. Mounting protected modem partitions read-only.
4. Providing a writable, isolated overlay for modem file writes.
5. Running the owner in a dedicated service with bounded lifetime.

The userspace owner must not receive credentials, raw NV backups, or vendor
binary blobs from the source repository.
