# Source Provenance

The initial owner and RPC implementation was imported from the independently
implemented MT6895 qqcandy Linux bring-up project. Vendor binaries were used
as protocol references; none are included or used as runtime dependencies.

Imported source identities, before publication-only path changes:

- owner: `8e09ade3cbefd06fb75f02628df3bc97ef63e605a4b3d9bc08a4209268526c24`
- RPC: `dff14d82298d1a7aac83322ce86624c6c5b5478045845a69f0f4724068b3cd0a`

Publication work changes configurable deployment paths, installation,
preflight, and MDLOG default gating. It does not make the imported service
generic or production-ready. The live bring-up instance has not been replaced
by this copy.

Files use GPL-2.0-or-later. See the complete license text in `LICENSE`.

Layering references, not source imports:

- Qualcomm remote-filesystem daemon: `linux-msm/rmtfs`
- upstream ModemManager's `qcom-soc` plugin

The separate MTK control-plane fork is
`MT6895-Mainline/modemmanager-mtk-soc`. MIPC remains internal there for now;
no new standalone protocol-library API or shared ABI is promised.
