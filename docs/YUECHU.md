# yuechu (Xiaomi Civi 3, MT6895) -- modem bring-up notes

Board integration for `MTK_CCCI_BOARD=qqcandy` on the yuechu (MT6895)
mainline Linux 7.2 board.  Everything below was observed on hardware during
the first MD bring-up (2026-10-17).

## Verified state

* MD boots to READY (`md1:4`) about 2 s after `CCCI_IOC_DO_START_MD`
  (owner start -> `[POWER ON] set MD boot slave done: ret=0` ->
  `md_state change 0 -> 2 -> 3 -> 4`).
* SIM (China Mobile) comes up after `at_cfun.py`: `AT+CPIN?` READY,
  `+CEREG: 0,1` registered, `+CGATT: 1` attached, operator `46000` on LTE.
* `AT+COPS=?` lists China Telecom / China Unicom / China Mobile, so both
  receive and transmit chains work.
* The vendor tinysys SCP is up and the CCCI SCP glue syncs the MD state
  (`YUECHU-SCPMDSTATE ... md_state sync to SCP`, `IPI MD_STATE=2 ret=0`).

## Kernel pins

* release `7.2.10+`
* `/sys/kernel/notes` sha256
  `ad1b750f15569f9dd1df8b3f3b81d313ebfe7efd18ff4410a7422d6a96b95ca0`

Recompute both for every kernel rebuild; the launcher refuses mismatches.

## Partition mounts (read-only, by-partlabel)

```
nvdata     -> /mnt/vendor/nvdata
nvcfg      -> /mnt/vendor/nvcfg
protect1   -> /mnt/vendor/protect_f
protect2   -> /mnt/vendor/protect_s
mcf_ota_a  -> /mnt/vendor/mcf_ota
```

`start_owner.py` validates each mount (exact target, `ro`, and
`by-partlabel` identity) before the modem is started.

## Device nodes required

`/dev/ccci_monitor`, `/dev/ccci_fs`, `/dev/ccci_rpc`, `/dev/ccci_ccb_ctrl`
(all present on the yuechu kernel with `CONFIG_MTK_CCCI_MAINLINE=y`).

## Known gaps at this bring-up

* The modem repeatedly probes `R:/plmn/TS25/4/60.txt`; no drive root on
  this device carries a `plmn/` tree, so the request is answered `-19`.
  It does not prevent registration.
* Mobile data still needs the CCCI data-path HIFs
  (`CONFIG_MTK_CCCI_MAINLINE_DATAPATH_HIF=y`).  The deployed image has them
  off, so only the CCIF control path is up (per docs/PEARL.md that means
  data would have TX only).
* `AT+CSQ` reports 99/99 on this firmware even when registered+attached;
  use `+CEREG` / `+CGATT` as the health signal.
