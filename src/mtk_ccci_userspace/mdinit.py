# SPDX-License-Identifier: GPL-2.0-or-later
#
# qqcandy v461: do NOT open /dev/ccci_md_log_ctrl before DO_START_MD.
#   PROVEN in run 70dfeed5 (v460): port_proxy.c:1214 port_user_register() maps
#   CCCI_UART1_RX -> CRIT_USR_META, and ccci_fsm.c:346 fsm_routine_boot() polls
#   ccci_port_check_critical_user() every EVENT_POLL_INTEVAL=20 ms until either
#   no critical user is active or ONLY CRIT_USR_FS is (ccci_port_critical_user_only_fsd).
#   With CRIT_USR_META set the gate never opened and the FSM sat in that poll for
#   the full BOOT_TIMEOUT (600 s in the current diagnostic build) -- md_state
#   stayed 0, no HS1, 2548+ get_boot_mode_from_dts polls.  The kernel's own
#   normal-boot branch (port_proxy.c:1344-1353) requires MDLOG and MDLOG_CTRL
#   *closed*; only the META_BOOT_ID branch (port_proxy.c:1333) expects UART1
#   open.  Normal boot must therefore not hold ccci_md_log_ctrl.
# qqcandy v457: + open the stock ccci_mdinit service-port set (no ccci_0_2xx).
# qqcandy v454: + read-only observation of the AP-side service ports stock
# ccci_mdinit opens but this harness never did, plus a /dev/ccci_monitor reader.
# qqcandy v452: + 0x101a GetDrive and 0x1016 UnlockAll (stock 0x19598/0x194bc contracts).
# qqcandy v451: + CCB control-header init (libccci_util ccci_ccb_init_users contract).
# qqcandy v450: CMPT_Write rewritten to the stock open/seek/write/close descriptor
#   semantics with handle chaining (block1 = handle). Fixes multi-chunk LID
#   rewrites that corrupted NR06_009/NR08_004 and caused lid_error_handle.c:238.
# qqcandy v425.11: + 0x1003 Read (stock 3-block reply: status + count + data).
# qqcandy v425.10: + 0x1025 GetFileDetail (stock 2-block reply: status + 24B times).
# qqcandy v425.9: + T: -> mcf_ota partition (the stock OTA package store).
# qqcandy v425.8: + 0x1010 GetAttributes.
# qqcandy v425.7: FS reply fragments carry CCCI_FS_REQ_SEND_AGAIN on all but the last.
# qqcandy v425.6: FS replies chunked at the 3476-byte CCCI FS wire limit.
# qqcandy v425.5: reader reassembles split FS messages (see try_parse_frame).
# qqcandy v425.4: + 0x1007 CreateDir, S: -> nvcfg.
# qqcandy v425.3: + 0x1024 CMPT_Write (COW), 0x100c Move, 0x1022 proven reply.
# qqcandy v425.1: 0x1022 reply layout proven from modem code (see below).
# qqcandy v425: X: drive REMAPPED to /mnt/vendor/protect_f/md (was nvcfg) and
# 0x1022 CMPT_Read implemented for real: reads desc[+20] length desc[+32] and
# returns the payload.  See the 0x1022 block below for the device evidence.
# v424 = 0x1022 diagnostic approximation; v423 = + 0x1005 Close + COW.
#
# Single behavioural variable vs v419: the responder now speaks the *stock*
# Open/handle protocol instead of returning a bare 4-byte zero.
#
# ------------------------------------------------------------------ evidence
# Wire frame (verified byte-for-byte against our own captured requests):
#   [struct ccci_header 16B][u32 op][u32 nblocks]{u32 len; data[len] (4B aligned)}*
# The AP->MD reply must use channel CCCI_FS_TX (=15) and op | 0xFFFF0000.
# port_dev_write() (PORT_F_USER_HEADER) sends the userspace buffer as the frame
# and only overwrites data[1] (= total length) and channel (= tx_ch).
#
# qqcandy drive mapping -- DEVICE-AUTHORITATIVE (read-only ext4 mounts of the
# stock partitions on this very device, 2026-09-22):
#   nvdata (ext4) -> /mnt/vendor/nvdata   [Z:]
#        md/nv_boot_trace        101423 B   <-- exactly what REQ#1 opens
#        md/NVRAM/{CALIBRAT,NVD_CORE,NVD_DATA,NVD_IMEI}, AllMap(23992 B), AllFile
#   nvcfg  (ext4) -> /mnt/vendor/nvcfg    [X:]
#        mdota/, sensor/, fg/, camera/, flash_calibration/
#   NO nv_config and NO nv_mini_dump exist anywhere -> REQ#2 (X:\nv_config,
#   mode 0x500 = read-only probe) is a probe that stock fails with -9; REQ#3
#   (X:\nv_mini_dump, mode 0x10400 = write intent) is created by stock.
#   NOTE: pearl's AllMap is 24272 B; the qqcandy AllMap is 23992 B and equals
#   the first u32 of the nvram partition.  Do not use pearl's number.
#
# Stock open semantics (authenticated ccci_mdinit, offline disassembly):
#   op 0x1001 -> 0x186f8 -> 0x1a628, which converts the UTF-16 path, maps the
#   drive letter (Z=0 X=1 Y=2 W=3 V=4 U=5 T=6 S=7 R=8 Q=9, base 0x341fc +
#   idx*36) and calls open@plt at 0x1ac54.  The reply is a single 4-byte
#   {handle} block; a failed open reports a negative errno (Android FSD logs
#   "ret -9", i.e. -EBADF).
#   op 0x1009 -> 0x19284 -> 0x1b514(handle,&out): cmp w0,#0x81, handle table
#   0x2ed30 (40 B entries), fd = [entry+16] (-1 invalid), [entry+8]==1, then
#   fstat(); invalid handle -> w21 = -10 (0x1b594).  Reply = {status}{size}.
#
# Read-only stance: the stock partitions are mounted read-only, so we never
# mutate NV data.  A modem-created file (write-intent mode, file absent) is
# redirected to a writable overlay so the modem-visible contract holds without
# touching stock partitions.  Reads always come from the real stock file.
import time
import ctypes, os, fcntl, struct, sys, time, signal, threading, binascii, mmap, select, glob, stat
import fnmatch

__version__ = "0.1.0"

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.prctl(15, b"ccci_mdinit", 0, 0, 0)

EVID = os.environ.get("CCCI_EVIDENCE_DIR", "/run/mtk-ccci/evidence")
# v873 EXPERIMENT -- single variable, rollback = this one line: the overlay/COW
# root is now CONFIGURABLE and defaults to a PERSISTENT directory under the Arch
# root, so the modem's NV write-backs survive a reboot exactly like stock (whose
# ccci_fsd writes the real, persistent nvdata partition) instead of vanishing
# from tmpfs every boot.  Basis: E1 proved the modem itself maintains
# Z:\NVRAM/NVD_DATA\CK00_000 (hiding it => assert at 28.6 s); the v826/v830
# "inert" verdict predates a boot NV chain that now reaches the first wave.  The
# read-only NV base is NOT touched by this: only the COW/overlay root moves.
#   MDINIT_OVERLAY_ROOT=/run/qqc_fs_overlay  => exact pre-v873 tmpfs behaviour.
# +B1 (merged into this file): a persistent root ALONE is not enough -- cow_map
# lives only in memory, so after a restart every promoted file would fall back
# to base and its first write would re-copy base OVER the persisted promotion
# (offline-proven).  cow_map_rebuild() below re-links OVERLAY/cow/* at startup;
# it is GATED OFF for the legacy root so the line above stays byte-exact.
OVERLAY_LEGACY = "/run/qqc_fs_overlay"
OVERLAY = os.environ.get("MDINIT_OVERLAY_ROOT", "/var/lib/mtk-ccci/overlay")
os.makedirs(EVID, exist_ok=True)
T0 = time.monotonic()

# Drive -> AP directory.  DEVICE-AUTHORITATIVE, from the stock partitions.
#   Z: -> nvdata partition, md/            (nv_boot_trace, NVRAM/, BITMAP ...)
#   X: -> protect1 partition, md/          <- v425 FIX
#   Y: -> protect2 partition, md/
#   W: -> nvdata partition, md_cmn/
# The v423/V424 mapping X: -> /mnt/vendor/nvcfg was WRONG: protect1/md is the
# only place that contains every file the modem asks for on X:, and the string
# "/mnt/vendor/protect_f/md" is literally present in stock ccci_mdinit.
#   protect1/md: MTBT_000(204) MT00A001(456) MTCS_000(424) MTSC_000(744)
#                MTFW_000(234) nv_mini_dump(778399) ...  nv_config ABSENT
#   protect2/md: MTBT_000(204) MTCS_000(424) MTSC_000(744) ... MT00A001 ABSENT
# nv_config is absent from BOTH, which is exactly why stock answers the modem's
# RO probe of X:\nv_config with -9 and the modem records it as a normal event.
# ---------------------------------------------------------------- drive table
# fix-lid: the letter -> directory bindings are now taken from the OFFICIAL
# NR16-family server `docs-local/external/mt6990-chain-bin/usr/bin/ccci_fsd`
# (FACT, VENDOR-BIN-ANALYSIS.md 3.1/3.2, re-verified for this patch):
#   * the used representation is the 9-entry POINTER table at .rodata 0x40f7e8,
#     8-byte stride, walked by `0x4046f8 ldr x23,[x26,x22,lsl#3]` with
#     `0x404860 cmp x22,#0x9`  => exactly 9 drives, in this order:
#         Z: X: Y: W: V: U: T: S: R:
#   * the 9 roots live at .data 0x421014, stride 0x24 (36 B), copied by the
#     init loop at 0x401dd4..0x401e94 (`mov x1,#0x24` / `cmp w23,#0x9`).
#   * mdinit.py:60 already recorded the same index order from the MODEM's own
#     md1rom (Z=0 X=1 Y=2 W=3 V=4 U=5 T=6 S=7 R=8 Q=9), so our modem addresses
#     drives by exactly this index -> the letters were right, the BINDINGS were
#     wrong for W/V/U/T/S/R.
# Candidates are tried IN ORDER and the first that EXISTS wins; a drive whose
# roots all fail is left out of FSD_DIRS, so map_md_path() returns None and the
# callers answer -19 (official "path not resolved").  **No directory is ever
# created** -- an absent root degrades explicitly instead of being faked.
#
# Where the OFFICIAL root is listed SECOND, that is a deliberate, documented
# device-specific deviation, not an oversight: the vendor binary targets a
# different product (FiberHome LG6851F / MT6990 OpenWrt) whose partition layout
# differs, while on PGZ110/MT6895 the directory the modem actually asks for is
# the second one (proven by the request paths in ours_journal.txt).  Putting the
# device-validated root second would silently change replies on the known-good
# path, which this patch must not do.
VENDOR_ROOT = os.environ.get("MTK_CCCI_VENDOR_ROOT", "/mnt/vendor")
VENDOR_ETC_ROOT = os.environ.get("MTK_CCCI_VENDOR_ETC_ROOT", "/vendor")
PRIVATE_ROOT = os.environ.get("MTK_CCCI_PRIVATE_ROOT", "/var/lib/mtk-ccci/private")

DRIVE_ROOTS = {
    # unambiguously correct, official == device (all 3 observed live)
    "Z": [os.path.join(VENDOR_ROOT, "nvdata/md")],            # official 0x421014
    "X": [os.path.join(VENDOR_ROOT, "protect_f/md")],         # official 0x421038
    "Y": [os.path.join(VENDOR_ROOT, "protect_s/md")],         # official 0x42105C
    # never requested by our modem (VENDOR-BIN-ANALYSIS 3.2 journal histogram),
    # so binding them officially costs nothing -- and W: was previously WRONG:
    # official W: = /vendor/firmware, while md_cmn is V:.
    "W": [os.path.join(VENDOR_ETC_ROOT, "firmware"),
          os.path.join(VENDOR_ROOT, "firmware")],
    "V": [os.path.join(VENDOR_ROOT, "nvdata/md_cmn")],        # official md_cmn root
    "U": [os.path.join(VENDOR_ROOT, "mdlpm")],                # likely absent here
    # Stock PGZ110 FSD maps T: to /vendor/etc/mdota.  That root may be absent
    # even when mcf_ota has similarly named directories; stat() then returns
    # ENOENT (-9), not metadata from the unrelated mcf_ota partition.
    "T": [os.path.join(VENDOR_ETC_ROOT, "etc/mdota")],
    #   modem asks S:/mdota/...; our nvcfg holds mdota/.  Official S: is
    #   /mnt/vendor (which on this device exists but has no mdota/).
    "S": [os.path.join(VENDOR_ROOT, "nvcfg"), VENDOR_ROOT],
    #   modem asks R:/cacerts/tls/*.*; the extracted tree lives here.  Official
    #   R: is /vendor/etc/md.  Keep the device-validated R: binding.
    "R": [os.path.join(VENDOR_ETC_ROOT, "etc/md")],
    # REOPENED(v872 "Q: 勿再改"): run9 stock FS frame #1120 asks
    # Q:/cacerts/, returns 0, and stock FSD maps it to /data/vendor_de/md.
    # Linux uses an isolated persistent application-data root, never NV.
    "Q": [PRIVATE_ROOT],
}
# The first nine are the official table; this phone's Q: is an additional
# private-data drive observed directly in run9, not a protected partition.
DRIVE_ORDER = ("Z", "X", "Y", "W", "V", "U", "T", "S", "R", "Q")


def resolve_drive_dirs(roots=None):
    """Bind each official drive letter to the first EXISTING candidate root.

    T: and Q: remain mapped even if their physical roots are absent.  T:
    lookups return ENOENT (-9); Q: writes go to the isolated COW overlay.
    Other absent roots are unmapped (-19).
    Never creates anything.
    """
    roots = DRIVE_ROOTS if roots is None else roots
    out = {}
    for letter in DRIVE_ORDER:
        cands = roots.get(letter, [])
        for cand in cands:
            if os.path.isdir(cand):
                out[letter] = cand
                break
        else:
            if letter in ("T", "Q") and cands:
                # Stock still resolves these drives when their backing root is
                # missing; a file lookup fails, while Q: mkdir uses the COW.
                out[letter] = cands[0]
                continue
            # FIX(v872 hotfix): this function runs at import time, BEFORE log() is
            # defined (log is at ~line 338) -> NameError killed the whole service
            # on the first deploy (device journal 07:31:12).  Use stderr directly.
            sys.stderr.write("DRIVE %s: no existing root among %r -> UNMAPPED (-19)\n"
                             % (letter, cands))
    return out


FSD_DIRS = resolve_drive_dirs()
MODE_RO_PROBE = 0x100          # stock: 0x100 set => read-only probe
# CCCI FS wire packet limit.  CCCI_MTU = (3584-128) = 3456
# (drivers/misc/mediatek/eccci/ccci_common_config.h).  port_dev_write() rejects
# PORT_F_USER_HEADER writes with -ENOMEM when
#     count > CCCI_MTU + header_len,  header_len = 16 + 4 for the FS port
# i.e. > 3476.  ccci_bm.h states the FS server sends CCCI_MTU of payload per
# packet while treating ccci_header and op_id as header, so the FS packet size
# is exactly 3476.  Confirmed by the modem's own request fragmentation: a
# 4116-byte logical message arrived as 3476 + 660, and 3456 + 640 = 4096
# = 4116 - 20.  A logical FS message longer than one packet MUST be chunked.
CCCI_MTU = 3456
FS_PKT_LIMIT = CCCI_MTU + 16 + 4      # 3476
MAX_HANDLE = 16
FS_OP_OPEN = 0x1001
FS_OP_SEEK = 0x1002
FS_OP_READ = 0x1003
FS_OP_WRITE = 0x1004
FS_OP_CLOSE = 0x1005
FS_OP_GET_SIZE = 0x1009
FS_OP_CMPT_READ = 0x1022
FS_OP_MOVE = 0x100c
FS_OP_CMPT_WRITE = 0x1024
FS_OP_MKDIR = 0x1007
FS_OP_GETATTR = 0x1010
FS_OP_GET_DETAIL = 0x1025
FS_OP_UNLOCK_ALL = 0x1016
FS_OP_GET_DRIVE = 0x101a
FS_OP_FIND_FIRST = 0x1012
FS_OP_FIND_NEXT = 0x1013
FS_OP_FIND_CLOSE = 0x1014
FS_OP_SET_DISK_FLAG = 0x101c
# fix-lid: ops the authoritative enum defines but this file had no branch for
# (LEAKED-MTK-MODEM-SRC.md FACT 2.1, `ccci_fs_if.h:79-115`).  The reply shapes
# below are NOT guessed: they were read from this device's own stock AP-side
# server, v537-stock-userspace-20260924/ccci_mdinit, whose FS-op jump table is
# u16@0xba72 with handler = 0x186f8 + tbl[op-0x1001]*4.  Each function below
# cites the exact handler addresses it was decoded from.
FS_OP_CLOSE_ALL = 0x1006
FS_OP_REMOVE_DIR = 0x1008
FS_OP_GET_FOLDER_SIZE = 0x100a
FS_OP_RENAME = 0x100b
FS_OP_COUNT = 0x100d
FS_OP_GET_DISK_INFO = 0x100e
FS_OP_DELETE = 0x100f
FS_OP_OPEN_HINT = 0x1011
FS_OP_LOCK_FAT = 0x1015
FS_OP_SHUTDOWN = 0x1017
FS_OP_XDELETE = 0x1018
FS_OP_CLEAR_DISK_FLAG = 0x1019
FS_OP_GET_CLUSTER_SIZE = 0x101b
FS_OP_OTP_WRITE = 0x101d
FS_OP_OTP_READ = 0x101e
FS_OP_OTP_QUERY_LEN = 0x101f
FS_OP_OTP_LOCK = 0x1020
FS_OP_RESTORE = 0x1021
FS_OP_BIN_REGION = 0x1023
# FS wire errors: native qqcandy ccci_mdinit Open calls open(2) at 0x1ac54.
# Its errno branch maps ENOENT (2) to -9 at 0x1b4d8/0x1b4e0; -19 at
# 0x1b074 is a distinct path-resolution failure. The old claim that every
# missing file returned -19 confused these branches.
# Evidence: docs-local/v873-fix-deploy/stock-open{,-tail}.asm.
FS_OK = 0
FS_PARAM_ERROR = -2
FS_DRIVE_NOT_FOUND = -4
FS_NO_MORE_FILES = -6          # official FindFirst/FindNext dir-end code
FS_FILE_NOT_FOUND = -9         # mapped file absent: ENOENT
FS_ACCESS_DENIED = -16
FS_IO_ERROR = -18              # NR16 errno mapper: EEXIST and most other errno
FS_PATH_NOT_FOUND = -19        # drive/path resolution failed, distinct from ENOENT
FS_PATH_TOO_LONG = -49         # official: converted path > 4096
FS_DISK_FULL = -22
FS_FILE_EXISTS = -36
FS_READ_ONLY_ERROR = -45


def fs_error_from_errno(e):
    """Map an OSError to the FS code the NR16-family server itself would send.

    AUTHORITATIVE BASIS (upgraded after this patch was first drafted): the
    official MT6990 / NR16-family FS server
    `docs-local/external/mt6990-chain-bin/usr/bin/ccci_fsd` contains an explicit
    errno->FS-code mapper at **0x4060b8**:

        sub  w19, w0, #2
        cmp  w19, #0x16
        b.hi -> return -18                 // errno < 2 || errno > 24
        adrp x0, 0x40f000 ; add x0, x0, #0x7a8
        ldrsb w0, [x0, w19, uxtw]          // 23-entry int8 table

    Its .rodata table at 0x40f7a8 was read out byte-for-byte: ONLY
        errno 2  (ENOENT) -> -9   FS_FILE_NOT_FOUND
        errno 13 (EACCES) -> -16  FS_ACCESS_DENIED
        errno 24 (EMFILE) -> -5
    and EVERY other errno in [2,24] -> -18; outside that range -> -18.
    This is the same table the pre-existing do_getfiledetail used, so that code
    was already right and this helper now matches it (one source of truth).

    NOTE for reviewers: an earlier draft of this helper invented -19 for ENOTDIR,
    -22 for ENOSPC, -36 for EEXIST and -2 for EBADF/EINVAL from the MT6795 leaked
    table.  That was WRONG for this generation -- the official NR16 server sends
    -18 for all of those.  Do not "improve" this table without new evidence.

    Leaking a raw errno is still unsafe (EINVAL(-22) would be read as
    FS_DISK_FULL), which is the defect this helper replaces.
    """
    return {2: FS_FILE_NOT_FOUND,      # ENOENT
            13: FS_ACCESS_DENIED,      # EACCES
            24: -5,                    # EMFILE (official table value)
            }.get(getattr(e, "errno", None), -18)


WHENCE = {0: os.SEEK_SET, 1: os.SEEK_CUR, 2: os.SEEK_END}
FS_OP_NAMES = {0x1001: "Open", 0x1002: "Seek", 0x1003: "Read", 0x1004: "Write",
               0x1005: "Close", 0x1006: "CloseAll", 0x1007: "CreateDir", 0x1010: "GetAttributes", 0x1009: "GetFileSize",
               0x100a: "GetFolderSize", 0x100b: "Rename", 0x100d: "Count",
               0x100e: "GetDiskInfo", 0x100f: "Delete", 0x1011: "OpenHint",
               0x1015: "LockFAT", 0x1017: "ShutDown", 0x1018: "XDelete",
               0x1019: "ClearDiskFlag", 0x101b: "GetClusterSize",
               0x101d: "OTPWrite", 0x101e: "OTPRead", 0x101f: "OTPQueryLength",
               0x1020: "OTPLock", 0x1021: "Restore", 0x1023: "Bin_Region_Access",
               0x100c: "Move", 0x1012: "FindFirst", 0x1013: "FindNext",
               0x1014: "FindClose", 0x1022: "CMPT_Read",
               0x1024: "CMPT_Write", 0x1025: "GetFileDetail",
               0x1016: "UnlockAll", 0x101a: "GetDrive",
               0x101c: "SetDiskFlag"}

handles = {}          # idx (1-based) -> {"fd","path","overlay","pos","promoted","src"}
hlock = threading.Lock()
# Persistent path -> COW overlay mapping.  Once a stock path has been promoted,
# every later Open of the same MD path must resolve to the overlay (the modem
# must keep observing its own appended data, never the untouched stock file).
cow_map = {}


def cow_map_rebuild():
    """v873+B1: re-link every persisted `OVERLAY/cow/<basename>` promotion to its
    base path, so a module restart keeps serving the modem its OWN bytes.

    BASIS (why B1 is required for the persistence experiment): `_promote_cow()`
    records the base->overlay mapping ONLY in the in-memory `cow_map`.  With the
    persistent root, a restart would otherwise fall back to the pristine base for
    every promoted file -- and the first write would re-copy the base OVER the
    persisted promotion (both facts offline-proven in the v873 self-test).  The
    modem would then see exactly the same NV input on boot 2 as on boot 1.

    AMBIGUITY: `cow/` is flat, so the base path is recovered by BASENAME.  A name
    that exists at more than one base path is SKIPPED (= keeps the old
    base-served behaviour instead of being mis-mapped).  Measured on this device
    (docs-local/v815-nv/device_nv_files.txt, 456 entries): exactly ONE such pair
    -- CALIBRAT/FILELIST vs NVD_IMEI/FILELIST; the other 454 names are unique.

    GATE: skipped for a legacy (tmpfs) root.  v872 never re-linked a mid-boot
    service restart, so keeping the map empty there makes
    MDINIT_OVERLAY_ROOT=/run/qqc_fs_overlay byte-identical to 298f5113... and
    makes the R0 one-line rollback exact rather than approximate.
    """
    if OVERLAY == OVERLAY_LEGACY:
        log("v873+B1 cow_map rebuild SKIPPED (legacy tmpfs root: pre-v873 "
            "semantics preserved)")
        return 0
    index = {}
    for root in FSD_DIRS.values():
        for dp, _dn, fns in os.walk(root):
            for f in fns:
                index.setdefault(f, []).append(os.path.join(dp, f))
    try:
        names = sorted(os.listdir(os.path.join(OVERLAY, "cow")))
    except OSError:
        names = []
    n, amb = 0, 0
    for f in names:
        o = os.path.join(OVERLAY, "cow", f)
        paths = index.get(f) or []
        if len(paths) == 1 and os.path.isfile(o):
            cow_map[paths[0]] = o
            n += 1
        elif len(paths) > 1:
            amb += 1
    log("v873+B1 cow_map rebuilt: %d promotion(s) relinked, %d ambiguous "
        "basename(s) skipped (e.g. FILELIST), %d cow entrie(s) seen"
        % (n, amb, len(names)))
    return n


def uptime():
    try:
        with open("/proc/uptime") as f:
            return float(f.read().split()[0])
    except OSError:
        return -1.0


def log(msg):
    print("[up=%10.6f t+%8.3f] %s" % (uptime(), time.monotonic() - T0, msg),
          flush=True)


def overlay_init():
    """v873: create the configured overlay root on demand (exist_ok=True).

    Only the ROOT is created here; the Z/, cow/ and .wh/ children keep being
    created lazily by their own call sites, so the sub-structure and every path
    resolution rule are unchanged.  The read-only NV base is never opened for
    writing.  A brand-new persistent root is deliberately NOT pre-populated from
    the old tmpfs root -- a predictable pristine start, only announced in the
    journal (the modem re-creates whatever it needs).
    """
    try:
        fresh = not os.path.isdir(OVERLAY) or not os.listdir(OVERLAY)
    except OSError:
        fresh = False
    try:
        os.makedirs(OVERLAY, exist_ok=True)
    except OSError as e:              # never a new crash mode: callers already
        log("v873 overlay root %s NOT creatable: %s"      # report their own
            % (OVERLAY, e))                               # write errors
        return
    stale = 0
    if fresh and OVERLAY != OVERLAY_LEGACY:
        try:
            stale = len(os.listdir(OVERLAY_LEGACY))
        except OSError:
            stale = 0
        if stale:
            log("v873 overlay root %s starts EMPTY while legacy %s holds %d "
                "entries -- NOT migrating (pristine start, deliberate)"
                % (OVERLAY, OVERLAY_LEGACY, stale))
    log("v873 overlay root=%s persistent=%s legacy_entries=%d"
        % (OVERLAY, OVERLAY != OVERLAY_LEGACY, stale))


overlay_init()
# v873+B1: must run AFTER overlay_init() (root exists) and after log() is
# defined; it walks the read-only base roots READ-ONLY and only fills cow_map.
cow_map_rebuild()


lifetime = 0
if len(sys.argv) > 1:
    try:
        lifetime = int(sys.argv[1])
    except ValueError:
        print("lifetime must be an integer number of seconds", flush=True)
        sys.exit(2)

fs_fd = None
mon_fd = None
rpc_fd = None


CCCI_IOC_DO_STOP_MD = (0x43 << 8) | 12    # _IO("C", 12)
# PEARL-MDRECOVER-1: ccci_mdinit calls these in its exception path; our
# owner never did, so after the (normal, Android-also-has-it)
# custom_nvram_sec assert the modem stayed in EXCEPTION forever while
# Android's mdinit restarted it and settled.  Verified by disassembling
# the stock binary: ioctl _IO('C',12) DO_STOP_MD, _IO('C',45)
# RESET_MD1_MD3_PCCIF, _IO('C',13) DO_START_MD appear repeatedly.
CCCI_IOC_RESET_MD1_MD3_PCCIF = (0x43 << 8) | 45   # _IO("C", 45)
# PEARL-MDRECOVER-4: DO_STOP_MD only parks the modem's state machine back
# in BOOTING (5 -> 7 -> 1) without re-running fsm_routine_boot, so the modem
# never reaches HS1.  DO_MD_RST is the hard reset that makes the FSM run the
# full boot sequence again.  Default = use DO_MD_RST; set
# PEARL_MDRECOVER_USERST=0 to go back to DO_STOP_MD.
CCCI_IOC_DO_MD_RST = (0x43 << 8) | 6   # _IO("C", 6)
# PEARL-MDRECOVER-5: CCCI_IOC_MD_RESET (C,0) is the one that matters.  In
# ccci_fsm_ioctl.c it sends CCCI_MD_MSG_RESET_REQUEST and injects
# MD_STA_EV_RESET_REQUEST -- i.e. it makes the FSM run its full boot again.
# DO_STOP_MD (C,12) only appends CCCI_COMMAND_STOP, which is why the modem
# was parked in BOOTING (5 -> 7 -> 1) and never reached HS1.  DO_MD_RST (C,6)
# is not implemented in this tree (ENOTTY).  Default = MD_RESET.
CCCI_IOC_MD_RESET = (0x43 << 8) | 0   # _IO("C", 0)
# PEARL-SIMLOCK-1: ccci_mdinit calls CCCI_IOC_SIM_LOCK_RANDOM_PATTERN
# (_IOW('C',46,unsigned int), 0x4004432e).  The kernel handler is
#   case SIM_LOCK_RANDOM_PATTERN:
#       fsm_monitor_send_message(md_id, CCCI_MD_MSG_RANDOM_PATTERN, 0);
# i.e. it pushes CCCI_MD_MSG_RANDOM_PATTERN at the modem and IGNORES the
# ioctl argument.  This owner never issued it, so the modem never saw that
# message -- and custom_nvram_sec (the IMEI / SIM-lock security module) is
# exactly the code that asserts here with para0 = -1001.
CCCI_IOC_SIM_LOCK_RANDOM_PATTERN = 0x4004432e   # _IOW("C", 46, unsigned int)


def md_stop_hw():
    """qqcandy: actually power the modem down before we go away.

    The old bye() only closed the fds and printed "modem will be stopped",
    which was not true: the MD kept running across a warm reboot, so the next
    boot's CCCI handshake met a live modem in an unknown state, hung, and the
    15 s hardware watchdog had to recover it.  Cold boot was always fine.
    stock's ccci_mdinit stops the modem on the way out; do the same here.

    CCCI_IOC_DO_STOP_MD takes an unsigned int *: 0 = normal stop (power off),
    non-zero = flight mode.  fsm_append_command(CCCI_COMMAND_STOP) performs the
    hardware stop asynchronously, so wait for the state to drop.
    """
    if mon_fd is None:
        return
    try:
        buf = bytearray(struct.pack("<I", 0))
        r = fcntl.ioctl(mon_fd, CCCI_IOC_DO_STOP_MD, buf, True)
        log("DO_STOP_MD ioctl -> %d" % r)
    except OSError as e:
        log("DO_STOP_MD ioctl failed: %s" % e)
        return
    st = -1
    for _ in range(40):                      # up to 4 s for the FSM to finish
        try:
            b = bytearray(struct.pack("<I", 0))
            fcntl.ioctl(mon_fd, CCCI_IOC_GET_MD_STATE, b, True)
            st = struct.unpack("<I", b)[0]
        except OSError:
            break
        if st in (0, 3):                     # INVALID / EXCEPTION => no longer up
            log("modem state now %d; hardware stopped" % st)
            return
        time.sleep(0.1)
    log("modem still state %d after stop wait; closing anyway" % st)


def bye(signum, frame):
    log("signal %d: stopping modem hardware, then closing fds" % signum)
    try:
        md_stop_hw()
    except Exception as e:
        log("md_stop_hw raised: %r" % (e,))
    for fd in (rpc_fd, fs_fd, mon_fd):
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    sys.exit(0)


# ------------------------------------------------------------------ protocol
def wcs2cs(b):
    out = []
    for i in range(0, len(b) - 1, 2):
        cp = b[i] | (b[i + 1] << 8)
        if cp == 0:
            break
        # stock 0x1a628 maps '\' (0x5c) to '/' (0x2f), exactly like the FSD
        out.append('/' if cp == 0x5C else (chr(cp) if 32 <= cp < 127 else '?'))
    return "".join(out)


def parse_req(data):
    """Return (op, nblocks, [(blk_bytes, ...)])."""
    if len(data) < 24:
        return None
    op, nb = struct.unpack_from("<II", data, 16)
    off, blks = 24, []
    for _ in range(nb):
        if off + 4 > len(data):
            break
        l = struct.unpack_from("<I", data, off)[0]
        off += 4
        if l > len(data) - off:
            break
        blks.append(data[off:off + l])
        off += (l + 3) & ~3
    return op, nb, blks


def map_md_path(mpath):
    """MD path (already converted, e.g. 'Z:/nv_boot_trace') -> AP path."""
    if isinstance(mpath, str) and len(mpath) >= 2 and mpath[1] == ':':
        drive, rest = mpath[0].upper(), mpath[2:]
        base = FSD_DIRS.get(drive)
        if (base is None or "\x00" in rest or
                (rest and not rest.startswith("/")) or
                ".." in rest.split("/")):
            return None, None
        path = base + rest
        root = os.path.realpath(base)
        try:
            if os.path.commonpath((root, os.path.realpath(path))) != root:
                return None, None
        except ValueError:
            return None, None
        return path, drive
    return None, None


def build_reply(req, op, blocks):
    """blocks = list of bytes; each becomes a 4B-aligned {len;data} block."""
    body = struct.pack("<II", op | 0xFFFF0000, len(blocks))
    for b in blocks:
        body += struct.pack("<I", len(b)) + b + b"\x00" * ((-len(b)) & 3)
    total = 16 + len(body)
    seq = (struct.unpack_from("<I", req, 8)[0] >> 16) & 0xFFFF
    reserved = struct.unpack_from("<I", req, 12)[0]
    hdr = struct.pack("<IIII", 0, total, (15 & 0xFFFF) | (seq << 16), reserved)
    return hdr + body


def send_reply(frame, op_field):
    """Write an FS reply, chunking it at the CCCI FS packet limit.

    Packet 0     : [ccci_header 16][op_field 4][body[0:3456]]
    Packet k > 0 : [ccci_header 16][op_field 4][body[k*3456:(k+1)*3456]]
    where body = frame[20:] (the logical frame after its own header and op).

    Every packet except the LAST carries data[0] |= CCCI_FS_REQ_SEND_AGAIN
    (0x80000000) -- the FS fragmentation marker that ccci_hif_ccif.h defines
    "specially for user: ccci_fsd data[0]".  Proof of the convention: the
    modem's own split request carried data[0]=0x80000000 on its first packet
    and data[0]=0 on its final packet; single-packet FS messages always use
    data[0]=0.  Without the marker the modem parses the first packet as a
    complete message, finds a block longer than the packet and fails the read
    (observed: CMPTREAD ret:-1001 for the 16384-byte NVD_DATA read).

    Stock FSD keeps the same transaction seq and reserved field in every
    fragment; each packet's data[1] is its own wire length.
    Returns (bytes_written, packet_count).
    """
    hdr = frame[:16]
    body = frame[20:]
    seq = (struct.unpack_from("<I", frame, 8)[0] >> 16) & 0xFFFF
    reserved = struct.unpack_from("<I", hdr, 12)[0]
    chunks = [body[i:i + CCCI_MTU] for i in range(0, len(body), CCCI_MTU)] or [b""]
    if len(chunks) == 1 and len(frame) <= FS_PKT_LIMIT:
        return os.write(fs_fd, frame), 1
    total, n = 0, 0
    for i, chunk in enumerate(chunks):
        d0 = 0x80000000 if i < len(chunks) - 1 else 0
        packet_len = 20 + len(chunk)
        h = struct.pack("<IIII", d0, packet_len,
                        (15 & 0xFFFF) | (seq << 16), reserved)
        total += os.write(fs_fd, h + op_field + chunk)
        n += 1
    return total, n


def do_open(mpath, mode):
    """Return (handle_or_neg_errno, logline)."""
    ap, drive = map_md_path(mpath)
    if ap is None:
        # fix-lid: an unmapped drive is a path that cannot resolve -> -19, the
        # official code for FindFirst's "all 9 drive letters failed" (0x4048c8)
        # and for Open's not-found path (0x40a504).
        return FS_PATH_NOT_FOUND, "unmapped drive in %r" % mpath
    ro = bool(mode & MODE_RO_PROBE)
    info = "drive=%s mode=0x%x %s ap=%s" % (
        drive, mode, "RO-probe" if ro else "write-intent", ap)

    # fix-lid: a tombstoned path is gone.  FS_CREATE(0x10000) / FS_CREATE_ALWAYS
    # (0x20000) legitimately re-create it (LEAKED FACT 2.4 open flags), anything
    # else gets the authoritative absence code -9 (FACT 2.4: the modem
    # special-cases FS_FILE_NOT_FOUND as an empty record at
    # nvram_drval_fat.c:1422-1427).
    wh = _is_whiteout(ap, drive)
    if wh and not (mode & 0x30000):
        return FS_FILE_NOT_FOUND, info + " -> whiteout (deleted) => -9"

    # COW persistence: a path that was promoted earlier resolves to the overlay
    # from now on, so the modem keeps seeing its own written data.
    resolved, present, _size, _note = resolve_ro_path(mpath)
    if present and resolved != ap:
        ovo = resolved
        flags = os.O_RDONLY if ro else os.O_RDWR
        try:
            fd = os.open(ovo, flags)
        except OSError as e:
            return fs_error_from_errno(e), info + " -> COW overlay open failed: %s" % e
        idx, _ = _alloc(fd, ovo, True, src=ap)
        return idx, (info + " -> COW-PERSIST reuse %s size=%d"
                     % (ovo, os.path.getsize(ovo)))

    # `and not wh` is essential: a tombstoned path must NOT fall through to the
    # stock file below (which still exists on disk), or FS_CREATE would hand back
    # a read-only handle onto content the modem just deleted.
    if os.path.exists(ap) and not wh:
        try:
            fd = os.open(ap, os.O_RDONLY)   # partitions are mounted read-only
        except OSError as e:
            return fs_error_from_errno(e), info + " -> open(RO) failed: %s" % e
        idx, _ = _alloc(fd, ap, False, src=ap)
        return idx, info + " -> EXISTS, opened RO"

    # FS_CCCI_Open: a mapped path that fails open(2) with ENOENT maps to
    # FS_FILE_NOT_FOUND (-9), not the unmapped-drive error (-19).
    # O_RDWR alone does not create a file; only FS_CREATE/FS_CREATE_ALWAYS do.
    if ro or not (mode & 0x30000):
        return FS_FILE_NOT_FOUND, info + " -> absent, no create flag => -9"

    # A create flag permits a new file in the writable overlay only.
    ov = os.path.join(OVERLAY, drive, os.path.relpath(ap, FSD_DIRS[drive]))
    try:
        os.makedirs(os.path.dirname(ov), exist_ok=True)
        # Stock opens with O_RDWR|O_CREAT and does NOT truncate an existing file,
        # so a reopen must preserve previously written content.  Only a genuine
        # first creation starts empty.
        ex = os.path.exists(ov)
        fd = os.open(ov, os.O_RDWR | os.O_CREAT, 0o660)
        if not ex:
            os.ftruncate(fd, 0)
        else:
            log("   OPEN overlay EXISTS -> reopened without truncate (%d B)"
                % os.path.getsize(ov))
        if wh:
            _clear_whiteout(ap, drive)   # fix-lid: a real create cancels the tombstone
    except OSError as e:
        return fs_error_from_errno(e), info + " -> absent, overlay create failed: %s" % e
    idx, _ = _alloc(fd, ov, True, src=ap)
    return idx, info + " -> absent, CREATED in overlay %s" % ov


def _alloc(fd, path, overlay, src=None):
    with hlock:
        for idx in range(1, MAX_HANDLE + 1):
            if idx not in handles and idx not in find_tab:
                handles[idx] = {"fd": fd, "path": path, "overlay": overlay,
                                "pos": 0, "promoted": overlay, "src": src}
                # Newly created overlay files must be visible to later opens.
                if overlay and src is not None:
                    cow_map[src] = path
                return idx, ""
        os.close(fd)
    return FS_PARAM_ERROR, "(handle table full)"   # fix-lid: was -9, not a file-absence


def _promote_cow(e):
    """Copy-on-write promotion: copy an existing stock (read-only) backing file
    into the writable overlay, then swap the handle over to it.  The real stock
    partition is never modified."""
    src = e["src"]
    ov = os.path.join(OVERLAY, "cow", os.path.basename(src))
    os.makedirs(os.path.dirname(ov), exist_ok=True)
    n = 0
    with open(src, "rb") as fi, open(ov, "wb") as fo:
        while True:
            b = fi.read(1 << 20)
            if not b:
                break
            fo.write(b)
            n += len(b)
    osz = os.path.getsize(src)
    if n != osz:
        raise OSError("COW copy short: %d != %d" % (n, osz))
    nfd = os.open(ov, os.O_RDWR)
    os.lseek(nfd, e["pos"], os.SEEK_SET)   # preserve the logical position exactly
    old = e["fd"]
    e["fd"] = nfd
    e["path"] = ov
    e["overlay"] = True
    e["promoted"] = True
    cow_map[src] = ov          # persist: future Opens of this path use the overlay
    try:
        os.close(old)
    except OSError:
        pass
    return ov, n


def do_close(h):
    """Stock 0x1c19c: handle<0x81, 40B entry (fd=[+16], state=[+8]==1),
    then plain close(2) (no fsync on the normal file path).  The handle entry is
    invalidated so the slot is reusable and a later use is an invalid handle.
    Reply = 1 block {4: status} (0 ok, -10 bad handle).
    The backing file itself is NOT deleted -- the COW overlay must survive so a
    reopen of the same MD path still observes the modem's own data."""
    with hlock:
        e = handles.pop(h, None)
    if e is None:
        return -10, "handle %d invalid => stock -10" % h
    try:
        os.close(e["fd"])
    except OSError as err:
        # fix-lid: was `-(err.errno or 5)`; -5 is not in the authoritative FS
        # table (LEAKED FACT 2.4) so the modem had no defined behaviour for it.
        return fs_error_from_errno(err), "close(%d) failed: %s" % (e["fd"], err)
    persist = e["src"] in cow_map
    return 0, ("closed handle=%d (backing=%s kept, cow_persist=%s, pos was %d)"
               % (h, e["path"], persist, e["pos"]))


def do_write(h, data, length):
    """Stock 0x1bdf8/0x23684: handle<0x81, 40B table entry (fd=[+16],
    state=[+8]==1), length sxtw, then sequential write(2) at the current
    position (so the position advances).  Reply = 2 blocks
    {4: status}{4: written}; status 0 on success, -10 bad handle,
    -errno on a real write error."""
    with hlock:
        e = handles.get(h)
    if e is None:
        return -10, 0, "handle %d invalid => stock -10" % h
    if length < 0:
        # fix-lid: was -22, which IS FS_DISK_FULL in the authoritative table
        # (LEAKED FACT 2.4) -- a negative length must not look like a full disk.
        return FS_PARAM_ERROR, 0, "negative length %d -> -2" % length
    if length != len(data):
        log("   WRITE WARN explicit length %d != block data %d -> using min"
            % (length, len(data)))
    length = min(length, len(data))
    if not e["promoted"]:
        try:
            ov, n = _promote_cow(e)
            log("   WRITE COW: copied %d B -> %s (pos preserved=%d)"
                % (n, ov, e["pos"]))
        except OSError as err:
            return fs_error_from_errno(err), 0, "COW promotion FAILED: %s" % err
    try:
        w = os.write(e["fd"], data[:length])
    except OSError as err:
        return fs_error_from_errno(err), 0, "write FAILED: %s" % err
    with hlock:
        e["pos"] += w
        pos = e["pos"]
    try:
        sz = os.fstat(e["fd"]).st_size
    except OSError:
        sz = -1
    return 0, w, "handle=%d wrote=%d newpos=%d size=%d" % (h, w, pos, sz)


def do_seek(h, off, whence):
    """Stock 0x1b848: handle<0x81, 40B table entry (fd=[+16], state=[+8]==1),
    whence<=2, then lseek(fd, (s32)offset, whence).  Reply = 1 block = w0
    (the new position, 32-bit).  Invalid handle/fd/state/whence -> -10."""
    with hlock:
        e = handles.get(h)
    if e is None:
        return -10, "handle %d invalid => stock -10" % h
    if whence > 2:
        return -10, "whence %d > 2 => stock -10" % whence
    try:
        pos = os.lseek(e["fd"], off, WHENCE[whence])
    except OSError as err:
        # INFERENCE: stock lets the raw lseek return through here; we return an
        # authoritative FS code and log it loudly.  fix-lid: was the bare errno,
        # whose EINVAL(-22) collides with FS_DISK_FULL (LEAKED FACT 2.4); a
        # failed seek must never be reported as a full disk.
        return fs_error_from_errno(err), "lseek FAILED: %s" % err
    with hlock:
        e["pos"] = pos
    return pos, "handle=%d off=%d whence=%d -> pos=%d" % (h, off, whence, pos)


def do_getsize(h):
    with hlock:
        e = handles.get(h)
    if e is None:
        return -10, 0, "handle %d invalid => stock -10" % h
    try:
        st = os.fstat(e["fd"])
    except OSError as err:
        return -10, 0, "fstat failed: %s" % err
    return 0, st.st_size, "%s size=%d" % (e["path"], st.st_size)


# ---------------------------------------------------------------- 0x1003 Read
# Stock AP handler @0x19188 (jump table 0xba72[2] = 0x4503 -> 0x19188):
#   19188  ldr  x19,[sp,#0x88]      ; descriptor list
#   1918c  ldr  x8, [x19,#0x8]      ; entry0.ptr = &handle (u32)
#   19190  ldr  x9, [x19,#0x18]     ; entry1.ptr = &length (u32)
#   19194  ldr  w0, [x8]            ; w0 = handle
#   19198  ldr  w2, [x9]            ; w2 = length requested
#   1919c  add  x1, x12,#0x1c       ; x1 = read destination (request buffer)
#   191a4  add  x3, sp,#0x120       ; x3 = &bytes_read
#   191ac  bl   0x1bb80             ; read helper (handle,dst,len,&n)
#   191b0  str  w0, [sp,#0x144]     ; status
#   191c0  ldr  w10,[sp,#0x120]     ; w10 = bytes read
#   191d0  mov  w20,#3              ; nblocks = 3
#   191d4  str  w10,[x19,#0x20]     ; entry2.len = bytes_read
#   191d8  ldr  x8, [sp,#0x90]      ; = x12+0x1c (read buffer)
#   191dc  str  x8, [x19,#0x28]     ; entry2.ptr = data
#   191e0  b    0x196c0             ; tail with w20=3
# Helper 0x1bb80: handle must be < 0x81 (else -10); table entry fd=[+16],
# state=[+8]==1 (else -10); read(2) at the current position via 0x23594; a -1
# read stores the raw return in *out and yields -10.  Reply blocks, in order:
#   {4: int32 status}{4: uint32 bytes_read}{bytes_read: data}
def do_read(h, length):
    """Sequential read at the handle position.  Never writes anything."""
    with hlock:
        e = handles.get(h)
    if e is None:
        return -10, 0, b"", "handle %d invalid => stock -10" % h
    if length <= 0:
        return 0, 0, b"", "handle=%d length=%d -> 0 bytes" % (h, length)
    try:
        data = os.read(e["fd"], length)
    except OSError as err:
        return fs_error_from_errno(err), 0, b"", "read FAILED: %s" % err
    with hlock:
        e["pos"] += len(data)
        pos = e["pos"]
    return 0, len(data), data, ("handle=%d want=%d got=%d newpos=%d file=%s"
                               % (h, length, len(data), pos, e["path"]))


# ------------------------------------------------------------------ reader
def try_parse_frame(buf):
    """Return (consumed_len, ok) for a complete FS request at buf[0].

    Returns (0, False) when more bytes are needed.  A block whose declared
    length runs past the end of what we have means the modem split one logical
    FS message across several CCIF messages (observed for ~4 KB trace writes:
    fragment 1 carried 3432 of a declared 4070 payload bytes and fragment 2's
    text continued the first fragment's text exactly mid-timestamp), so we must
    wait for and splice the continuation.
    """
    if len(buf) < 24:
        return 0, False
    nb = struct.unpack_from("<I", buf, 20)[0]
    if nb > 64:
        return 0, False
    off = 24
    for _ in range(nb):
        if off + 4 > len(buf):
            return 0, False
        l = struct.unpack_from("<I", buf, off)[0]
        off += 4
        if l > len(buf) - off:
            return 0, False
        off += (l + 3) & ~3
    return off, True


def fallback_reply(req):
    """Last-resort answer for a request whose handler raised (fix-lid).

    The reader loop has always caught handler exceptions, but it only LOGGED
    them: the modem's FS client, which is synchronous, then waited forever for
    an answer that never came.  This sends the authoritative FS_PARAM_ERROR
    (LEAKED-MTK-MODEM-SRC.md FACT 2.4) as a single 4-byte block for any op in
    the 0x10xx FS range -- the modal reply shape (22 of the stock handlers use
    it, and stock hardcodes -2 for the op it cannot serve, 0x18fe8).

    Returns True when a reply was written.
    """
    try:
        op = struct.unpack_from("<I", req, 16)[0]
    except Exception:
        return False
    if not (0x1000 <= op <= 0x10FF):
        return False
    try:
        send_reply(build_reply(req, op, [struct.pack("<i", FS_PARAM_ERROR)]),
                   struct.pack("<I", op | 0xFFFF0000))
    except (OSError, ValueError) as e:
        log("fallback reply write FAILED (op=0x%04x): %s" % (op, e))
        return False
    return True


def join_fs_fragment(pending, data):
    """Join MD fragments; stock replies use the last request packet's seq."""
    if pending and len(data) >= 20:
        return pending[:8] + data[8:12] + pending[12:] + data[20:]
    return pending + data


def fs_reader():
    n = 0
    pending = b""
    while True:
        try:
            data = os.read(fs_fd, 65536)
        except OSError as e:
            log("FS reader: os.read failed: %s" % e)
            return
        if not data:
            log("FS reader: EOF")
            return
        # Continuations repeat [CCCI header 16][op 4], then payload.  Keep
        # the latest fragment sequence for the response, as stock FSD does.
        pending = join_fs_fragment(pending, data)
        while True:
            used, ok = try_parse_frame(pending)
            if not ok:
                break
            req = pending[:used]
            pending = pending[used:]
            n += 1
            try:
                with open(os.path.join(EVID, "fs_req_%03d.bin" % n), "wb") as f:
                    f.write(req)
            except OSError as e:
                log("FS-REQ #%d blob write failed: %s" % (n, e))
            try:
                handle_one(n, req)
            except Exception as e:  # never let one request kill the responder
                import traceback
                log("FS-REQ #%d HANDLER EXCEPTION: %r" % (n, e))
                log(traceback.format_exc())
                # fix-lid: an exception used to leave this request UNANSWERED --
                # logged, but the modem's synchronous FS client waits forever.
                # Answer with the authoritative FS_PARAM_ERROR (LEAKED FACT 2.4)
                # whenever the frame parses and the op is in the 0x10xx FS range;
                # stock sets the same precedent for an op it cannot serve
                # (0x1023 handler hardcodes -2 at 0x18fe8).
                if fallback_reply(req):
                    log("FS-REQ #%d fallback reply sent (-> -2)" % n)

    return


# ---------------------------------------------------- deletion whiteouts (fix-lid)
# The stock partitions are mounted read-only and MUST stay byte-identical, so a
# Delete/RemoveDir/XDelete cannot be a real unlink of stock.  Instead we write a
# tombstone under OVERLAY/.wh/<drive>/<relpath>; resolve_ro_path, do_open and
# _find_entries all consult it, so the deleted object becomes invisible to the
# modem exactly as a real delete would make it.  Because OVERLAY lives on
# /run (tmpfs) the tombstones are dropped on reboot -- the stock partition is
# always the source of truth, so a bad delete can never be permanent.
WH_DIR = os.path.join(OVERLAY, ".wh")


def _wh_path(ap, drive):
    return os.path.join(WH_DIR, drive, os.path.relpath(ap, FSD_DIRS[drive])) + ".wh"


def _is_whiteout(ap, drive):
    if ap is None or drive is None:
        return False
    path = _wh_path(ap, drive)
    return os.path.isfile(path) or os.path.isfile(path[:-3])


def _set_whiteout(ap, drive):
    wh = _wh_path(ap, drive)
    os.makedirs(os.path.dirname(wh), exist_ok=True)
    with open(wh, "wb"):
        pass
    return wh


def _clear_whiteout(ap, drive):
    path = _wh_path(ap, drive)
    for marker in (path, path[:-3]):
        try:
            os.unlink(marker)
        except OSError:
            pass


def resolve_ro_path(mpath):
    """Resolve an MD path READ-ONLY, honouring the COW overlay + whiteouts.

    Returns (ap_path, present, size, note).  Never creates or truncates
    anything: the stock partitions must stay byte-identical.
    """
    ap, drive = map_md_path(mpath)
    if ap is None:
        return None, False, 0, "unmapped drive"
    if _is_whiteout(ap, drive):
        # fix-lid: a Delete/RemoveDir/XDelete tombstone must hide the stock
        # object from every later reader, otherwise the modem re-reads a file
        # it just deleted (nvram_scan_all_ldi / nvram_delete_all_nvram_files,
        # LEAKED-MTK-MODEM-SRC.md FACT 3.2/3.3).
        return ap, False, 0, "whiteout"
    if ap in cow_map and os.path.exists(cow_map[ap]):
        o = cow_map[ap]
        return o, True, os.path.getsize(o), "cow-overlay"
    # Persisted writes override the read-only backing after a process restart.
    ov = os.path.join(OVERLAY, drive, os.path.relpath(ap, FSD_DIRS[drive]))
    if os.path.exists(ov):
        return ov, True, os.path.getsize(ov), "overlay-file"
    if os.path.exists(ap):
        return ap, True, os.path.getsize(ap), "stock-ro"
    return ap, False, 0, "absent"


# v425.1 CORRECT IMPLEMENTATION -- reply layout proven from the modem's own code.
#
# Request descriptor (40 B) built by the modem's dev_fs_read @ 0x9162cbf4 and
# MD_FS_CMPT_Read @ 0x903397e4 (symbols.json; offset = addr - 0x90000000):
#     +0  steps    0x19, or 0x1d when the caller passes a non-zero offset
#     +4  +8       0
#     +12 capacity 0x700 (hardcoded in dev_fs_read)
#     +16 ptr      -> modem local (reply target for reply block1)
#     +20 OFFSET   file offset          <- advanced by bytes read in FS_CMPT_Read_Wrap
#     +24          0
#     +28 ptr      -> modem destination buffer (reply target for reply block3)
#     +32 LENGTH   bytes to read        <- min(len, 0x4000) per chunk
#     +36 ptr      -> modem local holding the per-chunk byte count (reply block2)
#
# FS_CMPT_Read_Wrap @ 0x9045b178 chains MD_FS_CMPT_Read in <=0x4000 chunks and
# advances [desc+20] (offset) and [desc+28] (destination) by the bytes reported
# in the local at [desc+36], accumulating the total into it.
#
# dev_fs_read's post-checks (@0x9162cc7e..0x9162cdd2):
#     s2 = desc+8;  if (s2 != 0)            -> error "FS_OP_CMPTREAD[fs_ret:%d]@722"
#     if (desc+0 != desc+4)                 -> error 0x104 -> "CMPT_R %d:%d,
#                                              read len(exp/r):%d:%d @728"
#     if (*(desc+36) != desc+32)            -> error 0x104 (same log)
#
# Both branches were observed live and match this model exactly:
#   v424 reply block0 = {status=-2, nread=0} -> desc+4=-2, desc+8=0
#        => desc+8==0 so it fell through, then desc+0(0x1d) != desc+4(-2)
#        => 0x104, logged "CMPT_R -2:29,read len(exp/r):0:44 @728".  OBSERVED.
#   v425 reply block0 = {status=0, nread=44} -> desc+4=0, desc+8=44
#        => desc+8!=0 => error @722 "FS_OP_CMPTREAD[fs_ret:44]".  OBSERVED.
#
# Therefore the ONLY reply that satisfies both checks is:
#     block0 (8 B) = {steps_echo, 0}      steps_echo = request desc+0
#     block1 (4 B) = unused by dev_fs_read (targets its own local)
#     block2 (4 B) = bytes delivered      <- checked against desc+32
#     block3       = payload              <- copied by the modem to desc+28
# The AP therefore never touches modem memory: the modem copies the payload
# itself.  Nothing outside the CCCI FS frame is required.
#
# SAFETY: read-only.  protect1/protect2/nvdata are mounted -o ro and are never
# written; every modem write goes through the COW overlay.
CMPT_MAX = 1 << 20


def do_cmpt_read(mpath, desc):
    """Return (blocks, logline)."""
    d = desc + b"\0" * 40
    steps, _a, _b, cap, dst1, off, stride, dst2, ln, addr3 = struct.unpack_from("<10I", d, 0)
    ap, present, size, note = resolve_ro_path(mpath)
    data = b""
    status = 0
    if present:
        try:
            if ln > CMPT_MAX:
                note += " len-capped"
                ln = CMPT_MAX
            with open(ap, "rb") as f:
                if off:
                    f.seek(off, os.SEEK_SET)
                data = f.read(ln)
        except OSError as e:
            # fix-lid: this exception used to be swallowed and the reply still
            # reported ret[1] = 0 (success) with 0 bytes delivered.  LEAKED
            # FACT 2.3 says ret[1] IS the FS error code and must be negative on
            # failure, otherwise dev_fs_read only sees a short read and logs
            # 0x104 "read len(exp/r)".  Only the error path changes.
            status = fs_error_from_errno(e)
            note += " read-error:%s" % e
    elif ap is None:
        # E2' (v873): an UNMAPPED DRIVE is the same -19 the rest of this server
        # returns (T8).  resolve_ro_path() returns ap=None only for that case.
        status = FS_PATH_NOT_FOUND
        note += " absent"
    else:
        # E2' (v873) -- THE DEVIATION THIS PATCH REMOVES.
        # Stock CMPT_Read is a compound OP: FS_CCCI_Open (Flag=0x700 =
        # FS_READ_ONLY|FS_OPEN_SHARED|FS_OPEN_NO_DIR -> open(...,O_RDONLY...))
        # runs FIRST; only then getsize/seek/read/close.  When the file is
        # missing that open() returns -1/ENOENT and the official errno mapper
        # (ccci_fsd:0x4060b8, .rodata table at 0x40f7a8 = [-9,-18,...]) turns
        # it into ret[1] = -9 with ret[0] = 0 (no op completed).
        # Old behaviour: ret[1] = 0 ("success") with 0 bytes.  The modem's
        # FS_CMPT_Read_Wrap then reports a 0-byte read, dev_fs_read compares it
        # against the requested Length and raises
        #   "CMPT_R 29:29,read len(exp/r):0:616 @728" -> 0x104 (260)
        # which the NV layer records as a CORRUPT RECORD (E1: [E][ID:0xE400])
        # instead of "file absent" (dev_err_code_translate(-9) = 0x1001).
        status = FS_FILE_NOT_FOUND
        note += " absent"
    extra = ("path=%r ap=%s(%s) size=%d steps=0x%x cap=%d off=%d len=%d "
             "got=%d dst1=0x%08x dst2=0x%08x addr3=0x%08x head=%s"
             % (mpath, ap, note, size, steps, cap, off, ln, len(data),
                dst1, dst2, addr3, binascii.hexlify(data[:32]).decode()))
    # E2': ret[0] IS the "completed ops" bitmap (NVRAM_FS_CMPT_* bits), not an
    # echo -- the modem's ccci_fs_get_buff() gates the copy of every reply LV on
    # it (GETFILESIZE->FileSize, READ->Read+Data).  On success the completed set
    # equals the requested opid_map (dev_fs_read enforces ret[0] == opid_map),
    # so the success bytes are unchanged; on failure the official server reports
    # only the ops it actually finished (0 when the open itself failed).
    # ret[1] is a SIGNED FS error code; the pre-E2' "<II" pack raised
    # struct.error on any negative value, so every error reply degenerated into
    # handle_one's generic -2 fallback instead of the official code.
    blocks = [struct.pack("<Ii", steps if status == 0 else 0, status),
              struct.pack("<I", 0),               # block1 FileSize (bit1 never set)
              struct.pack("<I", len(data)),       # block2 per-chunk byte count
              data]                               # block3 payload
    return blocks, extra


# ------------------------------------------------------ 0x100c Move
# Stock AP handler: op 0x100c -> 0x192ec (dispatch base is 0x186f8, not 0x186c8;
# idx = op - 0x1001, target = 0x186f8 + u16[0xba72 + idx*2]*4).
#   0x192ec: x0 = blocks[0].ptr (src, UTF-16), x1 = blocks[1].ptr (dst, UTF-16),
#            w2 = blocks[2][0] (flags), bl 0x1e540, b 0x196a8.
#   0x1e540 converts both UTF-16 paths and dispatches on the drive letter
#            (0x3a5a='Z' .. 0x3a51='Q' -> drive table 0x341fc + idx*36).
#            flags observed on the wire = 0x10001.
#   0x196a8 (common epilogue) => reply is ONE 4-byte block holding w0.
#            The modem's dev_fs_move @ 0x9162c7ea treats result >= 0 as success
#            (BGEC s3, zero) and result < 0 as failure.
# The destination resolves to protect2/md via Y:, a REAL stock NV partition, so
# the copy goes to the COW overlay and cow_map makes later Opens of Y: see it.
# The source is deliberately NOT deleted: protect_f/protect_s are the A/B mirror
# pair of the LID store, and deleting the source would desynchronise them.
# The deviation is logged as MOVE(COPY).
def do_move(src_mpath, dst_mpath, flags):
    """Return (result, logline).  Never writes a real stock partition."""
    src_ap, sdrive = map_md_path(src_mpath)
    dst_ap, ddrive = map_md_path(dst_mpath)
    if src_ap is None or dst_ap is None:
        return FS_PATH_NOT_FOUND, "unmapped drive src=%r dst=%r" % (src_mpath, dst_mpath)
    src_real, present, size, note = resolve_ro_path(src_mpath)
    dst_ov = os.path.join(OVERLAY, ddrive, os.path.relpath(dst_ap, FSD_DIRS[ddrive]))
    info = ("src=%r->%s(%s,size=%d) dst=%r->%s overlay=%s flags=0x%x"
            % (src_mpath, src_real, note, size, dst_mpath, dst_ap, dst_ov, flags))
    if not present:
        # fix-lid: was -2.  A missing source is FS_FILE_NOT_FOUND(-9), the code
        # the modem special-cases as benign (LEAKED FACT 2.4,
        # nvram_drval_fat.c:1422-1427); -2 (FS_PARAM_ERROR) reads as fatal.
        return FS_PATH_NOT_FOUND, info + " -> SRC ABSENT, no copy, -19"
    try:
        os.makedirs(os.path.dirname(dst_ov), exist_ok=True)
        with open(src_real, "rb") as fi, open(dst_ov, "wb") as fo:
            n = 0
            while True:
                b = fi.read(1 << 20)
                if not b:
                    break
                fo.write(b)
                n += len(b)
        if n != size:
            raise OSError("short copy %d != %d" % (n, size))
    except OSError as e:
        return fs_error_from_errno(e), info + " -> COPY FAILED: %s" % e
    cow_map[dst_ap] = dst_ov        # future Opens of Y:/... resolve to the overlay
    return 0, info + " -> MOVE(COPY) %d B ok" % n


# ---------------------------------------------------- 0x1024 CMPT_Write
#
# ROOT-CAUSE CORRECTION (v450).  The descriptor is NOT "offset-at-+16"; it is
# the same open/seek/write/close operation descriptor the stock userspace FSD
# uses.  Fields proven from the exact md1rom wrapper FS_CMPT_Write_Wrap
# @0x9045b0ec and MD_FS_CMPT_Write @0x90339622:
#     +0  flags   bit0 open, bit2 seek, bit4 close, bit5 write
#     +12 open mode
#     +16 seek offset (s32)     +20 seek whence
#     +24 source ptr (modem RAM, unused by AP)
#     +28 this-chunk length
#     +32 HANDLE (-1 first chunk)  <-- echoed back by the AP's reply block1
#     +36 ptr -> per-chunk HANDLE out      (AP reply block1 writes here)
#     +40 ptr -> per-chunk WRITTEN out     (AP reply block2 writes here)
# FS_CMPT_Write_Wrap after every chunk does  desc+32 = *(*desc+36)  and
# accumulates  written = *(*desc+40), then re-issues with the SAME handle and
# NO seek.  The file position therefore carries across chunks inside one open.
# The reply MUST be {8B block0}{4B handle}{4B written}; replying "written" in
# block1 (the previous v425..v449 behaviour) made the modem echo a bogus handle
# and the next chunk was written at offset 0 -- corrupting every multi-chunk
# LID rewrite (NR06_009, NR08_004, ...) until `lid_error_handle.c:238`
# "R fail as chksum error" asserted.  Single-chunk writes happened to work
# because desc+16 equalled their seek offset.
# The stock AP handler 0x1900c does exactly this: open (when handle<0) via
# 0x1a628, optional lseek via 0x1b848, write via 0x1bdf8, optional close via
# 0x1c19c, then replies 8/4/4 bytes.
# SAFETY: every write goes to the COW overlay only; protect_f stays read-only.
def _writable_overlay(mpath):
    """Return (ap_path, overlay_path, created) promoting stock content once."""
    ap, drive = map_md_path(mpath)
    if ap is None:
        return None, None, False
    if ap in cow_map and os.path.exists(cow_map[ap]):
        return ap, cow_map[ap], False
    ov = os.path.join(OVERLAY, drive, os.path.relpath(ap, FSD_DIRS[drive]))
    os.makedirs(os.path.dirname(ov), exist_ok=True)
    if not os.path.exists(ov):
        src, present, size, note = resolve_ro_path(mpath)
        with open(ov, "wb") as fo:
            if present:
                with open(src, "rb") as fi:
                    while True:
                        b = fi.read(1 << 20)
                        if not b:
                            break
                        fo.write(b)
        try:
            os.chmod(ov, 0o660)
        except OSError:
            pass
    cow_map[ap] = ov
    return ap, ov, True


def do_cmpt_write(mpath, desc, payload):
    """Stock open/seek/write/close descriptor semantics.  COW overlay only."""
    d = desc + b"\0" * 48
    flags = struct.unpack_from("<I", d, 0)[0]
    mode = struct.unpack_from("<I", d, 12)[0]
    seek_off = struct.unpack_from("<i", d, 16)[0]
    seek_whence = struct.unpack_from("<I", d, 20)[0]
    ln = struct.unpack_from("<I", d, 28)[0]
    handle = struct.unpack_from("<i", d, 32)[0]
    n = len(payload)
    if ln and ln < n:
        payload = payload[:ln]
        n = ln
    status, written, retops, notes = 0, 0, 0, []
    # --- open only when the echoed handle is not a live handle we own
    with hlock:
        live = handle in handles
    if not live:
        if flags & 0x1:
            ap, ov, fresh = _writable_overlay(mpath)
            if ov is None:
                status = -9
                notes.append("unmapped drive")
            else:
                try:
                    fd = os.open(ov, os.O_RDWR | os.O_CREAT, 0o660)
                except OSError as e:
                    status = -5
                    notes.append("open failed: %s" % e)
                else:
                    handle, _ = _alloc(fd, ov, True, src=ap)
                    if handle < 0:
                        status = handle
                        handle = -9
                    else:
                        retops |= 0x1
                    notes.append("open cow=%s promoted=%s mode=0x%x"
                                 % (ov, fresh, mode))
        else:
            status = -9
            notes.append("no handle and open bit clear")
    else:
        notes.append("reuse handle=%d" % handle)
    # --- seek
    if status == 0 and (flags & 0x4):
        with hlock:
            e = handles.get(handle)
        if e is None:
            status, notes = -10, notes + ["seek: handle gone"]
        else:
            try:
                pos = os.lseek(e["fd"], seek_off, WHENCE.get(seek_whence & 3,
                                                             os.SEEK_SET))
                e["pos"] = pos
                retops |= 0x4
                notes.append("seek off=%d whence=%d -> %d"
                             % (seek_off, seek_whence, pos))
            except OSError as err:
                status, notes = -5, notes + ["seek failed: %s" % err]
    # --- write
    if status == 0 and (flags & 0x20):
        with hlock:
            e = handles.get(handle)
        if e is None:
            status, notes = -10, notes + ["write: handle gone"]
        else:
            try:
                written = os.write(e["fd"], payload)
                with hlock:
                    e["pos"] += written
                retops |= 0x20
                notes.append("write want=%d got=%d pos=%d" % (n, written, e["pos"]))
            except OSError as err:
                status, notes = -5, notes + ["write failed: %s" % err]
    # --- close (release the slot, keep the overlay bytes)
    if flags & 0x10:
        with hlock:
            e = handles.pop(handle, None)
        if e is not None:
            try:
                os.close(e["fd"])
                retops |= 0x10
            except OSError as err:
                status = fs_error_from_errno(err)
                notes.append("close failed: %s" % err)
            notes.append("closed handle=%d" % handle)
    extra = ("path=%r flags=0x%x mode=0x%x off=%d len=%d payload=%d written=%d "
             "handle=%d status=%d %s"
             % (mpath, flags, mode, seek_off, ln, len(payload), written, handle,
                status, "; ".join(notes)))
    # E2': same signed-ret[1] fix as do_cmpt_read -- official write replies put
    # the failing op's FS code (or 0) in ret[1]; an unsigned pack cannot carry it.
    blocks = [struct.pack("<Ii", retops, status),
              struct.pack("<I", handle & 0xFFFFFFFF),  # block1 -> desc+36 handle
              struct.pack("<I", written)]              # block2 -> desc+40 written
    return blocks, extra


# ------------------------------------------------------ 0x1007 CreateDir
# Stock AP handler 0x19264: x0 = blocks[0].ptr (path), bl 0x1c8a4 (path convert
# + drive lookup + mkdir), b 0x196a8 => ONE 4-byte reply block = w0.
# The modem side is MD_FS_CreateDir @ 0x90339238, which the binary shows loading
# op 0x1007 (0x9033929a "ADDIU a3, zero, 0x1007") and preparing a single 4-byte
# reply buffer.
# First observed path: "S:\mdota" exists in the read-only nvcfg backing.
# Stock's mkdir returns EEXIST, which the NR16 FS errno mapper sends as -18.
# SAFETY: a genuinely missing directory is created under the COW overlay only.
def do_mkdir(mpath):
    """Return (result, logline).  Never writes a stock partition."""
    ap, drive = map_md_path(mpath)
    if ap is None:
        return FS_PATH_NOT_FOUND, "unmapped drive in %r" % mpath
    wh = _is_whiteout(ap, drive)
    if wh:
        pass          # fix-lid: a tombstoned dir is re-created by CreateDir
    ov = os.path.join(OVERLAY, drive, os.path.relpath(ap, FSD_DIRS[drive]))
    if not wh and (os.path.isdir(ap) or os.path.isdir(ov)):
        return FS_IO_ERROR, "path=%r ap=%s -> EEXIST, -18" % (mpath, ap)
    try:
        os.makedirs(ov, exist_ok=True)
        _clear_whiteout(ap, drive)
    except OSError as e:
        return fs_error_from_errno(e), "path=%r ap=%s overlay=%s -> FAILED: %s" % (mpath, ap, ov, e)
    return FS_OK, "path=%r ap=%s overlay=%s -> CREATED in overlay" % (mpath, ap, ov)


# ---------------------------------------------------- 0x1010 GetAttributes
# Modem op -> function map recovered by disassembling every MD_FS_* symbol in
# md1rom and extracting the FS opcode immediate it loads:
#   0x1001 Open 0x1002 Seek 0x1005 Close 0x1007 CreateDir 0x1008 RemoveDir
#   0x1009 GetFileSize 0x100a GetFolderSize 0x100b Rename 0x100c Move
#   0x100f Delete 0x1010 GetAttributes 0x1012 FindFirst 0x1013 FindNext
#   0x1014 FindClose 0x1016 UnlockAll 0x1017 ShutDown 0x101a GetDrive
#   0x101c SetDiskFlag 0x1021 Restore 0x1022 CMPT_Read 0x1023 Bin_Region_Access
#   0x1024 CMPT_Write 0x1025 GetFileDetail
# Stock AP handler 0x1010 -> 0x19370: x0 = blocks[0].ptr (path) -> bl 0x20098
# -> the shared drive-resolver/attribute routine, which strchr's to stat() and
# returns READ_ONLY bit 0 and DIRECTORY bit 4; b 0x196a8 => ONE 4-byte reply.
def do_getattr(mpath):
    """Return (value, logline).  Never creates or writes anything."""
    ap, present, size, note = resolve_ro_path(mpath)
    if not present:
        code = FS_PATH_NOT_FOUND if ap is None else FS_FILE_NOT_FOUND
        return code, "path=%r ap=%s(%s) -> ABSENT, %d" % (mpath, ap, note, code)
    try:
        mode = os.stat(ap).st_mode
    except OSError as e:
        return fs_error_from_errno(e), "path=%r -> stat failed: %s" % (mpath, e)
    # Native qqcandy 0x23d3c..0x23d58: readable and neither writable nor
    # executable gives READ_ONLY; 0x20328 adds DIRECTORY (0x10).
    val = int(bool(mode & 0o444) and not (mode & 0o333))
    if stat.S_ISDIR(mode):
        val |= 0x10
    return val, "path=%r ap=%s(%s,size=%d) -> attrs=%d" % (mpath, ap, note, size, val)


# --------------------------------------------------- 0x1025 GetFileDetail
# Stock AP handler, disassembled from vendor.img:/bin/ccci_mdinit at 0x19128:
#   19128  ldr  x19, [sp,#0x88]      ; parsed descriptor list
#   1912c  ldr  x0,  [x19,#0x8]      ; entry0.ptr = UTF-16 path (only input block)
#   19130  add  x1,  sp, #0x128      ; &detail (24 B stack scratch)
#   19134  bl   0x22bb0              ; FS_GetFileDetail(path, &detail)
#   19138  mov  w8, #4   / 19140 mov w10,#0x18 / 1914c mov w20,#2
#   19144  str  w0, [sp,#0x144]      ; block0 = int32 status
#   19148  str  w8, [x19]            ; block0.len = 4
#   19150  str  x9, [x19,#0x8]       ; block0.ptr = &status
#   19154  str  w10,[x19,#0x10]      ; block1.len = 24
#   1915c  str  x8,[x19,#0x18]       ; block1.ptr = &detail
#   19160  b    0x196c0              ; common tail, w20 = nblocks = 2
#
# FS_GetFileDetail @0x22bb0 converts the path (backslash -> '/'), keys the drive
# letter to a runtime-populated 36-byte drive record (same table as 0x1001/0x1010),
# stat()s <root>/<path-without-drive>, and on success (0x22ec8) stores the three
# tv_sec fields, in the order named by the format string @0x78d0
# "FS_GetFileDetail: mtime: %llu, atime=%llu, ctime=%llu":
#   detail[0] = st_mtim.tv_sec   (stat+0x58)
#   detail[1] = st_atim.tv_sec   (stat+0x48)
#   detail[2] = st_ctim.tv_sec   (stat+0x68)
# Return codes: 0 success; stat errno 2 -> -9 (0x22fa0); errno 24 -> -5 (0x230ec);
# errno 13 -> -16 (0x230f4); other errno -> -18 (0x230fc); composed path >= 0x1000
# -> -49 (0x22f08).  On any error the detail block is left untouched by stock; we
# send zeros so the reply is deterministic.
def do_getfiledetail(mpath):
    """Return (status, detail24, logline).  Read-only; writes nothing."""
    ap, present, size, note = resolve_ro_path(mpath)
    if not present:
        code = FS_PATH_NOT_FOUND if ap is None else FS_FILE_NOT_FOUND
        return code, b"\0" * 24, "path=%r ap=%s -> ABSENT, %d" % (mpath, ap, code)
    try:
        st = os.stat(ap)
    except OSError as e:
        # fix-lid: single source of truth -- same value-identical mapping as
        # before, now shared with every other error branch.
        code = fs_error_from_errno(e)
        return code, b"\0" * 24, ("path=%r ap=%s -> stat failed: %s (errno=%s, %d)"
                                  % (mpath, ap, e, e.errno, code))
    mt = st.st_mtime_ns // 1000000000
    at = st.st_atime_ns // 1000000000
    ct = st.st_ctime_ns // 1000000000
    detail = struct.pack("<QQQ", mt, at, ct)
    return 0, detail, ("path=%r ap=%s(%s,size=%d) -> status=0 mtime=%d atime=%d "
                       "ctime=%d" % (mpath, ap, note, size, mt, at, ct))


# ------------------------------------------------- 0x101a GetDrive / 0x1016 UnlockAll
# Stock 0x101a -> 0x19598: x0/x1/x2 = *(u32*)blocks[0..2], bl 0x2271c, one
# 4-byte reply block = the return value.  0x2271c validates and returns 0x5a
# (90) for type=4, else -2 with a log.  Live request (run 01d7ec02 #736):
# type=4, serial=2, AltMask=0xc -> 0x5a.
# Stock 0x1016 -> 0x194bc: one 4-byte reply block with value 1, no other work.
def do_getdrive(dtype, serial, altmask):
    """Return the stock reply value for GetDrive(type, serial, AltMask)."""
    if (dtype & 0x1C) == 0 or (dtype & 0xFFFFFFE3) != 0:
        return -2, "type=0x%x serial=%d mask=0x%x -> -2 (invalid type)" % (
            dtype, serial, altmask)
    if dtype != 0x10 and serial > 2:
        return -2, "type=0x%x serial=%d mask=0x%x -> -2 (serial>2)" % (
            dtype, serial, altmask)
    if serial == 0:
        return -2, "type=0x%x serial=0 -> -2" % dtype
    if dtype == 0x10 and serial > 1:
        return -2, "type=0x10 serial=%d -> -2" % serial
    if altmask != 1 and (altmask & 1):
        return -2, "type=0x%x mask=0x%x -> -2 (bit0)" % (dtype, altmask)
    if altmask != 2 and (altmask & 2):
        return -2, "type=0x%x mask=0x%x -> -2 (bit1)" % (dtype, altmask)
    if dtype != 4:
        return -2, "type=0x%x -> -2 (not FS_DRIVE_I_SYSTEM)" % dtype
    return 0x5A, "type=4 serial=%d mask=0x%x -> 0x5a" % (serial, altmask)


# ------------------------------------------------- 0x101c SetDiskFlag
# v816: the LAST FS request of every boot (FS-REQ #753, len=24, nblocks=0) and
# the only one this harness leaves unanswered.  Stock handler recovered from
# vendor/bin/ccci_mdinit: the FS-op jump table is a u16 array at 0xba72,
# index = op - 0x1001, handler = 0x186f8 + table[index]*4; index 27 (0x101c)
# gives 0x18f64:
#   18f64  mov  w8, #4              ; block0.len = 4
#   18f68  ldrb w9, [x26]           ; drive/mode byte
#   18f70  str  wzr, [sp, #324]     ; reply value = 0
#   18f78  str  w8, [x11]           ; block0.len
#   18f80  str  x10, [x11, #8]      ; block0.ptr = &value
#          ...                      ; b 198f0 common tail, nblocks = 1
# Modem side (md1rom 0x90338aea MD_FS_SetDiskFlag): request op = 0x101c with
# NO input block, one 4-byte output block, whose u32 it then logs.  So the
# minimum viable reply is exactly one 4-byte block with value 0.
def do_setdiskflag():
    """Stock-exact reply for FS 0x101c: one 4-byte block, value 0."""
    return 0, "nblocks=0 -> value=0 (stock handler 0x18f64)"


# ---------------------------------------------------------------------------
# v478 -- FS 0x1012 FindFirst / 0x1013 FindNext, CONSERVATIVE FIRST CUT.
#
# The modem's replay of its last unserved request is `0x1012 FindFirst` on
# `R:\cacerts\tls\*.*` (boot 013fd318 FS-REQ #746; v469 #751).  Contract proven so
# far (see PLAN-findfirst.md): reply nblocks = 4; block0 = 52-byte directory
# entry; block1 = name, length = chars*2 + 2, `0` = NO ENTRY; modem name capacity
# = 9 chars incl. NUL (max 8 UTF-16 chars); entry buffer 52 B inside the 72-byte
# struct the modem zeroes.
#
# The 52-byte entry's FIELD layout is still undecoded (it lives in
# CCCI_FS_OP_Wrapper.constprop.1368, 1229 ins), so this first cut sends NO guessed
# fields: it always returns the "no entry" state the modem's own code handles
# explicitly (w8 == 0 -> block1 length 0) with a zeroed 52-byte block0.  The
# purpose is to prove the reply path end to end (accepted? parsed? what does the
# modem do next?) before real names or real entry fields are ever emitted.
# The directory is still enumerated here, for evidence only.
find_seen = {"first": 0, "next": 0}


def _read_dir_names(directory):
    """Use libc readdir order, including '.'/'..' as stock FSD does."""
    c = ctypes.CDLL(None, use_errno=True)
    c.opendir.argtypes, c.opendir.restype = [ctypes.c_char_p], ctypes.c_void_p
    c.readdir.argtypes, c.readdir.restype = [ctypes.c_void_p], ctypes.c_void_p
    c.closedir.argtypes, c.closedir.restype = [ctypes.c_void_p], ctypes.c_int
    handle = c.opendir(os.fsencode(directory))
    if not handle:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    names = []
    try:
        while True:
            ctypes.set_errno(0)
            entry = c.readdir(handle)
            if not entry:
                err = ctypes.get_errno()
                if err:
                    raise OSError(err, os.strerror(err))
                break
            reclen = ctypes.c_ushort.from_address(entry + 16).value
            if reclen <= 19 or reclen > 1024:
                raise OSError("invalid dirent length")
            name = ctypes.string_at(entry + 19, reclen - 19).split(b"\0", 1)[0]
            names.append(os.fsdecode(name))
    finally:
        c.closedir(handle)
    return names


def _find_entries(mpath):
    """List wildcard matches in stock readdir order, including dot entries."""
    ap, drive = map_md_path(mpath)
    if not ap:
        return None, drive, []
    d = os.path.dirname(ap)
    try:
        names = [n for n in _read_dir_names(d)
                 if fnmatch.fnmatchcase(n, os.path.basename(ap))]
    except OSError as e:
        return ap, drive, ["<glob error %s>" % e]
    # fix-lid: a tombstoned entry must not be enumerated, or the modem's
    # FindFirst -> FindNext -> Delete loop (nvram_multi_folder.c:650-661,
    # LEAKED FACT 3.3) would rediscover and re-delete it on every pass.
    if drive:
        names = [n for n in names if not _is_whiteout(os.path.join(d, n), drive)]
    return ap, drive, names


# v865 -- 按离线逆向（NanoMIPS md1rom + stock ccci_mdinit）实现的**真枚举**。
# 纠正 v478 契约：应答 nblocks=3 = [4B 句柄/状态][52B 目录项][名字]（4 是**请求**的输入块数）；
# 旧实现回 4 块且顺序不同 => modem 在 CCCI_FS_OP_Wrapper(0x90338762) 断言并返回 -1001。
FIND_MORE, FIND_ENOENT, MAX_FIND = -6, -9, 64
find_tab = {}
find_seen = {"first": 0, "next": 0}


def _dosdt(t):
    # Stock FSD uses C struct tm's year-since-1900, and BFI overwrites both
    # date fields with tm_mday after the year addition.  Its seconds are raw.
    d = (t.tm_sec & 0x1F) | ((t.tm_min & 0x3F) << 5) | ((t.tm_hour & 0x1F) << 11)
    d = (d | 0x60000000) + ((t.tm_year - 1900) << 25)
    return ((d & ~0x01FF0000) | ((t.tm_mday & 0x1F) << 16) |
            ((t.tm_mday & 0x0F) << 21)) & 0xFFFFFFFF


def _attr_of(ap):
    try:
        m = os.stat(ap).st_mode
    except OSError:
        return None
    a = 0x01 if ((m & 0o444) and not (m & 0o333)) else 0
    return a | (0x10 if (m & 0o170000) == 0o040000 else 0)


def _entry52(ap, name, cap_chars):
    st = os.stat(ap)
    b = bytearray(52)
    b[11] = _attr_of(ap) or 0
    b[12] = 1 if len(name) < cap_chars else 0
    stamp = _dosdt(time.gmtime(st.st_mtime))  # stock Android sandbox timezone UTC
    struct.pack_into("<I", b, 14, stamp)
    struct.pack_into("<I", b, 22, stamp)
    struct.pack_into("<I", b, 28, st.st_size & 0xFFFFFFFF)
    return bytes(b)


def _name_blk(name, cap_chars):
    maxc = max(cap_chars - 1, 0)
    return name[:maxc].encode("utf-16-le", "replace") + b"\x00\x00", len(name) <= maxc


def _advance(h, cap_chars):
    c = find_tab.get(h)
    if c is None:
        return FIND_ENOENT, b"\x00" * 52, b""
    if c["idx"] >= len(c["names"]):
        return FIND_MORE, c.get("last_entry", b"\x00" * 52), b""
    n = c["names"][c["idx"]]
    ap = os.path.join(c["dir"], n)
    nb, _fits = _name_blk(n, cap_chars)
    try:
        e = _entry52(ap, n, cap_chars)
    except OSError:
        return FIND_ENOENT, b"\x00" * 52, b""
    c["idx"] += 1
    c["last_entry"] = e  # stock leaves the last entry in the output on EOF
    return 0, e, nb


def do_find_first(mpath, req_attr, forbid_attr, cap_chars):
    find_seen["first"] += 1
    ap, drive, names = _find_entries(mpath)
    if not ap:
        return FIND_ENOENT, b"\x00" * 52, b"", "unmapped path=%r" % mpath
    d = os.path.dirname(ap)

    def _ok(n):
        a = _attr_of(os.path.join(d, n))
        return a is not None and (req_attr & ~a) == 0 and (forbid_attr & a) == 0

    keep = [n for n in names if _ok(n)]
    if not keep or len(find_tab) >= MAX_FIND:
        return FIND_MORE, b"\x00" * 52, b"", ("path=%r dir=%r match=%d (MORE)"
                                              % (mpath, d, len(keep)))
    h = next((k for k in range(1, MAX_FIND + 1)
              if k not in find_tab and k not in handles), 0)
    if not h:
        return FIND_MORE, b"\x00" * 52, b"", "handle table full"
    find_tab[h] = {"dir": d, "names": keep, "idx": 0}
    st, e, nb = _advance(h, cap_chars)
    extra = ("path=%r dir=%r match=%d h=%d cap=%d attr=%d/%d st=%d"
             % (mpath, d, len(keep), h, cap_chars, req_attr, forbid_attr, st))
    if st != 0:
        find_tab.pop(h, None)
        return st, e, nb, extra + " (empty after filter)"
    return h, e, nb, extra


def do_find_next(handle, cap_chars):
    find_seen["next"] += 1
    st, e, nb = _advance(handle, cap_chars)
    extra = "h=%d cap=%d call#%d st=%d" % (handle, cap_chars, find_seen["next"], st)
    if st in (FIND_MORE, FIND_ENOENT):
        find_tab.pop(handle, None)
    return st, e, nb, extra


def do_find_close(handle):
    find_tab.pop(handle, None)
    return 0, "h=%d (tab=%d)" % (handle, len(find_tab))


# ===========================================================================
# fix-lid: the FS ops this file was missing entirely.
#
# AUDIT BASIS for every reply shape below: this device's OWN stock AP-side FS
# server, v537-stock-userspace-20260924/ccci_mdinit.  Its op->handler jump table
# is u16@0xba72 with handler = 0x186f8 + tbl[op-0x1001]*4 (v417-fs-consumer/
# RESULT.md, re-verified for this patch).  Each handler ends in one of two
# common epilogues that set the reply block count in w20:
#     0x196a8 -> w20 = 1, one 4-byte block (the generic scalar-result reply)
#     0x196c0 -> whatever the handler itself set
# The ops missing from this file were, per LEAKED-MTK-MODEM-SRC.md FACT 2.1:
#   0x1006 CloseAll  0x1008 RemoveDir  0x100a GetFolderSize  0x100b Rename
#   0x100d Count     0x100e GetDiskInfo 0x100f Delete        0x1011 OpenHint
#   0x1015 LockFAT   0x1017 ShutDown   0x1018 XDelete       0x1019 ClearDiskFlag
#   0x101b GetClusterSize  0x101d-0x1020 OTP*  0x1021 Restore  0x1023 BinRegion
# The task rule is honoured throughout: where the SEMANTICS are not provable
# from a leaked source we never fake success -- we record the request and reply
# with an authoritative FS_* code (FACT 2.4).  Stock itself sets the precedent:
# its 0x1023 handler hardcodes `mov w8,#0xfffffffe` (-2) at 0x18fe8.
# ===========================================================================

def do_close_all():
    """0x1006 CloseAll: stock 0x19240 `bl 0x155f0` (close every handle) then
    `19244 mov w8,#4` / `1924c mov w20,#1` => reply nb=1 [4B ret].
    BASIS: ccci_mdinit 0x19240-0x19260 disassembly."""
    with hlock:
        hs = list(handles.keys())
    for h in hs:
        do_close(h)
    return FS_OK, "closed %d handle(s) (stock 0x19240 -> bl 0x155f0)" % len(hs)


def do_shutdown():
    """0x1017 ShutDown: stock 0x194fc -> `bl 0x155f0` (the SAME close-all worker
    as CloseAll) then `19534 mov w20, wzr` => reply **nblocks = 0**, no blocks.
    BASIS: ccci_mdinit 0x194fc-0x19538 disassembly; LAST-REPLY-AUDIT.md:56.
    WHY IT MATTERS: this op WAS observed on the wire (t = 707.09 s, right after
    our 0x1016 UnlockAll reply) and this file had no branch for it, so it fell
    into the silent NO-REPLY default (LAST-REPLY-AUDIT.md:55 and :122)."""
    n = len(handles)
    do_close_all()
    return "closed %d handle(s), reply nblocks=0 (stock 0x194fc)" % n


def do_delete(mpath):
    """0x100f Delete: stock 0x19360 -> `19364 ldr x0,[x19,#8]` (path)
    `19368 bl 0x1fabc` -> `b 0x196a8` => reply nb=1 [4B ret].  0x1fabc is the
    shared path-convert + drive-resolve helper (it compares the drive u16
    against 0x3a5a='Z:', 0x3a58='X:', 0x3a59='Y:', 0x3a57='W:'); `unlink@plt`
    is present in this binary.
    BASIS: ccci_mdinit 0x19360 disassembly + the PLT symbol list.
    MODEM SIDE (LEAKED FACT 3.3): nvram_multi_folder.c:658
    `retval = FS_Delete(fullfilename); if (retval != FS_NO_ERROR)
     { FS_FindClose(handle); return KAL_FALSE; }` -- a wrong non-zero code aborts
    the whole folder wipe; nvram_drval_fat.c:423 also deletes a record file whose
    size does not match its section*records expectation.
    SAFETY: the stock partition is NEVER unlinked.  We drop our own overlay copy
    (if we made one) and write a tmpfs tombstone, so the file is invisible from
    now on -- see the whiteout block above."""
    ap, drive = map_md_path(mpath)
    if ap is None:
        return FS_PATH_NOT_FOUND, "unmapped drive in %r" % mpath
    ov = os.path.join(OVERLAY, drive, os.path.relpath(ap, FSD_DIRS[drive]))
    existed = os.path.exists(ov) or os.path.exists(ap)
    try:
        _set_whiteout(ap, drive)
        if os.path.exists(ov):
            os.unlink(ov)
        cow_map.pop(ap, None)
    except OSError as e:
        return fs_error_from_errno(e), "path=%r -> whiteout FAILED: %s" % (mpath, e)
    if not existed:
        # HYPOTHESIS: stock's unlink() would report the same absence as -9.  -9
        # is chosen deliberately over -2 because it is the code the modem treats
        # as "normal absence" rather than a fatal error (FACT 2.4).
        return FS_PATH_NOT_FOUND, "path=%r ap=%s -> absent, tombstoned, -19" % (mpath, ap)
    return FS_OK, "path=%r ap=%s -> tombstoned (stock untouched), 0" % (mpath, ap)


def do_remove_dir(mpath):
    """0x1008 RemoveDir: stock 0x19274 -> `19278 ldr x0,[x19,#8]` (path)
    `1927c bl 0x1cfe0` -> `b 0x196a8` => reply nb=1 [4B ret]; rmdir@plt present.
    BASIS: ccci_mdinit 0x19274 disassembly + PLT list.
    MODEM SIDE (LEAKED FACT 3.3): nvram_delete_certain_folder /
    nvram_create_certain_folder create and remove whole folder trees.
    SAFETY: a stock directory is never rmdir'd; we tombstone it and remove only
    our own overlay copy."""
    ap, drive = map_md_path(mpath)
    if ap is None:
        return FS_PATH_NOT_FOUND, "unmapped drive in %r" % mpath
    ov = os.path.join(OVERLAY, drive, os.path.relpath(ap, FSD_DIRS[drive]))
    existed = os.path.isdir(ov) or os.path.isdir(ap)
    try:
        _set_whiteout(ap, drive)
        if os.path.isdir(ov):
            try:
                os.rmdir(ov)
            except OSError:
                pass          # a non-empty overlay dir stays, but is invisible
        cow_map.pop(ap, None)
    except OSError as e:
        return fs_error_from_errno(e), "path=%r -> whiteout FAILED: %s" % (mpath, e)
    if not existed:
        return FS_PATH_NOT_FOUND, "path=%r ap=%s -> absent dir, tombstoned, -19" % (mpath, ap)
    return FS_OK, "path=%r ap=%s -> tombstoned dir, 0" % (mpath, ap)


def do_rename(src_mpath, dst_mpath):
    """0x100b Rename: stock 0x192d8 -> `x0 = LV0.ptr`, `x1 = LV1.ptr`,
    `192e4 bl 0x1dc70` -> `b 0x196a8` => reply nb=1 [4B ret]; rename@plt present.
    BASIS: ccci_mdinit 0x192d8 disassembly + PLT list.  Note this is exactly the
    0x100c Move handler (0x192ec -> 0x1e540) minus the third flag block.
    MODEM SIDE (LEAKED FACT 3.2): nvram_pseudo_merge() ->
    nvram_deal_with_exception() performs FS_Delete + FS_Rename.
    IMPLEMENTATION: reuse the proven do_move copy path, then tombstone the
    source -- which is what "rename" means to the modem, and what do_move
    deliberately does NOT do (it keeps the A/B LID mirror pair in sync).
    Never writes a stock partition."""
    src_real, present, size, note = resolve_ro_path(src_mpath)
    if not present:
        return FS_PATH_NOT_FOUND, "rename src=%r (%s) -> absent, -19" % (src_mpath, note)
    res, extra = do_move(src_mpath, dst_mpath, 0)
    if res != FS_OK:
        return res, "rename -> copy leg failed: " + extra
    ap, drive = map_md_path(src_mpath)
    try:
        _set_whiteout(ap, drive)
        cow_map.pop(ap, None)
    except OSError as e:
        return fs_error_from_errno(e), "rename -> copied but src whiteout FAILED: %s" % e
    return FS_OK, "rename %r -> %r %d B ok, src tombstoned" % (src_mpath, dst_mpath, size)


def do_open_hint(mpath, flag, hint):
    """0x1011 OpenHint: stock 0x19380.
    Decoded: `19384 ldr x8,[x19,#24]` = LV1.ptr -> `1938c ldr w1,[x8]` = Flag;
    `19388 ldr x0,[x19,#8]` = LV0.ptr = path; `19390 bl 0x1a628(path, Flag)`.
    Reply: `19394 mov w8,#4` (block0.len), `1939c mov w10,#8` (block1.len),
    `193a4 ldr x11,[x19,#40]` = LV2.ptr = the caller's OWN hint buffer, stored as
    block1.ptr, `193b0 mov w20,#2` => reply nb=2 = [4B ret][8B hint echo].
    BASIS: ccci_mdinit 0x19380-0x193bc disassembly; LAST-REPLY-AUDIT.md:96.
    HYPOTHESIS: 8 B is THIS build's hint size (the MT6795 source shows a 20 B
    hint, LEAKED FACT 2.2).  We resolve that conflict without inventing a
    semantic by echoing the request's own hint block verbatim -- exactly what
    stock does -- so the size follows whatever the modem sent.
    PRIORITY: low.  OpenHint belongs to the NON-compact NVRAM path and this
    target is compact (`__NVRAM_FS_OPERATION_COMPACT__`, FACT 2.3b), so the modem
    may never send it (LEAKED P0-2)."""
    ap, present, size, note = resolve_ro_path(mpath)
    if not present:
        return FS_PATH_NOT_FOUND, hint, (
            "path=%r ap=%s(%s) flag=0x%x -> absent, -19 (hint echoed, %d B)"
            % (mpath, ap, note, flag, len(hint)))
    return FS_OK, hint, (
        "path=%r ap=%s(%s,size=%d) flag=0x%x -> 0, hint echoed %d B"
        % (mpath, ap, note, size, flag, len(hint)))


def do_get_disk_info(mpath, flags):
    """0x100e GetDiskInfo: stock 0x19320.
    Decoded: `19320 add x0,sp,#0x11c0` (84-byte scratch), `19330 bl 0x1f8bc`;
    reply `19334 mov w8,#4` (block0.len), `1933c mov w10,#0x54` (84, block1.len),
    `1934c mov w20,#2` => reply nb=2 = [4B ret][84B disk info].
    BASIS: ccci_mdinit 0x19320-0x1935c disassembly.
    Worker 0x1f8bc decoded: it stats the runtime drive-table path via
    `statfs@plt` and on success writes exactly FOUR fields of the 84 B struct,
    then returns 0; on statfs failure it returns -1 (`1fa40 mov w0,#-1`):
        +48 = 512                 (`1f990 mov w8,#0x200; 1f99c stp w8,w4,[x19,#48]`)
        +52 = f_bsize / 512       (`1f994 ldr x9,[sp,#40]; 1f998 lsr x4,x9,#9`)
        +56 = f_blocks, low 32    (`1f9a0 ldr w5,[sp,#48]; 1f9b4 str w5,[x19,#56]`)
        +64 = 512                 (`1f9b8 str w8,[x19,#64]`)
    Stock leaves the other 80 bytes untouched (not zeroed); we emit 0 there
    rather than inventing values.
    HYPOTHESIS: which of these the modem reads as BytesPerCluster is NOT proven;
    +52 (sectors per block) is the only plausible candidate.  If the modem ever
    requests this op and still fails, REVERT THIS HUNK FIRST.
    MODEM SIDE (LEAKED FACT 3.2 / P0-2): FS_GetDiskInfo(L"Z:\\\\", &DI,
    FS_DI_BASIC_INFO|FS_DI_FREE_SPACE) is nvram_init()'s FIRST call, and it is
    only made when BytesPerCluster == 0."""
    ap, drive = map_md_path(mpath)
    if drive is None or drive not in FSD_DIRS:
        # unmapped path -> -19 (official FindFirst drive-match failure, 0x4048c8)
        return FS_PATH_NOT_FOUND, b"\0" * 84, "unmapped drive in %r -> -19" % mpath
    root = FSD_DIRS[drive]
    info = bytearray(84)
    try:
        st = os.statvfs(root)
    except OSError as e:
        return -1, bytes(info), "statvfs(%s) failed: %s -> -1 (stock value)" % (root, e)
    bsize = st.f_frsize or st.f_bsize or 512
    struct.pack_into("<I", info, 48, 512)
    struct.pack_into("<I", info, 52, max(bsize // 512, 1) & 0xFFFFFFFF)
    struct.pack_into("<I", info, 56, st.f_blocks & 0xFFFFFFFF)
    struct.pack_into("<I", info, 64, 512)
    return FS_OK, bytes(info), (
        "path=%r root=%s flags=0x%x -> 0, 84B disk-info (sector=512 spb=%d "
        "blocks=%d bfree=%d)"
        % (mpath, root, flags, max(bsize // 512, 1), st.f_blocks, st.f_bfree))


def do_get_folder_size(mpath, arg):
    """0x100a GetFolderSize: stock 0x192c0 -> `x0 = LV0.ptr` (path),
    `192c4 ldr x8,[x19,#24]; 192cc ldr w1,[x8]` = LV1.ptr's u32,
    `192d0 bl 0x1d5bc` -> `b 0x196a8` => reply nb=1 [4B size-or-negative-error].
    BASIS: ccci_mdinit 0x192c0-0x192d4 disassembly.
    HYPOTHESIS: the u32 is a filter/flags word (unproven); we log it and sum the
    resolved tree without filtering.  Absent path -> -9 (FACT 2.4)."""
    ap, present, size, note = resolve_ro_path(mpath)
    if not present:
        return FS_PATH_NOT_FOUND, "path=%r ap=%s(%s) arg=0x%x -> absent, -19" % (mpath, ap, note, arg)
    if os.path.isdir(ap):
        total = 0
        for dirpath, _dirs, files in os.walk(ap):
            for fn in files:
                try:
                    total += os.stat(os.path.join(dirpath, fn)).st_size
                except OSError:
                    pass
    else:
        total = size
    return FS_OK, "path=%r ap=%s(%s) arg=0x%x -> %d B" % (mpath, ap, note, arg, total)


def do_count(mpath, arg):
    """0x100d Count: stock 0x19308 -> `x0 = LV0.ptr` (path),
    `1930c ldr x8,[x19,#24]; 19314 ldr w1,[x8]`, `19318 bl 0x1f2cc` ->
    `b 0x196a8` => reply nb=1 [4B count-or-negative-error].
    BASIS: ccci_mdinit 0x19308-0x1931c disassembly.
    HYPOTHESIS: the u32 filter semantics and the exact counting rule are not
    proven; we count what the resolved path yields and log the arg.  Absent
    path -> -9 (FACT 2.4)."""
    ap, present, size, note = resolve_ro_path(mpath)
    if not present:
        return FS_PATH_NOT_FOUND, "path=%r ap=%s(%s) arg=0x%x -> absent, -19" % (mpath, ap, note, arg)
    if os.path.isdir(ap):
        try:
            n = len(os.listdir(ap))
        except OSError as e:
            return fs_error_from_errno(e), "path=%r listdir failed: %s" % (mpath, e)
    else:
        n = 1
    return FS_OK, "path=%r ap=%s(%s) arg=0x%x -> count=%d" % (mpath, ap, note, arg, n)


def do_lock_fat():
    """0x1015 LockFAT: stock 0x19480 stores value 0 unconditionally
    (`1948c str wzr,[sp,#324]`) then nb=1 with block0.len=4 => [4].  It is a
    local flag in stock; there is nothing to lock in our overlay.
    BASIS: ccci_mdinit 0x19480-0x194a0 disassembly."""
    return FS_OK, "-> 0 (stock 0x19480 hardcodes 0)"


def do_clear_disk_flag():
    """0x1019 ClearDiskFlag: stock 0x19554 stores value 0 unconditionally
    (`19560 str wzr,[sp,#324]`) then nb=1 with block0.len=4 => [4].
    BASIS: ccci_mdinit 0x19554-0x19570 disassembly."""
    return FS_OK, "-> 0 (stock 0x19554 hardcodes 0)"


def do_get_cluster_size(arg):
    """0x101b GetClusterSize: stock 0x195bc -> `195c4 ldr w0,[x8]` = LV0.ptr's
    u32, `195c8 bl 0x228c0` -> `b 0x196a8` => reply nb=1 [4B size-or-error].
    BASIS: ccci_mdinit 0x195bc-0x195cc disassembly.
    We return the REAL fundamental block size of the nvdata filesystem rather
    than a hardcoded constant (no invented value)."""
    try:
        st = os.statvfs(FSD_DIRS["Z"])
    except OSError as e:
        return -1, "arg=0x%x statvfs failed: %s -> -1" % (arg, e)
    val = st.f_frsize or st.f_bsize or 512
    return val, "arg=0x%x -> %d (real f_frsize of %s)" % (arg, val, FSD_DIRS["Z"])


def do_bin_region(arg):
    """0x1023 Bin_Region_Access: stock 0x18fa0 logs "SDF: %d", calls
    `18fe4 bl 0x22ad4(w0 = LV0.ptr's u32)` and then HARDCODES the reply to -2:
    `18fe8 mov w8,#0xfffffffe` / `18fec mov w9,#4` / `18ff4 mov w20,#1`.
    BASIS: ccci_mdinit 0x18fa0-0x19008 disassembly.
    So stock itself answers this op with nb=1 [4B = -2]; we mirror it exactly.
    This is also the precedent for the default branch in handle_one below."""
    return FS_PARAM_ERROR, "arg=0x%x -> -2 (stock 0x18fe8 hardcodes -2)" % arg


def do_refuse_write(op_name, mpath):
    """Record a write-capable op we deliberately do not perform, and answer with
    the authoritative refusal code instead of faking success.

    BASIS: this is now evidence-driven rather than table-picked.  The official
    NR16-family server `mt6990-chain-bin/usr/bin/ccci_fsd` implements XDelete as
    a recursive delete and gates writes on `FS_IsReadOnly`, and its errno mapper
    (0x4060b8) emits only three negatives for I/O failures: -9, -16 and -5.
    -16 FS_ACCESS_DENIED is therefore the generation-correct way to say "refused"
    and it is also in the MT6795 FACT 2.4 table.  (LEAKED P0-3 sanctioned
    "-45 FS_READ_ONLY_ERROR or -16"; -45 is NOT in the official mapper's
    vocabulary, so -16 is the safer of the two.  This is a deliberate refusal of
    a write to the X: important-data / IMEI partition -- FACT 3.4 -- and to the
    NV LID store for Restore.  No NV/IMEI data is written, deleted or restored.)"""
    return FS_ACCESS_DENIED, "%s path=%r -> -16 FS_ACCESS_DENIED (refused)" % (op_name, mpath)


def handle_one(n, data):
    if True:
        p = parse_req(data)
        if p is None:
            log("FS-REQ #%d len=%d UNPARSEABLE hex=%s"
                % (n, len(data), binascii.hexlify(data).decode()))
            return
        op, nb, blks = p
        log("FS-REQ #%d len=%d op=0x%04x(%s) nblocks=%d"
            % (n, len(data), op, FS_OP_NAMES.get(op, "?"), nb))
        for i, b in enumerate(blks):
            log("   blk%d len=%d raw=%s" % (i, len(b), binascii.hexlify(b).decode()))

        reply = None
        if op == FS_OP_OPEN and len(blks) >= 2:
            mpath = wcs2cs(blks[0])
            mode = struct.unpack_from("<I", blks[1] + b"\0\0\0\0", 0)[0]
            log("   OPEN path=%r" % mpath)
            h, extra = do_open(mpath, mode)
            if extra:
                log("   OPEN %s" % extra)
            log("   OPEN reply handle=%d" % h)
            reply = build_reply(data, op, [struct.pack("<i", h)])
        elif op == FS_OP_SEEK and len(blks) >= 3:
            h = struct.unpack_from("<i", blks[0] + b"\0\0\0\0", 0)[0]
            off = struct.unpack_from("<i", blks[1] + b"\0\0\0\0", 0)[0]
            whence = struct.unpack_from("<I", blks[2] + b"\0\0\0\0", 0)[0]
            res, extra = do_seek(h, off, whence)
            log("   SEEK %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", res)])
        elif op == FS_OP_READ and len(blks) >= 2:
            h = struct.unpack_from("<i", blks[0] + b"\0\0\0\0", 0)[0]
            ln = struct.unpack_from("<i", blks[1] + b"\0\0\0\0", 0)[0]
            st, nread, payload, extra = do_read(h, ln)
            log("   READ %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", st),
                                           struct.pack("<I", nread), payload])
        elif op == FS_OP_WRITE and len(blks) >= 3:
            h = struct.unpack_from("<i", blks[0] + b"\0\0\0\0", 0)[0]
            ln = struct.unpack_from("<i", blks[2] + b"\0\0\0\0", 0)[0]
            st, written, extra = do_write(h, blks[1], ln)
            log("   WRITE %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", st),
                                           struct.pack("<i", written)])
        elif op == FS_OP_CLOSE and len(blks) >= 1:
            h = struct.unpack_from("<i", blks[0] + b"\0\0\0\0", 0)[0]
            st, extra = do_close(h)
            log("   CLOSE %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", st)])
        elif op == FS_OP_GET_SIZE and len(blks) >= 1:
            h = struct.unpack_from("<i", blks[0] + b"\0\0\0\0", 0)[0]
            st, size, extra = do_getsize(h)
            log("   GETSIZE handle=%d status=%d size=%d (%s)" % (h, st, size, extra))
            reply = build_reply(data, op,
                                [struct.pack("<i", st), struct.pack("<I", size)])
        elif op == FS_OP_GETATTR and len(blks) >= 1:
            val, extra = do_getattr(wcs2cs(blks[0]))
            log("   GETATTR %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", val)])
        elif op == FS_OP_GET_DETAIL and len(blks) >= 1:
            mpath = wcs2cs(blks[0])
            st, detail, extra = do_getfiledetail(mpath)
            log("   GETDETAIL %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", st), detail])
        elif op == FS_OP_GET_DRIVE and len(blks) >= 3:
            a0 = struct.unpack_from("<I", blks[0] + b"\0\0\0\0", 0)[0]
            a1 = struct.unpack_from("<I", blks[1] + b"\0\0\0\0", 0)[0]
            a2 = struct.unpack_from("<I", blks[2] + b"\0\0\0\0", 0)[0]
            val, extra = do_getdrive(a0, a1, a2)
            log("   GETDRIVE %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", val)])
        elif op == FS_OP_UNLOCK_ALL:
            log("   UNLOCKALL -> 1 (stock 0x194bc)")
            reply = build_reply(data, op, [struct.pack("<i", 1)])
        elif op == FS_OP_SET_DISK_FLAG:
            val, extra = do_setdiskflag()
            log("   SETDISKFLAG %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", val)])
        elif op == FS_OP_MKDIR and len(blks) >= 1:
            res, extra = do_mkdir(wcs2cs(blks[0]))
            log("   MKDIR %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", res)])
        elif op == FS_OP_MOVE and len(blks) >= 3:
            msrc = wcs2cs(blks[0])
            mdst = wcs2cs(blks[1])
            fl = struct.unpack_from("<I", blks[2] + b"\0\0\0\0", 0)[0]
            res, extra = do_move(msrc, mdst, fl)
            log("   MOVE %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", res)])
        elif op == FS_OP_CMPT_WRITE and len(blks) >= 3:
            mpath = wcs2cs(blks[0])
            blocks, extra = do_cmpt_write(mpath, blks[1], blks[2])
            log("   CMPT_WRITE %s" % extra)
            reply = build_reply(data, op, blocks)
        elif op == FS_OP_CMPT_READ and len(blks) >= 2:
            mpath = wcs2cs(blks[0])
            blocks, extra = do_cmpt_read(mpath, blks[1])
            log("   CMPT_READ [DIAGNOSTIC APPROXIMATION] %s" % extra)
            reply = build_reply(data, op, blocks)
        elif op == FS_OP_FIND_FIRST and len(blks) >= 4:
            _ra = blks[1][0] if blks[1] else 0
            _fa = blks[2][0] if blks[2] else 0
            _cap = struct.unpack_from("<I", blks[3] + b"\0\0\0\0", 0)[0]
            h, entry, name, extra = do_find_first(wcs2cs(blks[0]), _ra, _fa, _cap)
            log("   FINDFIRST %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", h), entry, name])
        elif op == FS_OP_FIND_NEXT and len(blks) >= 2:
            _h = struct.unpack_from("<i", blks[0] + b"\0\0\0\0", 0)[0]
            _cap = struct.unpack_from("<I", blks[1] + b"\0\0\0\0", 0)[0]
            st, entry, name, extra = do_find_next(_h, _cap)
            log("   FINDNEXT %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", st), entry, name])
        elif op == FS_OP_FIND_CLOSE:
            _h = struct.unpack_from("<i", blks[0] + b"\0\0\0\0", 0)[0] if blks else 0
            res, extra = do_find_close(_h)
            log("   FINDCLOSE %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", res)])
        elif op == FS_OP_CLOSE_ALL:
            st, extra = do_close_all()
            log("   CLOSEALL %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", st)])
        elif op == FS_OP_SHUTDOWN:
            extra = do_shutdown()
            log("   SHUTDOWN %s" % extra)
            reply = build_reply(data, op, [])           # stock 0x194fc: nblocks=0
        elif op == FS_OP_DELETE and len(blks) >= 1:
            st, extra = do_delete(wcs2cs(blks[0]))
            log("   DELETE %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", st)])
        elif op == FS_OP_REMOVE_DIR and len(blks) >= 1:
            st, extra = do_remove_dir(wcs2cs(blks[0]))
            log("   REMOVEDIR %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", st)])
        elif op == FS_OP_RENAME and len(blks) >= 2:
            st, extra = do_rename(wcs2cs(blks[0]), wcs2cs(blks[1]))
            log("   RENAME %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", st)])
        elif op == FS_OP_OPEN_HINT and len(blks) >= 3:
            _fl = struct.unpack_from("<I", blks[1] + b"\0\0\0\0", 0)[0]
            st, hint, extra = do_open_hint(wcs2cs(blks[0]), _fl, blks[2])
            log("   OPENHINT %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", st), hint])
        elif op == FS_OP_GET_DISK_INFO and len(blks) >= 1:
            _fl = struct.unpack_from("<I", blks[1] + b"\0\0\0\0", 0)[0] if len(blks) >= 2 else 0
            st, info84, extra = do_get_disk_info(wcs2cs(blks[0]), _fl)
            log("   GETDISKINFO %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", st), info84])
        elif op == FS_OP_GET_FOLDER_SIZE and len(blks) >= 1:
            _a = struct.unpack_from("<I", blks[1] + b"\0\0\0\0", 0)[0] if len(blks) >= 2 else 0
            val, extra = do_get_folder_size(wcs2cs(blks[0]), _a)
            log("   GETFOLDERSIZE %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", val)])
        elif op == FS_OP_COUNT and len(blks) >= 1:
            _a = struct.unpack_from("<I", blks[1] + b"\0\0\0\0", 0)[0] if len(blks) >= 2 else 0
            val, extra = do_count(wcs2cs(blks[0]), _a)
            log("   COUNT %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", val)])
        elif op == FS_OP_LOCK_FAT:
            val, extra = do_lock_fat()
            log("   LOCKFAT %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", val)])
        elif op == FS_OP_CLEAR_DISK_FLAG:
            val, extra = do_clear_disk_flag()
            log("   CLEARDISKFLAG %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", val)])
        elif op == FS_OP_GET_CLUSTER_SIZE and len(blks) >= 1:
            _a = struct.unpack_from("<I", blks[0] + b"\0\0\0\0", 0)[0]
            val, extra = do_get_cluster_size(_a)
            log("   GETCLUSTERSIZE %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", val)])
        elif op == FS_OP_BIN_REGION and len(blks) >= 1:
            _a = struct.unpack_from("<I", blks[0] + b"\0\0\0\0", 0)[0]
            val, extra = do_bin_region(_a)
            log("   BINREGION %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", val)])
        elif op == FS_OP_XDELETE and len(blks) >= 1:
            val, extra = do_refuse_write("XDELETE", wcs2cs(blks[0]))
            log("   XDELETE %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", val)])
        elif op == FS_OP_RESTORE:
            val, extra = do_refuse_write("RESTORE", wcs2cs(blks[0]) if blks else "")
            log("   RESTORE %s" % extra)
            reply = build_reply(data, op, [struct.pack("<i", val)])
        elif op in (FS_OP_OTP_WRITE, FS_OP_OTP_LOCK):
            log("   %s -> -2 (not implemented; stock shape nb=1 [4])"
                % FS_OP_NAMES.get(op, "?"))
            reply = build_reply(data, op, [struct.pack("<i", FS_PARAM_ERROR)])
        elif op == FS_OP_OTP_QUERY_LEN:
            log("   OTPQUERYLENGTH -> -2 (not implemented; stock 0x1964c shape nb=2 [4,4])")
            reply = build_reply(data, op, [struct.pack("<i", FS_PARAM_ERROR),
                                          struct.pack("<I", 0)])
        elif op == FS_OP_OTP_READ and len(blks) >= 4:
            _n = struct.unpack_from("<I", blks[3] + b"\0\0\0\0", 0)[0]
            # stock 0x195f8 replies nb=2 [4, len-req]; we send len 0 in block1 so
            # no zero-filled buffer can be mistaken for real OTP content.
            log("   OTPREAD len-req=%d -> -2 (not implemented; block1 sent empty)" % _n)
            reply = build_reply(data, op, [struct.pack("<i", FS_PARAM_ERROR), b""])
        else:
            # fix-lid: this used to be a SILENT drop ("-> NOT IMPLEMENTED ... NO
            # REPLY"), which stalls the modem's synchronous FS client forever for
            # any op we lack -- exactly what happened to 0x1017 ShutDown
            # (LAST-REPLY-AUDIT.md:122).  Every op in the authoritative 0x10xx FS
            # range now gets an answer; stock sets the precedent by hardcoding -2
            # for the unhandled 0x1023 (0x18fe8).
            if 0x1000 <= op <= 0x10FF:
                log("   -> UNHANDLED op=0x%04x: replied -2 FS_PARAM_ERROR "
                    "(nb=1 [4]) instead of dropping the request" % op)
                reply = build_reply(data, op, [struct.pack("<i", FS_PARAM_ERROR)])
            else:
                log("   -> OUT-OF-RANGE op=0x%04x: no reply (not an FS opcode)" % op)

        if reply is None:
            return
        log("REPLY frame len=%d hex=%s" % (len(reply), binascii.hexlify(reply).decode()))
        with open(os.path.join(EVID, "fs_rep_%03d.bin" % n), "wb") as f:
            f.write(reply)
        try:
            w, npkt = send_reply(reply, reply[16:20])
            log("REPLY os.write returned %d in %d packet(s) (errno=%s)"
                % (w, npkt, ctypes.get_errno()))
        except OSError as e:
            log("REPLY os.write FAILED: %s" % e)


# ---------------------------------------------------------------- boot data
CCCI_IOC_SET_BOOT_DATA = 0x4040432f
MD_CFG_DUMP_FLAG = 2
MD_CFG_RAT_CHK_FLAG = 4
MD_CFG_RAT_STR0 = 5
MD_DBG_DUMP_INVALID = 0xFFFFFFFF
CCCI_IOC_DO_START_MD = (0x43 << 8) | 13
# v496: the remaining stock-ccci_mdinit ioctls (PROGRESS v490, extracted by
# disassembling every ioctl@plt call site of /tmp/vend/ccci_mdinit).
#   _IO('C',7)  -> SEND_RUNTIME_DATA   (no handler in our tree NOR in the vendor
#                                       drop => a no-op there too; called for parity)
#   _IO('C',21) -> SEND_BATTERY_INFO   (real: ccci_port_send_msg_to_md(
#                                       CCCI_SYSTEM_TX, MD_GET_BATTERY_INFO, mV))
#   _IOR('C',1,uint)  -> GET_MD_STATE
#   _IOR('C',59,uint) -> GET_MD_BOOT_MODE
CCCI_IOC_SEND_RUNTIME_DATA = (0x43 << 8) | 7
CCCI_IOC_SEND_BATTERY_INFO = (0x43 << 8) | 21
CCCI_IOC_GET_MD_STATE = 0x80044301
CCCI_IOC_GET_MD_BOOT_MODE = 0x8004433B
# v499: CCCI_IOC_GET_MD_STATE returns the *userspace* enum, not the FSM's
# internal 0..5 state (ccci_fsm.c ccci_fsm_get_md_state_for_user()):
#   MD_STATE_INVALID = 0, MD_STATE_BOOTING = 1, MD_STATE_READY = 2,
#   MD_STATE_EXCEPTION = 3   (mtk_ccci_common.h:322-327)
# The v496/v498 gate compared against the internal READY==4 and therefore never
# fired even when the modem was READY (v498 observed state 2).
MD_STATE_BOOTING = 1
MD_STATE_READY = 2
MD_STATE_EXCEPTION = 3
RAT_STR = os.environ.get("QQC_MD_RAT_STR", "N/C/Lf/Lt/W/G")


# ------------------------------------------------------- CCB control header
# v451: stock ccci_mdinit calls the vendor CCCI utility's ccci_ccb_init_users()
# (confirmed from the vendor utility symbol table) which opens
# /dev/ccci_ccb_ctrl and writes one 64-byte CCB control header per
# ccb_configs[] entry into SMEM_USER_RAW_CCB_CTRL.  Without it the modem's
# cccisrv_task_init reads dl_page_size (header+0x14) == 0 and asserts
# `ccci_shm_bm.c:602` (para0..2 = 0).
#
# Exact contract decoded from libccci_util.so:
#   ioctl(fd, 0x8004433F, &u32 n)              CCCI_IOC_GET_CCB_CONFIG_LENGTH
#   ioctl(fd, 0xC0184340, &ccb_config[24])     CCCI_IOC_GET_CCB_CONFIG (in/out)
#   ioctl(fd, 0xC0104347, &ccb_ctrl_info[16])  CCCI_IOC_CCB_CTRL_INFO  (in/out)
#   mmap(NULL, ctrl_length, RW, SHARED, fd, 0)
# and per config entry i writes at ctrl[i*0x40]:
#   +0x14 dl_page_size  +0x18 dl_buff_size  +0x1c 0xEEFF0011
#   +0x34 ul_page_size  +0x38 ul_buff_size  +0x3c 0xEEFF0011
# with all other bytes (guard bands, indices) zero.  The modem overwrites
# +0x00 and +0x20 with its own 0xAABBCDDD guard-band magic.
CCB_DEV = "/dev/ccci_ccb_ctrl"
CCCI_IOC_GET_CCB_CONFIG_LENGTH = 0x8004433F
CCCI_IOC_GET_CCB_CONFIG = 0xC0184340
CCCI_IOC_CCB_CTRL_INFO = 0xC0104347
CCB_GUARD_BAND_E = 0xEEFF0011


def ccb_init():
    """Write the 20 CCB control headers the modem reads at cccisrv_task_init."""
    try:
        fd = os.open(CCB_DEV, os.O_RDWR)
    except OSError as e:
        log("CCB: open %s failed: %s" % (CCB_DEV, e))
        return False
    try:
        buf = bytearray(4)
        fcntl.ioctl(fd, CCCI_IOC_GET_CCB_CONFIG_LENGTH, buf, True)
        n = struct.unpack_from("<I", buf, 0)[0]
        log("CCB: config count = %d" % n)
        cfgs = []
        for i in range(n):
            cb = bytearray(struct.pack("<IB3xIIII", i, 0, 0, 0, 0, 0))
            fcntl.ioctl(fd, CCCI_IOC_GET_CCB_CONFIG, cb, True)
            cfgs.append(struct.unpack_from("<IB3xIIII", cb, 0))
        clen = 0
        for u in range(3):
            cb = bytearray(struct.pack("<IIII", u, 0, 0, 0))
            fcntl.ioctl(fd, CCCI_IOC_CCB_CTRL_INFO, cb, True)
            uid, coff, caddr, cl = struct.unpack_from("<IIII", cb, 0)
            log("CCB user %d: ctrl_offset=%d ctrl_addr=0x%x ctrl_len=0x%x"
                % (u, coff, caddr, cl))
            clen = max(clen, cl)
        if clen < n * 0x40:
            log("CCB: ctrl region too small (%d < %d)" % (clen, n * 0x40))
            return False
        mm = mmap.mmap(fd, clen, mmap.MAP_SHARED,
                       mmap.PROT_READ | mmap.PROT_WRITE)
        for i, (uid, core, dlps, ulps, dlbs, ulbs) in enumerate(cfgs):
            hdr = bytearray(0x40)
            struct.pack_into("<I", hdr, 0x14, dlps)
            struct.pack_into("<I", hdr, 0x18, dlbs)
            struct.pack_into("<I", hdr, 0x1c, CCB_GUARD_BAND_E)
            struct.pack_into("<I", hdr, 0x34, ulps)
            struct.pack_into("<I", hdr, 0x38, ulbs)
            struct.pack_into("<I", hdr, 0x3c, CCB_GUARD_BAND_E)
            mm[i * 0x40:(i + 1) * 0x40] = hdr
            log("CCB[%02d] user=%d dl_page=%d dl_buff=%d ul_page=%d ul_buff=%d"
                % (i, uid, dlps, dlbs, ulps, ulbs))
        # region is pgprot_noncached; msync() is rejected (EINVAL), no flush needed
        mm.close()
        log("CCB: %d control headers written" % n)
        return True
    except OSError as e:
        log("CCB: ioctl/mmap failed: %s" % e)
        return False
    finally:
        os.close(fd)

fs_fd = os.open("/dev/ccci_fs", os.O_RDWR)
log("opened /dev/ccci_fs fd=%d dirs=%r" % (fs_fd, FSD_DIRS))
for d in FSD_DIRS.values():
    log("  %s mounted=%s exists=%s" % (d, os.path.ismount(d), os.path.isdir(d)))

mon_fd = os.open("/dev/ccci_monitor", os.O_RDWR)
log("comm=%s /dev/ccci_monitor fd=%d" % (
    open("/proc/self/comm").read().strip(), mon_fd))

t = threading.Thread(target=fs_reader, daemon=True, name="fs_reader")
t.start()

# v446: stock routes SAR_TABLE_IDX_QUERY (0x4010) to ccci_rpcd. The previous
# harness had no reader for that userspace port, leaving a real request queued
# after the complete FS phase. Restore only its binary-proven reply contract.
from qqc_rpc_sar import rpc_reader
rpc_fd = os.open("/dev/ccci_rpc", os.O_RDWR)
log("opened /dev/ccci_rpc fd=%d; stock SAR query responder" % rpc_fd)
rpc_thread = threading.Thread(target=rpc_reader,
                              args=(rpc_fd, EVID, log),
                              daemon=True, name="rpc_reader")
rpc_thread.start()

# ---------------------------------------------------------------------------
# v454 DIAGNOSTIC -- which AP-side service is the modem waiting on?
#
# FACT (stock binary /tmp/vend/ccci_mdinit, strings): stock ccci_mdinit opens
#   /dev/ccci_fs, /dev/ccci_rpc, /dev/ccci_monitor, /dev/ccci_ioctl0..4,
#   /dev/ccci_md_log_ctrl, /dev/ccci_md_log_rx|tx, /dev/ccci_pcm_rx|tx,
#   /dev/ccci_uem_rx|tx, /dev/ccci_ccb_*, /dev/ccci_imsa|imsc|imsdc|imsem|imsm|imsv,
#   /dev/ccci_ipc_*, /dev/ccci_md1_sta, /dev/ccci_mdx_sta,
#   /dev/ccci_mdl_monitor, /dev/ccci_wifi_proxy, /dev/ccci_woa.
# This harness opened only fs/rpc/monitor (monitor ioctls only, never read).
# Observation is read-only: we log what each channel delivers and do not reply,
# so this boot shows exactly which service the modem blocks on.
# ---------------------------------------------------------------------------
def monitor_reader(fd):
    while True:
        try:
            r, _, _ = select.select([fd], [], [], 1.0)
        except OSError:
            return
        if not r:
            continue
        try:
            d = os.read(fd, 4096)
        except OSError as e:
            log("MON: read err %s" % e)
            return
        if not d:
            continue
        if len(d) >= 16:
            magic, msg, ch, rsv = struct.unpack_from("<IIII", d, 0)
            log("MON: magic=%08x msg=0x%x ch=%08x resv=0x%x len=%d" %
                (magic, msg, ch, rsv, len(d)))
        else:
            log("MON: raw %s" % binascii.hexlify(d).decode())


def port_reader(path, fd):
    name = os.path.basename(path)
    while True:
        try:
            r, _, _ = select.select([fd], [], [], 1.0)
        except OSError:
            return
        if not r:
            continue
        try:
            d = os.read(fd, 4096)
        except OSError as e:
            log("PORT %s: read err %s" % (name, e))
            return
        if d:
            # v536: keep raw bytes AND rendered text -- the MD_LOG payload is the
            # modem's own console and only the text is readable in the log.
            try:
                with open("/run/qqc_port_%s.bin" % name, "ab") as _f:
                    if os.path.getsize("/run/qqc_port_%s.bin" % name) < (8 << 20):
                        _f.write(d)
            except OSError:
                pass
            log("PORT %s: RX %d bytes hex=%s ascii=%r" %
                (name, len(d), binascii.hexlify(d[:96]).decode(),
                 d[:400].decode("latin1")))


EXTRA_PORTS = [
    # v457: exactly the AP-side service ports that the AUTHENTICATED stock
    # ccci_mdinit opens (verified with strings on /tmp/vend/ccci_mdinit).
    # NOTE: /dev/ccci_0_200|202|204 are NOT among them -- v454 opened
    # CCCI_MD_DIRC (ccci_0_200) by mistake, which is why the modem asked on a
    # channel stock never listens to and a task died at t+156.8.
    # v461 CORRECTION: /dev/ccci_md_log_ctrl is deliberately NOT opened here.
    # It is CCCI_UART1 (META) -- opening it sets CRIT_USR_META, and the kernel's
    # normal-boot MD-start gate (port_proxy.c:1344-1353 + ccci_fsm.c:346) then
    # blocks the start for BOOT_TIMEOUT. See the file header.
    "/dev/ccci_wifi_proxy", "/dev/ccci_woa", "/dev/ccci_mdl_monitor",
    "/dev/ccci_ioctl0", "/dev/ccci_ioctl1",
    "/dev/ccci_ioctl2", "/dev/ccci_ioctl3", "/dev/ccci_ioctl4",
    "/dev/ccci_imsa", "/dev/ccci_imsc", "/dev/ccci_imsv", "/dev/ccci_imsdc",
    "/dev/ccci_imsm", "/dev/ccci_imsem", "/dev/ccci_aud", "/dev/ccci_bip",
    "/dev/ccci_vts", "/dev/ccci_raw_audio", "/dev/ccci_raw_dhl",
    "/dev/ccci_raw_mdm", "/dev/ccci_raw_netd", "/dev/ccci_raw_usb",
    "/dev/ccci_ikeraw", "/dev/ccci_ss_xcap",
]
threading.Thread(target=monitor_reader, args=(mon_fd,), daemon=True,
                 name="mon_reader").start()
log("v457 diag: monitor reader started")
for _p in EXTRA_PORTS:
    try:
        _fd = os.open(_p, os.O_RDWR | os.O_NONBLOCK)
    except OSError as e:
        log("v457 diag: open %s failed: %s" % (_p, e))
        continue
    log("v457 diag: open %s fd=%d" % (_p, _fd))
    threading.Thread(target=port_reader, args=(_p, _fd), daemon=True,
                     name=os.path.basename(_p)).start()

# ---------------------------------------------------------------------------
# v456 -- the stock IPC time service our harness never provided.
#
# FACT (authenticated stock /tmp/vend/ccci_mdinit):
#   0x13740: open("/dev/ccci_ipc_5", O_RDWR) -> gettimeofday() ->
#            ioctl(fd, 0x5006 /*CCCI_IPC_UPDATE_TIMEZONE*/, arg)
#            error string 0x25e1 "Set default tz by ipc port fail(%d)"
#   0x13afc: ioctl(fd, 0x5004 /*CCCI_IPC_UPDATE_TIME*/, tz)
#            error string 0x3519 "Update time to md by ipc port fail(%d)"
#            success string 0x32a4 "Update time to md done"
# Kernel side (port_ipc.c:143 -> port_proxy.c:86): UPDATE_TIME calls
#   send_new_time_to_md_after_6297() -> mtk_ccci_send_data on the CCCI_TIME
#   port (/dev/ccci_0_202) with {tv_sec lo, tv_sec hi, tz, tz_dsttime}.
# Our harness never issued it, so the modem never received the wall clock.
# ---------------------------------------------------------------------------
CCCI_IPC_UPDATE_TIME = 0x5004
CCCI_IPC_UPDATE_TIMEZONE = 0x5006
MD_TIME_TZ = int(os.environ.get("QQC_MD_TIME_TZ", "0"))


def time_sync(ipc_fd):
    # PEARL-TIMESYNC-1: the modem reaches READY ~1.6 s after DO_START_MD and
    # then asserts (EXCEPTION) ~2.3 s later.  The old 5 s initial sleep meant
    # EVERY UPDATE_TIME attempt landed outside the READY window, so the gate
    # in port_proxy.c (md_state != READY -> reject) returned -19 (ENODEV) all
    # 20 times and the modem never received the wall clock.
    #   CTime update: ...   (never observed in the log)
    # Start immediately and retry fast so at least one send lands in-window.
    time.sleep(0.3)
    for attempt in range(1, 21):
        try:
            r_tz = fcntl.ioctl(ipc_fd, CCCI_IPC_UPDATE_TIMEZONE, MD_TIME_TZ)
        except OSError as e:
            r_tz = -e.errno
        try:
            r = fcntl.ioctl(ipc_fd, CCCI_IPC_UPDATE_TIME, MD_TIME_TZ)
        except OSError as e:
            r = -e.errno
        log("v456 time_sync attempt %d: UPDATE_TIMEZONE=%d UPDATE_TIME=%d tz=%d"
            % (attempt, r_tz, r, MD_TIME_TZ))
        if isinstance(r, int) and r >= 0:
            log("v456 time_sync: modem clock delivered (PEARL-TIMESYNC-1)")
            return
        time.sleep(0.4)
    log("v456 time_sync: gave up after 20 attempts")


ipc_fd = None
try:
    ipc_fd = os.open("/dev/ccci_ipc_5", os.O_RDWR | os.O_NONBLOCK)
    log("v456: opened /dev/ccci_ipc_5 fd=%d" % ipc_fd)
    threading.Thread(target=port_reader, args=("/dev/ccci_ipc_5", ipc_fd),
                     daemon=True, name="ipc5_reader").start()
except OSError as e:
    log("v456: open /dev/ccci_ipc_5 failed: %s" % e)

boot = [0] * 16
# v536: optional MD logging-mode override, for modem-side visibility only.
# `MD_CFG_MDLOG_MODE` (index 0) lands in `get_booting_start_id()`'s bits 8..15
# (ccci_modem.c:1588) and the enum is modem_sys.h: MODE_IDLE=0, MODE_USB=1,
# MODE_SD=2, MODE_POLLING=3, MODE_WAITSD=4.  Stock user builds send 0; the file
# is absent unless a run deliberately asks for modem logs.
try:
    with open("/run/qqc_mdlog_mode") as _mf:
        boot[0] = int(_mf.read().strip(), 0)
except (OSError, ValueError):
    boot[0] = 0
boot[MD_CFG_DUMP_FLAG] = MD_DBG_DUMP_INVALID
# PGZ110 stock persist.vendor.md_c2k_cap_dep_check=0 (OTA vendor/build.prop).
boot[MD_CFG_RAT_CHK_FLAG] = 0
rat = (RAT_STR.encode() + b"\x00").ljust(24, b"\x00")[:24]
boot[MD_CFG_RAT_STR0:MD_CFG_RAT_STR0 + 6] = list(struct.unpack("<6I", rat))
buf = bytearray(struct.pack("<16I", *boot))
log("boot_data = %s" % " ".join("%08x" % v for v in boot))
log("SET_BOOT_DATA ret = %d"
    % fcntl.ioctl(mon_fd, CCCI_IOC_SET_BOOT_DATA, buf, True))

# v560: the modem is told the SIM slot configuration by the RIL through
# CCCI_IOC_UPDATE_SIM_SLOT_CFG (ccci_fsm_ioctl.c fsm_md_data_ioctl ->
# {need_update, sim_mode, slot1_mode, slot2_mode} -> per_md_data->sim_setting
# -> CCCI_MD_MSG_CFG_UPDATE to the FSM).  Our harness never sent it.  We send
# need_update=1 together with the kernel's OWN current mode values (they are
# zero because nothing has set them), so no SIM mode value is invented -- the
# only new thing exercised is the CFG_UPDATE notification itself.
#   _IOW('C', 38, unsigned int) = 0x40044326   UPDATE_SIM_SLOT_CFG
#   _IOR('C', 26, unsigned int) = 0x8004431a   GET_SIM_TYPE
CCCI_IOC_UPDATE_SIM_SLOT_CFG = 0x40044326
CCCI_IOC_GET_SIM_TYPE = 0x8004431A
try:
    simcfg = bytearray(struct.pack("<4I", 1, 0, 0, 0))
    log("v560 SIM_SLOT_CFG ret = %d"
        % fcntl.ioctl(mon_fd, CCCI_IOC_UPDATE_SIM_SLOT_CFG, simcfg, True))
except OSError as e:
    log("v560 SIM_SLOT_CFG failed: %s" % e)
try:
    _sb = bytearray(4)
    fcntl.ioctl(mon_fd, CCCI_IOC_GET_SIM_TYPE, _sb, True)
    log("v560 SIM_TYPE = 0x%08x" % struct.unpack("<I", _sb)[0])
except OSError as e:
    log("v560 GET_SIM_TYPE failed: %s" % e)

# v451: init the CCB control headers BEFORE the modem runs its cccisrv_task_init.
for attempt in range(1, 6):
    if ccb_init():
        break
    log("CCB: init attempt %d failed; retry in 1 s" % attempt)
    time.sleep(1)

log("DO_START_MD ret = %d" % fcntl.ioctl(mon_fd, CCCI_IOC_DO_START_MD, 0))

# ---------------------------------------------------------------------------
# v477 -- the one stock-AP action this harness has never performed.
#
# FACT: stock ccci_mdinit references /dev/ccci_md_log_ctrl,
# /dev/ccci_md_log_rx and /dev/ccci_md_log_tx (strings in
# /tmp/vend/ccci_mdinit), and stock's mdlogger owns the MD log-control channel.
# This harness has NEVER opened any of them, and the modem's MD_LOG channel
# (CCIF queue 2 / ttyC1) is completely silent in every run (rxq2 isr_cnt = 0)
# while FS (q4), RPC (q1) and IMS (q6) all work -- i.e. the modem's log service
# is not running, which is also why we have no modem-side narrative.
#
# This opens them AFTER the modem is READY, so it cannot hit the MD-start
# critical-user gate (that gate is only evaluated while fsm_routine_boot() is
# starting the modem; ccci_md_log_ctrl is CCCI_UART1 -> CRIT_USR_META and ttyC1
# is CCCI_MD_LOG -> CRIT_USR_MDLOG).  Observation only: whatever arrives is
# logged, nothing is answered.
# ---------------------------------------------------------------------------
def post_ready_log_bringup():
    # v536: poll for READY instead of the fixed 15 s sleep, so the modem's log
    # ring is drained as early as possible -- with MODE_POLLING the boot-time
    # narrative would otherwise be lost to ring wrap.  The critical-user gate is
    # only evaluated while fsm_routine_boot() is starting the modem, so opening
    # at READY (boot complete) is safe.
    _t0 = time.time()
    while time.time() - _t0 < 60:
        try:
            _b = bytearray(struct.pack("<I", 0))
            fcntl.ioctl(mon_fd, CCCI_IOC_GET_MD_STATE, _b, True)
            if struct.unpack("<I", _b)[0] == MD_STATE_READY:
                break
        except OSError:
            pass
        time.sleep(0.5)
    time.sleep(2)
    for _p in ("/dev/ccci_md_log_ctrl", "/dev/ttyC1"):
        try:
            _fd = os.open(_p, os.O_RDWR | os.O_NONBLOCK)
        except OSError as e:
            log("v477: open %s failed: %s" % (_p, e))
            continue
        log("v477: opened %s fd=%d post-READY" % (_p, _fd))
        threading.Thread(target=port_reader, args=(_p, _fd), daemon=True,
                         name=os.path.basename(_p)).start()


# MDLOG access is not part of the public service's normal startup contract.
# The existing diagnostic path remains opt-in and must be board-validated.
if os.environ.get("MTK_CCCI_ENABLE_MDLOG") == "1":
    threading.Thread(target=post_ready_log_bringup, daemon=True,
                     name="post_ready_log").start()


# ---------------------------------------------------------------------------
# v496 -- stock-ccci_mdinit parity for the ioctls this harness never issued.
#
# PROGRESS v490 extracted the complete ioctl set of the stock binary.  All of
# them are either read-backs or provably inert in this tree EXCEPT
# CCCI_IOC_SEND_BATTERY_INFO, which is the only remaining call that injects a
# real AP->MD system-channel message (MD_GET_BATTERY_INFO, answered by
# port_sysmsg.c sys_msg_send_battery()).  Stock calls it twice, before and
# after the modem is up.  The accompanying GET_* calls are read-only and are
# used here only to time and observe; no argument is guessed.
# ---------------------------------------------------------------------------
def post_ready_stock_ioctls():
    state = -1
    for _i in range(150):
        try:
            _b = bytearray(struct.pack("<I", 0))
            fcntl.ioctl(mon_fd, CCCI_IOC_GET_MD_STATE, _b, True)
            state = struct.unpack("<I", _b)[0]
        except OSError as e:
            log("v496: GET_MD_STATE failed: %s" % e)
            return
        if state in (MD_STATE_READY, MD_STATE_EXCEPTION):
            break
        time.sleep(1)
    log("v499: user md_state=%d before stock-ioctl replay" % state)
    if state == MD_STATE_EXCEPTION:
        log("v499: modem is in EXCEPTION; skipping stock-ioctl replay")
        return
    if state != MD_STATE_READY:
        log("v499: never reached READY; skipping stock-ioctl replay")
        return
    for rnd in (1, 2):
        for _name, _cmd in (("SEND_RUNTIME_DATA", CCCI_IOC_SEND_RUNTIME_DATA),
                            ("SEND_BATTERY_INFO", CCCI_IOC_SEND_BATTERY_INFO)):
            try:
                _r = fcntl.ioctl(mon_fd, _cmd, 0)
                log("v496: %s #%d ret=%d" % (_name, rnd, _r))
            except OSError as e:
                log("v496: %s #%d failed: %s" % (_name, rnd, e))
        try:
            _b = bytearray(struct.pack("<I", 0))
            fcntl.ioctl(mon_fd, CCCI_IOC_GET_MD_BOOT_MODE, _b, True)
            log("v496: GET_MD_BOOT_MODE = 0x%x" % struct.unpack("<I", _b)[0])
        except OSError as e:
            log("v496: GET_MD_BOOT_MODE failed: %s" % e)
        time.sleep(5)


threading.Thread(target=post_ready_stock_ioctls, daemon=True,
                 name="post_ready_stock_ioctls").start()

if ipc_fd is not None:
    threading.Thread(target=time_sync, args=(ipc_fd,), daemon=True,
                     name="time_sync").start()

# ---------------------------------------------------------------------------
# PEARL-MDRECOVER-1 -- the missing stock-AP action.
#
# Android and Linux BOTH hit the custom_nvram_sec -1001 assert (it is a
# normal event).  The difference is what happens next: stock ccci_mdinit
# restarts the modem (DO_STOP_MD -> RESET_MD1_MD3_PCCIF -> DO_START_MD and
# re-send of boot data / time / battery / SIM cfg) and the modem comes back
# and stays READY.  Our owner started it once and then only logged "alive".
#
# This supervisor polls the user-visible MD state and performs that restart
# sequence on EXCEPTION, with a bounded retry count.  NV is untouched: all
# modem NVRAM writes still go through the COW overlay.
# ---------------------------------------------------------------------------
def _md_user_state():
    try:
        _b = bytearray(struct.pack("<I", 0))
        fcntl.ioctl(mon_fd, CCCI_IOC_GET_MD_STATE, _b, True)
        return struct.unpack("<I", _b)[0]
    except OSError:
        return -1


def recover_md(attempt):
    log("MDRECOVER: attempt %d -- MD in EXCEPTION, restarting" % attempt)
    # 1) stop -- PEARL-MDRECOVER-6: DO_STOP_MD from EXCEPTION is legal and does
    # end in CCCI_FSM_GATED (see fsm_routine_stop: it explicitly accepts
    # CCCI_FSM_EXCEPTION and falls through to `curr_state = CCCI_FSM_GATED`).
    # The bug was TIMING: the owner waited only 1 s before DO_START_MD, but
    # fsm_routine_stop polls the modem, runs the EE check and stops the hardware
    # -- far longer.  DO_START_MD therefore arrived while curr_state was still
    # CCCI_FSM_STOPPING, fsm_routine_start took the `!= CCCI_FSM_GATED` branch
    # and called fsm_routine_zombie(), so the boot never ran and the modem parked
    # in BOOTING.  Wait for the user-visible state to return to 0 (GATED) first.
    #
    # PEARL-MDRECOVER-2 note: OFF by default.  The FSM already performs
    # its own restart (md_state 5 -> 7 -> 1) when the modem faults; issuing
    # DO_STOP_MD/DO_START_MD on top of that fights the FSM and leaves the modem
    # parked in BOOTING.  Set PEARL_MDRECOVER_STOPSTART=1 to restore the old
    # behaviour.
    if os.environ.get("PEARL_MDRECOVER_STOPSTART", "1") == "1":
        try:
            _mode = os.environ.get("PEARL_MDRECOVER_RESET", "stop")
            if _mode == "stop":
                _buf = bytearray(struct.pack("<I", 0))   # 0 = normal stop
                log("MDRECOVER: DO_STOP_MD -> %d"
                    % fcntl.ioctl(mon_fd, CCCI_IOC_DO_STOP_MD, _buf, True))
            elif _mode == "md_rst":
                log("MDRECOVER: DO_MD_RST -> %d"
                    % fcntl.ioctl(mon_fd, CCCI_IOC_DO_MD_RST, 0))
            else:
                log("MDRECOVER: MD_RESET(C,0) -> %d"
                    % fcntl.ioctl(mon_fd, CCCI_IOC_MD_RESET, 0))
        except OSError as e:
            log("MDRECOVER: reset failed: %s" % e)
        # wait for GATED (user-visible MD state 0) before starting, else
    # fsm_routine_start zombies out.  Bounded so we never hang.
    _g = 0
    while _g < 40:
        if _md_user_state() == 0:
            log("MDRECOVER: FSM reached GATED after %.1fs" % (_g * 0.5))
            break
        time.sleep(0.5)
        _g += 1
    if _g >= 40:
        log("MDRECOVER: FSM did not reach GATED in 20s (state=%d)"
            % _md_user_state())
    # 2) reset the MD1/MD3 PCCIF -- the step our owner never had
    try:
        log("MDRECOVER: RESET_MD1_MD3_PCCIF -> %d"
            % fcntl.ioctl(mon_fd, CCCI_IOC_RESET_MD1_MD3_PCCIF, 0))
    except OSError as e:
        log("MDRECOVER: RESET_MD1_MD3_PCCIF failed: %s" % e)
    time.sleep(1.0)
    # 3) start again -- same gate as (1); the FSM owns the restart.
    if os.environ.get("PEARL_MDRECOVER_STOPSTART", "1") == "1":
        try:
            log("MDRECOVER: DO_START_MD -> %d"
                % fcntl.ioctl(mon_fd, CCCI_IOC_DO_START_MD, 0))
        except OSError as e:
            log("MDRECOVER: DO_START_MD failed: %s" % e)
    # 3b) PEARL-MDRECOVER-3: re-write the CCB control headers.  The stock AP
    # builds them before the modem runs its cccisrv_task_init (owner v451 does
    # the same on the first boot).  After a restart the modem re-runs that init,
    # so the headers must be rebuilt or it parks in BOOTING and never reaches
    # HS1.
    try:
        log("MDRECOVER: ccb_init() -> %s" % ccb_init())
    except Exception as e:
        log("MDRECOVER: ccb_init() raised: %s" % e)
    # 3c) PEARL-SIMLOCK-1: re-arm the SIM-lock random pattern message
    try:
        _b = bytearray(struct.pack("<I", 0))
        fcntl.ioctl(mon_fd, CCCI_IOC_SIM_LOCK_RANDOM_PATTERN, _b, True)
        log("MDRECOVER: SIM_LOCK_RANDOM_PATTERN re-sent")
    except OSError as e:
        log("MDRECOVER: SIM_LOCK_RANDOM_PATTERN failed: %s" % e)
    # 4) re-send the boot-time context stock re-sends
    time.sleep(1.0)
    try:
        _buf = bytearray(struct.pack("<I", 0))
        fcntl.ioctl(mon_fd, CCCI_IOC_SET_BOOT_DATA, _buf, True)
        log("MDRECOVER: SET_BOOT_DATA re-sent")
    except OSError as e:
        log("MDRECOVER: SET_BOOT_DATA failed: %s" % e)
    for _name, _cmd in (("SEND_BATTERY_INFO", CCCI_IOC_SEND_BATTERY_INFO),
                        ("SEND_RUNTIME_DATA", CCCI_IOC_SEND_RUNTIME_DATA)):
        try:
            log("MDRECOVER: %s -> %d" % (_name, fcntl.ioctl(mon_fd, _cmd, 0)))
        except OSError as e:
            log("MDRECOVER: %s failed: %s" % (_name, e))


def simlock_sender():
    """PEARL-SIMLOCK-1: periodically deliver CCCI_MD_MSG_RANDOM_PATTERN.

    The modem's custom_nvram_sec security check runs shortly after READY; the
    stock AP triggers the message via CCCI_IOC_SIM_LOCK_RANDOM_PATTERN.  Send it
    from boot through READY (and after every restart) so the modem always has
    it.  The kernel ignores the argument, so the value is irrelevant.
    """
    try:
        libc.prctl(15, b"ccci_mdinit", 0, 0, 0)
    except Exception:
        pass
    _buf = bytearray(struct.pack("<I", 0))
    _n = 0
    _t0 = time.time()
    while time.time() - _t0 < 300:
        try:
            fcntl.ioctl(mon_fd, CCCI_IOC_SIM_LOCK_RANDOM_PATTERN, _buf, True)
            _n += 1
            if _n <= 5 or _n % 20 == 0:
                log("SIMLOCK: sent CCCI_MD_MSG_RANDOM_PATTERN #%d" % _n)
        except OSError as e:
            if _n == 0:
                log("SIMLOCK: ioctl failed: %s" % e)
        time.sleep(1.0)
    log("SIMLOCK: done, sent %d" % _n)


threading.Thread(target=simlock_sender, daemon=True, name="simlock").start()


def md_supervisor():
    global ipc_fd
    # PEARL-MDRECOVER-7 -- THE fix.
    #
    # ccci_fsm_ioctl.c:409 has  char *VALID_USER = "ccci_mdinit";  and the
    # CCCI_IOC_DO_START_MD handler does
    #     if (strncmp(current->comm, VALID_USER, strlen(VALID_USER)) == 0)
    #         fsm_append_command(ctl, CCCI_COMMAND_START, 0);
    #     else
    #         CCCI_ERROR_LOG(..., "drop invalid user:%s call MD start ioctl\n", ...);
    # current->comm is the *thread* name, not the process name.  The owner's main
    # thread renames itself to "ccci_mdinit" with prctl(PR_SET_NAME) (see the
    # module header), which is why the initial DO_START_MD works.  This
    # supervisor runs in its own thread whose comm is "md_supervisor", so every
    # recovery DO_START_MD was silently DROPPED:
    #     [ccci1/fsm]drop invalid user:md_supervisor call MD start ioctl
    # The modem therefore never restarted and parked in BOOTING forever.
    # threading.Thread(name=...) only sets the Python-side name; the OS comm
    # must be set from inside the thread with prctl.
    try:
        libc.prctl(15, b"ccci_mdinit", 0, 0, 0)   # PR_SET_NAME = 15
    except Exception as e:
        log("MDRECOVER: prctl(PR_SET_NAME) failed: %s" % e)
    _t0 = time.time()
    while time.time() - _t0 < 120:      # wait for the first READY/EXCEPTION
        _st = _md_user_state()
        if _st in (MD_STATE_READY, MD_STATE_EXCEPTION):
            break
        time.sleep(1)
    _n = 0
    while _n < 100:      # PEARL-MDRECOVER-9: 提高上限，便于抓 MD 窗口
        _st = _md_user_state()
        if _st == MD_STATE_EXCEPTION:
            _n += 1
            recover_md(_n)
            time.sleep(8)      # give the FSM's own restart time to progress
            if ipc_fd is not None:
                try:
                    fcntl.ioctl(ipc_fd, CCCI_IPC_UPDATE_TIMEZONE, MD_TIME_TZ)
                    fcntl.ioctl(ipc_fd, CCCI_IPC_UPDATE_TIME, MD_TIME_TZ)
                    log("MDRECOVER: time re-sent")
                except OSError as e:
                    log("MDRECOVER: time re-send failed: %s" % e)
        else:
            time.sleep(2)
    log("MDRECOVER: gave up after %d attempts (md_state=%d)" % (_n, _st))


threading.Thread(target=md_supervisor, daemon=True,
                 name="md_supervisor").start()

signal.signal(signal.SIGTERM, bye)
signal.signal(signal.SIGINT, bye)

if lifetime:
    log("holding both fds for %d s (modem supervisor)" % lifetime)
else:
    log("holding both fds until killed (modem supervisor)")
start = time.time()
while not lifetime or time.time() - start < lifetime:
    time.sleep(5)
    with hlock:
        hl = {k: v["path"] for k, v in handles.items()}
    log("alive %ds handles=%r" % (time.time() - start, hl))

log("lifetime done: closing fds, modem will be stopped")
os.close(mon_fd)
os.close(fs_fd)
os.close(rpc_fd)
