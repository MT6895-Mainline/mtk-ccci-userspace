#!/usr/bin/env python3
"""Enable ModemManager signal polling for the MT6895 pearl port.

ModemManager defaults to a signal-check rate of 0, so `mmcli -m 0` (and any
desktop UI reading it, e.g. Phosh) reports no signal forever even though the
modem answers AT+CSQ.  This one-shot helper waits for the modem to appear and
then asks ModemManager to poll it.

Environment:
    MTK_CCCI_MM_SIGNAL_RATE      poll interval in seconds (default 30)
    MTK_CCCI_MM_TUNE_TIMEOUT     how long to wait for the modem (default 300)
"""

import os
import shutil
import subprocess
import sys
import time

RATE = os.environ.get("MTK_CCCI_MM_SIGNAL_RATE", "30")
TIMEOUT = int(os.environ.get("MTK_CCCI_MM_TUNE_TIMEOUT", "300"))


def log(message):
    print("mm-tune: %s" % message, flush=True)


def mmcli(*args):
    try:
        done = subprocess.run(("mmcli",) + args, check=False,
                              capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout


def main():
    if shutil.which("mmcli") is None:
        log("找不到 mmcli，跳过")
        return 0

    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        listing = mmcli("-L")
        if listing and "Modem/" in listing:
            if mmcli("-m", "0", "--signal-setup=%s" % RATE) is not None:
                log("已设置信号轮询 %ss" % RATE)
                return 0
        time.sleep(5)
    log("等待 ModemManager 暴露 modem 超时，跳过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
