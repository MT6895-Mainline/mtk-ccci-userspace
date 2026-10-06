#!/usr/bin/env python3
"""PEARL: 基带 READY 后切换到全功能模式（AT+CFUN=1）。

MTK 基带上电默认 CFUN=0（最小功能），此时 SIM 不上电，ModemManager 初始化
会以 sim-missing 失败。这个 oneshot 在基带进入 READY(md1:4) 后通过
/dev/ttyCCCI0 发 AT+CFUN=1，随后 ModemManager 才启动。

只做这一件事，发完就关掉 AT 口，不和 ModemManager 抢端口。
"""
import os
import select
import sys
import termios
import time

DEV = os.environ.get("MTK_CCCI_AT_TTY", "/dev/ttyCCCI0")
BOOT = os.environ.get("MTK_CCCI_BOOT_NODE",
                      "/sys/kernel/ccci/boot")
READY_TIMEOUT = 240


def log(msg):
    print("at-cfun: %s" % msg, flush=True)


def md_ready():
    try:
        with open(BOOT, "r") as fh:
            return "md1:4" in fh.read()
    except OSError:
        return False


def wait_ready(timeout=READY_TIMEOUT):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if md_ready():
            return True
        time.sleep(1)
    return False


def at(fd, cmd, wait=3.0):
    os.write(fd, cmd)
    out = b""
    deadline = time.time() + wait
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.25)
        if r:
            try:
                data = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break
            out += data
            if b"OK" in out or b"ERROR" in out:
                break
    return out.decode("latin1").replace("\r", "").strip()


def main():
    if not os.path.exists(DEV):
        log("%s 不存在，跳过（没有 AT tty 的旧内核？）" % DEV)
        return 0
    if not wait_ready():
        log("等待基带 READY 超时，放弃")
        return 0

    fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        attrs = termios.tcgetattr(fd)
        attrs[0] = 0
        attrs[1] = 0
        attrs[3] = 0
        attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
        attrs[4] = termios.B115200
        attrs[5] = termios.B115200
        attrs[6][termios.VMIN] = 0
        attrs[6][termios.VTIME] = 0
        termios.tcsetattr(fd, termios.TCSANOW, attrs)

        cur = at(fd, b"AT+CFUN?\r\n")
        log("当前功能模式: %s" % cur.splitlines()[-1] if cur else "无响应")
        if "+CFUN: 1" not in cur:
            res = at(fd, b"AT+CFUN=1\r\n", wait=10.0)
            log("AT+CFUN=1 结果: %s" % res.replace("\n", " | ")[:200])
            if "OK" not in res:
                log("CFUN=1 未被接受")
                return 1
        else:
            log("已经是 CFUN=1")

        # RAT：模组出厂配置是 2G/3G/4G（+ERAT: 7,0,22,128,0），不含 5G NR。
        # 实测 AT+ERAT=15 之后接入制式变成 5gnr 且数据照常。设错了也不致命，
        # 失败只记日志。
        rat = os.environ.get("MTK_CCCI_RAT", "15")
        if rat and rat != "0":
            before = at(fd, b"AT+ERAT?\r\n")
            res = at(fd, b"AT+ERAT=" + rat.encode() + b"\r\n", wait=8.0)
            after = at(fd, b"AT+ERAT?\r\n")
            log("RAT: 设置 %s -> %s（前 %s / 后 %s）"
                % (rat, res.strip().replace("\n", " ")[:40],
                   before.strip().replace("\n", " ")[:40],
                   after.strip().replace("\n", " ")[:40]))

        # 给 SIM 上电与网络注册留点时间
        for _ in range(20):
            time.sleep(1)
            if "+CPIN: READY" in at(fd, b"AT+CPIN?\r\n"):
                log("SIM 已就绪")
                break
        else:
            log("警告：等待 SIM READY 超时（继续）")
        return 0
    finally:
        os.close(fd)


if __name__ == "__main__":
    sys.exit(main())
