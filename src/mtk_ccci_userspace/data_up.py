#!/usr/bin/env python3
"""PEARL: MTK 移动数据上线（PDP 激活 + ccmni 配置 + 连通性验证）。

关键经验（都是实测踩出来的）
----------------------------
1. 数据面必须编入 DPMAIF HIF（CONFIG_MTK_CCCI_MAINLINE_DATAPATH_HIF=y），
   否则 ccmni 只有 TX 没有 RX。
2. APN 用运营商下发的那个（本机是 cmnet.mnc000.mcc460.gprs）。
   用 "cmnet" 时 AT+CGACT 会 +CME ERROR: 5848 / CM_SER_UNAVAILABLE。
3. **必须等 PS 附着 + 网络注册完成再激活**。没注册就激活会拿到 IP，
   但数据面是死的（RX 永远 0）——必须验证，坏了就换 cid 重来。
4. AT 口必须独占：NetworkManager 会通过 D-Bus 提前把 ModemManager 拉起，
   MM 占着 AT 口时我们的命令收不到应答。所以本脚本自己先停 MM。
5. cid N ↔ ccmni(N-1)。

配置：/etc/mtk-ccci/data.conf
    APN=...  CID=...  DEV=...  METRIC=...  VERIFY_HOST=223.5.5.5
"""
import os
import re
import select
import subprocess
import sys
import termios
import time

DEV_AT = os.environ.get("MTK_CCCI_AT_TTY", "/dev/ttyCCCI0")
BOOT = os.environ.get("MTK_CCCI_BOOT_NODE",
                      "/sys/kernel/ccci/boot")
CONF = os.environ.get("MTK_CCCI_DATA_CONF",
                       "/etc/mtk-ccci/data.conf")
READY_TIMEOUT = 300
REG_TIMEOUT = 300
PING_TIMEOUT = 12

CFG = {
    "APN": "cmnet.mnc000.mcc460.gprs",
    "CID": "1",
    "DEV": "ccmni0",
    "METRIC": "1000",
    "VERIFY_HOST": "223.5.5.5",
    "DNS_FALLBACK": "211.139.5.28,211.139.5.27",
}


def log(msg):
    print("data-up: %s" % msg, flush=True)


def run(*argv):
    try:
        return subprocess.run(argv, check=False, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode
    except OSError:
        return -1


def load_conf():
    try:
        with open(CONF) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                CFG[k.strip()] = v.strip()
    except OSError:
        pass


def md_ready():
    try:
        with open(BOOT) as fh:
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


class At:
    def __init__(self, path):
        self.fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        a = termios.tcgetattr(self.fd)
        a[0] = 0
        a[1] = 0
        a[3] = 0
        a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
        a[4] = termios.B115200
        a[5] = termios.B115200
        a[6][termios.VMIN] = 0
        a[6][termios.VTIME] = 0
        termios.tcsetattr(self.fd, termios.TCSANOW, a)

    def close(self):
        os.close(self.fd)

    def _drain(self, sec=0.4):
        t0 = time.time()
        while time.time() - t0 < sec:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if r:
                try:
                    os.read(self.fd, 4096)
                except OSError:
                    return

    def cmd(self, text, wait=12.0):
        self._drain()
        os.write(self.fd, text.encode() + b"\r\n")
        out = b""
        deadline = time.time() + wait
        while time.time() < deadline:
            r, _, _ = select.select([self.fd], [], [], 0.3)
            if r:
                try:
                    data = os.read(self.fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                out += data
                if b"OK" in out or b"ERROR" in out:
                    break
        self._drain(0.3)
        return out.decode("latin1")


def parse_dns(text):
    dns = []
    for line in text.splitlines():
        if "+CGCONTRDP" not in line:
            continue
        for ip in re.findall(r'"(\d+\.\d+\.\d+\.\d+)"', line):
            if ip not in dns:
                dns.append(ip)
    return dns


def wait_registered(at, timeout=REG_TIMEOUT):
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        att = at.cmd("AT+CGATT?")
        reg = at.cmd("AT+CEREG?")
        last = "%s / %s" % (att.strip().replace("\n", " "),
                            reg.strip().replace("\n", " "))
        if "+CGATT: 1" in att and re.search(r"\+CEREG:\s*\d+,[15]", reg):
            log("已附着并注册: %s" % last)
            return True
        time.sleep(5)
    log("等待注册超时（最后状态 %s）" % last)
    return False


def configure(dev, ip, dns):
    if not os.path.exists("/sys/class/net/%s" % dev):
        log("网卡 %s 不存在" % dev)
        return False
    run("ip", "link", "set", dev, "up")
    run("ip", "addr", "flush", "dev", dev)
    run("ip", "addr", "add", "%s/24" % ip, "dev", dev)
    run("ip", "route", "replace", "default", "dev", dev,
        "metric", CFG["METRIC"])
    if dns:
        _write_dns(dev, dns)
    return True


def _write_dns(dev, dns):
    if os.path.exists("/run/systemd/resolve"):
        run("resolvectl", "dns", dev, *dns)
        run("resolvectl", "domain", dev, "~.")
        return
    try:
        with open("/etc/resolv.conf", "w") as fh:
            fh.write("# generated by mtk-ccci data-up\n")
            for d in dns:
                fh.write("nameserver %s\n" % d)
    except OSError as exc:
        log("写 /etc/resolv.conf 失败: %s" % exc)


def verify(dev):
    """真正打一次流量，确认这个 PDP 的数据面是活的。"""
    rc = run("ping", "-c", "2", "-W", "4", "-I", dev, CFG["VERIFY_HOST"])
    return rc == 0


def try_cid(at, cid):
    dev = "ccmni%d" % (cid - 1)
    apn = CFG["APN"]
    log("cid=%d 定义 APN=%s" % (cid, apn))
    at.cmd('AT+CGDCONT=%d,"IP","%s"' % (cid, apn))
    res = at.cmd("AT+CGACT=1,%d" % cid, wait=30.0)
    if "OK" not in res or "ERROR" in res:
        log("cid=%d 激活失败: %s" % (cid, res.strip().replace("\n", " | ")[:120]))
        return False
    addr = at.cmd("AT+CGPADDR=%d" % cid)
    m = re.search(r'"(\d+\.\d+\.\d+\.\d+)"', addr)
    if not m:
        log("cid=%d 没有拿到地址" % cid)
        return False
    ip = m.group(1)
    dns = parse_dns(at.cmd("AT+CGCONTRDP=%d" % cid)) or \
        CFG["DNS_FALLBACK"].split(",")
    log("cid=%d 地址=%s DNS=%s" % (cid, ip, ",".join(dns)))
    if not configure(dev, ip, dns):
        return False
    if verify(dev):
        log("cid=%d 经 %s 验证连通 ✓" % (cid, dev))
        return True
    log("cid=%d 配好了但打不通（数据面未绑定），换一个 cid 重试" % cid)
    run("ip", "addr", "flush", "dev", dev)
    return False


def main():
    load_conf()
    if not os.path.exists(DEV_AT):
        log("%s 不存在，跳过" % DEV_AT)
        return 0
    if not wait_ready():
        log("等待基带 READY 超时")
        return 0

    # AT 口必须独占：NM 会通过 D-Bus 提前拉起 MM
    mm_was_active = run("systemctl", "is-active", "--quiet", "ModemManager") == 0
    if mm_was_active:
        log("暂停 ModemManager 以独占 AT 口")
        run("systemctl", "stop", "ModemManager")
        time.sleep(2)

    ok = False
    try:
        at = At(DEV_AT)
        try:
            if "+CFUN: 1" not in at.cmd("AT+CFUN?"):
                log("切 AT+CFUN=1")
                at.cmd("AT+CFUN=1", wait=15.0)
            for _ in range(30):
                if "+CPIN: READY" in at.cmd("AT+CPIN?"):
                    break
                time.sleep(1)
            wait_registered(at)
            for cid in range(int(CFG["CID"]), int(CFG["CID"]) + 4):
                if try_cid(at, cid):
                    ok = True
                    break
        finally:
            at.close()
    finally:
        if mm_was_active:
            log("恢复 ModemManager")
            run("systemctl", "start", "ModemManager")

    if not ok:
        log("移动数据未能上线")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
