#!/usr/bin/env python3
"""Provision local IPv6 addresses + source-routing rules for V6 direct slots.

The mihomo TUN intercepts all locally-generated IPv6 traffic (ip rule
"from all iif lo lookup 2022"). To use a specific IPv6 source address for
outbound requests we must:
  1. add the address to the interface (SLAAC /64 lets us use any address)
  2. add a source-based rule: from <addr> lookup main (bypasses the TUN)

Requires root. Usage: sudo python3 v6_setup.py add|del
"""
import os
import subprocess
import sys

PREFIX = os.environ.get("V6_PREFIX", "2408:8256:4e89:18c3::")
IFACE = os.environ.get("V6_IFACE", "wlo1")
COUNT = int(os.environ.get("V6_COUNT", "10"))  # addresses ::2 .. ::N+1
START_N = int(os.environ.get("V6_START", "2"))
RULE_PREF_BASE = int(os.environ.get("V6_RULE_PREF", "3000"))
FW_MARK = int(os.environ.get("FW_MARK", "0xca7"), 0)
FW_PREF = int(os.environ.get("FW_PREF", "8000"))


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def ensure_fwmark_rule():
    """ip rule: from all fwmark <FW_MARK> lookup main (绕过系统 clash TUN).
    该规则优先级(8000)高于 TUN 的劫持规则(9002)，带 mark 的出站流量走真实网卡。
    """
    for fam in ("ip", "ip -6"):
        r = run(fam.split() + ["rule", "show"])
        if "fwmark 0x%x lookup main" % FW_MARK in r.stdout:
            continue
        r = run(fam.split() + ["rule", "add", "fwmark", hex(FW_MARK),
                               "lookup", "main", "pref", str(FW_PREF)])
        print("add %s fwmark rule: %s" % (
            "v4" if fam == "ip" else "v6",
            "ok" if r.returncode == 0 else r.stderr.strip()))


def addresses():
    return ["%s%d" % (PREFIX, n) for n in range(START_N, START_N + COUNT)]


def existing_addrs():
    r = run(["ip", "-6", "addr", "show", "dev", IFACE])
    return set(r.stdout)


def existing_rules():
    r = run(["ip", "-6", "rule", "show"])
    return r.stdout


def cmd_add():
    ensure_fwmark_rule()
    addrs = addresses()
    rules_txt = existing_rules()
    for i, a in enumerate(addrs):
        if a not in existing_addrs():
            r = run(["ip", "-6", "addr", "add", a + "/64", "dev", IFACE])
            print("add addr %s: %s" % (a, "ok" if r.returncode == 0 else r.stderr.strip()))
        pref = RULE_PREF_BASE + i
        rule = "from %s lookup main" % a
        if rule not in rules_txt:
            r = run(["ip", "-6", "rule", "add", "from", a, "lookup", "main",
                     "pref", str(pref)])
            print("add rule %s pref %d: %s" % (a, pref,
                  "ok" if r.returncode == 0 else r.stderr.strip()))
    print("done: %d v6 addresses provisioned on %s" % (len(addrs), IFACE))


def cmd_del():
    addrs = addresses()
    for a in addrs:
        run(["ip", "-6", "rule", "del", "from", a, "lookup", "main", "pref", "0"])
        run(["ip", "-6", "rule", "del", "from", a, "lookup", "main"])
        run(["ip", "-6", "addr", "del", a + "/64", "dev", IFACE])
        print("removed %s" % a)
    print("done: v6 addresses removed")


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "add"
    if action == "add":
        cmd_add()
    elif action == "del":
        cmd_del()
    else:
        sys.exit("usage: v6_setup.py add|del")
