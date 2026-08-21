#!/usr/bin/env python3
"""Generate 3 mihomo selector slot configs for the opencode-gate.

Each slot = one mihomo instance with ALL nodes in a `manual` select group
(and an `auto` url-test group for background probing). The gateway switches
a slot's node via its external-controller API on 429/5xx/connection errors.
"""
import json
import os

import yaml

BASE = os.path.dirname(os.path.abspath(__file__))
SUB_PATHS = [p.strip() for p in os.environ.get(
    "SUB_PATHS",
    "/home/lzy/clashctl/resources/profiles/2.yaml,"
    "/home/lzy/clashctl/resources/profiles/1.yaml",
).split(",") if p.strip()]
SLOTS_DIR = os.path.join(BASE, "slots")
LOGS_DIR = os.path.join(BASE, "logs")
DATA_DIR = os.path.join(BASE, "data")
GEO_SRC = os.environ.get("GEO_SRC", "/home/lzy/clashctl/resources")
MIHOMO = os.environ.get("MIHOMO", "/home/lzy/clashctl/bin/mihomo")

SLOTS = int(os.environ.get("SLOTS", "5"))
PROXY_START = int(os.environ.get("PROXY_START", "10800"))
API_START = int(os.environ.get("API_START", "10990"))

GEO_FILES = ("GeoIP.dat", "geosite.dat", "Country.mmdb", "ASN.mmdb")
META_MARKERS = ("剩余流量", "距离下次重置", "套餐到期", "官网")

NODE_TYPES = ("vless", "vmess", "trojan", "ss", "ssr", "http", "socks5",
              "tuic", "hysteria", "hysteria2", "wireguard")


def _quoted_str(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')


class QuotedDumper(yaml.SafeDumper):
    pass


QuotedDumper.add_representer(str, _quoted_str)


def load_proxies(paths):
    seen, out = set(), []
    ip_map = {}
    try:
        with open(os.path.join(DATA_DIR, "node_ips.json"), encoding="utf-8") as f:
            ip_map = json.load(f)
    except OSError:
        pass
    for idx, path in enumerate(paths):
        src = "A%d" % (idx + 1)
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except OSError as e:
            print("跳过订阅 %s: %s" % (path, e))
            continue
        proxies = data.get("proxies", [])
        for p in proxies:
            t = p.get("type")
            if t not in NODE_TYPES:
                continue
            if any(m in p.get("name", "") for m in META_MARKERS):
                continue
            # prefix with subscription id to avoid name collisions
            if p.get("name") and not str(p["name"]).startswith(src + "|"):
                p["name"] = "%s|%s" % (src, p["name"])
            # server hostname -> real IP (bypass clash fake-ip DNS)
            srv = p.get("server", "")
            if srv and srv in ip_map:
                p["server"] = ip_map[srv]
            key = json.dumps(p, sort_keys=True, ensure_ascii=False)
            if key in seen:
                continue
            seen.add(key)
            out.append(p)
    return out


def main():
    import sys
    if len(sys.argv) > 1:
        paths = sys.argv[1].split(",")
    else:
        paths = SUB_PATHS
    proxies = load_proxies(paths)
    if not proxies:
        sys.exit("no usable proxies found in %s" % ",".join(paths))

    for d in (SLOTS_DIR, LOGS_DIR, DATA_DIR):
        os.makedirs(d, exist_ok=True)

    node_names = [p["name"] for p in proxies]
    for g in GEO_FILES:
        src = os.path.join(GEO_SRC, g)
        dst = os.path.join(DATA_DIR, g)
        if os.path.exists(src) and not os.path.exists(dst):
            try:
                os.symlink(src, dst)
            except FileExistsError:
                pass

    for i in range(SLOTS):
        slot = "slot-%d" % i
        wd = os.path.join(SLOTS_DIR, slot)
        os.makedirs(wd, exist_ok=True)
        for g in GEO_FILES:
            src = os.path.join(DATA_DIR, g)
            dst = os.path.join(wd, g)
            if os.path.exists(src) and not os.path.exists(dst):
                try:
                    os.symlink(src, dst)
                except FileExistsError:
                    pass

        cfg = {
            "mixed-port": PROXY_START + i,
            "mode": "rule",
            "log-level": "warning",
            "ipv6": False,
            "allow-lan": False,
            "unified-delay": True,
            "external-controller": "127.0.0.1:%d" % (API_START + i),
            "profile": {"store-selected": False},
            # fwmark 绕过系统 clash TUN 劫持（slot 以 root 运行设置 SO_MARK）
            "routing-mark": int(os.environ.get("FW_MARK", "0xca7"), 0),
            # 节点域名已用真实 IP 写入，这里解析目标域名走真实 DNS
            "dns": {
                "enable": True,
                "enhanced-mode": "fake-ip",
                "fake-ip-range": "198.19.0.0/16",
                "nameserver": ["223.5.5.5", "119.29.29.29"],
                "proxy-server-nameserver": ["223.5.5.5"],
            },
            "proxies": proxies,
            "proxy-groups": [
                {"name": "manual", "type": "select", "proxies": node_names},
                {"name": "auto", "type": "url-test", "proxies": node_names,
                 "url": "https://opencode.ai/zen/v1/models",
                 "interval": "300", "tolerance": 100},
            ],
            "rules": ["MATCH,manual"],
        }
        with open(os.path.join(wd, "config.yaml"), "w", encoding="utf-8") as f:
            yaml.dump(cfg, f, Dumper=QuotedDumper, allow_unicode=True,
                      sort_keys=False, default_flow_style=False)
        print("slot-%d -> mixed-port %d, controller %d, %d nodes"
              % (i, PROXY_START + i, API_START + i, len(proxies)))

    with open(os.path.join(DATA_DIR, "nodes.json"), "w", encoding="utf-8") as f:
        json.dump({"nodes": node_names, "proxies": proxies, "sub_paths": paths},
                  f, ensure_ascii=False, indent=2)
    print("done: %d slots, %d nodes from %d subscriptions"
          % (SLOTS, len(proxies), len(paths)))


if __name__ == "__main__":
    main()
