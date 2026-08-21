#!/usr/bin/env python3
"""Resolve airport node server hostnames to real IPs via Cloudflare DoH.

The system DNS is hijacked by the clash TUN (fake-ip 198.18.x.x). To let slot
mihomo connect to airport nodes directly (bypassing the TUN via routing-mark)
we must resolve real IPs. We query Cloudflare DoH through the system clash
proxy (port 7890) which can reach the internet.

Usage: python3 resolve_node_ips.py <sub1.yaml> [sub2.yaml ...]
Writes: data/node_ips.json  {hostname: ip}
"""
import json
import os
import socket
import sys
import urllib.request
import urllib.parse

import yaml

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, "data")
OUT = os.path.join(DATA_DIR, "node_ips.json")
CLASH_HTTP = os.environ.get("CLASH_HTTP", "http://127.0.0.1:7890")
DOH = "https://cloudflare-dns.com/dns-query"


def doh_a(host, proxy=None):
    url = "%s?name=%s&type=A" % (DOH, urllib.parse.quote(host))
    handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy}) if proxy else None
    opener = urllib.request.build_opener(handler) if handler else urllib.request.build_opener()
    req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    with opener.open(req, timeout=10) as r:
        d = json.loads(r.read().decode())
    for a in d.get("Answer", []):
        if a.get("type") == 1:
            return a["data"]
    return None


def collect_hosts(paths):
    hosts = set()
    for path in paths:
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        for p in data.get("proxies", []):
            s = p.get("server", "")
            if s and not s.replace(".", "").isdigit():
                hosts.add(s)
    return sorted(hosts)


def main():
    paths = sys.argv[1:] if len(sys.argv) > 1 else []
    if not paths:
        sys.exit("usage: resolve_node_ips.py <sub.yaml> ...")
    hosts = collect_hosts(paths)
    mapping = {}
    if os.path.exists(OUT):
        try:
            mapping = json.load(open(OUT))
        except Exception:
            mapping = {}
    for h in hosts:
        if h in mapping and socket.inet_aton(mapping[h]):
            continue
        ip = doh_a(h, CLASH_HTTP)
        if ip:
            mapping[h] = ip
            print("  %s -> %s" % (h, ip))
        else:
            print("  %s -> (failed)" % h)
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(mapping, f, indent=2)
    print("done: %d hosts resolved -> %s" % (len(mapping), OUT))


if __name__ == "__main__":
    main()
