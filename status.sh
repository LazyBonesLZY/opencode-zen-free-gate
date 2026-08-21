#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "== gateway =="
if curl -s -m 3 http://127.0.0.1:13339/api/status >/dev/null 2>&1; then
  curl -s -m 3 http://127.0.0.1:13339/api/status | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('  slots:', len(d['slots']), '| V6:', d['config']['v6'], '| V4:', d['config']['v4'])
for s in d['slots']:
    mark = 'OK' if s['ok'] else '--'
    print(f\"  slot-{s['index']} [{s['mode']}] {mark} {s['current_node'] or ''} {(''+str(s['latency_ms'])+'ms') if s['latency_ms'] is not None else ''}\")
"
else
  echo "  gateway DOWN"
fi
echo "== V6 addresses =="
ip -6 addr show dev wlo1 | grep -c "2408:8256:4e89:18c3::" | xargs echo "  count:"
echo "== V4 slots =="
for i in 0 1 2 3 4; do
  proxy=$((10800 + i)); api=$((10990 + i))
  proxy_ok=$(ss -tln | grep -q ":$proxy " && echo OK || echo DOWN)
  api_node=$(curl -s -m 3 "http://127.0.0.1:$api/proxies/manual" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('now','?'))" 2>/dev/null || echo "?")
  echo "  slot-$((i+5)) proxy(127.0.0.1:$proxy)=$proxy_ok node=$api_node"
done
