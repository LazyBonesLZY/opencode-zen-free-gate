#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# stop gateway (matches python3 gate.py)
pids=$(pgrep -f "gate.py" || true)
[ -n "$pids" ] && kill $pids 2>/dev/null || true

# stop mihomo V4 slots (match both absolute and relative cmdline)
pids=$(pgrep -f "slots/slot-" || true)
[ -n "$pids" ] && kill $pids 2>/dev/null || true
sleep 1
pids=$(pgrep -f "slots/slot-" || true)
[ -n "$pids" ] && kill -9 $pids 2>/dev/null || true

echo "stopped gateway + V4 slots"
