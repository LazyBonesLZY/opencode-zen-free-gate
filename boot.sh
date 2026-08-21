#!/usr/bin/env bash
# systemd 开机自启入口：完整启动整个网关
set -euo pipefail
cd "$(dirname "$0")"
MIHOMO="${MIHOMO:-/home/lzy/clashctl/bin/mihomo}"
LOG_DIR="$(pwd)/logs"
mkdir -p "$LOG_DIR" data

# load optional config
[ -f config.env ] && set -a && . ./config.env && set +a

# 0. stop any existing instances
./stop.sh 2>/dev/null || true

# 1. provision IPv6 addresses
sudo -n python3 v6_setup.py add > "$LOG_DIR/v6_setup.log" 2>&1 || \
  echo "WARN: v6 setup failed" >> "$LOG_DIR/v6_setup.log"

# 2. generate slots if missing
if [ ! -f slots/slot-0/config.yaml ]; then
  python3 slots_gen.py > "$LOG_DIR/slots_gen.log" 2>&1 || \
    { echo "gen failed"; tail -5 "$LOG_DIR/slots_gen.log" >&2; exit 1; }
fi

# 3. start mihomo V4 slots
for cfg in slots/slot-*/config.yaml; do
  dir="$(dirname "$cfg")"
  name="$(basename "$dir")"
  "$MIHOMO" -d "$dir" -f "$cfg" > "$LOG_DIR/$name.log" 2>&1 &
done
sleep 2

# 4. run gateway in foreground (systemd tracks this process)
exec python3 gate.py
