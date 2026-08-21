#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
MIHOMO="${MIHOMO:-/home/lzy/clashctl/bin/mihomo}"
LOG_DIR="$(pwd)/logs"
mkdir -p "$LOG_DIR" data

# load optional config
[ -f config.env ] && set -a && . ./config.env && set +a

# 0. stop any existing instances first (avoid port conflicts)
./stop.sh 2>/dev/null || true

# 1. provision local IPv6 addresses (needs root)
echo "== 配置 IPv6 地址 =="
if ! sudo -n python3 v6_setup.py add 2>&1 | tail -3; then
  echo "WARN: v6 setup failed, V6 线路可能不可用"
fi

# 2. generate V4 proxy slot configs (5 slots, merged subscriptions)
if [ ! -f slots/slot-0/config.yaml ]; then
  python3 slots_gen.py > "$LOG_DIR/slots_gen.log" 2>&1 || { echo "gen failed"; tail -5 "$LOG_DIR/slots_gen.log"; exit 1; }
fi

# 3. start mihomo V4 slots
shopt -s nullglob
slot_pids=()
for cfg in slots/slot-*/config.yaml; do
  dir="$(dirname "$cfg")"
  name="$(basename "$dir")"
  "$MIHOMO" -d "$dir" -f "$cfg" > "$LOG_DIR/$name.log" 2>&1 &
  slot_pids+=("$!")
done
echo "已启动 ${#slot_pids[@]} 个 V4 代理槽"
sleep 2
for i in $(seq 0 4); do
  port=$((10800 + i))
  if ss -tln | grep -q ":$port "; then
    echo "  slot-$((i+5)) 代理 127.0.0.1:$port OK"
  else
    echo "  slot-$((i+5)) 启动失败 (见 logs/slot-$i.log)"
  fi
done

# 4. start gateway
if pgrep -f "gate.py" >/dev/null 2>&1; then
  echo "gate.py 已在运行"
else
  nohup python3 gate.py >> "$LOG_DIR/gate.log" 2>&1 &
  sleep 3
  echo "网关已启动"
fi

echo "---"
curl -s -m 5 http://127.0.0.1:13339/ping && echo
echo "状态页: http://127.0.0.1:13339/"
