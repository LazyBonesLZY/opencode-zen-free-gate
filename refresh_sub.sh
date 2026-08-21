#!/usr/bin/env bash
# 定时刷新订阅：重新拉取两个订阅 → 重新生成节点 → 重启 V4 代理槽
# 网关无需重启（运行时动态读取节点状态）
set -euo pipefail
cd "$(dirname "$0")"
# load optional config (SLOTS, V6_ACCOUNTS, V4_ACCOUNTS, ports...)
[ -f config.env ] && set -a && . ./config.env && set +a
MIHOMO="${MIHOMO:-/home/lzy/clashctl/bin/mihomo}"
LOG_DIR="$(pwd)/logs"
mkdir -p "$LOG_DIR" data

SUB_URL_1="${SUB_URL_1:-}"
SUB_URL_2="${SUB_URL_2:-}"
SUB_URL_3="${SUB_URL_3:-}"
SUB_URL_4="${SUB_URL_4:-}"
# 本地缓存备份（拉取失败时回退）
FALLBACK_1="/home/lzy/clashctl/resources/profiles/2.yaml"
FALLBACK_2="/home/lzy/clashctl/resources/profiles/1.yaml"
FALLBACK_3=""
FALLBACK_4=""

fetch_or_fallback() {
  local url="$1" out="$2" fb="$3"
  if curl -sL -m 30 -A "clash-verge/1.6.1" "$url" -o "$out.tmp" && [ -s "$out.tmp" ] && grep -q "proxies:" "$out.tmp"; then
    mv "$out.tmp" "$out"
    echo "  已拉取: $out ($(wc -c < "$out") 字节)"
  else
    rm -f "$out.tmp"
    if [ -n "$fb" ] && [ -f "$fb" ]; then
      cp "$fb" "$out" && echo "  拉取失败，使用本地缓存: $fb"
    else
      echo "  拉取失败，无缓存: $url" || true
    fi
  fi
}

echo "== 刷新订阅 =="
fetch_or_fallback "$SUB_URL_1" data/sub1.yaml "$FALLBACK_1"
fetch_or_fallback "$SUB_URL_2" data/sub2.yaml "$FALLBACK_2"
fetch_or_fallback "$SUB_URL_3" data/sub3.yaml "$FALLBACK_3"
fetch_or_fallback "$SUB_URL_4" data/sub4.yaml "$FALLBACK_4"

echo "== 确保 fwmark 规则存在 (绕过系统 clash TUN) =="
sudo -n python3 v6_setup.py add > /dev/null 2>&1 || true

echo "== 解析节点真实 IP (绕过 clash fake-ip DNS) =="
python3 resolve_node_ips.py data/sub1.yaml data/sub2.yaml data/sub3.yaml data/sub4.yaml 2>&1 | tail -3 || true

echo "== 重新生成节点 =="
python3 slots_gen.py "data/sub1.yaml,data/sub2.yaml,data/sub3.yaml,data/sub4.yaml" > "$LOG_DIR/slots_gen.log" 2>&1
grep "done:" "$LOG_DIR/slots_gen.log" || { echo "生成失败"; tail -5 "$LOG_DIR/slots_gen.log"; exit 1; }

echo "== 重启 V4 代理槽 =="
pids=$(pgrep -f "slots/slot-" || true)
[ -n "$pids" ] && kill $pids 2>/dev/null || true
sleep 1
pids=$(pgrep -f "slots/slot-" || true)
[ -n "$pids" ] && kill -9 $pids 2>/dev/null || true

for cfg in slots/slot-*/config.yaml; do
  dir="$(dirname "$cfg")"
  name="$(basename "$dir")"
  "$MIHOMO" -d "$dir" -f "$cfg" > "$LOG_DIR/$name.log" 2>&1 &
done
sleep 2
echo "完成: $(date '+%F %T')"
