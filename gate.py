#!/usr/bin/env python3
"""opencode-gate — opencode.ai/zen free reverse proxy gateway.

号池 (account pool) = 10 slots:
  * 5  V6 直连槽 (slots 0-4):  use local IPv6 source addresses directly
      (bound via socket source_address, routing bypasses the mihomo TUN via
      ip rules provisioned by v6_setup.py).
  * 5  V4 代理槽 (slots 5-9):  each slot = one mihomo instance with a
      `manual` select group; the gateway switches its node via the
      external-controller API on 429/5xx/connection errors.

Background probes keep per-node/per-addr health + latency for the status page.
stdlib only. Run: python3 gate.py
"""
import hashlib
import http.server
import json
import os
import socket
import ssl
import threading
import time
import hmac
import ipaddress
import random
import urllib.parse
import urllib.request
import urllib.error

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, "data")
PUBLIC_DIR = os.path.join(BASE, "public")
LOGS_DIR = os.path.join(BASE, "logs")

UPSTREAM_HOST = "opencode.ai"
UPSTREAM = "https://opencode.ai/zen"
UPSTREAM_PREFIX = "/zen"

PORT = int(os.environ.get("PORT", "13339"))

# account pool layout
V6_ACCOUNTS = int(os.environ.get("V6_ACCOUNTS", "2"))
V4_ACCOUNTS = int(os.environ.get("V4_ACCOUNTS", "8"))
TOTAL = V6_ACCOUNTS + V4_ACCOUNTS

# v6 direct config
V6_PREFIX = os.environ.get("V6_PREFIX", "2408:8256:4e89:18c3::")
V6_IFACE = os.environ.get("V6_IFACE", "wlo1")
V6_START = int(os.environ.get("V6_START", "2"))
V6_COUNT = int(os.environ.get("V6_COUNT", "10"))   # provisioned addresses
V6_DOH_INTERVAL = int(os.environ.get("V6_DOH_INTERVAL", "600"))

# v4 proxy config
PROXY_START = int(os.environ.get("PROXY_START", "10800"))
API_START = int(os.environ.get("API_START", "10990"))

MAX_RETRIES = int(os.environ.get("MAX_RETRIES", "3"))
TIMEOUT = int(os.environ.get("TIMEOUT", "15000"))
STREAM_TIMEOUT = int(os.environ.get("STREAM_TIMEOUT", "300000"))
UPSTREAM_AUTH = os.environ.get("UPSTREAM_AUTH", "Bearer public")
GATE_KEY = os.environ.get("GATE_KEY", "")

# oc-fwd 对齐参数（docs/configuration.md）
ZEN_RETRY_MAX = int(os.environ.get("ZEN_RETRY_MAX", "3"))
ZEN_RETRY_BACKOFF_SECONDS = float(os.environ.get("ZEN_RETRY_BACKOFF_SECONDS", "2"))
ZEN_RETRY_MAX_BACKOFF_SECONDS = float(os.environ.get("ZEN_RETRY_MAX_BACKOFF_SECONDS", "30"))
ZEN_CIRCUIT_FAILURES = int(os.environ.get("ZEN_CIRCUIT_FAILURES", "5"))
ZEN_CIRCUIT_COOLDOWN_SECONDS = int(os.environ.get("ZEN_CIRCUIT_COOLDOWN_SECONDS", "30"))
ZEN_MODELS = [s.strip() for s in os.environ.get("ZEN_MODELS", "").split(",") if s.strip()]
ZEN_MODEL_MAP = {}
for _kv in os.environ.get("ZEN_MODEL_MAP", "").split(","):
    if "=" in _kv:
        _k, _v = _kv.split("=", 1)
        ZEN_MODEL_MAP[_k.strip()] = _v.strip()
ZEN_MODEL_ENDPOINTS = {}
for _kv in os.environ.get("ZEN_MODEL_ENDPOINTS", "").split(","):
    if "=" in _kv:
        _k, _v = _kv.split("=", 1)
        ZEN_MODEL_ENDPOINTS[_k.strip().lower()] = _v.strip().lower()
ZEN_API_KEYS_FILE = os.environ.get("ZEN_API_KEYS_FILE", "")
ZEN_NO_KEY_FAIL_THRESHOLD = int(os.environ.get("ZEN_NO_KEY_FAIL_THRESHOLD", "3"))
ZEN_NO_KEY_PROBE_SECONDS = int(os.environ.get("ZEN_NO_KEY_PROBE_SECONDS", "3"))

# 节点/首字延迟优化：连接、首字节(TTFB) 各设独立超时，防止吊死在一个节点上
CONNECT_TIMEOUT = int(os.environ.get("CONNECT_TIMEOUT", "5000"))     # ms，建连+CONNECT
TTFB_TIMEOUT = int(os.environ.get("TTFB_TIMEOUT", "8000"))          # ms，发送后等待响应头
BODY_TIMEOUT = int(os.environ.get("BODY_TIMEOUT", "120000"))        # ms，非流式响应体读超时

# ── security ──────────────────────────────────────────────────────
# if GATE_KEY unset, auto-generate + persist (printed at startup)
GATE_KEY_FILE = os.path.join(DATA_DIR, "gate_key")
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(16 * 1024 * 1024)))

# 主动探测间隔（秒）：对槽位做轻量 /v1/models 探测。探测也消耗共享账号，
# 默认 300 秒一次，避免探测流量触发账号级 429。
PROBE_INTERVAL = int(os.environ.get("PROBE_INTERVAL", "300"))
PROBE_FAILURES = int(os.environ.get("PROBE_FAILURES", "2"))

# 全节点测速：RANK_INTERVAL 触发一轮遍历，RANK_REFRESH 为单节点测速缓存时长。
# /v1/models 是 GET 不计入生成配额，可较频繁刷新全池排名；
# 但每个节点之间仍间隔 2 秒，避免突发请求量。
RANK_INTERVAL = int(os.environ.get("RANK_INTERVAL", "1800"))
RANK_REFRESH = int(os.environ.get("RANK_REFRESH", "1800"))

CONTRIBUTOR_INTERVAL = float(os.environ.get("CONTRIBUTOR_INTERVAL", "10"))

AUDIT_FILE = os.path.join(DATA_DIR, "audit.jsonl")
MODELS_FILE = os.path.join(DATA_DIR, "models_cache.json")
STATS_FILE = os.path.join(DATA_DIR, "stats.json")

FORWARD = {
    "x-opencode-project", "x-opencode-session", "x-opencode-request",
    "x-opencode-client", "content-type", "accept", "anthropic-version",
    "anthropic-beta", "x-session-id", "conversation-id",
}

MIME_TYPES = {
    ".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
    ".png": "image/png", ".jpg": "image/jpeg", ".svg": "image/svg+xml",
    ".ico": "image/x-icon", ".woff": "font/woff", ".woff2": "font/woff2",
    ".ttf": "font/ttf", ".txt": "text/plain; charset=utf-8",
}

START_TIME = time.time()

stats = {"total": 0, "success": 0, "rateLimited": 0, "errors": 0, "switches": 0,
         "tokens": 0, "prompt_tokens": 0, "completion_tokens": 0}
token_by_model = {}  # model -> {"tokens","prompt_tokens","completion_tokens","req"}
token_lock = threading.Lock()
recent_logs = []
audit_log = []
MAX_LOGS = 500
MAX_AUDIT = 10000

cached_models = []
cached_models_time = 0
models_lock = threading.Lock()

# opencode.ai AAAA records (resolved via DOH, bypassing mihomo fake-ip DNS)
UPSTREAM_V6 = []
UPSTREAM_V6_AT = 0
v6_dns_lock = threading.Lock()

node_health = {}
node_health_lock = threading.Lock()

# 节点延迟排名：node -> (ema_ms, 最近测量时间)，用于最低延迟调度
node_latency = {}
node_latency_lock = threading.Lock()


def note_node_latency(node, ms):
    """记录节点延迟（指数移动平均，平滑抖动）。"""
    if not node:
        return
    with node_latency_lock:
        old, _ = node_latency.get(node, (None, 0))
        if old is None:
            node_latency[node] = (ms, time.time())
        else:
            node_latency[node] = (int(old * 0.7 + ms * 0.3), time.time())


def get_node_latency(node):
    with node_latency_lock:
        v = node_latency.get(node)
    return v[0] if v else None


# 节点并发计数：node -> in-flight 请求数，避免多并发打同一个 IP
node_inflight = {}
node_inflight_lock = threading.Lock()


def inc_node_inflight(node):
    with node_inflight_lock:
        node_inflight[node] = node_inflight.get(node, 0) + 1


def dec_node_inflight(node):
    with node_inflight_lock:
        c = node_inflight.get(node, 0)
        if c > 1:
            node_inflight[node] = c - 1
        else:
            node_inflight.pop(node, None)


def get_node_inflight(node):
    with node_inflight_lock:
        return node_inflight.get(node, 0)


# 全节点 opencode 测速：node -> (延迟ms, 测量时间)，周期刷新整个节点池
node_rank = {}
node_rank_lock = threading.Lock()

slots = []      # length TOTAL
accounts = []   # length TOTAL
account_cursor = 0
slots_lock = threading.Lock()
slot_route_locks = [threading.RLock() for _ in range(TOTAL)]
v4_switch_lock = threading.RLock()
schedule_lock = threading.Lock()
slot_inflight = [0 for _ in range(TOTAL)]

contributor_lock = threading.Lock()
contributor_last = 0.0

# oc-fwd circuit/fallback (P0/P1)
try:
    from gate_circuit import Circuit as _Circuit
    from gate_catalog import resolve_outbound_protocol, outbound_path, apply_model_map
    from gate_fallback import FallbackState as _FallbackState, load_api_keys as _load_api_keys
except ImportError:
    _Circuit = None
    resolve_outbound_protocol = outbound_path = apply_model_map = None
    _FallbackState = None
    _load_api_keys = None

upstream_circuit = None
fallback_state = None
api_keys_cache = []


def _init_oc_fwd_state():
    global upstream_circuit, fallback_state, api_keys_cache
    if _Circuit is not None:
        upstream_circuit = _Circuit(ZEN_CIRCUIT_FAILURES,
                                    ZEN_CIRCUIT_COOLDOWN_SECONDS * 1000)
    if _FallbackState is not None:
        api_keys_cache = _load_api_keys(ZEN_API_KEYS_FILE) if _load_api_keys else []
        fallback_state = _FallbackState(ZEN_NO_KEY_FAIL_THRESHOLD,
                                        len(api_keys_cache) > 0,
                                        ZEN_NO_KEY_PROBE_SECONDS)

# status-page timeline: {at, model, from, to, reason, detail}
timeline = []
timeline_lock = threading.Lock()
MAX_TIMELINE = 2000
TIMELINE_FILE = os.path.join(DATA_DIR, "timeline.json")
LAST_RECONCILE = 0

# slot state names mapped to status-page states
ST_OPERATIONAL = "operational"
ST_COOLDOWN = "cooldown"
ST_DOWN = "down"
ST_UNKNOWN = "unknown"


# ── security helpers ──────────────────────────────────────────────

def ensure_gate_key():
    """Return the configured GATE_KEY, auto-generating + persisting one."""
    global GATE_KEY
    if GATE_KEY:
        return GATE_KEY
    try:
        if os.path.exists(GATE_KEY_FILE):
            GATE_KEY = open(GATE_KEY_FILE).read().strip()
            return GATE_KEY
    except OSError:
        pass
    GATE_KEY = "sk-" + os.urandom(24).hex()
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(GATE_KEY_FILE, "w") as f:
            f.write(GATE_KEY)
        os.chmod(GATE_KEY_FILE, 0o600)
    except OSError:
        pass
    return GATE_KEY


def verify_key(supplied):
    if not GATE_KEY:
        return True  # auth disabled (local only)
    return hmac.compare_digest(supplied or "", GATE_KEY)


# Connection-failure cooldown shared across models.
node_cooldown = {}
node_cooldown_lock = threading.Lock()
model_node_cooldown = {}
model_node_cooldown_lock = threading.Lock()


def cooldown_global(node, seconds):
    with node_cooldown_lock:
        node_cooldown[node] = time.time() + seconds


def node_in_cooldown(node):
    with node_cooldown_lock:
        until = node_cooldown.get(node, 0)
        return until > time.time()


def cooldown_model_node(model, node, seconds):
    if model and node:
        with model_node_cooldown_lock:
            model_node_cooldown[(model, node)] = time.time() + seconds


def model_node_in_cooldown(model, node):
    with model_node_cooldown_lock:
        until = model_node_cooldown.get((model, node), 0)
    return until > time.time()


# 模型×节点 成功记忆：该模型在此节点成功过 → 优先复用（POST 通的出口很稀少）
model_node_ok = {}
model_node_ok_lock = threading.Lock()


def note_model_node_ok(model, node):
    if model and node:
        with model_node_ok_lock:
            model_node_ok[(model, node)] = time.time()


def model_node_was_ok(model, node, ttl=86400):
    with model_node_ok_lock:
        ts = model_node_ok.get((model, node), 0)
    return (time.time() - ts) < ttl


def acquire_contributor_gate():
    """Serialize contributor requests; this model has a shared rate limit."""
    contributor_lock.acquire()
    delay = CONTRIBUTOR_INTERVAL - (time.time() - contributor_last)
    if delay > 0:
        time.sleep(delay)


def release_contributor_gate():
    global contributor_last
    contributor_last = time.time()
    contributor_lock.release()


def push_timeline(model, from_state, to_state, reason, detail=""):
    with timeline_lock:
        timeline.append({"at": int(time.time() * 1000), "model": model,
                         "from": from_state, "to": to_state,
                         "reason": reason, "detail": detail})
        if len(timeline) > MAX_TIMELINE:
            del timeline[:-MAX_TIMELINE]
        try:
            with open(TIMELINE_FILE, "w", encoding="utf-8") as f:
                json.dump(timeline[-1000:], f, ensure_ascii=False)
        except OSError:
            pass


def load_timeline():
    global timeline
    try:
        with open(TIMELINE_FILE, encoding="utf-8") as f:
            timeline = json.load(f)
    except OSError:
        pass


def set_slot_state(i, state, reason, detail=""):
    """Update a slot's state, pushing a timeline event on transition."""
    with slots_lock:
        slot = slots[i]
        prev = slot.get("state", ST_UNKNOWN)
        if prev == state:
            slot["since"] = slot.get("since", time.time())
            return
        slot["state"] = state
        slot["since"] = time.time()
    push_timeline(accounts[i]["name"], prev, state, reason, detail)
    log("[slot-%d] 状态 %s → %s %s" % (i, prev, state, reason))


def v6_addrs():
    return ["%s%d" % (V6_PREFIX, n) for n in range(V6_START, V6_START + V6_COUNT)]


def log(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    recent_logs.append(line)
    if len(recent_logs) > MAX_LOGS:
        del recent_logs[:-MAX_LOGS]
    print(line, flush=True)


def audit(status, latency_ms, model, path, pt=0, ct=0, tt=0):
    entry = {"ts": int(time.time() * 1000), "status": status,
             "latency_ms": latency_ms, "model": model, "path": path,
             "pt": pt, "ct": ct, "tt": tt}
    audit_log.append(entry)
    if len(audit_log) > MAX_AUDIT:
        del audit_log[:-MAX_AUDIT]
    try:
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def save_stats():
    try:
        with token_lock:
            payload = {"stats": dict(stats), "token_by_model": dict(token_by_model)}
        with open(STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
    except OSError:
        pass


def load_stats():
    global stats, token_by_model
    try:
        with open(STATS_FILE, encoding="utf-8") as f:
            payload = json.load(f)
        s = payload.get("stats") or {}
        t = payload.get("token_by_model") or {}
        for k in ("total", "success", "rateLimited", "errors", "switches",
                  "tokens", "prompt_tokens", "completion_tokens"):
            if k in s:
                stats[k] = int(s[k])
        with token_lock:
            token_by_model.clear()
            for mk, mv in t.items():
                token_by_model[mk] = dict(mv)
        return True
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False


def record_tokens(model, pt, ct, tt):
    """Aggregate token usage globally and per model."""
    if not model:
        return
    stats["tokens"] += tt
    stats["prompt_tokens"] += pt
    stats["completion_tokens"] += ct
    with token_lock:
        m = token_by_model.setdefault(model, {"tokens": 0, "prompt_tokens": 0,
                                               "completion_tokens": 0, "req": 0})
        m["tokens"] += tt
        m["prompt_tokens"] += pt
        m["completion_tokens"] += ct
        m["req"] += 1
    save_stats()


def aggregate_sse(text):
    """把上游流式 SSE 聚合为完整 JSON（兼容 /responses 与 /chat/completions）。

    返回 (json_obj, model, pt, ct, tt)。
    若 text 本身是普通 JSON，直接解析返回。
    """
    text = text.strip()
    if text and not text.startswith("event:") and not text.startswith("data:"):
        try:
            return json.loads(text), "", 0, 0, 0
        except Exception:
            pass
    out_text = ""
    final_resp = None
    resp_id = ""
    model = ""
    pt = ct = tt = 0
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            d = json.loads(payload)
        except Exception:
            continue
        etype = d.get("type") or d.get("object") or ""
        if etype == "response.output_text.delta":
            out_text += d.get("delta", "")
            resp_id = d.get("id") or resp_id
            model = ((d.get("response") or {}).get("model") or model)
        elif etype == "response.completed":
            final_resp = d.get("response")
            model = model or (final_resp or {}).get("model", "")
        elif etype == "chat.completion.chunk":
            choices = d.get("choices") or []
            for c in choices:
                delta = c.get("delta") or {}
                out_text += delta.get("content") or ""
                if delta.get("reasoning_content"):
                    out_text += delta.get("reasoning_content") or ""
            model = model or d.get("model", "")
        u = d.get("usage") or (d.get("response") or {}).get("usage") or {}
        if u:
            pt = u.get("prompt_tokens", u.get("input_tokens", pt))
            ct = u.get("completion_tokens", u.get("output_tokens", ct))
            tt = u.get("total_tokens", 0) or (pt + ct)
    if not final_resp:
        final_resp = {"id": resp_id, "model": model, "status": "completed"}
    final_resp.setdefault("output", [
        {"id": "msg_%s" % resp_id, "type": "message", "status": "completed",
         "role": "assistant", "content": [{"type": "output_text",
                                           "text": out_text}]}])
    if out_text:
        msg = final_resp["output"][-1]
        if msg.get("type") == "message":
            msg["content"] = [{"type": "output_text", "text": out_text}]
    if tt:
        final_resp["usage"] = {"input_tokens": pt, "output_tokens": ct,
                               "total_tokens": tt}
    return final_resp, model, pt, ct, tt


def extract_tokens(text):
    """从上游响应体提取 (model, pt, ct, tt)。

    兼容多种格式：
    - SSE（chat/completions 与 responses 流式）：逐条 data: 解析，取最后带 usage 的
    - 普通 JSON（chat/completions 与 responses 非流式）：顶层或 response.usage
    """
    model = ""
    pt = ct = tt = 0
    if not text:
        return model, pt, ct, tt

    def consume(d):
        nonlocal model, pt, ct, tt
        m = d.get("model") or (d.get("response") or {}).get("model")
        if m:
            model = m
        u = d.get("usage") or (d.get("response") or {}).get("usage") or {}
        if u:
            pt = u.get("prompt_tokens", u.get("input_tokens", pt))
            ct = u.get("completion_tokens", u.get("output_tokens", ct))
            tt = u.get("total_tokens", 0) or (pt + ct)

    if "data:" in text:
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("data:") or "[DONE]" in line:
                continue
            try:
                consume(json.loads(line[5:].strip()))
            except Exception:
                continue
    else:
        try:
            consume(json.loads(text))
        except Exception:
            pass
    return model, pt, ct, tt


# ── DOH: resolve upstream AAAA (bypass fake-ip DNS) ───────────────

CLASH_PROXY = os.environ.get("CLASH_PROXY", "http://127.0.0.1:7890")


def resolve_aaaa_via_doh(proxy_port=None):
    """Resolve opencode.ai AAAA via Cloudflare DoH.

    Tries: system clash HTTP proxy (7890) first (always available), then a
    slot proxy if given. Avoids the fake-ip system DNS entirely.
    """
    proxies = []
    if CLASH_PROXY:
        proxies.append(CLASH_PROXY)
    if proxy_port:
        proxies.append("http://127.0.0.1:%d" % proxy_port)
    url = "https://cloudflare-dns.com/dns-query?name=%s&type=AAAA" % UPSTREAM_HOST
    for proxy in proxies:
        try:
            handler = urllib.request.ProxyHandler(
                {"http": proxy, "https": proxy})
            opener = urllib.request.build_opener(handler)
            req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
            with opener.open(req, timeout=10) as r:
                d = json.loads(r.read().decode("utf-8"))
            out = [a["data"] for a in d.get("Answer", [])
                   if a.get("type") == 28]
            if out:
                return out
        except Exception:
            continue
    return []


def refresh_upstream_v6():
    global UPSTREAM_V6, UPSTREAM_V6_AT
    # 7890 系统 clash 可能未运行；备用走第一个 V4 slot 代理做 DoH 解析。
    proxy_port = PROXY_START if V4_ACCOUNTS > 0 else None
    for attempt in range(3):
        try:
            addrs = resolve_aaaa_via_doh(proxy_port)
            if addrs:
                with v6_dns_lock:
                    UPSTREAM_V6 = addrs
                    UPSTREAM_V6_AT = time.time()
                log("上游 AAAA: %s" % ", ".join(addrs[:3]))
                return
            log("AAAA 解析为空 (attempt %d)" % (attempt + 1))
        except Exception as e:
            log("AAAA 解析失败: %s (attempt %d)" % (str(e)[:60], attempt + 1))
        time.sleep(3)


# ── slot / controller helpers ─────────────────────────────────────

def v4_api(i):
    return "http://127.0.0.1:%d" % (API_START + (i - V6_ACCOUNTS))


def _http_req(method, url, body=None, timeout=4):
    req = urllib.request.Request(url, method=method)
    if body is not None:
        req.data = json.dumps(body).encode()
        req.add_header("content-type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
        try:
            return json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            return {}


def get_manual_state(slot_idx):
    try:
        d = _http_req("GET", v4_api(slot_idx) + "/proxies/manual")
        return d.get("all", []), d.get("now", "")
    except Exception:
        return [], ""


def set_manual(slot_idx, node):
    try:
        _http_req("PUT", v4_api(slot_idx) + "/proxies/manual", {"name": node})
        return True
    except Exception:
        return False


# node -> observed egress IP (via ip.sb), cached to skip duplicate-IP nodes
egress_ip = {}
egress_ip_lock = threading.Lock()
EGRESS_VERIFY = os.environ.get("EGRESS_VERIFY", "1") == "1"


def get_egress_ip(slot_idx, timeout=8):
    """Query the slot's current egress IP via ip.sb / ipinfo (through the proxy)."""
    with slots_lock:
        proxy_port = slots[slot_idx]["proxy_port"]
    for host in ("api.ip.sb", "ipinfo.io"):
        try:
            sock = _connect_via_proxy("127.0.0.1", proxy_port, timeout,
                                      host, 443)
            sock.settimeout(timeout)
            path = "/ip" if host == "api.ip.sb" else "/ip"
            sock.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\n"
                          "Connection: close\r\n\r\n" % (path, host)).encode())
            head, rest = _read_until(sock)
            data = rest
            while True:
                c = sock.recv(65536)
                if not c:
                    break
                data += c
            sock.close()
            ip = data.decode("utf-8", "replace").strip()
            if ip and "." in ip:
                return ip
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
    return None


def verify_egress(slot_idx, node):
    """Verify egress IP for the node; skip if it duplicates a bad IP."""
    if not EGRESS_VERIFY:
        return True
    ip = get_egress_ip(slot_idx)
    if not ip:
        return True  # can't verify, allow (avoid being too strict)
    with egress_ip_lock:
        prev = egress_ip.get(node)
        egress_ip[node] = ip
    if prev and prev != ip:
        log("[slot-%d] 节点 %s 出口变化 %s → %s" % (slot_idx, node, prev, ip))
    return True


def verify_egress_current(slot_idx, node):
    """Verify only while the slot still points at the expected node."""
    with slot_route_locks[slot_idx]:
        with slots_lock:
            if slots[slot_idx].get("current_node") != node:
                return
        verify_egress(slot_idx, node)


def switch_and_probe(slot_idx, skip, reason, max_try=5):
    """切换节点后立即探测一次可用性（真实请求 /v1/models）。

    找到一个 200 的节点才返回 True；探测失败则冷却该节点并继续切换。
    返回 (ok, node)。
    """
    skip = skip or set()
    for _ in range(max_try):
        if not switch_slot(slot_idx, skip, reason):
            return False, ""
        with slots_lock:
            node = slots[slot_idx]["current_node"]
        if node in skip:
            continue
        try:
            with slots_lock:
                slot = slots[slot_idx]
            up = open_upstream(slot, "/v1/models", "GET",
                               {"authorization": UPSTREAM_AUTH,
                                "x-opencode-client": "cli",
                                "accept": "application/json"},
                               None, 8, False)
            body = b"".join(up.body_iter)
            t0 = time.time()
            latency = int((time.time() - t0) * 1000)
            if up.status < 500:
                record_result(slot_idx, node, True, 200, latency)
                log("[slot-%d] 切换后探测可达: %s HTTP %d (%dms)"
                    % (slot_idx, node, up.status, latency))
                return True, node
            # 探测失败：冷却并标记，继续切下一个
            cooldown_global(node, 30)
            set_slot_state(slot_idx, ST_COOLDOWN, "probe_fail",
                           "HTTP %d" % up.status)
            log("[slot-%d] 切换后探测失败 HTTP %d: %s → 继续切换"
                % (slot_idx, up.status, node))
            skip.add(node)
        except Exception as e:
            cooldown_global(node, 30)
            set_slot_state(slot_idx, ST_COOLDOWN, "probe_fail", str(e)[:50])
            log("[slot-%d] 切换后探测异常: %s → 继续切换"
                % (slot_idx, str(e)[:50]))
            skip.add(node)
    return False, ""



def switch_v4(slot_idx, skip, reason="", model=""):
    skip = skip or set()
    with v4_switch_lock, slot_route_locks[slot_idx]:
        all_nodes, now = get_manual_state(slot_idx)
        if not all_nodes:
            return False
        used = set()
        with slots_lock:
            for i, s in enumerate(slots):
                if i != slot_idx and s.get("current_node"):
                    used.add(s["current_node"])
        with egress_ip_lock:
            used_ips = {egress_ip[n] for n in used if n in egress_ip}
            known_ips = dict(egress_ip)
        # 候选排除：全局冷却 + 该模型的地区/限流冷却（否则 403 的节点会被反复选中）
        candidates = [n for n in all_nodes
                      if n not in skip and not node_in_cooldown(n)
                      and not (model and model_node_in_cooldown(model, n))]
        free = [n for n in candidates if n not in used and
                (n not in known_ips or known_ips[n] not in used_ips)]
        pool = free or candidates
        # 排序：该模型成功过的节点最优先 → 已知低延迟 → 未测随机
        pool.sort(key=lambda n: (0 if model_node_was_ok(model, n) else 1,
                                 get_node_latency(n) is None,
                                 get_node_latency(n) or 10 ** 9,
                                 random.random()))
        for node in pool:
            if set_manual(slot_idx, node):
                with slots_lock:
                    slots[slot_idx]["current_node"] = node
                    slots[slot_idx]["last_switch"] = time.time()
                    slots[slot_idx]["switched"] += 1
                stats["switches"] += 1
                log("[slot-%d] 切节点 → %s %s" % (slot_idx, node, reason))
                threading.Thread(target=verify_egress_current,
                                 args=(slot_idx, node), daemon=True).start()
                return True
    return False


def switch_v6(slot_idx, skip, reason=""):
    """Rotate a V6 slot to the next provisioned address not in cooldown."""
    skip = skip or set()
    addrs = v6_addrs()
    cur = slots[slot_idx]["current_node"]
    start = addrs.index(cur) if cur in addrs else -1
    with slots_lock:
        used = {s["current_node"] for i, s in enumerate(slots)
                if i != slot_idx and s.get("mode") == "v6"}
    for k in range(1, len(addrs) + 1):
        addr = addrs[(start + k) % len(addrs)]
        if addr in skip or addr in used:
            continue
        if node_in_cooldown(addr):
            continue
        with slots_lock:
            slots[slot_idx]["current_node"] = addr
            slots[slot_idx]["last_switch"] = time.time()
            slots[slot_idx]["switched"] += 1
        stats["switches"] += 1
        log("[slot-%d] V6换地址 → %s %s" % (slot_idx, addr, reason))
        return True
    return False


def switch_slot(slot_idx, skip=None, reason="", model=""):
    if slots[slot_idx]["mode"] == "v6":
        return switch_v6(slot_idx, skip, reason)
    return switch_v4(slot_idx, skip, reason, model=model)


def switch_slot_if_current(slot_idx, expected_node, skip=None, reason="", model=""):
    """Switch only if another concurrent request has not switched it already."""
    switch_lock = v4_switch_lock if slot_idx >= V6_ACCOUNTS else slot_route_locks[slot_idx]
    with switch_lock, slot_route_locks[slot_idx]:
        with slots_lock:
            if slots[slot_idx].get("current_node") != expected_node:
                return True
        return switch_slot(slot_idx, skip, reason, model=model)


def cooldown_node(slot_idx, node, seconds):
    cooldown_global(node, seconds)


def init_slots():
    addrs = v6_addrs()
    for i in range(TOTAL):
        mode = "v6" if i < V6_ACCOUNTS else "proxy"
        slot = {
            "index": i, "mode": mode,
            "proxy_port": None if mode == "v6" else PROXY_START + (i - V6_ACCOUNTS),
            "api_port": None if mode == "v6" else API_START + (i - V6_ACCOUNTS),
            "current_node": addrs[i] if mode == "v6" else "",
            "ok": False, "latency_ms": None, "last_check": 0,
            "cooldown_until": {}, "last_switch": 0, "switched": 0,
            "state": ST_UNKNOWN, "since": time.time(),
            "last_429": 0, "last_error": 0,
            "probe_failures": 0,
        }
        slots.append(slot)
        accounts.append({
            "index": i, "name": "线路 %02d" % (i + 1), "slot_idx": i,
            "mode": mode,
            "requests": 0, "success": 0, "rateLimited": 0,
            "errors": 0, "tokens": 0,
        })
    # init V4 slots: spread across distinct egress IPs (quota is per-IP)
    # 且按订阅轮转（A1→A2→A4→…），避免 8 个槽位全落在同一订阅上
    all_nodes = []
    for _ in range(10):
        all_nodes, _ = get_manual_state(V6_ACCOUNTS)
        if all_nodes:
            break
        time.sleep(1)
    # 按订阅前缀分组后交错排列：A1[0], A2[0], A4[0], A1[1], A2[1], ...
    by_sub = {}
    for n in all_nodes:
        by_sub.setdefault(n.split("|", 1)[0], []).append(n)
    subs = sorted(by_sub)
    interleaved = []
    idx = 0
    while len(interleaved) < len(all_nodes):
        progressed = False
        for s in subs:
            if idx < len(by_sub[s]):
                interleaved.append(by_sub[s][idx])
                progressed = True
                if len(interleaved) >= len(all_nodes):
                    break
        if not progressed:
            break
        idx += 1
    all_nodes = interleaved
    # 用第一个 V4 槽位作为临时探测通道：逐个临时切换候选节点，探测其真实出口 IP，
    # 挑选出口 IP 互不相同的节点分配给各槽位，保证 8 个槽位覆盖 8 个独立配额。
    probe_slot_idx = V6_ACCOUNTS
    chosen = []            # (node, egress_ip)
    chosen_ips = set()
    if all_nodes:
        for node in all_nodes:
            if len(chosen) >= V4_ACCOUNTS:
                break
            try:
                set_manual(probe_slot_idx, node)
                time.sleep(0.5)
                ip = get_egress_ip(probe_slot_idx, timeout=6)
            except Exception:
                ip = None
            if ip and ip not in chosen_ips:
                chosen.append((node, ip))
                chosen_ips.add(ip)
                log("[init] 节点 %s → 出口 %s" % (node[:40], ip))
        # 全部探测完仍不足时，退回节点名去重分配（宁可重复也不空槽）
        if len(chosen) < V4_ACCOUNTS:
            used = {n for n, _ in chosen}
            for node in all_nodes:
                if len(chosen) >= V4_ACCOUNTS:
                    break
                if node not in used:
                    chosen.append((node, None))
                    used.add(node)
        # 恢复探测槽位
        try:
            set_manual(probe_slot_idx, all_nodes[0])
        except Exception:
            pass
    for j in range(V4_ACCOUNTS):
        slot_idx = V6_ACCOUNTS + j
        if j < len(chosen):
            node, ip = chosen[j]
            if set_manual(slot_idx, node):
                slots[slot_idx]["current_node"] = node
                if ip:
                    with egress_ip_lock:
                        egress_ip[node] = ip
                threading.Thread(target=verify_egress_current,
                                 args=(slot_idx, node), daemon=True).start()
    for i in range(TOTAL):
        push_timeline(accounts[i]["name"], ST_UNKNOWN, ST_UNKNOWN, "initial")
    log("初始化 %d 个号 (V6直连 %d 个地址 / V4代理 %d 个槽, %d 节点)"
        % (TOTAL, V6_ACCOUNTS, V4_ACCOUNTS, len(all_nodes)))


# ── upstream tunnel ───────────────────────────────────────────────

def _read_until(sock, marker=b"\r\n\r\n", limit=1 << 16):
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > limit:
            break
    head, _, rest = buf.partition(marker)
    return head + marker, rest


class Upstream:
    def __init__(self, status, headers, body_iter, ttfb_ms=0):
        self.status = status
        self.headers = headers
        self.body_iter = body_iter
        self.ttfb_ms = ttfb_ms


def _connect_via_proxy(proxy_host, proxy_port, connect_s, dest_host, dest_port):
    sock = socket.create_connection((proxy_host, proxy_port), timeout=connect_s)
    sock.settimeout(connect_s)
    req = ("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"
           "Proxy-Connection: Keep-Alive\r\n\r\n"
           % (dest_host, dest_port, dest_host, dest_port)).encode()
    sock.sendall(req)
    head, _ = _read_until(sock)
    status = int(head.split(b" ", 2)[1])
    if status != 200:
        sock.close()
        raise ConnectionError("CONNECT failed: %s"
                              % head.split(b"\r\n", 1)[0].decode())
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(sock, server_hostname=dest_host)


def _connect_direct_v6(src_addr, connect_s):
    """Direct IPv6 TLS to the upstream using a specific source address."""
    with v6_dns_lock:
        addrs = list(UPSTREAM_V6)
    if not addrs:
        raise ConnectionError("upstream AAAA not resolved")
    last = None
    for ip in addrs:
        try:
            sock = socket.create_connection((ip, 443), timeout=connect_s,
                                            source_address=(src_addr, 0))
            sock.settimeout(connect_s)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx.wrap_socket(sock, server_hostname=UPSTREAM_HOST)
        except Exception as e:
            last = e
    raise ConnectionError("v6 direct connect failed: %s" % (last or "no addrs"))


def _send_request(sock, method, path, headers, body, ttfb_s, body_s, stream):
    hdrs = ["%s: %s" % (k, v) for k, v in headers.items() if v is not None]
    if body and "content-length" not in headers:
        hdrs.append("content-length: %d" % len(body.encode()))
    if "connection" not in headers:
        hdrs.append("connection: close")
    head = ("%s %s%s HTTP/1.1\r\nHost: %s\r\n%s\r\n\r\n"
            % (method, UPSTREAM_PREFIX, path, UPSTREAM_HOST, "\r\n".join(hdrs))).encode()
    t_send = time.time()
    sock.sendall(head)
    if body:
        sock.sendall(body.encode())
    # 首字节（TTFB）超时：等待响应头，防止吊死在慢/死节点上
    sock.settimeout(ttfb_s)
    head_buf, rest = _read_until(sock, limit=1 << 18)
    ttfb_ms = int((time.time() - t_send) * 1000)
    lines = head_buf.split(b"\r\n")
    status = int(lines[0].split(b" ", 2)[1])
    resp_headers = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, _, v = ln.partition(b":")
            resp_headers[k.decode().lower().strip()] = v.decode().strip()
    sock.settimeout(body_s)

    def body_iter():
        try:
            if resp_headers.get("transfer-encoding", "").lower() == "chunked":
                yield from _parse_chunked(_sock_iter(sock, rest))
            elif "content-length" in resp_headers:
                remaining = int(resp_headers["content-length"])
                if rest:
                    take = rest[:remaining]
                    yield take
                    remaining -= len(take)
                while remaining > 0:
                    data = sock.recv(min(65536, remaining))
                    if not data:
                        break
                    yield data
                    remaining -= len(data)
            else:
                yield rest
                while True:
                    data = sock.recv(65536)
                    if not data:
                        break
                    yield data
        finally:
            try:
                sock.close()
            except OSError:
                pass

    return Upstream(status, resp_headers, body_iter(), ttfb_ms=ttfb_ms)


def _parse_chunked(iterable):
    buf = b""
    for chunk in iterable:
        buf += chunk
        while True:
            idx = buf.find(b"\r\n")
            if idx < 0:
                break
            try:
                size = int(buf[:idx].split(b";")[0].strip(), 16)
            except ValueError:
                return
            if len(buf) < idx + 2 + size + 2:
                break
            yield buf[idx + 2:idx + 2 + size]
            buf = buf[idx + 2 + size + 2:]


def _sock_iter(sock, initial=b""):
    if initial:
        yield initial
    while True:
        try:
            data = sock.recv(65536)
        except (socket.timeout, OSError):
            return
        if not data:
            return
        yield data


def open_upstream(slot, path, method, headers, body, timeout, stream):
    connect_s = CONNECT_TIMEOUT / 1000.0
    ttfb_s = TTFB_TIMEOUT / 1000.0
    body_s = (STREAM_TIMEOUT / 1000.0 if stream else BODY_TIMEOUT / 1000.0)
    if slot["mode"] == "v6":
        sock = _connect_direct_v6(slot["current_node"], connect_s)
    else:
        sock = _connect_via_proxy("127.0.0.1", slot["proxy_port"], connect_s,
                                  UPSTREAM_HOST, 443)
    return _send_request(sock, method, path, headers, body, ttfb_s, body_s, stream)


# ── models cache ──────────────────────────────────────────────────

def fetch_models(slot_idx=0):
    global cached_models, cached_models_time
    # 模型列表 GET 不计生成配额，但 429 仍可能按出口限流；换出口重试避免单 IP 卡死发现
    tried = set()
    last_body = None
    for _ in range(min(3, TOTAL)):
        try:
            status, body = simple_probe(slot_idx, "/v1/models")
            last_body = body
            if status == 429:
                tried.add(slot_idx)
                # 换一个当前不在限流的出口重试
                found = None
                with slots_lock:
                    for i, s in enumerate(slots):
                        if i in tried:
                            continue
                        if s.get("current_node") and not model_node_in_cooldown("", s["current_node"]):
                            found = i
                            break
                if found is not None:
                    slot_idx = found
                    time.sleep(0.5)
                    continue
                break
            if status == 200 and body:
                data = json.loads(body)
                ms = data.get("data", data.get("models", []))
                with models_lock:
                    cached_models = ms
                    cached_models_time = time.time()
                with open(MODELS_FILE, "w", encoding="utf-8") as f:
                    json.dump({"models": ms, "time": cached_models_time}, f)
                log("已刷新模型列表: %d 个" % len(ms))
                return ms
            break
        except Exception as e:
            log("刷新模型失败: %s" % e)
            break
    return cached_models


def models_refresh_loop():
    # web 状态页与 /v1/models API 使用同一缓存；定时自动刷新，避免页面上固定不变
    while True:
        time.sleep(300)
        fetch_models()


def load_models_cache():
    global cached_models, cached_models_time
    try:
        with open(MODELS_FILE, encoding="utf-8") as f:
            d = json.load(f)
            cached_models = d.get("models", [])
            cached_models_time = d.get("time", 0)
            return bool(cached_models)
    except OSError:
        return False


# ── passive detection ─────────────────────────────────────────────
# 可用性只在真实请求经过时才更新（不主动探测，避免消耗免费额度）。
# dispatch() 每次请求后调用 record_result() 刷新节点/线路状态。

def record_result(slot_idx, node, ok, status, latency_ms):
    transition = None
    with slots_lock:
        slot = slots[slot_idx]
        slot["ok"] = ok
        slot["last_check"] = time.time()
        if ok:
            slot["latency_ms"] = latency_ms
            slot["probe_failures"] = 0
        else:
            slot["probe_failures"] = slot.get("probe_failures", 0) + 1
        if ok and slot["state"] != ST_OPERATIONAL:
            prev = slot["state"]
            slot["state"] = ST_OPERATIONAL
            slot["since"] = time.time()
            transition = (prev, ST_OPERATIONAL, "recovered")
        elif not ok and slot["probe_failures"] >= PROBE_FAILURES and \
                slot["state"] != ST_DOWN:
            prev = slot["state"]
            slot["state"] = ST_DOWN
            slot["latency_ms"] = None
            slot["since"] = time.time()
            transition = (prev, ST_DOWN, "probe_fail")
        mode = slot["mode"]
    if transition:
        push_timeline(accounts[slot_idx]["name"], *transition)
    with node_health_lock:
        node_health[node] = {"latency_ms": latency_ms if ok else None,
                             "ok": ok, "mode": mode,
                             "last_probe": time.time()}
    # 延迟排名：成功请求的 TTFB 或整请求延迟都可用于排名
    if latency_ms:
        note_node_latency(node, latency_ms)


def simple_probe(slot_idx, path, method="GET", headers=None, body=None, timeout=10):
    with slots_lock:
        slot = slots[slot_idx]
    up = open_upstream(slot, path, method, headers or {}, body, timeout, False)
    return up.status, b"".join(up.body_iter).decode("utf-8", "replace")


# ── active probing ─────────────────────────────────────────────────
# 周期性对槽位做轻量探测（/v1/models，GET，不计费），让"待检测"槽位尽快被检测。
# 探测结果会通过 record_result() 刷新槽位状态，与真实请求走同一套逻辑。

def probe_all_slots():
    for i in range(TOTAL):
        t0 = time.time()
        try:
            if not slot_route_locks[i].acquire(blocking=False):
                continue
            try:
                with slots_lock:
                    slot = dict(slots[i])
                if not slot.get("current_node") or \
                        node_in_cooldown(slot["current_node"]) or \
                        get_node_inflight(slot["current_node"]):
                    continue
                up = open_upstream(slot, "/v1/models", "GET", {}, None, 8, False)
                status = up.status
                b"".join(up.body_iter)
            finally:
                slot_route_locks[i].release()
            lat = int((time.time() - t0) * 1000)
            # 4xx/5xx 已证明线路可到达 opencode，不能把上游状态误判为节点掉线。
            record_result(i, slot["current_node"], True, status, lat)
        except Exception as e:
            lat = int((time.time() - t0) * 1000)
            with slots_lock:
                slot = slots[i]
            record_result(i, slot["current_node"], False, 0, None)
            log("探测 slot-%d 失败: %s" % (i, str(e)[:80]))
            with slots_lock:
                failures = slots[i].get("probe_failures", 0)
                failed_node = slots[i].get("current_node")
            if failures >= PROBE_FAILURES and failed_node:
                if switch_slot_if_current(i, failed_node, {failed_node},
                                          "(探测失败)"):
                    set_slot_state(i, ST_UNKNOWN, "probe_switch")


def probe_loop():
    while True:
        time.sleep(PROBE_INTERVAL)
        probe_all_slots()


def rank_probe_all():
    """遍历整个 V4 节点池，测每个节点到 opencode.ai 的往返速度。

    通过各槽位 mihomo 控制 API 的 /proxies/<node>/delay 直接测单个节点，
    不切换任何生产槽位的 current_node，不影响正在服务的出口 IP。
    """
    if V4_ACCOUNTS <= 0:
        return
    probe_idx = V6_ACCOUNTS
    all_nodes, _ = get_manual_state(probe_idx)
    if not all_nodes:
        return
    now = time.time()
    targets = []
    for n in all_nodes:
        with node_latency_lock:
            _, ts = node_latency.get(n, (None, 0))
        if node_in_cooldown(n):
            continue
        if ts and (now - ts) < RANK_REFRESH:
            continue
        targets.append(n)
    # 未测过的节点优先（补齐延迟数据），再按订阅交错，避免偏向单一订阅
    targets.sort(key=lambda n: 0 if n not in [x for x in targets
                 if (lambda t: t is not None)(node_latency.get(n, (None, 0))[0])] else 1)
    by_sub = {}
    for n in targets:
        by_sub.setdefault(n.split("|", 1)[0], []).append(n)
    interleaved = []
    idx = 0
    while len(interleaved) < len(targets):
        progressed = False
        for s in sorted(by_sub):
            if idx < len(by_sub[s]):
                interleaved.append(by_sub[s][idx])
                progressed = True
                if len(interleaved) >= len(targets):
                    break
        if not progressed:
            break
        idx += 1
    targets = interleaved
    # 轮流用 8 个 V4 槽位的 mihomo delay API 测速，分摊请求压力。
    api_pool = [v4_api(i) for i in range(V6_ACCOUNTS, TOTAL)]
    for target_idx, node in enumerate(targets):
        time.sleep(2)
        api = api_pool[target_idx % len(api_pool)]
        url = ("%s/proxies/%s/delay?url=%s&timeout=6000"
               % (api, urllib.parse.quote(node, safe=""),
                  urllib.parse.quote("https://opencode.ai/zen/v1/models", safe="")))
        try:
            d = _http_req("GET", url, timeout=10)
            delay = d.get("delay")
            if delay is not None and delay > 0:
                note_node_latency(node, delay)
                log("测速 %s → opencode %dms" % (node[:40], delay))
        except Exception:
            continue


def rank_probe_loop():
    # 启动 60 秒后先跑一轮全池测速，让节点智能选择尽快拿到新鲜排名；
    # 之后每 RANK_INTERVAL 秒一轮。测速是 GET 不计生成配额，且逐节点间隔。
    time.sleep(60)
    while True:
        rank_probe_all()
        time.sleep(RANK_INTERVAL)


# ── dispatch ──────────────────────────────────────────────────────

def build_upstream_headers(req_headers, body):
    h = {}
    for k in FORWARD:
        v = req_headers.get(k)
        if v:
            h[k] = v
    h["authorization"] = UPSTREAM_AUTH
    h["x-opencode-client"] = h.get("x-opencode-client", "cli")
    h["user-agent"] = "opencode/1.18.16 ai-sdk/provider-utils/4.0.23 runtime/python"
    h["accept"] = h.get("accept", "application/json")
    h["content-type"] = h.get("content-type", "application/json")
    inject_opencode_headers(h, body)
    return h


def inject_opencode_headers(h, body):
    seed = h.get("x-opencode-session") or h.get("x-session-id") or h.get("conversation-id")
    if not seed:
        try:
            p = json.loads(body) if body else {}
            seed = p.get("conversation_id") or (p.get("metadata") or {}).get("session_id")
        except Exception:
            seed = None
    if not seed:
        try:
            p = json.loads(body) if body else {}
            for m in p.get("messages") or []:
                if isinstance(m, dict) and m.get("role") == "user":
                    seed = json.dumps(m.get("content"))
                    break
        except Exception:
            pass
    if not seed:
        seed = "default"
    if "x-opencode-session" not in h:
        h["x-opencode-session"] = "ses_" + hashlib.sha256(seed.encode()).hexdigest()[:24]
    if "x-opencode-request" not in h:
        h["x-opencode-request"] = "req_" + os.urandom(8).hex()
    if "x-opencode-project" not in h:
        h["x-opencode-project"] = "prj_" + hashlib.sha256(
            b"opencode2api:default").hexdigest()[:24]


def chat_to_responses_body(body: str) -> str:
    try:
        p = json.loads(body) if body else {}
        msgs = p.get("messages") or []
        inp = []
        for m in msgs:
            if isinstance(m, dict):
                role = m.get("role", "user")
                content = m.get("content", "")
                if isinstance(content, list):
                    content = "".join(c.get("text", "") for c in content if isinstance(c, dict))
                inp.append({"role": role, "content": str(content)})
        out: dict = {"model": p.get("model"), "input": inp}
        if p.get("stream") is not None:
            out["stream"] = p["stream"]
        if p.get("temperature") is not None:
            out["temperature"] = p["temperature"]
        return json.dumps(out)
    except Exception:
        return body


def responses_to_chat_body(body: str) -> str:
    """Convert Responses input/tools to Chat Completions, including tool results."""
    try:
        p = json.loads(body) if body else {}
        messages = []
        pending_calls = []
        for item in p.get("input") or []:
            if not isinstance(item, dict):
                continue
            typ = item.get("type", "")
            if typ == "function_call":
                pending_calls.append({
                    "id": item.get("call_id") or item.get("id"),
                    "type": "function",
                    "function": {
                        "name": item.get("name", ""),
                        "arguments": item.get("arguments", "{}"),
                    },
                })
                continue
            if typ == "function_call_output":
                if pending_calls:
                    messages.append({"role": "assistant", "content": "",
                                     "tool_calls": pending_calls})
                    pending_calls = []
                messages.append({"role": "tool",
                                 "tool_call_id": item.get("call_id"),
                                 "content": str(item.get("output", ""))})
                continue
            role = item.get("role")
            if role:
                content = item.get("content", "")
                if isinstance(content, list):
                    parts = []
                    for part in content:
                        if isinstance(part, dict):
                            parts.append(part.get("text") or
                                         part.get("input_text") or
                                         part.get("output_text") or "")
                        else:
                            parts.append(str(part))
                    content = "".join(parts)
                messages.append({"role": role, "content": content})
        if pending_calls:
            messages.append({"role": "assistant", "content": "",
                             "tool_calls": pending_calls})
        # Some Responses clients only replay call/output. Chat providers reject
        # a history starting with assistant/tool, so add a neutral context item.
        if messages and messages[0].get("role") in ("assistant", "tool"):
            messages.insert(0, {"role": "user",
                                "content": "Continue using the tool result."})
        tools = []
        for tool in p.get("tools") or []:
            if not isinstance(tool, dict):
                continue
            if tool.get("type") == "function" and "function" not in tool:
                tools.append({"type": "function", "function": {
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                    "parameters": tool.get("parameters", {"type": "object"}),
                }})
            else:
                tools.append(tool)
        out = {"model": p.get("model"), "messages": messages,
               "stream": False}
        if tools:
            out["tools"] = tools
        choice = p.get("tool_choice")
        if choice:
            out["tool_choice"] = choice
        for key in ("temperature", "top_p", "max_tokens"):
            if key in p:
                out[key] = p[key]
        return json.dumps(out)
    except Exception:
        return body


def chat_completion_to_responses(raw: str, alias_model=""):
    """Convert a non-stream Chat completion to a Responses response."""
    d = json.loads(raw)
    choice = (d.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    output = []
    for call in msg.get("tool_calls") or []:
        fn = call.get("function") or {}
        output.append({"id": call.get("id"), "type": "function_call",
                       "name": fn.get("name", ""),
                       "call_id": call.get("id"),
                       "arguments": fn.get("arguments", "{}")})
    content = msg.get("content") or ""
    if content:
        output.append({"id": "msg_" + str(d.get("id", "")),
                       "type": "message", "status": "completed",
                       "role": "assistant", "content": [
                           {"type": "output_text", "text": content,
                            "annotations": [], "logprobs": []}]})
    usage = d.get("usage") or {}
    return {
        "id": d.get("id"), "object": "response", "status": "completed",
        "model": alias_model or d.get("model"), "output": output,
        "stop_reason": "tool_call" if msg.get("tool_calls") else
                       choice.get("finish_reason"),
        "usage": {"input_tokens": usage.get("prompt_tokens", 0),
                  "output_tokens": usage.get("completion_tokens", 0),
                  "total_tokens": usage.get("total_tokens", 0)},
    }


def chat_to_messages_body(body: str) -> str:
    try:
        p = json.loads(body) if body else {}
        msgs = p.get("messages") or []
        # Anthropic expects system separately, but passthrough here
        out: dict = {"model": p.get("model"), "messages": msgs, "max_tokens": p.get("max_tokens", 4096)}
        if p.get("stream") is not None:
            out["stream"] = p["stream"]
        return json.dumps(out)
    except Exception:
        return body


def append_free_suffix(body):
    try:
        p = json.loads(body)
        if p.get("model") and not str(p["model"]).endswith("-free"):
            p["model"] = str(p["model"]) + "-free"
        for m in p.get("messages", []):
            if isinstance(m, dict) and m.get("role") == "assistant" \
                    and "reasoning_content" not in m:
                m["reasoning_content"] = ""
        return json.dumps(p)
    except Exception:
        return body


def inject_safety_id(body):
    """为请求体注入 safety_identifier（contributor 类免费模型要求端用户标识）。

    优先使用客户端已提供的 user / safety_identifier 字段；否则用稳定的
    x-opencode-session 派生一个。对 chat/completions 与 responses 都适用。
    """
    try:
        p = json.loads(body)
        if p.get("user") or p.get("safety_identifier"):
            return body
        sid = "opc_" + hashlib.sha256(
            ("zen:" + (p.get("conversation_id") or "default")).encode()
        ).hexdigest()[:20]
        p["safety_identifier"] = sid
        return json.dumps(p)
    except Exception:
        return body


def dispatch(account_idx, path, method, req_headers, body, stream):
    """Route request through the account's slot, switching node on failure.

    Passive detection: each attempt's outcome updates node/line status via
    record_result(). On 429/5xx/connection error the node is cooldown'd
    globally (shared across slots) and the slot switches node; if the whole
    pool of a slot is exhausted, fail over to the next slot.
    """
    acct = accounts[account_idx]
    slot_idx = acct["slot_idx"]
    last_err = None
    last_status = 0
    total_attempts = 0
    # 免费配额按出口 IP 分配：每个请求对每个不同出口 IP 最多打一次，
    # 429 后切换到不同出口 IP 再试，避免在同一 IP 上反复撞限流。
    tried_ips = set()
    max_attempts = min(TOTAL, 8)
    try:
        model = str((json.loads(body) or {}).get("model", "")).lower()
    except Exception:
        model = ""
    order = list(range(V6_ACCOUNTS, TOTAL)) if "contributor" in model \
        else list(range(TOTAL))
    if slot_idx not in order:
        slot_idx = order[0]
    start = order.index(slot_idx)
    order = order[start:] + order[:start]

    for sidx in order:
        with slots_lock:
            slot = slots[sidx]
            current_node = slot["current_node"]
        if model_node_in_cooldown(model, current_node):
            continue
        # 该槽位出口 IP 已被本次请求试过并 429，跳过（配额按 IP 分配）。
        with egress_ip_lock:
            cur_ip = egress_ip.get(current_node)
        if cur_ip and cur_ip in tried_ips:
            continue
        tried = set()
        # 每个请求最多尝试 max_attempts 个不同出口 IP；429 切换后立即重试新节点。
        for attempt in range(1, max_attempts + 1):
            if total_attempts >= max_attempts:
                break
            total_attempts += 1
            with slots_lock:
                node = slots[sidx]["current_node"]
            if node in tried:
                try:
                    switch_slot(sidx, tried, "(重试)")
                except Exception:
                    pass
                node = slots[sidx]["current_node"]
            tried.add(node)
            t0 = time.time()
            inc_node_inflight(node)
            released = False

            def release_node():
                nonlocal released
                if not released:
                    released = True
                    dec_node_inflight(node)

            try:
                with slot_route_locks[sidx]:
                    with slots_lock:
                        route_slot = dict(slots[sidx])
                    up = open_upstream(route_slot, path, method, req_headers,
                                       body, TIMEOUT, stream)
                latency = int((time.time() - t0) * 1000)
                if up.status == 429:
                    last_status = 429
                    # 熔断仅对「无 API key 回退」时启用；有 key 时熔断促换 key。
                    # 无 key 场景按 IP 配额：同一请求内换出口立即重试。
                    if upstream_circuit and not upstream_circuit.allow():
                        up.body_iter.close()
                        release_node()
                        stats["rateLimited"] += 1
                        acct["rateLimited"] += 1
                        cooldown_model_node(model, node, 60)
                        log("[429] %s 熔断中，直接返回" % acct["name"])
                        total_attempts = max_attempts
                        break
                    up.body_iter.close()
                    release_node()
                    stats["rateLimited"] += 1
                    acct["rateLimited"] += 1
                    # 429 冷却时长：优先上游 Retry-After（额度重置时间），
                    # 无则默认 600s；到期自动释放（时间戳比较自然过期）
                    ra = up.headers.get("retry-after")
                    try:
                        cd = int(ra) if ra else 600
                    except ValueError:
                        cd = 600
                    cd = min(max(cd, 60), 86400)
                    cooldown_model_node(model, node, cd)
                    if upstream_circuit:
                        upstream_circuit.record_failure()
                    with slots_lock:
                        slots[sidx]["last_429"] = time.time()
                    with egress_ip_lock:
                        ip = egress_ip.get(node)
                    if ip:
                        tried_ips.add(ip)
                    log("[429] %s(%s) 出口 %s 限流，冷却 %ds 后释放"
                        % (acct["name"], slot["mode"], ip or node, cd))
                    if fallback_state and fallback_state.should_fallback(model, 429):
                        fallback_state.mark_keyed(model)
                        log(f"[key] 模型 {model} 429 达阈值，切 key")
                    # 换到新节点后立即在本请求内继续尝试（不 break）
                    with egress_ip_lock:
                        skip_ips = dict(egress_ip)
                    skip_tried = tried | {n for n, ip2 in skip_ips.items()
                                          if ip2 in tried_ips}
                    try:
                        switch_slot_if_current(sidx, node, skip_tried, "(429)", model=model)
                    except Exception:
                        pass
                    if total_attempts >= max_attempts:
                        break
                    # 本槽位连吃 2 次 429 → 直接跳下一个槽位（别在本槽死磕）
                    if attempt >= 2:
                        break
                    continue
                if up.status >= 500:
                    last_status = up.status
                    up.body_iter.close()
                    release_node()
                    stats["errors"] += 1
                    acct["errors"] += 1
                    with slots_lock:
                        slots[sidx]["last_error"] = time.time()
                    log("[%d] %s(%s) 节点 %s 上游错误，换槽重试 (attempt %d)"
                        % (up.status, acct["name"], slot["mode"], node, attempt))
                    # oc-fwd: 非200立即尝试匿名->key 回退（P1）
                    if fallback_state and fallback_state.should_fallback(model, up.status):
                        fallback_state.mark_keyed(model)
                        log("[key] 模型 %s 触发匿名->key 回退" % model)
                    time.sleep(random.uniform(0.2, 0.6))
                    # 5xx 换节点后同一请求内继续重试
                    with egress_ip_lock:
                        ip = egress_ip.get(node)
                    if ip:
                        tried_ips.add(ip)
                    with egress_ip_lock:
                        skip_ips = dict(egress_ip)
                    skip_tried = tried | {n for n, ip2 in skip_ips.items()
                                          if ip2 in tried_ips}
                    try:
                        switch_slot_if_current(sidx, node, skip_tried, "(%d)" % up.status, model=model)
                    except Exception:
                        pass
                    if total_attempts >= max_attempts:
                        break
                    continue
                if 400 <= up.status < 500:
                    # 读取错误体，检测 RegionError（模型有地区限制）
                    err_body = b"".join(up.body_iter).decode("utf-8", "replace")
                    is_region = ("RegionError" in err_body or
                                 "not available in your country" in err_body)
                    if is_region:
                        last_status = up.status
                        release_node()
                        log("[403] %s(%s) 节点 %s 地区受限，冷却+换号 (attempt %d)"
                            % (acct["name"], slot["mode"], node, attempt))
                        stats["errors"] += 1
                        acct["errors"] += 1
                        with slots_lock:
                            slots[sidx]["last_error"] = time.time()
                        # 地区限制只隔离当前模型，不影响其它模型使用该线路。
                        cooldown_model_node(model, node, 1800)
                        if fallback_state and fallback_state.should_fallback(model, up.status):
                            fallback_state.mark_keyed(model)
                            log("[key] 模型 %s 地区受限触发回退" % model)
                        with egress_ip_lock:
                            ip = egress_ip.get(node)
                        if ip:
                            tried_ips.add(ip)
                        with egress_ip_lock:
                            skip_ips = dict(egress_ip)
                        skip_tried = tried | {n for n, ip2 in skip_ips.items()
                                              if ip2 in tried_ips}
                        try:
                            switch_slot_if_current(sidx, node, skip_tried, "(403)", model=model)
                        except Exception:
                            pass
                        if total_attempts >= max_attempts:
                            break
                        continue
                    # 其他 4xx 是客户端侧错误，原样透传
                    release_node()
                    record_result(sidx, node, False, up.status, None)
                    return Upstream(up.status, up.headers,
                                    iter([err_body.encode()]))
                # success (2xx) pass through
                record_result(sidx, node, up.status < 400,
                              up.status, latency if up.status < 400 else None)
                # 记住该模型在此节点成功过，后续优先复用此出口
                note_model_node_ok(model, node)
                if upstream_circuit:
                    upstream_circuit.record_success()
                if fallback_state:
                    fallback_state.note_success(model)
                # 用 TTFB（首字节时间）做节点延迟排名，比整请求时间更准
                if up.ttfb_ms:
                    note_node_latency(node, up.ttfb_ms)
                original_iter = up.body_iter

                def tracked_body_iter():
                    try:
                        yield from original_iter
                    finally:
                        original_iter.close()
                        release_node()

                up.body_iter = tracked_body_iter()
                return up
            except Exception as e:
                release_node()
                last_err = e
                stats["errors"] += 1
                acct["errors"] += 1
                cooldown_global(node, 60)
                # 连接失败/超时也按模型冷却，避免同一模型反复撞死节点
                cooldown_model_node(model, node, 300)
                with slots_lock:
                    slots[sidx]["last_error"] = time.time()
                    slots[sidx]["probe_failures"] = \
                        slots[sidx].get("probe_failures", 0) + 1
                    failures = slots[sidx]["probe_failures"]
                if failures >= PROBE_FAILURES:
                    set_slot_state(sidx, ST_DOWN, "connection_error", str(e)[:50])
                log("[!] %s(%s) 节点 %s 连接失败: %s → 切换 (attempt %d)"
                    % (acct["name"], slot["mode"], node, str(e)[:50], attempt))
                try:
                    switch_slot_if_current(sidx, node, tried, "(连接失败)", model=model)
                except Exception:
                    pass
                if total_attempts >= max_attempts:
                    break
                continue
        log("[!] %s 号 槽位 %d 节点耗尽，故障转移到其他号" % (acct["name"], sidx))
        if total_attempts >= max_attempts:
            break

    if last_status == 429:
        err = {"error": {"message": "上游模型当前限流，请稍后重试"}}
        return Upstream(429, {"content-type": "application/json",
                              "retry-after": "10"},
                        iter([json.dumps(err, ensure_ascii=False).encode()]))
    err = {"error": {"message": "上游请求失败: %s" % (last_err or "重试耗尽")}}
    log("[!!] %s 号 所有 %d 个号均失败" % (acct["name"], TOTAL))
    return Upstream(502, {"content-type": "application/json"},
                    iter([json.dumps(err).encode()]))


def next_account(model=None):
    """Pick the next account for a request.

    激进延迟加权调度：越快被选中概率越高。
    - 权重 = (1000/ms)^3，延迟差 2 倍 → 选中概率差 8 倍，快槽位碾压慢的
    - 保留 10% 探索概率在全部可用槽位中随机选，避免慢的/新槽位饿死
      （防止某 IP 一直不被用，也保证未知延迟的槽位有机会被实测）
    - 未测过延迟的槽位：V4 假设快(600ms)、V6 假设慢(3000ms)
    - 跳过 down 和当前节点在冷却中的槽位
    - 地区敏感模型（如 muse-spark 贡献者模型）：跳过 V6 直连槽位
      （V6 是中国 IP 慢且常地区受限），只用 V4 代理槽位
    """
    global account_cursor
    now = time.time()
    prefer_v4 = bool(model) and "contributor" in str(model).lower()
    with schedule_lock, slots_lock:
        available = []
        weighted = []
        for i, s in enumerate(slots):
            if s["state"] == ST_DOWN:
                continue
            if prefer_v4 and i < V6_ACCOUNTS:
                continue
            node = s["current_node"]
            if node and node_in_cooldown(node):
                continue
            if node and model_node_in_cooldown(str(model or "").lower(), node):
                continue
            available.append(i)
            # 延迟是主要偏好：快节点明显优先（延迟差 2 倍 → 权重差 4 倍），
            # 但配合并发惩罚，避免最快出口垄断整个请求池。
            nl = get_node_latency(node)
            if nl and nl > 0:
                base = max(nl, 100)
            else:
                # 未测过的节点保守估计为慢（2000ms），让已知快节点优先
                base = 2000 if i >= V6_ACCOUNTS else 3000
            # 并发惩罚：节点 in-flight 越多权重越低，避免多并发打同一个 IP
            infl = get_node_inflight(node)
            w = (1000.0 / base) ** 2
            w /= (1 + infl + slot_inflight[i]) ** 2
            weighted.append((i, w))
        if not available:
            fallback = range(V6_ACCOUNTS, TOTAL) if prefer_v4 else range(TOTAL)
            chosen = min(fallback, key=lambda i: slot_inflight[i])
        # 10% 探索：在全部可用槽位里均匀随机（给慢的/新的机会）
        elif random.random() < 0.10:
            chosen = random.choice(available)
        else:
            total = sum(w for _, w in weighted)
            r = random.random() * total
            chosen = weighted[-1][0]
            for i, w in weighted:
                r -= w
                if r <= 0:
                    chosen = i
                    break
        slot_inflight[chosen] += 1
        return chosen


def release_account(account_idx):
    with schedule_lock:
        slot_inflight[account_idx] = max(0, slot_inflight[account_idx] - 1)


# ── HTTP server ───────────────────────────────────────────────────

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("access-control-allow-origin", "*")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _check_auth(self):
        if not GATE_KEY:
            return True
        auth = self.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        if verify_key(token):
            return True
        log("拒绝未授权访问: %s %s from %s" % (self.command, self.path, self.client_address[0]))
        self._json(401, {"error": {"message": "未授权"}})
        return False

    def _read_body(self):
        length = int(self.headers.get("content-length", 0) or 0)
        if length > MAX_BODY_BYTES:
            self._json(413, {"error": {"message": "请求体过大"}})
            return None
        return self.rfile.read(length).decode("utf-8", "replace") if length else ""

    def _serve_static(self, pathname):
        if pathname in ("", "/"):
            pathname = "/index.html"
        safe = os.path.normpath(pathname.lstrip("/"))
        fp = os.path.join(PUBLIC_DIR, safe)
        if not fp.startswith(PUBLIC_DIR):
            return False
        if not os.path.isfile(fp):
            return False
        ext = os.path.splitext(fp)[1].lower()
        ctype = MIME_TYPES.get(ext, "application/octet-stream")
        with open(fp, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(data)))
        self.send_header("cache-control", "no-cache")
        self.end_headers()
        self.wfile.write(data)
        return True

    def do_GET(self):
        self._route()

    def do_POST(self):
        self._route()

    def do_PUT(self):
        self._route()

    def do_DELETE(self):
        self._route()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("access-control-allow-origin", "*")
        self.send_header("access-control-allow-methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.send_header("access-control-allow-headers", "*")
        self.end_headers()

    def _route(self):
        parsed = urllib.parse.urlparse(self.path)
        pathname = parsed.path
        method = self.command
        ip = self.client_address[0]

        # ── public (no auth) ─────────────────────────────────────
        if pathname == "/ping":
            self._json(200, {"ok": True})
            return
        if pathname == "/" or pathname.startswith("/static/"):
            if self._serve_static("/" if pathname == "/" else pathname.replace("/static/", "/", 1)):
                return
        if pathname == "/index.html":
            if self._serve_static("/index.html"):
                return
        # public, sanitized status snapshot (frontend polls this);
        # with a valid key it returns the full internal view
        if pathname == "/api/status" and method == "GET":
            auth = self.headers.get("authorization", "")
            token = auth[7:] if auth.lower().startswith("bearer ") else ""
            full = bool(GATE_KEY) and verify_key(token)
            self._api_status(public=not full)
            return

        # ── protected endpoints (require GATE_KEY) ──────────────
        if method == "OPTIONS":
            self.send_response(204)
            self.send_header("access-control-allow-origin", "*")
            self.send_header("access-control-allow-methods", "GET,POST,PUT,DELETE,OPTIONS")
            self.send_header("access-control-allow-headers", "*")
            self.end_headers()
            return
        if not self._check_auth():
            return

        if pathname == "/api/accounts" and method == "GET":
            self._json(200, {"accounts": accounts, "slots": slots,
                             "upstream_auth": UPSTREAM_AUTH,
                             "v6_addrs": v6_addrs()})
            return
        if pathname == "/api/nodes" and method == "GET":
            with node_health_lock:
                health = dict(node_health)
            with egress_ip_lock:
                egress = dict(egress_ip)
            self._json(200, {"nodes": health, "egress": egress})
            return
        if pathname == "/api/scheduler" and method == "GET":
            with node_inflight_lock:
                inflight = dict(node_inflight)
            with schedule_lock:
                slot_load = list(slot_inflight)
            self._json(200, {"node_inflight": inflight,
                             "slot_inflight": slot_load,
                             "backoff_ms": 0})
            return
        if pathname == "/api/logs" and method == "GET":
            self._json(200, {"logs": recent_logs[-200:]})
            return
        if pathname == "/api/audit" and method == "GET":
            self._json(200, {"audit": audit_log[-300:]})
            return
        if pathname == "/api/models" and method == "GET":
            with models_lock:
                self._json(200, {"data": cached_models, "cachedAt": cached_models_time})
            return
        if pathname == "/api/models/refresh" and method == "POST":
            threading.Thread(target=fetch_models, daemon=True).start()
            self._json(200, {"success": True, "msg": "刷新中"})
            return
        if pathname == "/api/probe" and method == "POST":
            threading.Thread(target=probe_all_slots, daemon=True).start()
            self._json(200, {"success": True, "msg": "出口探测中"})
            return
        if pathname == "/api/switch" and method == "POST":
            raw = self._read_body()
            if raw is None:
                return
            try:
                body = json.loads(raw) if raw else {}
            except Exception:
                body = {}
            slot_i = int(body.get("slot", 0))
            if 0 <= slot_i < TOTAL:
                ok = switch_slot(slot_i, reason="(手动)")
                self._json(200, {"success": ok, "node": slots[slot_i]["current_node"]})
            else:
                self._json(400, {"error": "slot 无效"})
            return
        if pathname == "/api/rebalance" and method == "POST":
            for a in accounts:
                switch_slot(a["slot_idx"], reason="(重平衡)")
            self._json(200, {"success": True})
            return
        if pathname == "/api/v6/refresh" and method == "POST":
            threading.Thread(target=refresh_upstream_v6, daemon=True).start()
            self._json(200, {"success": True})
            return

        if pathname.startswith("/v1/") or pathname.startswith("/openai/v1/"):
            self._proxy_v1()
            return

        if pathname == "/favicon.ico":
            self.send_response(404)
            self.end_headers()
            return

        self._json(404, {"error": {"message": "not found"}})

    def _api_status(self, public=False):
        with slots_lock:
            slot_data = [dict(s) for s in slots]
            account_data = [dict(a) for a in accounts]
        with models_lock:
            nmodels = len(cached_models)
        with timeline_lock:
            tl = list(timeline[-200:])
        global LAST_RECONCILE
        LAST_RECONCILE = int(time.time() * 1000)

        # 只保留今天的动态（今天 00:00:00 起）
        today_ms = int(time.mktime(time.strptime(
            time.strftime("%Y-%m-%d"), "%Y-%m-%d")) * 1000)
        tl = [e for e in tl if e.get("at", 0) >= today_ms]

        # overall aggregation
        states = [s.get("state", ST_UNKNOWN) for s in slot_data]
        if not slot_data:
            overall = ST_UNKNOWN
        elif any(s == ST_DOWN for s in states):
            overall = ST_DOWN
        elif any(s == ST_COOLDOWN for s in states):
            overall = ST_COOLDOWN
        elif all(s == ST_OPERATIONAL for s in states):
            overall = ST_OPERATIONAL
        else:
            overall = ST_UNKNOWN

        # models[] = one entry per account (component row on the status page)
        models = []
        for a in account_data:
            s = slot_data[a["slot_idx"]]
            m = {
                "model": a["name"],
                "state": s.get("state", ST_UNKNOWN),
                "since": int(s.get("since", time.time()) * 1000),
                "latency_ms": s["latency_ms"],
                "switches": s["switched"],
                "requests": a["requests"],
                "success": a["success"],
                "rateLimited": a["rateLimited"],
                "errors": a["errors"],
                "last_429": int(s.get("last_429", 0) * 1000),
            }
            if not public:
                m["mode"] = s["mode"]
                m["exit"] = s["current_node"]
            models.append(m)

        if public:
            # public page shows each of the 10 slots with its OWN state
            # (sanitized: no node names / modes / IPs / internal config)
            slot_rows = []
            name_to_idx = {a["name"]: a["index"] for a in account_data}
            for s in slot_data:
                # most recent error event for THIS slot
                last_err = ""
                for e in reversed(tl):
                    if e.get("model") == accounts[s["index"]]["name"] and \
                            e["reason"] in ("rate_limited", "server_error",
                                            "connection_error", "probe_fail"):
                        last_err = e["reason"]
                        break
                slot_rows.append({
                    "slot": s["index"] + 1,  # 1-based, neutral
                    "state": s.get("state", ST_UNKNOWN),
                    "since": int(s.get("since", time.time()) * 1000),
                    "latency_ms": s["latency_ms"],
                    "switches": s["switched"],
                    "last_429": int(s.get("last_429", 0) * 1000),
                    "last_error": last_err,
                })

            # available free models (for display only), sorted alphabetically
            # with big-pickle (hidden free model) placed last
            with models_lock:
                free_ids = sorted(
                    [str(x.get("id", "")) for x in cached_models
                     if str(x.get("id", "")).endswith("-free")
                     or str(x.get("id", "")) == "big-pickle"])
                free_ids = [m for m in free_ids if m != "big-pickle"] + \
                           [m for m in free_ids if m == "big-pickle"]

            # public timeline: strip node-name detail (info leak), keep slot #
            tl = [{"at": e["at"], "slot": name_to_idx.get(e.get("model", ""), 0) + 1,
                   "from": e["from"], "to": e["to"],
                   "reason": e["reason"]} for e in tl]

            # per-model token usage (sorted by tokens desc)
            with token_lock:
                per_model = [{"model": k, **v} for k, v in token_by_model.items()]
            per_model.sort(key=lambda x: -x["tokens"])
            token_summary = {
                "total": stats["tokens"],
                "prompt": stats["prompt_tokens"],
                "completion": stats["completion_tokens"],
                "by_model": per_model,
            }

        self._json(200, {
            "overall": overall,
            "interval": 0,
            "last_reconcile": LAST_RECONCILE,
            "slots": slot_rows if public else slot_data,
            "free_models": free_ids if public else [str(x.get("id", "")) for x in cached_models],
            "timeline": tl,
            "uptime": time.time() - START_TIME,
            "stats": stats,
            "tokens": token_summary if public else {
                "total": stats["tokens"],
                "prompt": stats["prompt_tokens"],
                "completion": stats["completion_tokens"],
            },
            "modelsCount": nmodels,
            "upstream": UPSTREAM,
        } if public else {
            "overall": overall,
            "interval": 0,
            "last_reconcile": LAST_RECONCILE,
            "models": models,
            "timeline": tl,
            "uptime": time.time() - START_TIME,
            "stats": stats,
            "slots": slot_data,
            "accounts": account_data,
            "modelsCount": nmodels,
            "upstream": UPSTREAM,
            "upstreamV6": list(UPSTREAM_V6),
            "config": {"total": TOTAL, "v6": V6_ACCOUNTS, "v4": V4_ACCOUNTS,
                       "proxyStart": PROXY_START, "apiStart": API_START,
                       "maxRetries": MAX_RETRIES, "gateKey": bool(GATE_KEY)},
        })

    def _proxy_v1(self):
        # auth already enforced in _route; keep as defense-in-depth
        path = self.path.split("?")[0]
        if path.startswith("/openai/v1/"):
            path = path[len("/openai"):]
        inbound_path = path
        body = self._read_body() if self.command in ("POST", "PUT") else ""
        if body is None:
            return  # 413 already sent

        is_completions = path.endswith("/chat/completions")
        is_responses = path.endswith("/responses")
        stream = False
        if (is_completions or is_responses) and body:
            try:
                stream = bool(json.loads(body).get("stream"))
            except Exception:
                stream = False
            if is_completions:
                body = append_free_suffix(body)
            # contributor 类免费模型需要 end-user identifier
            body = inject_safety_id(body)

        try:
            req_model = (json.loads(body) or {}).get("model", "")
        except Exception:
            req_model = ""
        if ZEN_MODELS and req_model not in ZEN_MODELS and req_model not in ZEN_MODEL_MAP:
            self._json(400, {"error": {"message": f"model \"{req_model}\" is not allowed by this proxy"}})
            return
        mapped_model = apply_model_map(req_model, ZEN_MODEL_MAP) if 'apply_model_map' in globals() and apply_model_map else req_model
        if mapped_model != req_model:
            try:
                p = json.loads(body) if body else {}
                p["model"] = mapped_model
                body = json.dumps(p)
            except Exception:
                pass
            req_model = mapped_model
        outbound_proto = None
        response_conversion = ""
        if resolve_outbound_protocol:
            outbound_proto = resolve_outbound_protocol(req_model, ZEN_MODEL_ENDPOINTS)
            if outbound_proto == "responses" and path == "/v1/chat/completions":
                path = "/v1/responses"
                body = chat_to_responses_body(body)
            elif outbound_proto == "chat" and path == "/v1/responses":
                path = "/v1/chat/completions"
                body = responses_to_chat_body(body)
                response_conversion = "chat_to_responses"
            elif outbound_proto == "messages" and path not in ("/v1/messages",):
                path = "/v1/messages"
                body = chat_to_messages_body(body)
        contributor = "contributor" in str(req_model).lower()
        if contributor:
            acquire_contributor_gate()
        # oc-fwd FallbackState: if model is keyed, inject a random API key
        orig_auth = None
        if fallback_state and fallback_state.is_keyed(req_model) and api_keys_cache:
            orig_auth = UPSTREAM_AUTH
            import os as _os2
            globals()["UPSTREAM_AUTH"] = "Bearer " + random.choice(api_keys_cache)
        acct_idx = None
        try:
            acct_idx = next_account(req_model)
            acct = accounts[acct_idx]
            acct["requests"] += 1
            req_headers = build_upstream_headers(self.headers, body)
            t0 = time.time()
            if stream:
                self._proxy_stream(path, self.command, req_headers, body, acct,
                                   response_conversion, req_model)
            else:
                self._proxy_plain(path, self.command, req_headers, body, acct, t0,
                                  response_conversion, req_model)
            # probe anon recovery when keyed
            if fallback_state and fallback_state.is_keyed(req_model):
                if fallback_state.try_probe_recover(req_model):
                    try:
                        s, _ = simple_probe(acct["slot_idx"], "/v1/models")
                        if s == 200:
                            fallback_state.recover(req_model)
                            log(f"[key] 模型 {req_model} 匿名已恢复，切回匿名")
                    except Exception:
                        pass
        finally:
            if orig_auth is not None:
                globals()["UPSTREAM_AUTH"] = orig_auth
            if acct_idx is not None:
                release_account(acct_idx)
            if contributor:
                release_contributor_gate()

    def _proxy_plain(self, path, method, headers, body, acct, t0,
                     response_conversion="", client_model=""):
        stats["total"] += 1
        up = dispatch(acct["index"], path, method, headers, body, stream=False)
        raw = b"".join(up.body_iter).decode("utf-8", "replace")
        latency = int((time.time() - t0) * 1000)
        stats["success"] += 1 if up.status < 400 else 0
        acct["success"] += 1 if up.status < 400 else 0

        model = ""
        pt = ct = tt = 0
        resp_body = raw
        ctype = up.headers.get("content-type", "application/json")
        if response_conversion == "chat_to_responses" and up.status == 200:
            try:
                resp_body = json.dumps(
                    chat_completion_to_responses(raw, client_model),
                    ensure_ascii=False)
                ctype = "application/json"
            except Exception:
                pass
        elif path == "/v1/models" and up.status == 200:
            try:
                d = json.loads(raw)
                all_m = d.get("data", d.get("models", []))
                free_m = [m for m in all_m
                          if str(m.get("id", "")).endswith("-free")
                          or m.get("id") == "big-pickle"]
                d["data"] = free_m
                d["models"] = free_m
                resp_body = json.dumps(d)
                with models_lock:
                    cached_models = all_m
            except Exception:
                pass
        else:
            model, pt, ct, tt = extract_tokens(raw)
            if tt:
                acct["tokens"] += tt
                record_tokens(model, pt, ct, tt)

        audit(up.status, latency, model, path, pt, ct, tt)
        data = resp_body.encode()
        self.send_response(up.status)
        self.send_header("content-type", ctype)
        if up.headers.get("retry-after"):
            self.send_header("retry-after", up.headers["retry-after"])
        self.send_header("content-length", str(len(data)))
        self.send_header("access-control-allow-origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _proxy_stream(self, path, method, headers, body, acct,
                      response_conversion="", client_model=""):
        stats["total"] += 1
        up = dispatch(acct["index"], path, method, headers, body, stream=True)
        stats["success"] += 1 if up.status < 400 else 0
        acct["success"] += 1 if up.status < 400 else 0

        self.send_response(up.status)
        ctype = up.headers.get("content-type", "text/event-stream")
        if "text/event-stream" not in ctype and up.status == 200:
            ctype = "text/event-stream"
        self.send_header("content-type", ctype)
        self.send_header("cache-control", "no-cache")
        self.send_header("access-control-allow-origin", "*")
        self.send_header("connection", "close")
        self.close_connection = True
        if up.status >= 400:
            data = b"".join(up.body_iter)
            self.send_header("content-length", str(len(data)))
            if up.headers.get("retry-after"):
                self.send_header("retry-after", up.headers["retry-after"])
            self.end_headers()
            self.wfile.write(data)
            audit(up.status, 0, "", path)
            return
        if response_conversion == "chat_to_responses":
            # Conversion requests use a non-stream Chat upstream response.
            # Emit canonical Responses SSE events for streaming clients.
            raw = b"".join(up.body_iter).decode("utf-8", "replace")
            self.end_headers()
            try:
                response = chat_completion_to_responses(raw, client_model)
                events = []
                for item in response.get("output", []):
                    events.append(("response.output_item.added", {
                        "type": "response.output_item.added", "item": item}))
                    events.append(("response.output_item.done", {
                        "type": "response.output_item.done", "item": item}))
                events.append(("response.completed", {
                    "type": "response.completed", "response": response}))
                for event, payload in events:
                    data = ("event: %s\ndata: %s\n\n" %
                            (event, json.dumps(payload, ensure_ascii=False))).encode()
                    self.wfile.write(data)
                    self.wfile.flush()
                audit(up.status, 0, client_model, path)
            except Exception as e:
                log("工具响应转换失败: %s" % str(e)[:80])
            return
        self.end_headers()
        model = ""
        pt = ct = tt = 0
        buf_parts = []   # 累积所有 chunk，流结束后统一解析（避免 TCP 切碎 usage）
        client_alive = True
        try:
            for chunk in up.body_iter:
                if client_alive:
                    try:
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        client_alive = False
                # 即使客户端断开也要继续读完上游，拿到结尾的 usage 事件
                buf_parts.append(chunk)
        except Exception:
            pass
        # 流结束后统一解析，提取 model + usage（兼容 SSE / JSON / responses 嵌套格式）
        model, pt, ct, tt = extract_tokens(
            b"".join(buf_parts).decode("utf-8", "replace"))
        if tt:
            acct["tokens"] += tt
            record_tokens(model, pt, ct, tt)
        audit(up.status, 0, model, path, pt, ct, tt)
        try:
            self.wfile.flush()
        except Exception:
            pass


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)
    key = ensure_gate_key()
    _init_oc_fwd_state()
    if not load_stats():
        # 首次运行：从 audit.jsonl 回填历史用量，避免重启归零
        try:
            rebuilt_stats = {"total": 0, "success": 0, "tokens": 0,
                             "prompt_tokens": 0, "completion_tokens": 0}
            rebuilt_by_model = {}
            with open(AUDIT_FILE, encoding="utf-8") as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    if e.get("status", 0) < 500:
                        rebuilt_stats["total"] += 1
                        if e.get("status", 0) < 400:
                            rebuilt_stats["success"] += 1
                    pt = int(e.get("pt", 0) or 0)
                    ct = int(e.get("ct", 0) or 0)
                    tt = int(e.get("tt", 0) or 0) or (pt + ct)
                    if tt:
                        rebuilt_stats["tokens"] += tt
                        rebuilt_stats["prompt_tokens"] += pt
                        rebuilt_stats["completion_tokens"] += ct
                        m = e.get("model") or "unknown"
                        cur = rebuilt_by_model.setdefault(
                            m, {"tokens": 0, "prompt_tokens": 0,
                                "completion_tokens": 0, "req": 0})
                        cur["tokens"] += tt
                        cur["prompt_tokens"] += pt
                        cur["completion_tokens"] += ct
                        cur["req"] += 1
            for k in ("total", "success", "tokens", "prompt_tokens", "completion_tokens"):
                stats[k] = rebuilt_stats[k]
            with token_lock:
                token_by_model.clear()
                token_by_model.update(rebuilt_by_model)
            save_stats()
            log(f"已从审计回填用量: {rebuilt_stats['tokens']} tok / {rebuilt_stats['total']} 次")
        except OSError:
            pass
    init_slots()
    load_timeline()
    refresh_upstream_v6()
    load_models_cache()
    if not cached_models:
        threading.Thread(target=fetch_models, daemon=True).start()

    def dns_loop():
        while True:
            time.sleep(V6_DOH_INTERVAL)
            refresh_upstream_v6()
    threading.Thread(target=dns_loop, daemon=True).start()

    threading.Thread(target=probe_loop, daemon=True).start()
    threading.Thread(target=probe_all_slots, daemon=True).start()
    threading.Thread(target=rank_probe_loop, daemon=True).start()
    threading.Thread(target=models_refresh_loop, daemon=True).start()

    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    log("opencode-gate 启动: http://0.0.0.0:%d 上游 %s" % (PORT, UPSTREAM))
    log("访问密钥: %s  (访问 /v1/* 与 /api/* 需 Authorization: Bearer <key>)" % key)
    log("检测方式: 被动式（仅真实请求时更新状态，不主动探测）; 请求体上限 %d 字节"
        % MAX_BODY_BYTES)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
