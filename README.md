# opencode-zen-free-gate

`opencode.ai/zen` 免费模型反代网关。把单账号并发与限流分散到多个**独立出口 IP** 上，对上游无感，并对外提供 OpenAI 兼容 API。

## 能力

- **智能网关**：统一 `/v1/*` OpenAI 兼容入口（`/v1/chat/completions`、`/v1/responses`、`/v1/models`）。
- **智能代理**：出口由 `slots/` 下的 `mihomo` 实例承载，`mihomo` 进程以 `root` 启动并设置 `routing-mark`（`FW_MARK`，默认 `0xca7`），通过 `ip rule fwmark lookup main` 绕过系统 `clash TUN`，直连机场节点真实 IP。
- **智能调度**：按 `opencode.ai` 实测延迟排序（`node_latency` EMA），`upstream_circuit` 熔断 + 按出口 IP 并发惩罚避免单 IP 打满，订阅后台测速自动更新可用节点。
- **自动配额切换**：配额按出口 IP 分配，`429` 自动切换到**不同出口 IP 的可用节点**并重试，多并发请求分散到不同出口。

## 目录与约定

- `gate.py`：网关主程序（转发、调度、熔断、状态 API）。中文状态页，不显示 `V4/V6/IP/"几号"`。
- `config.env`：运行时配置（`V6_ACCOUNTS/V4_ACCOUNTS/SLOTS/PORT/FW_MARK/UPSTREAM_AUTH/ZEN_*` 等），**不进仓库**，参考 `config.env.example`。
- `data/`：运行时数据与订阅缓存（如 `nodes.json`、`node_ips.json`、`sub*.yaml`、`audit.jsonl`、`stats.json`），**不进仓库**。
- `slots/`：`slots_gen.py` 生成的 `mihomo` 槽位配置与运行时 `mihomo` 进程，**不进仓库**。
- `logs/`：运行时日志，**不进仓库**。

## 快速开始

1. **机场订阅**：把订阅 URL 写入 `config.env` 或直接更新 `data/sub*.yaml`，推荐多订阅合并。例如本仓库当前为 4 订阅聚合。
2. **生成与启动**：
   - `sudo systemctl start opencode-refresh.service` 刷新订阅并重启 `slots`（`refresh_sub.sh` 会 `resolve_node_ips.py` → `slots_gen.py`）。不要以普通用户直接跑 `refresh_sub.sh`，否则 `fwmark` 会 `operation not permitted`。
   - `sudo systemctl restart opencode-gate.service` 启动网关（`boot.sh` 读 `config.env`）。
3. **验证**：`curl http://127.0.0.1:13339/ping`；状态页 `http://127.0.0.1:13339/`。

## 机场代理落地

- **订阅来源**：`refresh_sub.sh` 内的 `SUB_URL_*`，拉取失败回退到 `clashctl/resources/profiles/*.yaml`。
- **IP 解析**：`resolve_node_ips.py` 通过 `Cloudflare DoH` 经本机代理解析节点 `server` 为真实 IP，写入 `data/node_ips.json`。
- **槽位生成**：`slots_gen.py` 合并订阅并生成 `SLOTS` 个 `mihomo` 槽位（每个 `mixed-port 10800+i` / `controller 10990+i`），均标记 `routing-mark=FW_MARK`。
- **默认端口与标记**：`config.env` 中 `V4` 槽固定 `10800` 起，控制器 `10990` 起，`fwmark 0xca7`。
- **迁移/复用**：迁移机器时只需复制 `config.env` 里的订阅 URL 与 `data/sub*.yaml`，运行 `opencode-refresh.service` 即可重建 `slots/`。
- **系统 clash 隔离**：主 `clashctl` 进程 `mihomo -d /home/lzy/clashctl/resources -f runtime.yaml` 监听 `7890/7891`，网关 `slots/slot-*` 使用独立配置目录，不共享状态。

## 参考与致谢

- 参考 [AS214933/oc-fwd](https://github.com/AS214933/oc-fwd) 的重试/熔断与限流设计，网关侧保留按出口 IP 自动切换的配额调度。
