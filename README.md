# RDP On-Demand Proxy

轻量级 Python TCP 代理，面向 Windows RDP 按需启停场景。内置腾讯云 CVM、阿里云 ECS、Telegram/钉钉/企业微信通知，支持 Docker 部署。

## 主要能力

- 监听 RDP 端口并保持 TCP 连接不立即断开
- 一次性验证链接放行（默认 5 分钟有效）
- 自动检查 CVM 状态，按需开机并轮询等待
- 支持阿里云 ECS 状态查询、开机、关机
- 云主机就绪后执行 RDP TCP 透明双向转发
- 空闲超时自动关机，支持 `STOP_CHARGING`
- 结构化 JSON 日志，记录连接、状态变化、验证、转发、关机
- 单目标单会话并发控制（多余连接拒绝）

## 项目结构

- `run.py`: 启动入口
- `rdp_proxy/app.py`: 进程入口与信号处理
- `rdp_proxy/proxy.py`: 核心代理流程、开机等待、转发、空闲关机
- `rdp_proxy/verification.py`: 一次性验证 HTTP 服务
- `rdp_proxy/notifications.py`: Telegram / 钉钉 / 企业微信通知
- `rdp_proxy/cloud/tencent_cvm.py`: 腾讯云 CVM 实现
- `config.example.json`: 配置模板

## 快速开始

### 1. 准备配置

复制 YAML 模板并填写：

```bash
cp config.example.yml config.yml
```

必须配置：

- `server.external_verify_base_url`: 可被你点击访问的公网地址
- `notifications.telegram.bot_token`
- `notifications.telegram.chat_id`
- `targets[].cloud.secret_id`
- `targets[].cloud.secret_key`
- `targets[].cloud.region`
- `targets[].cloud.instance_id`
- `targets[].target_ip`

### 2. 安装依赖并启动

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py --config config.yml
```

### 3. 连接流程

1. 使用 `mstsc` 连接代理 IP:端口
2. 服务保持连接并发送 Telegram 验证消息
3. 点击一次性链接放行
4. 服务按需开机并在就绪后开始 RDP 透明转发
5. 断开后进入空闲计时，超时自动关机

## Docker 部署

### 构建

```bash
docker build -t rdp-on-demand-proxy .
```

### 运行

```bash
docker run -d --name rdp-proxy \
  -p 3389:3389 \
  -p 8080:8080 \
  -v $(pwd)/config.yml:/app/config.yml:ro \
  --restart unless-stopped \
  rdp-on-demand-proxy
```

## Linux 后台运行与开机自启

### systemd 示例

`/etc/systemd/system/rdp-proxy.service`

```ini
[Unit]
Description=RDP On-Demand Proxy
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/rdp-proxy
ExecStart=/opt/rdp-proxy/.venv/bin/python /opt/rdp-proxy/run.py --config /opt/rdp-proxy/config.yml
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

启用：

```bash
sudo systemctl daemon-reload
sudo systemctl enable rdp-proxy
sudo systemctl start rdp-proxy
sudo systemctl status rdp-proxy
```

## 配置说明

核心字段：

- `targets[].listen_port`: 代理监听端口
- `targets[].target_rdp_port`: 目标 RDP 端口（默认 3389）
- `targets[].startup_timeout_seconds`: 启动等待超时（默认 60）
- `targets[].startup_poll_seconds`: 状态轮询间隔（默认 5）
- `targets[].idle_shutdown_minutes`: 空闲关机分钟数（默认 10）
- `targets[].cloud`: 设为空对象 `{}`（或省略）时跳过云状态检查与自动关机，适合仅调试代理/通知/授权
- `targets[].cloud.stop_mode`: 腾讯云停机模式，建议 `STOP_CHARGING`
- `targets[].cloud.provider`: `tencent_cvm` 或 `aliyun_ecs`
- `security.wait_for_verification_seconds`: 等待验证时间
- `security.forwarding_slot_wait_seconds`: 验证通过后等待转发槽位时间（默认 120）。当目标已有会话占用时，新连接会在该时间内排队等待放通。
- `security.verification_notify_delay_seconds`: 验证通知延迟窗口（默认 2 秒）。连接在该窗口内断开时，不发送连接请求通知，可抑制扫描噪声。
- `security.max_pending_verification_connections`: 待授权连接池总上限（默认 5）。
- `security.max_pending_verifications_per_ip`: 同源 IP 待授权并发上限（默认 1）。
- `security.approved_ip_reuse_seconds`: 某 IP 授权成功后，N 秒内新连接免二次授权（默认 60）。
- `security.per_ip_connection_rate_window_seconds`: 同源 IP 新建连接限流窗口秒数（默认 5）。
- `security.per_ip_connection_rate_limit`: 同源 IP 每个窗口允许的新建连接数（默认 4）。超出后连接会等待到下一个窗口再继续。
- `notifications.telegram.insecure_skip_verify`: 仅在本机证书链异常时用于调试，`true` 会跳过 Telegram HTTPS 证书校验
- `notifications.dingtalk.secret`: 钉钉加签密钥，开启机器人加签时必填

通知策略：

- 所有 `enabled: true` 的通知通道都会并行尝试发送，不会只发一个通道。
- RDP 连接验证仍按每次连接发送，不会因短时间重连而跳过验证。
- 连接验证通知会在 `security.verification_notify_delay_seconds` 观察窗口后发送；若连接很快断开，则不发送通知。
- 如果客户端在等待授权阶段已经断开，该次验证 token 会被立即作废；点击旧链接会提示失效，避免“无意义授权”影响后续连接。
- Telegram 的“连接验证请求”消息会在验证链接过期后自动尝试删除（默认 5 分钟，与 `security.token_ttl_seconds` 一致）。
- Telegram 的“连接断开提醒”不会定时删除；当下一次连接真正建立转发后，会自动尝试删除上一条断开提醒。
- 断开提醒采用 30 秒观察窗口：若断开后 30 秒内出现新连接，会抑制上一条断开提醒，减少“密码阶段二次建连”噪声。
- 通知中的来源 IP 默认脱敏为“IP 尾号”。
- 可选开启 `notifications.geoip.enabled` 获取来源城市 + ASN 信息，推荐离线模式：`notifications.geoip.mode=offline`。
- 离线模式需要本地数据库文件：`notifications.geoip.city_db_path`（GeoLite2-City.mmdb）与 `notifications.geoip.asn_db_path`（GeoLite2-ASN.mmdb）。
- 兼容在线模式：`notifications.geoip.mode=online` 时仍支持 `endpoint_templates` 回退查询。
- 保持向后兼容：如果仍使用单个 `endpoint_template` 字段，也可正常工作。
- 本项目 Docker 镜像内置 GeoLite2 数据库，无需自行下载即可直接使用。
- 若需手动更新数据库，免费注册 MaxMind 账号后，在 `config.yml` 的 `notifications.geoip.update` 填入凭据，
  然后运行：`python scripts/update_geoip.py --config config.yml`

连接噪声识别策略：

- 对新建 TCP 连接会先做 RDP 握手预判：仅当首包符合典型 RDP TPKT + X.224 特征时，才进入验证流程。
- 常见扫描行为（仅 TCP 探测、HTTP/TLS 非 RDP 探测、连上即断）会被直接丢弃，不发送“连接请求通知”。
- “连接未真正成功”的断开（例如：未授权、握手后极短时长且流量很小、密码错误导致快速断开）会被断开通知资格过滤抑制。

云开关机重试策略：

- 对开机/关机请求，遇到网络请求异常或云端状态异常会执行指数退避重试。
- 默认最多重试 3 次（总尝试 4 次），退避间隔为 5s、10s、20s，总耗时约 1 分钟。
- 如判断为密钥不可用/鉴权失败类错误，不执行重试并直接失败。
- 开关机最终结果（成功/失败）会通过所有已启用 IM 通道发送通知。
- 以下状态按幂等成功处理：
  - 对已运行/启动中的实例执行开机请求
  - 对已停止/停止中的实例执行关机请求
  - 当实例处于与目标动作冲突的过渡态（如 STOPPING 时请求 START），会指数退避等待状态变化后再重试。

## 联调自检

通知自检（会向所有启用通道发测试消息）：

```bash
python run.py --config config.yml --self-check notifications
```

云状态自检（只查状态，不变更实例）：

```bash
python run.py --config config.yml --self-check cloud --cloud-check-operation status
```

云开机/关机触发自检（会执行真实动作）：

```bash
python run.py --config config.yml --self-check cloud --cloud-check-operation start
python run.py --config config.yml --self-check cloud --cloud-check-operation stop
```

说明：

- `--self-check cloud` 的 `start/stop` 已复用运行时的状态感知与指数退避策略。
- 幂等状态会直接判定成功（如对已停止实例执行 stop）。
- 若处于冲突过渡态（如 STOPPING 时请求 start），会等待状态变化后重试。
- 自检最终结果同样会通过所有已启用 IM 通道通知。

排查“正在配置远程会话”建议：

- 观察日志中的 `Forwarding stats`，确认双向字节是否持续增长。
- 如果 `client_to_upstream_bytes` 增长而 `upstream_to_client_bytes` 长时间不增长，通常是目标主机会话侧问题（系统负载、组策略、用户配置文件、RDS 服务状态）。
- 如果两者都停止增长，优先检查链路中间设备会话保持与目标主机事件日志。

连接审计日志：

- 运行时会生成文本审计日志 `logs/connections-<target_name>.log`。
- 日志覆盖连接建立、验证发送/超时、上游转发开始、连接重置、连接结束等关键阶段，便于排查如 0x904/0x7 这类连接失败。
- 每次连接会分配 `connection_id`，可据此串联整条会话链路。
- 审计日志默认不记录客户端 IP，仅保留 `connection_id`、端口、阶段、原因、字节统计等信息。
- 新增关键事件：
  - `verification_wait_started` / `verification_wait_finished`：授权等待起止与耗时。
  - `connection_aborted`：连接提前结束的阶段与原因（如 `client_disconnected_before_notify_window`、`verification_timeout_deny`、`instance_not_ready`）。
  - `connection_rejected`：连接被并发策略拒绝（如 `single_session_policy`）。
  - `verification_bypassed_recent_approval`：命中“同 IP 近期已授权”直通放行。
  - `rate_limit_wait`：命中同 IP 新建连接限流，等待到下一窗口。
- 建议排障时按同一个 `connection_id` 提供完整事件序列（建议从 `connected` 到 `connection_closed` 全部复制）。
- 是否记录敏感 IP 信息遵循 `server.access_log_details`：关闭时自动去除 `client_ip` 等敏感字段。
- 若不希望在日志中落地来源 IP，建议显式设置 `server.access_log_details: false`。

## 注意事项

- 默认实现为“先验证后开机”，可减少误触发开机成本。
- `verify_http_port` 与 RDP 端口通常应分离；HTTP 验证链接需可公网访问。
- 当前并发策略：允许多个连接同时进入“待授权”阶段（默认最多 5 条、同源 IP 最多 1 条），但同一目标同一时刻只放通 1 条转发会话。
- 当某条连接被授权后，会清理其他不同 IP 的待授权连接，避免恶意占坑导致长期阻塞。
- 如果需要 YAML 配置，请额外安装 `PyYAML`。

## 第三方数据来源

本项目 Docker 镜像包含 GeoLite2 数据库，创建者 MaxMind，来源 [https://www.maxmind.com](https://www.maxmind.com)。  
GeoLite2 数据库依据 [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) 授权发布，分发时须保留本署名。
