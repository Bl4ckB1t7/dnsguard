# DNS Ops Platform

轻量的企业 DNS / BIND / RPZ 运维控制面。它不替代 BIND，也不直接接管 DNS 查询服务，而是负责规则管理、发布、节点状态、审计和回滚。

## 1. 为什么开发这个系统

企业 DNS 运维通常会遇到以下问题：

- RPZ 白名单依赖人工修改主 DNS 文件，容易出现格式错误或漏改。
- 修改后需要重启或手动 reload，发布窗口长，影响面不可见。
- 主节点和辅节点的 RPZ Serial、同步状态缺少统一视图。
- 误删规则后只能依赖备份文件，缺少可操作的版本回滚。
- 多人协作时没有发布任务状态、操作审计和变更原因。
- DNS 节点地址、发布密钥和运行状态混在一起，迁移、备份和恢复困难。
- 传统方案引入数据库、消息队列和复杂微服务后，部署成本又过高。

本项目的目标是：**用一个轻量控制面解决 DNS/RPZ 的日常运维问题，同时保持 BIND 数据面稳定、文件可读、部署简单、可回滚。**

## 2. 设计原则

1. BIND 继续承担 DNS 查询和 RPZ 执行，不把查询链路迁移到 Web 系统。
2. 不使用数据库，规则、节点配置、版本和审计均使用 JSON 文件保存。
3. 发布前生成预览并进行规则校验，发布后记录版本。
4. 当前默认使用 `artifact` 模式，只生成 RPZ 文件；生产环境显式配置 `nsupdate` 后才更新 Primary。
5. 管理 API 默认只监听回环地址，由管理网卡上的前端代理访问。
6. 生产必须启用认证、HTTPS 或可信 HTTPS 反向代理。

## 3. 系统架构

```text
管理员浏览器
    │ 管理网卡:5173
    ▼
Vite Preview / 反向代理
    │ /api → 127.0.0.1:8080
    ▼
Go API 控制面
    ├── Cookie 会话、CSRF、登录限速、审计
    ├── RPZ 规则、预览、版本、回滚、发布任务
    ├── dig / SOA Serial 节点探测
    └── JSON 文件持久化
             │ nsupdate + TSIG
             ▼
        BIND RPZ Primary
             │ NOTIFY / IXFR
             ▼
        BIND Secondary 集群
```

控制面不要求必须部署在 DNS Primary 上。推荐部署在独立管理节点，只需要：

- 能访问 DNS Primary 的 DNS/动态更新端口；
- 能查询 Primary 和 Secondary 的 RPZ SOA；
- 能读取 TSIG key 文件，或通过受保护的密钥挂载提供；
- 管理员能从管理网卡访问前端。

如果发布方式是本机 `rndc` 或本地 RPZ 文件，则控制面才需要与 BIND 位于同一台服务器。

## 4. 一键部署

### 4.1 前置条件

Debian/Ubuntu 示例：

```bash
sudo apt-get update
sudo apt-get install -y git curl nodejs npm golang bind9-dnsutils
```

确认命令存在：

```bash
node --version
npm --version
go version
dig -v
ip link show
```

### 4.2 首次部署

```bash
git clone https://github.com/Bl4ckB1t7/dns-ops-platform.git
cd dns-ops-platform
cp .env.example .env
```

编辑 `.env`，至少修改：

- `BIND_INTERFACE` 或 `WEB_BIND_ADDRESS`；
- `DNS_NODE_CONFIG_FILE`；
- `RPZ_PUBLISH_MODE`、`RPZ_PRIMARY`、`RPZ_PRIMARY_PORT`；
- `RPZ_KEY_FILE`；
- 生产认证和 HTTPS 配置。

启动：

```bash
./scripts/start-dns-ops.sh
```

脚本会自动完成：

1. 从 `.env` 读取配置；
2. 根据 `BIND_INTERFACE` 获取管理网卡 IPv4，或使用 `WEB_BIND_ADDRESS`；
3. 首次运行执行 `npm ci`；
4. 构建 React 前端和 Go API；
5. 创建数据目录；
6. 启动 API 和前端预览服务；
7. 输出访问地址。

停止：

```bash
./scripts/stop-dns-ops.sh
```

旧的 `start-tailscale.sh` 和 `stop-tailscale.sh` 仅保留为兼容入口，新的部署文档统一使用 `start-dns-ops.sh` 和 `stop-dns-ops.sh`。这里的 `BIND_INTERFACE` 只是服务器网卡名，不依赖某个特定网络产品。

日常升级：

```bash
git pull --ff-only
./scripts/start-dns-ops.sh
```

### 4.3 管理网卡配置

默认配置：

```dotenv
BIND_INTERFACE=tailscale0
WEB_BIND_ADDRESS=
```

如果服务器网卡名字就是 `tailscale`：

```dotenv
BIND_INTERFACE=tailscale
WEB_BIND_ADDRESS=
```

也可以直接指定地址，不依赖网卡名称：

```dotenv
WEB_BIND_ADDRESS=192.0.2.20
```

脚本不会调用或依赖 `tailscale` 命令，只通过 `ip` 读取指定网卡地址。

## 5. 配置说明

### 5.1 应用和访问

| 配置 | 示例 | 说明 |
|---|---|---|
| `APP_ENV` | `production` | 生产环境必须设置为 `production` |
| `AUTH_ENABLED` | `true` | 生产必须开启 |
| `AUTH_USERNAME` | `admin` | 管理用户名 |
| `AUTH_PASSWORD` | 强随机密码 | 生产不能使用默认值 |
| `AUTH_SECRET` | 32 位以上随机值 | 会话签名密钥 |
| `AUTH_FILE` | `/etc/dns-ops/auth.json` | 密码哈希文件，可选 |
| `BIND_INTERFACE` | `tailscale0` | 自动获取 Web 绑定地址的网卡名 |
| `WEB_BIND_ADDRESS` | `192.0.2.20` | 直接指定前端监听地址，优先级高于网卡 |
| `WEB_MODE` | `preview` | 生产使用 `preview`，开发可使用 `dev` |
| `LISTEN_ADDR` | `127.0.0.1:8080` | Go API 监听地址，不建议直接暴露 |
| `TLS_CERT_FILE` | `/etc/dns-ops/tls/fullchain.pem` | API 直出 HTTPS 时使用 |
| `TLS_KEY_FILE` | `/etc/dns-ops/tls/privkey.pem` | API 直出 HTTPS 时使用 |
| `TRUST_PROXY_TLS` | `true` | HTTPS 在可信反向代理终止时使用 |

### 5.2 DNS 节点配置

节点配置默认文件：`config/dns-nodes.json`。生产建议放在 `/etc/dns-ops/dns-nodes.json`：

```json
[
  {
    "id": "primary-1",
    "name": "DNS Primary",
    "role": "primary",
    "address": "10.0.0.10:53"
  },
  {
    "id": "secondary-1",
    "name": "DNS Secondary 1",
    "role": "secondary",
    "address": "10.0.0.11:53"
  }
]
```

页面保存节点地址时会原子写入此文件，服务启动时读取此文件。`DNS_NODE_ADDRESSES` 只作为旧版本兼容和首次迁移入口：

```dotenv
DNS_NODE_CONFIG_FILE=/etc/dns-ops/dns-nodes.json
DNS_NODE_ADDRESSES=primary-1=10.0.0.10:53,secondary-1=10.0.0.11:53
```

### 5.3 RPZ 发布配置

安全的测试/预览模式：

```dotenv
RPZ_PUBLISH_MODE=artifact
RPZ_ARTIFACT_FILE=/var/lib/dns-ops/rpz/rpz.local.db
```

生产动态更新模式：

```dotenv
RPZ_PUBLISH_MODE=nsupdate
RPZ_PRIMARY=10.0.0.10
RPZ_PRIMARY_PORT=53
RPZ_ZONE=rpz.local
RPZ_KEY_FILE=/etc/dns-ops/keys/rpz-manager.key
```

发布链路：

```text
页面修改 → 发布预览 → named-checkzone → nsupdate → RPZ Primary → Secondary 同步
```

`baidu.com` 会生成两条 QNAME 触发规则：

```text
baidu.com.rpz.local.
*.baidu.com.rpz.local.
```

### 5.4 运行数据和日志

| 文件/目录 | 用途 |
|---|---|
| `DNS_STATE_FILE` | RPZ 规则、已发布快照、版本记录 |
| `DNS_NODE_CONFIG_FILE` | DNS 节点名称、角色、地址 |
| `AUDIT_FILE` | 登录、规则、节点、发布审计 |
| `RPZ_ARTIFACT_FILE` | 生成的 RPZ 文件 |
| `RPZ_LOG_FILES` | BIND RPZ 日志，用于命中统计 |
| `.run/` | API/Web PID、二进制和启动日志 |

建议权限：

```bash
sudo install -d -o dnsops -g dnsops -m 0750 /etc/dns-ops /var/lib/dns-ops /var/log/dns-ops
sudo install -o dnsops -g dnsops -m 0640 config/dns-nodes.json /etc/dns-ops/dns-nodes.json
sudo install -o dnsops -g bind -m 0640 /path/to/rpz-manager.key /etc/dns-ops/keys/rpz-manager.key
```

TSIG key 只能授予控制面读取权限，不能放入 Git、前端目录或普通用户可读目录。

## 6. 已有生产 BIND 的接入步骤

1. 在管理节点安装项目和依赖，不修改现有 BIND 配置。
2. 将 `RPZ_KEY_FILE` 以最小权限挂载到控制面。
3. 先使用 `RPZ_PUBLISH_MODE=artifact` 验证配置和生成文件。
4. 使用 `named-checkzone` 检查现有 RPZ Zone 和生成文件。
5. 在维护窗口切换到 `RPZ_PUBLISH_MODE=nsupdate`。
6. 添加测试域名并发布，确认 Primary、全部 Secondary 的 SOA Serial 一致。
7. 验证回滚和删除流程后，再开放给运维人员使用。
8. 使用 systemd、Nginx 或现有进程管理器托管服务，禁止使用开发模式长期运行。

控制面不应直接覆盖生产 BIND Zone 文件。动态更新、权限和 NOTIFY/IXFR 应由 BIND 的原生机制负责。

## 7. 认证和生产安全要求

生产 `.env` 至少满足：

```dotenv
APP_ENV=production
AUTH_ENABLED=true
AUTH_USERNAME=admin
AUTH_PASSWORD=<strong-random-password>
AUTH_SECRET=<at-least-32-random-characters>
WEB_MODE=preview
```

HTTPS 任选一种：

**Go API 直出 HTTPS：**

```dotenv
TLS_CERT_FILE=/etc/dns-ops/tls/fullchain.pem
TLS_KEY_FILE=/etc/dns-ops/tls/privkey.pem
TRUST_PROXY_TLS=false
```

**反向代理终止 HTTPS：**

```dotenv
TRUST_PROXY_TLS=true
```

此时必须确保 API 只监听 `127.0.0.1`，反向代理只允许 HTTPS 访问。

## 8. 验证、备份和恢复

构建与单元测试：

```bash
npm run build
cd server && go test ./... && go test -race ./... && go vet ./...
cd ..
```

本地 BIND 功能测试：

```bash
./scripts/test-functional.sh
```

备份至少包含：

```text
DNS_STATE_FILE
DNS_NODE_CONFIG_FILE
AUDIT_FILE
RPZ_KEY_FILE（使用受保护的密钥备份流程）
```

恢复顺序：

```text
停止控制面 → 恢复节点配置 → 恢复状态文件 → 检查 RPZ 版本 → 启动控制面 → 只读验证 → 再发布
```

## 9. 故障排查

查看启动日志：

```bash
tail -f .run/api.log .run/web.log
```

检查端口：

```bash
ss -ltnp | grep -E '5173|8080'
```

检查节点 SOA：

```bash
dig @10.0.0.10 -p 53 rpz.local SOA +short
dig @10.0.0.11 -p 53 rpz.local SOA +short
```

常见问题：

- 前端地址为空：检查 `BIND_INTERFACE` 是否存在 IPv4，或直接配置 `WEB_BIND_ADDRESS`。
- 节点不可达：检查控制面到 DNS 节点的 UDP/TCP 53 连通性和防火墙。
- nsupdate 失败：检查 `RPZ_KEY_FILE` 权限、Key 名称、Primary 地址和 BIND `update-policy`。
- 辅节点版本不一致：检查 Primary 的 NOTIFY、allow-notify、transfer-source 和 IXFR 日志。
