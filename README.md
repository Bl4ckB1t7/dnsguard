# DNS Ops Platform

一个轻量的企业 DNS / BIND / RPZ 管理项目。

## 当前版本

- 登录页直接复用了 `network-ops-platform` 的雷达式登录界面。
- Go API 提供 Cookie 会话、图形验证码、登录限速、CSRF 和审计。
- DNS 节点配置和 RPZ 规则使用 JSON 文件保存，不使用数据库；节点地址配置与运行状态分离。
- 前端提供 DNS 节点实时状态、RPZ 白名单新增和删除页面，规则不设置过期时间。
- DNS 节点状态通过 `dig` 查询 RPZ Zone 的 SOA Serial；辅节点会与 Primary Serial 比对，显示正常、版本不一致或不可达。
- 当前 RPZ 页面是策略控制面，后续可以接入 `named-checkzone`、`rndc reload` 或 `nsupdate` 发布器。

点击“生成 / 发布 RPZ”时，默认使用 `RPZ_PUBLISH_MODE=artifact`，生成文件到 `RPZ_ARTIFACT_FILE`，不会触碰生产 BIND。配置 `RPZ_PUBLISH_MODE=nsupdate`、`RPZ_PRIMARY` 和 `RPZ_KEY_FILE` 后，才会通过 TSIG `nsupdate` 更新 RPZ Primary。

## 一键部署与启动

首次部署只需要：

```bash
cp .env.example .env
# 按实际环境修改 .env 中的 DNS、RPZ 和 HTTPS 参数
./scripts/start-tailscale.sh
```

脚本会自动检查 `Node.js`、`Go`、`dig` 和 Tailscale，首次运行自动执行 `npm ci`，构建前端和 Go API，并以生产预览模式启动。默认通过 Tailscale 地址访问；停止服务：

```bash
./scripts/stop-tailscale.sh
```

日常升级同样只需要拉取代码后再次执行 `./scripts/start-tailscale.sh`。

开发调试可以在 `.env` 中设置 `WEB_MODE=dev`；生产环境保持 `WEB_MODE=preview`。

## 手动启动（开发）

前端：

```bash
npm install
npm run dev
```

后端：

```bash
cd server
go run .
```

Tailscale 访问：

```bash
./scripts/start-tailscale.sh
```

脚本会自动读取本机 Tailscale IPv4，前端绑定到该地址，API 仍只监听本机回环地址。

默认地址：

```text
Frontend: http://127.0.0.1:5173
API:      http://127.0.0.1:8080
```

当前 Tailscale 启动脚本默认 `AUTH_ENABLED=false`，暂时直接进入控制台。重新启用认证时设置 `AUTH_ENABLED=true`；生产环境必须同时设置 `AUTH_PASSWORD` 和长度至少 32 位的 `AUTH_SECRET`。

生产环境可让 Go API 直接提供 HTTPS：设置 `APP_ENV=production`、`AUTH_ENABLED=true`、`TLS_CERT_FILE` 和 `TLS_KEY_FILE`。如果 HTTPS 由 Nginx、Traefik 或 Tailscale Funnel 等反向代理终止，则设置 `TRUST_PROXY_TLS=true`，并确保代理只允许 HTTPS 访问。

节点地址运行时从 `DNS_NODE_CONFIG_FILE` 读取，默认是 `config/dns-nodes.json`。页面修改节点地址后会原子写入该文件，程序启动时自动读取。首次启动如果配置文件不存在，会从旧状态文件和兼容用的 `DNS_NODE_ADDRESSES` 自动迁移。

配置示例：

```json
[
  {"id":"primary-1","name":"DNS Primary","role":"primary","address":"10.0.0.10:53"},
  {"id":"secondary-1","name":"DNS Secondary 1","role":"secondary","address":"10.0.0.11:53"}
]
```

旧版环境仍可通过 `DNS_NODE_ADDRESSES` 配置，格式为 `节点ID=host:port`，例如：

```bash
DNS_NODE_ADDRESSES=primary-1=10.0.0.10:53,secondary-1=10.0.0.11:53
```

运行环境需要安装 `dig`（Debian/Ubuntu 通常由 `bind9-dnsutils` 提供）。

## 文件型状态

```text
DNS_STATE_FILE   DNS 节点和 RPZ 规则
DNS_NODE_CONFIG_FILE DNS 节点名称、角色和地址配置
AUDIT_FILE       操作审计记录
```

不建议 Web 服务直接修改生产 BIND 文件。后续发布器应在校验后执行：

```text
rules → named-checkzone → RPZ Primary → NOTIFY / IXFR → Secondary
```

## 验证

```bash
npm run build
cd server && go test ./...
cd ..
./scripts/test-functional.sh
```

`test-functional.sh` 需要本地 BIND 测试环境和 `AUTH_ENABLED=false`，会创建一个临时 RPZ 规则，验证发布、精确/泛域名记录、主辅同步、删除回滚和待发布状态，结束后自动清理。
