# DNS Ops Platform

一个轻量的企业 DNS / BIND / RPZ 管理项目。

## 当前版本

- 登录页直接复用了 `network-ops-platform` 的雷达式登录界面。
- Go API 提供 Cookie 会话、图形验证码、登录限速、CSRF 和审计。
- DNS 节点和 RPZ 规则使用 JSON 文件保存，不使用数据库。
- 前端提供 DNS 节点状态、RPZ 白名单新增和删除页面，规则不设置过期时间。
- 当前 RPZ 页面是策略控制面，后续可以接入 `named-checkzone`、`rndc reload` 或 `nsupdate` 发布器。

点击“生成 / 发布 RPZ”时，默认使用 `RPZ_PUBLISH_MODE=artifact`，生成文件到 `RPZ_ARTIFACT_FILE`，不会触碰生产 BIND。配置 `RPZ_PUBLISH_MODE=nsupdate`、`RPZ_PRIMARY` 和 `RPZ_KEY_FILE` 后，才会通过 TSIG `nsupdate` 更新 RPZ Primary。

## 启动

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

## 文件型状态

```text
DNS_STATE_FILE   DNS 节点和 RPZ 规则
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
```
