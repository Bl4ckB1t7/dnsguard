# DNS Ops Platform 八项优化测试反馈

## 1. 结论

本轮按“完成一项、完整测试一项、通过后再进入下一项”的顺序完成 8 项优化。
最终静态检查、运行时功能测试、并发测试、systemd 单元校验和 API/Web 安全响应头
验证均通过。工作区已恢复为认证开启状态，Git 分支与远端 `main` 一致。

最终结果：**通过**。

## 2. 测试范围与环境

| 项目 | 实际值 |
|---|---|
| 项目 | `dns-ops-platform` |
| 测试日期 | 2026-11-03 |
| API | `127.0.0.1:8080` |
| Web | `127.0.0.1:5173` |
| BIND 实验室 | Primary `127.0.0.2:5353`；Secondary `127.0.0.3:5353`、`127.0.0.4:5353` |
| RPZ Zone | `rpz.local` |
| 功能测试脚本 | `scripts/test-functional.sh` |
| 工作区状态 | `AUTH_ENABLED=true`；未提交修改为 0；`main...origin/main` |

测试期间仅为运行功能测试临时关闭认证，测试退出时通过 trap 恢复 `.env` 并重启服务；
最终验证 `/api/auth/me` 返回 HTTP 401，确认认证没有保持关闭。

## 3. 八项优化与逐项结果

| 序号 | 优化内容 | 主要路径 | 提交 | 逐项结果 |
|---:|---|---|---|---|
| 1 | 生产环境认证默认开启和启动校验 | `server/main.go`、`server/auth.go`、`.env.example` | `b22b352` | 通过 |
| 2 | CAPTCHA 图形化渲染、限速和禁止缓存 | `server/captcha.go`、`server/dns_test.go` | `610d6ff` | 通过 |
| 3 | DNS 节点地址允许网段/主机白名单 | `server/dns.go`、`scripts/start-dns-ops.sh` | `e9985ac` | 通过 |
| 4 | RPZ 发布任务互斥，避免重复发布/回滚并发执行 | `server/rpz.go`、`server/rpz_test.go` | `5f4baf0` | 通过 |
| 5 | JSON 状态、DNS 节点配置和审计文件串行/原子写入 | `server/dns.go`、`server/audit.go` | `458986e` | 通过 |
| 6 | systemd API 服务与定时健康检查部署模板 | `deploy/systemd/`、`README.md` | `2ac112b` | 通过 |
| 7 | 受保护的运行状态接口、检查脚本和 systemd timer | `server/monitoring.go`、`scripts/check-dns-ops.sh` | `0a84b46` | 通过 |
| 8 | API/Web 安全响应头和 CSP | `server/auth.go`、`vite.config.ts` | `de5c812` | 通过 |

### 3.1 认证默认值和生产校验

- 生产环境拒绝占位 `AUTH_SECRET`。
- 生产环境要求 `AUTH_ENABLED=true` 和 bcrypt `AUTH_FILE`。
- 密码仍不写入 `.env`，认证文件使用受保护的 bcrypt 哈希。
- 单项测试包含 Go 单元测试、race、vet、前端构建、11 项端到端功能测试和认证恢复检查。

结果：通过。认证恢复后 `/api/auth/me` 为 HTTP 401（未携带会话）。

### 3.2 CAPTCHA 安全

- 验证码不再把明文答案放进 SVG `<text>`。
- 单 IP 生成频率限制为每分钟 10 次。
- 验证码响应设置 `Cache-Control: no-store`。

结果：通过。测试确认 SVG 不包含明文答案，超过限制返回 HTTP 429；随后完整功能测试
11/11 通过。

### 3.3 DNS 节点白名单

- 默认允许回环、RFC1918 私网和 ULA 网段。
- `DNS_NODE_ALLOWED_HOSTS` 可显式放行受控主机名。
- 节点保存、运行时探测和加载配置共用地址校验，防止只校验前端保存而未校验探测。

结果：通过。运行时提交 `203.0.113.10:53` 被 HTTP 400 拒绝；合法实验室节点保持
healthy，完整功能测试 11/11 通过。

### 3.4 RPZ 发布互斥

- 发布任务在进入后台执行前抢占唯一执行槽。
- 已有任务运行时，重复发布返回 HTTP 409 和活动任务 ID。
- 回滚同样检查活动发布任务。
- 任务完成或失败都释放执行槽。

结果：通过。互斥槽单元测试通过，发布/回滚功能测试通过，完整功能测试 11/11 通过。

### 3.5 持久化并发安全

- 状态快照、序列化和文件替换在同一进程锁及文件锁保护下完成。
- DNS 节点配置和审计追加写入增加进程级串行化及文件锁。
- 写文件使用临时文件、Sync 和 Rename，降低进程中断产生半文件的风险。

结果：通过。20 个并发 RPZ 创建请求全部返回唯一 ID，随后 GET 能看到 20 条记录并完成
批量清理；race 测试和完整功能测试 11/11 通过。

### 3.6 systemd 部署

- 新增 `deploy/systemd/dns-ops-api.service`。
- 使用 `dnsops` 非特权用户、`NoNewPrivileges`、`ProtectSystem=strict`、
  `ProtectHome`、`PrivateTmp`、显式可写目录和网络族限制。
- 新增健康检查的 service/timer 模板，生产可用 systemd 管理 API 并每分钟执行检查。
- README 补充了用户、目录、构建、启停、升级和回滚步骤。

结果：通过。将部署路径替换为当前可执行文件后，三个 unit 通过
`systemd-analyze verify`；部署脚本语法、构建和完整功能测试 11/11 通过。
仓库不直接把本机 `/opt` 写入测试环境，因此原始模板的绝对部署路径需要在实际安装时创建。

### 3.7 运行监控和告警

- 新增 `GET /api/monitoring/status`，只返回健康数量、待发布状态和发布任务状态，
  不返回节点地址或规则内容。
- 设置 `MONITORING_TOKEN` 时要求 Bearer Token；未设置时仅允许本机回环访问。
- `scripts/check-dns-ops.sh` 在状态不是 `ok` 时返回非零退出码，可接入现有告警系统。

结果：通过。无 Token 的远程请求返回 HTTP 401，正确 Token 返回状态 `ok`；检查脚本
成功退出，完整功能测试 11/11 通过。

### 3.8 Web/API 安全响应头

- API 统一设置 `X-Content-Type-Options`、`X-Frame-Options`、`Referrer-Policy`、
  `Permissions-Policy`。
- API 在 TLS 或可信代理 HTTPS 场景设置 HSTS。
- Vite preview/server 设置 CSP、禁止 iframe、禁止对象加载和同源脚本策略。

结果：通过。API 和 Web 实际响应均包含预期安全头；Go 单元测试、前端构建和完整功能
测试 11/11 通过。

## 4. 最终测试记录

### 4.1 静态和单元测试

执行命令：

```bash
bash -n scripts/*.sh
(cd server && go test ./...)
(cd server && go test -race ./...)
(cd server && go vet ./...)
cd .. && npm run build
git diff --check
```

结果：全部通过。Go 普通测试、race 测试、vet 和前端生产构建均成功。构建阶段仅出现
Node 依赖自身的弃用提示，不影响构建结果。

### 4.2 systemd 模板校验

生产模板使用 `/opt/dns-ops-platform` 和 `/etc/dns-ops`，测试时将路径替换为当前工作区
可执行文件进行语法与依赖校验：

```bash
systemd-analyze verify deploy/systemd/dns-ops-api.service
systemd-analyze verify deploy/systemd/dns-ops-monitor.service
systemd-analyze verify deploy/systemd/dns-ops-monitor.timer
```

结果：使用实际可执行文件路径的等价测试单元全部通过。安装生产模板前需按 README 创建
`dnsops` 用户、安装目录和 `/etc/dns-ops/dns-ops.env`。

### 4.3 完整功能测试

执行：

```bash
./scripts/test-functional.sh
```

结果：**11/11 通过**。

覆盖项：

1. API health；
2. 页面 settings；
3. 认证关闭测试模式下的认证状态；
4. 真实 DNS 节点状态和 RPZ Serial 比对；
5. DNS 节点配置持久化；
6. 真实 RPZ 命中统计接口；
7. 新建规则产生待发布状态；
8. 精确域名和泛域名 RPZ 发布及 Primary/Secondary 同步；
9. 删除规则重新产生待发布状态；
10. 删除后的再次发布；
11. RPZ 批量删除和发布任务。

### 4.4 监控和安全头运行验证

结果：

- `GET /api/monitoring/status`：正确 Token 返回 HTTP 200 和 `status=ok`；错误/缺失 Token
  按配置拒绝；
- `scripts/check-dns-ops.sh`：返回 JSON 且成功退出；异常状态会返回非零码并输出 `ALERT`；
- API：实际响应包含 `nosniff`、`DENY`、`no-referrer` 和 Permissions Policy；
- Web：实际响应包含 CSP 及上述安全头；
- 认证恢复：`GET /api/auth/me` 未携带会话返回 HTTP 401。

## 5. Evidence → Finding → Path

### E-001

- title: 静态、并发安全和前端构建检查通过
- observed_at: 2026-11-03
- source_type: command
- source_ref: `server/`、`scripts/`、`npm` 构建输出
- content_hash: n/a
- artifact_path: n/a
- repro_command: |
    bash -n scripts/*.sh && cd server && go test ./... && go test -race ./... && go vet ./... && cd .. && npm run build && git diff --check
- raw_excerpt: `go test`、`go test -race`、`go vet`、`vite build` 均退出成功
- linked_workitem: WI-001
- supersedes: none

### E-002

- title: BIND 实验室完整 RPZ 功能测试
- observed_at: 2026-11-03
- source_type: command
- source_ref: `scripts/test-functional.sh`
- content_hash: n/a
- artifact_path: n/a
- repro_command: |
    ./scripts/test-functional.sh
- raw_excerpt: `Functional tests passed: 11`
- linked_workitem: WI-001
- supersedes: none

### E-003

- title: 监控接口与安全响应头运行验证
- observed_at: 2026-11-03
- source_type: network
- source_ref: `127.0.0.1:8080`、`127.0.0.1:5173`
- content_hash: n/a
- artifact_path: n/a
- repro_command: |
    MONITORING_TOKEN="$MONITORING_TOKEN" ./scripts/check-dns-ops.sh
    curl -sS -D - -o /dev/null http://127.0.0.1:8080/api/health
    curl -sS -D - -o /dev/null http://127.0.0.1:5173/
- raw_excerpt: 监控状态为 `ok`；API/Web 均返回预期安全头；认证恢复后 `/api/auth/me` 为 401
- linked_workitem: WI-001
- supersedes: none

### F-001

- title: 八项优化已在本地 BIND 实验环境验证
- severity: info
- category: design
- status: validated
- evidence_ids: [E-001, E-002, E-003]
- location: `server/`、`scripts/`、`deploy/systemd/`、`vite.config.ts`
- impact: 生产部署具备更明确的认证、并发、发布、监控和浏览器安全基线；部署仍需按 README 配置真实证书、TSIG、节点地址和 systemd 目录。
- confidence: high
- repro_steps:
  1. 按 README 准备 `.env`、认证文件和 BIND/RPZ 实验节点。
  2. 执行静态检查和 `scripts/test-functional.sh`。
  3. 使用正确/错误监控 Token 验证监控接口，再检查 API/Web 响应头。
- remediation: 生产上线前替换示例配置，创建 `dnsops` 用户和受保护的 `/etc/dns-ops`、`/var/lib/dns-ops` 目录。
- optional_attack: 

### P-001

- title: 八项优化的逐项验证路径
- path_type: callflow
- start: 代码变更
- goal: 通过本地 BIND 实验和运行时 HTTP 验证
- steps:
  1. action: 提交认证/CAPTCHA/节点白名单改动并运行单元、race、vet、构建和功能测试 — evidence: E-001、E-002 — finding: F-001
  2. action: 提交 RPZ 互斥和 JSON/审计串行化改动并运行互斥与并发场景 — evidence: E-001、E-002 — finding: F-001
  3. action: 校验 systemd API/monitor timer 模板和实际可执行文件路径 — evidence: E-001 — finding: F-001
  4. action: 使用 Token/回环策略验证监控接口和检查脚本 — evidence: E-003 — finding: F-001
  5. action: 访问 API 与 Web 并检查安全响应头，最后恢复认证开启 — evidence: E-003 — finding: F-001
- residual_risks: 生产证书、反向代理 ACL、BIND TSIG 权限和真实节点可达性仍需由部署方按现场变更流程确认。

## 6. 交付状态

- 代码已提交并推送到远端 `main`。
- 最新提交：`de5c812 security: add web security headers`。
- 文档已保存为本文件。
- 工作区无未提交修改。
