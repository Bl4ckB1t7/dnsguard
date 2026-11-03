# DNS Ops Platform 源代码安全审计报告

> 审计日期：2026-11-03
> 审计类型：白盒代码审计 + 本地功能验证
> 目标：`dns-ops-platform`
> 审计基线：提交 `1f79c91`
> Flavor：null（普通 Web/API 源码审计，不涉及恶意样本或 APT）

## 1. 执行摘要

本次审计覆盖 Go API、React 前端、启动脚本、文件型状态存储和 RPZ 发布链路。发现的首要风险是部署示例默认关闭认证，导致管理 API 在当前默认配置下可被未认证调用；其次是认证配置缺省时仍存在 `admin/admin` 和固定签名密钥回退。DNS 节点地址可由请求写入并触发服务端 `dig`，形成可被滥用的任意 DNS 探测能力。验证码缓存、文件持久化并发一致性和 HTTP 超时配置还存在可用性与审计完整性风险。Go race test、go vet、前端构建和现有功能测试均通过，但自动 SAST 工具在本机不可用，`npm audit` 也因当前 npm 镜像不支持 audit endpoint 未完成。

**总体结论：暂不建议按当前默认 `.env.example` 直接暴露到生产网络。** 至少应先启用认证、替换默认凭据/密钥、限制节点地址范围，并补齐 HTTP 超时和持久化并发保护。

**跟进说明**：报告生成后已移除 `AUTH_PASSWORD` 明文回退，新增 `scripts/create-auth-file.sh` 和 bcrypt `AUTH_FILE` 启动校验。F-002 是审计基线上的已验证问题，当前代码已完成该项修复；F-001、F-003 及其余问题仍需按本报告处理。

## 2. 范围与限制

### 2.1 Scope 摘要

- `auth`：本地仓库源码、启动脚本和测试环境；未提供独立 `scope.md`。
- `in_scope`：`server/`、`src/`、`scripts/`、`.env.example`、`README.md`、`package.json`。
- `network_profile`：仅访问本机 DNS Ops API 和本地 BIND 测试环境；未测试任何外部生产主机。
- 限制：没有对真实生产 BIND、真实反向代理、操作系统账户权限和多进程部署做现场验证。

### 2.2 工具与检查项

| 工具/检查 | 结果 |
|---|---|
| `go test -race ./...` | 通过 |
| `go vet ./...` | 通过 |
| `npm run build` | 通过 |
| `./scripts/test-functional.sh` | 11/11 通过 |
| Semgrep | 本机未安装，未执行 |
| gosec/staticcheck | 本机未安装，未执行 |
| `npm audit --omit=dev` | 镜像返回 `[NOT_IMPLEMENTED]`，未得到依赖漏洞结论 |

## 3. 发现汇总

| 编号 | 发现 | 风险 | 状态 |
|---|---|---:|---|
| F-001 | 默认部署关闭认证，管理 API 可未认证写入 | 高 | 已验证 |
| F-002 | 认证缺省回退到弱口令和固定签名密钥 | 高 | 已修复（跟进） |
| F-003 | DNS 节点地址可触发任意服务端 DNS 探测 | 中 | 已验证 |
| F-004 | 验证码缓存没有容量上限 | 中 | 候选，代码确认 |
| F-005 | JSON/审计文件存在并发快照覆盖风险 | 中 | 候选，代码确认 |
| F-006 | HTTP Server 未配置读写/空闲超时 | 低 | 候选，代码确认 |
| F-007 | 缺少基础安全响应头 | 低 | 已确认的加固项 |

## 4. 核心发现

### 4.1 F-001：默认部署关闭认证，管理 API 可未认证写入

- `severity: high`
- `category: misconfig`
- `status: validated`
- `confidence: high`
- `location: .env.example:1-8; server/auth.go:346-354; server/main.go:90-104`
- `evidence_ids: [E-001, E-002]`

**描述**：`.env.example` 将 `AUTH_ENABLED=false` 作为默认值；中间件在认证关闭时直接放行所有请求。生产环境校验只有在 `APP_ENV=production` 时才会阻止该配置，因此使用默认 `development` 配置启动时，节点配置、RPZ 规则、发布和审计接口都可被未认证调用。

**复现步骤**（仅本地运行实例）：

```bash
curl -i -X POST http://127.0.0.1:8080/api/dns/nodes \
  -H 'Content-Type: application/json' \
  -d '{"id":"primary-1","address":"127.0.0.1:8080"}'
```

观察到 `HTTP 200` 和 `{"updated":true,...}`，请求没有 Cookie 或 CSRF Token。测试后已恢复本地节点地址。

**影响**：攻击者若能访问控制台端口，可修改 DNS 探测配置、添加/删除 RPZ 白名单、触发 RPZ 发布和读取审计数据，最终影响 DNS 策略。

**修复建议**：

1. 将 `.env.example` 和启动脚本默认值改为 `AUTH_ENABLED=true`。
2. 让服务在非测试环境也拒绝 `AUTH_ENABLED=false`，增加显式 `ALLOW_INSECURE_DEV=true` 才允许关闭。
3. 将认证关闭模式限制为绑定回环地址或显式 `DEV_ONLY=true`，禁止通过 Tailscale/生产网卡启动。
4. 在部署脚本中首次启动前强制检查强密码和随机 `AUTH_SECRET`。

### 4.2 F-002：认证缺省回退到弱口令和固定签名密钥

- `severity: high`
- `category: misconfig`
- `status: validated`
- `confidence: high`
- `location: server/auth.go:58-70`
- `evidence_ids: [E-003]`

**描述**：未设置环境变量时，`authPassword()` 回退为 `admin`，`authSecret()` 回退为固定字符串。单独运行 `cd server && go run .` 时，若没有其他配置保护，认证可能使用可猜测的默认凭据和可公开推导的会话签名密钥。

**影响**：攻击者可登录管理控制台；固定密钥还会降低会话伪造和离线分析的成本。生产校验虽覆盖 `APP_ENV=production`，但不能覆盖误用 `development` 的部署。

**修复建议**：

- 删除默认密码和默认密钥回退；缺失时启动失败。
- 首次部署生成随机密钥，并要求管理员通过环境变量或受保护的 Secret 文件提供。
- 禁止用 `development` 作为可对外监听的部署模式。

### 4.3 F-003：DNS 节点地址可触发任意服务端 DNS 探测

- `severity: medium`
- `category: vuln`
- `status: validated`
- `confidence: high`
- `location: server/dns.go:167-180, 621-635`
- `evidence_ids: [E-002, E-004]`

**描述**：节点地址只校验主机非空和端口范围，随后拼接为 `dig @<host> -p <port>` 参数。它不限制地址必须属于已登记 DNS 网段，也不限制私有、回环、链路本地或云元数据地址。每次节点状态读取都会触发服务端探测。

**本地验证**：将 `primary-1` 地址改为 `127.0.0.1:8080` 后调用 `/api/dns/nodes`，服务端返回该节点 `down / 探测失败`；随后已恢复到本地 BIND 测试地址。这证明请求可控制服务端探测目标。

**影响**：在 F-001 场景下，未认证攻击者可以让服务端对内网地址和端口发起 DNS 探测，造成盲探测、日志噪声或访问内部 DNS 服务。

**修复建议**：

- 节点地址只允许来自受保护配置文件，页面只读；或维护明确的 CIDR/主机白名单。
- 拒绝回环、链路本地、云元数据和未授权 RFC1918 地址，除非显式允许。
- 对节点探测增加并发上限、频率限制和审计字段。
- 不要把任意用户可提交的地址直接作为探测目标。

### 4.4 F-004：验证码缓存没有容量上限

- `severity: medium`
- `category: vuln`
- `status: candidate`
- `confidence: high`
- `location: server/captcha.go:38-49`
- `evidence_ids: [E-005]`

**描述**：`/api/auth/captcha` 未做速率限制；每次请求向全局 `captchas` map 加入一个 5 分钟条目，只有后续请求到达时才清理过期项，也没有最大条目数或按 IP 配额。

**影响**：连续请求可令进程内存持续增长，影响登录服务和同进程 API 的可用性。

**修复建议**：

- 按 IP 和全局设置验证码请求速率限制。
- 设置 map 最大容量，达到上限时淘汰最旧条目或返回 429。
- 使用带 TTL/容量的缓存实现，并定期清理，而不是仅依赖下一次请求触发清理。

### 4.5 F-005：JSON/审计文件存在并发快照覆盖风险

- `severity: medium`
- `category: design`
- `status: candidate`
- `confidence: medium`
- `location: server/dns.go:458-496; server/audit.go:46-65`
- `evidence_ids: [E-006, E-007]`

**描述**：`saveDNSState` 在锁外获取 `state` 的 JSON 快照，之后才进入文件锁写入；两个请求可分别取得旧、新快照并以相反顺序落盘，导致后写入的旧快照覆盖较新的变更。`auditEvent` 也在内存锁释放后直接写固定 `.tmp` 文件，没有跨进程文件锁。

**影响**：并发添加/删除 RPZ 规则或节点配置更新时可能丢失已提交变更；审计记录可能被覆盖，降低追责完整性。当前 `go test -race` 通过不代表该时序问题不存在，因为它是逻辑上的落盘顺序问题。

**修复建议**：

- 将“读取内存状态、生成快照、文件替换”纳入同一进程内写锁；或为每次写入使用单一串行写队列。
- 所有持久化文件统一使用跨进程锁，并让审计写入使用 append-only 或 SQLite/WAL（如果未来允许使用数据库）。
- 增加并发 HTTP 测试，校验最终规则集合和审计条目数。

### 4.6 F-006：HTTP Server 未配置完整超时

- `severity: low`
- `category: hardening`
- `status: candidate`
- `confidence: high`
- `location: server/main.go:80`
- `evidence_ids: [E-008]`

**描述**：服务器只配置了 `ReadHeaderTimeout`，没有 `ReadTimeout`、`WriteTimeout` 和 `IdleTimeout`。`MaxBytesReader` 只限制请求体大小，不能解决慢速发送或长时间占用连接的问题。

**影响**：当 API 直接暴露或反向代理配置不当时，慢速连接可占用 goroutine 和连接资源。

**修复建议**：按部署环境设置 `ReadTimeout`、`WriteTimeout`、`IdleTimeout`，并在反向代理层设置请求体、连接和响应超时。

### 4.7 F-007：缺少基础安全响应头

- `severity: low`
- `category: hardening`
- `status: validated`
- `confidence: high`
- `location: server/auth.go:346-350; server/main.go:80`
- `evidence_ids: [E-009]`

**描述**：应用层没有统一设置 `Content-Security-Policy`、`X-Content-Type-Options`、`Referrer-Policy`、`Permissions-Policy`、`X-Frame-Options` 或 HSTS。当前前端采用 React 转义用户输入，未发现直接的 DOM XSS sink，但缺少纵深防御。

**修复建议**：在 Go 中间件或生产反向代理统一添加安全头；HTTPS 部署后添加 HSTS，并根据前端资源策略逐步收紧 CSP。

## 5. 正向控制与未发现问题

- 非 GET 请求在认证开启时要求 CSRF Token，且请求体限制为 1 MiB。
- 密码文件支持 bcrypt，生产模式会校验密码、`AUTH_SECRET`、认证开关和 TLS/可信代理配置。
- RPZ 发布使用 `exec.CommandContext`，未发现通过 shell 拼接执行命令的路径。
- RPZ 域名使用正则校验，发布任务有 15 秒上下文超时。
- 状态文件使用临时文件、`fsync`、原子 rename 和备份文件。
- React 页面未发现 `dangerouslySetInnerHTML`、`eval` 或直接 `innerHTML` 使用。

## 6. Evidence 链

### E-001

- title: 默认认证配置与认证短路路径
- observed_at: 2026-11-03
- source_type: file
- source_ref: `.env.example:1-8`, `server/auth.go:346-354`, `server/main.go:90-104`
- content_hash: n/a
- artifact_path: n/a
- repro_command: `grep -nE 'AUTH_ENABLED|APP_ENV|if !authEnabled|APP_ENV.*production' .env.example server/auth.go server/main.go`
- raw_excerpt: `AUTH_ENABLED=false`; `if !authEnabled() { next.ServeHTTP(...) }`

### E-002

- title: 未认证节点配置写入
- observed_at: 2026-11-03
- source_type: network
- source_ref: local API `POST /api/dns/nodes`
- content_hash: n/a
- artifact_path: n/a
- repro_command: `curl -i -X POST http://127.0.0.1:8080/api/dns/nodes -H 'Content-Type: application/json' -d '{"id":"primary-1","address":"127.0.0.1:8080"}'`
- raw_excerpt: `HTTP 200`; `{"updated":true,"nodeId":"primary-1","address":"127.0.0.1:8080"}`

### E-003

- title: 认证默认凭据和默认签名密钥
- observed_at: 2026-11-03
- source_type: file
- source_ref: `server/auth.go:58-70`
- content_hash: n/a
- artifact_path: n/a
- repro_command: `nl -ba server/auth.go | sed -n '58,70p'`
- raw_excerpt: `return "admin"`; `return []byte("change-this-network-visualizer-secret")`

### E-004

- title: 节点地址控制服务端 dig 目标
- observed_at: 2026-11-03
- source_type: network
- source_ref: local API `POST /api/dns/nodes` followed by `GET /api/dns/nodes`
- content_hash: n/a
- artifact_path: n/a
- repro_command: `curl ... address=127.0.0.1:8080; curl http://127.0.0.1:8080/api/dns/nodes`
- raw_excerpt: `primary-1 address=127.0.0.1:8080 status=down lastSync=探测失败`

### E-005

- title: 验证码全局 map 无容量限制
- observed_at: 2026-11-03
- source_type: file
- source_ref: `server/captcha.go:38-49`
- content_hash: n/a
- artifact_path: n/a
- repro_command: `nl -ba server/captcha.go | sed -n '38,49p'`
- raw_excerpt: `captchas[id] = captchaEntry{...}`，无速率限制和最大容量判断

### E-006

- title: 状态快照在文件锁外生成
- observed_at: 2026-11-03
- source_type: file
- source_ref: `server/dns.go:458-496`
- content_hash: n/a
- artifact_path: n/a
- repro_command: `nl -ba server/dns.go | sed -n '458,496p'`
- raw_excerpt: `json.MarshalIndent(state, ...)` 在 `withStateFileLock` 之前执行

### E-007

- title: 审计临时文件无跨进程锁
- observed_at: 2026-11-03
- source_type: file
- source_ref: `server/audit.go:46-65`
- content_hash: n/a
- artifact_path: n/a
- repro_command: `nl -ba server/audit.go | sed -n '46,65p'`
- raw_excerpt: 多个请求都写入固定 `path + ".tmp"`

### E-008

- title: HTTP Server 只设置请求头超时
- observed_at: 2026-11-03
- source_type: file
- source_ref: `server/main.go:80`
- content_hash: n/a
- artifact_path: n/a
- repro_command: `nl -ba server/main.go | sed -n '76,86p'`
- raw_excerpt: `ReadHeaderTimeout` 存在，其他连接超时未设置

### E-009

- title: 未发现统一安全响应头中间件
- observed_at: 2026-11-03
- source_type: file
- source_ref: `server/auth.go:346-410`, `server/main.go:80`
- content_hash: n/a
- artifact_path: n/a
- repro_command: `grep -RInE 'Content-Security-Policy|X-Frame-Options|Strict-Transport-Security|X-Content-Type-Options' server src`
- raw_excerpt: 无匹配

### E-010

- title: 自动化验证结果
- observed_at: 2026-11-03
- source_type: command
- source_ref: repository test commands
- content_hash: n/a
- artifact_path: n/a
- repro_command: `cd server && go test -race ./... && go vet ./...; cd .. && npm run build && ./scripts/test-functional.sh`
- raw_excerpt: Go tests/vet/build 通过；功能测试 `11/11` 通过

## 7. Path

### P-001

- title: 默认配置到未认证管理变更
- path_type: attack
- start: 可访问控制台端口的未认证请求
- goal: 修改 DNS/RPZ 管理状态
- steps:
  1. action: 使用默认 `.env.example` 启动，认证开关为 false — evidence: E-001 — finding: F-001
  2. action: 直接 POST `/api/dns/nodes`，不携带 Cookie/CSRF — evidence: E-002 — finding: F-001
  3. action: 将节点地址改为服务端可访问的任意主机和端口 — evidence: E-004 — finding: F-003
  4. action: 通过 RPZ 管理接口继续修改规则或触发发布 — evidence: E-001 — finding: F-001
- residual_risks: 生产模式的强制校验能阻止部分错误配置，但依赖部署者正确设置 `APP_ENV=production`。

## 8. 修复优先级

| 优先级 | 建议 |
|---|---|
| P0 | 默认开启认证；禁止生产/可远程部署使用 `AUTH_ENABLED=false`；删除默认密码和固定密钥回退 |
| P1 | 限制 DNS 节点地址白名单；验证码按 IP/全局限速并设置容量上限；修复持久化写入串行化和审计文件锁 |
| P2 | 配置 HTTP 完整超时；增加安全响应头；补装并运行 Semgrep、gosec/staticcheck，切换到支持 `npm audit` 的 registry |

## 9. Timeline 摘要

1. 2026-11-03：读取本地源码审计规范，确认审计范围为当前仓库。
2. 2026-11-03：完成 Go API、React、启动脚本和配置文件人工审查。
3. 2026-11-03：执行 `go test -race`、`go vet`、前端构建和 11 项功能测试。
4. 2026-11-03：在本地实例验证未认证节点配置写入和服务端 DNS 探测路径，并恢复测试配置。

