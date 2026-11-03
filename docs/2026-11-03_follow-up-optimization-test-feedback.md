# DNS Ops Platform 后续六项优化测试反馈

## 1. 结论

按照 Ethan 的要求，本轮跳过“RPZ 审批流程”和“角色权限”两项，只优化其余六项。
每项均按“实现 → 完整测试 → 提交 → 推送 GitHub”的顺序执行，最终静态测试、BIND
实验室功能测试和生产部署模板验证全部通过。

最终结果：**通过**。

## 2. 本轮范围

| 原建议项 | 状态 |
|---|---|
| 1. 停止脚本残留进程 | 已完成 |
| 2. 生产环境强制监控 Token | 已完成 |
| 3. DNS 节点探测后台缓存 | 已完成 |
| 4. RPZ 审批流程 | 按要求跳过 |
| 5. 角色权限 | 按要求跳过 |
| 6. 审计日志增强 | 已完成 |
| 7. Nginx 生产部署 | 已完成 |
| 8. 备份与恢复自动化 | 已完成 |

## 3. 变更和逐项测试

### 3.1 停止脚本进程组清理

变更：`scripts/stop-dns-ops.sh` 现在校验 PID 所属命令/进程组，并按进程组发送
TERM，超时后发送 KILL，避免 Vite 子进程成为孤儿进程。

测试：

- `bash -n scripts/*.sh`：通过；
- 启动 API/Web 后执行停止脚本，确认工作区 API/Vite 进程和 Web 端口已释放：通过；
- 再次启动并访问 API/Web：通过；
- 完整 BIND/RPZ 功能测试：11/11 通过。

提交：`fc783a4 fix: stop DNS Ops process groups cleanly`

### 3.2 生产环境强制监控 Token

变更：生产环境要求 `MONITORING_TOKEN` 至少 32 位，缺失或使用示例值时 API 拒绝启动。
开发/本地环境保持原有回环访问行为。

测试：

- 生产配置缺失 Token 的单元测试：通过；
- Go 普通测试、race、vet：通过；
- 前端构建：通过；
- 完整 BIND/RPZ 功能测试：11/11 通过。

提交：`f655c96 security: require monitoring token in production`

### 3.3 DNS 节点探测后台缓存

变更：节点 `dig` 探测改为后台定时刷新；页面读取缓存，不再每次同步等待所有节点。
新增配置：

```dotenv
DNS_HEALTH_CACHE_SECONDS=5
DNS_HEALTH_INTERVAL_SECONDS=10
```

节点配置保存后会立即失效缓存，下一次读取重新探测。

测试：

- 缓存读取不触发同步 `dig` 的单元测试：通过；
- race、vet、前端构建：通过；
- 第二次节点读取耗时约 0 秒，确认命中缓存：通过；
- 完整 BIND/RPZ 功能测试：11/11 通过。

提交：`0e6f703 perf: move DNS health probes to background cache`

### 3.4 审计日志增强

变更：

- 审计记录增加 SHA-256 哈希链；
- 支持 `AUDIT_MAX_ENTRIES`；
- 支持按大小轮转 `.1`、`.2` 等备份；
- `/api/audit` 支持 `q`、`actor`、`action`、`page`、`pageSize` 搜索分页；
- 轮转和写入继续使用文件锁与原子替换。

测试：

- 哈希链和轮转单元测试：通过；
- 搜索和分页单元测试：通过；
- API 运行时搜索接口：通过；
- race、vet、前端构建：通过；
- 完整 BIND/RPZ 功能测试：11/11 通过。

提交：`077da1e feat: add searchable rotating audit trail`

### 3.5 Nginx 生产部署

变更：新增 `deploy/nginx/dns-ops.conf`，支持：

- HTTPS 终止；
- 静态托管 `dist/`；
- `/api/` 反向代理到 `127.0.0.1:8080`；
- CSP、HSTS、禁止 iframe 等安全头。

测试：

- `nginx -t`：通过；
- 临时 HTTPS Nginx 实例静态页面访问：通过；
- API 反向代理 `/api/health`：通过；
- 安全响应头验证：通过；
- 完整 BIND/RPZ 功能测试：11/11 通过。

提交：`22c6b3c ops: add nginx production frontend proxy`

### 3.6 备份与恢复自动化

变更：

- 新增 `scripts/backup-dns-ops.sh`；
- 新增 `scripts/restore-dns-ops.sh`；
- 备份包含 SHA-256 manifest；
- 敏感认证文件和 TSIG Key 必须显式开启；
- 归档权限为 600，备份目录权限为 700；
- 恢复前拒绝 API/systemd 服务运行中操作；
- 恢复校验路径、文件类型和 SHA-256，限制只能恢复到已配置目标文件；
- 使用临时文件和 Rename 原子替换。

测试：

- 备份、敏感文件、权限和校验：通过；
- 服务运行中恢复保护：通过；
- 恢复后内容校验：通过；
- 恶意路径限制逻辑已覆盖实现；
- 完整 BIND/RPZ 功能测试：11/11 通过。

提交：

- `fe0c84c ops: add verified backup and restore scripts`
- `db87873 security: restrict restore destinations`

## 4. 最终测试结果

执行命令：

```bash
bash -n scripts/*.sh
(cd server && go test ./...)
(cd server && go test -race ./...)
(cd server && go vet ./...)
npm run build
git diff --check
./scripts/test-functional.sh
```

结果：

- Shell 语法：通过；
- Go 单元测试：通过；
- Go race 测试：通过；
- `go vet`：通过；
- React/Vite 构建：通过；
- BIND/RPZ 功能测试：**11/11 通过**；
- 监控检查脚本：通过；
- 认证恢复检查：`/api/auth/me` 返回 401；
- Git 状态：`main...origin/main`，无未提交修改。

## 5. Evidence → Finding → Path

### E-001

- title: 六项变更的静态和单元测试
- observed_at: 2026-11-03
- source_type: command
- source_ref: `scripts/`、`server/`、`deploy/nginx/`
- content_hash: n/a
- artifact_path: n/a
- repro_command: |
    bash -n scripts/*.sh
    (cd server && go test ./... && go test -race ./... && go vet ./...)
    npm run build
- raw_excerpt: Go 测试、race、vet 和前端构建均退出成功
- linked_workitem: WI-FOLLOWUP-001
- supersedes: none

### E-002

- title: BIND/RPZ 端到端验证
- observed_at: 2026-11-03
- source_type: command
- source_ref: `scripts/test-functional.sh`
- content_hash: n/a
- artifact_path: n/a
- repro_command: |
    ./scripts/test-functional.sh
- raw_excerpt: `Functional tests passed: 11`
- linked_workitem: WI-FOLLOWUP-001
- supersedes: none

### E-003

- title: 生产部署和恢复链路验证
- observed_at: 2026-11-03
- source_type: command
- source_ref: `deploy/nginx/dns-ops.conf`、backup/restore scripts
- content_hash: n/a
- artifact_path: n/a
- repro_command: |
    nginx -t -c /temporary/test/nginx.conf -p /temporary/test
    ./scripts/backup-dns-ops.sh
    ./scripts/restore-dns-ops.sh BACKUP_ARCHIVE
- raw_excerpt: Nginx 临时 HTTPS 实例、API 代理、备份校验和恢复均通过
- linked_workitem: WI-FOLLOWUP-001
- supersedes: none

### F-001

- title: 选定的六项运维优化已通过本地验证
- severity: info
- category: design
- status: validated
- evidence_ids: [E-001, E-002, E-003]
- location: `scripts/`、`server/`、`deploy/nginx/`
- impact: 停止、监控、节点探测、审计、生产 Web 代理和恢复流程更加可控；审批流和角色权限按要求未实施。
- confidence: high
- repro_steps:
  1. 执行静态检查和 Go 测试。
  2. 启动本地 BIND 实验室并执行 `scripts/test-functional.sh`。
  3. 使用临时 Nginx 配置验证 HTTPS 静态托管与 API 代理。
  4. 创建临时备份并执行恢复，校验文件内容和哈希。
- remediation: 生产部署时替换 Nginx 域名/证书，配置真实监控 Token，并将备份归档交给企业备份系统。
- optional_attack:

### P-001

- title: 后续六项优化验证路径
- path_type: callflow
- start: 现有 DNS Ops Platform
- goal: 完成选定优化并通过运行时验证
- steps:
  1. action: 修复 API/Web 进程组停止 — evidence: E-001、E-002 — finding: F-001
  2. action: 增加生产监控 Token 校验 — evidence: E-001、E-002 — finding: F-001
  3. action: 将 DNS 探测改为后台缓存 — evidence: E-001、E-002 — finding: F-001
  4. action: 增强审计哈希链、轮转、搜索和分页 — evidence: E-001、E-002 — finding: F-001
  5. action: 增加 Nginx HTTPS 静态托管和 API 代理 — evidence: E-003 — finding: F-001
  6. action: 增加校验型备份和受限恢复 — evidence: E-003 — finding: F-001
- residual_risks: 生产证书、Nginx 管理网段 ACL、企业备份介质权限和真实 DNS 节点可达性仍需按现场变更流程确认。

## 6. 交付状态

- 代码已逐项提交并推送到 GitHub 远端 `main`。
- 最新提交：`db87873 security: restrict restore destinations`。
- 当前工作区无未提交修改。
- 认证已恢复开启。
