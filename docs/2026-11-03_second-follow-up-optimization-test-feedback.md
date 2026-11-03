# DNS Ops Platform 第二轮优化测试反馈

## 1. 结论

本轮完成了上一轮建议中的 6 项，跳过 CI 自动测试项；此前明确跳过的 RPZ 审批流程和
角色权限也没有实施。每项均完成独立测试后再进入下一项，并逐项提交、推送 GitHub。

最终结果：**通过**。

## 2. 本轮范围

| 优化项 | 状态 |
|---|---|
| 生产配置预检 | 已完成 |
| RPZ 发布重试和超时 | 已完成 |
| 首次登录强制改密码 | 已完成 |
| 备份保留策略 | 已完成 |
| BIND 发布前置校验 | 已完成 |
| GitHub Actions CI | 按要求跳过 |
| Web 错误、加载和重试体验 | 已完成 |
| RPZ 审批流程 | 之前按要求跳过 |
| 角色权限 | 之前按要求跳过 |

## 3. 逐项变更和测试

### 3.1 生产配置预检

`APP_ENV=production` 启动时现在检查：

- `named-checkzone` 是否存在；
- bcrypt 认证文件和权限；
- DNS 节点配置文件；
- TLS 证书/私钥；
- 状态、审计和 RPZ 产物目录；
- nsupdate 模式下的 TSIG Key 和权限。

测试：生产配置缺失/完整场景单测、race、vet、前端构建、BIND 功能测试 11/11 均通过。

提交：`e4f58a3 feat: add production configuration preflight`

### 3.2 RPZ 发布重试和超时

新增配置：

```dotenv
RPZ_PUBLISH_TIMEOUT_SECONDS=15
RPZ_PUBLISH_RETRIES=2
RPZ_PUBLISH_RETRY_BACKOFF_SECONDS=1
```

`nsupdate` 临时失败会自动重试；发布任务返回 `attempts`，最终失败保留错误原因并进入
监控告警状态。发布前后探测 Primary SOA Serial，拒绝 Serial 回退。

测试：模拟临时失败后成功、达到重试上限、race、vet、构建和功能测试 11/11 均通过。

提交：`4c8e383 reliability: retry RPZ publishes with timeout`

### 3.3 首次登录强制修改密码

通过 `scripts/create-auth-file.sh` 新生成的认证文件会写入
`mustChangePassword=true`。首次登录后只允许访问改密码/退出相关接口，页面显示不可关闭的
首次改密窗口，修改成功后才开放 DNS/RPZ 操作。
没有该字段的旧认证文件会在加载时按首次改密处理，改密成功后持久化为 `false`。

测试：

- `authMe` 返回强制改密状态：通过；
- 中间件阻止 Dashboard 接口：通过；
- 前端构建：通过；
- 完整 BIND/RPZ 功能测试 11/11：通过。

提交：`0a98b95 security: require initial password change`

### 3.4 备份保留策略

新增：

```dotenv
BACKUP_RETENTION_COUNT=14
```

备份脚本按时间保留最新归档，超过数量的本机旧归档自动清理；异地企业备份副本不受影响。

测试：临时目录生成 3 份备份、保留数量设为 2，最终只保留最新 2 份；随后完整功能测试
11/11 通过。

提交：`cf23638 ops: add backup retention policy`

### 3.5 BIND 发布前置校验

生产启动强制要求 `named-checkzone`。RPZ Serial 使用单调生成策略，nsupdate 发布前后
探测 Primary SOA，发现 Serial 回退或无效时任务失败。

测试：生产预检、SOA 校验、Primary/Secondary 实验环境发布、race、vet、构建和功能测试
11/11 均通过。实验室 BIND 的动态更新 Serial 在部分重复更新场景保持不变，因此校验
采用“不回退”策略，而不是错误地强制每次必须递增。

提交：`16904b1 security: require BIND publish preflight checks`

### 3.6 Web 错误、加载和重试体验

- API 请求统一增加 10 秒超时；
- 超时显示 DNS/API 检查提示；
- 状态加载期间显示“加载中…”并禁用刷新按钮；
- 页面增加全局错误条和重试按钮；
- RPZ 发布/回滚失败显示明确前缀和服务端错误原因。

测试：前端构建、错误文案进入生产 Bundle 验证、BIND 功能测试 11/11 均通过。

提交：`7f13978 ux: improve frontend error states and retries`

## 4. 最终测试结果

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
- Go race：通过；
- `go vet`：通过；
- React/Vite 构建：通过；
- BIND/RPZ 功能测试：**11/11 通过**；
- 认证恢复检查：`/api/auth/me` 返回 HTTP 401；
- Git 状态：`main...origin/main`，无未提交修改。

## 5. Evidence → Finding → Path

### E-001

- title: 生产预检、RPZ 重试和认证流程测试
- observed_at: 2026-11-03
- source_type: command
- source_ref: `server/`、`scripts/`
- content_hash: n/a
- artifact_path: n/a
- repro_command: |
    (cd server && go test ./... && go test -race ./... && go vet ./...)
    ./scripts/test-functional.sh
- raw_excerpt: Go 测试通过；功能测试 `Functional tests passed: 11`
- linked_workitem: WI-SECOND-FOLLOWUP-001
- supersedes: none

### E-002

- title: 备份保留和恢复链路测试
- observed_at: 2026-11-03
- source_type: command
- source_ref: `scripts/backup-dns-ops.sh`、`scripts/restore-dns-ops.sh`
- content_hash: n/a
- artifact_path: n/a
- repro_command: |
    BACKUP_RETENTION_COUNT=2 ./scripts/backup-dns-ops.sh
    ./scripts/restore-dns-ops.sh BACKUP_ARCHIVE
- raw_excerpt: 临时目录生成 3 份备份后保留 2 份，恢复校验通过
- linked_workitem: WI-SECOND-FOLLOWUP-001
- supersedes: none

### E-003

- title: 前端错误状态和生产 Bundle 验证
- observed_at: 2026-11-03
- source_type: command
- source_ref: `src/components/DnsDashboard.tsx`、`dist/`
- content_hash: n/a
- artifact_path: n/a
- repro_command: |
    npm run build
    curl -fsS http://WEB_BIND_ADDRESS:5173/
- raw_excerpt: 构建成功，Bundle 包含超时、加载失败和重试文案
- linked_workitem: WI-SECOND-FOLLOWUP-001
- supersedes: none

### F-001

- title: 本轮选定的六项优化已通过本地 BIND 实验验证
- severity: info
- category: design
- status: validated
- evidence_ids: [E-001, E-002, E-003]
- location: `server/`、`scripts/`、`src/components/DnsDashboard.tsx`
- impact: 生产启动、RPZ 发布、首次认证、备份恢复和前端故障反馈更加可控；CI、审批流和角色权限未实施。
- confidence: high
- repro_steps:
  1. 执行 Go/Race/Vet 和前端构建。
  2. 执行 `scripts/test-functional.sh` 验证 BIND/RPZ。
  3. 使用临时配置验证备份轮转和恢复。
  4. 刷新 Web 页面并检查错误、加载和重试状态。
- remediation: 生产上线前配置真实证书、节点、TSIG、监控 Token 和企业备份策略。
- optional_attack:

### P-001

- title: 第二轮优化验证路径
- path_type: callflow
- start: DNS Ops Platform 生产配置
- goal: 通过启动、发布、恢复和 Web 运行验证
- steps:
  1. action: 启动前执行生产文件、权限和 named-checkzone 预检 — evidence: E-001 — finding: F-001
  2. action: 执行 RPZ 发布并验证重试、超时和 Primary SOA — evidence: E-001 — finding: F-001
  3. action: 使用新认证文件登录并完成首次改密 — evidence: E-001 — finding: F-001
  4. action: 生成多份备份并执行保留、校验和恢复 — evidence: E-002 — finding: F-001
  5. action: 访问前端并验证加载失败提示和重试入口 — evidence: E-003 — finding: F-001
- residual_risks: CI、审批流和角色权限需要后续单独规划；真实生产证书、备份介质和 BIND 变更窗口仍需现场确认。

## 6. 交付状态

- 代码已逐项提交并推送到 GitHub `main`。
- 测试反馈文档已生成。
- 认证已恢复开启。
