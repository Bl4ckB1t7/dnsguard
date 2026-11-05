# DNSGuard · 域盾

**轻量级 BIND RPZ 安全策略管理平台**

> **让每一次解析，都有安全边界。**

<p align="center">
  <img src="docs/images/dnsguard-overview.png" alt="DNSGuard 产品概览" width="100%">
</p>

DNSGuard 是一个面向企业和网络管理员的 DNS 安全策略控制面，通过 Web 界面管理 RPZ 规则、DNS 节点、发布任务和审计记录。

DNSGuard 不替代 BIND，不参与客户端 DNS 查询，也不要求改造现有 DNS 架构。它通过 `nsupdate + TSIG` 向 BIND Primary 发布策略，由 BIND 原生机制将变更同步到 Secondary。

> **核心原则：控制面与 DNS 数据面分离。即使 DNSGuard 停止运行，BIND 仍可独立提供已加载的 DNS 解析服务。**

## 核心功能

| 功能 | 说明 |
|---|---|
| RPZ 规则管理 | 支持 passthru 白名单、A 记录重定向和多级子域名匹配 |
| TLD deny RPZ | 独立 Zone，显式启用后管理 TLD 拒绝触发项 |
| TLD 数据同步 | 校验并同步 IANA TLD 列表，保留版本和数量状态 |
| 受控策略发布 | 增量、分批 `nsupdate + TSIG` 发布和发布预览 |
| BIND 集群管理 | Primary / Secondary 状态、SOA Serial 和同步检查 |
| 完整性核对 | 只读 AXFR 全量规则集合校验 |
| 发布任务追踪 | `pending_verification`、`reconcile_required`、异常诊断和人工核对 |
| 版本与审计 | 策略版本、受控回滚、审计哈希链和恢复保护 |
| 安全认证 | 管理员登录、会话保护、CSRF 和访问限制 |
| Docker 部署 | Docker Compose、一体化 Web 初始化向导 |
| 数据持久化 | 使用 JSON 文件，无需独立数据库 |

## 工作原理

```mermaid
flowchart TD
    A[管理员浏览器] --> B[DNSGuard Web]
    B --> C[DNSGuard API]
    C --> D[JSON 状态与审计]
    C --> E[nsupdate + TSIG]
    E --> F[BIND Primary]
    F -->|NOTIFY / IXFR / AXFR| G[BIND Secondary 1]
    F -->|NOTIFY / IXFR / AXFR| H[BIND Secondary 2]
    I[DNS 客户端] --> G
    I --> H
```

**DNSGuard 管理策略，BIND 执行策略。**

生产部署只包含 `dnsguard-api` 和 `dnsguard-web` 两个 Docker 服务。BIND DNS 服务器保持独立运行。

## 部署前：对接现有 BIND RPZ 集群

### 部署边界

DNSGuard 是 DNS 策略控制面，生产 Docker Compose 只部署 `dnsguard-api` 和 `dnsguard-web`。BIND Primary / Secondary 由管理员独立部署，DNSGuard 不负责安装 BIND、修改 `named.conf`、修改 `response-policy`、直接编辑 Zone 文件或 reload/restart BIND。

### BIND 管理员需要提前准备

在部署 DNSGuard 前，请确认：

1. BIND Primary 和至少一台 Secondary 已正常工作。
2. 白名单 / A 重定向 RPZ Zone 已创建并可用。
3. 递归 DNS 的 `response-policy` 已按管理员规划配置正确的 Zone 顺序，白名单 / 重定向 Zone 位于 TLD deny Zone 之前。
4. 已准备最小权限 TSIG Key 和动态更新权限。
5. Primary 到 Secondary 的 NOTIFY / IXFR / AXFR 已配置并可用。
6. 如需 TLD deny，已提前创建独立 deny RPZ Zone。
7. 如需自动发布 TLD deny，已为 DNSGuard 配置该 Zone 的只读 AXFR 权限。
8. DNS TCP/UDP 53、必要的 Zone Transfer、DNSGuard HTTPS 等网络路径可达。
9. 如启用 IANA 同步，DNSGuard 可以访问 IANA HTTPS 数据源。
10. 管理员已独立评估递归设置和 DNS 查询外传风险。

具体 BIND 配置、TSIG、Zone Transfer 和 `response-policy` 说明见：[BIND RPZ 部署与 DNSGuard 对接](docs/bind-rpz-deployment.md)。其中的地址、密钥和域名均为占位符，不要直接用于生产。

### 部署前只读对接检查

脚本参数以 [`scripts/rpz-connect.sh`](scripts/rpz-connect.sh) 实际实现为准。先准备配置文件：

```bash
cp deploy/docker/rpz-connect.env.example /path/to/rpz-connect.env
# 按实际 BIND 地址、RPZ Zone、Secondary 和宿主机 TSIG 文件路径修改

./scripts/rpz-connect.sh --env-file /path/to/rpz-connect.env
```

默认是只读预检，检查工具、TSIG 文件权限、Primary / Secondary SOA Serial、节点连通性和同步一致性；配置可选参数时，还会执行实际递归 A、白名单或 TLD deny 证据检查。参数不完整的可选检查会显示 `NOT RUN`。该命令不修改 RPZ 记录、不修改 BIND 配置、不 reload/restart BIND，也不会自动修复失败项。

检查失败时，应先排查 BIND 配置、TSIG 权限和网络连通性，不要绕过安全检查。

如需在启用严格策略前准备初始白名单，可在对接检查时额外导出 JSON。输入文件每行一个域名，脚本只做规范化、去重和格式校验，不执行 DNS UPDATE：

```bash
./scripts/rpz-connect.sh \
  --env-file /path/to/rpz-connect.env \
  --whitelist-file /path/to/approved-domains.txt \
  --export-whitelist-json /path/to/whitelist-seed.json

install -d -m 0750 docker-data/bootstrap
install -m 0600 /path/to/whitelist-seed.json docker-data/bootstrap/whitelist-seed.json
printf '\nRPZ_WHITELIST_SEED_FILE=/var/lib/dnsguard/bootstrap/whitelist-seed.json\n' >> deploy/docker/dnsguard.env
```

启动后初始化向导会显示发现的条目数量，并将其导入为未发布草稿；不会自动修改 BIND。管理员应在页面核对后，再使用正常发布流程提交白名单。已有 DNSGuard 数据时不会重新导入或覆盖现有规则。

### 可选：受控临时 TXT 写入测试

脚本支持显式授权的临时 TXT 测试，但默认不开启。只有在隔离环境或已批准的维护窗口中，才执行：

```bash
./scripts/rpz-connect.sh \
  --env-file /path/to/rpz-connect.env \
  --write-test --confirm WRITE-TEST
```

该模式只使用脚本生成的随机测试名称和随机 TXT 内容，默认限制在 `_dnsguard-preflight.<RPZ_ZONE>` 命名空间；自定义名称也必须位于受保护测试命名空间内。脚本会先确认目标不存在，写入后精确删除并再次查询确认。写入、读回或清理结果不确定时会失败并要求人工核对，不会执行正式 RPZ 发布。不要把实际业务域名或业务策略作为测试对象。

### 双 RPZ Zone 架构

- **Zone 1：白名单与 A 重定向**：管理 `passthru` 白名单、域名及多级子域名放行，以及 A 记录重定向。
- **Zone 2：TLD deny**：独立管理 IANA TLD 列表对应的精确和通配触发项，并通过增量方式维护。

白名单 / 重定向 Zone 必须在 BIND 的 RPZ 策略顺序中具有更高优先级。DNSGuard 只通过 `nsupdate + TSIG` 更新管理员预先配置的 Primary Zone；Primary / Secondary 同步由 BIND 原生 NOTIFY / IXFR / AXFR 完成。

TLD deny 发布是**显式启用**功能，不是默认开启。它不能被描述为在所有 BIND 配置下百分之百阻止 DNS C2 或 DNS 数据外传。本文不包含未经验证的 `* CNAME .` 根级全局拒绝方案。

## 快速开始

DNSGuard v1.0.1 采用 **Docker Compose Only** 部署。

环境要求：Docker Engine、Docker Compose Plugin、现有 BIND RPZ 集群、TSIG Key 和 HTTPS 证书。

```bash
git clone --branch v1.0.1 --single-branch https://github.com/Bl4ckB1t7/dnsguard.git dnsguard
cd dnsguard

cp deploy/docker/dnsguard.env.example deploy/docker/dnsguard.env

# 按部署手册准备配置、TSIG Key 和 HTTPS 证书
./scripts/docker-init.sh
docker compose up -d
docker compose ps
```

首次打开 HTTPS 管理页面后，使用 Web 初始化向导完成管理员创建、DNS 节点配置和 TSIG 验证。

**完整安装说明：** [Docker 部署与运维手册](deploy/docker/README.md)

**正式版本：** [DNSGuard v1.0.1 GitHub Release](https://github.com/Bl4ckB1t7/dnsguard/releases/tag/v1.0.1)

推荐的部署顺序是：先准备并验证独立 BIND 集群，执行只读对接预检，再启动 DNSGuard Compose，完成 Web 初始化，发布少量受控规则并验证同步；需要 TLD deny 时，最后在独立 Zone 已准备并验证后显式开启。

## 界面预览

登录页和控制台分别如下，便于快速了解 DNSGuard 的使用方式：

| 安全登录 | DNS 控制台 |
|---|---|
| <img src="docs/images/dnsguard-login.jpg" alt="DNSGuard 安全登录页" width="430"> | <img src="docs/images/dnsguard-dashboard.jpg" alt="DNSGuard DNS 控制台" width="430"> |

## 安全与部署边界

DNSGuard 仅管理经过授权的 BIND RPZ 集群，不会自动安装、修改或重启生产 BIND。生产环境必须使用 HTTPS，并妥善保护 TSIG 密钥和持久化数据。

控制台的 **TLD 数据状态**卡片显示 IANA TLD 数据的数量、版本和同步状态。默认每 24 小时检查一次；下载失败时保留上一份有效状态。默认不发布 deny RPZ；管理员在隔离环境配置并验证第二个 RPZ Zone 后，可显式启用 `TLD_DENY_PUBLISH_ENABLED=true`，由 DNSGuard 通过现有 `nsupdate + TSIG` 更新该 Zone。DNSGuard 不会自动修改 `named.conf`、重启 BIND 或改变递归配置。

正式部署前，应在隔离环境完成 RPZ 发布、同步、备份和恢复测试。

## v1.0.1 隔离 BIND 验收摘要

正式验收使用 BIND 9.20.30 和真实隔离 Primary / Secondary 集群完成：

- 测试 TLD：1,436 个；RPZ 拒绝触发项：2,872 条；`nsupdate`：15 批。
- Primary / Secondary SOA：`16 / 16 / 16`；AXFR 全量核对：PASS。
- 白名单、多级子域名、A 重定向和 TLD 默认拒绝：PASS。
- 隔离上游查询观测未发现被拒绝查询名称到达受控上游。
- 总结果：`20 PASS / 0 FAIL / 0 NOT RUN`。

这些结果来自隔离 BIND 配置，不代表所有生产 BIND 配置均已验证；客户端收到 `NXDOMAIN` 也不能单独等同于完全阻止 DNS 数据外传。详见：[v1.0.1 隔离 BIND 正式验收报告](docs/acceptance/v1.0.1-bind-acceptance.md)。

## 文档

- [DNSGuard v1.0.1 GitHub Release](https://github.com/Bl4ckB1t7/dnsguard/releases/tag/v1.0.1)
- [BIND RPZ 部署与 DNSGuard 对接](docs/bind-rpz-deployment.md)
- [Docker 安装、初始化与运维](deploy/docker/README.md)
- [v1.0.1 隔离 BIND 验收报告](docs/acceptance/v1.0.1-bind-acceptance.md)
- [版本发布说明](RELEASE_NOTES.md)
- [安全说明](SECURITY.md)
- [许可证](LICENSE)

## 本地开发与隔离测试

本地开发仍可使用 Go 和 React，但这不是生产部署方式：

```bash
npm ci
npm run build
(cd server && go test ./... -count=1)
```

隔离验收测试使用独立 Docker 网络、测试 TSIG 和临时目录，不连接生产 DNS：

```bash
./tests/backup-restore.sh
./tests/docker-initialization-wizard.sh
./tests/docker-production-deployment.sh
./tests/bind-cluster/run-acceptance.sh
```

## License

MIT License
