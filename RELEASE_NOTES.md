# DNSGuard v1.1.0

## 正式发布说明

DNSGuard v1.1.0 正式采用“白名单与 A 重定向优先，其余默认 DENY”的部署模式。
DNSGuard 仍然只是控制面，BIND Primary/Secondary 由管理员独立部署和维护。

## 主要更新

- **全局默认 DENY**：使用独立 `global-deny` RPZ Zone；白名单和 A 重定向优先。
- **一键安装**：准备好授权的 TSIG Key 和 HTTPS 证书后执行 `./install.sh`。
- **白名单文件导入**：Web RPZ 页面支持 TXT（每行一个域名）和白名单 JSON，支持预览、去重和格式校验；导入只创建 `draft`，不会自动发布。
- **部署与发布引导**：按“连接 BIND → 审核并发布白名单 → 启用并验证 DENY”分阶段操作；发布会核验 Primary/Secondary 同步，失败或未验证不会提示完成。
- **可靠性与安全**：保留 `nsupdate + TSIG`、SOA/规则核对、审计、版本回滚和 `reconcile_required` 保护。

## 最短部署入口

```bash
git clone --branch v1.1.0 --single-branch \
  https://github.com/Bl4ckB1t7/dnsguard.git dnsguard
cd dnsguard
./install.sh
```

首次上线必须先审核并发布白名单，确认 Primary/Secondary 已同步，再由 BIND 管理员启用全局 DENY。DNSGuard 不自动安装、修改、reload 或 restart 生产 BIND，也不修改 `named.conf`、`response-policy` 或生产 Zone 文件。

## 升级注意事项

- 从 v1.0.1 升级的已初始化部署不会自动切换到 `global` 模式；历史策略和数据保持不变，迁移前请先备份。
- 生产 BIND 集群、TSIG、Zone Transfer 和 RPZ 优先级由管理员独立确认。
- 客户端收到 `NXDOMAIN` 不等于完整 QNAME 没有到达上游。隔离验收已保留部分 DNSSEC `DO=1` 查询可能上游外传的风险；本版本不宣称百分之百阻断 DNS 隧道。

## 验收资料

- [v1.1.0 全局 DENY 验收](docs/acceptance/v1.1.0-global-deny-acceptance.md)
- [v1.1.0 一键安装最终验收](docs/acceptance/v1.1.0-install-final-check.md)
- [DNS 隧道重新验收](docs/acceptance/v1.1.0-dns-tunnel-retest.md)

---

# DNSGuard v1.0.0

## 产品定位

DNSGuard（域盾）是企业 DNS 的 RPZ 控制面。BIND Primary/Secondary 仍是独立的
DNS 数据面，DNSGuard 不参与客户端 DNS 查询；即使控制面停止，BIND 继续提供已加载
的解析服务。

## 主要能力

- RPZ 白名单（passthru）和 A 记录重定向；
- Primary 动态更新、TSIG 认证和 Secondary NOTIFY/IXFR/AXFR 同步核验；
- 发布前规则校验、Zone 校验、SOA Serial 和实际解析效果验证；
- 并发发布互斥、不可变发布快照、失败诊断和 `reconcile_required` 人工核对状态；
- JSON 文件原子写入、备份、版本记录和受保护的审计哈希链；
- Bootstrap Token 保护的 Web 首次初始化向导；
- CSRF、Session、Cookie 安全属性、登录限速和管理操作审计；
- Docker Compose 非 root、只读根文件系统、内部 API 网络和 HTTPS 入口。
- 控制台 TLD DENY 数据状态：每日校验 IANA TLD 列表并显示数量、版本和同步状态；不自动修改 BIND 配置。

## 部署方式

V1.0 生产唯一支持 Docker Compose：

```bash
git checkout v1.0.0
cp deploy/docker/dnsguard.env.example deploy/docker/dnsguard.env
./scripts/docker-init.sh
docker compose up -d
```

完整安装、初始化、备份恢复、旧部署迁移和升级回滚流程见
[`deploy/docker/README.md`](deploy/docker/README.md)。V1.0 生产只支持 Docker Compose。

## 安全边界

- 生产 BIND 不放入 DNSGuard Compose，也不会被安装脚本自动重启或改写配置；
- 生产 TSIG、Bootstrap Token、HTTPS 私钥不进入镜像、Git 或普通日志；
- 初始化 TSIG 权限检查会明确提示一次临时 TXT 写入和删除；清理失败时必须人工处置；
- 发布失败不会未经核对自动重放或盲目回滚；
- 状态恢复不会被当作 BIND Zone 已经回滚，Zone 回滚必须创建新的受控发布任务。

## 已知限制

- 不使用数据库、Redis、消息队列或微服务；JSON 文件需要纳入受保护备份；
- Docker 备份必须在宿主机以 `DNSGUARD_BACKUP_MODE=docker` 执行，不能把容器内路径当作宿主机路径；
- `deploy/docker/dnsguard.env` 含敏感配置，必须与 TSIG/HTTPS 私钥一起通过显式敏感备份选项保护；
- RPZ 命中统计依赖挂载的 BIND 日志，未接入日志时不影响发布；
- 升级和回滚需要人工核对 BIND 集群状态，不提供未经验证的自动回滚。
- 旧版本主机进程部署需要按手册人工迁移到 `docker-data/`、`secrets/` 和 `tls/`；不会自动删除旧数据或覆盖现有环境。

## 升级和回滚

升级前先备份 `docker-data/`，必要时单独保护性备份 `secrets/` 和 `tls/`。应用回滚
只切换 DNSGuard 控制面版本，不会改变 BIND 当前 Zone。RPZ 规则回滚必须在后台选择
已审计版本并重新发布、验证 Primary/Secondary Serial 及实际解析效果。
