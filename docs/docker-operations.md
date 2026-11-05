# DNSGuard Docker 高级运维

本文集中说明不适合放在首次安装主线中的内容：持久化目录、备份恢复、升级回滚、旧部署迁移和故障排查。生产部署入口见 [Docker 安装与初始化手册](../deploy/docker/README.md)。

## 持久化数据与权限

### v1.1.0 全局默认 DENY

新部署的正式策略是“白名单与 A 重定向优先，其余默认 DENY”。BIND 管理员必须先准备
两个 RPZ Zone，并保证白名单 / 重定向 Zone 排在全局 deny Zone 前面。首次上线时，建议
先只在递归实例启用白名单 / 重定向 Zone，待白名单发布并确认同步后再加入全局 deny：

```conf
response-policy {
    zone "RPZ_ZONE";
    zone "global-deny.rpz.local";
};
```

全局 deny Zone 由管理员独立创建，例如：

```dns
$ORIGIN global-deny.rpz.local.
* IN CNAME .
```

DNSGuard 不创建、修改、reload 或 restart BIND，也不会在初始化时向该 Zone 写入规则。
初始化仅只读检查 deny Zone 的 Primary / Secondary SOA、根级通配触发项和管理员配置的
递归测试名称。`NXDOMAIN` 只代表客户端看到的 RCODE；是否有被拒绝 QNAME 到达上游，必须在
目标 BIND 配置中单独观测。`qname-wait-recurse`、DNSSEC 和其他递归选项由 BIND 管理员
独立评估，不能把本项目的隔离结果直接推广到生产。

首次上线必须按以下顺序操作：先准备并人工审核白名单 JSON，再完成初始化、核对草稿、发布白名单并确认 Primary/Secondary 同步，最后才把全局 deny Zone 加入 BIND 的 `response-policy`。如需在 deny 尚未启用时完成首次初始化，可临时设置 `RPZ_GLOBAL_DENY_SETUP_DEFERRED=true`；该模式会明确显示递归拒绝检查未执行，不能替代最终验证。白名单发布和同步完成后启用 deny，并移除该变量；已初始化服务在重启时会拒绝保留该临时配置。

全局模式首次初始化必须准备经过人工审核的白名单 JSON：

```dotenv
RPZ_DEFAULT_DENY_MODE=global
RPZ_GLOBAL_DENY_ZONE=global-deny.rpz.local
RPZ_GLOBAL_DENY_RECURSOR=RECURSOR_IP:53
RPZ_GLOBAL_DENY_CHECK_NAME=KNOWN_RESOLVABLE_DENY_TEST_NAME
RPZ_WHITELIST_SEED_FILE=/var/lib/dnsguard/bootstrap/whitelist-seed.json
TLD_DENY_ENABLED=false
TLD_DENY_PUBLISH_ENABLED=false
```

对接脚本只生成 JSON，不写入 BIND；初始化将其导入为未发布草稿。现有 v1.0.1 部署的
TLD 状态、发布历史和备份字段不会被删除，升级时不会强制重新初始化；升级后是否切换
到全局模式，必须由管理员先完成 BIND 侧准备和隔离验证。

已初始化的 v1.0.1 状态没有 `PolicyMode` 字段时，按历史 `legacy` 处理，不会因为把
环境变量改成 `global` 就自动切换。若环境变量模式与持久化模式不一致，API 会 fail-closed
并提示“策略模式不一致”；不会清空、覆盖、重新发布 RPZ，也不会修改生产 BIND。管理员
应先完成备份、隔离验证和受控迁移，再让配置模式与持久化状态一致。

## 备份

Docker 备份必须在**宿主机**执行，不能直接把 `/var/lib/dnsguard` 当作宿主机路径。
备份脚本的 Docker 模式会读取 bind mount 的真实目录，并递归覆盖规则、节点、认证、
审计及轮转文件、初始化状态、发布任务、版本、Telegram 配置和 RPZ 产物；不会把
`.lock`、`.tmp` 或 `.pid` 文件恢复回去。

只备份可重建的 DNSGuard 状态：

```bash
docker compose stop
BACKUP_DIR=/secure/backup/dnsguard \
DNSGUARD_BACKUP_MODE=docker \
DNSGUARD_DATA_DIR="$PWD/docker-data" \
DNSGUARD_SECRET_DIR="$PWD/secrets" \
DNSGUARD_TLS_DIR="$PWD/tls" \
./scripts/backup-dnsguard.sh
```

需要同时备份 TSIG 和 HTTPS 私钥时，必须显式启用敏感备份，并将归档复制到受控的
密钥备份系统：

```bash
BACKUP_INCLUDE_SENSITIVE=true \
BACKUP_DIR=/secure/backup/dnsguard-sensitive \
DNSGUARD_BACKUP_MODE=docker \
DNSGUARD_DATA_DIR="$PWD/docker-data" \
DNSGUARD_SECRET_DIR="$PWD/secrets" \
DNSGUARD_TLS_DIR="$PWD/tls" \
DNSGUARD_ENV_FILE="$PWD/deploy/docker/dnsguard.env" \
./scripts/backup-dnsguard.sh
chmod 0600 /secure/backup/dnsguard-sensitive/dnsguard-*.tar.gz
sha256sum /secure/backup/dnsguard-sensitive/dnsguard-*.tar.gz > /secure/backup/dnsguard-sensitive/SHA256SUMS
```

归档自身带有每个文件的 SHA-256 manifest；外部 `SHA256SUMS` 用于传输完整性。备份
目录应为 `0700`，归档应为 `0600`。默认不备份 TSIG/私钥，避免普通状态备份扩大
密钥暴露范围。`deploy/docker/dnsguard.env` 同样包含 `AUTH_SECRET` 等敏感配置，只有
显式设置 `BACKUP_INCLUDE_SENSITIVE=true` 且通过 `DNSGUARD_ENV_FILE` 指定时才会以
归档内 `config/dnsguard.env` 备份；不要把这类归档放入普通备份库。

## 恢复演练和正式恢复

先停止控制面并确认备份校验通过：

```bash
docker compose down
sha256sum -c /secure/backup/dnsguard-sensitive/SHA256SUMS
```

恢复普通状态：

```bash
DNSGUARD_BACKUP_MODE=docker \
DNSGUARD_DATA_DIR="$PWD/docker-data" \
DNSGUARD_SECRET_DIR="$PWD/secrets" \
DNSGUARD_TLS_DIR="$PWD/tls" \
./scripts/restore-dnsguard.sh /secure/backup/dnsguard/dnsguard-YYYYMMDDTHHMMSSZ.tar.gz
```

恢复包含 TSIG/证书的敏感归档必须明确 opt-in：

```bash
RESTORE_INCLUDE_SENSITIVE=true \
DNSGUARD_BACKUP_MODE=docker \
DNSGUARD_DATA_DIR="$PWD/docker-data" \
DNSGUARD_SECRET_DIR="$PWD/secrets" \
DNSGUARD_TLS_DIR="$PWD/tls" \
DNSGUARD_ENV_FILE="$PWD/deploy/docker/dnsguard.env" \
./scripts/restore-dnsguard.sh /secure/backup/dnsguard-sensitive/dnsguard-YYYYMMDDTHHMMSSZ.tar.gz
```

恢复脚本会先完整校验 manifest、成员路径、哈希、重复成员、符号链接、文件数量和解压
大小，再写入目标。默认不会覆盖已有文件；确实要覆盖时必须停止 Compose、确认备份并
显式设置 `RESTORE_ALLOW_OVERWRITE=true`。覆盖过程中会先保存临时回退副本，写入失败会
尝试恢复原文件。`config/dnsguard.env` 始终按敏感文件处理，修改 manifest 的
`sensitive` 标记不能绕过 `RESTORE_INCLUDE_SENSITIVE=true`。

恢复开始后会在 `docker-data/.restore-in-progress.json` 写入事务标记，并在每个文件和
目录完成必要的同步后删除。该标记存在时，备份会拒绝继续，API 健康检查保持失败，
初始化脚本也会拒绝启动；这不是跨文件完全原子事务，进程或主机突然断电后必须保持
Compose 停止，检查回退结果和备份内容，必要时重新执行恢复。确认人工核对完成后才能
删除该标记并启动服务。恢复的 JSON 状态也不代表 BIND Zone 已经回滚，必须重新核对
Primary/Secondary 的 SOA Serial 和实际解析结果。

恢复后：

1. 检查文件权限和 JSON 完整性；
2. `docker compose up -d`，确认容器健康；
3. 登录后台，检查规则、节点、版本、任务和审计链；
4. 查询 Primary/Secondary 的 SOA Serial 和关键 RPZ 解析结果；
5. 若任务显示 `reconcile_required`，先人工核对 BIND 实际状态，不要自动重放或把旧 JSON 误当作 Zone 回滚；
6. 恢复旧状态不会修改生产 BIND 当前 Zone，也不能宣称 RPZ 已回滚。需要回滚 Zone 时，必须在后台创建新的受控 RPZ 发布/回滚任务并完成集群验证。

## 升级和回滚

升级前：

```bash
docker compose stop
# 完成普通状态备份，必要时完成敏感备份
git fetch --tags origin
git checkout TARGET_TAG
docker compose build --pull
docker compose up -d
docker compose ps
```

先检查健康、登录、节点状态和发布任务，再进行任何 RPZ 操作。JSON 数据文件保持
向后兼容；升级失败时保留同一组 `docker-data/`、`secrets/` 和 `tls/`：

```bash
docker compose down
git checkout PREVIOUS_TAG
docker compose build --pull
docker compose up -d
```

**应用版本回滚不等于 RPZ Zone 回滚。** 回到旧应用只改变控制面程序；BIND 仍保持
当前已加载 Zone。RPZ 规则回滚必须由管理员选择已审计版本、创建新的发布任务，并
验证 Primary/全部 Secondary Serial 和实际解析效果。禁止清空 `docker-data`、直接
覆盖状态文件或未经验证自动回滚。

## 常见错误

- `AUTH_SECRET` 或 `MONITORING_TOKEN` 是 `REPLACE_` 占位值：重新编辑 env。
- `RPZ_KEY_FILE is not readable`：检查 key 位于 `secrets/`，权限允许 UID 10001 读取。
- Bootstrap Token 权限不安全：使用 `chmod 0600`，并确认容器 API 用户可读。
- HTTPS 启动失败：检查 `tls/fullchain.pem` 和 `tls/privkey.pem` 的权限及证书匹配。
- 节点不可达：检查管理节点到 DNS 节点 53 端口、允许网段和容器出站策略。
- 初始化 TSIG 清理失败：暂停初始化，人工查询并删除临时 TXT，再核对 Serial。
- `reconcile_required`：不要重试发布；先取证并人工比对 Primary/Secondary 实际状态。

## 旧部署一次性迁移

V1.0 生产只支持 Docker Compose。旧版本的主机进程部署不会被自动删除、停止或覆盖，
也不会被 `docker-init.sh` 自动迁移。迁移前由维护人员完成完整备份，并保留旧目录副本。

旧部署迁移步骤：

1. 停止旧 DNSGuard 控制面，确认没有旧进程占用 Web/API 端口；生产 BIND 不需要停止。
2. 创建新目录：`docker-data/`、`secrets/`、`tls/` 和 `bind-logs/`。
3. 将旧的状态、节点、认证、审计、版本、发布任务、初始化状态、Telegram 配置和 RPZ
   产物复制到 `docker-data/`。
4. 将旧 TSIG 复制到 `secrets/rpz-manager.key`，将证书和私钥复制到 `tls/`；不要把密钥
   放进环境文件或镜像。
5. 将 `docker-data/` 与 TSIG 的所有者修正为 `10001:10001`，TLS 私钥允许 `101:101`
   读取，认证文件为 `0600`，Bootstrap Token 为 `0600`，目录至少为 `0750`。
6. 检查 `deploy/docker/dnsguard.env` 的容器内路径。宿主机备份命令必须使用
   `DNSGUARD_DATA_DIR`、`DNSGUARD_SECRET_DIR` 和 `DNSGUARD_TLS_DIR`，不能把
   `/var/lib/dnsguard` 当作宿主机路径。
7. 执行 `./scripts/docker-init.sh` 和 `docker compose config`，确认已有认证文件和节点
   配置没有被覆盖，再执行 `docker compose up -d`。
8. 登录后台，核对节点、RPZ 规则、版本、发布任务、审计哈希链和 Telegram 配置；逐台
   查询 BIND Primary/Secondary 的 SOA Serial，并抽查关键 RPZ 解析效果。
9. 验证完成后再人工下线旧控制面。迁移不会修改生产 BIND 的配置、进程或当前 Zone。

恢复旧 JSON 只恢复 DNSGuard 控制面状态，不代表 BIND Zone 已回滚。任何 RPZ 回滚都必须
通过新的受控发布任务完成 Primary/Secondary 和实际解析验证。
