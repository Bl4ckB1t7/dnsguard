# DNSGuard v1.1.0 Docker Compose 交付手册（开发分支）

Docker Compose 是 DNSGuard 的推荐生产部署方式。Compose 只运行 DNSGuard
控制面：`dnsguard-api` 和 `dnsguard-web`。生产 BIND Primary/Secondary 必须继续
独立运行，不放入这个 Compose 项目，也不由 DNSGuard 代理客户端 DNS 查询。

## 1. 服务器要求

- Linux x86_64 主机，建议 Debian 12 或 Ubuntu 22.04/24.04。
- Docker Engine 24+ 和 Docker Compose Plugin 2.20+。
- `python3`、`openssl`、`curl` 和 `install`；不需要 Go、Node.js、npm、BIND 或其他主机级运行时。
- 到 Primary 的 TCP/UDP 53 连通性以及到全部 Secondary 的 SOA 查询连通性。
- 生产 RPZ TSIG key 文件和 HTTPS 证书/私钥。
- 管理入口只允许从管理网段访问；不要把管理端口直接暴露到公网。

## 2. 先准备 BIND RPZ 集群

DNSGuard 不会安装或管理生产 BIND。启动 Compose 前，请先准备 RPZ Primary、至少一台 Secondary、TSIG 动态更新权限、NOTIFY / IXFR / AXFR 和递归 DNS 的 `response-policy`。建议先阅读：[BIND RPZ 部署与 DNSGuard 对接](../../docs/bind-rpz-deployment.md)。

准备完成后，确认 DNSGuard 所在主机能够访问 Primary 和全部 Secondary 的 TCP/UDP 53 端口。不要把生产 BIND 放进本 Compose，也不要把生产 TSIG 写入 Git 或环境变量模板。

可使用仓库提供的一键只读检查脚本：`scripts/rpz-connect.sh`。配置模板为 `deploy/docker/rpz-connect.env.example`；脚本默认只检查连通性、SOA、Serial 和密钥权限，不会修改 BIND。TSIG 写权限测试必须显式使用 `--write-test --confirm WRITE-TEST`。

如果严格策略启用前需要准备初始白名单，可用对接脚本生成未发布 JSON（输入文件每行一个域名）：

```bash
./scripts/rpz-connect.sh \
  --env-file /path/to/rpz-connect.env \
  --whitelist-file /path/to/approved-domains.txt \
  --export-whitelist-json /path/to/whitelist-seed.json
install -d -m 0750 docker-data/bootstrap
install -m 0600 /path/to/whitelist-seed.json docker-data/bootstrap/whitelist-seed.json
```

在 `deploy/docker/dnsguard.env` 中加入：

```dotenv
RPZ_WHITELIST_SEED_FILE=/var/lib/dnsguard/bootstrap/whitelist-seed.json
```

这是初始化输入，不是 BIND Zone 文件。脚本不会执行 DNS UPDATE；初始化向导只会把它导入为草稿，管理员核对后仍需通过正常发布流程提交。初始 JSON 必须位于 `docker-data/` 对应的数据挂载内，权限不得对 other 开放；已有部署不会重新导入。

## 3. 获取正式版本

v1.1.0 尚未创建正式 Tag 或 Release。生产仍应固定使用已批准的版本 Tag；验收本分支前不要将其用于生产：

```bash
git clone --branch main --single-branch https://github.com/Bl4ckB1t7/dnsguard.git dnsguard
cd dnsguard
# v1.1.0 发布后再改为对应的正式 Tag
```

如果使用内部镜像仓库，也应固定镜像 digest 或已批准的版本号，不使用 `latest`。

## 4. 准备配置和密钥

```bash
cp deploy/docker/dnsguard.env.example deploy/docker/dnsguard.env
install -d -m 0750 docker-data secrets tls bind-logs
chmod 0640 deploy/docker/dnsguard.env
```

默认目录位于仓库根目录。也可以在 `deploy/docker/dnsguard.env` 中设置宿主机路径：

```dotenv
DNSGUARD_DATA_DIR=/srv/dnsguard/data
DNSGUARD_SECRET_DIR=/srv/dnsguard/secrets
DNSGUARD_TLS_DIR=/srv/dnsguard/tls
DNSGUARD_BIND_LOG_DIR=/srv/dnsguard/bind-logs
```

相对路径统一以仓库根目录为基准，而不是以 `deploy/docker/` 或当前 shell 目录为基准。
`docker-init.sh`、Compose、备份和恢复脚本会使用同一组解析结果；脚本会拒绝根目录、
仓库 `.git` 目录、目录重叠和符号链接路径。绝对路径必须由部署人员预先创建并明确授权，
脚本不会递归修改未配置的目录。

编辑 `deploy/docker/dnsguard.env`，至少设置：

- `AUTH_SECRET`、`MONITORING_TOKEN`：每个环境独立的随机值，至少 32 字符；
- `DNS_NODE_ADDRESSES`、`DNS_NODE_ALLOWED_CIDRS`；
- `RPZ_ZONE`、`RPZ_PRIMARY`、`RPZ_PRIMARY_PORT`；
- `RPZ_KEY_FILE=/run/dnsguard-secrets/rpz-manager.key`；
- v1.1.0 全局默认拒绝模式：`RPZ_DEFAULT_DENY_MODE=global`、预先配置的 `RPZ_GLOBAL_DENY_ZONE`、`RPZ_GLOBAL_DENY_RECURSOR` 和 `RPZ_GLOBAL_DENY_CHECK_NAME`；
- `RPZ_WHITELIST_SEED_FILE=/var/lib/dnsguard/bootstrap/whitelist-seed.json`，该文件由对接脚本生成并放入 `docker-data/bootstrap/`；
- 旧 v1.0.1 TLD 兼容路径默认关闭（`TLD_DENY_ENABLED=false`、`TLD_DENY_PUBLISH_ENABLED=false`）；旧状态文件保留用于升级兼容，不参与 v1.1.0 全局 DENY 可用性判断；
- `TRUSTED_PROXY_CIDRS` 和 HTTPS 反向代理选项（如使用企业入口）。

不要把真实值写入 Git：

```bash
openssl rand -hex 32
openssl rand -hex 32
install -m 0640 PATH_TO_PRODUCTION_RPZ_KEY secrets/rpz-manager.key
install -m 0644 PATH_TO_FULLCHAIN_PEM tls/fullchain.pem
install -o 101 -g 101 -m 0640 PATH_TO_PRIVATE_KEY tls/privkey.pem
umask 077
openssl rand -hex 32 > secrets/bootstrap.token
chown 10001:10001 secrets/bootstrap.token
chmod 0600 secrets/bootstrap.token
```

TSIG key、Bootstrap Token、证书和私钥只通过受保护的 bind mount 进入容器；项目不会
生成或修改生产 BIND 的 `named.conf`、TSIG 配置或服务状态。

## 5. 初始化、启动和健康检查

```bash
./scripts/docker-init.sh
docker compose up -d
docker compose ps
docker compose logs --tail=200 dnsguard-api
docker compose logs --tail=200 dnsguard-web
```

默认只有 Web 发布宿主机 443，API 没有宿主机端口。可用 Compose 插值修改入口：

```bash
DNSGUARD_WEB_BIND_IP=127.0.0.1 DNSGUARD_WEB_PORT=8443 docker compose up -d
```

访问 `https://管理地址/`。`/api/health` 只用于健康检查；管理 API 仍需要认证。
如果 443 已由企业 HTTPS 入口占用，使用反向代理并将 `DNSGUARD_WEB_PORT` 绑定到
管理网卡的内部端口，禁止使用明文 HTTP 管理页面。

容器重建不会丢失 `docker-data/`，也不会重新开放初始化向导：

```bash
docker compose down
docker compose up -d
docker compose ps
```

## 6. Web 首次初始化向导

1. 全局默认拒绝模式下，先确认 `docker-data/bootstrap/whitelist-seed.json` 已准备，且包含人工审核的初始白名单。
2. 从部署终端读取 `secrets/bootstrap.token`，不要通过聊天、日志或 URL 传递。
3. 在浏览器向导输入一次性 Bootstrap Token。
4. 设置管理员用户名和至少 12 位的管理员密码。
5. 添加一个 `primary` 和至少一个 `secondary` 节点；Primary 角色不能填成 Secondary。
6. 选择受保护目录中的 TSIG key，系统不会回显完整密钥。
7. 确认 RPZ Zone、Primary/Secondary 地址后执行检查。

向导先做只读 SOA、Zone、Serial 和网络检查。全局默认拒绝模式还会检查 deny Zone 的
Primary/Secondary SOA，以及管理员配置的递归测试名称是否返回 `NXDOMAIN`。勾选 TSIG 写权限检查后，系统会在
Primary RPZ Zone 写入随机临时 TXT 记录，然后立即删除。该步骤会真实修改一次
Primary，页面必须明确展示影响；如果写入成功但清理失败，不得继续初始化，应使用
相同 TSIG 人工删除提示中的临时记录并重新核对 Zone。

只有所有检查通过，RPZ 发布门禁才会打开。初始化完成后 Bootstrap Token 立即失效；
重复初始化、并发抢占和容器重建都必须被拒绝。初始化失败时不要删除 JSON 状态，先
查看 `docker compose logs dnsguard-api` 和 Primary 的审计/Zone 状态，再修正配置重试。

初始化后可在已认证后台修改管理员密码、节点配置和 TSIG 路径。任何变更都需要经过
认证、CSRF 校验并留下审计记录。

## 7. 持久化数据和权限

### v1.1.0 全局默认 DENY

新部署的正式策略是“白名单与 A 重定向优先，其余默认 DENY”。BIND 管理员必须先在
递归实例加载两个 RPZ Zone，并保证白名单 / 重定向 Zone 排在全局 deny Zone 前面：

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

## 8. 备份

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

## 9. 恢复演练和正式恢复

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

## 10. 升级和回滚

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

## 11. 常见错误

- `AUTH_SECRET` 或 `MONITORING_TOKEN` 是 `REPLACE_` 占位值：重新编辑 env。
- `RPZ_KEY_FILE is not readable`：检查 key 位于 `secrets/`，权限允许 UID 10001 读取。
- Bootstrap Token 权限不安全：使用 `chmod 0600`，并确认容器 API 用户可读。
- HTTPS 启动失败：检查 `tls/fullchain.pem` 和 `tls/privkey.pem` 的权限及证书匹配。
- 节点不可达：检查管理节点到 DNS 节点 53 端口、允许网段和容器出站策略。
- 初始化 TSIG 清理失败：暂停初始化，人工查询并删除临时 TXT，再核对 Serial。
- `reconcile_required`：不要重试发布；先取证并人工比对 Primary/Secondary 实际状态。

## 11. 旧部署一次性迁移

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
