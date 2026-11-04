# DNSGuard Docker Compose 生产部署

Docker Compose 是 DNSGuard 的推荐生产部署方式。Compose 只运行 DNSGuard 控制面：`dnsguard-api` 和 `dnsguard-web`。生产 BIND Primary/Secondary 必须继续独立运行在现有主机或 DNS 集群中，不放入这个 Compose 项目。

## 前置条件

- Docker Engine 和 Docker Compose Plugin。
- 到生产 BIND Primary 的 TCP/UDP 53 动态更新和 SOA 查询连通性。
- 到所有 Secondary 的 SOA 查询连通性。
- 生产 RPZ TSIG key 文件；本项目不会生成、修改或安装 BIND key。
- HTTPS 证书和私钥。
- `python3`（仅用于一次性初始化节点 JSON，不需要 Go、Node.js 或 npm）。

目标服务器不需要安装 Go、Node.js、npm、bind9-utils 或 systemd 服务。

## 首次安装

```bash
git clone https://github.com/Bl4ckB1t7/dnsguard.git
cd dnsguard
cp deploy/docker/dnsguard.env.example deploy/docker/dnsguard.env
```

编辑 `deploy/docker/dnsguard.env`，至少替换 `AUTH_SECRET`、`MONITORING_TOKEN`、`DNS_NODE_ADDRESSES`、`DNS_NODE_ALLOWED_CIDRS`、`RPZ_PRIMARY` 和 `RPZ_PRIMARY_PORT`。

准备生产文件：

```bash
install -d -m 0750 secrets tls bind-logs
install -m 0640 PATH_TO_PRODUCTION_RPZ_KEY secrets/rpz-manager.key
install -m 0644 PATH_TO_FULLCHAIN_PEM tls/fullchain.pem
install -o 101 -g 101 -m 0640 PATH_TO_PRIVATE_KEY tls/privkey.pem
```

运行安全初始化：

```bash
./scripts/docker-init.sh
```

初始化脚本会校验生产参数、创建节点配置、只在不存在时生成 bcrypt 管理员认证文件、构建固定版本镜像并设置 UID/GID `10001:10001` 权限。它不会覆盖已有认证、节点、规则、审计、版本、发布任务或 TSIG 文件，也不会生成或修改生产 BIND 的 TSIG 配置。

启动：

```bash
docker compose up -d
docker compose ps
```

默认只有 Web 容器发布宿主机 443，API 没有 `ports` 配置，只能通过内部网络被 Nginx 访问。若 443 已由企业入口占用，可设置 `DNSGUARD_WEB_PORT=8443`，再由企业 HTTPS 反向代理转发；浏览器到 Web 入口仍必须使用 HTTPS。

## 持久化和权限

默认 Bind Mount：

```text
docker-data/     JSON 状态、节点、认证、审计、版本、任务、Telegram、RPZ 产物
secrets/         TSIG key，只读挂载到 API
tls/             Web HTTPS 证书，只读挂载到 Nginx
bind-logs/       BIND RPZ 日志，只读挂载到 API
```

API 以非 root `10001:10001` 运行，根文件系统只读，仅 `docker-data/` 可写。Web 根文件系统只读，Nginx 缓存、运行时 PID 和临时目录使用 tmpfs。Compose 启用 `no-new-privileges`、丢弃 Linux capabilities、进程/内存/CPU 限制和 Docker 日志轮转。

不要提交 `deploy/docker/dnsguard.env`、`docker-data/`、`secrets/`、`tls/` 或 `bind-logs/`。

## 日常运维

```bash
docker compose ps
docker compose logs --tail=200 dnsguard-api
docker compose logs --tail=200 dnsguard-web
curl -k https://DNSGUARD_DOMAIN/api/health
docker compose restart
docker compose stop
docker compose start
```

DNSGuard 停止时，BIND 继续使用当前已加载 Zone 独立提供解析。

## 备份、升级和回滚

```bash
docker compose stop
BACKUP_DIR=/secure/backup/path \
  DNSGUARD_ENV_FILE="$PWD/deploy/docker/dnsguard.env" \
  ./scripts/backup-dnsguard.sh
```

升级前备份，然后从目标 tag 或 commit 构建：

```bash
git fetch --tags origin
git checkout TARGET_TAG_OR_COMMIT
docker compose build --pull
docker compose up -d
docker compose ps
```

回滚时回到上一版本，保留同一组 `docker-data/`、`secrets/` 和 `tls/`：

```bash
docker compose down
git checkout PREVIOUS_TAG_OR_COMMIT
docker compose build
docker compose up -d
```

不要删除 `docker-data/` 来修复启动问题。状态、审计或发布任务异常时，应先人工核对 BIND 状态，不自动重放或盲目回滚。

卸载但保留数据：

```bash
docker compose down
```

确认备份后再执行 `docker compose down --rmi local` 和 `rm -rf docker-data secrets tls bind-logs`。

## 安全边界

- 生产 `APP_ENV=production` 和 `AUTH_ENABLED=true` 不能关闭。
- API 不暴露宿主机端口，不挂载 Docker Socket，不使用 privileged 或 host network。
- 生产 TSIG 不进入镜像、环境变量、Git 或构建日志。
- 本部署不会启动 BIND，也不会自动向生产 BIND 写入规则；只有管理员在页面发起发布时，DNSGuard 才通过已配置 TSIG 执行 `nsupdate`。
