# 域盾 DNSGuard

![域盾 DNSGuard](docs/images/dnsguard-overview.png)

**域盾（DNSGuard）是一个简单、可审计的企业 DNS RPZ 管理平台。**

它把日常的 RPZ 规则维护、发布、同步检查和操作审计集中到一个 Web 页面中，减少手工修改 Zone 文件和重启 BIND 带来的风险。

> DNSGuard 是 **DNS 控制面**。BIND Primary 和 Secondary 仍然独立提供 DNS 解析；即使 DNSGuard 停止，BIND 也会继续使用当前已加载的 Zone 工作。

## 它解决什么问题？

企业 DNS 运维中，常见问题是：

- 手工修改 RPZ，容易写错格式；
- 多台 Secondary 同步后，难以确认 Serial 是否一致；
- 规则是谁加的、什么时候发布的，不容易追踪；
- 发布失败后，人工判断和恢复过程不统一。

DNSGuard 的目标很简单：

**在一个页面管理规则，点击发布，系统负责检查结果并留下记录。**

## 你可以用它做什么？

- 管理 RPZ 白名单（passthru）；
- 将指定域名重定向到 A 记录；
- 管理一台 Primary 和多台 Secondary；
- 通过 `nsupdate + TSIG` 更新 Primary；
- 检查 Secondary 的 NOTIFY / IXFR / AXFR 同步结果；
- 发布后核对 SOA Serial 和实际解析效果；
- 查看版本、发布任务和审计记录；
- 在故障状态下保留人工核对和恢复路径。

## 工作方式

```text
管理员浏览器
      │ HTTPS
      ▼
DNSGuard Web + API
      │
      ├── JSON 文件保存规则、节点、任务和审计记录
      ├── nsupdate + TSIG 更新 BIND Primary
      └── dig 检查 Primary / Secondary 的 Serial 和解析结果
                                      │
                         NOTIFY / IXFR / AXFR
                                      ▼
                              BIND Secondary 集群
```

生产环境中，DNSGuard 不接管客户端 DNS 查询，也不会安装、重启或修改生产 BIND 服务。

## 生产部署：只需要 Docker Compose

V1.0 生产环境只支持 Docker Compose。目标服务器不需要安装 Go、Node.js、npm，也不需要手动创建服务文件。

### 1. 获取代码

```bash
git clone https://github.com/Bl4ckB1t7/dnsguard.git
cd dnsguard
```

### 2. 准备配置和密钥

```bash
cp deploy/docker/dnsguard.env.example deploy/docker/dnsguard.env
install -d -m 0750 docker-data secrets tls bind-logs
```

编辑 `deploy/docker/dnsguard.env`，填写：

- BIND Primary 地址和 RPZ Zone；
- Secondary 地址允许范围；
- `AUTH_SECRET` 和 `MONITORING_TOKEN`；
- 发布超时和重试参数。

将生产文件放入受保护目录：

```bash
install -m 0640 PATH_TO_PRODUCTION_RPZ_KEY secrets/rpz-manager.key
install -m 0644 PATH_TO_FULLCHAIN_PEM tls/fullchain.pem
install -o 101 -g 101 -m 0640 PATH_TO_PRIVATE_KEY tls/privkey.pem

umask 077
openssl rand -hex 32 > secrets/bootstrap.token
chown 10001:10001 secrets/bootstrap.token
chmod 0600 secrets/bootstrap.token
```

不要把 TSIG、Bootstrap Token、HTTPS 私钥、生产环境文件或 `docker-data/` 提交到 Git。

### 3. 启动

```bash
./scripts/docker-init.sh
docker compose up -d
docker compose ps
```

默认只有 Web 容器对外提供 HTTPS，API 只在 Docker 内部网络中通信。

## 第一次登录

浏览器打开 HTTPS 地址后，系统会自动进入初始化页面：

1. 从服务器上的 `secrets/bootstrap.token` 读取 Bootstrap Token；
2. 创建管理员账号和密码；
3. 添加 BIND Primary；
4. 添加一台或多台 Secondary；
5. 配置 TSIG 并执行连接检查；
6. 检查通过后开启 RPZ 发布。

Bootstrap Token 只用于首次初始化，初始化完成后自动失效。已有数据升级时不会重新开放初始化页面，也不会覆盖已有管理员和节点配置。

## 日常操作

在“RPZ 规则”中添加、修改或删除规则，然后通过“发布”提交到 BIND Primary。系统会：

1. 检查规则和 Zone 格式；
2. 固定本次发布的规则快照；
3. 使用 TSIG 更新 Primary；
4. 等待 Secondary 同步；
5. 检查各节点 SOA Serial；
6. 验证关键域名的实际解析结果；
7. 保存发布任务和审计记录。

如果 Primary 成功但部分 Secondary 没有同步，系统会显示同步异常，不会把整个集群直接标记为成功，也不会未经核对自动回滚。

常用命令：

```bash
docker compose ps
docker compose logs --tail=200 dnsguard-api
docker compose logs --tail=200 dnsguard-web
docker compose stop
docker compose start
```

## 备份与恢复

规则、节点、认证、审计、版本和发布任务都保存在 `docker-data/`，需要纳入备份。

普通状态备份：

```bash
docker compose stop
DNSGUARD_BACKUP_MODE=docker \
DNSGUARD_DATA_DIR="$PWD/docker-data" \
DNSGUARD_SECRET_DIR="$PWD/secrets" \
DNSGUARD_TLS_DIR="$PWD/tls" \
BACKUP_DIR=/secure/backup/dnsguard \
./scripts/backup-dnsguard.sh
```

TSIG、HTTPS 私钥和含有 `AUTH_SECRET` 的环境文件属于敏感数据，只有明确需要时才备份：

```bash
BACKUP_INCLUDE_SENSITIVE=true \
DNSGUARD_ENV_FILE="$PWD/deploy/docker/dnsguard.env" \
DNSGUARD_BACKUP_MODE=docker \
DNSGUARD_DATA_DIR="$PWD/docker-data" \
DNSGUARD_SECRET_DIR="$PWD/secrets" \
DNSGUARD_TLS_DIR="$PWD/tls" \
BACKUP_DIR=/secure/backup/dnsguard-sensitive \
./scripts/backup-dnsguard.sh
```

恢复前必须停止 Compose。敏感文件恢复必须显式设置 `RESTORE_INCLUDE_SENSITIVE=true`。恢复 JSON 不等于回滚 BIND Zone；恢复后仍需人工核对 Primary、Secondary 的 Serial 和实际解析结果。

详细的备份、恢复、升级、回滚和旧部署迁移说明见：

- [`deploy/docker/README.md`](deploy/docker/README.md)
- [`RELEASE_NOTES.md`](RELEASE_NOTES.md)

## 安全边界

- 生产 BIND 不放入 DNSGuard Compose；
- API 不直接暴露宿主机端口；
- 容器使用非 root 用户和 HTTPS；
- TSIG 不进入镜像、Git 或普通日志；
- 管理操作使用认证、Session、CSRF 和审计保护；
- 发布失败时保留诊断证据，不盲目重放或自动回滚；
- 不要在生产环境运行故障注入测试。

## 本地开发和隔离测试

本地开发仍可使用 Go 和 React，但这不是生产部署方式：

```bash
npm ci
npm run build
(cd server && go test ./... -count=1)
```

完整隔离验收：

```bash
./tests/backup-restore.sh
./tests/docker-initialization-wizard.sh
./tests/docker-production-deployment.sh
./tests/bind-cluster/run-acceptance.sh
```

这些测试使用独立 Docker 网络、测试 TSIG 和临时目录，不连接生产 DNS。

## 许可证

本项目使用 [MIT License](LICENSE)。
