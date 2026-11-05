# DNSGuard Docker Compose 安装手册

DNSGuard 生产环境只支持 Docker Compose。Compose 只运行 DNSGuard 控制面：
`dnsguard-api` 和 `dnsguard-web`。生产 BIND Primary/Secondary 必须独立运行，DNSGuard
不会安装、修改、代理或重启 BIND。

## 服务器要求

- Debian 12 或 Ubuntu 22.04/24.04，x86_64。
- Docker Engine 24+、Docker Compose Plugin 2.20+。
- 主机可访问 BIND Primary/Secondary 的 DNS、SOA 和必要的 AXFR 路径。
- 已准备 TSIG Key、HTTPS 证书和私钥。
- 管理入口只允许从管理网段访问，不要直接暴露公网。

不需要在目标服务器安装 Go、Node.js、npm 或 BIND。

## 第 1 步：准备现有 BIND

由 BIND 管理员提前完成：

1. Primary 和至少一台 Secondary 正常运行。
2. 创建白名单/A 重定向 RPZ Zone，并配置动态更新 TSIG。
3. 配置 NOTIFY、IXFR/AXFR 和必要的只读 SOA/AXFR 检查权限。
4. 如采用 v1.1.0 全局 DENY，创建独立 `global-deny` RPZ Zone，例如：

   ```dns
   $ORIGIN global-deny.rpz.local.
   * IN CNAME .
   ```

5. 首次上线时，先不要把 deny Zone 加入递归 `response-policy`；白名单/A 重定向 Zone 必须优先。

旧版 v1.0.1 的 `tld-deny.rpz.local` 仅作为兼容 Zone 保留；v1.1.0 及以后使用
`global-deny.rpz.local` 作为全局 DENY Zone。

DNSGuard 不会自动编辑 `named.conf`、`response-policy` 或 Zone 文件。详细 BIND 配置见
[BIND RPZ 对接文档](../../docs/bind-rpz-deployment.md)。

### BIND 位于另一套 Docker 网络时

如果 BIND 在独立物理机或虚拟机上，直接在 Web 初始化和节点配置中填写该机器可达的
DNS 地址即可，不需要使用下面的 override。

如果 BIND 在另一套 Docker 网络中，先由 BIND 管理员确认网络已经存在，然后使用仓库根目录的
`compose.bind-network.yaml`。该文件只把 `dnsguard-api` 加入指定的**外部网络**；`dnsguard-web`
仍只连接 `dnsguard-internal`。DNSGuard 不创建、修改或删除 BIND 网络。

```bash
# 使用已经存在的 BIND Docker 网络名称；不要填写宿主机映射端口
export DNSGUARD_BIND_NETWORK=existing-bind-network
docker network inspect "$DNSGUARD_BIND_NETWORK" >/dev/null

docker compose --env-file deploy/docker/dnsguard.env \
  -f compose.yaml -f compose.bind-network.yaml config
docker compose --env-file deploy/docker/dnsguard.env \
  -f compose.yaml -f compose.bind-network.yaml up -d
```

容器内的 DNSGuard API 必须使用 BIND 容器在该网络上的可达地址和 `53` 端口（例如
`BIND_CONTAINER_IP:53` 或该网络中的 DNS 服务名）。宿主机上执行的对接脚本才使用 BIND
Compose 暴露的映射端口，例如 `127.0.0.1:15353`；不要把 `127.0.0.1:15353` 填入 API
容器配置，因为容器内的 `127.0.0.1` 指向 DNSGuard API 自身。

API 重建时继续使用同一组 Compose 文件，外部网络连接会由 Compose 自动恢复：

```bash
docker compose --env-file deploy/docker/dnsguard.env \
  -f compose.yaml -f compose.bind-network.yaml up -d --force-recreate dnsguard-api
```

若 `DNSGUARD_BIND_NETWORK` 未设置，或指定的外部网络不存在，Compose 会在启动前报错并退出；
它不会自动创建网络。未使用 override 时，正式 `compose.yaml` 的默认网络架构保持不变。

首次安装时不需要再手动执行 `docker network connect`，直接使用一键入口即可：

```bash
export DNSGUARD_BIND_NETWORK=your-existing-bind-network
./install.sh
```

安装脚本会先检查外部网络，再让 `docker-init.sh`、Compose 启动和状态查看使用同一组文件。
普通独立 BIND 部署不设置该变量，直接执行 `./install.sh` 即可。

## 第 2 步：获取代码并一键准备

正式部署使用已批准的版本 Tag。v1.1.0 发布后使用：

```bash
git clone --branch v1.1.0 --single-branch \
  https://github.com/Bl4ckB1t7/dnsguard.git dnsguard
cd dnsguard
chmod 0750 install.sh
```

执行：

```bash
./install.sh
```

首次执行只需要按提示提供 BIND Primary、递归 DNS、TSIG Key 和 HTTPS 证书/私钥。脚本会自动生成安全的 `AUTH_SECRET`、`MONITORING_TOKEN` 和 Bootstrap Token，并创建目录、校验权限、构建镜像、启动 API/Web。它不会生成不可信的自签名证书。

如需无人值守，可在执行前提供 `DNSGUARD_PRIMARY`、`DNSGUARD_RECURSOR`、`RPZ_TSIG_SOURCE`、`TLS_CERT_SOURCE` 和 `TLS_KEY_SOURCE`。已有 `deploy/docker/dnsguard.env`、密钥、证书和数据不会覆盖。

Bootstrap Token 不会打印到普通日志或聊天输出；按脚本最后输出的受保护路径在部署主机上读取，例如：

```bash
cat ./secrets/bootstrap.token
```

如果设置了自定义 `DNSGUARD_SECRET_DIR`，请改为读取该目录下的
`bootstrap.token`；安装脚本最后输出的受保护路径始终是最终依据。不要把 Token
放进截图、工单或聊天。重复执行安装不会重新生成或覆盖已有 Token。

### TSIG Key：已有 Primary 与新建 Primary

- **已有 BIND Primary（默认推荐）**：复制 Primary 当前已授权、与 `update-policy` 匹配的现有 Key。安装脚本只复制一次，不会替换目标文件，也不会修改 BIND。
- **新建 BIND Primary**：由 BIND 管理员在受保护的 DNS 管理主机生成 Key，并把同一份 Key 配置到 Primary 和 DNSGuard；重新生成后必须同步修改 Primary，否则 `nsupdate` 会认证失败。

生成新 Key 的示例（仅由 BIND 管理员执行，不会自动写入生产 BIND）：

```bash
KEY_DIR=/secure/dnsguard-keys
umask 077
install -d -m 0700 "$KEY_DIR"
tsig-keygen -a hmac-sha256 dnsguard-rpz > "$KEY_DIR/rpz-manager.key"
chmod 0640 "$KEY_DIR/rpz-manager.key"
```

然后先将该 Key 加入 Primary 的受保护配置并完成 BIND 侧检查，再运行：

```bash
export RPZ_TSIG_SOURCE="$KEY_DIR/rpz-manager.key"
./install.sh
```

安装前会检查 Key 是否为普通文件、不可被 other 读取、包含 BIND `key`/`algorithm`/`secret` 配置块；失败时会给出修复提示，但不会打印密钥内容。通常应使用 `0600` 或 `0640`，不要改成 `0644`。

高级方式仍可手动准备文件，但不建议新安装使用：

```bash
KEY_SOURCE=/secure/dnsguard-keys/rpz-manager.key
CERT_SOURCE=/secure/dnsguard-tls/fullchain.pem
PRIVATE_KEY_SOURCE=/secure/dnsguard-tls/privkey.pem
install -D -m 0640 "$KEY_SOURCE" secrets/rpz-manager.key
install -D -m 0644 "$CERT_SOURCE" tls/fullchain.pem
install -D -m 0640 "$PRIVATE_KEY_SOURCE" tls/privkey.pem
umask 077
openssl rand -hex 32 > secrets/bootstrap.token
chown 10001:10001 secrets/bootstrap.token
chmod 0600 secrets/bootstrap.token
```

初次上线时 deny Zone 尚未加入 `response-policy`，临时在 env 中启用：

```dotenv
RPZ_GLOBAL_DENY_SETUP_DEFERRED=true
```

该变量只用于首次分阶段初始化；初始化完成后重启服务会拒绝保留它。

## 第 3 步：只读对接检查和白名单准备

先执行只读检查：

```bash
RPZ_CONNECT_ENV="$PWD/.local/rpz-connect.env"
mkdir -p "$(dirname "$RPZ_CONNECT_ENV")"
cp deploy/docker/rpz-connect.env.example "$RPZ_CONNECT_ENV"
./scripts/rpz-connect.sh --env-file "$RPZ_CONNECT_ENV"
```

默认只检查工具、TSIG 文件权限、Primary/Secondary 连通性、SOA Serial 和同步一致性，不修改 BIND。

登录后的 RPZ 规则页面可以直接导入人工审核的 TXT 或 JSON。TXT 每行一个域名：

```text
baidu.com
qq.com
example.org
```

也可以继续使用对接脚本导出 JSON：

```bash
./scripts/rpz-connect.sh --env-file "$RPZ_CONNECT_ENV" \
  --whitelist-file approved-domains.txt \
  --export-whitelist-json whitelist-seed.json
```

导入文件只生成 `draft`，不会自动写入 BIND；请审核后点击发布。

`RPZ_GLOBAL_DENY_SETUP_DEFERRED=true` 由一键安装首次写入，允许先完成初始化和白名单导入；白名单发布、同步及业务验证完成后，再由 BIND 管理员启用 deny Zone 并移除该临时配置。

一键安装会要求提供一个启用 DENY 前确实可解析的测试域名，并先执行正常解析基线；不能使用 `blocked.example.com` 或示例占位名。启用后，递归检查会复用已持久化的基线，避免把一个原本不存在的域名误判为 RPZ 拒绝成功。

## 第 4 步：启动和完成初始化

```bash
docker compose --env-file deploy/docker/dnsguard.env logs --tail=100 dnsguard-api
```

打开 `https://管理地址/`，按向导完成：

1. 输入一次性 Bootstrap Token；
2. 设置管理员账户和密码；
3. 添加一个 Primary 和至少一个 Secondary，确认角色正确；
4. 选择受保护目录中的 TSIG Key；
5. 执行只读 SOA、Zone、Serial、连通性和全局 deny 检查。

全局模式下，白名单 JSON 会被导入为 `draft`。页面中的“导入成功”不代表已经发布；此时 `Published` 应为空。

初始化完成后，后台顶部会显示三阶段引导：先确认 BIND 节点健康，再在规则页审核并发布白名单，最后由 BIND 管理员启用 deny Zone。引导只把实际已发布且所有节点健康的状态显示为“已同步”；全局 DENY 检查失败或未验证时不会显示成功。

## 第 5 步：发布白名单并确认同步

在已认证后台核对所有白名单规则，确认无误后使用正常发布流程：

1. 提交白名单发布任务；
2. 等待任务状态为成功；
3. 检查 Primary SOA Serial；
4. 逐台检查 Secondary SOA Serial 和关键规则解析；
5. 验证白名单及任意层级子域名放行；
6. 配置并发布需要的 A 重定向，确认返回预期 IPv4。

发布失败、同步异常或状态为 `reconcile_required` 时停止切换，不要启用全局 DENY。

## 第 6 步：最后启用全局 DENY

只有白名单和 A 重定向确认生效后，BIND 管理员才执行自己的配置变更，将 deny Zone 加入 `response-policy`，并按 BIND 维护流程完成检查和加载。

随后：

1. 从 `deploy/docker/dnsguard.env` 删除 `RPZ_GLOBAL_DENY_SETUP_DEFERRED=true`；
2. 重建 DNSGuard Compose，使 API 以正式模式启动：

   ```bash
   docker compose --env-file deploy/docker/dnsguard.env up -d --force-recreate
   docker compose --env-file deploy/docker/dnsguard.env ps
   ```

3. 通过 BIND 递归节点验证白名单、多级子域名、A 重定向和未知域名；
4. 确认没有业务域名在白名单发布前被提前拒绝。

DNSGuard 不会代替管理员修改或重启生产 BIND。

## 第 7 步：安全边界

- 客户端收到 `NXDOMAIN` 不等于完整 QNAME 没有到达上游。
- 隔离测试中部分 DO=1 查询仍可能到达上游；上线前必须按生产 BIND 配置单独验证。
- 全局 DENY 不应宣传为所有查询类型和 DNSSEC 场景下的绝对 DNS 隧道阻断。
- 生产 TSIG、Bootstrap Token、HTTPS 私钥和真实业务域名不得进入日志或 Git。
- 默认只读对接检查不会自动修复 BIND；临时 TXT 写入测试必须显式使用 `--write-test --confirm WRITE-TEST`。

## 高级运维

备份、恢复、升级、回滚、旧部署迁移、持久化权限和故障排查见：

[Docker 高级运维手册](../../docs/docker-operations.md)

环境变量的完整分组和默认值见：

[`deploy/docker/dnsguard.env.example`](dnsguard.env.example)
