# DNSGuard v1.1.1 Docker Compose 安装手册

DNSGuard 生产环境只支持 Docker Compose。Compose 只运行 DNSGuard 控制面：
`dnsguard-api` 和 `dnsguard-web`。生产 BIND Primary/Secondary 必须独立运行，DNSGuard
不会安装、修改、代理或重启 BIND。

## 服务器要求

- Debian 12 或 Ubuntu 22.04/24.04，x86_64。
- Docker Engine 24+、Docker Compose Plugin 2.20+。
- 主机或 API 容器可访问 BIND 的 DNS、SOA 和必要的 AXFR 路径。
- 已准备已有 BIND 使用的 TSIG Key、企业 HTTPS 证书和私钥。

目标服务器不需要安装 Go、Node.js、npm 或 BIND。管理入口应只允许管理网段访问，不要直接暴露到公网。

## 第 1 步：准备现有 BIND

由 BIND 管理员提前完成：

1. 准备白名单/A 重定向 RPZ Zone、动态更新 TSIG、NOTIFY、IXFR/AXFR 和必要的只读 SOA/AXFR 权限。
2. 将白名单/A 重定向 Zone 放在 `response-policy` 的较高优先级。
3. 如使用 v1.1.1 全局 DENY，创建独立 `global-deny.rpz.local`，例如：

   ```dns
   $ORIGIN global-deny.rpz.local.
   * IN CNAME .
   ```

4. 首次上线先不要把 deny Zone 加入递归 `response-policy`，并准备一个目前能够正常解析的测试域名作为递归基线。

DNSGuard 不会编辑 `named.conf`、`response-policy` 或 Zone 文件。v1.1.1 的全局 DENY 不依赖 IANA TLD 列表。

旧版 `tld-deny.rpz.local` 仅作为 v1.0.1 兼容 Zone 保留；`global-deny.rpz.local` 才是 v1.1.0+ 的正式全局 DENY Zone。

详细 BIND 配置见[BIND RPZ 部署与对接文档](../../docs/bind-rpz-deployment.md)。

## 第 2 步：获取 v1.1.1 并运行一键安装

先克隆，再运行仓库内脚本：

```bash
git clone --branch v1.1.1 --single-branch \
  https://github.com/Bl4ckB1t7/dnsguard.git dnsguard
cd dnsguard
./install.sh
```

首次运行会检查 Docker/Compose，提示提供：

- BIND Primary 地址；
- 启用 DENY 前可正常解析的测试域名及递归 DNS 地址；
- 已有 BIND TSIG Key；
- HTTPS 证书和私钥。

首次尚未存在 `deploy/docker/dnsguard.env` 时，安装会生成 `AUTH_SECRET`、`MONITORING_TOKEN` 和一次性 Bootstrap Token，并创建持久化目录。若已经准备了环境文件，则必须先填入真实安全参数。已有配置、密钥、证书、Token 和数据不会被覆盖。缺少 TSIG 或证书时会停止，不会用不可信的自签名证书继续启动。

### BIND 在另一套 Docker 网络中

如果 BIND 位于独立物理机或虚拟机，直接使用 BIND 实际可达的地址和 `53` 端口，不设置下面的变量。

如果 BIND 位于另一套已经存在的 Docker 网络：

```bash
export DNSGUARD_BIND_NETWORK=existing-bind-network
./install.sh
```

安装脚本会检查网络存在，并检查其实际 Subnet 是否被 `DNS_NODE_ALLOWED_CIDRS` 明确授权；不满足时失败，不创建网络、不修改网络、不自动放宽 CIDR。API 使用 BIND 容器在该网络中的可达地址和 `53` 端口；不要把宿主机的 `127.0.0.1:15353` 之类映射端口填给 API。

如果脚本提示 Subnet 未授权，先查看实际网段并将其明确加入 `deploy/docker/dnsguard.env` 的 `DNS_NODE_ALLOWED_CIDRS`，然后重新运行安装：

```bash
docker network inspect "$DNSGUARD_BIND_NETWORK"
./install.sh
```

不要用 `docker network connect` 手工补连接。安装脚本会自动同时使用 `compose.yaml` 和 `compose.bind-network.yaml`；API 重建时也必须保留这两个文件：

```bash
docker compose --env-file deploy/docker/dnsguard.env \
  -f compose.yaml -f compose.bind-network.yaml \
  up -d --force-recreate dnsguard-api
```

`dnsguard-web` 只加入 `dnsguard-internal`，不会加入 BIND 外部网络。未设置 `DNSGUARD_BIND_NETWORK` 时，正式 `compose.yaml` 的默认网络架构不变。

### Bootstrap Token

默认安装完成后，在仓库根目录的受保护终端读取：

```bash
sudo cat ./secrets/bootstrap.token
```

如果设置了 `DNSGUARD_SECRET_DIR`，改为读取该自定义目录下的 `bootstrap.token`；安装脚本最后输出的实际路径是最终依据。Token 不会打印到普通日志，重复安装不会重新生成或覆盖它。

### TSIG Key 边界

已有 BIND Primary 时，默认复制当前已授权且与 Primary `update-policy` 匹配的 Key。DNSGuard 只读取它，不会生成、替换或修改生产 BIND Key。

如果是新建 Primary，由 BIND 管理员在受保护的 DNS 管理主机生成 Key，并将同一份 Key 配置到 Primary 和 DNSGuard。重新生成后必须同步修改 Primary，否则动态更新会认证失败。

管理员可在受保护的管理主机生成新 Key：

```bash
KEY_DIR="$HOME/dnsguard-admin-keys"
umask 077
install -d -m 0700 "$KEY_DIR"
tsig-keygen -a hmac-sha256 dnsguard-rpz > "$KEY_DIR/rpz-manager.key"
chmod 0640 "$KEY_DIR/rpz-manager.key"
```

上例中的 `$HOME/dnsguard-admin-keys` 是本机实际目录，不是 DNSGuard 容器路径。先完成 BIND 侧配置和检查，再把 Key 的实际路径提供给 `./install.sh`。安装检查文件类型、权限和基本 BIND `key`/`algorithm`/`secret` 结构，但不会打印密钥内容。

## 第 3 步：初始化与白名单

打开安装输出的 HTTPS 地址，完成：

1. Bootstrap Token、管理员账户和密码；
2. Primary、Secondary、Zone 和 TSIG 选择；
3. 只读 SOA、Serial、Zone 和连通性检查。

首次安装不要求手工导出 Seed JSON。白名单可以在登录后的 RPZ 规则页面直接导入：

```text
baidu.com
qq.com
example.org
```

TXT 每行一个域名；现有白名单 JSON 也可以导入。导入前会校验和预览，导入后只生成 `draft`，不会自动调用 `nsupdate`。必须由管理员审核并确认发布。

如需在部署前生成可审阅的 JSON，可使用只读对接脚本导出；这不是标准安装必需步骤：

```bash
cp deploy/docker/rpz-connect.env.example .local-rpz-connect.env
# 编辑 .local-rpz-connect.env，填写实际 Primary、Secondary 和宿主机 TSIG 路径
./scripts/rpz-connect.sh --env-file .local-rpz-connect.env \
  --whitelist-file approved-domains.txt \
  --export-whitelist-json whitelist-seed.json
```

默认对接检查只读，不修改 BIND。临时 TXT 写入测试必须显式使用 `--write-test --confirm WRITE-TEST`，且只允许脚本限定的测试命名空间。

## 第 4 步：安全上线顺序

首次上线必须严格按以下顺序：

1. 连接 BIND，完成初始化检查；
2. 导入、审核并发布白名单和 A 重定向；
3. 确认 Primary 及所有 Secondary 的 Serial、关键规则和实际递归结果；
4. 由 BIND 管理员把 `global-deny.rpz.local` 加入 `response-policy`；
5. 由 BIND 管理员完成配置并 reload 后，运行收尾脚本：

   ```bash
   ./scripts/finalize-global-deny.sh
   ```

   脚本会在 API 容器内执行只读核验，确认白名单发布、Primary/Secondary 同步、Global Deny Zone、`* CNAME .` 和基线对应的递归 NXDOMAIN；通过后原子关闭 `RPZ_GLOBAL_DENY_SETUP_DEFERRED`，保留权限一致的 env 备份，并使用 `--no-build` 只重建 API。

6. 回到 Web 执行全局 DENY 只读核验；

普通 BIND 使用：

```bash
docker compose --env-file deploy/docker/dnsguard.env \
  -f compose.yaml up -d --force-recreate
```

如果设置了 `DNSGUARD_BIND_NETWORK`，必须保留外部网络 override：

```bash
export DNSGUARD_BIND_NETWORK=existing-bind-network
docker compose --env-file deploy/docker/dnsguard.env \
  -f compose.yaml -f compose.bind-network.yaml up -d --force-recreate
```

首次安装在需要分阶段上线时会使用 `RPZ_GLOBAL_DENY_SETUP_DEFERRED=true`，它只允许先完成初始化和白名单发布。已初始化部署保留该变量会被拒绝启动；DNSGuard 不会代替管理员修改或 reload BIND。若收尾脚本失败，不会伪造完成状态；请按输出的日志和 env 备份提示排障后重复执行。

只有发布和所有节点同步证据完整、全局 DENY 只读核验通过后，首次部署引导才会完全消失。之后新增草稿或节点暂时离线不会重新打开引导，相关异常会在规则和节点页面显示。

## 第 5 步：完成后检查

通过递归 DNS 节点验证：

- 白名单域名及任意层级子域名正常放行；
- A 重定向返回预期 IPv4；
- 未授权域名按 BIND 全局 DENY 返回预期结果；
- Primary/Secondary 状态和 Serial 一致。

权威 RPZ Zone 检查使用非递归查询；实际策略效果必须使用递归查询。客户端收到 `NXDOMAIN` 不等于完整 QNAME 没有到达上游，隔离测试中部分 DNSSEC `DO=1` 查询仍可能外传。

## 高级运维

备份、恢复、升级、回滚、旧部署迁移和故障排查见[Docker 高级运维手册](../../docs/docker-operations.md)。环境变量完整分组见[`deploy/docker/dnsguard.env.example`](dnsguard.env.example)。

## 卸载

停止服务但保留数据：

```bash
docker compose --env-file deploy/docker/dnsguard.env -f compose.yaml down
```

如使用外部 BIND 网络，停止时同样保留 `-f compose.bind-network.yaml`。删除持久化目录前请先完成备份，并确认不会误删生产 TSIG、证书或 JSON 状态。
