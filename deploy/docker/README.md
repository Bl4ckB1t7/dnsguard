# DNSGuard Docker Compose 安装手册

DNSGuard 的生产部署方式是 Docker Compose，生产 Compose 只运行 `dnsguard-api` 和
`dnsguard-web`。BIND Primary/Secondary 由管理员独立部署；DNSGuard 不安装、修改、代理或
重启 BIND。

## 1. 安装前准备

- Docker Engine 24+ 和 Docker Compose Plugin 2.20+。
- 当前用户可以执行 `docker info`；安装器不会修改 Docker Socket 权限。
- 可信 HTTPS 证书和私钥。安装器不会生成自签名证书。
- **首次启动前不要求 BIND、RPZ Zone 或 TSIG。** BIND 接入在平台启动后的 Web 向导中完成。
- BIND 接入阶段需要已有 Primary/Secondary、业务 RPZ Zone、授权 TSIG，以及管理员配置的
  NOTIFY/IXFR/AXFR 和网络权限。

DNSGuard 不自动修改 `named.conf`、`response-policy` 或生产 Zone 文件，也不会自动启用
`global-deny.rpz.local`。

## 2. 一键启动控制面

先克隆，再运行仓库内脚本：

```bash
git clone --branch v1.2.0 --single-branch \
  https://github.com/Bl4ckB1t7/dnsguard.git dnsguard
cd dnsguard
./install.sh
```

首次安装只会要求 HTTPS 证书和私钥，并生成受保护的一次性 Bootstrap Token。没有 BIND、RPZ
或 TSIG 时，平台仍应启动；安装器会明确提示这些内容稍后在 Web 中准备。重复执行不会覆盖
已有 env、密钥、Token、证书或数据。失败时先按错误提示修正，再重新执行。

如果 BIND 在另一套已存在的 Docker 网络中：

```bash
export DNSGUARD_BIND_NETWORK=existing-bind-network
./install.sh
```

安装器会检查实际 Subnet 是否已包含在 `DNS_NODE_ALLOWED_CIDRS` 中，不会创建或修改网络。
API 使用 BIND 容器在外部网络中的地址和 53 端口；不要把宿主机映射端口（例如
`127.0.0.1:15353`）填给 API。Web 只加入 `dnsguard-internal`。

Bootstrap Token 默认读取方式：

```bash
sudo cat ./secrets/bootstrap.token
```

若设置 `DNSGUARD_SECRET_DIR`，读取该目录下的 `bootstrap.token`；以安装脚本最后输出的实际
路径为准。不要将 Token 写入聊天、截图或普通日志。

## 3. Web 初始化：先平台，后 BIND

1. 打开安装输出的 HTTPS 地址。
2. 输入 Bootstrap Token，创建管理员。此时只有 DNSGuard 平台完成启动，BIND 状态为“未接入”。
3. 登录后在向导中填写 Primary、Secondary、RPZ Zone，并将已有 TSIG Key 放入挂载的 secrets
   目录。完成 SOA、节点和 TSIG 检查。
4. BIND 未通过检查前，RPZ 发布和其他依赖 BIND 的写操作保持禁用；页面可以登录并显示下一步。

### 可选：生成 RPZ 初始化配置包

在接入向导填写 Primary、Secondary、业务 RPZ Zone 和 Global Deny Zone 后，可以先点击“预览配置包”或“下载 ZIP”。配置包只包含：

- Primary/Secondary Zone 配置片段和初始 Zone 文件；
- 业务 RPZ 优先、Global Deny 暂不加入 `response-policy` 的示例；
- TSIG include 配置和受保护环境中的生成说明；
- `named-checkconf`/`named-checkzone` 验证脚本、备份和冲突拒绝说明。

配置包不包含 TSIG Secret，也不会通过 SSH、Docker Socket 或 API 修改 BIND。BIND 管理员必须在 BIND 主机审核并执行包内脚本：

```bash
# Primary 主机
BIND_CONFIG_ROOT=/etc/bind ./apply-rpz-config.sh --check primary
BIND_CONFIG_ROOT=/etc/bind ./apply-rpz-config.sh --apply primary
BIND_CONFIG_ROOT=/etc/bind ./verify-rpz-config.sh primary

# 每台 Secondary 主机
BIND_CONFIG_ROOT=/etc/bind ./apply-rpz-config.sh --check secondary
BIND_CONFIG_ROOT=/etc/bind ./apply-rpz-config.sh --apply secondary
BIND_CONFIG_ROOT=/etc/bind ./verify-rpz-config.sh secondary
```

脚本默认只检查；`--apply` 也只在 `BIND_CONFIG_ROOT` 下创建不存在的 DNSGuard 管理目录，发现已有目录会拒绝覆盖。管理员仍需手工审核并将片段纳入 `named.conf`，再按正常变更流程执行 `named-checkconf` 和 BIND reload。Global Deny Zone 可以先创建，但在白名单发布、Primary/Secondary 同步确认前不得加入 `response-policy`。

已有 BIND 时，使用与 Primary `update-policy` 匹配的现有 Key。DNSGuard 不生成、替换或修改
BIND Key。新建 Key 必须由 BIND 管理员生成并同步配置 Primary，之后再把同一份 Key 安全提供给
DNSGuard。

## 4. 白名单发布和 Global Deny

接入 BIND 后：

1. 在 RPZ 页面导入 TXT（每行一个域名）或现有白名单 JSON。
2. 预览并审核；导入只生成 `draft`，不会自动调用 `nsupdate`。
3. 管理员确认发布，等待 Primary 和所有 Secondary 完成真实验证。
4. 由 BIND 管理员准备并启用独立 `global-deny.rpz.local`，并按目标 BIND 配置完成递归基线。
5. 回到 Web 执行全局 DENY 只读检查。

`global-deny.rpz.local` 是 v1.1.0+ 的全局默认拒绝 Zone；`tld-deny.rpz.local` 是 v1.0.1
旧 TLD 兼容路径，不是当前全局 DENY 的必要依赖。DNSGuard 不会自动修改 `response-policy`。

权威 Zone 查询使用 `+norecurse`，实际递归策略效果必须用递归查询验证。客户端 NXDOMAIN 不
等于完整 QNAME 没有到达上游；隔离测试中部分 DNSSEC `DO=1` 查询仍可能外传。

## 5. 手工 Compose 运维

普通部署：

```bash
docker compose --env-file deploy/docker/dnsguard.env \
  -f compose.yaml up -d --force-recreate
```

使用外部 BIND 网络时，重建 API 必须保留 override：

```bash
export DNSGUARD_BIND_NETWORK=existing-bind-network
docker compose --env-file deploy/docker/dnsguard.env \
  -f compose.yaml -f compose.bind-network.yaml up -d --force-recreate dnsguard-api
```

停止服务但保留数据：

```bash
docker compose --env-file deploy/docker/dnsguard.env -f compose.yaml down
```

外部网络部署停止时同样保留 `-f compose.bind-network.yaml`。不要使用 `down -v`，不要直接
清空 `docker-data`；备份、恢复、升级和回滚见[高级运维手册](../../docs/docker-operations.md)。

## 6. 部署边界

DNSGuard 只通过 `nsupdate + TSIG` 更新管理员预先准备的 RPZ。它不代替 BIND 递归架构，
不保证所有 DNSSEC 或 DNS 隧道场景都能阻断上游 QNAME 外传。

详细 BIND 配置见[BIND RPZ 部署与对接文档](../../docs/bind-rpz-deployment.md)，环境变量见
[`dnsguard.env.example`](dnsguard.env.example)。
