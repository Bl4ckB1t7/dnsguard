# BIND RPZ 部署与 DNSGuard 对接

本页说明如何准备现有 BIND RPZ 集群，再将 DNSGuard 接入。DNSGuard 只负责控制面操作：通过 `nsupdate + TSIG` 更新 RPZ Primary，并通过 SOA、规则和实际解析结果检查同步状态。

DNSGuard 不安装、修改或重启生产 BIND，也不参与客户端 DNS 查询。生产 BIND 仍然是独立的数据面。

## 1. 推荐拓扑

```text
管理员浏览器
      |
 DNSGuard API -- nsupdate + TSIG --> BIND RPZ Primary
                                      |  NOTIFY / IXFR / AXFR
                                      +--> BIND Secondary 1
                                      +--> BIND Secondary 2

客户端 --> 企业递归 DNS（启用 response-policy） --> 外部 DNS
```

DNSGuard 只需要能够访问：

- Primary 的 DNS TCP/UDP 53 端口，以及动态更新权限；
- 每台 Secondary 的 DNS TCP/UDP 53 端口，用于 SOA 和 RPZ 规则校验；
- 管理员访问 DNSGuard Web 的 HTTPS 入口。

不要把生产 BIND 加入 DNSGuard 的 Docker Compose。Compose 只运行 `dnsguard-api` 和 `dnsguard-web`。

## 2. 准备 RPZ Zone

以下配置是模板，部署前必须替换所有大写占位符：

- `RPZ_ZONE`
- `PRIMARY_IP`
- `SECONDARY_1_IP`
- `SECONDARY_2_IP`
- `RECURSOR_IP`
- `TLD_DENY_ZONE`
- `DNSGUARD_IP`

先在隔离环境用实际 BIND 版本验证配置，再安排生产变更窗口。

### 2.1 生成并分发 TSIG

在受保护的 DNS 管理主机生成一次密钥：

```bash
umask 077
tsig-keygen -a hmac-sha256 dnsguard-rpz > dnsguard-rpz.key
chmod 0600 dnsguard-rpz.key
```

将同一份 key 文件：

1. 以受保护权限放到 Primary 的 BIND 配置目录；
2. 以只读 Secret 或受保护 bind mount 提供给 DNSGuard；
3. 不提交 Git、不写入 `.env`、日志、截图或工单正文。

Primary 的 key 文件应只允许 BIND 进程和必要的管理员读取。DNSGuard 容器中的非 root API 用户必须能够读取挂载文件，但不能通过放宽为 `0644` 解决权限问题。具体 UID/GID 以 `deploy/docker/README.md` 为准。

### 2.2 Primary 配置

在 Primary 的 `named.conf` 或独立 include 文件中配置 TSIG 和 RPZ Zone：

```conf
include "/etc/bind/keys/dnsguard-rpz.key";

zone "RPZ_ZONE" {
    type primary;
    file "/var/lib/bind/db.RPZ_ZONE";

    // 仅允许 DNSGuard 使用该 key 动态更新本 RPZ Zone。
    update-policy {
        grant dnsguard-rpz zonesub ANY;
    };

    notify yes;
    also-notify {
        SECONDARY_1_IP;
        SECONDARY_2_IP;
    };

    // 仅允许列出的 Secondary 请求 Zone Transfer。
    allow-transfer {
        SECONDARY_1_IP;
        SECONDARY_2_IP;
    };
};
```

`update-policy` 和 `allow-update` 不要同时配置。示例中的 `zonesub ANY` 只授权这一个 RPZ Zone；如果企业已有更细的 update-policy，应按现有安全策略收敛记录类型和来源。

### 2.3 Secondary 配置

每台 Secondary 配置同一个 RPZ Zone，并将 Primary 列为传送源：

```conf
zone "RPZ_ZONE" {
    type secondary;
    primaries {
        PRIMARY_IP;
    };
    file "/var/cache/bind/db.RPZ_ZONE";
    allow-notify { PRIMARY_IP; };
};
```

确认防火墙允许：

- Primary -> Secondary：UDP/TCP 53，用于 NOTIFY 和 Zone Transfer；
- Secondary -> Primary：TCP/UDP 53，用于刷新、IXFR/AXFR；
- DNSGuard -> Primary：UDP/TCP 53，用于 `nsupdate`；
- DNSGuard -> Secondary：UDP/TCP 53，用于状态检查。

### 2.4 可选：配置 TLD 默认拒绝 Zone

如果要启用 DNSGuard 的 TLD 默认拒绝策略，在同一台 RPZ Primary 上再配置一个独立的 deny Zone。这个 Zone 由 DNSGuard 使用同一份 TSIG 通过 `nsupdate` 更新；DNSGuard 不会自动写入或修改下面的 BIND 配置。

Primary 增加：

```conf
zone "TLD_DENY_ZONE" {
    type primary;
    file "/var/lib/bind/db.TLD_DENY_ZONE";

    // 只允许 DNSGuard 管理该 deny Zone 的 CNAME 触发项。
    update-policy {
        grant dnsguard-rpz zonesub CNAME;
    };

    notify yes;
    also-notify {
        SECONDARY_1_IP;
        SECONDARY_2_IP;
    };
    allow-transfer {
        SECONDARY_1_IP;
        SECONDARY_2_IP;
        // 仅用于人工 reconcile 的只读 AXFR 核对。
        DNSGUARD_IP;
    };
};
```

每台 Secondary 增加：

```conf
zone "TLD_DENY_ZONE" {
    type secondary;
    primaries {
        PRIMARY_IP;
    };
    file "/var/cache/bind/db.TLD_DENY_ZONE";
    allow-notify { PRIMARY_IP; };
};
```

配置完成后先只读校验，再安排 BIND 配置变更窗口：

```bash
named-checkconf
named-checkzone TLD_DENY_ZONE /var/lib/bind/db.TLD_DENY_ZONE
```

首次创建的 Zone 至少应包含 SOA 和 NS 记录。不要把该 Zone 文件交给 DNSGuard 容器管理，也不要把生产 TSIG 写进仓库或环境变量。

## 3. 在递归 DNS 上启用 RPZ

只有实际为客户端提供递归解析的 BIND 实例才需要启用 `response-policy`。在该实例的 `options` 中引用已同步的 RPZ Zone：

```conf
options {
    recursion yes;
    response-policy {
        zone "RPZ_ZONE";
    };
};
```

如果 Secondary 只承担权威 Zone Transfer，不承担递归解析，不要仅为测试 RPZ 而开启递归。实际生效验证应查询企业递归 DNS，而不是只查询 RPZ 权威 Zone。

### 3.1 TLD 数据状态与默认拒绝边界

DNSGuard 控制台中的 TLD 数据状态用于展示和校验 IANA TLD 列表版本、数量与同步状态。默认情况下只同步列表，不发布 deny RPZ。完成隔离验收并明确设置 `TLD_DENY_PUBLISH_ENABLED=true` 后，DNSGuard 才会通过现有 `nsupdate + TSIG` 向管理员预先配置的第二个 deny Zone 发布 TLD 触发项；它仍然不会自动修改 `named.conf`、reload/restart BIND。

生产 BIND 需要由管理员独立配置第二个动态 Zone（见 [2.4](#24-可选配置-tld-默认拒绝-zone)），并在递归实例按顺序加载两个 RPZ：白名单/重定向 Zone 在前，TLD deny Zone 在后。示例（先在隔离环境验证）：

```conf
response-policy {
    zone "RPZ_ZONE";
    zone "TLD_DENY_ZONE";
};
```

每台 Secondary 以同样的 `TLD_DENY_ZONE` 配置为 secondary，并允许 Primary NOTIFY/IXFR/AXFR。不要让 DNSGuard 自动写入这些 BIND 配置。DNSGuard 发布每个 TLD 的精确触发项和 `*.TLD` 通配触发项，动作是 `CNAME .`；白名单 Zone 的 `passthru` 命中优先级和多 Zone 行为必须用当前 BIND 版本的隔离测试确认。

必须同时验证：

- 白名单域名及其子域名仍然 PASSTHRU；
- A 重定向返回预期 IPv4；
- deny RPZ 的已知可解析测试域名返回预期 RCODE；
- deny RPZ 权威触发项存在明确的动作证据（例如 `CNAME .`），不能把普通域名本身不存在误判为策略命中；
- BIND 的上游查询、DNSSEC、AAAA/TXT/CNAME 和内部域名行为符合企业策略。

TLD 拒绝不等于 100% 全局封锁：它只能覆盖已配置并被 BIND 实际加载的触发项，且 RPZ 匹配、递归缓存、DNSSEC 和例外规则都会影响结果。DNS C2 防护必须在递归前拦截路径上核对真实查询效果；DNSGuard 只负责受控管理现有 RPZ，不代替 BIND 的策略配置。`qname-wait-recurse` 等选项如需使用，必须由管理员依据当前 BIND 版本的官方文档和隔离测试结果独立决定，DNSGuard 不会自动设置。

## 4. DNSGuard 配置

Docker Compose 部署中，关键配置类似：

```dotenv
RPZ_PUBLISH_MODE=nsupdate
RPZ_ZONE=RPZ_ZONE
RPZ_PRIMARY=PRIMARY_IP
RPZ_PRIMARY_PORT=53
RPZ_KEY_FILE=/run/dnsguard-secrets/rpz-manager.key
TLD_DENY_PUBLISH_ENABLED=false
TLD_DENY_ZONE=TLD_DENY_ZONE
TLD_DENY_TTL_SECONDS=300
TLD_PUBLISH_TIMEOUT_SECONDS=120
TLD_PUBLISH_BATCH_TLDS=100
TLD_PUBLISH_BATCH_BYTES=32768
TLD_DENY_ARTIFACT_FILE=/var/lib/dnsguard/rpz/TLD_DENY_ZONE.db
```

`TLD_SYNC_TIMEOUT_SECONDS` 只限制 TLD 下载和格式校验；`TLD_PUBLISH_TIMEOUT_SECONDS` 单独限制批量 `nsupdate`、Primary/Secondary SOA 和代表性触发项的发布验收。发布超时不会自动重放，而是进入人工核对状态。
`TLD_PUBLISH_BATCH_TLDS` 和 `TLD_PUBLISH_BATCH_BYTES` 分别限制单批 TLD 变更数和 DNS UPDATE 文本大小，默认 100 个 TLD、32 KiB；实际批次以先达到的限制为准。

控制台会分别显示 `DENY Zone`、`Secondary` 和递归检查状态：Zone 发布成功不等于 Secondary 已同步，Secondary 已同步也不等于递归路径已经验证。需要验证递归效果时，额外配置 `TLD_DENY_RECURSOR`、`TLD_DENY_CHECK_NAME`，可选设置 `TLD_DENY_EXPECTED_RCODE`（默认 `NXDOMAIN`）；未配置时显示“递归未配置”，不会伪装成通过。

如果 IANA 列表相对上一份有效列表减少超过 10%，DNSGuard 会保留旧列表和已发布策略，记录新旧数量并拒绝自动发布。首次同步没有旧列表基线，不执行该比例判断。

### 3.2 `reconcile_required` 人工恢复

当某个批次超时、Primary 状态无法确认、或发布状态文件保存失败时，系统会进入 `reconcile_required`，并停止自动重放。此时不会把部分批次误记为完整发布，也不会自动删除或回滚 Zone 中已有记录。

恢复步骤：

1. 先在 Primary 上确认动态更新日志、TLD deny Zone SOA 和 AXFR 权限；再确认每台 Secondary 的 SOA Serial。
2. 登录 DNSGuard，在 TLD 数据状态卡片点击“人工核对并恢复”。该操作通过认证和 CSRF 保护的 `POST /api/dns/tld/reconcile` 执行。
3. DNSGuard 使用 TSIG 对 Primary 执行只读 AXFR，要求实际 Zone 中每个 TLD 的精确和通配 `CNAME .` 触发项都存在，并且集合与当前待发布列表完全一致。
4. 通过后，系统再次核对 Primary、Secondary、代表性触发项和已配置的递归检查，成功才清除 `reconcile_required` 并恢复自动同步；任何不一致都保持锁定并返回原因。

该恢复动作不会发送 DNS UPDATE，不会修改 `named.conf`、`response-policy` 或重启 BIND，并会写入审计记录。不要直接编辑 JSON 状态文件或把状态字符串改成 `published`。

首次初始化向导中：

1. 添加一台 `primary`，地址填写 `PRIMARY_IP:53`；
2. 至少添加一台 `secondary`，地址填写对应的 `SECONDARY_*_IP:53`；
3. 选择受保护目录中的 TSIG key；
4. 先执行只读 SOA、Zone、Serial 和网络检查；
5. 如执行 TSIG 写权限检查，确认页面提示并接受“写入后删除临时记录”的影响；
6. 检查全部通过后，再开启 RPZ 发布。

DNSGuard 发布时会固定规则快照，使用 TSIG 更新 Primary，然后逐台检查 Primary/Secondary 的 SOA Serial 和关键规则的实际回答。Primary 成功而 Secondary 未同步时，状态应保持为部分成功或同步异常，不能直接当作集群发布成功。

## 5. RPZ 规则匹配说明

DNSGuard 当前会为每条域名规则生成两个 QNAME 触发项：

- `example.com.RPZ_ZONE`：匹配精确域名；
- `*.example.com.RPZ_ZONE`：匹配其子域名。

因此，在 DNSGuard 页面填写 `example.com` 时，系统按当前实现同时覆盖根域名和子域名；删除或修改规则也会同时处理这两个触发项。不要直接手改生成的 RPZ 文件来改变匹配范围，应通过 DNSGuard 管理规则并重新发布。

支持的常用动作：

- `passthru`：生成 RPZ passthru，允许该请求继续正常解析；
- `A`：将匹配结果重定向到指定 IPv4 地址。

## 6. 一键对接检查

仓库提供 `scripts/rpz-connect.sh`，用于把 BIND 准备情况一次性检查出来。默认只读，不修改 `named.conf`、不 reload/restart BIND、不发布 RPZ 规则：

```bash
cp deploy/docker/rpz-connect.env.example /tmp/rpz-connect.env
# 编辑 /tmp/rpz-connect.env，填写实际地址和宿主机上的 TSIG 文件路径
./scripts/rpz-connect.sh --env-file /tmp/rpz-connect.env --render /tmp/dnsguard-rpz-rendered
```

脚本会检查 `dig`/`nsupdate` 工具、TSIG 文件权限、Primary/Secondary SOA Serial 和节点一致性，并生成不含密钥内容的 DNSGuard/BIND 配置模板。它不会自动安装或修改生产 BIND。

如需验证 TSIG 动态更新权限，必须显式执行写入测试：

```bash
./scripts/rpz-connect.sh \
  --env-file /tmp/rpz-connect.env \
  --write-test --confirm WRITE-TEST
```

该模式只向 Primary 写入一个随机临时 TXT 记录，验证后立即删除并再次查询确认。清理失败时脚本返回失败，并要求人工核对该临时记录；它不会继续执行正式 RPZ 发布。

如果设置 `RPZ_RECURSOR`、`RPZ_CHECK_NAME` 和 `RPZ_EXPECTED_A`，脚本还会通过递归 DNS 查询指定测试域名并核对预期 A 记录；未同时设置这三个值时，实际策略验证会明确显示为 `NOT RUN`。还可以按管理员提供的隔离测试数据配置 `RPZ_ALLOW_CHECK_NAME`/`RPZ_ALLOW_EXPECTED_A` 验证白名单，及 `RPZ_DENY_ZONE`、`RPZ_DENY_CHECK_NAME`、`RPZ_DENY_TRIGGER`、`RPZ_DENY_BASELINE_RECURSOR`、`RPZ_DENY_BASELINE_EXPECTED_A` 验证默认拒绝。默认拒绝验证会先用基线解析器确认测试域名确实可解析，再检查策略解析器的 RCODE，并查询 deny Zone 触发项的实际动作证据；参数不完整时输出 `NOT RUN`，不会假设 TLD 拒绝已经启用。

对接检查还可以把人工审核的域名清单转换为 DNSGuard 初始化用的白名单草稿。该操作只生成本地 JSON，不写入 BIND：

```bash
./scripts/rpz-connect.sh \
  --env-file /tmp/rpz-connect.env \
  --whitelist-file /path/to/approved-domains.txt \
  --export-whitelist-json /path/to/whitelist-seed.json
```

每行一个域名，空行和 `#` 注释会忽略；脚本会小写化、去除末尾点并去重，拒绝通配符、下划线、重复输出覆盖和无效域名。将结果放入 Docker 的 `docker-data/bootstrap/whitelist-seed.json`，并设置 `RPZ_WHITELIST_SEED_FILE=/var/lib/dnsguard/bootstrap/whitelist-seed.json` 后，首次初始化会将规则以 `draft` 导入。它们不会自动发布，已有部署也不会重新导入。

脚本输出使用 `PASS`、`FAIL`、`WARN`，适合安装验收和故障排查。`--write-test` 不应在未经审批的生产变更窗口外执行。

## 7. 发布前检查

在 Primary 或配置检查主机执行只读检查：

```bash
named-checkconf
dig @PRIMARY_IP RPZ_ZONE SOA +short
dig @SECONDARY_1_IP RPZ_ZONE SOA +short
dig @SECONDARY_2_IP RPZ_ZONE SOA +short
```

如果有离线 Zone 文件，再执行：

```bash
named-checkzone RPZ_ZONE /path/to/db.RPZ_ZONE
```

发布后应记录：

1. Primary 的新 SOA Serial；
2. 每台 Secondary 的 SOA Serial；
3. 关键规则在递归 DNS 上的实际解析结果；
4. DNSGuard 发布任务、审计记录和异常诊断。

实际 RPZ 解析验证示例：

```bash
dig @RECURSOR_IP example.com A +short
dig @RECURSOR_IP sub.example.com A +short
```

使用测试域名和测试 IP，避免在生产验证中误导真实用户流量。`passthru` 规则应验证其不再被 RPZ 改写；A 规则应验证返回预期 IPv4。

## 8. 变更、故障和回滚边界

- 不要通过编辑 Zone 文件并重启 BIND 来发布 DNSGuard 管理的规则；动态更新会产生 journal，直接改文件可能造成状态不一致。
- DNSGuard 停止时，BIND 继续提供当前已加载的 Zone；不要因为控制面不可用而重启 BIND。
- Primary 更新成功但 Secondary 同步失败时，先保留现场并人工核对 Serial、Transfer 日志和实际解析，不要盲目自动回滚。
- DNSGuard 的版本回滚不等于 RPZ Zone 回滚。RPZ 回滚必须从已审计版本创建新的受控发布任务，并重新验证 Primary、全部 Secondary 和实际解析。
- 如果恢复了旧的 DNSGuard JSON 状态，必须执行 `reconcile_required` 人工核对；恢复文件不会自动修改 BIND 当前 Zone。

## 9. 隔离验收

仓库提供不连接生产 DNS 的三节点 BIND 验收环境：

```bash
./tests/bind-cluster/run-acceptance.sh
```

它使用独立 Docker 网络、测试 TSIG 和临时目录，覆盖真实 `nsupdate`、NOTIFY、IXFR/AXFR、SOA、RPZ 实际解析、节点故障和发布恢复。生产变更前应先在该环境完成验收。
