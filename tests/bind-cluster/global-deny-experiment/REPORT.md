# RPZ Global Default-Deny 实验报告

- 分支：`experiment/rpz-global-default-deny`
- 被测试代码 Commit：`ac07959`
- 基线 main：`e935a7f6c1a6aeff2dd3f73d799621e5c5389d31`
- BIND 版本：`BIND 9.20.30 (Stable Release) <id:769c3fb>`
- qname-wait-recurse：`yes`
- 网络：独立 Docker Bridge（172.31.0.0/24）
- 生产 DNS / 生产 TSIG：未使用

## 规则

`global-deny.rpz.local` 使用：

`* IN CNAME .`

`named-checkzone` 通过，Primary 和两台 Secondary 均加载该 Zone。

## 结果

- SOA Serial：Primary/Secondary-1/Secondary-2 = `1 1 1`。
- 白名单 passthru：`allow.example.com`、`deep.sub.allow.example.com` 在三台节点均返回上游地址。
- A 重定向：`redirect.example.com`、`sub.redirect.example.com` 在三台节点均返回 `192.0.2.250`。
- 多级未知名称测试：
- global-deny-1a09dfb643bd648b.deep.branch.example.com → NXDOMAIN, 上游观察到完整 QNAME
- global-deny-f94b353f3a546ebb.deep.branch.example.net → NXDOMAIN, 上游观察到完整 QNAME
- global-deny-0f3e419034ac9daf.deep.branch.example.xyz → NXDOMAIN, 上游观察到完整 QNAME
- 根级通配 `.com`：三台节点均返回 NXDOMAIN。
- 模拟上游观测：`QUERY_OBSERVED`（通过容器 stdout 核对完整 QNAME）。
- DNSSEC DO=1：`NXDOMAIN`，上游观测：`QUERY_OBSERVED`。
- 总体：`FAIL`（FAILURES=4）

## qname-wait-recurse 对比

以下三次均使用相同的隔离 BIND 9.20.30、根级 `* CNAME .`、白名单、A 重定向和受控上游：

| 配置 | 普通多级未知域名 | DNSSEC DO=1 | 上游观测 |
|---|---|---|---|
| 默认 | NXDOMAIN | NXDOMAIN | 两类查询均观察到完整 QNAME |
| `qname-wait-recurse no` | NXDOMAIN | NXDOMAIN | 普通查询未观察到；DNSSEC 查询观察到 |
| `qname-wait-recurse yes` | NXDOMAIN | NXDOMAIN | 两类查询均观察到完整 QNAME |

因此，`qname-wait-recurse no` 只能改善本次普通 QNAME 查询的外传观测，不能证明 DNSSEC DO=1 查询不会到达上游。当前实验结论为：根级全局拒绝可以返回 NXDOMAIN，但尚不能作为“阻断所有 DNS 隧道上游通信”的生产方案。

## 解释边界

客户端收到 NXDOMAIN 不能单独证明不存在 DNS 数据外传。该结论只适用于本次隔离 BIND 配置、受控上游和观测日志，不能推广到所有生产 BIND 配置。

## 与 TLD deny 的对比

根级通配方案规则数量少、更新简单，但本次默认递归配置下，客户端虽收到 NXDOMAIN，受控上游仍可观察到完整 QNAME；这说明 NXDOMAIN 不能等同于查询未外传。其 RPZ 匹配范围、PASSTHRU 优先级、DNSSEC、缓存和递归行为必须按 BIND 版本实测；如果白名单或 A 重定向未优先命中，可能造成业务中断。现有 TLD deny 方案规则数量更多、更新成本更高，但匹配边界和逐项完整性更容易审计。两种方案均不能替代生产递归链路和查询外传评估。
