# RPZ Global Default-Deny 实验报告

- 分支：`experiment/rpz-global-default-deny`
- 基线 main：`e935a7f6c1a6aeff2dd3f73d799621e5c5389d31`
- BIND 版本：`BIND 9.20.30 (Stable Release) <id:769c3fb>`
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
- global-deny-2ce373a3bb5aba76.deep.branch.example.com → NXDOMAIN, 上游观察到完整 QNAME
- global-deny-420351e681990786.deep.branch.example.net → NXDOMAIN, 上游观察到完整 QNAME
- global-deny-7fa8fc9c656b344a.deep.branch.example.xyz → NXDOMAIN, 上游观察到完整 QNAME
- 根级通配 `.com`：三台节点均返回 NXDOMAIN。
- 模拟上游观测：`QUERY_OBSERVED`（通过容器 stdout 核对完整 QNAME）。
- 总体：`FAIL`（FAILURES=3）

## 解释边界

客户端收到 NXDOMAIN 不能单独证明不存在 DNS 数据外传。该结论只适用于本次隔离 BIND 配置、受控上游和观测日志，不能推广到所有生产 BIND 配置。

## 与 TLD deny 的对比

根级通配方案规则数量少、更新简单，但本次默认递归配置下，客户端虽收到 NXDOMAIN，受控上游仍可观察到完整 QNAME；这说明 NXDOMAIN 不能等同于查询未外传。其 RPZ 匹配范围、PASSTHRU 优先级、DNSSEC、缓存和递归行为必须按 BIND 版本实测；如果白名单或 A 重定向未优先命中，可能造成业务中断。现有 TLD deny 方案规则数量更多、更新成本更高，但匹配边界和逐项完整性更容易审计。两种方案均不能替代生产递归链路和查询外传评估。
