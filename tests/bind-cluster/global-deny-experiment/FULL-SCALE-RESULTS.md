# IANA TLD 全量规模补充测试

本报告记录一次独立于 `run.sh` 代表性用例之外的全量规模测试。测试只使用隔离
Docker BIND 集群，不使用生产 DNS 或生产 TSIG。

## 输入与环境

- 数据源：`https://data.iana.org/TLD/tlds-alpha-by-domain.txt`
- TLD 数量：1,436
- BIND：9.20.30
- 节点：1 Primary、2 Secondary、1 模拟上游
- 查询形态：
  - `iana1436-N.example.<TLD>`（3 级标签）
  - `iana1436-N.deep.example.<TLD>`（4 级标签）
- 总查询数：2,872 个

## 实际结果

| 节点 | 响应数 | NXDOMAIN | 其他 RCODE | 结果 |
|---|---:|---:|---:|---|
| Primary | 2,872 | 2,872 | 0 | PASS |
| Secondary-1 | 2,872 | 2,872 | 0 | PASS |
| Secondary-2 | 2,872 | 2,872 | 0 | PASS |

模拟上游日志中观察到的完整唯一 QNAME：

| 来源节点 | 唯一 QNAME 数量 |
|---|---:|
| Primary | 2,872 |
| Secondary-1 | 2,872 |
| Secondary-2 | 2,872 |

## 结论

`* IN CNAME .` 在本次配置下可以让客户端收到 NXDOMAIN，但没有阻止递归服务器
将被拒绝的完整 QNAME 发送到模拟上游。因此：

- 全量 TLD、多级名称的客户端拒绝：PASS；
- “被拒绝查询不外传”：FAIL；
- NXDOMAIN 不能作为 DNS 数据外传已被阻断的证明。

本次没有启用或评估 `qname-wait-recurse no`。任何此类配置都必须由 BIND 管理员
在实际生产配置中独立评估，DNSGuard 不会自动修改生产 BIND 配置。
