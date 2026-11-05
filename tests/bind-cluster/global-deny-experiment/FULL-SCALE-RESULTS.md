# IANA TLD 全量规模与递归前策略对照测试

本报告记录独立于 `run.sh` 代表性用例之外的全量规模 A/B 测试。测试只使用隔离
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

测试了两种 `response-policy` 行为：

- `qname-wait-recurse` 默认行为；
- `qname-wait-recurse no`。

## 默认行为结果

| 节点 | 响应数 | NXDOMAIN | 其他 RCODE | 结果 |
|---|---:|---:|---:|---|
| Primary | 2,872 | 2,872 | 0 | PASS |
| Secondary-1 | 2,872 | 2,872 | 0 | PASS |
| Secondary-2 | 2,872 | 2,872 | 0 | PASS |

模拟上游日志中观察到的完整唯一 QNAME：

| 来源节点 | 唯一上游 QNAME 数量 |
|---|---:|
| Primary | 2,872 |
| Secondary-1 | 2,872 |
| Secondary-2 | 2,872 |

默认行为结论：客户端拒绝成功，但 2,872 个完整 QNAME 均到达模拟上游。

## `qname-wait-recurse no` 结果

| 节点 | 响应数 | NXDOMAIN | 其他 RCODE | 结果 |
|---|---:|---:|---:|---|
| Primary | 2,872 | 2,872 | 0 | PASS |
| Secondary-1 | 2,872 | 2,872 | 0 | PASS |
| Secondary-2 | 2,872 | 2,872 | 0 | PASS |

模拟上游唯一 QNAME 数量：

| 来源节点 | 唯一上游 QNAME 数量 |
|---|---:|
| Primary | 0 |
| Secondary-1 | 0 |
| Secondary-2 | 0 |

普通 DO=0 查询在 `qname-wait-recurse no` 下未到达模拟上游。

## DNSSEC 对照

在 `qname-wait-recurse no` 模式下，对代表性 DNSSEC `DO=1` 查询进行测试：

- 客户端：NXDOMAIN；
- 模拟上游：观察到完整 QNAME；
- 结论：DNSSEC 查询仍存在上游可见性，不能宣称实现全协议阻断。

## 结论

`* IN CNAME .` 在默认行为下可以让客户端收到 NXDOMAIN，但没有阻止递归服务器
将被拒绝的完整 QNAME 发送到模拟上游。设置 `qname-wait-recurse no` 后，普通
DO=0 查询未到达上游，但 DNSSEC `DO=1` 仍可到达。因此：

- 全量 TLD、多级名称的客户端拒绝：PASS；
- 默认行为下“被拒绝查询不外传”：FAIL；
- `qname-wait-recurse no` 下普通 DO=0 查询不外传：PASS；
- `qname-wait-recurse no` 下 DNSSEC DO=1 查询不外传：FAIL；
- NXDOMAIN 不能作为 DNS 数据外传已被阻断的证明。

任何此类配置都必须由 BIND 管理员在实际生产配置中独立评估，DNSGuard 不会自动
修改生产 BIND 配置。
