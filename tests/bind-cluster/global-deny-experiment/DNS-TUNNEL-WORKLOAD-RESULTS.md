# DNS 隧道流量形态验收

本测试不运行真实 C2 或隧道工具，而是在隔离 BIND 集群中模拟常见 DNS 隧道
协议的查询形态：编码数据标签、分片多标签、TXT/NULL 请求、会话序号和
DNSSEC `DO=1` 查询。测试目标是验证 RPZ 拒绝后是否仍向上游发送完整 QNAME。

## 模拟流量形态

| 形态 | 查询类型 | 说明 |
|---|---|---|
| iodine-like | A、NULL | Base32 长标签、编码分片 |
| dnscat-like | TXT | 会话标识加十六进制数据块 |
| 通用隧道 | AAAA | 多级长标签分片 |
| DNSSEC 变体 | A + `DO=1` | 检查 DNSSEC 请求的递归前策略行为 |

## 测试结果

### 默认 `qname-wait-recurse` 行为

- 所有模拟流量均返回 NXDOMAIN；
- Base32、Hex、长多标签、TXT、NULL 和 DNSSEC 查询的完整 QNAME 均到达模拟上游；
- 结论：客户端拒绝成功，但不能阻止 DNS 隧道查询外传。

### `qname-wait-recurse no`

- 普通 `DO=0` 的 A、TXT、AAAA、NULL 隧道形态均返回 NXDOMAIN；
- Primary、Secondary-1、Secondary-2 的代表性隧道 QNAME 均未到达模拟上游；
- DNSSEC `DO=1` 查询返回 NXDOMAIN，但完整 QNAME 仍到达模拟上游；
- 结论：普通 DNS 隧道形态阻断成功，DNSSEC 变体仍未实现上游隔离。

## 安全结论

当前不能将该方案描述为“完全阻断 DNS 隧道”。准确结论是：

> `qname-wait-recurse no` 可以在本次 BIND 9.20.30 隔离配置中阻止普通
> `DO=0` 隧道查询到达上游，但不能阻止 DNSSEC `DO=1` 查询。

测试脚本：[`run-dns-tunnel-workload.sh`](run-dns-tunnel-workload.sh)

```bash
QNAME_WAIT_RECURSE=no ./run-dns-tunnel-workload.sh
QNAME_WAIT_RECURSE=default ./run-dns-tunnel-workload.sh
```

所有测试仅使用隔离 Docker BIND 集群，未修改生产 BIND。
