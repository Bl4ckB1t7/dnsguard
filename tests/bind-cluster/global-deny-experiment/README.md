# RPZ 根级默认拒绝实验

本目录仅用于隔离实验，验证 BIND 9 RPZ 中：

```dns
$ORIGIN global-deny.rpz.local.
* IN CNAME .
```

是否可以替代按 TLD 生成的拒绝记录。实验不会连接生产 DNS，也不使用生产 TSIG。

## 运行

```bash
./tests/bind-cluster/global-deny-experiment/run.sh
```

脚本会自动生成临时 TSIG、上游权威 Zone、Primary/Secondary 配置，启动独立
Docker Bridge 网络中的 1 台 Primary、2 台 Secondary 和模拟上游，并验证：

- `named-checkzone`、Zone 加载和 Primary/Secondary SOA；
- 白名单 passthru 及多级子域名；
- A 重定向及子域名；
- `.com`、`.net`、`.xyz` 下多级未知名称的拒绝结果；
- 被拒绝的完整查询名称是否出现在模拟上游日志中。

默认测试结束后清理容器和运行目录。需要保留容器进行人工检查时使用：

```bash
./tests/bind-cluster/global-deny-experiment/run.sh --keep
./tests/bind-cluster/global-deny-experiment/run.sh --clean
```

实际结果写入同目录的 `REPORT.md`；运行时配置、TSIG、Zone 和日志位于被 Git
忽略的 `runtime/` 下，不应提交。

1,436 个 IANA TLD、2,872 个三级/四级查询的补充结果见
[`FULL-SCALE-RESULTS.md`](FULL-SCALE-RESULTS.md)。

## 解释边界

客户端收到 NXDOMAIN 不能单独证明不存在 DNS 数据外传。上游观测只对本次隔离
BIND 配置、受控上游和实际运行环境有效，不能推广为所有生产 BIND 配置的保证。
根级通配与现有 TLD deny 方案的比较及限制见 `REPORT.md`。
