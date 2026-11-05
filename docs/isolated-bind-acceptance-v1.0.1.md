# DNSGuard v1.0.1 隔离 BIND 最终验收摘要

> 本文只记录隔离 Docker BIND 集群的实际验收结果，不代表生产 DNS 变更或生产环境验收。

- 验收日期：2026-11-05 UTC
- 验收分支：`fix/v1.0.1-security-hardening`
- 验收 Commit：`00ebe1f2515c39f17e94177832cfd3ec7c864207`
- BIND：`9.20.30`
- TLD fixture：`1436`
- 生产连接：无
- 结果：`20 PASS / 0 FAIL / 0 NOT RUN`

## 执行命令

完整验收使用真实隔离 BIND Primary、两台 Secondary 和模拟上游：

```bash
TLD_FIXTURE_COUNT=1436 ./tests/bind-cluster/run-acceptance.sh
```

为保留运行时证据并进行上游查询观测，随后使用相同规模运行：

```bash
TLD_FIXTURE_COUNT=1436 ./tests/bind-cluster/run-acceptance.sh --keep
```

运行时报告和脱敏证据位于本地的 `tests/bind-cluster/runtime/`，该目录被 Git 忽略，不包含在仓库中。TSIG、Zone journal 和临时状态不会提交。

## 关键结果

| 项目 | 结果 | 实际证据 |
|---|---|---|
| TLD 分批发布 | PASS | 1436 个 TLD；初始 Serial 1，最终 Serial 16；默认每批 100 个 TLD，实际为 15 批 |
| RPZ 触发项 | PASS | Primary AXFR 统计 2872 条 `CNAME .` 记录，即每个 TLD 的精确项和通配项各一条 |
| Primary / Secondary 同步 | PASS | 三个节点 TLD deny Zone SOA Serial 均为 16；Secondary 延迟和恢复用例通过 |
| AXFR 全量集合 | PASS | Primary 只读 AXFR 得到 2872 条触发项；状态为 `published`，`tldCount=1436` |
| 白名单 | PASS | `allowed.example.com` 及多级子域名返回 `192.0.2.101` |
| A 重定向 | PASS | `redirect.example.com` 及多级子域名返回 `192.0.2.250` |
| TLD 默认拒绝 | PASS | `blocked.example.com` 及多级子域名返回 `NXDOMAIN` |
| 拒绝查询上游观测 | PASS（本隔离路径） | 随机未缓存 `c2-final-72b6ae20c15d3460.example.com` 返回 `NXDOMAIN`；模拟上游日志未出现完整查询名 |
| BIND 独立运行 | PASS | `bind-independent-of-api` 用例通过，DNSGuard API 停止后已加载策略仍可查询 |

## 上游查询观测

本次使用已知存在的隔离 `example.com` 权威区作为受控上游，避免将“上游不存在该域名”误判为 RPZ 阻断。随机名称查询结果：

```text
client_rcode=NXDOMAIN
upstream_received=NO
```

该结果只说明本次隔离 BIND 配置下没有观察到该查询到达模拟上游，不能替代对生产 BIND `qname-wait-recurse` 等选项的独立评估。DNSGuard 未修改任何 BIND 生产配置。

## 失败与恢复

完整脚本共 20 个用例，失败用例为 0，NOT RUN 为 0。覆盖 Secondary 离线、Primary 不可达、TSIG 错误、API 重启、AXFR 恢复、发布失败、并发发布和 BIND 独立运行等场景。

隔离测试 Primary 的 TLD deny Zone 额外允许 Docker bridge gateway 执行只读 AXFR；这是测试环境配置，不应直接复制到生产。生产管理员应按实际 DNSGuard 地址配置最小化的 AXFR 权限。
