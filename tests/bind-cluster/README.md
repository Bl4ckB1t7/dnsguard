# DNSGuard V1.0 Docker BIND 集群验收环境

这个目录提供一套**完全隔离**的真实 BIND9 验收环境：一个 RPZ Primary、两个
Secondary，以及使用仓库当前源码启动的 DNSGuard API。它不是生产部署脚本，
不会读取生产配置、生产 TSIG 或连接生产 DNS。

## 拓扑与安全边界

| 服务 | Docker 固定地址 | 宿主机测试端口 |
| --- | --- | --- |
| `bind-primary` | `172.30.0.10` | `127.0.0.1:15353` |
| `bind-secondary-1` | `172.30.0.11` | `127.0.0.1:15354` |
| `bind-secondary-2` | `172.30.0.12` | `127.0.0.1:15355` |

三个容器只加入独立的 Docker bridge 网络 `dnsguard-bind-acceptance`，不使用
host network，也不占用宿主机 UDP/TCP 53。Primary 只允许测试 TSIG 动态更新，
Secondary 通过真实 NOTIFY 和 IXFR/AXFR 获取 `rpz.local`。`app.test` 是静态的
测试递归路径，用于验证 passthru、精确 A 重定向和泛域名 A 重定向。

## 前置条件

需要 `docker`、`docker compose`、`dig`、`nsupdate`、`named-checkzone`、`go`、
`curl` 和 `openssl`。首次执行会拉取 `internetsystemsconsortium/bind9:9.20`。

## 执行

在仓库根目录执行：

```bash
./tests/bind-cluster/run-acceptance.sh
```

脚本会自动清理本套 Compose 项目、生成新的运行时 TSIG、初始化三个独立数据和
日志目录、编译当前 `server/`、启动测试 API、等待 BIND 就绪、执行验收并在结束
时采集日志。默认执行后清理容器，但保留 `runtime/acceptance-report.md` 和日志
以便查看；`--keep` 保留容器和运行时现场，`--clean` 只清理环境：

```bash
./tests/bind-cluster/run-acceptance.sh --keep
./tests/bind-cluster/run-acceptance.sh --clean
```

运行时目录已被 Git 忽略，包含随机 TSIG、API 状态、BIND zone journal、日志和
报告，不能提交到仓库。

## 自动验收用例

脚本输出每个用例的 `PASS`、`FAIL` 或 `NOT RUN`，并把命令输出保存到
`runtime/evidence/`：

- 正常发布、SOA Serial、AXFR/Zone 内容和 `named-checkzone`
- RPZ 实际递归效果：passthru、精确域名 A redirect、泛域名 A redirect
- Secondary 同步延迟与恢复
- Secondary 离线、Primary 离线
- TSIG 错误
- API 在 queued/running 阶段重启后的任务恢复
- 发布中并发编辑、新增/修改/删除规则不污染固定快照
- 发布失败后的恢复及 BIND 数据面独立性
- 并发/重复发布拒绝

报告中的 `NOT RUN` 只表示环境或前置条件不满足，绝不当作通过。Docker 不可用
时脚本会写出 NOT RUN 报告并返回非零状态。

## 与生产的区别

这里的 DNSGuard 使用 `AUTH_ENABLED=false`、本地高端口和临时 JSON 状态，仅为
隔离自动化验收。生产仍应使用真实认证、TLS、生产节点配置和生产 TSIG 权限；
本脚本没有生产部署、生产变更或生产回滚路径。
