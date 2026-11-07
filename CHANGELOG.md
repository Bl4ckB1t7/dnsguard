## [1.2.1-rc] — 发布候选（未发布）

> v1.2.1 仍为候选版本，尚未创建 Tag 或 GitHub Release。详见 [RC 说明](docs/release-notes/v1.2.1-rc.md)。

### 候选修复与验证

- 修复 RPZ 配置包 apply 后未把管理 include 纳入实际加载 named.conf 的问题。
- 真实隔离 E2E 覆盖 ZIP 下载、宿主机 Bash apply、最终配置加载、白名单同步、Global Deny 延迟启用和 finalize 收尾。
- 保留 BIND 独立管理、最小权限、无生产 reload，以及 NXDOMAIN 不等于 QNAME 未外传的安全边界。
- 使用真实 v1.1.1 tag 的隔离升级、中断恢复和快照回滚验收通过。
- 使用 IANA 当前 1,436 条 TLD 快照的隔离兼容验收通过，并校验实际输入数量。
- 隔离 `qname-wait-recurse no` profile 的 DO=0/DO=1 多类型 QNAME 观察通过；该结果不替代公网或其他递归器验证，也不消除 DNSSEC DO=1 外传风险。
- 公网 DNSLog、独立公网来源、所有目标配置下的 DO=1 外传和移动/平板完整视觉回归仍未完成，当前发布建议为 NO-GO。

# Changelog

## [1.2.0] — 正式发布

> DNSGuard v1.2.0 已正式发布。详见 [GitHub Release](https://github.com/Bl4ckB1t7/dnsguard/releases/tag/v1.2.0)。

### 新增与改进

- platform-first 首次部署：先启动 DNSGuard Web/API，再通过 Web 向导接入 BIND。
- RPZ 初始化配置包：支持预览、下载、角色化应用、格式校验、备份、幂等处理和冲突拒绝。
- 白名单 TXT/JSON 导入、草稿审核、发布任务及 Primary/Secondary 同步核验。
- Global Deny 延迟启用与最终只读收尾检查。
- 外部 BIND Docker 网络的可选 Compose override 和安装器支持。
- Bootstrap Token、TSIG、HTTPS、Docker 权限和失败恢复提示加固。

### 兼容性与安全边界

- DNSGuard 仍是控制面；生产 BIND 由管理员独立部署和维护。
- 不自动修改 `named.conf`、`response-policy`、Zone 文件，也不自动 reload/restart BIND。
- v1.0.1 的 legacy 状态、JSON 数据、白名单、审计、备份和回滚数据保留。
- 白名单必须先审核发布并确认 Secondary 同步，之后才能启用 Global Deny。
- 客户端 `NXDOMAIN` 不等于完整 QNAME 没有到达上游；部分 DNSSEC `DO=1` 场景仍可能外传。

### 验证状态

- Go test、Race、Vet：PASS。
- React build：PASS。
- Bash 语法与 ShellCheck：PASS。
- 隔离 BIND/RPZ 配置包验收：已有真实证据，结论仅适用于隔离环境。
- 公网 DNSLog：未执行（NOT RUN）。
