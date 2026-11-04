# DNSGuard BIND / RPZ 开发环境

本地测试环境不占用系统 53 端口：

```text
RPZ Primary:   127.0.0.2:5353
DNS Secondary: 127.0.0.3:5353
DNS Secondary-2: 127.0.0.4:5353
RPZ Zone:      rpz.local
```

管理平台作为控制面，通过 TSIG `nsupdate` 更新 Primary；Secondary 通过 IXFR/NOTIFY 同步。

本地联调时可用以下环境变量启动平台：

```bash
RPZ_PUBLISH_MODE=nsupdate \
RPZ_PRIMARY=127.0.0.2 RPZ_PRIMARY_PORT=5353 \
RPZ_ZONE=rpz.local \
RPZ_KEY_FILE="$PWD/dev/bind-rpz/keys/rpz-manager.key" \
DNS_NODE_ADDRESSES=primary-1=127.0.0.2:5353,secondary-1=127.0.0.3:5353,secondary-2=127.0.0.4:5353 \
RPZ_LOG_FILES=/var/log/named/dnsguard-dev-rpz/primary.log,/var/log/named/dnsguard-dev-rpz/secondary.log,/var/log/named/dnsguard-dev-rpz/secondary-2.log \
./scripts/start-dnsguard.sh
```

启动本地 BIND RPZ 开发环境需要 root 权限。脚本会优先使用 `BIND_USER`/`BIND_GROUP`，未设置时
自动探测系统中的 `bind` 或 `named` 账号，不再依赖某个固定用户名：

```bash
sudo BIND_USER=bind BIND_GROUP=bind ./scripts/start-bind-rpz.sh
./scripts/stop-bind-rpz.sh
```

如果目标系统使用其他专用账号，替换这两个变量即可。开发环境默认使用
Debian/Ubuntu 的 BIND 布局：`/etc/bind/dnsguard-dev-rpz`、`/var/lib/bind/dnsguard-dev-rpz` 和
`/var/log/named/dnsguard-dev-rpz`。
