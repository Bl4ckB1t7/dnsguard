# Local BIND / RPZ Lab

本地测试环境不占用系统 53 端口：

```text
RPZ Primary:   127.0.0.2:5353
DNS Secondary: 127.0.0.3:5353
RPZ Zone:      rpz.local
```

管理平台作为控制面，通过 TSIG `nsupdate` 更新 Primary；Secondary 通过 IXFR/NOTIFY 同步。

本地联调时可用以下环境变量启动平台：

```bash
RPZ_PUBLISH_MODE=nsupdate \
RPZ_PRIMARY=127.0.0.2 RPZ_PRIMARY_PORT=5353 \
RPZ_ZONE=rpz.local \
RPZ_KEY_FILE=/home/REDACTED/dns-ops-platform/dns-lab/keys/rpz-manager.key \
./scripts/start-tailscale.sh
```
