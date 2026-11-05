# Global default-DENY isolated acceptance

This is an isolated BIND-only acceptance environment for the v1.1.0 global
`* IN CNAME .` RPZ policy. It creates a temporary TSIG key and Docker bridge
network, and never uses production DNS, production keys, or the production
Compose file.

Run the default `qname-wait-recurse no` profile:

```bash
./tests/bind-cluster/global-deny-acceptance/run-acceptance.sh
```

Set `QNAME_WAIT_RECURSE=default` or `yes` to compare recursive behavior. Set
`TEST_DNSSEC=1` only when explicitly testing DO=1; DNSSEC results are reported
separately and are not silently treated as proof that QNAME leakage is blocked.

Use `STAGED_FIRST_DEPLOYMENT=1` for the first-install rehearsal: the isolated
cluster starts with the deny Zone loaded but not active in `response-policy`,
publishes the whitelist and A redirect with `nsupdate + TSIG`, waits for both
Secondaries, then activates global DENY and repeats the business and deny
queries. This only changes the isolated test configuration.

The generated report and logs remain under the ignored `runtime/` directory.
The test covers the global deny Zone, three-level names, whitelist passthru,
A redirect, Primary/Secondary transfer, and controlled-upstream observation.
