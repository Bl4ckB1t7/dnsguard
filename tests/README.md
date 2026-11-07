# DNSGuard tests

These are source-controlled, isolated acceptance and deployment tests. They
are not production deployment files and must never be pointed at a production
BIND cluster.

## Test groups

- `bind-cluster/`: three-container BIND Primary/Secondary RPZ integration
  environment and reliability acceptance tests.
- `docker-production-bind/`: isolated BIND configuration used by the Docker
  deployment checks.
- `docker-initialization-wizard.sh`: first-run initialization and bootstrap
  token checks.
- `docker-production-deployment.sh`: Docker image, permissions, persistence
  and safety checks.
- `backup-restore.sh`: isolated Docker host-path backup, checksum and restore
  rehearsal, including explicit sensitive-file opt-in, restore markers and
  mid-transaction rollback.
- `docker-paths.sh`: host-path resolution, overlap and symlink safety checks.
- `rpz-connect-security.sh`: isolated RPZ preflight and temporary-write safety
  checks using fake DNS tools; it never writes to a real BIND server.
- `e2e/run-all.sh`: one-command, isolated API/Web plus one BIND Primary and one
  Secondary acceptance flow. It creates uniquely named resources, runs real
  Chromium against the HTTPS service, and writes a Markdown evidence report.

The scripts generate TSIG keys, state, logs and reports in ignored runtime
directories. Nothing under those runtime directories should be committed.
Test credentials are local fixtures only and must not be reused in a
deployment.

Run the BIND acceptance suite with:

```bash
./tests/bind-cluster/run-acceptance.sh
```

Docker tests require Docker Engine and the Compose plugin. If Docker is not
available, record the result as `NOT RUN` rather than substituting a mock for a
real BIND test. The BIND harness selects an existing non-root account for its
permission-failure cases; set `TEST_RUN_USER` explicitly in CI when necessary.

Run the modern full flow with:

```bash
bash ./tests/e2e/run-all.sh
```

This modern flow uses `global-deny.rpz.local`. The older
`bind-cluster/run-acceptance.sh` remains a separate legacy TLD-deny compatibility
harness; its results must not be substituted for the Global Deny flow.
