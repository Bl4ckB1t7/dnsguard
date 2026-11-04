# Contributing to DNSGuard

## Before submitting changes

Run the checks that apply to your change:

```bash
(cd server && go test ./... -count=1)
(cd server && go test -race ./... -count=1)
(cd server && go vet ./...)
npm run build
bash -n scripts/*.sh tests/*.sh
git diff --check
```

For RPZ publishing or Docker changes, also run the isolated acceptance tests
documented in `tests/bind-cluster/README.md`. Docker acceptance tests must use
the generated runtime directories under `tests/*-runtime/`; those directories
must remain untracked.

## Security and production boundary

- Do not connect tests to a production BIND server.
- Do not commit TSIG keys, passwords, tokens, certificates, logs, or state files.
- Keep BIND as the independent DNS data plane.
- Do not add a database, queue, or unrelated service without an architecture
  decision.
- Describe failure handling and recovery behavior for changes to RPZ publishing.

## Pull requests

Include the affected files, test commands and their actual results. Mark tests
that could not run as `NOT RUN`; do not report an unexecuted test as passing.
