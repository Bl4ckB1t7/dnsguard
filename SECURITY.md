# Security policy

## Reporting a vulnerability

Please do not open a public issue for a suspected security vulnerability.
Contact the repository maintainer privately through the GitHub account that
owns this repository and include:

- affected commit or version;
- deployment mode (Docker Compose or systemd);
- a minimal reproduction using only an isolated test environment; and
- the impact and any available mitigation.

Do not include production DNS data, TSIG keys, passwords, session cookies,
Telegram tokens, certificates, or private logs in a report.

## Scope and safety boundary

DNSGuard is a control plane. BIND remains the DNS data plane. Security tests
must use an isolated BIND cluster and must not connect to or modify production
DNS. The repository's `tests/` directory contains test source and configuration
only; generated runtime state, credentials, reports, and logs are excluded from
Git.

## Secrets

Never commit any of the following:

- `deploy/docker/dnsguard.env`;
- `docker-data/`, `secrets/`, `tls/`, or `bind-logs/`;
- TSIG keys, private keys, certificates, passwords, tokens, or session data;
- local process state under `.run/`; or
- generated test reports and BIND runtime data.

Use the checked-in `*.example` files as templates and generate deployment
secrets outside the repository.
