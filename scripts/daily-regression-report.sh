#!/usr/bin/env bash
set -Eeuo pipefail

REPORT_FILE="${1:-${RUNNER_TEMP:-/tmp}/dnsguard-daily-regression.md}"
RUN_URL="${REGRESSION_RUN_URL:-unknown}"
RESULTS=(
  "Go: ${REGRESSION_GO_RESULT:-NOT RUN}"
  "Shell/Compose: ${REGRESSION_SHELL_RESULT:-NOT RUN}"
  "Web/Playwright: ${REGRESSION_WEB_RESULT:-NOT RUN}"
  "Legacy BIND compatibility: ${REGRESSION_BIND_RESULT:-NOT RUN}"
  "Real Docker BIND E2E: ${REGRESSION_E2E_RESULT:-NOT RUN}"
  "v1.1.1 to candidate upgrade/rollback: ${REGRESSION_UPGRADE_RESULT:-NOT RUN}"
)

mkdir -p "$(dirname "$REPORT_FILE")"
{
  printf '# DNSGuard daily regression\n\n'
  printf -- '- run: %s\n' "$RUN_URL"
  printf -- '- public DNSLog / DNSSEC DO=1 upstream observation: NOT RUN\n\n'
  printf '| check | result |\n|---|---|\n'
  for result in "${RESULTS[@]}"; do
    name="${result%%:*}"
    value="${result#*: }"
    printf '| %s | %s |\n' "$name" "$value"
  done
} >"$REPORT_FILE"

failure=0
for result in "${RESULTS[@]}"; do
  value="${result#*: }"
  [[ "$value" == success ]] || failure=1
done

if ((failure)); then
  if [[ "${GITHUB_EVENT_NAME:-}" == schedule || "${GITHUB_EVENT_NAME:-}" == workflow_dispatch ]]; then
    if ! issue_output="$(bash scripts/update-regression-issue.sh "$REPORT_FILE" 2>&1)"; then
      printf 'regression report generated, but issue automation failed: %s\n' "$issue_output" >&2
      exit 2
    fi
    printf '%s\n' "$issue_output"
  else
    printf 'regression failure outside scheduled/manual run; issue update skipped\n' >&2
  fi
  exit 1
fi

printf 'all scheduled regression checks passed; no issue update required\n'
