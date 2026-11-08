#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_SCRIPT="$ROOT_DIR/scripts/daily-regression-report.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

export REGRESSION_RUN_URL='https://example.invalid/actions/runs/test'

run_report() {
  local report="$1" expected_exit="$2"
  shift 2
  set +e
  output="$(env "$@" bash "$REPORT_SCRIPT" "$report" 2>&1)"
  actual_exit=$?
  set -e
  [[ "$actual_exit" == "$expected_exit" ]] || {
    printf 'unexpected exit: expected=%s actual=%s output=%s\n' "$expected_exit" "$actual_exit" "$output" >&2
    return 1
  }
}

success_report="$TMP_DIR/success/report.md"
run_report "$success_report" 0 \
  GITHUB_EVENT_NAME=schedule \
  REGRESSION_GO_RESULT=success \
  REGRESSION_SHELL_RESULT=success \
  REGRESSION_BIND_RESULT=success \
  REGRESSION_WEB_RESULT=success \
  REGRESSION_E2E_RESULT=success \
  REGRESSION_UPGRADE_RESULT=success
grep -Fq '| Go | success |' "$success_report"

fake_bin="$TMP_DIR/bin"
mkdir -p "$fake_bin"
cat >"$fake_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "$1" == api && "$2" == repos/*/issues\?state=open\&per_page=100 ]]; then
  printf '[]\n'
  exit 0
fi
if [[ "$1" == api && "$2" == --method && "$3" == POST ]]; then
  printf 'created\n' >"${GH_CAPTURE:?}"
  exit 0
fi
printf 'unexpected gh invocation: %s\n' "$*" >&2
exit 1
EOF
chmod +x "$fake_bin/gh"

failure_report="$TMP_DIR/failure/report.md"
run_report "$failure_report" 1 \
  PATH="$fake_bin:$PATH" \
  GH_CAPTURE="$TMP_DIR/gh-capture" \
  GITHUB_EVENT_NAME=schedule \
  GITHUB_REPOSITORY=example/repo \
  REGRESSION_GO_RESULT=failure \
  REGRESSION_SHELL_RESULT=success \
  REGRESSION_BIND_RESULT=success \
  REGRESSION_WEB_RESULT=success \
  REGRESSION_E2E_RESULT=success \
  REGRESSION_UPGRADE_RESULT=success
grep -Fq '| Go | failure |' "$failure_report"
grep -Fq 'created' "$TMP_DIR/gh-capture"

cat >"$fake_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "$1" == api && "$2" == repos/*/issues\?state=open\&per_page=100 ]]; then
  printf '[]\n'
  exit 0
fi
printf 'HTTP 403: Resource not accessible by integration token\n' >&2
exit 1
EOF
chmod +x "$fake_bin/gh"

permission_report="$TMP_DIR/permission/report.md"
set +e
permission_output="$(env PATH="$fake_bin:$PATH" GITHUB_EVENT_NAME=schedule GITHUB_REPOSITORY=example/repo \
  REGRESSION_GO_RESULT=failure REGRESSION_SHELL_RESULT=success REGRESSION_BIND_RESULT=success \
  REGRESSION_WEB_RESULT=success REGRESSION_E2E_RESULT=success REGRESSION_UPGRADE_RESULT=success \
  bash "$REPORT_SCRIPT" "$permission_report" 2>&1)"
permission_exit=$?
set -e
[[ "$permission_exit" == 2 ]] || { printf 'permission failure exit=%s output=%s\n' "$permission_exit" "$permission_output" >&2; exit 1; }
grep -Fq 'issues:write permission' <<<"$permission_output"
[[ -r "$permission_report" ]]

printf 'PASS: daily report success, failure/issue update, and permission diagnostics\n'
