#!/usr/bin/env bash
set -Eeuo pipefail

# Update one deduplicated issue for scheduled regression failures.  This script
# only uses the repository's GitHub token and never uploads test secrets.
REPORT_FILE="${1:?usage: $0 REPORT_FILE}"
REPOSITORY="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
RUN_URL="${REGRESSION_RUN_URL:-https://github.com/${REPOSITORY}/actions/runs/${GITHUB_RUN_ID:-unknown}}"
TITLE='[automated-regression] DNSGuard daily regression'
MARKER='<!-- dnsguard-daily-regression -->'

command -v gh >/dev/null 2>&1 || { printf 'gh is required for issue reporting\n' >&2; exit 2; }
[[ -r "$REPORT_FILE" ]] || { printf 'report is not readable: %s\n' "$REPORT_FILE" >&2; exit 2; }

body="$(cat "$REPORT_FILE")"
body="$(printf '%s\n\n%s\n\nWorkflow: %s' "$MARKER" "$body" "$RUN_URL")"

issues_json="$(gh api "repos/${REPOSITORY}/issues?state=open&per_page=100")"
issue_number="$(printf '%s' "$issues_json" | python3 -c '
import json, sys
for issue in json.load(sys.stdin):
    if issue.get("pull_request"):
        continue
    if issue.get("title") == "[automated-regression] DNSGuard daily regression":
        print(issue["number"])
        break
')"

if [[ -n "$issue_number" ]]; then
  if ! gh_error="$(gh api --method PATCH "repos/${REPOSITORY}/issues/${issue_number}" \
    -f body="$body" 2>&1 >/dev/null)"; then
    printf 'issue update failed; verify GITHUB_TOKEN has issues:write permission: %s\n' "$gh_error" >&2
    exit 3
  fi
  printf 'updated regression issue #%s\n' "$issue_number"
else
  if ! gh_error="$(gh api --method POST "repos/${REPOSITORY}/issues" \
    -f title="$TITLE" -f body="$body" 2>&1 >/dev/null)"; then
    printf 'issue creation failed; verify GITHUB_TOKEN has issues:write permission: %s\n' "$gh_error" >&2
    exit 3
  fi
  printf 'created regression issue\n'
fi
