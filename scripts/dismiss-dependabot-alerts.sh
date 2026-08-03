#!/usr/bin/env bash

###
# Bulk-dismiss Dependabot alerts whose manifest path matches a pattern.
#
# Why this exists:
#   This repo contains large amounts of *generated* code under samples/ and a
#   vendored website/ tree. Dependabot raises an alert for every vulnerable
#   dependency in every manifest/lockfile it finds there, which can add up to
#   thousands of alerts against code that is never shipped. GitHub's Dependabot
#   auto-triage rules match a single manifest file each (and are capped at 10
#   per repo), so they cannot exclude a whole subtree. This script dismisses
#   those alerts in bulk via the REST API instead.
#
# What it does NOT touch:
#   Alerts whose manifest path does not match --path-regex (by default, anything
#   outside samples/ and website/, e.g. the product code under modules/).
#
# Requirements:
#   - gh (GitHub CLI) authenticated with a token that has security_events write
#     scope for the target repo:  gh auth status
#   - jq is not required (uses gh's built-in -q/jq expressions)
#
# Usage:
#   scripts/dismiss-dependabot-alerts.sh [options]
#
# Options:
#   -r, --repo REPO         owner/name (default: derived from `gh repo view`)
#   -p, --path-regex REGEX  Ruby/jq-style regex matched against manifest_path
#                           (default: '^(samples|website)/')
#   -R, --reason REASON     Dismissal reason. One of:
#                           fix_started | inaccurate | no_bandwidth |
#                           not_used | tolerable_risk   (default: not_used)
#   -c, --comment TEXT      Dismissal comment stored on each alert.
#   -n, --dry-run           List matching alerts and exit without changing them.
#   -h, --help              Show this help.
#
# Examples:
#   # Preview what would be dismissed:
#   scripts/dismiss-dependabot-alerts.sh --dry-run
#
#   # Dismiss all open samples/ + website/ alerts:
#   scripts/dismiss-dependabot-alerts.sh
#
#   # Dismiss only a specific subtree with a custom reason:
#   scripts/dismiss-dependabot-alerts.sh -p '^samples/client/' -R tolerable_risk
#
# Note: dismissals are reversible. You can reopen alerts individually in the
#       Security tab, and a dismissed alert re-triggers if it recurs later.
###

set -euo pipefail

REPO=""
PATH_REGEX='^(samples|website)/'
REASON="not_used"
COMMENT="Generated sample/website code, not shipped product; excluded from triage."
DRY_RUN=0

usage() {
  cat <<'EOF'
Bulk-dismiss Dependabot alerts whose manifest path matches a pattern.

Usage:
  scripts/dismiss-dependabot-alerts.sh [options]

Options:
  -r, --repo REPO         owner/name (default: derived from the 'origin' remote)
  -p, --path-regex REGEX  regex matched against manifest_path
                          (default: '^(samples|website)/')
  -R, --reason REASON     fix_started | inaccurate | no_bandwidth |
                          not_used | tolerable_risk        (default: not_used)
  -c, --comment TEXT      dismissal comment stored on each alert
  -n, --dry-run           list matching alerts and exit without changing them
  -h, --help              show this help

Examples:
  scripts/dismiss-dependabot-alerts.sh --dry-run
  scripts/dismiss-dependabot-alerts.sh
  scripts/dismiss-dependabot-alerts.sh -p '^samples/client/' -R tolerable_risk

Requires the GitHub CLI (gh) authenticated with security_events write scope.
Dismissals are reversible via the Security tab.
EOF
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    -r|--repo)        REPO="$2"; shift 2 ;;
    -p|--path-regex)  PATH_REGEX="$2"; shift 2 ;;
    -R|--reason)      REASON="$2"; shift 2 ;;
    -c|--comment)     COMMENT="$2"; shift 2 ;;
    -n|--dry-run)     DRY_RUN=1; shift ;;
    -h|--help)        usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

case "$REASON" in
  fix_started|inaccurate|no_bandwidth|not_used|tolerable_risk) ;;
  *) echo "Invalid --reason '$REASON'." >&2; exit 1 ;;
esac

if ! command -v gh >/dev/null 2>&1; then
  echo "error: GitHub CLI (gh) is not installed or not on PATH." >&2
  exit 1
fi

if [ -z "$REPO" ]; then
  # Prefer the 'origin' remote (your fork) over any 'upstream' remote.
  origin_url="$(git remote get-url origin 2>/dev/null || true)"
  if [ -n "$origin_url" ]; then
    # Handle git@github.com:OWNER/REPO.git and https://github.com/OWNER/REPO(.git)
    REPO="$(printf '%s\n' "$origin_url" \
      | sed -E 's#^git@[^:]+:##; s#^https?://[^/]+/##; s#\.git$##')"
  fi
  if [ -z "$REPO" ]; then
    REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)"
  fi
  if [ -z "$REPO" ]; then
    echo "error: could not determine repo. Pass --repo owner/name." >&2
    exit 1
  fi
fi

echo "Repo:        $REPO"
echo "Path regex:  $PATH_REGEX"
echo "Reason:      $REASON"
echo "Mode:        $([ "$DRY_RUN" -eq 1 ] && echo 'DRY RUN (no changes)' || echo 'DISMISS')"
echo

# Collect matching open alert numbers.
ids_file="$(mktemp)"
trap 'rm -f "$ids_file"' EXIT
gh api --paginate "repos/${REPO}/dependabot/alerts?state=open&per_page=100" \
  -q ".[] | select(.dependency.manifest_path|test(\"${PATH_REGEX}\")) | .number" \
  | sort -un > "$ids_file"

total=$(grep -c . "$ids_file" || true)
echo "Matching open alerts: ${total}"

if [ "$total" -eq 0 ]; then
  echo "Nothing to do."
  exit 0
fi

if [ "$DRY_RUN" -eq 1 ]; then
  echo "--- alert #  ->  manifest_path (ecosystem: package) ---"
  gh api --paginate "repos/${REPO}/dependabot/alerts?state=open&per_page=100" \
    -q ".[] | select(.dependency.manifest_path|test(\"${PATH_REGEX}\")) | \"#\(.number)\t\(.dependency.manifest_path)\t(\(.dependency.package.ecosystem): \(.dependency.package.name))\""
  echo
  echo "Dry run only. Re-run without --dry-run to dismiss these ${total} alerts."
  exit 0
fi

ok=0; fail=0; i=0
while read -r n; do
  [ -z "$n" ] && continue
  i=$((i+1))
  if gh api -X PATCH "repos/${REPO}/dependabot/alerts/${n}" \
       -f state=dismissed \
       -f dismissed_reason="$REASON" \
       -f dismissed_comment="$COMMENT" >/dev/null 2>&1; then
    ok=$((ok+1))
  else
    fail=$((fail+1))
    sleep 2   # brief backoff in case of a secondary rate limit
  fi
  if [ $((i % 50)) -eq 0 ]; then
    echo "progress: ${i}/${total} (ok=${ok} fail=${fail})"
  fi
  sleep 0.35  # stay under Dependabot API secondary rate limits
done < "$ids_file"

echo "COMPLETE: attempted=${i} ok=${ok} fail=${fail}"
[ "$fail" -eq 0 ]
