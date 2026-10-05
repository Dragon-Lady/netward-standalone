#!/usr/bin/env bash
# Tear down ONLY the processes and scratch state this verify run created.
# NEVER deletes evidence under .cursor/skills/verify-netward/evidence/
# Usage: source STATE/env.sh && helpers/cleanup.sh
#    or: helpers/cleanup.sh /tmp/netward-verify-$RUN_ID
set -euo pipefail

STATE_DIR="${1:-${NETWARD_VERIFY_STATE_DIR:-}}"
[[ -n "$STATE_DIR" ]] || { echo "usage: cleanup.sh STATE_DIR (or source env.sh first)" >&2; exit 2; }
[[ "$STATE_DIR" == /tmp/netward-verify-* ]] || { echo "refusing to clean non-verify state: $STATE_DIR" >&2; exit 2; }

kill_pidfile() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local pid
  pid="$(cat "$f" 2>/dev/null || true)"
  [[ -n "$pid" ]] || return 0
  if [[ -d "/proc/$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      [[ -d "/proc/$pid" ]] || break
      sleep 0.05
    done
    if [[ -d "/proc/$pid" ]]; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$f"
}

kill_pidfile "$STATE_DIR/netward.pid"
kill_pidfile "$STATE_DIR/upstream.pid"

# Remove scratch only. Evidence lives under the skill tree and is untouched.
rm -rf "$STATE_DIR"
echo "CLEANUP OK removed $STATE_DIR (evidence preserved)"
