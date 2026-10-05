#!/usr/bin/env bash
# Read-only health check for a verify launch.
# Usage: source STATE/env.sh && helpers/doctor.sh
set -euo pipefail

: "${NETWARD_VERIFY_LISTEN:?source STATE/env.sh first}"
: "${NETWARD_VERIFY_STATE_DIR:?}"
: "${NETWARD_VERIFY_DB:?}"
: "${NETWARD_PYTHON:?}"

fail() { echo "DOCTOR FAIL: $*" >&2; exit 1; }
ok() { echo "DOCTOR OK: $*"; }

NW_PID="$(cat "$NETWARD_VERIFY_STATE_DIR/netward.pid" 2>/dev/null || true)"
UP_PID="$(cat "$NETWARD_VERIFY_STATE_DIR/upstream.pid" 2>/dev/null || true)"
[[ -n "$NW_PID" && -d "/proc/$NW_PID" ]] || fail "netward pid $NW_PID not running"
[[ -n "$UP_PID" && -d "/proc/$UP_PID" ]] || fail "upstream pid $UP_PID not running"

# Confirm PIDs own the expected ports (ss if available, else curl).
LISTEN_PORT="${NETWARD_VERIFY_LISTEN_PORT:?}"
if command -v ss >/dev/null 2>&1; then
  ss -ltnp 2>/dev/null | grep -E ":${LISTEN_PORT}\\b" | grep -q "pid=${NW_PID}," \
    || fail "listen port $LISTEN_PORT not owned by netward pid $NW_PID"
fi

CODE="$(curl -s -o /tmp/netward-doctor-body.$$ -w "%{http_code}" --max-time 2 "$NETWARD_VERIFY_LISTEN/" || true)"
[[ "$CODE" =~ ^[0-9]{3}$ ]] || fail "listen URL not answering HTTP (got '$CODE')"
rm -f /tmp/netward-doctor-body.$$

# Version + disposable DB path checks.
LIVE_VER="$("$NETWARD_PYTHON" -c 'from importlib.metadata import version; print(version("netward"))')"
[[ "$LIVE_VER" == "${NETWARD_VERIFY_VERSION:-$LIVE_VER}" ]] || fail "version drift: live=$LIVE_VER expected=$NETWARD_VERIFY_VERSION"
case "$NETWARD_VERIFY_DB" in
  /tmp/netward-verify-*/netward-verify.db) ;;
  *) fail "refusing non-isolated DB path: $NETWARD_VERIFY_DB" ;;
esac
[[ -f "$NETWARD_VERIFY_DB" ]] || fail "DB missing: $NETWARD_VERIFY_DB"

# Patterns should auto-seed on first run.
COUNT="$("$NETWARD_PYTHON" -m netward.cli --db "$NETWARD_VERIFY_DB" list-patterns 2>/dev/null | grep -c wordpress_admin_probe || true)"
[[ "$COUNT" -ge 1 ]] || fail "wordpress_admin_probe not active after seed"

ok "pid=$NW_PID listen=$NETWARD_VERIFY_LISTEN version=$LIVE_VER db=$NETWARD_VERIFY_DB"
