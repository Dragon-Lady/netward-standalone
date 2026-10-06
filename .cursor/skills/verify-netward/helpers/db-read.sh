#!/usr/bin/env bash
# Read-only SQL against the disposable verify DB (refuses any other path).
# Usage: source STATE/env.sh && helpers/db-read.sh "SELECT ..."
set -euo pipefail
: "${NETWARD_VERIFY_DB:?source STATE/env.sh first}"
: "${NETWARD_PYTHON:?}"
case "$NETWARD_VERIFY_DB" in
  /tmp/netward-verify-*/netward-verify.db) ;;
  *) echo "refusing non-isolated DB path: $NETWARD_VERIFY_DB" >&2; exit 2 ;;
esac
[[ $# -eq 1 ]] || { echo "usage: db-read.sh \"SELECT ...\"" >&2; exit 2; }
case "$(echo "$1" | tr '[:lower:]' '[:upper:]' | sed 's/^[[:space:]]*//')" in
  SELECT*|PRAGMA\ TABLE_INFO*) ;;
  *) echo "db-read.sh only runs SELECT / PRAGMA table_info" >&2; exit 2 ;;
esac
"$NETWARD_PYTHON" - "$NETWARD_VERIFY_DB" "$1" <<'PY'
import sqlite3, sys
con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
cur = con.execute(sys.argv[2])
print("|".join(d[0] for d in cur.description))
for row in cur.fetchall():
    print("|".join("" if v is None else str(v) for v in row))
PY
