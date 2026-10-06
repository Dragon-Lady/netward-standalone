#!/usr/bin/env bash
# Launch an isolated Net Ward + mock upstream for verification.
# Usage: helpers/launch.sh [RUN_ID]
# Writes state under /tmp/netward-verify-$RUN_ID and prints env exports.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

PYTHON="${NETWARD_PYTHON:-}"
if [[ -z "$PYTHON" ]]; then
  if [[ -x /tmp/netward-verify-venv/bin/python ]]; then
    PYTHON=/tmp/netward-verify-venv/bin/python
  else
    PYTHON="$(command -v python3)"
  fi
fi

RUN_ID="${1:-$(date +%Y%m%dT%H%M%S)-$$}"
STATE_DIR="/tmp/netward-verify-${RUN_ID}"
mkdir -p "$STATE_DIR"

read -r UPSTREAM_PORT LISTEN_PORT < <("$PYTHON" - <<'PY'
import socket
ports = []
for _ in range(2):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    ports.append(s.getsockname()[1])
    s.close()
print(ports[0], ports[1])
PY
)

UPSTREAM_LOG="$STATE_DIR/upstream.log"
UPSTREAM_HITS="$STATE_DIR/upstream_hits.txt"
: > "$UPSTREAM_HITS"

cat > "$STATE_DIR/upstream.py" << PY
from http.server import BaseHTTPRequestHandler, HTTPServer

HITS = r"""$UPSTREAM_HITS"""
LOG = r"""$UPSTREAM_LOG"""
PORT = $UPSTREAM_PORT

class H(BaseHTTPRequestHandler):
    def _handle(self):
        with open(HITS, "a", encoding="utf-8") as f:
            f.write(self.path + "\n")
        body = b"from upstream"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle

    def log_message(self, fmt, *args):
        with open(LOG, "a", encoding="utf-8") as f:
            f.write("%s - %s\n" % (self.address_string(), fmt % args))

HTTPServer(("127.0.0.1", PORT), H).serve_forever()
PY

"$PYTHON" "$STATE_DIR/upstream.py" >"$STATE_DIR/upstream.stdout" 2>"$STATE_DIR/upstream.stderr" &
echo $! > "$STATE_DIR/upstream.pid"

CONFIG="$STATE_DIR/config.json"
DB="$STATE_DIR/netward-verify.db"
cat > "$CONFIG" << JSON
{
  "node_id": "netward-verify-${RUN_ID}",
  "upstream_target": "http://127.0.0.1:${UPSTREAM_PORT}",
  "listen_address": "127.0.0.1:${LISTEN_PORT}",
  "storage_path": "${DB}",
  "mirror_intensity_default": "moderate",
  "mesh_enabled": false,
  "mesh_endpoint": null,
  "trust_manifest_url": null,
  "alert_channels": [],
  "alert_email": null,
  "alert_slack_webhook": null,
  "alert_ntfy_topic": null
}
JSON

for i in $(seq 1 50); do
  if "$PYTHON" - <<PY
import socket, sys
s = socket.socket()
s.settimeout(0.2)
try:
    s.connect(("127.0.0.1", $UPSTREAM_PORT))
    sys.exit(0)
except Exception:
    sys.exit(1)
PY
  then
    break
  fi
  sleep 0.05
  if [[ $i -eq 50 ]]; then
    echo "upstream failed to bind" >&2
    exit 1
  fi
done

cd "$REPO_ROOT"
"$PYTHON" -m netward --config "$CONFIG" --allow-permissive-db \
  >"$STATE_DIR/netward.stdout" 2>"$STATE_DIR/netward.stderr" &
echo $! > "$STATE_DIR/netward.pid"

for i in $(seq 1 100); do
  if curl -s -o /dev/null -w "%{http_code}" --max-time 0.5 "http://127.0.0.1:${LISTEN_PORT}/" | grep -Eq '^[0-9]{3}$'; then
    break
  fi
  sleep 0.05
  if [[ $i -eq 100 ]]; then
    echo "netward failed to become ready" >&2
    echo "--- stderr ---" >&2
    cat "$STATE_DIR/netward.stderr" >&2 || true
    exit 1
  fi
done

VERSION="$("$PYTHON" -c 'from importlib.metadata import version; print(version("netward"))')"

cat > "$STATE_DIR/env.sh" << ENV
export NETWARD_VERIFY_RUN_ID="$RUN_ID"
export NETWARD_VERIFY_STATE_DIR="$STATE_DIR"
export NETWARD_VERIFY_LISTEN="http://127.0.0.1:${LISTEN_PORT}"
export NETWARD_VERIFY_LISTEN_PORT="$LISTEN_PORT"
export NETWARD_VERIFY_UPSTREAM_PORT="$UPSTREAM_PORT"
export NETWARD_VERIFY_UPSTREAM_HITS="$UPSTREAM_HITS"
export NETWARD_VERIFY_DB="$DB"
export NETWARD_VERIFY_CONFIG="$CONFIG"
export NETWARD_VERIFY_VERSION="$VERSION"
export NETWARD_VERIFY_REPO="$REPO_ROOT"
export NETWARD_PYTHON="$PYTHON"
ENV

echo "READY run_id=$RUN_ID listen=http://127.0.0.1:${LISTEN_PORT} upstream=127.0.0.1:${UPSTREAM_PORT} version=$VERSION state=$STATE_DIR"
echo "source $STATE_DIR/env.sh"
