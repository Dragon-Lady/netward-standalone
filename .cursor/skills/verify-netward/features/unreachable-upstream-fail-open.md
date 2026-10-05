# Unreachable upstream fail-open

Unreachable upstream fail-open lets an operator confirm that when the upstream is down, unmatched requests still receive a safe Net Ward response instead of a raw proxy error, matching the documented fail-open posture.

## Sub-features

- `stop-upstream` takes down only the verify upstream PID.
- `default-mirror` returns a non-empty safe response for an unmatched path.
- `restore-or-cleanup` does not leave a half-dead verify topology without recording it.

## How to get to it (user POV)

- Configure Net Ward with an unreachable `upstream_target` (README Configuration: unmatched requests return a default mirror response instead of exposing a raw proxy error).

## Driving it with curl+cli

Preconditions:

- Doctor was green before stopping upstream.
- Use the verify upstream PID only (`$NETWARD_VERIFY_STATE_DIR/upstream.pid`).

- **Stop upstream.** `kill "$(cat "$NETWARD_VERIFY_STATE_DIR/upstream.pid")"` and wait until the PID is gone. Do not kill netward.
- **Unmatched request.** Run `curl -sS -D - -o "$EVIDENCE/body.txt" "$NETWARD_VERIFY_LISTEN/somewhere-unique-$RANDOM"`. Must receive an HTTP status (not a curl connection failure to Net Ward). Body must not expose a raw aiohttp client traceback. A default mirror JSON/HTML body is acceptable.
- **Probe still mirrors.** `curl -sS "$NETWARD_VERIFY_LISTEN/wp-admin/"` still returns a mirror (not a transport error).
- **Proof.** Save responses under `evidence/<RUN_ID>/unreachable-upstream-fail-open/`. Prefer full Cleanup afterward rather than partially restarting upstream mid-map unless the next feature needs it.

## Gotchas

- This recipe intentionally breaks doctor (upstream PID dead). Run it last in a session, or Cleanup + Launch before other features.
- Connection refused to the **listen** port means Net Ward itself died — that is a product failure, not this feature.
- Never stop an upstream you did not start for this `RUN_ID`.
