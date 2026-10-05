# Clean pass-through

Clean pass-through lets an operator confirm that normal (non-probe) HTTP traffic reaches the configured upstream and returns its response unchanged through Net Ward.

## Sub-features

- `pass-root` forwards `GET /` to upstream.
- `pass-health` forwards an unmatched path such as `/healthz`.
- `pass-side-effect` records the upstream hit for the requested path.

## How to get to it (user POV)

- With Net Ward running in front of an upstream, request any path that does not match an active probe pattern (README: `curl -i http://127.0.0.1:8080/`).

## Driving it with curl+cli

Preconditions:

- Doctor is green for this `RUN_ID`.
- `$NETWARD_VERIFY_UPSTREAM_HITS` has been truncated for this recipe (`: > "$NETWARD_VERIFY_UPSTREAM_HITS"`).
- `wordpress_admin_probe` (and other vendor patterns) may be active; choose an unmatched path.

- **Root pass-through.** Request `/`. Run `curl -sS -D - -o /tmp/nw-body.$$ "$NETWARD_VERIFY_LISTEN/"`. Status is `200` and body is exactly `from upstream`.
- **Unmatched path.** Request `/healthz`. Run `curl -sS -D - -o /tmp/nw-body2.$$ "$NETWARD_VERIFY_LISTEN/healthz"`. Status is `200` and body is `from upstream`.
- **Upstream side effect.** Read `"$NETWARD_VERIFY_UPSTREAM_HITS"`. The file contains `/` and `/healthz` (or `/healthz` alone if root was not driven).
- **Proof.** Save headers+body and the hits file under `evidence/<RUN_ID>/clean-pass-through/`.

## Gotchas

- `/admin` and `/wp-admin/` match vendor probes — they are not clean pass-through.
- If upstream is down, unmatched traffic may receive a default mirror instead of `from upstream` (see unreachable-upstream-fail-open).
- Do not treat a 200 alone as proof; the body must be the upstream marker and the hit log must list the path.
