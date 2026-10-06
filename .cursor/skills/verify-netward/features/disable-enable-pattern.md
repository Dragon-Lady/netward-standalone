# Disable and enable pattern

Disable and enable pattern lets an operator turn off a vendor probe that conflicts with a real upstream path, then turn it back on, and observe the proxy routing change.

## Sub-features

- `disable-wp` disables `wordpress_admin_probe` so `/wp-admin/` can pass through.
- `enable-wp` re-enables the pattern so `/wp-admin/` mirrors again.
- `route-flip` proves both states with curl + upstream hits.

## How to get to it (user POV)

- Run `python -m netward.cli --db … disable-pattern wordpress_admin_probe` / `enable-pattern wordpress_admin_probe` (README Operator Commands).

## Driving it with curl+cli

Preconditions:

- Doctor is green; pattern currently active.
- Hit log truncated or snapshotted before each phase.

- **Disable.** Run `"$NETWARD_PYTHON" -m netward.cli --db "$NETWARD_VERIFY_DB" disable-pattern wordpress_admin_probe`. Exit `0`; stdout says disabled.
- **Pass-through while disabled.** Wait 31s (pattern cache TTL), truncate hits, then `curl -sS "$NETWARD_VERIFY_LISTEN/wp-admin/"`. Body is `from upstream` and hits contain `/wp-admin/`.
- **Enable.** Run `"$NETWARD_PYTHON" -m netward.cli --db "$NETWARD_VERIFY_DB" enable-pattern wordpress_admin_probe`. Exit `0`.
- **Mirror while enabled.** Wait 31s again, truncate hits, then curl `/wp-admin/` again. Body is not `from upstream`; hits do not contain `/wp-admin/`.
- **Proof.** Save both CLI transcripts and both curl+hits pairs under `evidence/<RUN_ID>/disable-enable-pattern/`.

## Gotchas

- Pattern cache TTL in the running proxy is 30s (`_PATTERN_CACHE_TTL`). Routing does not flip immediately after a CLI toggle (re-confirmed 2026-10-05); wait at least 31s before each post-toggle curl, not a brief retry.
- Leave the pattern **enabled** at the end of the recipe so later features stay valid.
- Disabling the wrong ID is a failed CLI (exit 1) — capture stderr.
