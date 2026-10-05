# SQLite recording and alerts

SQLite recording and alerts lets an operator confirm what Net Ward writes to its local DB for a mirrored probe (probe row, source counters, pattern hit counter) and what the alert surface does in this release.

## Sub-features

- `probe-row` a mirrored `/wp-admin/` request is stored with `pattern_id = wordpress_admin_probe`, `classification = probe`, `mirror_fired = 1`, `upstream_passed = 0`.
- `source-counters` the `127.0.0.1` source row has `probe_count` ≥ 1.
- `pattern-hits` `list-patterns` HITS for `wordpress_admin_probe` increases by the number of mirrored probes.
- `alerts-surface` the `alerts` table exists; no runtime path in this release writes or prints alerts (README: v0.4.1+ logs alerts to stdout only, delivery reserved).

## How to get to it (user POV)

- Operator-owned SQLite at `storage_path` (README Privacy and Local Data Use) and `python -m netward.cli --db … list-patterns` (HITS column).

## Driving it with curl+cli

Preconditions:

- Doctor is green on a fresh launch (HITS start at 0).

- **Baseline hits.** `"$NETWARD_PYTHON" -m netward.cli --db "$NETWARD_VERIFY_DB" list-patterns | grep wordpress_admin_probe`. HITS `0`.
- **Two probes.** `curl -sS -o /dev/null "$NETWARD_VERIFY_LISTEN/wp-admin/"` and `curl -sS -o /dev/null "$NETWARD_VERIFY_LISTEN/wp-login.php"`; wait ~1s.
- **Hits after.** Re-run `list-patterns`. HITS for `wordpress_admin_probe` is `2`.
- **Probe rows.** `helpers/db-read.sh "SELECT pattern_id, classification, mirror_fired, upstream_passed FROM probes WHERE pattern_id='wordpress_admin_probe'"` → two rows `wordpress_admin_probe|probe|1|0`.
- **Source row.** `helpers/db-read.sh "SELECT ip_address, probe_count, legit_count FROM sources"` → `127.0.0.1` with `probe_count` ≥ 2.
- **Alerts.** `helpers/db-read.sh "SELECT COUNT(*) FROM alerts"` → `0`, and `grep -c '\[NETWARD\]' "$NETWARD_VERIFY_STATE_DIR/netward.stdout"` → `0`. Record as "alert delivery not reachable from the operator path in this release", not as verified.
- **Proof.** Save CLI outputs, query outputs, stdout grep, and `meta.txt` under `evidence/<RUN_ID>/sqlite-recording-and-alerts/`.

## Gotchas

- Probe logging is fire-and-forget on a worker thread; read the DB after a short pause.
- HITS counting requires the match-count fix in `storage.probes_log` (added 2026-10-05, not yet in a release). On an older build HITS stays `0` — report it as the known bug, not a recipe failure.
- `db-read.sh` refuses any DB outside `/tmp/netward-verify-*` and anything other than `SELECT` / `PRAGMA table_info`.
