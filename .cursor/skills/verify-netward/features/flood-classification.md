# Flood classification

Flood classification lets an operator confirm that a single source exceeding 1000 requests in 10 seconds is labeled `flood` in local storage, while legitimate-shaped requests from it still reach upstream (flood is informational, not a block) and probe paths are still mirrored.

## Sub-features

- `burst-labels-flood` requests beyond the threshold are stored with `classification = 'flood'`.
- `flood-still-passes` unmatched flood requests keep `upstream_passed = 1` and appear in the upstream hit log.
- `flood-probe-mirrors` a probe path during the burst is mirrored and stored as `flood` with its `pattern_id`.

## How to get to it (user POV)

- Send more than 1000 requests from one IP within 10s through Net Ward; inspect the operator-owned SQLite DB (README Privacy: classifications are recorded locally).

## Driving it with curl+cli

Preconditions:

- Doctor is green. Run after the other non-destructive recipes (it fills the hit log and probes table).
- `$NETWARD_VERIFY_UPSTREAM_HITS` truncated.

- **Burst.** Run `curl -s --parallel --parallel-max 50 -o /dev/null "$NETWARD_VERIFY_LISTEN/flood-[1-1200]"` and confirm it completes in under 10s.
- **Probe during burst.** Immediately run `curl -sS -o "$EVIDENCE/wp.body.txt" -w "%{http_code}" "$NETWARD_VERIFY_LISTEN/wp-admin/"`. Body not `from upstream`.
- **Stored labels.** Wait ~2s for async logging, then `helpers/db-read.sh "SELECT classification, upstream_passed, COUNT(*) FROM probes WHERE json_extract(request_json,'$.path') LIKE '/flood-%' GROUP BY 1,2"`. A `flood|1|N` row with N > 0 exists.
- **Probe row.** `helpers/db-read.sh "SELECT classification, pattern_id, mirror_fired FROM probes WHERE json_extract(request_json,'$.path')='/wp-admin/' ORDER BY timestamp DESC LIMIT 1"` → `flood|wordpress_admin_probe|1`.
- **Upstream still served.** `grep -c '^/flood-' "$NETWARD_VERIFY_UPSTREAM_HITS"` equals the burst size.
- **Proof.** Save the query outputs, hit count, timing, and `meta.txt` under `evidence/<RUN_ID>/flood-classification/`.

## Gotchas

- The rate window lives in daemon memory per source; all curl requests come from `127.0.0.1`, so one source. The first ~999 requests are `unknown`, only the rest are `flood`.
- If the burst takes longer than 10s the threshold is never reached; raise `--parallel-max` rather than lowering the bar.
- `request_json` field names come from the stored probe; if the `json_extract` path returns nothing, inspect one row with `SELECT request_json … LIMIT 1` before failing.
