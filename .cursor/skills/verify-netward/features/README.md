# Net Ward verification map

This directory is the maintained source for verifying operator-facing Net Ward behavior. Read the index before driving the app, then use the matching feature file as the recipe.

## Baseline preconditions

- Launch via `.cursor/skills/verify-netward/helpers/launch.sh "$RUN_ID"` so listen port, upstream port, and SQLite DB are disposable under `/tmp/netward-verify-$RUN_ID`.
- `export NETWARD_PYTHON="$PWD/.venv/bin/python"` (interpreter with editable `netward` installed from this checkout; use another path if your environment differs).
- `source /tmp/netward-verify-$RUN_ID/env.sh` then run `helpers/doctor.sh` and require listen URL, version, and isolated DB path.
- Never drive an instance that was not started by this verification run.
- Read the verify DB only through `helpers/db-read.sh` (read-only, refuses non-verify paths).
- Never point verify config at a production upstream or a non-`/tmp/netward-verify-*` database.

## Driving conventions

- Start every recipe from a doctor-healthy launch unless its preconditions say otherwise.
- Prefer stable path signatures (`/wp-admin/`), pattern IDs (`wordpress_admin_probe`), and CLI subcommands over body-hash guesses.
- Treat every command as literal. Keep quoted paths and flags unchanged.
- Drive the proxy with `curl -i "$NETWARD_VERIFY_LISTEN/…"`.
- Drive the operator CLI with `"$NETWARD_PYTHON" -m netward.cli --db "$NETWARD_VERIFY_DB" …`.
- Truncate `$NETWARD_VERIFY_UPSTREAM_HITS` before a recipe when the proof depends on which paths upstream saw.
- Cleanup removes `/tmp/netward-verify-$RUN_ID` only. Proof artifacts under `evidence/` stay.

## Proof and skip reporting

- Capture the user/operator action and the resulting state, not only the final status code.
- HTTP proof includes `curl -i` headers+body plus the upstream hit log (or its absence).
- CLI proof includes the command, stdout, stderr, and exit code.
- Mutation proof includes a second read (`list-patterns` or a follow-up curl).
- Record the feature ID and entry point used with every artifact under `evidence/<RUN_ID>/<feature-id>/`.
- Report an unreachable path with the attempted command and the unmet precondition.
- Do not report a skipped entry point as verified through a different path.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph describing the operator-visible behavior. It then uses exactly four H2 sections in this order.

1. `Sub-features` lists short IDs with one line for each behavior.
2. `How to get to it (user POV)` lists every operator entry point.
3. `Driving it with curl+cli` starts with `Preconditions:` and uses labeled bullets that pair each action with an exact command and observable result.
4. `Gotchas` lists traps that can waste or invalidate a verification run.

Keep implementation details out of the map. Name only operator paths, stable handles, required state, commands, and observable proof.

## Features

- [Clean pass-through](./clean-pass-through.md) — unmatched request reaches upstream with body `from upstream`.
- [WordPress probe mirror](./wordpress-probe-mirror.md) — `/wp-admin/` is mirrored; upstream is not hit.
- [Install and list patterns](./install-list-patterns.md) — vendor pattern seed and listing via CLI.
- [Disable and enable pattern](./disable-enable-pattern.md) — toggle `wordpress_admin_probe` and observe proxy routing change.
- [Unreachable upstream fail-open](./unreachable-upstream-fail-open.md) — unmatched path still gets a safe response when upstream is down.
- [Vendor path probes](./vendor-path-probes.md) — `.env`, `.git/config`, `xmlrpc.php`, `phpmyadmin`, `/admin` are mirrored; upstream is not hit.
- [Scanner User-Agent probe](./scanner-ua-probe.md) — scanner UA on a clean path is mirrored; a normal UA passes.
- [Basic auth probe (optional)](./basic-auth-probe.md) — off by default; `netward-cli enable-pattern` gives 401 + `WWW-Authenticate`; disable restores pass-through.
- [World-writable DB refusal](./world-writable-db-refusal.md) — startup refuses a world-writable storage path unless `--allow-permissive-db`.
- [Config validation](./config-validation.md) — YAML, non-JSON, missing required fields, and bad `alert_channels` exit 1 before binding.
- [Flood classification](./flood-classification.md) — >1000 req/10s from one source is labeled `flood` in SQLite but still reaches upstream.
- [SQLite recording and alerts](./sqlite-recording-and-alerts.md) — probe rows, source counters, and `list-patterns` HITS; alert delivery not reachable in this release.
