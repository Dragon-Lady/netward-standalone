---
name: verify-netward
description: "Drive Net Ward (HTTP reverse-proxy deception layer + operator CLI) the way an operator does — launch an isolated proxy+upstream, curl real paths, manage patterns via netward.cli, and keep proof under evidence/. Use when proving Net Ward behavior after a change, before declaring a fix done, or when asked to /verify-netward."
---

# Verify Net Ward

Net Ward is a user-space HTTP reverse proxy: clean traffic reaches `upstream_target`; known probes get harmless mirror responses and never hit upstream. Primary surface is the proxy daemon (`python -m netward --config …`). Secondary surface is the management CLI (`python -m netward.cli --db …`). Drive both with plain HTTP (`curl`) and the CLI — not pytest internals — for user-path proofs.

Run this skill from the Net Ward standalone checkout you are verifying. Do not expand product scope; verification only. Never touch Push Guard / Netlify. Never delete operator data outside `/tmp/netward-verify-*` scratch dirs.

## Launch

Isolated verify topology (new ports + disposable DB every run):

```bash
cd /path/to/netward-standalone
# One-time (or when deps drift): uv venv .venv --python 3.12
#                           && uv pip install -e ".[dev]" --python .venv/bin/python
export NETWARD_PYTHON="$PWD/.venv/bin/python"

RUN_ID=$(date +%Y%m%dT%H%M%S)-$$
.cursor/skills/verify-netward/helpers/launch.sh "$RUN_ID"
# → READY … listen=http://127.0.0.1:<port> …
source /tmp/netward-verify-$RUN_ID/env.sh
```

What launch does:

1. Starts a tiny upstream on a free `127.0.0.1` port that returns `from upstream` and appends each path to `$NETWARD_VERIFY_UPSTREAM_HITS`.
2. Writes a disposable config (`node_id=netward-verify-$RUN_ID`, `storage_path=/tmp/netward-verify-$RUN_ID/netward-verify.db`, matching listen/upstream ports).
3. Starts `python -m netward --config $CONFIG --allow-permissive-db` in the background.
4. Waits until `curl` gets an HTTP status from the listen URL (there is **no** ready log line from the daemon — port answering is the ready signal).

Teardown for this launch is `helpers/cleanup.sh` (see Cleanup). Never use the repo's example `127.0.0.1:8080` / `netward.db` for verification if a live operator instance might own them — always use the helper's isolated ports/DB.

## Doctor

Read-only "is this instance worth driving?":

```bash
source /tmp/netward-verify-$RUN_ID/env.sh
.cursor/skills/verify-netward/helpers/doctor.sh
```

Doctor requires:

- `netward.pid` and `upstream.pid` still alive.
- Listen port owned by the netward PID (via `ss` when available).
- Listen URL answers HTTP.
- Installed package version matches `$NETWARD_VERIFY_VERSION`.
- DB path is under `/tmp/netward-verify-*/netward-verify.db` (refuses any other DB).
- `wordpress_admin_probe` is present in `python -m netward.cli --db $NETWARD_VERIFY_DB list-patterns` (auto-seed happened).

If doctor fails, run Cleanup for that `RUN_ID`, then Launch again. Never drive an instance you did not start.

## Drive

Harness: **curl** against `$NETWARD_VERIFY_LISTEN` plus **`python -m netward.cli --db $NETWARD_VERIFY_DB`**. Prefer path/header signatures and CLI pattern IDs from `netward/data/vendor_patterns.json` over fragile body substrings alone.

Baseline before every recipe:

```bash
source /tmp/netward-verify-$RUN_ID/env.sh
.cursor/skills/verify-netward/helpers/doctor.sh
# Optional: truncate hit log so this feature's upstream proof is clean
: > "$NETWARD_VERIFY_UPSTREAM_HITS"
```

Mapped features (see `features/`):

| Feature | Drive entry |
|---------|-------------|
| [Clean pass-through](features/clean-pass-through.md) | `curl -i "$NETWARD_VERIFY_LISTEN/"` |
| [WordPress probe mirror](features/wordpress-probe-mirror.md) | `curl -i "$NETWARD_VERIFY_LISTEN/wp-admin/"` |
| [Install and list patterns](features/install-list-patterns.md) | `python -m netward.cli --db $NETWARD_VERIFY_DB list-patterns` |
| [Disable and enable pattern](features/disable-enable-pattern.md) | `disable-pattern` / `enable-pattern` then re-curl |
| [Unreachable upstream fail-open](features/unreachable-upstream-fail-open.md) | stop upstream, curl unmatched path |
| [Vendor path probes](features/vendor-path-probes.md) | `curl` `/.env`, `/.git/config`, `/xmlrpc.php`, `/phpmyadmin/`, `/admin` |
| [Scanner User-Agent probe](features/scanner-ua-probe.md) | `curl -A "sqlmap/1.7" "$NETWARD_VERIFY_LISTEN/healthz"` |
| [Basic auth probe (optional)](features/basic-auth-probe.md) | `netward-cli … enable-pattern basic_auth_probe`, wait 31s, curl with `Authorization: Basic` |
| [World-writable DB refusal](features/world-writable-db-refusal.md) | `timeout 10 python -m netward --config <0777 storage dir>` (± `--allow-permissive-db`) |
| [Config validation](features/config-validation.md) | `timeout 10 python -m netward --config bad.yaml` / missing field / bad `alert_channels` |
| [Flood classification](features/flood-classification.md) | `curl --parallel … "$NETWARD_VERIFY_LISTEN/flood-[1-1200]"` then `helpers/db-read.sh` |
| [SQLite recording and alerts](features/sqlite-recording-and-alerts.md) | curl a probe, then `list-patterns` HITS + `helpers/db-read.sh` |
| [Probe report](features/probe-report.md) | fixed probe mix, two unmatched suspicious paths, one clean request, then `report` |

Exact commands and expected observables live in each feature file. Drive ONE feature per proof run unless asked for a full map pass. In a full pass run `flood-classification` after the other HTTP recipes and `unreachable-upstream-fail-open` last.

## Evidence

Proof root (survives cleanup):

```text
.cursor/skills/verify-netward/evidence/<RUN_ID>/<feature-id>/
```

Capture for every proof:

1. **Action transcript** — the exact `curl`/`cli` command(s) run (`cmd.txt`).
2. **Response** — full `curl -i` headers+body (`response.txt`) or CLI stdout/stderr + exit code (`cli.out`, `cli.err`, `cli.exit`).
3. **Side effect** — upstream hit log snapshot (`upstream_hits.txt`) and/or a second read (`list-patterns` after a mutation).
4. **Meta** — `meta.txt` with `RUN_ID`, listen URL, version, feature id, timestamp (America/Chicago).

Proof standards:

- Exercise the real operator path (HTTP through the running proxy, or the real CLI). Do not call `_make_handler` / pytest fixtures as the proof.
- Capture the action and the resulting state (e.g. mirror body **and** empty upstream hit for that path).
- Mocks only at the production boundary already used by operators: a stand-in upstream is fine; do not stub classify/mirror.
- Dry-run does not apply here; observe files/ports/HTTP, do not trust names alone.

## Cleanup

```bash
source /tmp/netward-verify-$RUN_ID/env.sh   # if still available
.cursor/skills/verify-netward/helpers/cleanup.sh
# or: .cursor/skills/verify-netward/helpers/cleanup.sh /tmp/netward-verify-$RUN_ID
```

Cleanup kills **only** the PIDs recorded in that state's `netward.pid` / `upstream.pid`, then removes `/tmp/netward-verify-$RUN_ID`. It refuses any other path. It never deletes `.cursor/skills/verify-netward/evidence/`. After cleanup, confirm evidence still exists at the named path.

## Helpers

All under `.cursor/skills/verify-netward/helpers/` (executable):

| Script | Invocation |
|--------|------------|
| `launch.sh` | `.cursor/skills/verify-netward/helpers/launch.sh "$RUN_ID"` |
| `doctor.sh` | `source /tmp/netward-verify-$RUN_ID/env.sh && .cursor/skills/verify-netward/helpers/doctor.sh` |
| `cleanup.sh` | `.cursor/skills/verify-netward/helpers/cleanup.sh /tmp/netward-verify-$RUN_ID` |
| `db-read.sh` | `source /tmp/netward-verify-$RUN_ID/env.sh && .cursor/skills/verify-netward/helpers/db-read.sh "SELECT …"` (read-only; verify DB only) |

Set `NETWARD_PYTHON` to the interpreter that has `netward` installed. The helpers fall back to `/tmp/netward-verify-venv/bin/python`, then `python3`, when it is unset.

## Isolate

Two verify runs can coexist: each picks free ports and its own `/tmp/netward-verify-$RUN_ID` DB. Never attach to a shared `127.0.0.1:8080` operator instance. Never point verify config at a real upstream that holds customer traffic.

## Maintain

When the app or feature map drifts, run `/maintain-verification-skill` against this skill directory.

**Maintenance history:** The 12 recipes were developed against Net Ward 0.4.6 on 2026-10-05 and all 12 were rerun on the 0.4.8 code with the hit-counter fix (evidence in the ignored `evidence/full-*` directories). With alert delivery wired, `sqlite-recording-and-alerts` was rerun under `evidence/alert-20261005-verify3/`: two mirrored WordPress probes raised HITS from 0 to 2, recorded one alert with count 2 and a stdout delivery receipt, and sent no probe requests upstream. The first alert proof run exposed buffered daemon stdout; the successful run followed the flush fix.
