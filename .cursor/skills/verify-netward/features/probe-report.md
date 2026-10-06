# Probe report

Probe report reads the local Net Ward database and prints an aggregate digest: whether the site was probed, counts by attack family, source ranks, weak spots, and an alert summary. It does not print raw IP addresses. Suggested patterns are shown and are not installed.

## Sub-features

- `verdict` a fresh database that has seen probes says `probed`; the digest names the data window.
- `family-mix` a fixed mix of WordPress, secret-file, admin, and scanner-UA probes shows up as counts, with location as the site path.
- `weak-spots` two unmatched suspicious paths that reached upstream are listed with a suggestion; one clean request is not listed as a path.
- `formats` Markdown and HTML reports are written owner-only, and HTML escapes attacker-supplied path text.
- `send-once` `--send` delivers one digest through the configured alert channel.

## How to get to it (user POV)

- `python -m netward.cli --db $NETWARD_VERIFY_DB report`
- `python -m netward.cli --db $NETWARD_VERIFY_DB report --format md --output FILE`
- `python -m netward.cli --db $NETWARD_VERIFY_DB report --format html --output FILE`
- `python -m netward.cli --db $NETWARD_VERIFY_DB report --send --config FILE`

## Driving it with curl+cli

Preconditions:

- Doctor is green on a fresh launch.
- `$NETWARD_VERIFY_UPSTREAM_HITS` truncated so this recipe's clean request is the only upstream hit you assert.

- **Probe mix.** `curl -sS -o /dev/null "$NETWARD_VERIFY_LISTEN/wp-admin/"`; `curl -sS -o /dev/null "$NETWARD_VERIFY_LISTEN/.env"`; `curl -sS -o /dev/null "$NETWARD_VERIFY_LISTEN/.git/config"`; `curl -sS -o /dev/null "$NETWARD_VERIFY_LISTEN/admin"`; `curl -sS -o /dev/null -A "sqlmap/1.7" "$NETWARD_VERIFY_LISTEN/healthz"`. Wait ~1s. Upstream hit log does not contain those paths.
- **Unmatched suspicious.** `curl -sS -o /dev/null "$NETWARD_VERIFY_LISTEN/cgi-bin/oops.php"` and `curl -sS -o /dev/null "$NETWARD_VERIFY_LISTEN/wp-content/debug.log"`. Both paths are appended to the upstream hit log. `/backup/.env.old` is not unmatched — the vendor `.env` pattern already matches it.
- **Clean request.** `curl -sS -D - "$NETWARD_VERIFY_LISTEN/hello-clean"` returns the upstream body `from upstream`.
- **Markdown.** `"$NETWARD_PYTHON" -m netward.cli --db "$NETWARD_VERIFY_DB" report --since 7d --format md --output "$NETWARD_VERIFY_STATE_DIR/probe-report.md"`. Stdout says `Wrote`. File contains `Verdict: probed`, `WordPress:`, `secrets .env/.git:`, `cgi-bin/oops.php`, and `wp-content/debug.log`. It does not contain a raw client IP. Mode is `0600`.
- **HTML.** Same command with `--format html` and `probe-report.html`. File contains `Verdict: probed` and does not contain an unescaped `<script` from any path you sent. The two suspicious paths are visible as text.
- **Send once.** Write a JSON config whose `alert_channels` is `["stdout"]` and whose required fields match the running verify config. `"$NETWARD_PYTHON" -m netward.cli --db "$NETWARD_VERIFY_DB" report --send --config "$NETWARD_VERIFY_STATE_DIR/report-send.json"`. Stdout contains exactly one `[NETWARD] INFO probe_report` digest. The digest has no raw IP.
- **Proof.** Save the curl transcript, both report files, the send transcript, and `meta.txt` under `evidence/<RUN_ID>/probe-report/`.

## Gotchas

- Probe logging is fire-and-forget. Read the report after a short pause.
- The report opens the database read-only. Do not point it at a database outside `/tmp/netward-verify-*` during verification.
- `/admin` matches `generic_admin_login_probe`. `/cgi-bin/oops.php` and `/wp-content/debug.log` do not match a vendor pattern; they are the weak-spot pair. A path such as `/backup/.env.old` is already covered by `env_file_probe`.
- Suggestions in the report are text. Do not install them as part of this recipe.
- Retention copy in the report is a warning about the 7-day / 10,000-row cap, not a second probe count.
