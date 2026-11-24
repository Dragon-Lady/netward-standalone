# Net Ward

**A user-space deception layer that turns DDoS and bot abuse into wasted effort.**

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](CHANGELOG.md)

Net Ward sits in front of your HTTP service as a reverse proxy. Real traffic passes through untouched. Known probes and floods get harmless **mirror responses** that burn bot effort and never reach your app — no kernel hooks, no payloads, no retaliation, **fail-open by design**.

### Why Net Ward

- **Deflects, doesn't fight back.** Bots waste time on convincing-but-harmless mirrors; your upstream never sees the request.
- **User-space and fail-open.** No kernel modules, no packet tampering. If classification or rendering fails, traffic passes through to upstream. Unmatched requests receive 503 when upstream cannot serve them. Storage failures use readable, cached, or bundled patterns while keeping the listener available.
- **Drops in anywhere.** One Python process in front of any HTTP service. Point your load balancer at it and go.
- **Honest by design.** No telemetry, no harvested credentials, operator owns every byte of local data. Apache-2.0.

> **Built and maintained by Dragon Lady** — [github.com/Dragon-Lady](https://github.com/Dragon-Lady) · X: [@answerislove2](https://x.com/answerislove2)
> Independent security researcher tracking live supply-chain and bot-abuse campaigns in the wild.

**Website:** [dragon-lady.github.io/netward-standalone](https://dragon-lady.github.io/netward-standalone/)

**Version 0.5.1** adds an exact, case-insensitive match for the
`artex-recon/1.0` User-Agent to the scanner rule. Stop the proxy and back up
its database before upgrading. Startup refreshes the bundled definitions and
preserves operator settings and match history.

---

## Quick Start

```bash
python -m pip install --upgrade "netward>=0.5.1"
# Create config.json in a directory owned by your user (not directly in /tmp).
cat > config.json <<'JSON'
{
  "node_id": "netward-local",
  "upstream_target": "http://127.0.0.1:9000",
  "listen_address": "127.0.0.1:8080",
  "storage_path": "netward.db"
}
JSON
# Edit upstream_target to point at your running app before starting.
python -m netward --config config.json
```

Version 0.5.1 or newer is the recommended baseline for new installations and
upgrades. Older releases remain available for reproducibility; new deployments
should use the current release.

Or from source:

```bash
git clone https://github.com/Dragon-Lady/netward-standalone
cd netward-standalone
pip install -e .
```

Net Ward listens on `listen_address` and forwards clean traffic to `upstream_target`.

---

## Configuration

For a PyPI installation, use the minimal `config.json` above. The full
`example_config.json` is a repository file, not an installed wheel resource.
From a source checkout, copy it and edit the upstream target:

```bash
cp example_config.json config.json
```

Point `upstream_target` at a real HTTP service before you start Net Ward. If
the upstream is unreachable, unmatched requests return 503 Service Unavailable.
Matched probes continue to receive their configured decoys.

Required fields:

| Field | Meaning |
|-------|---------|
| `node_id` | Stable name for this Net Ward instance |
| `upstream_target` | HTTP service being protected |
| `listen_address` | Host and port Net Ward binds |

Optional fields control mirror intensity, local storage, mesh placeholders, alert channels, upstream timeouts, and probe-log retention. A pattern match or the start of a request flood records an alert in SQLite. Alerts are deduplicated by kind, source, and pattern for five minutes. An empty `alert_channels` list sends to stdout; select any combination of `stdout`, `email`, `slack`, and `ntfy` for explicit delivery. Outbound delivery runs in the background and retries failed channels. Recent undelivered alerts are retried on startup.

Email requires `alert_email`, `alert_smtp_host`, and `alert_smtp_from`. Set `alert_smtp_port` and `alert_smtp_security` (`starttls`, `ssl`, or `none`); `none` is permitted only for a loopback SMTP server. If authentication is needed, set `alert_smtp_username` and `alert_smtp_password_env` to the name of an environment variable containing the password. Slack requires `alert_slack_webhook`. ntfy requires `alert_ntfy_topic` (a topic on ntfy.sh or a full self-hosted topic URL); for a protected topic, set `alert_ntfy_token_env` to the name of an environment variable containing its bearer token. HTTP destinations must use HTTPS except on loopback. `alert_timeout_secs` defaults to five seconds. Net Ward checks requested destinations at startup and stores successful delivery receipts in the alerts table. Alert messages contain the source IP, pattern ID, and classification; they do not include raw request bodies or headers.

| Optional field | Default | Meaning |
|----------------|---------|---------|
| `upstream_timeout_total` | `10` | Whole-request budget for the upstream call, in seconds |
| `upstream_timeout_connect` | `3` | Connect (DNS + TCP + TLS) timeout, in seconds |
| `upstream_timeout_sock_read` | `5` | Idle time between upstream socket reads, in seconds |
| `upstream_max_concurrency` | `64` | In-flight upstream requests |
| `upstream_max_body_bytes` | `8388608` | Max buffered upstream response body (8 MiB). Larger bodies on unmatched requests return 503 |
| `probe_retention_secs` | `604800` | Probe-log TTL (7 days) |
| `probe_max_rows` | `10000` | Max probe-log rows after purge-on-write |
| `alert_timeout_secs` | `5` | Per-channel timeout for outbound alert delivery, in seconds |

---

## Run

```bash
python -m netward --config config.json
```

Example topology:

| Component | Address |
|-----------|---------|
| Net Ward | `127.0.0.1:8080` |
| Upstream app | `http://127.0.0.1:9000` |
| Storage | `netward.db` |

Point your load balancer or web server at Net Ward. Keep the upstream app reachable only from the host or trusted network when possible.
Set `listen_address` to `0.0.0.0:<port>` only when you intentionally want Net Ward reachable beyond localhost.
On Linux/macOS, keep `storage_path` non-world-writable. Example: `chmod 600 netward.db`, or `chmod 644 netward.db` only if you intentionally need read access for monitoring.

### Resource Monitoring

Net Ward sustains its documented per-box capacity continuously, but Python runtime memory pools may retain working-set state after sustained heavy load. Operators running Net Ward under continuous heavy traffic should monitor process resource usage and restart the daemon periodically, for example weekly or when RSS exceeds 2x baseline. v0.5 will refine this guidance based on operator feedback and local test observations, not automatic telemetry.

---

## Verify

Clean request should reach upstream:

```bash
curl -i http://127.0.0.1:8080/
```

Known probe should be mirrored:

```bash
curl -i http://127.0.0.1:8080/wp-admin/
```

The WordPress probe returns a fake login page for `/wp-admin`, `/wp-admin/`
and its subpaths (such as `/wp-admin/login.php`), plus `/wp-login.php`.
Matching ignores case and does not include lookalikes such as `/wp-administer`.
When rendering succeeds, the upstream service does not receive the request.

**Before protecting a real admin panel:** disable `generic_admin_login_probe`
if your app uses `/admin` or `/admin/login`; disable `wordpress_admin_probe`
if it serves the WordPress admin paths. See [Operator Commands](#operator-commands).
A mirror-rendering error instead fails open to upstream and is logged at ERROR.

### When upstream is unavailable

Inspection failure and an unavailable upstream are different cases:

- **Fail-open:** classification or mirror-rendering failures allow forwarding
  to upstream. If a matched probe's mirror cannot render, that request also
  forwards to upstream; the rendering error is logged at ERROR. Storage-write
  failures must not prevent an otherwise successful response.
- **Unmatched requests:** if upstream is dead, times out, or sends a response
  over the configured body cap, Net Ward returns 503 with `Cache-Control:
  no-store` and `Retry-After: 30`. A classifier failure follows this same rule
  when forwarding fails. These responses are not counted as mirrors or clean
  pass-through events. Monitors can see the outage.
- **Matched probes:** the configured decoy continues to work during an outage.
  The default mirror is a fallback for a matched probe with no usable template.

There are five default variants, selected by a stable digest of the source ID
and path. The same source ID and path get the same variant; generated fields
inside the body can vary. When source lookup is unavailable, a deterministic
per-client fallback ID keeps repeated requests stable. Switching between an
older stored ID and the fallback ID can change the variant once.

| Status | Default response |
|--------|------------------|
| 200 | JSON status with an ID and timestamp |
| 429 | JSON rate-limit response with `Retry-After: 30` |
| 503 | HTML Service Unavailable page |
| 200 | JSON with `data: null` and `next: null` |
| 200 | Plain-text `OK` |

An unmatched `curl -i http://127.0.0.1:8080/healthz` returns 503 during an
upstream outage. The variants above apply only to matched-probe fallbacks.
Custom rules that match a health endpoint will still intercept it; keep monitor
paths out of such rules.
Default timeouts are 3 seconds to connect, 5 seconds between socket reads,
and 10 seconds total. Forwarding exceptions, timeouts, and body-cap fallbacks
are logged at WARNING without upstream URLs, request data, or exception messages.

### When storage is unavailable

If writable SQLite startup fails, Net Ward logs a warning and still starts
serving. It first tries the existing database read-only, preserving readable
operator patterns and disables. When a checkpointed WAL database cannot be
read without creating sidecars, it uses a private read-only snapshot after
checking that the source stayed unchanged and has no WAL, shared-memory, or
rollback-journal files. A normal SQLite reader handles existing WAL files so
committed policy changes in the WAL are retained; the snapshot fallback never
ignores them. Snapshot policy stays fixed until restart. If neither read path
is available, the database is corrupt, or it has no patterns, it runs without
persistence using the bundled probe patterns and mirror bodies in memory.
The temporary snapshot is used only for reads and removed on clean shutdown,
including SIGTERM on platforms with event-loop signal support, and on listener
setup failures. It is not a replacement writable database. SIGKILL, power loss
and platforms without graceful signal support can leave the private directory.

At runtime, a failed pattern refresh preserves the last successfully read
pattern set, including an intentionally empty one. With no successful read,
bundled defaults cover the first request too. A failed vendor mirror lookup
can use its bundled body. Unmatched requests continue to the real app.

**Limits:** when both storage and its cached configuration are unavailable,
custom patterns and intentional disables cannot be recovered; bundled defaults
may mirror paths your real app uses. Reports, counters, durable alert queues,
and delivery receipts are not reliable without writable storage. Warnings name
the failing operation and exception class, never the private exception message,
and repeat at most once per minute per storage operation. Restore database
access and restart to leave a read-only/no-persistence startup mode. Malformed
configuration and the explicit world-writable-path security check still refuse
startup.

For testing, changing mode bits on an already-open Linux database may not stop
writes through existing descriptors. Use a fresh process with a read-only file
and directory, or inject an actual storage error in an isolated test. Do not
fault a production database to test this behavior.

### Happy-path example

With the example topology above, a healthy first run should look like this:

1. Start a small upstream service on `127.0.0.1:9000`.
2. Start Net Ward on `127.0.0.1:8080`.
3. Request `/` through Net Ward and confirm the upstream response comes back.
4. Request `/wp-admin/` through Net Ward and confirm a mirror response comes back instead.

Expected result: normal traffic reaches the upstream app, while the known probe
is handled by Net Ward's mirror layer. This is the simplest signal that the
proxy path, pattern match, and mirror response are all working.

---

## Operator Commands

Install or refresh the bundled vendor pattern set:

```bash
python -m netward.cli --db netward.db install-patterns
python -m netward.cli --db netward.db install-patterns --force
```

This development update refreshes vendor definitions automatically at startup.
Stop the proxy and back up the database before upgrading. Review new rule
families before restarting: new default rules become active, while optional
rules start disabled. Existing enables, disables, creation timestamps and match
history survive both normal and forced refresh, even if all existing vendor
rules are disabled. Expiry cleanup retains disabled vendor policy records.

Vendor-owned matching fields and decoy content are refreshed. Put custom rules
under separate operator-origin IDs. Non-vendor rules and existing mirrors they
reference are preserved. A refresh either completes as one transaction or rolls
back; malformed packs cannot partly install. Restart after an offline CLI
refresh so the proxy immediately uses the updated definitions.

These guarantees apply to this update. In 0.4.14 and earlier, a package upgrade
does not refresh definitions and `install-patterns --force` can reset disables
and match history.

### Additional probe coverage

The default pack adds PHP diagnostic files, named environment files,
service-account credentials, private credential files, repository metadata,
infrastructure state, diagnostic logs and source backups. Repeated slashes are
collapsed only for matching. Forwarded paths and query strings retain their
original encoding. Classification also resolves `.` and `..` path segments and
removes final-segment padding (trailing dots, NULs and whitespace), `;...` path
parameters and a case-insensitive `::$data` suffix. This changes only the matching
copy, including for encoded forms already decoded by the HTTP server. It does not
decode a second time or strip suffixes from intermediate directory names. Generic
application pages are not added to the defaults.

The following rules are installed **disabled** because real sites may serve
these paths. Enable only families that your application does not use:

| Optional rule | Content it can intercept |
|---------------|--------------------------|
| `short_php_diagnostic_probe` | Short PHP names such as test or information pages |
| `framework_diagnostic_route_probe` | Framework diagnostics and server status routes |
| `deployment_file_probe` | Deployment and automation configuration downloads |
| `runtime_configuration_file_probe` | Public runtime configuration and generic JSON key files |
| `database_download_probe` | Named SQL downloads |
| `archive_download_probe` | Named site archive downloads |
| `cms_manifest_probe` | CMS manifests and development-library paths |

For example, after reviewing your routes:

```bash
python -m netward.cli --db netward.db enable-pattern framework_diagnostic_route_probe
```

Refresh preserves this enable until you explicitly disable the rule again.

**Rollback after a definition refresh:** if returning to 0.4.13 or earlier,
stop the proxy and restore the pre-refresh database backup along with the older
package before restarting. Those versions do not support the new
`fake_aws_access_key_id` generator. A package-only downgrade leaves the refreshed
AWS mirror unable to render.

List active patterns:

```bash
python -m netward.cli --db netward.db list-patterns
```

Read a probe report without writing the database. The report is aggregate
counts: which probe families fired, which request-path totals those families
hit, and how many sources were involved. It does not print raw IP addresses
or geography. `--send` delivers that same digest — path counts included,
never raw IPs. Output files are owner-only (`0600`).

```bash
python -m netward.cli --db netward.db report
python -m netward.cli --db netward.db report --since 7d --format md --output report.md
python -m netward.cli --db netward.db report --format html --output report.html
python -m netward.cli --db netward.db report --family wordpress --top 10
python -m netward.cli --db netward.db report --send --config config.json
```

“Clean pass-through events” counts unmatched, non-flood requests that received
an upstream response, including older rows labeled `unknown`. It describes
routing, not a guarantee that the traffic is safe. Unavailable-upstream responses and matched
probes forwarded after rendering errors do not count as clean pass-throughs.

The stored probe log is capped at 7 days or 10,000 rows. A report describes
that window and says so. Suggested tighter patterns are printed for review
and are not installed.

Disable or re-enable a pattern:

```bash
python -m netward.cli --db netward.db disable-pattern wordpress_admin_probe
python -m netward.cli --db netward.db enable-pattern wordpress_admin_probe
```

If your upstream exposes a real admin panel at `/admin`, disable
`generic_admin_login_probe` or replace it with a tighter operator pattern before
putting Net Ward in front of that service:

```bash
python -m netward.cli --db netward.db disable-pattern generic_admin_login_probe
```

---

## Optional Patterns

Some vendor patterns are shipped but **disabled by default** because they can
break legitimate traffic if your upstream uses the same protocol feature the
pattern targets.

### `basic_auth_probe`

Catches brute-force credential stuffing via `Authorization: Basic <base64>`.

**Safe to enable only when:** your upstream does not use HTTP Basic Auth at all.
If your upstream accepts Basic Auth credentials from real users, enabling this
pattern traps those users in an infinite 401 loop — Net Ward returns a fake
challenge, the browser re-prompts, the cycle repeats.

Enable:

```bash
netward-cli --db netward.db enable-pattern basic_auth_probe
```

Disable again:

```bash
netward-cli --db netward.db disable-pattern basic_auth_probe
```

To verify it is working once enabled:

```bash
curl -i -H "Authorization: Basic dXNlcjpwYXNz" http://127.0.0.1:8080/api/admin
```

Should return `401` with `WWW-Authenticate: Basic realm="Restricted"`. The
upstream should not receive the request.

---

## Safety Model

Net Ward is fail-open and user-space only:

- No kernel hooks
- No packet tampering outside normal HTTP responses
- No hostile payloads
- No retaliation
- No phone-home and no maintainer telemetry
- If classification or mirror rendering fails, traffic is forwarded to upstream. Unmatched requests receive 503 if forwarding cannot complete; matched probes retain their decoy fallback. Storage failures keep serving with readable, cached, or bundled patterns as described above; recording a request must not block its response.
- Fail-closed (drop traffic when Net Ward cannot classify or store) is **not** implemented.

The mirror layer is meant to deflect automated abuse, not attack it back.

Login values are not a collected product. Sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, and similar) and password-like body or query keys are redacted before a probe is written to the local database. Residual risk remains: other headers, unstructured bodies, and values that do not use those key names can still be stored locally under the operator's control. Do not treat the probe log as a credential vault, and do not send real secrets in public reports.

---

## Privacy and Local Data Use

Net Ward does not send telemetry to the project maintainers and does not use
operator traffic for any external purpose.

Because Net Ward is a live reverse proxy, it keeps operator-owned local records
needed to detect and deflect DDoS, probe, and bot activity. Those records may
include source IPs, timestamps, request paths, selected (redacted) headers,
redacted query strings, request sizes, short redacted request-body snippets,
classifications, pattern matches, and alert metadata in the configured local
SQLite database.

Probe rows are bounded: older than `probe_retention_secs` or beyond
`probe_max_rows` are purged on write. That is the "bounded logs" guarantee —
without those caps the probe table would grow without limit.

That data stays under the operator's control. It is not uploaded, sold, shared,
or used by the Net Ward project. Its purpose is limited to local attack-point
detection, abuse-pattern review, alerting, and improving the operator's own
deflection rules. Redaction reduces accidental credential retention; it is not
a promise that no login-like value can ever appear in a local row.

Do not send real credentials, private customer data, or full traffic captures in
public issues or support requests. Share sanitized examples only.

---

## Known Limitations and Roadmap

- Some pattern kinds are intentionally conservative or deferred. Net Ward favors
  fail-open behavior over blocking uncertain traffic.
- Mirror responses are only as complete as the installed response set. Operators
  should treat them as deflection surfaces, not a full deception platform.
- Resource monitoring guidance is based on local testing and operator review, not
  automatic telemetry.

See [CHANGELOG.md](CHANGELOG.md) for release notes and planned refinements.

---

## Support

**Net Ward is free and open source, and it stays that way.** Nothing is paywalled and no feature is held back for sponsors.

If Net Ward is saving your service some grief and you'd like to help keep it tested and moving toward v0.5, support is **optional** and always appreciated:

- [GitHub Sponsors](https://github.com/sponsors/Dragon-Lady)
- [Buy Me a Coffee](https://buymeacoffee.com/dragonladytools)

---

## Files

| File | Purpose |
|------|---------|
| `capture.py` | Reverse proxy and request capture |
| `classify.py` | Pattern matching and flood classification |
| `mirror.py` | Safe mirror response rendering |
| `storage.py` | SQLite persistence |
| `bootstrap.py` | Vendor pattern seeding |
| `cli.py` | Operator management commands |
| `report.py` | Read-only probe report |
| `data/vendor_patterns.json` | Bundled default probe patterns |
| `operator_layer.py` | Config validation and alert surface |

---

*[Net Ward v0.5.1](CHANGELOG.md)*
