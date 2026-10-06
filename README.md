# Net Ward

**A user-space deception layer that turns DDoS and bot abuse into wasted effort.**

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](CHANGELOG.md)

Net Ward sits in front of your HTTP service as a reverse proxy. Real traffic passes through untouched. Known probes and floods get harmless **mirror responses** that burn bot effort and never reach your app — no kernel hooks, no payloads, no retaliation, **fail-open by design**.

### Why Net Ward

- **Deflects, doesn't fight back.** Bots waste time on convincing-but-harmless mirrors; your upstream never sees the request.
- **User-space and fail-open.** No kernel modules, no packet tampering. If classification, a storage read, or rendering ever fails, traffic passes straight through to upstream (or the default mirror if upstream is down).
- **Drops in anywhere.** One Python process in front of any HTTP service. Point your load balancer at it and go.
- **Honest by design.** No telemetry, no harvested credentials, operator owns every byte of local data. Apache-2.0.

> **Built and maintained by Dragon Lady** — [github.com/Dragon-Lady](https://github.com/Dragon-Lady) · X: [@answerislove2](https://x.com/answerislove2)
> Independent security researcher tracking live supply-chain and bot-abuse campaigns in the wild.

**Website:** [dragon-lady.github.io/netward-standalone](https://dragon-lady.github.io/netward-standalone/)

---

## Quick Start

```bash
pip install netward
python -m netward --config example_config.json
```

Or from source:

```bash
git clone https://github.com/Dragon-Lady/netward-standalone
cd netward-standalone
pip install -e .
```

Net Ward listens on `listen_address` and forwards clean traffic to `upstream_target`.

---

## Configuration

Copy the example config and edit the upstream target:

```bash
cp example_config.json config.json
```

Point `upstream_target` at a real HTTP service before you start Net Ward. If
the upstream is unreachable, unmatched requests return a default mirror response
instead of exposing a raw proxy error.

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
| `upstream_max_body_bytes` | `8388608` | Max buffered upstream response body (8 MiB). Larger bodies fail-open to the default mirror |
| `probe_retention_secs` | `604800` | Probe-log TTL (7 days) |
| `probe_max_rows` | `10000` | Max probe-log rows after purge-on-write |

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

The WordPress probe returns a fake login page. The upstream service does not receive the request.

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

List active patterns:

```bash
python -m netward.cli --db netward.db list-patterns
```

Read a probe report without writing the database. The report is aggregate
counts: which probe families fired, where on the site they landed, and how
many sources were involved. It does not print raw IP addresses or geography.
Output files are owner-only (`0600`). `--send` delivers that digest once
through the alert channels in the config file.

```bash
python -m netward.cli --db netward.db report
python -m netward.cli --db netward.db report --since 7d --format md --output report.md
python -m netward.cli --db netward.db report --format html --output report.html
python -m netward.cli --db netward.db report --family wordpress --top 10
python -m netward.cli --db netward.db report --send --config config.json
```

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
- If classification, a storage **read**, or mirror rendering fails, traffic is forwarded to upstream. If upstream is also unreachable, the default mirror is returned. Storage failures must not 500 the request path.
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

*[Net Ward v0.4.9](CHANGELOG.md)*
