# Net Ward

**A user-space deception layer that turns DDoS and bot abuse into wasted effort.**

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](CHANGELOG.md)

Net Ward sits in front of your HTTP service as a reverse proxy. Real traffic passes through untouched. Known probes and floods get harmless **mirror responses** that burn bot effort and never reach your app — no kernel hooks, no payloads, no retaliation, **fail-open by design**.

### Why Net Ward

- **Deflects, doesn't fight back.** Bots waste time on convincing-but-harmless mirrors; your upstream never sees the request.
- **User-space and fail-open.** No kernel modules, no packet tampering. If classification or rendering ever fails, traffic passes straight through to upstream.
- **Drops in anywhere.** One Python process in front of any HTTP service. Point your load balancer at it and go.
- **Honest by design.** No telemetry, no harvested credentials, operator owns every byte of local data. Apache-2.0.

> **Built and maintained by Dragon Lady** — [github.com/Dragon-Lady](https://github.com/Dragon-Lady) · X: [@answerislove2](https://x.com/answerislove2)
> Independent security researcher tracking live supply-chain and bot-abuse campaigns in the wild.

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

Optional fields control mirror intensity, local storage, mesh placeholders, and alert channels. v0.4.1 logs alerts to stdout; external alert delivery is reserved for a later release.

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
netward --db netward.db enable-pattern basic_auth_probe
```

Disable again:

```bash
netward --db netward.db disable-pattern basic_auth_probe
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
- No collection of submitted login values
- No retaliation
- If classification, storage, or mirror rendering fails, traffic passes to upstream

The mirror layer is meant to deflect automated abuse, not attack it back.

---

## Privacy and Local Data Use

Net Ward does not send telemetry to the project maintainers and does not use
operator traffic for any external purpose.

Because Net Ward is a live reverse proxy, it keeps operator-owned local records
needed to detect and deflect DDoS, probe, and bot activity. Those records may
include source IPs, timestamps, request paths, selected headers, query strings,
request sizes, short request-body snippets, classifications, pattern matches,
and alert metadata in the configured local SQLite database.

That data stays under the operator's control. It is not uploaded, sold, shared,
or used by the Net Ward project. Its purpose is limited to local attack-point
detection, abuse-pattern review, alerting, and improving the operator's own
deflection rules.

Do not send real credentials, private customer data, or full traffic captures in
public issues or support requests. Share sanitized examples only.

---

## Known Limitations and Roadmap

- v0.4.1 logs alerts to stdout only. External alert delivery is reserved for a
  later release.
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
| `data/vendor_patterns.json` | Bundled default probe patterns |
| `operator_layer.py` | Config validation and alert surface |

---

*[Net Ward v0.4.1](CHANGELOG.md)*
