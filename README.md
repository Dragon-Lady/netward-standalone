# Net Ward
**User-space DDoS and bot deflection for small teams.**

Net Ward runs in front of an HTTP service as a reverse proxy. Normal traffic passes through. Known probe and abuse patterns receive harmless mirror responses that waste bot effort without damaging the client, the protected application, or the host system.

---

## Quick Start

```bash
pip install -e netward/
python -m netward --config netward/example_config.json
```

Net Ward listens on `listen_address` and forwards clean traffic to `upstream_target`.

---

## Configuration

Copy the example config and edit the upstream target:

```bash
cp netward/example_config.json config.json
```

Required fields:

| Field | Meaning |
|-------|---------|
| `node_id` | Stable name for this Net Ward instance |
| `upstream_target` | HTTP service being protected |
| `listen_address` | Host and port Net Ward binds |

Optional fields control mirror intensity, local storage, mesh placeholders, and alert channels. v0.3 logs alerts to stdout; external alert delivery is reserved for a later release.

---

## Run

```bash
python -m netward --config config.json
```

Example topology:

| Component | Address |
|-----------|---------|
| Net Ward | `0.0.0.0:8080` |
| Upstream app | `http://127.0.0.1:9000` |
| Storage | `netward.db` |

Point your load balancer or web server at Net Ward. Keep the upstream app reachable only from the host or trusted network when possible.

---

## Verify

Clean request should reach upstream:

```bash
curl -i http://127.0.0.1:8080/
```

Known probe should be mirrored:

```bash
curl -i http://127.0.0.1:8080/wp-admin/
curl -i -H "Authorization: Basic dXNlcjpwYXNz" http://127.0.0.1:8080/api/admin
```

The Basic authorization probe should return `401` with a fake realm. The upstream service should not receive that request.

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
| `operator.py` | Config validation and alert surface |

---

*Net Ward v0.3*
