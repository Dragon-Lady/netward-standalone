# Changelog

All notable changes to Net Ward are documented here.
Format follows Keep a Changelog. Versioning is semver.

## [Unreleased]

## [0.4.0] - 2026-04-30
### Added
- `pyproject.toml` enabling `pip install netward` from wheel or source
- `CHANGELOG.md` (this file) following Keep a Changelog convention
- `SECURITY.md` with vulnerability disclosure policy, supported versions,
  response SLA, and coordinated disclosure window
- `requirements.txt` annotated to document that `pynacl` is reserved for
  the v0.5 mesh layer and not exercised in v0.4

### Changed
- **BREAKING:** `netward.operator` renamed to `netward.operator_layer` to
  avoid shadowing Python's stdlib `operator` module. The shadow caused
  circular imports when builds or tools ran from inside the package
  directory. Update imports:
  `from netward.operator import X` → `from netward.operator_layer import X`

## [0.3.0] - 2026-04-30
### Added
- Apache 2.0 license and notice files.
- Docker image with multi-stage build, non-root runtime user, and config mount support at `/etc/netward/`.
- Operator README with quickstart, configuration, verification, and command reference.
- `example_config.json` with annotated operator fields.
- Buyer hygiene test gate for source cleanliness.
- `OperatorConfig.storage_path` field for configurable SQLite storage.

### Changed
- `mirror.user_agent_echo` now prefers the already-extracted `probe.request.user_agent` field.
- `random_int` mirror generator now caches parsed bounds.

### Fixed
- Pattern storage adapter now round-trips `expires_at`.
- Schema migrations now sort by target version before application.

## [0.2.0] - 2026-04-30
### Added
- Eleven-pattern vendor deception set that installs automatically on first run.
- `bootstrap.install_vendor_patterns`, with idempotent install behavior.
- Pattern management CLI commands: `install-patterns`, `list-patterns`, `disable-pattern`, and `enable-pattern`.
- Vendor pattern validation gate covering regex compilation, mirror cross-references, PII guard compatibility, hostile-marker checks, and false-positive sanity.

## [0.1.0] - 2026-04-30
### Added
- `capture` aiohttp reverse proxy with fail-open routing.
- `classify` path/header pattern matching, flood detection, and source reputation updates.
- `mirror` template substitution with XSS-safe user-agent echo and PII guard.
- `operator` config validation and alert deduplication.
- `storage` SQLite backend with schema migrations and idempotent CRUD operations.
- Seventy-nine tests across seven modules.

## [0.0.0] - 2026-04-30
### Added
- Schema contract using `TypedDict` definitions for source, pattern, probe, mirror response, mesh intel, trust, node, and operator entities.
- Module placeholders for capture, classify, mirror, operator, and mesh.
- Sixteen contract round-trip tests.
