# Basic auth probe (optional pattern)

Basic auth probe lets an operator opt in to mirroring `Authorization: Basic …` credential-stuffing requests with a fake 401 challenge, and opt back out. It ships disabled because it would trap real Basic-Auth users.

## Sub-features

- `default-disabled` passes a Basic-Auth request to upstream out of the box.
- `enable-401` after `enable-pattern basic_auth_probe`, returns `401` with `WWW-Authenticate: Basic realm="Restricted"`.
- `disable-restores` after `disable-pattern basic_auth_probe`, Basic-Auth requests pass to upstream again.

## How to get to it (user POV)

- README Optional Patterns: `netward-cli --db netward.db enable-pattern basic_auth_probe` / `disable-pattern basic_auth_probe`, then `curl -i -H "Authorization: Basic dXNlcjpwYXNz" …/api/admin`.

## Driving it with curl+cli

Preconditions:

- Doctor is green; `basic_auth_probe` is **absent** from `list-patterns` (disabled by default).
- Use the venv console script `"$(dirname "$NETWARD_PYTHON")/netward-cli"` so the README entry point is exercised.

- **Default disabled.** Truncate hits, then `curl -sS -i -H "Authorization: Basic dXNlcjpwYXNz" "$NETWARD_VERIFY_LISTEN/api/admin"`. Body `from upstream`; hits contain `/api/admin`.
- **Enable.** Run `"$(dirname "$NETWARD_PYTHON")/netward-cli" --db "$NETWARD_VERIFY_DB" enable-pattern basic_auth_probe`. Exit `0`, stdout `Pattern 'basic_auth_probe' enabled.`; `list-patterns` now includes it.
- **401 challenge.** Wait 31s (pattern cache TTL), truncate hits, repeat the curl. Status `401`, header `WWW-Authenticate: Basic realm="Restricted"`; hits do not contain `/api/admin`.
- **Disable.** Run `"$(dirname "$NETWARD_PYTHON")/netward-cli" --db "$NETWARD_VERIFY_DB" disable-pattern basic_auth_probe`. Exit `0`.
- **Restored.** Wait 31s, truncate hits, repeat the curl. Body `from upstream`; hits contain `/api/admin`.
- **Proof.** Save CLI transcripts, all three curl responses, hits snapshots, and `meta.txt` under `evidence/<RUN_ID>/basic-auth-probe/`.

## Gotchas

- `netward` (no `-cli`) is the proxy entry point and requires `--config`; the management console script is `netward-cli`.
- Routing only flips after the 30s pattern cache expires; a curl right after the CLI toggle still shows the old behavior.
- Always end with the pattern **disabled** so later recipes see shipped defaults.
