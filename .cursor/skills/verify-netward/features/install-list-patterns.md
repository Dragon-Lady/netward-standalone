# Install and list patterns

Install and list patterns lets an operator seed the bundled vendor pattern set into the local SQLite DB and inspect which patterns are active.

## Sub-features

- `install-seed` installs vendor patterns into an empty or existing DB.
- `install-idempotent` reports already-installed without `--force`.
- `list-active` prints active pattern rows including `wordpress_admin_probe`.

## How to get to it (user POV)

- Run `python -m netward.cli --db netward.db install-patterns` and `… list-patterns` (README Operator Commands). First proxy start also auto-seeds.

## Driving it with curl+cli

Preconditions:

- Doctor is green (auto-seed already ran on launch) **or** a fresh `$NETWARD_VERIFY_DB` path is available.
- Use only the disposable verify DB.

- **List after launch.** Run `"$NETWARD_PYTHON" -m netward.cli --db "$NETWARD_VERIFY_DB" list-patterns`. Exit code `0`. Stdout includes a header and `wordpress_admin_probe`.
- **Idempotent install.** Run `"$NETWARD_PYTHON" -m netward.cli --db "$NETWARD_VERIFY_DB" install-patterns`. Exit code `0`. Stdout contains `Vendor patterns already installed` (or a non-zero installed count only on a truly empty DB).
- **Force reinstall.** Run `"$NETWARD_PYTHON" -m netward.cli --db "$NETWARD_VERIFY_DB" install-patterns --force`. Exit code `0`. Stdout reports installed pattern/mirror counts.
- **Proof.** Save stdout/stderr/exit for each command under `evidence/<RUN_ID>/install-list-patterns/`.

## Gotchas

- The proxy entrypoint (`python -m netward`) is not the management CLI; use `python -m netward.cli`.
- Always pass `--db` to the verify DB. A bare `netward.db` in the repo cwd is operator data — do not use or delete it.
- `list-patterns` shows active patterns only; disabled ones disappear from the list until re-enabled. `basic_auth_probe` ships disabled, so `--force` reports 17 installed but 16 are listed.
- The ID column is truncated to 36 characters (e.g. `brickstorm_pfsense_ipsec_blacklist_p`); grep long IDs by prefix.
