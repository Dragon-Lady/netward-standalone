# World-writable DB refusal

World-writable DB refusal lets an operator confirm that Net Ward refuses to start when its SQLite storage path (or the directory it would be created in) is world-writable, and only proceeds when `--allow-permissive-db` is passed explicitly.

## Sub-features

- `refuse-start` exits `1` with `Config error: ERROR: storage path permissions are too permissive … world-writable` and never binds.
- `override-flag` with `--allow-permissive-db`, prints the same warning plus `Proceeding because --allow-permissive-db was set.` and binds.

## How to get to it (user POV)

- `python -m netward --config config.json` with `storage_path` under a world-writable location (README Run: keep `storage_path` non-world-writable); `--allow-permissive-db` is the documented override (`python -m netward --help`).

## Driving it with curl+cli

Preconditions:

- A launched verify state dir exists (`$NETWARD_VERIFY_STATE_DIR`); this recipe only writes inside it.
- Pick a fresh free port for the second daemon; never reuse `$NETWARD_VERIFY_LISTEN_PORT`.

- **Prepare.** `mkdir "$NETWARD_VERIFY_STATE_DIR/permcheck" && chmod 0777 "$NETWARD_VERIFY_STATE_DIR/permcheck"`, then copy `$NETWARD_VERIFY_CONFIG` to `permcheck.json` with `storage_path` set to `…/permcheck/netward-verify.db` and `listen_address` set to the fresh port.
- **Refuse.** Run `timeout 10 "$NETWARD_PYTHON" -m netward --config permcheck.json`. Exit `1`; stderr contains `world-writable`; the fresh port never accepts a connection; no DB file is created.
- **Override.** Run `timeout 4 "$NETWARD_PYTHON" -m netward --config permcheck.json --allow-permissive-db` (backgrounded), curl the fresh port while it runs. Stderr contains `Proceeding because --allow-permissive-db was set.`; curl gets an HTTP status; `timeout` reaps the process (exit `124`).
- **Proof.** Save both stderr files, exit codes, the override curl status, and `meta.txt` under `evidence/<RUN_ID>/world-writable-db-refusal/`.

## Gotchas

- When the DB file does not exist yet, the check targets its parent directory; when it exists, it checks the file mode.
- Always wrap these starts in `timeout` so no second daemon can outlive the recipe; confirm the fresh port is closed afterwards.
- `helpers/launch.sh` always passes `--allow-permissive-db`, so normal launches never exercise this guard.
