# Config validation

Config validation lets an operator confirm that Net Ward rejects bad config files with a clear `Config error:` message and exit `1` before binding: YAML is not accepted, required fields must be present, and `alert_channels` must be a list.

## Sub-features

- `yaml-rejected` a `.yaml` config fails with `YAML config loading deferred to a later release; use JSON`.
- `non-json-rejected` a `.txt` config fails with `config file must be JSON for the standalone release`.
- `missing-fields` a JSON config without `listen_address` fails with `missing required config fields: listen_address`.
- `bad-alert-channels` `"alert_channels": "email"` fails with `alert_channels must be a list`.

## How to get to it (user POV)

- `python -m netward --config <file>` (README Configuration: required fields `node_id`, `upstream_target`, `listen_address`; example_config.json is JSON).

## Driving it with curl+cli

Preconditions:

- A launched verify state dir exists; write the bad configs inside `$NETWARD_VERIFY_STATE_DIR/configcheck/`.

- **YAML.** Write `bad.yaml` (any content), run `timeout 10 "$NETWARD_PYTHON" -m netward --config bad.yaml`. Exit `1`; stderr `Config error: YAML config loading deferred …`.
- **Non-JSON suffix.** Same with `bad.txt`. Exit `1`; stderr contains `must be JSON`.
- **Missing field.** Copy `$NETWARD_VERIFY_CONFIG` minus `listen_address` to `missing.json`, run it. Exit `1`; stderr `Config error: missing required config fields: listen_address`.
- **Bad alert_channels.** Copy the config with `"alert_channels": "email"` to `alerts.json`, run it. Exit `1`; stderr contains `alert_channels must be a list`.
- **Proof.** Save each config file, stderr, and exit code plus `meta.txt` under `evidence/<RUN_ID>/config-validation/`.

## Gotchas

- Every case must exit before binding; wrap in `timeout` anyway so a validation regression cannot leave a daemon running.
- Exit `124` from `timeout` means the daemon started — that is a failed proof, not a pass.
