# Vendor path probes

Vendor path probes lets an operator confirm that the bundled path-signature probes beyond WordPress (secret files, VCS metadata, XML-RPC, database admin panels, generic admin logins) are answered by Net Ward's mirror layer and never reach upstream.

## Sub-features

- `env-file` mirrors `GET /.env` (`env_file_probe`).
- `git-config` mirrors `GET /.git/config` (`git_config_probe`).
- `xmlrpc` mirrors `GET /xmlrpc.php` (`wordpress_xmlrpc_probe`).
- `phpmyadmin` mirrors `GET /phpmyadmin/` (`phpmyadmin_probe`).
- `generic-admin` mirrors `GET /admin` (`generic_admin_login_probe`).
- `upstream-isolation` leaves the upstream hit log without any of those paths.

## How to get to it (user POV)

- With Net Ward running and vendor patterns installed (auto-seeded on first start), request any of those paths through the listen address. README Operator Commands notes `/admin` is mirrored by `generic_admin_login_probe`.

## Driving it with curl+cli

Preconditions:

- Doctor is green; the five pattern IDs above appear in `list-patterns` (IDs are truncated to 36 chars there).
- `$NETWARD_VERIFY_UPSTREAM_HITS` truncated for this recipe.

- **Warm upstream.** Run `curl -sS -o /dev/null -w "%{http_code}\n" "$NETWARD_VERIFY_LISTEN/"`. Expect `200`; hits contain `/`.
- **Each probe path.** For `p` in `/.env /.git/config /xmlrpc.php /phpmyadmin/ /admin`, run `curl -sS -D "$EVIDENCE/<name>.headers.txt" -o "$EVIDENCE/<name>.body.txt" "$NETWARD_VERIFY_LISTEN$p"`. Each returns an HTTP status and a body that is not exactly `from upstream`.
- **Upstream isolation.** Read `"$NETWARD_VERIFY_UPSTREAM_HITS"`. It contains only `/` (from the warm request), none of the probe paths.
- **Proof.** Save headers, bodies, hits snapshot, and `meta.txt` under `evidence/<RUN_ID>/vendor-path-probes/`.

## Gotchas

- Mirror status varies per pattern and response template (200/401/403/404/503 all occur); assert "not upstream body" + "not in hits".
- `/admin` is mirrored by default. An operator with a real `/admin` must disable `generic_admin_login_probe`; do not "fix" that by editing the pattern during verification.
- `/phpmyadmin` without a trailing slash also matches; keep the recipe's exact paths so evidence is comparable run to run.
