# WordPress probe mirror

WordPress probe mirror lets an operator confirm that a known WordPress admin probe is answered by Net Ward's mirror layer and never reaches the upstream app.

## Sub-features

- `mirror-wp-admin` returns a mirror for `GET /wp-admin/`.
- `mirror-wp-login` returns a mirror for `GET /wp-login.php`.
- `mirror-blocks-upstream` leaves the upstream hit log without those paths.

## How to get to it (user POV)

- With Net Ward running and vendor patterns installed, request `/wp-admin/` or `/wp-login.php` (README Verify section).

## Driving it with curl+cli

Preconditions:

- Doctor is green; `wordpress_admin_probe` appears in `list-patterns`.
- `$NETWARD_VERIFY_UPSTREAM_HITS` truncated for this recipe.
- Optionally warm the hit log with one clean request first so upstream liveness is proven.

- **Warm upstream.** Run `curl -sS -o /dev/null -w "%{http_code}\n" "$NETWARD_VERIFY_LISTEN/"`. Expect `200`. Hits file contains `/`.
- **Probe path.** Run `curl -sS -D "$EVIDENCE/response.headers.txt" -o "$EVIDENCE/response.body.txt" "$NETWARD_VERIFY_LISTEN/wp-admin/"`. Status is one of `200`, `401`, `403`, `429`, `503` (mirror variants). Body must **not** be exactly `from upstream`. A WordPress-themed or fake login/HTML/JSON mirror is expected.
- **Confirm upstream isolation.** Read `"$NETWARD_VERIFY_UPSTREAM_HITS"`. It must not contain `/wp-admin/` (warm `/` may remain).
- **Alternate entry.** Run the same curl against `/wp-login.php`. Same isolation rule.
- **Proof.** Save curl outputs, hits snapshot, and `meta.txt` under `evidence/<RUN_ID>/wordpress-probe-mirror/`.

## Gotchas

- Mirror HTTP status is intentionally varied; assert "not upstream body" + "not in hits", not a single status code.
- Pattern must be enabled. If someone disabled `wordpress_admin_probe`, this feature fails closed into pass-through — report disable-enable separately.
- Trailing slash matters for some signatures; prefer `/wp-admin/` as in the README.
