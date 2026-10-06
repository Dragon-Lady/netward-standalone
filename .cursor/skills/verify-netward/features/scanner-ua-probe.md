# Scanner User-Agent probe

Scanner User-Agent probe lets an operator confirm that requests carrying a known scanner tool in `User-Agent` (sqlmap, nikto, nuclei, …) are mirrored even on an otherwise clean path, while a normal browser UA on the same path passes through.

## Sub-features

- `scanner-ua-mirrored` mirrors `GET /healthz` sent with `User-Agent: sqlmap/1.7`.
- `normal-ua-passes` passes the same path with a normal UA to upstream.
- `header-isolation` keeps the scanner request out of the upstream hit log.

## How to get to it (user POV)

- With vendor patterns installed, any request whose `User-Agent` matches `scanner_ua_probe` is mirrored (header-kind pattern; header name defaults to `User-Agent`).

## Driving it with curl+cli

Preconditions:

- Doctor is green; `scanner_ua_probe` appears in `list-patterns`.
- `$NETWARD_VERIFY_UPSTREAM_HITS` truncated for this recipe.

- **Normal UA.** Run `curl -sS -A "Mozilla/5.0" -D "$EVIDENCE/normal.headers.txt" -o "$EVIDENCE/normal.body.txt" "$NETWARD_VERIFY_LISTEN/healthz"`. Status `200`, body `from upstream`; hits contain `/healthz`.
- **Scanner UA.** Truncate hits, then run `curl -sS -A "sqlmap/1.7" -D "$EVIDENCE/scanner.headers.txt" -o "$EVIDENCE/scanner.body.txt" "$NETWARD_VERIFY_LISTEN/healthz"`. Body is not `from upstream`; hits do not contain `/healthz`.
- **Proof.** Save both header/body pairs, both hits snapshots, and `meta.txt` under `evidence/<RUN_ID>/scanner-ua-probe/`.

## Gotchas

- curl's default UA (`curl/x.y`) is not a scanner signature; pass `-A` explicitly for both legs so the proof does not depend on curl's default.
- Use a path that is otherwise clean (`/healthz`) so the mirror is attributable to the header, not the path.
