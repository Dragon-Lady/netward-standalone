"""
Net Ward -- Bootstrap

Seed storage with the built-in vendor pattern set on first run.
Called automatically by start_capture_loop before the proxy binds.

install_vendor_patterns(storage, force=False) -> tuple[int, int]
    Reads netward/data/vendor_patterns.json, upserts MirrorResponses
    then Patterns. Idempotent: second call is a no-op unless force=True.
    Returns (patterns_installed, mirrors_installed).

Raises BootstrapError on malformed JSON — never touches storage in
that case, so storage is always left in a consistent state.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

_VENDOR_DATA_PATH = Path(__file__).parent / "data" / "vendor_patterns.json"


class BootstrapError(Exception):
    pass


def install_vendor_patterns(
    storage,
    force: bool = False,
    _data_path: Optional[Path] = None,
) -> tuple[int, int]:
    """
    Seed vendor patterns + mirror responses into storage.

    force=False  -- no-op if any vendor-origin patterns already exist.
    force=True   -- re-upserts regardless of existing state.
    _data_path   -- override for tests; production always uses the package default.

    Returns (patterns_installed, mirrors_installed).
    """
    # Idempotency guard
    if not force:
        try:
            existing = storage.patterns_active()
            if any(p.get("origin") == "vendor" for p in existing):
                return (0, 0)
        except Exception:
            pass  # storage errors fall through to a fresh install attempt

    # Validate JSON before touching storage
    data_path = _data_path or _VENDOR_DATA_PATH
    try:
        raw = Path(data_path).read_text(encoding="utf-8")
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BootstrapError(f"vendor_patterns.json is invalid JSON: {exc}") from exc
    except OSError as exc:
        raise BootstrapError(f"cannot read vendor_patterns.json: {exc}") from exc

    mirrors = data.get("mirror_responses", [])
    patterns = data.get("patterns", [])
    if not isinstance(mirrors, list) or not isinstance(patterns, list):
        raise BootstrapError(
            "vendor_patterns.json must have 'mirror_responses' and 'patterns' arrays"
        )

    now = time.time()

    # Upsert mirrors first — patterns reference them by id
    mirrors_installed = 0
    for mr in mirrors:
        mr = dict(mr)
        if not mr.get("created_at"):
            mr["created_at"] = now
        storage.mirror_response_upsert(mr)
        mirrors_installed += 1

    # Upsert patterns
    patterns_installed = 0
    for pat in patterns:
        pat = dict(pat)
        if not pat.get("created_at"):
            pat["created_at"] = now
        storage.patterns_upsert(pat)
        patterns_installed += 1

    return (patterns_installed, mirrors_installed)
