"""
Net Ward -- Bootstrap

Refresh storage with the built-in vendor definitions on startup.
Called automatically by start_capture_loop before the proxy binds.

install_vendor_patterns(storage, force=False) -> tuple[int, int]
    Reads netward/data/vendor_patterns.json, upserts MirrorResponses
    then Patterns, preserving operator policy and match history.
    Returns (patterns_installed, mirrors_installed).

Raises BootstrapError on malformed JSON — never touches storage in
that case, so storage is always left in a consistent state.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from netward.regex_policy import PatternPolicyError

_VENDOR_DATA_PATH = Path(__file__).parent / "data" / "vendor_patterns.json"


class BootstrapError(Exception):
    pass


def load_vendor_data(_data_path: Optional[Path] = None) -> dict:
    """Read bundled patterns and mirror bodies without depending on storage."""
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

    return {"mirror_responses": mirrors, "patterns": patterns}


def install_vendor_patterns(
    storage,
    force: bool = False,
    _data_path: Optional[Path] = None,
) -> tuple[int, int]:
    """
    Seed vendor patterns + mirror responses into storage.

    force=False  -- insert missing definitions and refresh changed definitions.
    force=True   -- refresh all vendor definitions, preserving policy/history.
    _data_path   -- override for tests; production always uses the package default.

    Returns (patterns_installed, mirrors_installed).
    """
    data = load_vendor_data(_data_path)
    mirrors, patterns = data["mirror_responses"], data["patterns"]
    now = time.time()
    try:
        mirrors = [dict(m, created_at=m.get("created_at") or now) for m in mirrors]
        patterns = [dict(p, created_at=p.get("created_at") or now) for p in patterns]
        mirror_ids = {m["id"] for m in mirrors}
        if len(mirror_ids) != len(mirrors) or len({p["id"] for p in patterns}) != len(patterns):
            raise ValueError("duplicate vendor definition id")
        if any(p["origin"] != "vendor" or p.get("mirror_response_id") not in mirror_ids
               for p in patterns):
            raise ValueError("invalid vendor origin or mirror reference")
        return storage.install_vendor_bundle(patterns, mirrors, force=force)
    except PatternPolicyError:
        raise
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise BootstrapError("invalid vendor definition structure") from exc
