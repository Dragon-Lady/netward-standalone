"""
Net Ward -- Classify Layer

Given a Probe and context (installed Patterns, Source state, rate window),
return a ClassifyResult with the routing decision.

classify(probe, ctx) -> ClassifyResult
    Core pipeline. No I/O -- all state arrives via ctx. Fail-safe: any
    NotImplementedError from unsupported Pattern kinds is swallowed so
    one bad pattern can never crash classification of legitimate traffic.

update_source_reputation(source) -> Source
    Recalculate reputation from cumulative probe_count.
    Returns updated copy; caller is responsible for persisting.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Optional, TypedDict

_log = logging.getLogger(__name__)
_warned_pattern_ids: set[str] = set()  # emit one warning per pattern id, not per request

from netward.schema import (
    Pattern,
    Probe,
    Source,
    PROBES_TO_SUSPICIOUS,
    PROBES_TO_KNOWN_BAD,
)


class ClassifyContext(TypedDict, total=False):
    patterns: list[Pattern]
    source: Optional[Source]
    rate_window: list[float]  # recent request timestamps from this source


class ClassifyResult(TypedDict):
    probe: Probe
    fire_mirror: bool
    mirror_response_id: Optional[str]


# Requests within this window that trigger flood classification
FLOOD_WINDOW_SECS: float = 1.0
FLOOD_THRESHOLD: int = 30

_ORIGIN_RANK: dict[str, int] = {"operator": 0, "vendor": 1, "mesh": 2, "local": 3}


def _pattern_sort_key(p: Pattern) -> tuple:
    origin = p.get("origin", "local")
    rank = _ORIGIN_RANK.get(origin, 3)
    # mesh: highest confidence first; local: highest match_count first
    secondary = -(p.get("confidence", 0.0)) if origin == "mesh" else 0
    tertiary = -(p.get("match_count", 0)) if origin == "local" else 0
    return (rank, secondary, tertiary)


def _match_pattern(probe: Probe, pattern: Pattern) -> bool:
    """
    Returns True if probe matches pattern.
    Raises NotImplementedError for kinds not yet implemented (body, timing,
    method, tls_fingerprint, asn_burst, composite -- deferred to v0.2).
    Callers must catch NotImplementedError and skip the pattern.
    """
    kind = pattern.get("kind")
    sig = pattern.get("signature", "")
    req = probe.get("request", {})

    if kind == "path":
        return bool(re.search(sig, req.get("path", "")))
    if kind == "header":
        headers = req.get("headers", {})
        return any(bool(re.search(sig, v, re.IGNORECASE)) for v in headers.values())
    raise NotImplementedError(f"kind={kind!r} deferred to v0.2")


def classify(probe: Probe, ctx: ClassifyContext) -> ClassifyResult:
    """
    Classification pipeline (evaluated in order):
    1. known_bad source  -> fire mirror immediately, skip pattern scan
    2. flood             -> FLOOD_THRESHOLD requests within FLOOD_WINDOW_SECS
    3. pattern match     -> ordered: operator > vendor > mesh > local
    4. no match          -> unknown (caller routes upstream)
    """
    source: Optional[Source] = ctx.get("source")
    patterns: list[Pattern] = ctx.get("patterns") or []
    rate_window: list[float] = ctx.get("rate_window") or []
    now = time.time()

    updated: Probe = dict(probe)  # type: ignore[assignment]

    # 1. known_bad: skip pattern scan entirely
    if source and source.get("reputation") == "known_bad":
        updated["classification"] = "probe"
        updated["mirror_fired"] = True
        return {"probe": updated, "fire_mirror": True, "mirror_response_id": None}

    # 2. flood check
    recent = sum(1 for t in rate_window if now - t <= FLOOD_WINDOW_SECS)
    if recent >= FLOOD_THRESHOLD:
        updated["classification"] = "flood"
        updated["mirror_fired"] = True
        return {"probe": updated, "fire_mirror": True, "mirror_response_id": None}

    # 3. pattern match (operator > vendor > mesh by confidence > local by match_count)
    for pattern in sorted(patterns, key=_pattern_sort_key):
        try:
            matched = _match_pattern(probe, pattern)
        except NotImplementedError as exc:
            pat_id = pattern.get("id", "?")
            if pat_id not in _warned_pattern_ids:
                _log.warning("pattern %s skipped: %s -- deferred to v0.2", pat_id, exc)
                _warned_pattern_ids.add(pat_id)
            continue
        if matched:
            updated["classification"] = "probe"
            updated["pattern_id"] = pattern["id"]
            updated["mirror_fired"] = True
            mr_id = pattern.get("mirror_response_id")
            if mr_id:
                updated["response_id"] = mr_id
            return {"probe": updated, "fire_mirror": True, "mirror_response_id": mr_id}

    # 4. no match
    updated["classification"] = "unknown"
    updated["upstream_passed"] = True
    return {"probe": updated, "fire_mirror": False, "mirror_response_id": None}


def update_source_reputation(source: Source) -> Source:
    """Flip reputation at thresholds. Returns updated copy; does not persist."""
    updated: Source = dict(source)  # type: ignore[assignment]
    count = updated.get("probe_count", 0)
    rep = updated.get("reputation", "neutral")
    if rep in ("clean", "neutral") and count >= PROBES_TO_SUSPICIOUS:
        updated["reputation"] = "suspicious"
    elif rep == "suspicious" and count >= PROBES_TO_KNOWN_BAD:
        updated["reputation"] = "known_bad"
    return updated
