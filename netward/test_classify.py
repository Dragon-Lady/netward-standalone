"""
Net Ward -- classify layer unit tests.
Pure logic: no I/O, no HTTP, no storage dependency.
"""
from __future__ import annotations

import time

from netward import classify as mod
from netward.schema import (
    PROBES_TO_KNOWN_BAD,
    PROBES_TO_SUSPICIOUS,
    Pattern,
    Probe,
    Source,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _probe(path: str = "/", headers: dict | None = None) -> Probe:
    return {
        "id": "test-probe",
        "timestamp": time.time(),
        "source_id": "src-1",
        "pattern_id": None,
        "classification": "unknown",
        "request": {
            "method": "GET",
            "path": path,
            "headers": headers or {"User-Agent": "pytest/1.0"},
            "body_size": 0,
        },
        "response_id": None,
        "mirror_fired": False,
        "upstream_passed": False,
    }


def _pattern(kind: str, sig: str, origin: str = "vendor", mr_id: str | None = None) -> Pattern:
    return {
        "id": f"pat-{kind}",
        "kind": kind,
        "signature": sig,
        "description": f"{kind} test pattern",
        "severity": "warn",
        "origin": origin,
        "created_at": time.time(),
        "match_count": 0,
        "confidence": 0.9,
        "mirror_response_id": mr_id,
        "mutation_generation": 0,
    }


def _source(reputation: str = "neutral", probe_count: int = 0) -> Source:
    return {
        "id": "src-1",
        "ip_address": "1.2.3.4",
        "reputation": reputation,
        "first_seen": time.time(),
        "last_seen": time.time(),
        "probe_count": probe_count,
        "legit_count": 0,
        "notes": [],
    }


def _flood_window(n: int = 30) -> list[float]:
    """n timestamps within the last 0.5 seconds."""
    now = time.time()
    return [now - 0.1] * n


# ---------------------------------------------------------------------------
# classify() -- routing decisions
# ---------------------------------------------------------------------------

class TestClassify:
    def test_path_pattern_match_fires_mirror(self):
        probe = _probe("/wp-admin/login.php")
        patterns = [_pattern("path", r"^/wp-admin\b")]
        result = mod.classify(probe, {"patterns": patterns, "source": _source()})
        assert result["fire_mirror"] is True
        assert result["probe"]["classification"] == "probe"
        assert result["probe"]["pattern_id"] == "pat-path"
        assert result["probe"]["mirror_fired"] is True

    def test_header_pattern_match_fires_mirror(self):
        probe = _probe("/", headers={"User-Agent": "masscan/1.3", "Host": "example.com"})
        patterns = [_pattern("header", r"masscan")]
        result = mod.classify(probe, {"patterns": patterns, "source": _source()})
        assert result["fire_mirror"] is True
        assert result["probe"]["classification"] == "probe"

    def test_flood_fires_mirror(self):
        result = mod.classify(
            _probe("/"),
            {"patterns": [], "source": _source(), "rate_window": _flood_window(30)},
        )
        assert result["fire_mirror"] is True
        assert result["probe"]["classification"] == "flood"

    def test_flood_below_threshold_does_not_trigger(self):
        result = mod.classify(
            _probe("/"),
            {"patterns": [], "source": _source(), "rate_window": _flood_window(29)},
        )
        assert result["fire_mirror"] is False
        assert result["probe"]["classification"] == "unknown"

    def test_no_match_returns_unknown_routes_upstream(self):
        probe = _probe("/api/v1/data")
        patterns = [_pattern("path", r"^/wp-admin\b")]
        result = mod.classify(probe, {"patterns": patterns, "source": _source()})
        assert result["fire_mirror"] is False
        assert result["probe"]["classification"] == "unknown"
        assert result["probe"]["upstream_passed"] is True

    def test_known_bad_source_fires_mirror_skips_patterns(self):
        # No patterns needed -- known_bad bypasses pattern scan entirely
        result = mod.classify(
            _probe("/perfectly/normal/path"),
            {"patterns": [], "source": _source(reputation="known_bad")},
        )
        assert result["fire_mirror"] is True
        assert result["probe"]["classification"] == "probe"

    def test_unsupported_kind_skipped_not_crashed(self):
        # timing is unsupported (raises NotImplementedError); path pattern after it must still fire
        patterns = [
            _pattern("timing", "anything"),   # NotImplementedError -- must skip
            _pattern("path", r"^/wp-admin\b"),
        ]
        result = mod.classify(
            _probe("/wp-admin/"),
            {"patterns": patterns, "source": _source()},
        )
        assert result["fire_mirror"] is True
        assert result["probe"]["classification"] == "probe"

    def test_empty_context_returns_unknown(self):
        result = mod.classify(_probe("/"), {})
        assert result["fire_mirror"] is False
        assert result["probe"]["classification"] == "unknown"

    def test_pattern_mr_id_propagated_to_result(self):
        patterns = [_pattern("path", r"^/admin", mr_id="mr-specific-99")]
        result = mod.classify(_probe("/admin/page"), {"patterns": patterns})
        assert result["mirror_response_id"] == "mr-specific-99"
        assert result["probe"]["response_id"] == "mr-specific-99"


# ---------------------------------------------------------------------------
# Pattern ordering -- operator > vendor > mesh > local
# ---------------------------------------------------------------------------

class TestPatternOrdering:
    def test_operator_pattern_evaluated_before_vendor(self):
        # Both match the same path; operator origin should win (id distinguishes)
        operator_pat = {**_pattern("path", r"^/admin"), "id": "op-1", "origin": "operator"}
        vendor_pat = {**_pattern("path", r"^/admin"), "id": "vnd-1", "origin": "vendor"}
        result = mod.classify(
            _probe("/admin/"),
            {"patterns": [vendor_pat, operator_pat], "source": _source()},
        )
        assert result["probe"]["pattern_id"] == "op-1"

    def test_mesh_patterns_sorted_by_confidence(self):
        low = {**_pattern("path", r"^/admin"), "id": "mesh-low", "origin": "mesh", "confidence": 0.6}
        high = {**_pattern("path", r"^/admin"), "id": "mesh-high", "origin": "mesh", "confidence": 0.95}
        result = mod.classify(
            _probe("/admin/"),
            {"patterns": [low, high], "source": _source()},
        )
        assert result["probe"]["pattern_id"] == "mesh-high"


# ---------------------------------------------------------------------------
# update_source_reputation()
# ---------------------------------------------------------------------------

class TestUpdateSourceReputation:
    def test_neutral_flips_to_suspicious_at_threshold(self):
        src = _source(reputation="neutral", probe_count=PROBES_TO_SUSPICIOUS)
        updated = mod.update_source_reputation(src)
        assert updated["reputation"] == "suspicious"

    def test_suspicious_flips_to_known_bad_at_threshold(self):
        src = _source(reputation="suspicious", probe_count=PROBES_TO_KNOWN_BAD)
        updated = mod.update_source_reputation(src)
        assert updated["reputation"] == "known_bad"

    def test_below_threshold_no_change(self):
        src = _source(reputation="neutral", probe_count=PROBES_TO_SUSPICIOUS - 1)
        updated = mod.update_source_reputation(src)
        assert updated["reputation"] == "neutral"

    def test_does_not_mutate_original(self):
        src = _source(reputation="neutral", probe_count=PROBES_TO_SUSPICIOUS)
        mod.update_source_reputation(src)
        assert src["reputation"] == "neutral"  # original untouched
