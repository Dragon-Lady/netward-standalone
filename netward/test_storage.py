"""
Tests for netward.storage — sqlite3 backend for the standalone build.

Coverage:
- Schema migration creates tables and records version
- Source upsert + lookup round-trip
- Source upsert is idempotent (same id, second call updates)
- Pattern upsert + active list filters expired
- Pattern purge removes expired
- Probe log + recent_for_source counts within window
- MirrorResponse upsert + lookup round-trip
- MeshIntel archive round-trip
- Alert upsert + recent within window
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid

import pytest

from netward.schema import (
    MeshIntel,
    MirrorResponse,
    OperatorAlert,
    Pattern,
    Probe,
    RequestMetadata,
    Source,
)
from netward.storage import Storage


@pytest.fixture
def storage(tmp_path):
    db = tmp_path / "netward_test.db"
    s = Storage(db)
    yield s
    s.close()


# ----- schema migration -----

def test_storage_creates_tables(storage):
    cur = storage._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    names = {r["name"] for r in cur.fetchall()}
    assert {"sources", "patterns", "probes", "mirror_responses",
            "mesh_intel", "alerts", "_schema_version"} <= names


def test_storage_records_schema_version(storage):
    row = storage._conn.execute(
        "SELECT MAX(version) AS v FROM _schema_version"
    ).fetchone()
    assert row["v"] is not None
    assert row["v"] >= 0


def test_existing_v1_alerts_migrate_without_losing_rows(tmp_path):
    db = tmp_path / "v1.db"
    with sqlite3.connect(db) as conn:
        conn.executescript("""
            CREATE TABLE _schema_version(version INTEGER PRIMARY KEY, applied_at REAL);
            INSERT INTO _schema_version VALUES (1, 1);
            CREATE TABLE alerts (
              id TEXT PRIMARY KEY, severity TEXT NOT NULL, kind TEXT NOT NULL,
              title TEXT NOT NULL, body TEXT, source_id TEXT, pattern_id TEXT,
              triggered_at REAL NOT NULL, delivered_to_json TEXT NOT NULL DEFAULT '[]',
              acknowledged INTEGER NOT NULL DEFAULT 0, acknowledged_at REAL
            );
            INSERT INTO alerts(id,severity,kind,title,triggered_at)
              VALUES ('old-alert','warn','pattern_match','old',1000);
        """)
    with Storage(db) as storage:
        row = storage._conn.execute("SELECT count FROM alerts WHERE id='old-alert'").fetchone()
        assert row["count"] == 1
        assert storage._conn.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0] == 2


# ----- Source -----

def _make_source(ip: str = "203.0.113.7", reputation: str = "neutral") -> Source:
    now = time.time()
    return {
        "id": str(uuid.uuid4()),
        "ip_address": ip,
        "asn": 64512,
        "asn_name": "TEST-AS",
        "geo_country": "US",
        "geo_region": "MN",
        "reputation": reputation,
        "first_seen": now,
        "last_seen": now,
        "probe_count": 0,
        "legit_count": 0,
        "notes": [],
    }


def test_source_upsert_then_lookup_roundtrip(storage):
    source = _make_source(ip="198.51.100.42")
    storage.sources_upsert(source)

    found = storage.sources_lookup("198.51.100.42")
    assert found is not None
    assert found["id"] == source["id"]
    assert found["asn"] == 64512
    assert found["reputation"] == "neutral"
    assert found["notes"] == []


def test_source_lookup_missing_returns_none(storage):
    assert storage.sources_lookup("192.0.2.1") is None


def test_source_upsert_is_idempotent(storage):
    source = _make_source(ip="198.51.100.99")
    storage.sources_upsert(source)
    source["probe_count"] = 7
    source["reputation"] = "suspicious"
    source["notes"] = ["flooded /wp-admin"]
    storage.sources_upsert(source)

    found = storage.sources_lookup("198.51.100.99")
    assert found["probe_count"] == 7
    assert found["reputation"] == "suspicious"
    assert found["notes"] == ["flooded /wp-admin"]


# ----- Pattern -----

def _make_pattern(
    *, signature: str = r"^/wp-admin", expires_at: float | None = None
) -> Pattern:
    return {
        "id": str(uuid.uuid4()),
        "kind": "path",
        "signature": signature,
        "description": "WordPress admin probe",
        "severity": "warn",
        "origin": "vendor",
        "origin_node_id": None,
        "created_at": time.time(),
        "last_matched": None,
        "match_count": 0,
        "mirror_response_id": None,
        "confidence": 0.8,
        "parent_pattern_id": None,
        "mutation_generation": 0,
        "expires_at": expires_at,
    }


def test_pattern_upsert_then_active(storage):
    p1 = _make_pattern(signature=r"^/wp-admin")
    p2 = _make_pattern(signature=r"^/.env")
    storage.patterns_upsert(p1)
    storage.patterns_upsert(p2)

    active = storage.patterns_active()
    sigs = {p["signature"] for p in active}
    assert sigs == {r"^/wp-admin", r"^/.env"}


def test_pattern_active_filters_expired(storage):
    fresh = _make_pattern(signature=r"^/api/login")
    expired = _make_pattern(
        signature=r"^/old-thing", expires_at=time.time() - 100
    )
    storage.patterns_upsert(fresh)
    storage.patterns_upsert(expired)

    active = storage.patterns_active()
    sigs = {p["signature"] for p in active}
    assert r"^/api/login" in sigs
    assert r"^/old-thing" not in sigs


def test_pattern_expires_at_round_trips(storage):
    """Round-trip: storage writes expires_at; adapter must read it back."""
    expiry = time.time() + 86400
    p = _make_pattern(signature=r"^/with-expiry", expires_at=expiry)
    storage.patterns_upsert(p)

    active = storage.patterns_active()
    matches = [x for x in active if x["signature"] == r"^/with-expiry"]
    assert len(matches) == 1
    assert matches[0]["expires_at"] == pytest.approx(expiry)


def test_pattern_purge_expired(storage):
    fresh = _make_pattern(signature=r"^/keep")
    stale = _make_pattern(signature=r"^/drop", expires_at=time.time() - 10)
    storage.patterns_upsert(fresh)
    storage.patterns_upsert(stale)

    removed = storage.patterns_purge_expired(time.time())
    assert removed == 1

    active = storage.patterns_active()
    sigs = {p["signature"] for p in active}
    assert sigs == {r"^/keep"}


# ----- Probe -----

def _make_probe(*, source_id: str, ts: float | None = None) -> Probe:
    request: RequestMetadata = {
        "method": "GET",
        "path": "/wp-admin",
        "headers": {"User-Agent": "evil-scanner/1.0"},
        "query_string": None,
        "body_snippet": None,
        "body_size": 0,
        "tls_fingerprint": None,
        "user_agent": "evil-scanner/1.0",
    }
    return {
        "id": str(uuid.uuid4()),
        "timestamp": ts if ts is not None else time.time(),
        "source_id": source_id,
        "pattern_id": None,
        "classification": "probe",
        "request": request,
        "response_id": None,
        "mirror_fired": True,
        "upstream_passed": False,
    }


def test_probe_log_then_recent_window_counts(storage):
    src_id = str(uuid.uuid4())
    now = time.time()
    storage.probes_log(_make_probe(source_id=src_id, ts=now))
    storage.probes_log(_make_probe(source_id=src_id, ts=now - 30))
    storage.probes_log(_make_probe(source_id=src_id, ts=now - 600))

    in_60s = storage.probes_recent_for_source(src_id, window_secs=60, now=now)
    in_300s = storage.probes_recent_for_source(src_id, window_secs=300, now=now)
    in_1h = storage.probes_recent_for_source(src_id, window_secs=3600, now=now)

    assert in_60s == 2
    assert in_300s == 2
    assert in_1h == 3


def test_probe_recent_isolates_by_source(storage):
    src_a = str(uuid.uuid4())
    src_b = str(uuid.uuid4())
    now = time.time()
    storage.probes_log(_make_probe(source_id=src_a, ts=now))
    storage.probes_log(_make_probe(source_id=src_b, ts=now))

    assert storage.probes_recent_for_source(src_a, 60, now) == 1
    assert storage.probes_recent_for_source(src_b, 60, now) == 1


def test_probe_log_updates_only_matched_pattern(storage):
    matched = _make_pattern()
    other = _make_pattern(signature=r"^/other")
    storage.patterns_upsert(matched)
    storage.patterns_upsert(other)
    first = _make_probe(source_id=str(uuid.uuid4()), ts=1001.0)
    first["pattern_id"] = matched["id"]
    second = _make_probe(source_id=str(uuid.uuid4()), ts=1000.0)
    second["pattern_id"] = matched["id"]

    storage.probes_log(first)
    storage.probes_log(second)

    patterns = {p["id"]: p for p in storage.patterns_active()}
    assert patterns[matched["id"]]["match_count"] == 2
    assert patterns[matched["id"]]["last_matched"] == 1001.0
    assert patterns[other["id"]]["match_count"] == 0
    assert patterns[other["id"]]["last_matched"] is None


def test_probe_log_without_pattern_does_not_increment_counts(storage):
    pattern = _make_pattern()
    storage.patterns_upsert(pattern)

    storage.probes_log(_make_probe(source_id=str(uuid.uuid4())))

    active = storage.patterns_active()
    assert len(active) == 1
    assert active[0]["match_count"] == 0
    assert active[0]["last_matched"] is None


def _logged_request(storage, probe_id: str) -> dict:
    row = storage._conn.execute(
        "SELECT request_json FROM probes WHERE id = ?", (probe_id,)
    ).fetchone()
    assert row is not None
    return json.loads(row["request_json"])


def test_probes_log_redacts_sensitive_headers(storage):
    probe = _make_probe(source_id=str(uuid.uuid4()))
    probe["request"]["headers"] = {
        "Authorization": "Basic dXNlcjpwYXNz",
        "Cookie": "session=abc123",
        "Set-Cookie": "session=abc123; HttpOnly",
        "Proxy-Authorization": "Basic eHh4",
        "User-Agent": "evil-scanner/1.0",
        "X-Api-Key": "super-secret-key",
    }
    storage.probes_log(probe)
    stored = _logged_request(storage, probe["id"])
    assert stored["headers"]["Authorization"] == "[REDACTED]"
    assert stored["headers"]["Cookie"] == "[REDACTED]"
    assert stored["headers"]["Set-Cookie"] == "[REDACTED]"
    assert stored["headers"]["Proxy-Authorization"] == "[REDACTED]"
    assert stored["headers"]["X-Api-Key"] == "[REDACTED]"
    assert stored["headers"]["User-Agent"] == "evil-scanner/1.0"
    assert "dXNlcjpwYXNz" not in json.dumps(stored)
    assert "abc123" not in json.dumps(stored)
    assert probe["request"]["headers"]["Authorization"] == "Basic dXNlcjpwYXNz"


def test_probes_log_redacts_password_like_body_keys(storage):
    probe = _make_probe(source_id=str(uuid.uuid4()))
    probe["request"]["body_snippet"] = "username=alice&password=s3cret&token=abc"
    probe["request"]["body_size"] = len(probe["request"]["body_snippet"])
    storage.probes_log(probe)
    stored = _logged_request(storage, probe["id"])
    assert "s3cret" not in stored["body_snippet"]
    assert "alice" in stored["body_snippet"]
    assert "[REDACTED]" in stored["body_snippet"]


def test_probes_log_redacts_json_password_body(storage):
    probe = _make_probe(source_id=str(uuid.uuid4()))
    probe["request"]["body_snippet"] = '{"username":"alice","password":"s3cret"}'
    storage.probes_log(probe)
    stored = _logged_request(storage, probe["id"])
    assert "s3cret" not in stored["body_snippet"]
    assert "alice" in stored["body_snippet"]


def test_probes_log_redacts_password_like_query_keys(storage):
    probe = _make_probe(source_id=str(uuid.uuid4()))
    probe["request"]["query_string"] = "q=hello&access_token=leakme"
    storage.probes_log(probe)
    stored = _logged_request(storage, probe["id"])
    assert "leakme" not in (stored.get("query_string") or "")
    assert "hello" in (stored.get("query_string") or "")


def test_probes_purge_by_ttl(storage):
    src = str(uuid.uuid4())
    now = time.time()
    storage.probes_log(_make_probe(source_id=src, ts=now - 3600))
    storage.probes_log(_make_probe(source_id=src, ts=now - 10))
    removed = storage.probes_purge(now=now, retention_secs=60, max_rows=10_000)
    assert removed == 1
    assert storage.probes_recent_for_source(src, window_secs=10_000, now=now) == 1


def test_probes_purge_by_max_rows_keeps_newest(storage):
    src = str(uuid.uuid4())
    now = time.time()
    for i in range(5):
        storage.probes_log(_make_probe(source_id=src, ts=now - 5 + i))
    removed = storage.probes_purge(now=now, retention_secs=86_400, max_rows=2)
    assert removed == 3
    assert storage.probes_recent_for_source(src, window_secs=10_000, now=now) == 2
    rows = storage._conn.execute(
        "SELECT timestamp FROM probes ORDER BY timestamp ASC"
    ).fetchall()
    assert [r["timestamp"] for r in rows] == [now - 2, now - 1]


def test_probes_log_enforces_retention(tmp_path):
    db = tmp_path / "retain.db"
    s = Storage(db, probe_retention_secs=60, probe_max_rows=3)
    try:
        src = str(uuid.uuid4())
        now = time.time()
        for i in range(5):
            s.probes_log(_make_probe(source_id=src, ts=now - 4 + i))
        count = s._conn.execute("SELECT COUNT(*) AS c FROM probes").fetchone()["c"]
        assert count <= 3
        stale = s.probes_log(_make_probe(source_id=src, ts=now - 3600))
        # the just-logged stale row must be purged by TTL on write
        remaining = s._conn.execute(
            "SELECT COUNT(*) AS c FROM probes WHERE timestamp < ?",
            (now - 60,),
        ).fetchone()["c"]
        assert remaining == 0
    finally:
        s.close()


# ----- MirrorResponse -----

def test_mirror_response_upsert_then_lookup_roundtrip(storage):
    mr: MirrorResponse = {
        "id": str(uuid.uuid4()),
        "matches_pattern_id": str(uuid.uuid4()),
        "intensity": "moderate",
        "http_status": 200,
        "headers": {"Content-Type": "text/html"},
        "body_template": "<html>Hello {{user_id}}</html>",
        "body_template_vars": {"user_id": "fake_id"},
        "description": "WordPress fake admin login",
        "created_at": time.time(),
    }
    storage.mirror_response_upsert(mr)
    found = storage.mirror_response_lookup(mr["id"])
    assert found is not None
    assert found["body_template"] == "<html>Hello {{user_id}}</html>"
    assert found["body_template_vars"] == {"user_id": "fake_id"}
    assert found["headers"] == {"Content-Type": "text/html"}


def test_mirror_response_lookup_missing_returns_none(storage):
    assert storage.mirror_response_lookup(str(uuid.uuid4())) is None


# ----- MeshIntel -----

def test_mesh_intel_archive_persists(storage):
    intel: MeshIntel = {
        "id": str(uuid.uuid4()),
        "kind": "new_pattern",
        "origin_node_id": str(uuid.uuid4()),
        "payload": {"pattern_signature": r"^/.env"},
        "signature": "ed25519:placeholder",
        "published_at": time.time(),
        "expires_at": time.time() + 86400,
        "propagation_count": 0,
        "received_at": None,
        "verified": False,
    }
    storage.mesh_intel_archive(intel)
    row = storage._conn.execute(
        "SELECT id, kind, payload_json, verified FROM mesh_intel WHERE id = ?",
        (intel["id"],),
    ).fetchone()
    assert row is not None
    assert row["kind"] == "new_pattern"
    assert "pattern_signature" in row["payload_json"]
    assert row["verified"] == 0


# ----- OperatorAlert -----

def _make_alert(*, kind: str = "new_pattern", source_id: str | None = None) -> OperatorAlert:
    return {
        "id": str(uuid.uuid4()),
        "severity": "warn",
        "kind": kind,
        "title": "Probe pattern fired",
        "body": "Source X hit /wp-admin",
        "source_id": source_id,
        "pattern_id": None,
        "triggered_at": time.time(),
        "delivered_to": [],
        "acknowledged": False,
        "acknowledged_at": None,
    }


def test_alert_upsert_then_recent(storage):
    a1 = _make_alert(kind="new_pattern")
    a2 = _make_alert(kind="flood_active")
    storage.alerts_upsert(a1)
    storage.alerts_upsert(a2)

    recent = storage.alerts_recent(now=time.time(), window_secs=60)
    kinds = {a["kind"] for a in recent}
    assert kinds == {"new_pattern", "flood_active"}


def test_alert_recent_excludes_outside_window(storage):
    old: OperatorAlert = {
        "id": str(uuid.uuid4()),
        "severity": "info",
        "kind": "old_alert",
        "title": "old",
        "body": "",
        "source_id": None,
        "pattern_id": None,
        "triggered_at": time.time() - 7200,
        "delivered_to": [],
        "acknowledged": True,
        "acknowledged_at": time.time() - 7000,
    }
    storage.alerts_upsert(old)
    storage.alerts_upsert(_make_alert(kind="fresh_alert"))

    recent = storage.alerts_recent(now=time.time(), window_secs=60)
    kinds = {a["kind"] for a in recent}
    assert "fresh_alert" in kinds
    assert "old_alert" not in kinds


def test_alert_upsert_idempotent(storage):
    a = _make_alert(kind="dedupe_test")
    storage.alerts_upsert(a)
    a["acknowledged"] = True
    a["acknowledged_at"] = time.time()
    storage.alerts_upsert(a)

    recent = storage.alerts_recent(now=time.time(), window_secs=60)
    matches = [r for r in recent if r["id"] == a["id"]]
    assert len(matches) == 1
    assert matches[0]["acknowledged"] is True


def test_alert_record_deduplicates_and_preserves_receipts(storage):
    first = _make_alert(kind="pattern_match", source_id="source-1")
    first["pattern_id"] = "pattern-a"
    first["triggered_at"] = 1000.0
    stored, is_new = storage.alerts_record(first, 300)
    assert is_new and stored["id"] == first["id"]
    storage.alerts_mark_delivered(first["id"], ["stdout", "slack"])
    second = dict(first, id=str(uuid.uuid4()), triggered_at=1100.0)
    merged, is_new = storage.alerts_record(second, 300)
    assert not is_new and merged["count"] == 2
    assert merged["triggered_at"] == 1000.0
    assert merged["delivered_to"] == ["stdout", "slack"]
    different = dict(second, id=str(uuid.uuid4()), pattern_id="pattern-b")
    assert storage.alerts_record(different, 300)[1]
    later = dict(first, id=str(uuid.uuid4()), triggered_at=1301.0)
    assert storage.alerts_record(later, 300)[1]
    assert len(storage.alerts_recent(1301.0, 1000)) == 3


def test_pending_alerts_only_include_missing_channels(storage):
    alert = _make_alert(kind="pattern_match", source_id="source-2")
    storage.alerts_upsert(alert)
    assert len(storage.alerts_pending(["stdout", "slack"], time.time())) == 1
    storage.alerts_mark_delivered(alert["id"], ["stdout"])
    assert len(storage.alerts_pending(["stdout", "slack"], time.time())) == 1
    storage.alerts_mark_delivered(alert["id"], ["slack"])
    assert storage.alerts_pending(["stdout", "slack"], time.time()) == []
