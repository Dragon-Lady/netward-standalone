"""Probe report: read-only aggregate summary of the local probe log."""
from __future__ import annotations

import json
import os
import sqlite3
import stat
import time

from netward import bootstrap
from netward.report import (
    DIGEST_CHAR_LIMIT,
    SLACK_TEXT_LIMIT,
    build_report,
    render,
    run_report,
    send_digest,
)
from netward.storage import Storage

SECRET_IP = "203.0.113.44"
LEGIT_PATH = "/account/tanya-private-note"
EVIL_PATH = "/wp-admin/<script>alert(1)</script>"


def _probe(storage, *, pid, ts, source, classification, path, pattern_id=None,
           method="GET", ua="", upstream=False):
    storage.probes_log({
        "id": pid,
        "timestamp": ts,
        "source_id": source,
        "pattern_id": pattern_id,
        "classification": classification,
        "request": {"method": method, "path": path, "user_agent": ua, "headers": {}},
        "mirror_fired": classification == "probe",
        "upstream_passed": upstream,
    })


def _seed(tmp_path, *, now):
    db = tmp_path / "netward.db"
    storage = Storage(db)
    bootstrap.install_vendor_patterns(storage, force=True)
    storage.sources_upsert({
        "id": "src-a",
        "ip_address": SECRET_IP,
        "reputation": "suspicious",
        "first_seen": now - 100,
        "last_seen": now,
        "probe_count": 3,
        "legit_count": 1,
        "notes": [],
    })
    storage.sources_upsert({
        "id": "src-b",
        "ip_address": "198.51.100.9",
        "reputation": "neutral",
        "first_seen": now - 50,
        "last_seen": now,
        "probe_count": 1,
        "legit_count": 0,
        "notes": [],
    })
    _probe(storage, pid="p1", ts=now - 86400 * 3, source="src-a",
           classification="probe", path="/.env", pattern_id="env_file_probe", ua="curl/8")
    _probe(storage, pid="p2", ts=now - 20, source="src-a",
           classification="probe", path=EVIL_PATH, pattern_id="wordpress_admin_probe",
           ua="wp-scan")
    _probe(storage, pid="p3", ts=now - 10, source="src-b",
           classification="probe", path="/wp-login.php", pattern_id="wordpress_admin_probe")
    _probe(storage, pid="p4", ts=now - 5, source="src-a",
           classification="flood", path="/flood-1", ua="mass-flood")
    _probe(storage, pid="p5", ts=now - 4, source="src-a",
           classification="probe", path="/healthz", pattern_id="scanner_ua_probe",
           ua="sqlmap/1.7")
    _probe(storage, pid="p6", ts=now - 3, source="src-a",
           classification="legit", path="/cgi-bin/oops.php", upstream=True)
    _probe(storage, pid="p7", ts=now - 2, source="src-a",
           classification="unknown", path="/backup/.env.old", method="POST", upstream=True)
    _probe(storage, pid="p8", ts=now - 1, source="src-b",
           classification="legit", path=LEGIT_PATH, upstream=True)
    storage.alerts_upsert({
        "id": "a1",
        "severity": "warn",
        "kind": "pattern_match",
        "title": "match",
        "body": f"source {SECRET_IP} hit wordpress",
        "source_id": "src-a",
        "pattern_id": "wordpress_admin_probe",
        "triggered_at": now - 10,
        "delivered_to": ["stdout"],
        "count": 2,
        "acknowledged": False,
    })
    storage.close()
    _checkpoint(db)
    return db


def _checkpoint(db):
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()


def _silence_side_files(db):
    for suffix in ("-wal", "-shm"):
        side = db.parent / (db.name + suffix)
        if side.exists():
            side.unlink()


def test_empty_db_is_not_probed(tmp_path):
    db = tmp_path / "empty.db"
    Storage(db).close()
    report = build_report(str(db))
    assert report["verdict"]["label"] == "not probed"
    assert report["verdict"]["probed"] is False
    assert "not probed" in render(report, "text")


def test_family_counts_and_privacy(tmp_path):
    now = time.time()
    db = _seed(tmp_path, now=now)
    report = build_report(str(db), now=now)
    by_id = {section["id"]: section for section in report["families"]}
    assert by_id["wordpress"]["count"] == 2
    assert by_id["secrets"]["count"] == 1
    assert by_id["floods"]["count"] == 1
    assert by_id["ua_scanners"]["count"] == 1
    assert by_id["admin"]["count"] == 0
    assert by_id["webshells"]["count"] == 0
    assert report["verdict"]["label"] == "probed"
    assert report["verdict"]["clean_events"] == 2
    blob = json.dumps(report)
    assert SECRET_IP not in blob
    assert "198.51.100.9" not in blob
    assert LEGIT_PATH not in blob
    assert "src-a" not in blob
    assert report["top_sources"][0] == {"rank": 1, "events": 4}
    assert "ip" not in report["top_sources"][0]


def test_weak_spots_never_fired_and_disabled(tmp_path):
    now = time.time()
    db = _seed(tmp_path, now=now)
    report = build_report(str(db), now=now)
    weak = report["weak_spots"]
    paths = {item["path"]: item for item in weak["suspicious_unmatched"]}
    assert paths["/cgi-bin/oops.php"]["count"] == 1
    assert paths["/backup/.env.old"]["suggestion"].startswith("path ^")
    assert paths["/backup/.env.old"]["installed"] is False
    assert LEGIT_PATH not in paths
    never = {item["id"] for item in weak["never_fired"]}
    disabled = {item["id"] for item in weak["disabled"]}
    assert "git_config_probe" in never
    assert "basic_auth_probe" in disabled
    assert "basic_auth_probe" not in never
    assert "wordpress_admin_probe" not in never
    text = render(report, "text")
    assert "not installed" in text


def test_since_drops_older_rows(tmp_path):
    now = time.time()
    db = _seed(tmp_path, now=now)
    report = build_report(str(db), since=now - 86400, now=now)
    by_id = {section["id"]: section["count"] for section in report["families"]}
    assert by_id["secrets"] == 0
    assert by_id["wordpress"] == 2
    rendered = run_report(str(db), since="1d", now=now)
    assert "secrets .env/.git: 0" in rendered


def test_html_escapes_attacker_text(tmp_path):
    now = time.time()
    db = _seed(tmp_path, now=now)
    page = render(build_report(str(db), now=now), "html")
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_report_does_not_change_the_database(tmp_path):
    now = time.time()
    db = _seed(tmp_path, now=now)
    _silence_side_files(db)
    before = db.read_bytes()
    out = tmp_path / "report.md"
    run_report(str(db), fmt="md", output=str(out), now=now)
    assert db.read_bytes() == before
    assert not (tmp_path / "netward.db-wal").exists()
    mode = stat.S_IMODE(out.stat().st_mode)
    assert mode == 0o600


def test_send_delivers_once_under_slack_limit(tmp_path, monkeypatch):
    now = time.time()
    db = _seed(tmp_path, now=now)
    report = build_report(str(db), now=now)
    calls = []

    def _capture(alert, config, channels=None):
        calls.append((alert, channels))
        return ["stdout"]

    monkeypatch.setattr("netward.operator_layer.deliver_alert", _capture)
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "node_id": "netward-test",
        "upstream_target": "http://127.0.0.1:9",
        "listen_address": "127.0.0.1:9",
        "alert_channels": ["stdout"],
    }))
    delivered = send_digest(report, str(config))
    assert delivered == ["stdout"]
    assert len(calls) == 1
    body = calls[0][0]["body"]
    formatted = f"[NETWARD] INFO probe_report: Probe report\n{body}"
    assert len(formatted) < SLACK_TEXT_LIMIT
    assert SECRET_IP not in body
    assert LEGIT_PATH not in body

    monkeypatch.setattr("netward.report.DIGEST_CHAR_LIMIT", 120)
    calls.clear()
    send_digest(report, str(config))
    assert len(calls) == 1
    short = calls[0][0]["body"]
    assert "truncated" in short
    assert len(short) < 120 + 40
    assert len(short) < DIGEST_CHAR_LIMIT or "truncated" in short
