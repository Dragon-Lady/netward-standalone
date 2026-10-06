from __future__ import annotations

import json
import shutil
import socketserver
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from netward.operator_layer import (
    ValidationError,
    dedupe_alert,
    deliver_alert,
    load_config,
    validate_storage_permissions,
)
from netward.schema import OperatorAlert, OperatorConfig


_WORKSPACE_TMP_ROOT = Path(__file__).resolve().parent.parent / ".codex-test-operator"


def _config(**overrides) -> OperatorConfig:
    cfg: OperatorConfig = {
        "node_id": "node-1",
        "upstream_target": "http://127.0.0.1:8080",
        "listen_address": "127.0.0.1:9000",
        "mirror_intensity_default": "moderate",
        "mesh_enabled": False,
        "mesh_endpoint": None,
        "trust_manifest_url": None,
        "alert_channels": [],
        "alert_email": None,
        "alert_slack_webhook": None,
        "alert_ntfy_topic": None,
    }
    cfg.update(overrides)
    return cfg


def _alert(**overrides) -> OperatorAlert:
    alert: OperatorAlert = {
        "id": "alert-1",
        "severity": "warn",
        "kind": "flood_active",
        "title": "Flood active",
        "body": "source is sending probes",
        "source_id": "source-1",
        "pattern_id": None,
        "triggered_at": time.time(),
        "delivered_to": [],
        "acknowledged": False,
        "acknowledged_at": None,
    }
    alert.update(overrides)
    return alert


def _workspace_tempdir() -> Path:
    path = _WORKSPACE_TMP_ROOT / str(uuid.uuid4())
    path.mkdir(parents=True, exist_ok=False)
    return path


def test_load_config_reads_valid_json(tmp_path):
    path = tmp_path / "netward.json"
    path.write_text(json.dumps(_config()), encoding="utf-8")

    loaded = load_config(str(path))

    assert loaded["node_id"] == "node-1"
    assert loaded["upstream_target"] == "http://127.0.0.1:8080"


@pytest.mark.parametrize("raw_channels", [None, []])
def test_load_config_normalizes_empty_alert_channels(tmp_path, raw_channels):
    cfg = _config(alert_channels=raw_channels)
    path = tmp_path / "netward.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")

    loaded = load_config(str(path))

    assert loaded["alert_channels"] == []


def test_load_config_normalizes_missing_alert_channels(tmp_path):
    cfg = _config()
    cfg.pop("alert_channels")
    path = tmp_path / "netward.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")

    loaded = load_config(str(path))

    assert loaded["alert_channels"] == []


def test_load_config_missing_required_field_is_clear(tmp_path):
    bad = _config()
    bad.pop("upstream_target")
    path = tmp_path / "netward.json"
    path.write_text(json.dumps(bad), encoding="utf-8")

    with pytest.raises(ValidationError, match="upstream_target"):
        load_config(str(path))


def test_load_config_rejects_unknown_alert_channel(tmp_path):
    path = tmp_path / "netward.json"
    path.write_text(json.dumps(_config(alert_channels=["pagerduty"])), encoding="utf-8")

    with pytest.raises(ValidationError, match="unknown alert channels"):
        load_config(str(path))


def test_load_config_accepts_upstream_and_probe_bounds(tmp_path):
    cfg = _config(
        upstream_timeout_total=8,
        upstream_timeout_connect=2,
        upstream_timeout_sock_read=4,
        upstream_max_concurrency=16,
        upstream_max_body_bytes=1024,
        probe_retention_secs=3600,
        probe_max_rows=100,
    )
    path = tmp_path / "netward.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")

    loaded = load_config(str(path))

    assert loaded["upstream_timeout_total"] == 8
    assert loaded["probe_max_rows"] == 100


def test_load_config_rejects_non_positive_upstream_timeout(tmp_path):
    path = tmp_path / "netward.json"
    path.write_text(json.dumps(_config(upstream_timeout_total=0)), encoding="utf-8")

    with pytest.raises(ValidationError, match="upstream_timeout_total"):
        load_config(str(path))


def test_validate_storage_permissions_rejects_world_writable_db(monkeypatch):
    tmpdir = _workspace_tempdir()
    try:
        db_path = tmpdir / "netward.db"
        db_path.write_text("", encoding="utf-8")
        monkeypatch.setattr("netward.operator_layer._is_world_writable", lambda path: True)

        with pytest.raises(ValidationError, match="world-writable"):
            validate_storage_permissions(
                _config(storage_path=str(db_path)),
                platform_name="linux",
            )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_validate_storage_permissions_allows_override_for_world_writable_db(
    capsys,
    monkeypatch,
):
    tmpdir = _workspace_tempdir()
    try:
        db_path = tmpdir / "netward.db"
        db_path.write_text("", encoding="utf-8")
        monkeypatch.setattr("netward.operator_layer._is_world_writable", lambda path: True)

        validate_storage_permissions(
            _config(storage_path=str(db_path)),
            allow_permissive_db=True,
            platform_name="linux",
        )

        captured = capsys.readouterr()
        assert "ERROR:" in captured.err
        assert "--allow-permissive-db" in captured.err
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_validate_storage_permissions_missing_db_checks_parent_dir(monkeypatch):
    tmpdir = _workspace_tempdir()
    try:
        db_path = tmpdir / "state" / "netward.db"
        db_path.parent.mkdir()
        seen: list[str] = []

        def fake_is_world_writable(path):
            seen.append(str(path))
            return False

        monkeypatch.setattr("netward.operator_layer._is_world_writable", fake_is_world_writable)

        validate_storage_permissions(
            _config(storage_path=str(db_path)),
            platform_name="linux",
        )

        assert seen == [str(db_path.parent)]
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_validate_storage_permissions_clean_posix_path_passes(capsys, monkeypatch):
    tmpdir = _workspace_tempdir()
    try:
        db_path = tmpdir / "netward.db"
        db_path.write_text("", encoding="utf-8")
        monkeypatch.setattr("netward.operator_layer._is_world_writable", lambda path: False)

        validate_storage_permissions(
            _config(storage_path=str(db_path)),
            platform_name="darwin",
        )

        captured = capsys.readouterr()
        assert captured.err == ""
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_validate_storage_permissions_windows_logs_skip(capsys, monkeypatch):
    tmpdir = _workspace_tempdir()
    try:
        db_path = tmpdir / "netward.db"
        db_path.write_text("", encoding="utf-8")

        def should_not_run(path):
            raise AssertionError("world-writable check should be skipped on Windows")

        monkeypatch.setattr("netward.operator_layer._is_world_writable", should_not_run)

        validate_storage_permissions(
            _config(storage_path=str(db_path)),
            platform_name="win32",
        )

        captured = capsys.readouterr()
        assert "INFO:" in captured.err
        assert "avoid shared-write locations" in captured.err
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_deliver_alert_logs_to_stdout(capsys):
    delivered = deliver_alert(_alert(), _config())

    captured = capsys.readouterr()
    assert delivered == ["stdout"]
    assert "[NETWARD] WARN flood_active" in captured.out


@pytest.mark.parametrize("raw_channels", [None, []])
def test_deliver_alert_treats_empty_channels_as_stdout(raw_channels, capsys):
    delivered = deliver_alert(_alert(), _config(alert_channels=raw_channels))

    captured = capsys.readouterr()
    assert delivered == ["stdout"]
    assert "Flood active" in captured.out


def test_configured_channels_deliver_independently(monkeypatch, capsys):
    sent = []
    monkeypatch.setattr("netward.operator_layer._post",
                        lambda url, body, headers, timeout: sent.append((url, body, headers)))
    class FakeSMTP:
        def __init__(self, host, port, timeout):
            assert host == "127.0.0.1"
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
        def send_message(self, message):
            sent.append(("email", message["To"], message.get_content()))
    monkeypatch.setattr("netward.operator_layer.smtplib.SMTP", FakeSMTP)
    cfg = _config(alert_channels=["stdout", "email", "slack", "ntfy"],
                  alert_email="operator@example.test", alert_smtp_host="127.0.0.1",
                  alert_smtp_port=2525, alert_smtp_from="netward@example.test",
                  alert_smtp_security="none",
                  alert_slack_webhook="http://127.0.0.1:8001/slack",
                  alert_ntfy_topic="http://127.0.0.1:8002/topic")
    delivered = deliver_alert(_alert(), cfg)
    assert delivered == ["stdout", "email", "slack", "ntfy"]
    assert len(sent) == 3
    assert "[NETWARD]" in capsys.readouterr().out
    assert json.loads(sent[1][1])["text"].startswith("[NETWARD]")
    assert sent[2][2]["Priority"] == "3"


def test_one_channel_failure_does_not_suppress_others(monkeypatch, capsys):
    def post(url, body, headers, timeout):
        if "slack" in url:
            raise OSError("secret URL must not be logged")
    monkeypatch.setattr("netward.operator_layer._post", post)
    cfg = _config(alert_channels=["slack", "ntfy"],
                  alert_slack_webhook="http://127.0.0.1/slack",
                  alert_ntfy_topic="http://127.0.0.1/topic")
    assert deliver_alert(_alert(), cfg) == ["ntfy"]
    assert "secret URL" not in capsys.readouterr().err


def test_slack_and_ntfy_post_to_local_receivers():
    received = []
    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append((self.path, self.headers, self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        cfg = _config(alert_channels=["slack", "ntfy"],
                      alert_slack_webhook=base + "/slack",
                      alert_ntfy_topic=base + "/topic")
        assert deliver_alert(_alert(), cfg) == ["slack", "ntfy"]
        assert [item[0] for item in received] == ["/slack", "/topic"]
        assert json.loads(received[0][2])["text"].startswith("[NETWARD]")
        assert received[1][1]["Priority"] == "3"
        assert b"source is sending probes" in received[1][2]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_email_sends_to_local_smtp_receiver():
    messages = []
    class SMTPHandler(socketserver.StreamRequestHandler):
        def handle(self):
            self.wfile.write(b"220 local test SMTP\r\n")
            data_lines = []
            in_data = False
            while line := self.rfile.readline():
                command = line.upper()
                if in_data:
                    if line == b".\r\n":
                        messages.append(b"".join(data_lines))
                        self.wfile.write(b"250 queued\r\n")
                        in_data = False
                    else:
                        data_lines.append(line)
                elif command.startswith(b"EHLO"):
                    self.wfile.write(b"250-localhost\r\n250 8BITMIME\r\n")
                elif command.startswith((b"MAIL FROM", b"RCPT TO")):
                    self.wfile.write(b"250 ok\r\n")
                elif command.startswith(b"DATA"):
                    self.wfile.write(b"354 send data\r\n")
                    in_data = True
                elif command.startswith(b"QUIT"):
                    self.wfile.write(b"221 bye\r\n")
                    break
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SMTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        cfg = _config(alert_channels=["email"],
                      alert_email="operator@example.test",
                      alert_smtp_host="127.0.0.1",
                      alert_smtp_port=server.server_address[1],
                      alert_smtp_from="netward@example.test",
                      alert_smtp_security="none")
        assert deliver_alert(_alert(), cfg) == ["email"]
        assert len(messages) == 1
        assert b"[NETWARD] WARN flood_active" in messages[0]
        assert b"operator@example.test" in messages[0]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("overrides,expected", [
    ({"alert_channels": ["email"]}, "alert_email"),
    ({"alert_channels": ["slack"]}, "alert_slack_webhook"),
    ({"alert_channels": ["ntfy"]}, "alert_ntfy_topic"),
    ({"alert_channels": ["stdout", "stdout"]}, "duplicates"),
])
def test_requested_channel_without_destination_rejected(tmp_path, overrides, expected):
    path = tmp_path / "netward.json"
    path.write_text(json.dumps(_config(**overrides)), encoding="utf-8")
    with pytest.raises(ValidationError, match=expected):
        load_config(str(path))


def test_dedupe_alert_within_window_rolls_up_count():
    base = _alert(id="alert-1", triggered_at=1000.0)
    new = _alert(id="alert-2", triggered_at=1100.0, body="new detail")

    merged = dedupe_alert(new, [base])

    assert merged is not None
    assert merged["id"] == "alert-1"
    assert merged["count"] == 2
    assert merged["body"] == "new detail"


def test_dedupe_alert_outside_window_passes_new_alert():
    base = _alert(id="alert-1", triggered_at=1000.0)
    new = _alert(id="alert-2", triggered_at=2000.0)

    passed = dedupe_alert(new, [base])

    assert passed == new
