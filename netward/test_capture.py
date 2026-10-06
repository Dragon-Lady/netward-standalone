"""
Net Ward -- capture layer tests.
Tests the routing pipeline end-to-end using aiohttp.test_utils.TestClient.
Mirror and storage layers are stubbed.
"""
from __future__ import annotations

import asyncio
import threading
import time
from collections import deque

import pytest
import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import netward.capture as cap_mod
from netward.capture import _make_handler
from netward.schema import OperatorConfig
from netward.storage import Storage

_ALERT_DISPATCHER_KEY = web.AppKey("alert_dispatcher", cap_mod._AlertDispatcher)


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------

class _MockStorage:
    def __init__(self):
        self.sources: dict = {}
        self.patterns: list = []
        self.probes: list = []
        self.mirror_responses: dict = {}

    def sources_lookup(self, ip: str):
        return self.sources.get(ip)

    def sources_upsert(self, source):
        self.sources[source["ip_address"]] = source

    def patterns_active(self):
        return list(self.patterns)

    def probes_log(self, probe):
        self.probes.append(probe)

    def mirror_response_lookup(self, mr_id: str):
        return self.mirror_responses.get(mr_id)

    def alerts_recent(self, window_secs: int):
        return []

    def alerts_upsert(self, alert):
        pass


def _config(upstream: str = "http://127.0.0.1:59999") -> OperatorConfig:
    return {
        "node_id": "test-node",
        "upstream_target": upstream,
        "listen_address": "0.0.0.0:8080",
        "mirror_intensity_default": "minimal",
        "mesh_enabled": False,
        "alert_channels": [],
    }


def _wp_admin_pattern() -> dict:
    return {
        "id": "pat-wp-admin",
        "kind": "path",
        "signature": r"^/wp-admin\b",
        "description": "WordPress admin probe",
        "severity": "warn",
        "origin": "vendor",
        "created_at": time.time(),
        "match_count": 0,
        "confidence": 0.95,
        "mirror_response_id": None,
        "mutation_generation": 0,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_module_state():
    """Reset module-level rate windows between tests."""
    cap_mod._rate_windows.clear()
    yield
    cap_mod._rate_windows.clear()


@pytest.fixture
def mock_storage():
    return _MockStorage()


@pytest.fixture
def stub_mirror(monkeypatch):
    """Replace fire_mirror with a fixed detectable response."""
    def _fire(probe, mr):
        return {
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": '{"netward":"mirrored"}',
        }
    monkeypatch.setattr("netward.capture._mirror_mod.fire_mirror", _fire)


async def _make_client(config: OperatorConfig, storage) -> tuple[TestClient, aiohttp.ClientSession]:
    connector = aiohttp.TCPConnector()
    session = aiohttp.ClientSession(connector=connector)
    handler_func = _make_handler(config, storage, session)

    @web.middleware
    async def catch_all(request: web.Request, handler) -> web.Response:
        return await handler_func(request)

    app = web.Application(middlewares=[catch_all])
    app[_ALERT_DISPATCHER_KEY] = handler_func.alert_dispatcher
    client = TestClient(TestServer(app))
    await client.start_server()
    return client, session


@pytest.mark.asyncio
async def test_matched_requests_record_and_deliver_one_deduplicated_alert(tmp_path):
    storage = Storage(tmp_path / "alerts.db")
    storage.patterns_upsert(_wp_admin_pattern())
    client, session = await _make_client(_config(), storage)
    try:
        for _ in range(2):
            response = await client.get("/wp-admin/")
            await response.read()
        for _ in range(50):
            alerts = storage.alerts_recent(time.time(), 60)
            if alerts and alerts[0]["delivered_to"]:
                break
            await asyncio.sleep(0.02)
        assert len(alerts) == 1
        assert alerts[0]["kind"] == "pattern_match"
        assert alerts[0]["pattern_id"] == "pat-wp-admin"
        assert alerts[0]["count"] == 2
        assert alerts[0]["delivered_to"] == ["stdout"]
    finally:
        await client.app[_ALERT_DISPATCHER_KEY].close()
        await client.close()
        await session.close()
        storage.close()


@pytest.mark.asyncio
async def test_slow_alert_delivery_does_not_hold_proxy_response(tmp_path, monkeypatch):
    storage = Storage(tmp_path / "slow-alert.db")
    storage.patterns_upsert(_wp_admin_pattern())
    entered = threading.Event()
    release = threading.Event()
    def slow_delivery(alert, config, channels):
        entered.set()
        release.wait(timeout=5)
        return ["stdout"]
    monkeypatch.setattr(cap_mod._operator, "deliver_alert", slow_delivery)
    client, session = await _make_client(_config(), storage)
    try:
        response = await asyncio.wait_for(client.get("/wp-admin/"), timeout=1)
        await response.read()
        assert response.status in {200, 429, 503}
        assert await asyncio.to_thread(entered.wait, 1)
        assert storage.alerts_recent(time.time(), 60)[0]["delivered_to"] == []
    finally:
        release.set()
        await client.app[_ALERT_DISPATCHER_KEY].close()
        await client.close()
        await session.close()
        storage.close()


@pytest.mark.asyncio
async def test_flood_threshold_records_critical_alert(tmp_path):
    storage = Storage(tmp_path / "flood-alert.db")
    source = {
        "id": "flood-source", "ip_address": "127.0.0.1", "reputation": "neutral",
        "first_seen": time.time(), "last_seen": time.time(),
        "probe_count": 0, "legit_count": 0, "notes": [],
    }
    storage.sources_upsert(source)
    cap_mod._rate_windows[source["id"]] = deque([time.time()] * 999, maxlen=2000)
    client, session = await _make_client(_config(), storage)
    try:
        response = await client.get("/ordinary-path")
        await response.read()
        await client.app[_ALERT_DISPATCHER_KEY].close()
        alerts = storage.alerts_recent(time.time(), 60)
        assert len(alerts) == 1
        assert alerts[0]["kind"] == "flood_active"
        assert alerts[0]["severity"] == "critical"
        assert alerts[0]["pattern_id"] is None
        assert alerts[0]["delivered_to"] == ["stdout"]
    finally:
        await client.close()
        await session.close()
        storage.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_legit_request_forwarded_upstream(mock_storage):
    """
    No patterns, no flood -> classification=unknown -> forwards to upstream.
    If the upstream is unreachable, Net Ward falls back to the default mirror
    (one of five response-shape variants) rather than a raw 502.
    """
    client, session = await _make_client(_config(upstream="http://127.0.0.1:59997"), mock_storage)
    try:
        resp = await client.get("/api/v1/status")
        # Default mirror variants: 200 (json ok), 429 (rate limited), 503 (html),
        # 200 (empty json), 200 (plain). Any is valid; 502 is the failure mode.
        assert resp.status in {200, 429, 503}
        await asyncio.sleep(0.05)  # let fire-and-forget probe log flush
        assert len(mock_storage.probes) > 0
        logged = mock_storage.probes[-1]
        assert logged["classification"] == "unknown"
        assert logged["upstream_passed"] is False
        assert logged["mirror_fired"] is True
    finally:
        await client.close()
        await session.close()


@pytest.mark.asyncio
async def test_probe_match_fires_mirror(mock_storage, stub_mirror):
    """
    Request matching a path pattern returns mirror response, not upstream 502.
    """
    mock_storage.patterns = [_wp_admin_pattern()]
    client, session = await _make_client(_config(), mock_storage)
    try:
        resp = await client.get("/wp-admin/login.php")
        assert resp.status == 200
        body = await resp.text()
        assert "mirrored" in body
        await asyncio.sleep(0.05)
        assert len(mock_storage.probes) > 0
        logged = mock_storage.probes[-1]
        assert logged["classification"] == "probe"
        assert logged["mirror_fired"] is True
    finally:
        await client.close()
        await session.close()


@pytest.mark.asyncio
async def test_flood_with_probe_path_fires_mirror(mock_storage, stub_mirror):
    """
    Source in flood state (1000 hits in window) hitting a probe-shaped path
    still receives a mirror response (B1 semantics: pattern match drives mirror,
    flood state labels classification but does not change routing).
    """
    now = time.time()
    source_id = "flood-test-source"
    mock_storage.sources["127.0.0.1"] = {
        "id": source_id,
        "ip_address": "127.0.0.1",
        "reputation": "neutral",
        "first_seen": now,
        "last_seen": now,
        "probe_count": 0,
        "legit_count": 0,
        "notes": [],
    }
    mock_storage.patterns = [_wp_admin_pattern()]
    # 1000 timestamps within the last 0.5 s -> just at FLOOD_THRESHOLD (1000/10s)
    cap_mod._rate_windows[source_id] = deque([now - 0.1] * 1000, maxlen=2000)

    client, session = await _make_client(_config(), mock_storage)
    try:
        resp = await client.get("/wp-admin/")   # probe-shaped path → pattern match
        assert resp.status == 200               # stub_mirror always returns 200
        body = await resp.text()
        assert "mirrored" in body
        await asyncio.sleep(0.05)
        assert len(mock_storage.probes) > 0
        logged = mock_storage.probes[-1]
        assert logged["classification"] == "flood"
        assert logged["mirror_fired"] is True
    finally:
        await client.close()
        await session.close()


@pytest.mark.asyncio
async def test_flood_without_probe_path_passes_through(mock_storage):
    """
    Source in flood state hitting a non-probe path still reaches upstream (B1).
    Upstream unavailable here → default mirror fallback, but classification is
    still 'flood' and the probe log shows the pass-through attempt.
    """
    now = time.time()
    source_id = "flood-test-source"
    mock_storage.sources["127.0.0.1"] = {
        "id": source_id,
        "ip_address": "127.0.0.1",
        "reputation": "neutral",
        "first_seen": now,
        "last_seen": now,
        "probe_count": 0,
        "legit_count": 0,
        "notes": [],
    }
    # No patterns installed — any path will pass through (or fall to mirror if upstream down)
    cap_mod._rate_windows[source_id] = deque([now - 0.1] * 1000, maxlen=2000)

    client, session = await _make_client(_config(upstream="http://127.0.0.1:59995"), mock_storage)
    try:
        resp = await client.get("/api/health")
        assert resp.status in {200, 429, 503}  # upstream down → default mirror variant
        await asyncio.sleep(0.05)
        assert len(mock_storage.probes) > 0
        logged = mock_storage.probes[-1]
        assert logged["classification"] == "flood"
    finally:
        await client.close()
        await session.close()


@pytest.mark.asyncio
async def test_no_match_routes_upstream(mock_storage):
    """
    Pattern installed but path doesn't match -> unknown -> upstream.
    If upstream is unavailable, Net Ward falls back to one of the default mirror
    variants rather than a raw 502.
    """
    mock_storage.patterns = [_wp_admin_pattern()]
    client, session = await _make_client(_config(upstream="http://127.0.0.1:59996"), mock_storage)
    try:
        resp = await client.get("/totally/legitimate/endpoint")
        assert resp.status in {200, 429, 503}  # default mirror variant (not a raw 502)
        await asyncio.sleep(0.05)
        assert len(mock_storage.probes) > 0
        logged = mock_storage.probes[-1]
        assert logged["classification"] == "unknown"
        assert logged["mirror_fired"] is True
        assert logged["upstream_passed"] is False
    finally:
        await client.close()
        await session.close()


# ---------------------------------------------------------------------------
# Fail-open storage reads (v0.4.7 review)
# ---------------------------------------------------------------------------

class _FailingReadStorage(_MockStorage):
    """Storage whose hot-path reads raise, simulating SQLite lock/IO/corruption."""

    def sources_lookup(self, ip: str):
        raise RuntimeError("sqlite locked: sources_lookup")

    def mirror_response_lookup(self, mr_id: str):
        raise RuntimeError("sqlite locked: mirror_response_lookup")


@pytest.mark.asyncio
async def test_storage_read_failure_fail_opens_never_500():
    """
    sources_lookup / mirror_response_lookup exceptions must not abort the
    handler with 500. Traffic continues fail-open: forward upstream, or
    default-mirror if upstream is down.
    """
    storage = _FailingReadStorage()
    client, session = await _make_client(
        _config(upstream="http://127.0.0.1:59994"), storage
    )
    try:
        resp = await client.get("/api/status")
        assert resp.status != 500, (
            "storage read failure must not 500 the request path"
        )
        assert resp.status in {200, 429, 503}
        body = await resp.text()
        assert body  # default mirror or upstream body, never an empty crash
    finally:
        await client.close()
        await session.close()


@pytest.mark.asyncio
async def test_storage_read_failure_still_forwards_when_upstream_up(mock_storage):
    """When storage reads fail but upstream is healthy, traffic still passes."""
    served: list[str] = []

    async def upstream_ok(request):
        served.append(request.path)
        return web.Response(text="from upstream")

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", upstream_ok)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        storage = _FailingReadStorage()
        client, session = await _make_client(
            _config(upstream=f"http://127.0.0.1:{port}"), storage
        )
        try:
            resp = await client.get("/healthz")
            assert resp.status == 200
            assert await resp.text() == "from upstream"
            assert served == ["/healthz"]
        finally:
            await client.close()
            await session.close()
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_mirror_lookup_failure_uses_default_mirror(stub_mirror):
    """
    A pattern that names a mirror_response_id must still return a mirror
    (never 500) when mirror_response_lookup raises.
    """
    storage = _FailingReadStorage()
    pat = _wp_admin_pattern()
    pat["mirror_response_id"] = "mr-missing"
    storage.patterns = [pat]
    client, session = await _make_client(_config(), storage)
    try:
        resp = await client.get("/wp-admin/login.php")
        assert resp.status != 500
        assert resp.status == 200
        assert "mirrored" in await resp.text()
    finally:
        await client.close()
        await session.close()


# ---------------------------------------------------------------------------
# Upstream timeouts + concurrency cap
# ---------------------------------------------------------------------------

async def _spin_upstream(handler) -> tuple[web.AppRunner, int]:
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, port


@pytest.mark.asyncio
async def test_upstream_timeout_fail_opens_to_default_mirror(mock_storage):
    """Hung upstream must not pin the worker; request fail-opens to default mirror."""

    async def slow(request):
        await asyncio.sleep(10)
        return web.Response(text="too late")

    runner, port = await _spin_upstream(slow)
    try:
        cfg = _config(upstream=f"http://127.0.0.1:{port}")
        cfg["upstream_timeout_total"] = 0.2
        cfg["upstream_timeout_connect"] = 0.2
        cfg["upstream_timeout_sock_read"] = 0.2
        client, session = await _make_client(cfg, mock_storage)
        try:
            t0 = time.monotonic()
            resp = await client.get("/slow")
            elapsed = time.monotonic() - t0
            assert elapsed < 2.0, f"upstream timeout did not fire, elapsed={elapsed:.2f}s"
            assert resp.status != 500
            assert resp.status in {200, 429, 503}
            assert "too late" not in await resp.text()
        finally:
            await client.close()
            await session.close()
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_upstream_concurrency_cap_serializes_in_flight(mock_storage):
    """upstream_max_concurrency=1 must keep at most one upstream request in flight."""
    release = asyncio.Event()
    in_flight = 0
    max_seen = 0
    lock = asyncio.Lock()

    async def hold(request):
        nonlocal in_flight, max_seen
        async with lock:
            in_flight += 1
            max_seen = max(max_seen, in_flight)
        try:
            await asyncio.wait_for(release.wait(), timeout=3)
        except asyncio.TimeoutError:
            pass
        async with lock:
            in_flight -= 1
        return web.Response(text="ok")

    runner, port = await _spin_upstream(hold)
    try:
        cfg = _config(upstream=f"http://127.0.0.1:{port}")
        cfg["upstream_max_concurrency"] = 1
        cfg["upstream_timeout_total"] = 5.0
        client, session = await _make_client(cfg, mock_storage)
        try:
            t1 = asyncio.create_task(client.get("/a"))
            t2 = asyncio.create_task(client.get("/b"))
            await asyncio.sleep(0.3)
            assert max_seen <= 1, f"concurrency cap leaked; max in-flight={max_seen}"
            release.set()
            r1, r2 = await asyncio.gather(t1, t2)
            assert r1.status == 200
            assert r2.status == 200
            assert await r1.text() == "ok"
            assert await r2.text() == "ok"
        finally:
            await client.close()
            await session.close()
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_upstream_body_over_cap_fail_opens_to_default_mirror(mock_storage):
    """Oversized upstream bodies are not fully buffered; request fail-opens."""

    async def fat(request):
        return web.Response(body=b"X" * 2048)

    runner, port = await _spin_upstream(fat)
    try:
        cfg = _config(upstream=f"http://127.0.0.1:{port}")
        cfg["upstream_max_body_bytes"] = 64
        client, session = await _make_client(cfg, mock_storage)
        try:
            resp = await client.get("/fat")
            assert resp.status != 500
            body = await resp.text()
            assert "X" * 64 not in body
            assert resp.status in {200, 429, 503}
        finally:
            await client.close()
            await session.close()
    finally:
        await runner.cleanup()
