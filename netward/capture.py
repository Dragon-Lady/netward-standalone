"""
Net Ward -- Capture Layer

aiohttp reverse-proxy entry point. All inbound HTTP traffic passes through
here: build a Probe, classify it, then route -- mirror response (probe/flood)
or pass-through to upstream (unknown/legit).

Design rule (from __init__.py): FAIL SAFE, FAIL OPEN.
If classification or mirroring raises, the request is forwarded to upstream
rather than dropped. Net Ward must never take the host application down.

Public interface:
    start_capture_loop(config, storage=None) -> None
        Bind to config["listen_address"], proxy to config["upstream_target"].
        Runs until cancelled (asyncio.CancelledError).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from collections import deque
from typing import Optional

import aiohttp
from aiohttp import web

from netward.schema import (
    ALERT_DEDUP_WINDOW_SECS,
    PROBE_MAX_ROWS,
    PROBE_RETENTION_SECS,
    UPSTREAM_MAX_BODY_BYTES,
    UPSTREAM_MAX_CONCURRENCY,
    UPSTREAM_TIMEOUT_CONNECT_SECS,
    UPSTREAM_TIMEOUT_SOCK_READ_SECS,
    UPSTREAM_TIMEOUT_TOTAL_SECS,
    OperatorConfig,
    Probe,
    RequestMetadata,
    Source,
)
from netward import classify as _classify_mod
from netward import mirror as _mirror_mod
from netward import operator_layer as _operator

_log = logging.getLogger(__name__)
_storage_warnings: dict[str, float] = {}


def _warn_storage(operation: str, exc: Exception) -> None:
    """One warning per operation per minute, with no private exception text."""
    now = time.monotonic()
    previous = _storage_warnings.get(operation)
    if previous is None or now - previous >= 60:
        _storage_warnings[operation] = now
        _log.warning("Net Ward storage %s failed; continuing degraded: %s",
                     operation, type(exc).__name__)


# Body capture cap per schema (RequestMetadata.body_snippet)
_BODY_SNIPPET_MAX = 4096

# Must stay in sync with classify.FLOOD_WINDOW_SECS (both are 10.0 s, v0.4.1)
_RATE_WINDOW_SECS: float = 10.0

# Per-source rate windows (source_id -> bounded deque of request timestamps).
# maxlen=2000: headroom above the 1000-hit flood threshold to avoid evicting
# in-window timestamps before they age out naturally.
# Dict is capped at _RATE_WINDOW_MAX_SOURCES; oldest quarter evicted when full.
_RATE_WINDOW_MAX_SOURCES = 10_000
_rate_windows: dict[str, deque] = {}


class _AlertDispatcher:
    """Keep outbound sends out of the proxy response path."""

    def __init__(self, config: OperatorConfig, storage):
        self.config = config
        self.storage = storage
        self.tasks: set[asyncio.Task] = set()
        self.in_flight: set[str] = set()
        self.capacity = asyncio.Semaphore(8)

    def submit(self, alert: dict) -> None:
        if alert["id"] in self.in_flight:
            return
        self.in_flight.add(alert["id"])
        task = asyncio.create_task(self._deliver(alert))
        self.tasks.add(task)
        task.add_done_callback(lambda done: self._finished(alert["id"], done))

    def _finished(self, alert_id: str, task: asyncio.Task) -> None:
        self.tasks.discard(task)
        self.in_flight.discard(alert_id)
        if not task.cancelled() and task.exception():
            _log.error("Net Ward alert %s delivery failed: %s", alert_id,
                       type(task.exception()).__name__)

    async def _deliver(self, alert: dict) -> None:
        channels = self.config.get("alert_channels") or ["stdout"]
        remaining = [c for c in channels if c not in alert.get("delivered_to", [])]
        async with self.capacity:
            for attempt in range(3):
                if not remaining:
                    break
                if attempt:
                    await asyncio.sleep(2 ** (attempt - 1))
                successful = await asyncio.to_thread(
                    _operator.deliver_alert, alert, self.config, remaining
                )
                if successful:
                    await asyncio.to_thread(
                        self.storage.alerts_mark_delivered, alert["id"], successful
                    )
                remaining = [c for c in remaining if c not in successful]

    async def close(self) -> None:
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)

    async def recover_pending(self) -> None:
        """Keep retrying recent undelivered alerts while the node is running."""
        channels = self.config.get("alert_channels") or ["stdout"]
        while True:
            try:
                pending = await asyncio.to_thread(
                    self.storage.alerts_pending, channels, time.time()
                )
                for alert in pending:
                    self.submit(alert)
            except Exception as exc:
                _log.error("Net Ward pending alert recovery failed: %s", type(exc).__name__)
            await asyncio.sleep(60)


def _get_rate_window(source_id: str) -> deque:
    if source_id not in _rate_windows:
        if len(_rate_windows) >= _RATE_WINDOW_MAX_SOURCES:
            evict_n = _RATE_WINDOW_MAX_SOURCES // 4
            for k in list(_rate_windows.keys())[:evict_n]:
                del _rate_windows[k]
        _rate_windows[source_id] = deque(maxlen=2000)
    return _rate_windows[source_id]

# Hop-by-hop headers stripped before forwarding upstream
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
})

_PATTERN_CACHE_TTL = 30.0

# Default mirror variant set (v0.4.1 fingerprint hardening).
# A single fixed JSON shape was detectable under load (stress-state signature).
# Variant selection is deterministic per (source_id, path) so a given source
# sees a consistent shape per path — prevents second-probe shape divergence.
_DEFAULT_MIRROR: dict = {
    "id": "_netward_default",
    "matches_pattern_id": "",
    "intensity": "minimal",
    "http_status": 200,
    "headers": {"Content-Type": "application/json"},
    "body_template": '{"status":"ok","id":"{{uuid}}","timestamp":"{{timestamp}}"}',
    "body_template_vars": {"uuid": "uuid", "timestamp": "timestamp"},
    "description": "Default minimal mirror (fallback; prefer _select_default_mirror)",
    "created_at": 0.0,
}

_DEFAULT_MIRROR_VARIANTS: list[dict] = [
    {
        "id": "_netward_default_0",
        "matches_pattern_id": "",
        "intensity": "minimal",
        "http_status": 200,
        "headers": {"Content-Type": "application/json"},
        "body_template": '{"status":"ok","id":"{{uuid}}","timestamp":"{{timestamp}}"}',
        "body_template_vars": {"uuid": "uuid", "timestamp": "timestamp"},
        "description": "Default variant 0 — JSON ok",
        "created_at": 0.0,
    },
    {
        "id": "_netward_default_1",
        "matches_pattern_id": "",
        "intensity": "minimal",
        "http_status": 429,
        "headers": {"Content-Type": "application/json", "Retry-After": "30"},
        "body_template": '{"error":"rate limited","retry_after":30}',
        "body_template_vars": {},
        "description": "Default variant 1 — rate limited JSON",
        "created_at": 0.0,
    },
    {
        "id": "_netward_default_2",
        "matches_pattern_id": "",
        "intensity": "minimal",
        "http_status": 503,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body_template": "<html><body><h1>Service Unavailable</h1><p>Try again later.</p></body></html>",
        "body_template_vars": {},
        "description": "Default variant 2 — HTML 503",
        "created_at": 0.0,
    },
    {
        "id": "_netward_default_3",
        "matches_pattern_id": "",
        "intensity": "minimal",
        "http_status": 200,
        "headers": {"Content-Type": "application/json"},
        "body_template": '{"data":null,"next":null}',
        "body_template_vars": {},
        "description": "Default variant 3 — empty result JSON",
        "created_at": 0.0,
    },
    {
        "id": "_netward_default_4",
        "matches_pattern_id": "",
        "intensity": "minimal",
        "http_status": 200,
        "headers": {"Content-Type": "text/plain; charset=utf-8"},
        "body_template": "OK",
        "body_template_vars": {},
        "description": "Default variant 4 — plain OK",
        "created_at": 0.0,
    },
]


def _select_default_mirror(source_id: str, path: str) -> dict:
    """Deterministic variant per (source_id, path) to prevent shape divergence."""
    digest = hashlib.sha256(f"{source_id}\0{path}".encode("utf-8")).digest()
    idx = int.from_bytes(digest[:8], "big") % len(_DEFAULT_MIRROR_VARIANTS)
    return _DEFAULT_MIRROR_VARIANTS[idx]


async def _read_body_snippet(request: web.Request) -> Optional[str]:
    try:
        raw = await request.read()
        if not raw:
            return None
        return raw[:_BODY_SNIPPET_MAX].decode("utf-8", errors="replace")
    except Exception:
        return None


async def _build_probe(request: web.Request, source_id: str) -> Probe:
    body = await _read_body_snippet(request)
    req_meta: RequestMetadata = {
        "method": request.method,
        "path": request.path,
        "headers": dict(request.headers),
        "query_string": request.query_string or None,
        "body_snippet": body,
        "body_size": len(body.encode("utf-8", errors="replace")) if body else 0,
        "user_agent": request.headers.get("User-Agent"),
    }
    return {
        "id": str(uuid.uuid4()),
        "timestamp": time.time(),
        "source_id": source_id,
        "pattern_id": None,
        "classification": "unknown",
        "request": req_meta,
        "response_id": None,
        "mirror_fired": False,
        "upstream_passed": False,
    }


def _client_timeout_from_config(config: OperatorConfig) -> aiohttp.ClientTimeout:
    return aiohttp.ClientTimeout(
        total=float(config.get("upstream_timeout_total", UPSTREAM_TIMEOUT_TOTAL_SECS)),
        connect=float(config.get("upstream_timeout_connect", UPSTREAM_TIMEOUT_CONNECT_SECS)),
        sock_read=float(config.get("upstream_timeout_sock_read", UPSTREAM_TIMEOUT_SOCK_READ_SECS)),
    )


def _max_concurrency_from_config(config: OperatorConfig) -> int:
    return max(1, int(config.get("upstream_max_concurrency", UPSTREAM_MAX_CONCURRENCY)))


def _max_body_from_config(config: OperatorConfig) -> int:
    return max(1, int(config.get("upstream_max_body_bytes", UPSTREAM_MAX_BODY_BYTES)))


async def _read_capped_body(resp: aiohttp.ClientResponse, max_bytes: int) -> Optional[bytes]:
    """Read an upstream body up to max_bytes. None means the cap was exceeded."""
    chunks: list[bytes] = []
    total = 0
    async for chunk in resp.content.iter_chunked(65_536):
        total += len(chunk)
        if total > max_bytes:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


async def _forward_upstream(
    request: web.Request,
    upstream: str,
    session: aiohttp.ClientSession,
    *,
    timeout: Optional[aiohttp.ClientTimeout] = None,
    semaphore: Optional[asyncio.Semaphore] = None,
    max_body_bytes: int = UPSTREAM_MAX_BODY_BYTES,
) -> Optional[web.Response]:
    """Forward to upstream. Return None when upstream is unavailable."""
    url = upstream.rstrip("/") + request.path
    if request.query_string:
        url += "?" + request.query_string
    fwd_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP and k.lower() != "host"
    }

    async def _do() -> Optional[web.Response]:
        try:
            body = await request.read()
            async with session.request(
                method=request.method,
                url=url,
                headers=fwd_headers,
                data=body,
                allow_redirects=False,
                timeout=timeout,
            ) as resp:
                content = await _read_capped_body(resp, max_body_bytes)
                if content is None:
                    _log.warning("Net Ward upstream response exceeded body cap; using default mirror")
                    return None
                resp_headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() not in _HOP_BY_HOP | {"content-encoding"}
                }
                return web.Response(status=resp.status, headers=resp_headers, body=content)
        except asyncio.TimeoutError:
            _log.warning("Net Ward upstream timed out; using default mirror")
            return None
        except Exception as exc:
            # Exception messages can contain credentials, URLs, or request data.
            _log.warning("Net Ward upstream forwarding failed; using default mirror: %s",
                         type(exc).__name__)
            return None

    if semaphore is None:
        return await _do()
    async with semaphore:
        return await _do()


def _mirror_response_from_probe(probe: Probe, mirror: dict) -> web.Response:
    http_resp = _mirror_mod.fire_mirror(probe, mirror)
    return web.Response(
        status=http_resp["status"],
        headers=http_resp["headers"],
        text=http_resp["body"],
    )


def _fire_and_forget(storage, probe: Probe) -> None:
    """Schedule probe logging without blocking the response path."""
    try:
        loop = asyncio.get_running_loop()
        task = loop.create_task(asyncio.to_thread(storage.probes_log, probe))
        def finished(done):
            if not done.cancelled():
                exc = done.exception()  # Retrieve failures instead of leaking task tracebacks.
                if exc is not None:
                    _warn_storage("probe log", exc)
        task.add_done_callback(finished)
    except RuntimeError:
        pass  # no running loop (e.g., during sync tests)
    except Exception as exc:
        _warn_storage("probe log scheduling", exc)


def _make_handler(config: OperatorConfig, storage, session: aiohttp.ClientSession):
    upstream = config["upstream_target"]
    timeout = _client_timeout_from_config(config)
    semaphore = asyncio.Semaphore(_max_concurrency_from_config(config))
    max_body_bytes = _max_body_from_config(config)
    dispatcher = _AlertDispatcher(config, storage)

    # Read the bundled fallback once. A successful DB read always takes
    # precedence, including an empty set that reflects intentional disables.
    try:
        from netward.bootstrap import load_vendor_data
        bundle = load_vendor_data()
    except Exception as exc:
        _warn_storage("bundled pattern load", exc)
        bundle = {"patterns": [], "mirror_responses": []}
    bundled_mirrors = {m["id"]: m for m in bundle["mirror_responses"]}
    _pcache: list = []
    _pcache_at: float = 0.0
    _pcache_loaded = False

    def _get_patterns() -> list:
        nonlocal _pcache, _pcache_at, _pcache_loaded
        now = time.time()
        if not _pcache_loaded or now - _pcache_at > _PATTERN_CACHE_TTL:
            try:
                _pcache = storage.patterns_active()
            except Exception as exc:
                _warn_storage("pattern read", exc)
                if not _pcache_loaded:
                    _pcache = [p for p in bundle["patterns"]
                               if p.get("expires_at") is None or p["expires_at"] > now]
            _pcache_at = now
            _pcache_loaded = True
        return _pcache

    async def handle(request: web.Request) -> web.Response:
        ip = request.remote or "0.0.0.0"
        now = time.time()

        # Source lookup or create — fail-open on storage read errors
        try:
            source = storage.sources_lookup(ip)
        except Exception as exc:
            _warn_storage("source lookup", exc)
            source = None
        if not source:
            source = {
                "id": str(uuid.uuid5(uuid.NAMESPACE_URL, "netward-source:" + ip)),
                "ip_address": ip,
                "reputation": "neutral",
                "first_seen": now,
                "last_seen": now,
                "probe_count": 0,
                "legit_count": 0,
                "notes": [],
            }
        source_id: str = source["id"]

        # Rate window update (in-memory, bounded + evicting)
        window = _get_rate_window(source_id)
        prior_window_count = sum(1 for t in window if now - t <= _RATE_WINDOW_SECS)
        window.append(now)
        rate_window = list(window)

        probe = await _build_probe(request, source_id)

        # Classify -- fail-open on any unhandled exception
        patterns = _get_patterns()
        try:
            result = _classify_mod.classify(
                probe, {"patterns": patterns, "source": source, "rate_window": rate_window}
            )
        except Exception as exc:
            _log.error("Net Ward classifier failed; failing open: %s", type(exc).__name__)
            probe["classification"] = "unknown"
            upstream_response = await _forward_upstream(
                request,
                upstream,
                session,
                timeout=timeout,
                semaphore=semaphore,
                max_body_bytes=max_body_bytes,
            )
            if upstream_response is None:
                probe["mirror_fired"] = True
                probe["upstream_passed"] = False
                response = _mirror_response_from_probe(
                    probe, _select_default_mirror(source_id, request.path)
                )
            else:
                probe["upstream_passed"] = True
                response = upstream_response
            _fire_and_forget(storage, probe)
            return response

        updated = result["probe"]
        classification = updated.get("classification", "unknown")

        # Source counters + reputation.
        # Key on fire_mirror, not classification: a "flood"-classified request
        # that didn't match a pattern still passes to upstream — that's legit
        # traffic, not a probe. Only mirror-firing events are probe_count.
        if result["fire_mirror"]:
            source["probe_count"] = source.get("probe_count", 0) + 1
        else:
            source["legit_count"] = source.get("legit_count", 0) + 1
        source["last_seen"] = now
        source = _classify_mod.update_source_reputation(source)
        try:
            storage.sources_upsert(source)
        except Exception as exc:
            _warn_storage("source write", exc)

        # Route
        _default_mr = _select_default_mirror(source_id, request.path)
        if result["fire_mirror"]:
            mr_id = result.get("mirror_response_id")
            mr = None
            if mr_id:
                try:
                    mr = storage.mirror_response_lookup(mr_id)
                except Exception as exc:
                    _warn_storage("mirror lookup", exc)
                    mr = bundled_mirrors.get(mr_id)
            mr = mr or _default_mr
            try:
                response = _mirror_response_from_probe(updated, mr)
            except Exception as exc:
                # Mirror failed -- fail-open, pass upstream
                _log.error(
                    "Net Ward mirror render failed; failing open: %s",
                    type(exc).__name__,
                )
                upstream_response = await _forward_upstream(
                    request,
                    upstream,
                    session,
                    timeout=timeout,
                    semaphore=semaphore,
                    max_body_bytes=max_body_bytes,
                )
                if upstream_response is None:
                    updated["mirror_fired"] = True
                    updated["upstream_passed"] = False
                    response = _mirror_response_from_probe(updated, _default_mr)
                else:
                    updated["mirror_fired"] = False
                    updated["upstream_passed"] = True
                    response = upstream_response
        else:
            upstream_response = await _forward_upstream(
                request,
                upstream,
                session,
                timeout=timeout,
                semaphore=semaphore,
                max_body_bytes=max_body_bytes,
            )
            if upstream_response is None:
                updated["mirror_fired"] = True
                updated["upstream_passed"] = False
                response = _mirror_response_from_probe(updated, _default_mr)
            else:
                updated["upstream_passed"] = True
                if classification == "unknown":
                    updated["classification"] = "legit"
                response = upstream_response

        _fire_and_forget(storage, updated)
        pattern_id = updated.get("pattern_id")
        flood_started = (classification == "flood" and
                         prior_window_count < _classify_mod.FLOOD_THRESHOLD)
        if pattern_id or flood_started:
            pattern = next((p for p in patterns if p.get("id") == pattern_id), None)
            alert = {
                "id": str(uuid.uuid4()),
                "severity": "critical" if flood_started else (pattern or {}).get("severity", "warn"),
                "kind": "flood_active" if flood_started else "pattern_match",
                "title": "Request flood detected" if flood_started else "Probe pattern matched",
                "body": f"Source {ip}; pattern {pattern_id or 'none'}; classification {classification}",
                "source_id": source_id,
                "pattern_id": pattern_id if not flood_started else None,
                "triggered_at": now,
                "delivered_to": [],
                "count": 1,
            }
            try:
                stored, is_new = storage.alerts_record(alert, ALERT_DEDUP_WINDOW_SECS)
                if is_new:
                    dispatcher.submit(stored)
            except Exception as exc:
                _warn_storage("alert recording", exc)
        return response

    handle.alert_dispatcher = dispatcher
    return handle


async def start_capture_loop(config: OperatorConfig, storage=None) -> None:
    """
    Bind to config["listen_address"] and begin proxying to
    config["upstream_target"]. Runs until cancelled.
    Storage startup failures use read-only or no-persistence mode so the
    listener still starts; explicit configuration/security checks remain fatal.
    """
    _operator.validate_alert_config(config)
    owns_storage = storage is None
    if storage is None:
        from netward.storage import Storage, UnavailableStorage
        path = config.get("storage_path", "netward.db")
        try:
            storage = Storage(
                path,
                probe_retention_secs=float(config.get("probe_retention_secs", PROBE_RETENTION_SECS)),
                probe_max_rows=int(config.get("probe_max_rows", PROBE_MAX_ROWS)),
            )
        except Exception as exc:
            _warn_storage("startup write access", exc)
            try:
                storage = Storage.open_readonly(path)
                _log.warning("Net Ward started with read-only storage; persistence unavailable")
            except Exception as read_exc:
                _warn_storage("startup read access", read_exc)
                storage = UnavailableStorage()
                _log.warning("Net Ward started without persistence; using bundled probe defaults")

    try:
        from netward import bootstrap as _bootstrap
        _bootstrap.install_vendor_patterns(storage)
    except Exception as exc:
        _warn_storage("vendor seed", exc)

    timeout = _client_timeout_from_config(config)
    limit = _max_concurrency_from_config(config)
    connector = aiohttp.TCPConnector(limit=limit)
    session = aiohttp.ClientSession(connector=connector, timeout=timeout)
    _proxy_handler = _make_handler(config, storage, session)
    recovery_task = asyncio.create_task(_proxy_handler.alert_dispatcher.recover_pending())

    @web.middleware
    async def catch_all(request: web.Request, handler) -> web.Response:
        return await _proxy_handler(request)

    app = web.Application(middlewares=[catch_all])

    runner = web.AppRunner(app)
    await runner.setup()

    listen = config.get("listen_address", "0.0.0.0:8080")
    host, _, port_str = listen.rpartition(":")
    if not host:
        host = "0.0.0.0"
    site = web.TCPSite(runner, host, int(port_str))
    await site.start()

    try:
        await asyncio.Event().wait()
    finally:
        recovery_task.cancel()
        await asyncio.gather(recovery_task, return_exceptions=True)
        await _proxy_handler.alert_dispatcher.close()
        await session.close()
        await runner.cleanup()
        if owns_storage:
            storage.close()
