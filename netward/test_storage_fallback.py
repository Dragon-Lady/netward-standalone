"""Actual daemon startup with unavailable storage, using loopback servers only."""
import asyncio
import contextlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestServer
import pytest

from netward.bootstrap import install_vendor_patterns
from netward.storage import Storage


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["readonly", "missing_parent_readonly", "invalid_db_path"])
async def test_daemon_starts_and_routes_when_database_is_unwritable(tmp_path, mode):
    if mode != "invalid_db_path" and (os.name != "posix" or os.geteuid() == 0):
        pytest.skip("mode-bit write denial requires an unprivileged POSIX user")
    protected = tmp_path / "protected"
    protected.mkdir(mode=0o700)
    db = protected / "netward.db"
    if mode == "readonly":
        with Storage(db) as store:
            install_vendor_patterns(store)
            store._conn.execute("UPDATE patterns SET expires_at=1 WHERE id='generic_admin_login_probe'")
        with sqlite3.connect(db) as conn:
            conn.execute("PRAGMA journal_mode=DELETE")
        db.chmod(0o444)
    elif mode == "invalid_db_path":
        db.mkdir()
    if mode != "invalid_db_path":
        protected.chmod(0o555)
    served = []
    async def upstream(request):
        served.append(request.path)
        return web.Response(text="upstream response")
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", upstream)
    server = TestServer(app)
    await server.start_server()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"node_id": "startup-test", "listen_address": f"127.0.0.1:{port}",
                                  "upstream_target": str(server.make_url("/")), "storage_path": str(db)}))
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(sys.executable, "-m", "netward", "--config", str(config),
                    cwd=tmp_path, env=env, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=1)) as client:
            for _ in range(100):
                assert proc.returncode is None, "daemon exited before serving"
                try:
                    async with client.get(f"http://127.0.0.1:{port}/healthz") as response:
                        assert response.status == 200
                        assert await response.text() == "upstream response"
                    break
                except aiohttp.ClientConnectorError:
                    await asyncio.sleep(0.05)
            else:
                pytest.fail("daemon never started serving")
            for path in ("/.env", "/wp-admin/login.php"):
                async with client.get(f"http://127.0.0.1:{port}" + path) as response:
                    assert response.status == 200
                    assert await response.text() != "upstream response"
                assert path not in served
            if mode == "readonly":
                # Readable disabled/custom configuration wins over bundled defaults.
                async with client.get(f"http://127.0.0.1:{port}/admin") as response:
                    assert await response.text() == "upstream response"
            assert proc.returncode is None
    finally:
        if proc is not None:
            if proc.returncode is None:
                proc.terminate()
            _, errors = await asyncio.wait_for(proc.communicate(), 5)
        await server.close()
        protected.chmod(0o700)
        if mode == "readonly":
            db.chmod(0o600)
    log = errors.decode()
    assert "started with read-only storage" in log if mode == "readonly" else "started without persistence" in log
    assert "Task exception was never retrieved" not in log
    assert str(db) not in log
