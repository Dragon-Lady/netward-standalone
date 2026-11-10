"""Actual daemon startup with unavailable storage, using loopback servers only."""
import asyncio
import json
import hashlib
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
from netward.storage import Storage, StorageError


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["readonly", "readonly_wal_sidecars", "missing_parent_readonly", "invalid_db_path"])
async def test_daemon_starts_and_routes_when_database_is_unwritable(tmp_path, mode):
    if mode != "invalid_db_path" and (os.name != "posix" or os.geteuid() == 0):
        pytest.skip("mode-bit write denial requires an unprivileged POSIX user")
    protected = tmp_path / "protected"
    protected.mkdir(mode=0o700)
    db = protected / "netward.db"
    held_store = None
    if mode.startswith("readonly"):
        with Storage(db) as store:
            install_vendor_patterns(store)
            assert store._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        held_store = Storage(db)
        held_store._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        held_store._conn.execute("UPDATE patterns SET expires_at=1 WHERE id IN "
                                "('generic_admin_login_probe', 'env_file_probe')")
        if mode == "readonly":
            held_store.close()
            held_store = None
            assert not Path(str(db) + "-wal").exists()
        else:
            # Keep committed disables in WAL, absent from the main database.
            assert Path(str(db) + "-wal").stat().st_size > 0
            for suffix in ("-wal", "-shm"):
                Path(str(db) + suffix).chmod(0o444)
        db.chmod(0o444)
    elif mode == "invalid_db_path":
        db.mkdir()
    if mode != "invalid_db_path":
        protected.chmod(0o555)
    original_hash = hashlib.sha256(db.read_bytes()).hexdigest() if db.is_file() else None
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
            mirrored = ("/wp-admin/login.php",) if mode.startswith("readonly") else ("/.env", "/wp-admin/login.php")
            for path in mirrored:
                async with client.get(f"http://127.0.0.1:{port}" + path) as response:
                    assert response.status == 200
                    assert await response.text() != "upstream response"
                assert path not in served
            if mode.startswith("readonly"):
                # Both saved disables must win over bundled defaults in WAL mode.
                for path in ("/.env", "/admin"):
                    async with client.get(f"http://127.0.0.1:{port}" + path) as response:
                        assert await response.text() == "upstream response"
                    assert path in served
            assert proc.returncode is None
    finally:
        if proc is not None:
            if proc.returncode is None:
                proc.terminate()
            _, errors = await asyncio.wait_for(proc.communicate(), 5)
        await server.close()
        if original_hash is not None:
            assert hashlib.sha256(db.read_bytes()).hexdigest() == original_hash
        if mode == "readonly":
            assert not Path(str(db) + "-wal").exists()
            assert not Path(str(db) + "-shm").exists()
        protected.chmod(0o700)
        if mode.startswith("readonly"):
            db.chmod(0o600)
        if held_store is not None:
            for suffix in ("-wal", "-shm"):
                Path(str(db) + suffix).chmod(0o600)
            held_store.close()
    log = errors.decode()
    if mode == "readonly":
        assert "started with read-only storage" in log
    elif mode == "readonly_wal_sidecars":
        # SQLite can initialize successfully yet reject later writes.
        assert "storage" in log.lower()
        assert "started without persistence" not in log
    else:
        assert "started without persistence" in log
    assert "Task exception was never retrieved" not in log
    assert str(db) not in log


@pytest.mark.parametrize("sidecar", ["-wal", "-shm", "-journal"])
def test_snapshot_fallback_refuses_sidecars(tmp_path, sidecar):
    db = tmp_path / "source.db"
    with Storage(db) as store:
        install_vendor_patterns(store)
    Path(str(db) + sidecar).touch()
    target = tmp_path / "snapshot.db"
    with pytest.raises(StorageError, match="sidecars"):
        Storage._copy_checkpointed_database(db, target)
    assert not target.exists()


@pytest.mark.parametrize("change", ["main", "wal"])
def test_snapshot_fallback_rejects_source_changes(tmp_path, monkeypatch, change):
    import netward.storage as storage_module
    db = tmp_path / "source.db"
    with Storage(db) as store:
        install_vendor_patterns(store)
    original_copy = storage_module.shutil.copyfileobj

    def changing_copy(src, dst):
        original_copy(src, dst)
        if change == "main":
            with db.open("ab") as writer:
                writer.write(b"changed")
        else:
            Path(str(db) + "-wal").write_bytes(b"new commit")

    monkeypatch.setattr(storage_module.shutil, "copyfileobj", changing_copy)
    with pytest.raises(StorageError, match="changed|sidecars"):
        Storage._copy_checkpointed_database(db, tmp_path / "snapshot.db")


def test_readonly_reader_sees_disables_committed_only_in_wal(tmp_path):
    db = tmp_path / "source.db"
    with Storage(db) as writer:
        install_vendor_patterns(writer)
        writer._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        main_before = db.read_bytes()
        writer._conn.execute("UPDATE patterns SET expires_at=1 WHERE id='env_file_probe'")
        assert db.read_bytes() == main_before
        assert Path(str(db) + "-wal").stat().st_size > 0
        with Storage.open_readonly(db) as reader:
            assert reader._snapshot_dir is None
            assert "env_file_probe" not in {p["id"] for p in reader.patterns_active()}
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                reader._conn.execute("UPDATE patterns SET expires_at=NULL")


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0,
                    reason="requires an unprivileged POSIX user")
def test_checkpointed_wal_snapshot_is_private_readonly_and_removed_on_close(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    db = protected / "source.db"
    with Storage(db) as writer:
        install_vendor_patterns(writer)
        writer._conn.execute("UPDATE patterns SET expires_at=1 WHERE id='env_file_probe'")
    db.chmod(0o444)
    protected.chmod(0o555)
    try:
        with Storage.open_readonly(db) as reader:
            directory = Path(reader._snapshot_dir.name)
            snapshot = directory / "snapshot.db"
            assert directory.stat().st_mode & 0o777 == 0o700
            assert snapshot.stat().st_mode & 0o777 == 0o600
            assert "env_file_probe" not in {p["id"] for p in reader.patterns_active()}
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                reader._conn.execute("UPDATE patterns SET expires_at=NULL")
        assert not directory.exists()
    finally:
        protected.chmod(0o700)
        db.chmod(0o600)
