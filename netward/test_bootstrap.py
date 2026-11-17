"""
Net Ward -- bootstrap layer tests.
Covers install_vendor_patterns idempotency, error handling, and the
disable/enable cycle that the CLI delegates to direct SQL.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from netward import bootstrap as mod
from netward.storage import Storage


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def storage(tmp_path):
    s = Storage(tmp_path / "bootstrap_test.db")
    yield s
    s.close()


def _write_vendor_json(path: Path, n_patterns: int = 3, n_mirrors: int = 2) -> Path:
    mirrors = [
        {
            "id": f"mirror_{i}",
            "matches_pattern_id": f"vendor_test_{i}",
            "intensity": "minimal",
            "http_status": 200,
            "headers": {"Content-Type": "application/json"},
            "body_template": '{"id":"{{uuid}}"}',
            "body_template_vars": {"uuid": "uuid"},
            "description": f"test mirror {i}",
            "created_at": 0,
        }
        for i in range(n_mirrors)
    ]
    patterns = [
        {
            "id": f"vendor_test_{i}",
            "kind": "path",
            "signature": f"^/test-{i}\\b",
            "description": f"test pattern {i}",
            "severity": "warn",
            "origin": "vendor",
            "mirror_response_id": f"mirror_{i % n_mirrors}",
            "confidence": 0.9,
            "match_count": 0,
            "mutation_generation": 0,
            "created_at": 0,
        }
        for i in range(n_patterns)
    ]
    path.write_text(json.dumps({"version": 1, "mirror_responses": mirrors, "patterns": patterns}))
    return path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_empty_db_seeds_patterns_and_mirrors(storage, tmp_path):
    data_path = _write_vendor_json(tmp_path / "v.json", n_patterns=3, n_mirrors=2)
    pats, mirrors = mod.install_vendor_patterns(storage, _data_path=data_path)
    assert pats == 3
    assert mirrors == 2
    active = storage.patterns_active()
    assert len(active) == 3
    assert all(p["origin"] == "vendor" for p in active)


def test_second_call_is_idempotent(storage, tmp_path):
    data_path = _write_vendor_json(tmp_path / "v.json")
    mod.install_vendor_patterns(storage, _data_path=data_path)
    pats2, mirrors2 = mod.install_vendor_patterns(storage, _data_path=data_path)
    assert pats2 == 0 and mirrors2 == 0


def test_force_reinstalls_and_returns_full_counts(storage, tmp_path):
    data_path = _write_vendor_json(tmp_path / "v.json", n_patterns=2, n_mirrors=1)
    mod.install_vendor_patterns(storage, _data_path=data_path)
    pats, mirrors = mod.install_vendor_patterns(storage, force=True, _data_path=data_path)
    assert pats == 2
    assert mirrors == 1


def test_malformed_json_raises_clear_error_storage_untouched(storage, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not {{ valid json }")
    with pytest.raises(mod.BootstrapError, match="invalid JSON"):
        mod.install_vendor_patterns(storage, _data_path=bad)
    assert len(storage.patterns_active()) == 0


def test_disable_pattern_then_list_filters_it_out(storage, tmp_path):
    data_path = _write_vendor_json(tmp_path / "v.json", n_patterns=2, n_mirrors=1)
    mod.install_vendor_patterns(storage, _data_path=data_path)

    # Disable pattern 0 via direct SQL (same logic as cli.py disable-pattern)
    target_id = "vendor_test_0"
    storage._conn.execute(
        "UPDATE patterns SET expires_at = ? WHERE id = ?",
        (time.time() - 1, target_id),
    )

    active = storage.patterns_active()
    active_ids = {p["id"] for p in active}
    assert target_id not in active_ids
    assert "vendor_test_1" in active_ids


def test_real_vendor_json_installs_cleanly(storage):
    """Smoke test: the real vendor_patterns.json ships without errors."""
    pats, mirrors = mod.install_vendor_patterns(storage)
    assert pats > 0
    assert mirrors > 0
    active = storage.patterns_active()
    assert len(active) > 0
    # basic_auth_probe ships with expires_at=1 (disabled by default); active < pats is expected
    assert len(active) <= pats


def test_basic_auth_probe_is_seeded_but_disabled_by_default(storage):
    """basic_auth_probe ships disabled to avoid trapping legitimate Basic Auth users.
    It must be in the DB (so enable-pattern works) but absent from patterns_active()."""
    mod.install_vendor_patterns(storage)
    active_ids = {p["id"] for p in storage.patterns_active()}
    assert "basic_auth_probe" not in active_ids

    row = storage._conn.execute(
        "SELECT expires_at FROM patterns WHERE id = ?", ("basic_auth_probe",)
    ).fetchone()
    assert row is not None, "basic_auth_probe must be seeded into storage"
    assert row["expires_at"] == pytest.approx(1.0)


@pytest.mark.parametrize("force", [False, True])
def test_upgrade_adds_definitions_and_preserves_policy_and_history(storage, tmp_path, force):
    pack = _write_vendor_json(tmp_path / "old.json", n_patterns=2, n_mirrors=1)
    mod.install_vendor_patterns(storage, _data_path=pack)
    storage._conn.execute("UPDATE patterns SET expires_at=1,match_count=83,last_matched=120 "
                          "WHERE id='vendor_test_0'")
    created = storage._conn.execute("SELECT created_at FROM patterns WHERE id='vendor_test_0'").fetchone()[0]
    new_pack = _write_vendor_json(tmp_path / "new.json", n_patterns=3, n_mirrors=2)
    new = json.loads(new_pack.read_text())
    new['patterns'][0]['signature'] = r'^/changed-diagnostic$'
    new['mirror_responses'][0]['body_template'] = 'updated inert response'
    new_pack.write_text(json.dumps(new))
    mod.install_vendor_patterns(storage, force=force, _data_path=new_pack)
    row = storage._conn.execute("SELECT * FROM patterns WHERE id='vendor_test_0'").fetchone()
    assert (row['expires_at'],row['match_count'],row['last_matched'],row['created_at']) == (1,83,120,created)
    assert row['signature'] == r'^/changed-diagnostic$'
    assert {p['id'] for p in storage.patterns_active()} == {'vendor_test_1','vendor_test_2'}
    assert storage.mirror_response_lookup('mirror_0')['body_template'] == 'updated inert response'
    assert mod.install_vendor_patterns(storage, _data_path=new_pack) == (0,0)


@pytest.mark.parametrize("force", [False, True])
def test_refresh_does_not_reenable_all_disabled_rules(storage, tmp_path, force):
    pack = _write_vendor_json(tmp_path / 'pack.json')
    mod.install_vendor_patterns(storage, _data_path=pack)
    storage._conn.execute('UPDATE patterns SET expires_at=1')
    mod.install_vendor_patterns(storage, force=force, _data_path=pack)
    assert storage.patterns_active() == []
    assert storage._conn.execute('SELECT COUNT(*) FROM patterns').fetchone()[0] == 3


def test_refresh_preserves_explicit_enable_of_optional_rule(storage):
    mod.install_vendor_patterns(storage)
    storage._conn.execute("UPDATE patterns SET expires_at=NULL WHERE id='basic_auth_probe'")
    mod.install_vendor_patterns(storage, force=True)
    assert 'basic_auth_probe' in {p['id'] for p in storage.patterns_active()}


def test_purge_retains_disabled_vendor_policy(storage, tmp_path):
    pack = _write_vendor_json(tmp_path / 'pack.json')
    mod.install_vendor_patterns(storage, _data_path=pack)
    storage._conn.execute('UPDATE patterns SET expires_at=1')
    assert storage.patterns_purge_expired(time.time()) == 0
    mod.install_vendor_patterns(storage, _data_path=pack)
    assert storage.patterns_active() == []


@pytest.mark.parametrize('force', [False, True])
def test_refresh_preserves_nonvendor_collision_and_shared_mirror(storage, tmp_path, force):
    pack = _write_vendor_json(tmp_path / 'pack.json')
    mod.install_vendor_patterns(storage, _data_path=pack)
    storage._conn.execute("UPDATE patterns SET origin='operator',signature='^/custom-policy$' "
                          "WHERE id='vendor_test_0'")
    storage._conn.execute("UPDATE mirror_responses SET body_template='operator content' WHERE id='mirror_0'")
    mod.install_vendor_patterns(storage, force=force, _data_path=pack)
    row = storage._conn.execute("SELECT origin,signature FROM patterns WHERE id='vendor_test_0'").fetchone()
    assert tuple(row) == ('operator','^/custom-policy$')
    assert storage.mirror_response_lookup('mirror_0')['body_template'] == 'operator content'


def test_invalid_later_pattern_cannot_partially_install(storage, tmp_path):
    from netward.regex_policy import PatternPolicyError
    pack = _write_vendor_json(tmp_path / 'pack.json')
    data = json.loads(pack.read_text())
    data['patterns'][-1]['signature'] = '(x+)+$'
    pack.write_text(json.dumps(data))
    with pytest.raises(PatternPolicyError):
        mod.install_vendor_patterns(storage, _data_path=pack)
    assert storage._conn.execute('SELECT COUNT(*) FROM patterns').fetchone()[0] == 0
    assert storage._conn.execute('SELECT COUNT(*) FROM mirror_responses').fetchone()[0] == 0


def test_database_failure_rolls_back_entire_refresh(storage, tmp_path):
    import sqlite3
    old = _write_vendor_json(tmp_path / 'old.json', n_patterns=1, n_mirrors=1)
    mod.install_vendor_patterns(storage, _data_path=old)
    storage._conn.execute("CREATE TRIGGER reject_new BEFORE INSERT ON patterns "
                          "WHEN NEW.id='vendor_test_1' BEGIN SELECT RAISE(ABORT,'test fault'); END")
    before = list(storage._conn.iterdump())
    new = _write_vendor_json(tmp_path / 'new.json', n_patterns=2, n_mirrors=2)
    with pytest.raises(sqlite3.IntegrityError):
        mod.install_vendor_patterns(storage, _data_path=new)
    assert list(storage._conn.iterdump()) == before


@pytest.mark.parametrize('fault', ['duplicate','missing_mirror','wrong_origin','missing_field'])
def test_invalid_definition_pack_fails_before_writes(storage, tmp_path, fault):
    pack = _write_vendor_json(tmp_path / 'pack.json')
    data = json.loads(pack.read_text())
    if fault == 'duplicate':
        data['patterns'].append(data['patterns'][0])
    elif fault == 'missing_mirror':
        data['patterns'][0]['mirror_response_id'] = 'absent'
    elif fault == 'wrong_origin':
        data['patterns'][0]['origin'] = 'operator'
    else:
        del data['patterns'][0]['kind']
    pack.write_text(json.dumps(data))
    with pytest.raises(mod.BootstrapError):
        mod.install_vendor_patterns(storage, _data_path=pack)
    assert storage.patterns_active() == []
    assert storage._conn.execute('SELECT COUNT(*) FROM mirror_responses').fetchone()[0] == 0


def test_cli_force_preserves_disable_and_optional_enable(tmp_path):
    from netward.cli import main
    db = tmp_path / 'commands.db'
    def command(*args):
        main(['--db',str(db),*args])
    command('install-patterns')
    command('disable-pattern','env_file_probe')
    command('enable-pattern','runtime_configuration_file_probe')
    command('install-patterns','--force')
    with Storage(db) as store:
        active = {p['id'] for p in store.patterns_active()}
        assert 'env_file_probe' not in active
        assert 'runtime_configuration_file_probe' in active
