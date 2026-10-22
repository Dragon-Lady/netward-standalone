"""
Buyer hygiene gate for Net Ward source.

Net Ward ships under Apache 2.0 to paying operators. Every line in the
package must be OK to read on day one. This test scans production source
and operator-facing files for content that has no business in a
buyer-distributable artifact: personal paths, internal team narrative
references, cross-product leakage, debug residue.

Production source: every .py file in netward/ that is not a test_*.py
Operator-facing: README.md, NOTICE, LICENSE, example_config.json
Allowed exceptions: data/vendor_patterns.json (deception content; the
"AKIA" prefix in the AWS fake mirror is intentional bait, not a leak).

Private and crew terms are never stored in this repository. Load them at
test time from PUSH_GUARD_BLOCKED_TERMS or a gitignored local file.
When neither source is present, those checks skip cleanly.

This module lives outside the installable package so it is not included
in the wheel or sdist.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_THIS_MODULE = sys.modules[__name__]


NETWARD_DIR = Path(__file__).resolve().parent.parent / "netward"
PROJECT_ROOT = NETWARD_DIR.parent
LOCAL_TERMS_FILE = PROJECT_ROOT / ".push-guard-blocked-terms"

# All .py files under netward/ except __pycache__
_ALL_PY = [p for p in NETWARD_DIR.rglob("*.py") if "__pycache__" not in p.parts]
PRODUCTION_PY = [p for p in _ALL_PY if not p.name.startswith("test_")]
TEST_PY = [p for p in _ALL_PY if p.name.startswith("test_")]


def _parse_terms(raw: str) -> list[str]:
    terms: list[str] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        terms.append(item)
    return terms


def _load_blocked_terms() -> list[str] | None:
    env = os.environ.get("PUSH_GUARD_BLOCKED_TERMS", "")
    parsed = _parse_terms(env)
    if parsed:
        return parsed
    if LOCAL_TERMS_FILE.is_file():
        text = LOCAL_TERMS_FILE.read_text(encoding="utf-8", errors="replace")
        parsed = _parse_terms(text)
        if parsed:
            return parsed
    return None


def _blocked_terms_or_skip() -> list[str]:
    terms = _load_blocked_terms()
    if not terms:
        pytest.skip(
            "blocked-term list not configured; set PUSH_GUARD_BLOCKED_TERMS "
            "or provide the gitignored local terms file"
        )
    return terms


# -----------------------------------------------------------------------------
# Denylists — substring matches (case-insensitive where noted)
# -----------------------------------------------------------------------------

# Paths that pin to a developer's local machine
PERSONAL_PATH_FRAGMENTS = (
    r"c:\users\local-user",
    r"\users\local-user",
    r"/users/local-user",
    r"/home/local-user",
)

# Specific external identifiers that must never leak into Net Ward source.
SEPARATE_PRODUCT_IDS = (
    "000001",
    "249249",
    "F11AA3",
    "053977",
    "B6DB6D",
)

# Generic placeholders that must not appear as narrative residue.
GENERIC_TEAM_PLACEHOLDERS = (
    "LocalUser",
)


def _read_lower(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace").lower()


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _find_blocked_terms(text: str, terms: list[str]) -> list[str]:
    lowered = text.lower()
    return [term for term in terms if term.lower() in lowered]


# -----------------------------------------------------------------------------
# Loader
# -----------------------------------------------------------------------------

def test_blocked_terms_absent_returns_none(monkeypatch, tmp_path):
    monkeypatch.delenv("PUSH_GUARD_BLOCKED_TERMS", raising=False)
    monkeypatch.setattr(_THIS_MODULE, "LOCAL_TERMS_FILE", tmp_path / "missing-terms")
    assert _load_blocked_terms() is None


def test_blocked_terms_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "PUSH_GUARD_BLOCKED_TERMS",
        "# comment\nexample-blocked-term\nexample-blocked-term\nother-example-term\n",
    )
    monkeypatch.setattr(_THIS_MODULE, "LOCAL_TERMS_FILE", tmp_path / "unused-terms")
    assert _load_blocked_terms() == ["example-blocked-term", "other-example-term"]


def test_blocked_terms_from_local_file(monkeypatch, tmp_path):
    terms_file = tmp_path / ".push-guard-blocked-terms"
    terms_file.write_text("# comment\nfile-example-term\n", encoding="utf-8")
    monkeypatch.delenv("PUSH_GUARD_BLOCKED_TERMS", raising=False)
    monkeypatch.setattr(_THIS_MODULE, "LOCAL_TERMS_FILE", terms_file)
    assert _load_blocked_terms() == ["file-example-term"]


def test_blocked_term_scan_detects_injected_marker(tmp_path, monkeypatch):
    marker = "nw-hygiene-canary-term"
    target = tmp_path / "sample.py"
    target.write_text(f"value = '{marker}'\n", encoding="utf-8")
    monkeypatch.setenv("PUSH_GUARD_BLOCKED_TERMS", marker)
    monkeypatch.setattr(_THIS_MODULE, "LOCAL_TERMS_FILE", tmp_path / "unused-terms")
    found = _find_blocked_terms(_read(target), _load_blocked_terms() or [])
    assert found == [marker]


# -----------------------------------------------------------------------------
# Production source checks
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("py_file", PRODUCTION_PY, ids=lambda p: p.name)
def test_no_personal_paths_in_production(py_file):
    text = _read_lower(py_file)
    found = [frag for frag in PERSONAL_PATH_FRAGMENTS if frag in text]
    assert not found, (
        f"{py_file.name} contains personal path fragments: {found}. "
        "Buyers see this; remove or replace with relative/configurable paths."
    )


@pytest.mark.parametrize("py_file", PRODUCTION_PY, ids=lambda p: p.name)
def test_no_blocked_terms_in_production(py_file):
    terms = _blocked_terms_or_skip()
    found = _find_blocked_terms(_read(py_file), terms)
    assert not found, (
        f"{py_file.name} contains blocked terms that must not ship. "
        "Remove the matching private or cross-product wording."
    )


@pytest.mark.parametrize("py_file", PRODUCTION_PY, ids=lambda p: p.name)
def test_no_separate_product_ids_in_production(py_file):
    text = _read(py_file)
    found = [h for h in SEPARATE_PRODUCT_IDS if h in text]
    assert not found, (
        f"{py_file.name} contains identifiers that belong to a different "
        f"product: {found}."
    )


@pytest.mark.parametrize("py_file", PRODUCTION_PY, ids=lambda p: p.name)
def test_no_team_placeholders_in_production(py_file):
    """Apache 2.0 attribution lives in NOTICE. Production code comments
    should not name individual contributors — that's narrative residue."""
    text = _read(py_file)
    found = [name for name in GENERIC_TEAM_PLACEHOLDERS if name in text]
    assert not found, (
        f"{py_file.name} contains team placeholders: {found}. "
        "Move attribution to NOTICE or remove."
    )


_PRINT_OK_FILES = frozenset({
    "operator_layer.py",  # standalone alert delivery to stdout (documented)
    "cli.py",             # CLI tool: stdout is the user interface contract
    "__main__.py",        # entrypoint: print() before logger is configured for fatal errors
})


@pytest.mark.parametrize("py_file", PRODUCTION_PY, ids=lambda p: p.name)
def test_no_top_level_print_statements(py_file):
    """Production library code uses logging or return values; print() is
    debug residue. CLI / entrypoint / alert-delivery files where stdout
    IS the user interface are explicitly exempted."""
    if py_file.name in _PRINT_OK_FILES:
        return
    lines = _read(py_file).splitlines()
    offenders = []
    for i, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        if stripped.startswith("print(") and not stripped.startswith("print()"):
            offenders.append(f"line {i}: {stripped[:60]}")
    assert not offenders, (
        f"{py_file.name} has print() calls in production code:\n  "
        + "\n  ".join(offenders)
    )


# -----------------------------------------------------------------------------
# Top-level package files (LICENSE / NOTICE presence)
# -----------------------------------------------------------------------------

def test_license_file_exists():
    assert (PROJECT_ROOT / "LICENSE").exists(), (
        "Apache 2.0 LICENSE file missing from project root"
    )


def test_notice_file_exists():
    assert (PROJECT_ROOT / "NOTICE").exists(), (
        "NOTICE file missing — Apache 2.0 attribution lives here"
    )


def test_license_is_apache_2_0():
    text = _read(PROJECT_ROOT / "LICENSE")
    assert "Apache License" in text
    assert "Version 2.0" in text


# -----------------------------------------------------------------------------
# Test files under netward/ — also scanned when present in the checkout.
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("py_file", TEST_PY, ids=lambda p: p.name)
def test_no_personal_paths_in_tests(py_file):
    text = _read_lower(py_file)
    found = [frag for frag in PERSONAL_PATH_FRAGMENTS if frag in text]
    assert not found, f"{py_file.name} contains personal path: {found}"


@pytest.mark.parametrize("py_file", TEST_PY, ids=lambda p: p.name)
def test_no_blocked_terms_in_tests(py_file):
    terms = _blocked_terms_or_skip()
    found = _find_blocked_terms(_read(py_file), terms)
    assert not found, f"{py_file.name} contains blocked terms that must not ship."


@pytest.mark.parametrize("py_file", TEST_PY, ids=lambda p: p.name)
def test_no_separate_product_ids_in_tests(py_file):
    text = _read(py_file)
    found = [h for h in SEPARATE_PRODUCT_IDS if h in text]
    assert not found, f"{py_file.name} contains separate-product ids: {found}"


@pytest.mark.parametrize("py_file", TEST_PY, ids=lambda p: p.name)
def test_no_team_placeholders_in_tests(py_file):
    text = _read(py_file)
    found = [name for name in GENERIC_TEAM_PLACEHOLDERS if name in text]
    assert not found, (
        f"{py_file.name} contains team placeholders: {found}. "
        "Test docstrings ship under source distribution; scrub narrative."
    )


def test_no_blocked_terms_in_hygiene_module():
    terms = _blocked_terms_or_skip()
    found = _find_blocked_terms(_read(Path(__file__)), terms)
    assert not found, (
        "hygiene test contains blocked terms; keep the live list out of source"
    )


# -----------------------------------------------------------------------------
# Operator-facing artifacts (README, example_config, NOTICE) — these reach
# buyers directly and must not contain the same leaks production source can't.
# -----------------------------------------------------------------------------

OPERATOR_FACING = [
    p for p in [
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "example_config.json",
        PROJECT_ROOT / "CHANGELOG.md",
        PROJECT_ROOT / "SECURITY.md",
    ]
    if p.exists()
]


@pytest.mark.parametrize("doc", OPERATOR_FACING, ids=lambda p: p.name)
def test_operator_docs_no_personal_paths(doc):
    text = _read_lower(doc)
    found = [frag for frag in PERSONAL_PATH_FRAGMENTS if frag in text]
    assert not found, f"{doc.name} contains personal path: {found}"


@pytest.mark.parametrize("doc", OPERATOR_FACING, ids=lambda p: p.name)
def test_operator_docs_no_blocked_terms(doc):
    terms = _blocked_terms_or_skip()
    found = _find_blocked_terms(_read(doc), terms)
    assert not found, (
        f"{doc.name} contains blocked terms that must not ship. "
        "Net Ward ships standalone."
    )


@pytest.mark.parametrize("doc", OPERATOR_FACING, ids=lambda p: p.name)
def test_operator_docs_no_separate_product_ids(doc):
    text = _read(doc)
    found = [h for h in SEPARATE_PRODUCT_IDS if h in text]
    assert not found, f"{doc.name} contains separate-product ids: {found}"


@pytest.mark.parametrize("doc", OPERATOR_FACING, ids=lambda p: p.name)
def test_operator_docs_no_team_placeholders(doc):
    text = _read(doc)
    found = [name for name in GENERIC_TEAM_PLACEHOLDERS if name in text]
    assert not found, (
        f"{doc.name} contains team placeholders: {found}. "
        "Move attribution to NOTICE if needed."
    )
