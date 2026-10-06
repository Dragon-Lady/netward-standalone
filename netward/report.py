"""
Net Ward — probe report.

Read-only summary of what the local probe log still holds. Stdlib only.
Reports use aggregate counts. They do not include raw IP addresses,
geography, or legitimate-user detail. Suggested patterns are text only
and are never written back to the database.
"""
from __future__ import annotations

import html
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from netward.schema import PROBE_MAX_ROWS, PROBE_RETENTION_SECS

# Incoming Slack webhook `text` is limited to 40,000 characters. Stay
# far under that so a digest is one delivery, not a split or a failure.
SLACK_TEXT_LIMIT = 40_000
DIGEST_CHAR_LIMIT = 3_000

FAMILY_ORDER = (
    "wordpress",
    "secrets",
    "admin",
    "webshells",
    "appliance",
    "ua_scanners",
    "basic_auth",
    "floods",
)

FAMILY_LABELS = {
    "wordpress": "WordPress",
    "secrets": "secrets .env/.git",
    "admin": "admin panels",
    "webshells": "webshells",
    "appliance": "appliance/CVE",
    "ua_scanners": "UA scanners",
    "basic_auth": "basic auth",
    "floods": "floods",
}

_FAMILY_PATTERNS: dict[str, set[str]] = {
    "wordpress": {"wordpress_admin_probe", "wordpress_xmlrpc_probe"},
    "secrets": {"env_file_probe", "git_config_probe", "aws_credentials_probe"},
    "admin": {
        "generic_admin_login_probe",
        "joomla_administrator_probe",
        "phpmyadmin_probe",
    },
    "webshells": {"shell_uploader_probe"},
    "appliance": {
        "brickstorm_pfsense_ipsec_blacklist_probe",
        "verdantbamboo_appliance_implant_probe",
        "appliance_cron_persistence_probe",
        "cisco_sdwan_manager_api_probe",
        "ubiquiti_unifi_os_update_probe",
        "ivanti_sentry_mics_config_probe",
    },
    "ua_scanners": {"scanner_ua_probe"},
    "basic_auth": {"basic_auth_probe"},
    "floods": set(),
}

_SUSPICIOUS_PATH = re.compile(
    r"(?i)(?:\.env|\.git|wp-|xmlrpc|phpmyadmin|\bpma\b|/admin|webshell|"
    r"shell\.php|c99\.php|\.\./|cgi-bin|/actuator|\.aws|eval-stdin|phpunit)"
)

_DURATION = re.compile(r"^(\d+)([smhd])$")


class ReportError(Exception):
    """Operator-facing report failure."""


def parse_time_bound(value: str, *, now: float) -> float:
    """Parse `--since` / `--until`.

    A duration (`7d`, `12h`, `30m`, `90s`) is relative to `now`.
    Anything else is an absolute Unix timestamp or an ISO-8601 instant.
    """
    text = value.strip()
    match = _DURATION.fullmatch(text)
    if match:
        count = int(match.group(1))
        unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
        return now - count * unit
    try:
        return float(text)
    except ValueError:
        pass
    iso = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(iso)
    except ValueError as exc:
        raise ReportError(
            f"could not parse time bound {value!r}; use 7d, 12h, a Unix "
            "timestamp, or an ISO-8601 time"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def family_for(pattern_id: Optional[str], classification: str) -> str:
    if classification == "flood":
        return "floods"
    if pattern_id:
        for name, ids in _FAMILY_PATTERNS.items():
            if pattern_id in ids:
                return name
        return "other"
    return "unmatched"


def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _open_readonly(db_path: str) -> sqlite3.Connection:
    path = Path(db_path)
    if not path.is_file():
        raise ReportError(f"database not found: {db_path}")
    # A running proxy keeps a WAL file. mode=ro reads those frames and
    # does not write the database. When the WAL is already checkpointed
    # away, immutable=1 avoids creating a new sidecar on open.
    wal = Path(str(path) + "-wal")
    query = "mode=ro" if wal.exists() else "mode=ro&immutable=1"
    uri = path.resolve().as_uri() + "?" + query
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise ReportError(f"could not open database read-only: {exc}") from exc
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return row is not None


def _request_bits(raw: str) -> tuple[str, str, str]:
    try:
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    path = str(data.get("path") or "")
    method = str(data.get("method") or "")
    ua = data.get("user_agent")
    if not ua and isinstance(data.get("headers"), dict):
        headers = data["headers"]
        ua = headers.get("User-Agent") or headers.get("user-agent") or ""
    return path, method, str(ua or "")


def _top(counter: dict[str, int], limit: int) -> list[dict[str, Any]]:
    ranked = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    return [{"value": key, "count": count} for key, count in ranked[:limit] if key]


def build_report(
    db_path: str,
    *,
    since: Optional[float] = None,
    until: Optional[float] = None,
    top: int = 5,
    family: Optional[str] = None,
    now: Optional[float] = None,
) -> dict[str, Any]:
    """Build the report dict. Opens the database read-only."""
    top_n = max(1, int(top))
    selected = _normalize_family(family) if family else None
    clock = now if now is not None else datetime.now(timezone.utc).timestamp()
    conn = _open_readonly(db_path)
    try:
        if not _table_exists(conn, "probes"):
            return _empty_report(selected)
        probes = _load_probes(conn, since, until)
        patterns = _load_patterns(conn) if _table_exists(conn, "patterns") else []
        alerts = _load_alerts(conn, since, until) if _table_exists(conn, "alerts") else []
    finally:
        conn.close()
    return _assemble(probes, patterns, alerts, top_n=top_n, family=selected, now=clock)


def render(report: dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report, indent=2, sort_keys=True) + "\n"
    if fmt == "md":
        return _render_md(report)
    if fmt == "html":
        return _render_html(report)
    if fmt == "text":
        return _render_text(report)
    raise ReportError(f"unknown format {fmt!r}")


def write_output(path: str, text: str) -> None:
    """Write a report file readable only by the owner."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            fd = -1
    finally:
        if fd >= 0:
            os.close(fd)


def send_digest(report: dict[str, Any], config_path: str) -> list[str]:
    """Deliver the digest once through the configured alert channels."""
    from netward.operator_layer import deliver_alert, load_config

    config = load_config(config_path)
    body = render(report, "text")
    if len(body) > DIGEST_CHAR_LIMIT:
        body = body[: DIGEST_CHAR_LIMIT - 40].rstrip() + "\n…(truncated for alert delivery)\n"
    alert = {
        "id": "probe-report",
        "severity": "info",
        "kind": "probe_report",
        "title": "Probe report",
        "body": body,
        "triggered_at": datetime.now(timezone.utc).timestamp(),
        "delivered_to": [],
        "count": 1,
        "acknowledged": False,
    }
    formatted_len = len(f"[NETWARD] INFO probe_report: Probe report\n{body}")
    if formatted_len > SLACK_TEXT_LIMIT:
        raise ReportError("probe report digest exceeds the Slack text limit")
    return deliver_alert(alert, config)


def run_report(
    db_path: str,
    *,
    since: Optional[str] = None,
    until: Optional[str] = None,
    fmt: str = "text",
    output: Optional[str] = None,
    top: int = 5,
    family: Optional[str] = None,
    send: bool = False,
    config: Optional[str] = None,
    now: Optional[float] = None,
) -> str:
    clock = now if now is not None else datetime.now(timezone.utc).timestamp()
    since_ts = parse_time_bound(since, now=clock) if since else None
    until_ts = parse_time_bound(until, now=clock) if until else None
    if since_ts is not None and until_ts is not None and since_ts > until_ts:
        raise ReportError("--since is later than --until")
    report = build_report(
        db_path,
        since=since_ts,
        until=until_ts,
        top=top,
        family=family,
        now=clock,
    )
    text = render(report, fmt)
    if output:
        write_output(output, text)
    if send:
        if not config:
            raise ReportError("--send requires --config")
        send_digest(report, config)
    return text


def _normalize_family(value: str) -> str:
    key = value.strip().lower().replace(" ", "_").replace("-", "_")
    aliases = {
        "wordpress": "wordpress",
        "wp": "wordpress",
        "secrets": "secrets",
        "env": "secrets",
        "git": "secrets",
        "admin": "admin",
        "admin_panels": "admin",
        "webshells": "webshells",
        "webshell": "webshells",
        "appliance": "appliance",
        "cve": "appliance",
        "ua": "ua_scanners",
        "ua_scanners": "ua_scanners",
        "scanners": "ua_scanners",
        "basic_auth": "basic_auth",
        "basicauth": "basic_auth",
        "floods": "floods",
        "flood": "floods",
    }
    name = aliases.get(key)
    if not name:
        raise ReportError(
            f"unknown family {value!r}; choose one of: {', '.join(FAMILY_ORDER)}"
        )
    return name


def _empty_report(family: Optional[str]) -> dict[str, Any]:
    return _assemble([], [], [], top_n=5, family=family, now=None)


def _load_probes(
    conn: sqlite3.Connection,
    since: Optional[float],
    until: Optional[float],
) -> list[dict[str, Any]]:
    sql = (
        "SELECT source_id, timestamp, pattern_id, classification, "
        "request_json, upstream_passed FROM probes"
    )
    clauses: list[str] = []
    params: list[float] = []
    if since is not None:
        clauses.append("timestamp >= ?")
        params.append(since)
    if until is not None:
        clauses.append("timestamp < ?")
        params.append(until)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    rows = []
    buckets: dict[str, str] = {}
    for row in conn.execute(sql, params):
        path, method, ua = _request_bits(row["request_json"])
        source_id = row["source_id"] or ""
        if source_id not in buckets:
            buckets[source_id] = f"s{len(buckets) + 1}"
        rows.append(
            {
                "timestamp": float(row["timestamp"]),
                "pattern_id": row["pattern_id"],
                "classification": row["classification"],
                "path": path,
                "method": method,
                "ua": ua,
                "upstream_passed": bool(row["upstream_passed"]),
                "_source_bucket": buckets[source_id],
            }
        )
    return rows


def _load_patterns(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = []
    for row in conn.execute(
        "SELECT id, description, match_count, expires_at FROM patterns"
    ):
        rows.append(
            {
                "id": row["id"],
                "description": row["description"] or "",
                "match_count": int(row["match_count"] or 0),
                "expires_at": row["expires_at"],
            }
        )
    return rows


def _load_alerts(
    conn: sqlite3.Connection,
    since: Optional[float],
    until: Optional[float],
) -> list[dict[str, Any]]:
    sql = "SELECT severity, kind, count, triggered_at FROM alerts"
    clauses: list[str] = []
    params: list[float] = []
    if since is not None:
        clauses.append("triggered_at >= ?")
        params.append(since)
    if until is not None:
        clauses.append("triggered_at < ?")
        params.append(until)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    return [
        {
            "severity": row["severity"],
            "kind": row["kind"],
            "count": int(row["count"] or 1),
        }
        for row in conn.execute(sql, params)
    ]


def _assemble(
    probes: list[dict[str, Any]],
    patterns: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    *,
    top_n: int,
    family: Optional[str],
    now: Optional[float],
) -> dict[str, Any]:
    attack = [row for row in probes if row["classification"] in {"probe", "flood"}]
    clean = [row for row in probes if row["classification"] == "legit"]
    timestamps = [row["timestamp"] for row in probes]
    attack_ts = [row["timestamp"] for row in attack]
    scoped = attack
    if family:
        scoped = [
            row for row in attack
            if family_for(row["pattern_id"], row["classification"]) == family
        ]
    counts: dict[str, int] = {}
    for row in scoped:
        bucket = row["_source_bucket"]
        counts[bucket] = counts.get(bucket, 0) + 1
    ranked = sorted(counts.values(), reverse=True)[:top_n]
    top_sources = [
        {"rank": rank, "events": events}
        for rank, events in enumerate(ranked, start=1)
    ]
    return {
        "verdict": {
            "probed": bool(attack),
            "label": "probed" if attack else "not probed",
            "probe_events": sum(1 for row in attack if row["classification"] == "probe"),
            "flood_events": sum(1 for row in attack if row["classification"] == "flood"),
            "clean_events": len(clean),
            "rows_in_window": len(probes),
            "first_probe": _iso(min(attack_ts) if attack_ts else None),
            "last_probe": _iso(max(attack_ts) if attack_ts else None),
            "data_first": _iso(min(timestamps) if timestamps else None),
            "data_last": _iso(max(timestamps) if timestamps else None),
            "family_filter": family,
            "retention_warning": (
                "The probe log keeps at most "
                f"{int(PROBE_RETENTION_SECS // 86400)} days or "
                f"{PROBE_MAX_ROWS} rows. This report describes only the "
                "rows still stored, not the full history of the site."
            ),
        },
        "families": _family_sections(scoped, top_n, only=family),
        "top_sources": top_sources,
        "weak_spots": _weak_spots(probes, patterns, now),
        "alerts": _alert_summary(alerts),
    }


def _family_sections(
    attack: list[dict[str, Any]],
    top_n: int,
    *,
    only: Optional[str] = None,
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {name: [] for name in FAMILY_ORDER}
    grouped["other"] = []
    for row in attack:
        grouped.setdefault(family_for(row["pattern_id"], row["classification"]), []).append(row)
    sections = []
    names = [only] if only else list(FAMILY_ORDER) + ["other"]
    for name in names:
        rows = grouped.get(name) or []
        if name == "other" and not rows:
            continue
        stamps = [row["timestamp"] for row in rows]
        paths: dict[str, int] = {}
        methods: dict[str, int] = {}
        uas: dict[str, int] = {}
        for row in rows:
            if row["path"]:
                paths[row["path"]] = paths.get(row["path"], 0) + 1
            if row["method"]:
                methods[row["method"]] = methods.get(row["method"], 0) + 1
            if row["ua"]:
                uas[row["ua"]] = uas.get(row["ua"], 0) + 1
        sections.append(
            {
                "id": name,
                "label": FAMILY_LABELS.get(name, name),
                "count": len(rows),
                "first_seen": _iso(min(stamps) if stamps else None),
                "last_seen": _iso(max(stamps) if stamps else None),
                "top_paths": _top(paths, top_n),
                "top_methods": _top(methods, top_n),
                "top_user_agents": _top(uas, top_n),
            }
        )
    return sections


def _weak_spots(
    probes: list[dict[str, Any]],
    patterns: list[dict[str, Any]],
    now: Optional[float],
) -> dict[str, Any]:
    suspicious: dict[str, dict[str, Any]] = {}
    for row in probes:
        if row["pattern_id"] or row["classification"] in {"probe", "flood"}:
            continue
        if not row["upstream_passed"]:
            continue
        if not _SUSPICIOUS_PATH.search(row["path"]):
            continue
        key = row["path"]
        slot = suspicious.setdefault(
            key,
            {"path": row["path"], "method": row["method"], "count": 0},
        )
        slot["count"] += 1
    suggestions = []
    for slot in sorted(suspicious.values(), key=lambda item: (-item["count"], item["path"])):
        suggestion = "path ^" + re.escape(slot["path"]) + "$"
        suggestions.append(
            {
                "path": slot["path"],
                "method": slot["method"],
                "count": slot["count"],
                "suggestion": suggestion,
                "installed": False,
            }
        )
    clock = now if now is not None else datetime.now(timezone.utc).timestamp()
    never_fired = []
    disabled = []
    for pattern in sorted(patterns, key=lambda item: item["id"]):
        expires = pattern["expires_at"]
        is_disabled = expires is not None and float(expires) <= clock
        entry = {"id": pattern["id"], "description": pattern["description"]}
        if is_disabled:
            disabled.append(entry)
        elif pattern["match_count"] == 0:
            never_fired.append(entry)
    return {
        "suspicious_unmatched": suggestions,
        "never_fired": never_fired,
        "disabled": disabled,
        "note": "Suggested patterns are shown only and are not installed.",
    }


def _alert_summary(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    events = 0
    for alert in alerts:
        events += alert["count"]
        by_severity[alert["severity"]] = by_severity.get(alert["severity"], 0) + alert["count"]
        by_kind[alert["kind"]] = by_kind.get(alert["kind"], 0) + alert["count"]
    return {
        "receipts": len(alerts),
        "events": events,
        "by_severity": by_severity,
        "by_kind": by_kind,
    }


def _render_text(report: dict[str, Any]) -> str:
    verdict = report["verdict"]
    lines = [
        "Net Ward probe report",
        f"Verdict: {verdict['label']}",
        f"Probe events: {verdict['probe_events']}",
        f"Flood events: {verdict['flood_events']}",
        f"Clean pass-through events: {verdict['clean_events']}",
        f"Rows in window: {verdict['rows_in_window']}",
        f"First probe: {verdict['first_probe'] or '—'}",
        f"Last probe: {verdict['last_probe'] or '—'}",
        f"Data covers: {verdict['data_first'] or '—'} .. {verdict['data_last'] or '—'}",
        verdict["retention_warning"],
    ]
    if verdict.get("family_filter"):
        lines.append(f"Family filter: {verdict['family_filter']}")
    lines.append("")
    lines.append("Attack surface")
    for section in report["families"]:
        lines.append(
            f"- {section['label']}: {section['count']} "
            f"(first {section['first_seen'] or '—'}, last {section['last_seen'] or '—'})"
        )
        lines.extend(_text_tops("paths", section["top_paths"]))
        lines.extend(_text_tops("methods", section["top_methods"]))
        lines.extend(_text_tops("user agents", section["top_user_agents"]))
    lines.append("")
    lines.append("Top sources (counts only)")
    if not report["top_sources"]:
        lines.append("- none")
    for source in report["top_sources"]:
        lines.append(f"- source #{source['rank']}: {source['events']} events")
    lines.append("")
    lines.append("Weak spots")
    weak = report["weak_spots"]
    if not weak["suspicious_unmatched"]:
        lines.append("- suspicious unmatched: none")
    for item in weak["suspicious_unmatched"]:
        lines.append(
            f"- suspicious unmatched: {item['count']} x {item['method']} {item['path']}"
        )
        lines.append(f"  suggestion (not installed): {item['suggestion']}")
    if not weak["never_fired"]:
        lines.append("- never fired: none")
    for item in weak["never_fired"]:
        lines.append(f"- never fired: {item['id']}")
    if not weak["disabled"]:
        lines.append("- disabled: none")
    for item in weak["disabled"]:
        lines.append(f"- disabled: {item['id']}")
    lines.append(weak["note"])
    lines.append("")
    alerts = report["alerts"]
    lines.append(
        f"Alerts: {alerts['receipts']} receipts, {alerts['events']} events"
    )
    for kind, count in sorted(alerts["by_kind"].items()):
        lines.append(f"- {kind}: {count}")
    lines.append("")
    return "\n".join(lines)


def _text_tops(label: str, items: list[dict[str, Any]]) -> list[str]:
    if not items:
        return []
    rendered = ", ".join(f"{item['value']} ({item['count']})" for item in items)
    return [f"  top {label}: {rendered}"]


def _render_md(report: dict[str, Any]) -> str:
    text = _render_text(report)
    body = "\n".join(f"> {line}" if line else ">" for line in text.splitlines())
    return "# Net Ward probe report\n\n" + body + "\n"


def _render_html(report: dict[str, Any]) -> str:
    verdict = report["verdict"]
    parts = [
        "<!DOCTYPE html>",
        "<html><head><meta charset=\"utf-8\"><title>Net Ward probe report</title></head><body>",
        "<h1>Net Ward probe report</h1>",
        f"<p>Verdict: {html.escape(verdict['label'])}</p>",
        "<ul>",
        f"<li>Probe events: {verdict['probe_events']}</li>",
        f"<li>Flood events: {verdict['flood_events']}</li>",
        f"<li>Clean pass-through events: {verdict['clean_events']}</li>",
        f"<li>First probe: {html.escape(verdict['first_probe'] or '—')}</li>",
        f"<li>Last probe: {html.escape(verdict['last_probe'] or '—')}</li>",
        (
            "<li>Data covers: "
            f"{html.escape(verdict['data_first'] or '—')} .. "
            f"{html.escape(verdict['data_last'] or '—')}</li>"
        ),
        f"<li>{html.escape(verdict['retention_warning'])}</li>",
        "</ul>",
        "<h2>Attack surface</h2>",
    ]
    for section in report["families"]:
        parts.append(f"<h3>{html.escape(section['label'])} ({section['count']})</h3>")
        parts.append("<ul>")
        for label, key in (
            ("paths", "top_paths"),
            ("methods", "top_methods"),
            ("user agents", "top_user_agents"),
        ):
            for item in section[key]:
                parts.append(
                    "<li>"
                    f"{html.escape(label)}: {html.escape(str(item['value']))} "
                    f"({item['count']})</li>"
                )
        parts.append("</ul>")
    parts.append("<h2>Top sources</h2><ul>")
    if not report["top_sources"]:
        parts.append("<li>none</li>")
    for source in report["top_sources"]:
        parts.append(f"<li>source #{source['rank']}: {source['events']} events</li>")
    parts.append("</ul><h2>Weak spots</h2><ul>")
    weak = report["weak_spots"]
    for item in weak["suspicious_unmatched"]:
        parts.append(
            "<li>suspicious unmatched: "
            f"{html.escape(item['method'])} {html.escape(item['path'])} "
            f"({item['count']}) suggestion "
            f"{html.escape(item['suggestion'])}</li>"
        )
    for item in weak["never_fired"]:
        parts.append(f"<li>never fired: {html.escape(item['id'])}</li>")
    for item in weak["disabled"]:
        parts.append(f"<li>disabled: {html.escape(item['id'])}</li>")
    parts.append(f"<li>{html.escape(weak['note'])}</li>")
    alerts = report["alerts"]
    parts.append(
        "</ul><h2>Alerts</h2>"
        f"<p>{alerts['receipts']} receipts, {alerts['events']} events</p>"
    )
    parts.append("</body></html>\n")
    return "\n".join(parts)

