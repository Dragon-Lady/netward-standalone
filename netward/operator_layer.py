"""
Net Ward — Operator Layer

Responsibility: surface what the human running the node needs to know,
when, and how. Config validation, alert delivery, dashboard hooks.

Public contract this module exposes:
    load_config(path: str) -> OperatorConfig
        Read + validate config file. Reject on missing required fields.
        Never auto-write — operator changes are deliberate.

    deliver_alert(alert: OperatorAlert, config: OperatorConfig) -> list[str]
        Fan out the alert to configured channels (stdout, email, Slack,
        ntfy). Returns list of channel names that delivered
        successfully — the rest become retry candidates.

    dedupe_alert(alert: OperatorAlert, recent: list[OperatorAlert]) -> Optional[OperatorAlert]
        Roll up alerts in the same dedup window (per ALERT_DEDUP_WINDOW_SECS).
        Returns merged alert OR None if suppressed.

Configured channels receive the first alert for each kind/source/pattern
deduplication window. Severity is included in each message; the operator
chooses channels in the config.

Dashboard requirements (separate module / future build, but contract here):
- Live counters from NodeStatus
- Last 24h probe timeline
- Top 10 Sources by probe_count
- Top 10 Patterns by match_count
- Mesh peer health
- Recent OperatorAlerts (last 7 days)
- Trust manifest viewer + audit log of changes

Buyer-distributable note:
Operator tools must work for the small-shop case (one Linux box, no
managed cloud). The supported channels are stdout, email, Slack, and ntfy.
"""
from __future__ import annotations

import json
import os
import smtplib
import ssl
import stat
import sys
from email.message import EmailMessage
from pathlib import Path
from typing import Optional
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .schema import (
    ALERT_DEDUP_WINDOW_SECS,
    OperatorAlert,
    OperatorConfig,
)


_REQUIRED_CONFIG_FIELDS = frozenset({"node_id", "upstream_target", "listen_address"})
_SUPPORTED_ALERT_CHANNELS = frozenset({"stdout", "email", "slack", "ntfy"})
_POSITIVE_NUMBER_FIELDS = frozenset({
    "upstream_timeout_total",
    "upstream_timeout_connect",
    "upstream_timeout_sock_read",
    "upstream_max_concurrency",
    "upstream_max_body_bytes",
    "probe_retention_secs",
    "probe_max_rows",
    "alert_smtp_port",
    "alert_timeout_secs",
})
_POSITIVE_INTEGER_FIELDS = frozenset({
    "upstream_max_concurrency",
    "upstream_max_body_bytes",
    "probe_max_rows",
    "alert_smtp_port",
})


class ValidationError(ValueError):
    """Raised when an operator-editable config file is invalid."""


def load_config(path: str) -> OperatorConfig:
    """Read and validate an operator config file.

    The standalone build intentionally supports JSON only so the package stays
    stdlib-only. YAML gets a precise deferred error instead of a surprise
    dependency.
    """
    config_path = Path(path)
    if config_path.suffix.lower() in {".yaml", ".yml"}:
        raise NotImplementedError("YAML config loading deferred to a later release; use JSON")
    if config_path.suffix.lower() != ".json":
        raise ValidationError("config file must be JSON for the standalone release")

    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON config: {exc.msg}") from exc

    if not isinstance(raw, dict):
        raise ValidationError("config root must be an object")

    _validate_required_fields(raw)
    _validate_alert_channels(raw)
    validate_alert_config(raw)
    _validate_optional_bounds(raw)
    raw["alert_channels"] = _normalized_alert_channels(raw)
    return raw


def validate_storage_permissions(
    config: OperatorConfig,
    *,
    allow_permissive_db: bool = False,
    platform_name: Optional[str] = None,
) -> None:
    """Validate storage_path permissions before the listener binds.

    POSIX builds refuse to start on world-writable DB paths unless the operator
    explicitly overrides the check. Windows emits an informational skip because
    POSIX mode bits are not a reliable permission signal there.
    """
    platform_name = (platform_name or sys.platform).lower()
    if platform_name.startswith("win"):
        print(
            "INFO: storage permission check skipped on Windows; avoid shared-write "
            "locations for the Net Ward database.",
            file=sys.stderr,
        )
        return

    target = _storage_permission_target(config.get("storage_path"))
    if not _is_world_writable(target):
        return

    message = (
        "ERROR: storage path permissions are too permissive: "
        f"{target} is world-writable. Fix the path or start with "
        "--allow-permissive-db."
    )
    if allow_permissive_db:
        print(f"{message} Proceeding because --allow-permissive-db was set.", file=sys.stderr)
        return
    raise ValidationError(message)


def deliver_alert(
    alert: OperatorAlert, config: OperatorConfig, channels: Optional[list[str]] = None
) -> list[str]:
    """Attempt each selected channel independently; return successful receipts."""
    selected = channels if channels is not None else (_normalized_alert_channels(config) or ["stdout"])
    delivered: list[str] = []
    for channel in selected:
        try:
            if channel == "stdout":
                print(_format_alert(alert), file=sys.stdout, flush=True)
            elif channel == "email":
                _send_email(alert, config)
            elif channel == "slack":
                _send_slack(alert, config)
            elif channel == "ntfy":
                _send_ntfy(alert, config)
            else:
                raise ValueError("unsupported alert channel")
        except Exception as exc:
            # Never print a webhook URL, credentials, or message body in failures.
            print(f"Net Ward alert {alert['id']} delivery to {channel} failed: "
                  f"{type(exc).__name__}", file=sys.stderr)
        else:
            delivered.append(channel)
    return delivered


def validate_alert_config(config: OperatorConfig) -> None:
    """Refuse to start when a requested destination cannot be used."""
    _validate_alert_channels(config)
    channels = _normalized_alert_channels(config)
    if len(channels) != len(set(channels)):
        raise ValidationError("alert_channels must not contain duplicates")
    if "email" in channels:
        for field in ("alert_email", "alert_smtp_host", "alert_smtp_from"):
            if not config.get(field):
                raise ValidationError(f"email alerts require {field}")
        security = config.get("alert_smtp_security", "starttls")
        if security not in {"starttls", "ssl", "none"}:
            raise ValidationError("alert_smtp_security must be starttls, ssl, or none")
        if security == "none" and config["alert_smtp_host"] not in {"localhost", "127.0.0.1", "::1"}:
            raise ValidationError("unencrypted SMTP is allowed only on loopback")
        if config.get("alert_smtp_username") and not config.get("alert_smtp_password_env"):
            raise ValidationError("SMTP username requires alert_smtp_password_env")
        if config.get("alert_smtp_password_env") and not os.getenv(config["alert_smtp_password_env"]):
            raise ValidationError("SMTP password environment variable is missing")
    if "slack" in channels:
        _validate_http_destination(config.get("alert_slack_webhook"), "alert_slack_webhook")
    if "ntfy" in channels:
        if not config.get("alert_ntfy_topic"):
            raise ValidationError("ntfy alerts require alert_ntfy_topic")
        if "://" in config["alert_ntfy_topic"]:
            _validate_http_destination(config["alert_ntfy_topic"], "alert_ntfy_topic")
        if config.get("alert_ntfy_token_env") and not os.getenv(config["alert_ntfy_token_env"]):
            raise ValidationError("ntfy token environment variable is missing")


def _validate_http_destination(value: Optional[str], field: str) -> None:
    parsed = urlparse(value or "")
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValidationError(f"{field} must be an HTTPS URL")
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        return
    raise ValidationError(f"{field} must use HTTPS (HTTP allowed on loopback)")


def _post(url: str, body: bytes, headers: dict[str, str], timeout: float) -> None:
    request = Request(url, data=body, headers=headers, method="POST")
    # A redirect can leak webhook credentials or downgrade HTTPS.
    opener = build_opener(_NoRedirect)
    with opener.open(request, timeout=timeout) as response:
        response.read(1024)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _send_slack(alert: OperatorAlert, config: OperatorConfig) -> None:
    payload = json.dumps({"text": _format_alert(alert)}).encode("utf-8")
    _post(config["alert_slack_webhook"], payload,
          {"Content-Type": "application/json"}, float(config.get("alert_timeout_secs", 5)))


def _send_ntfy(alert: OperatorAlert, config: OperatorConfig) -> None:
    topic = config["alert_ntfy_topic"]
    url = topic if "://" in topic else f"https://ntfy.sh/{quote(topic, safe='')}"
    headers = {"Content-Type": "text/plain; charset=utf-8",
               "Title": str(alert.get("title", "Net Ward alert")),
               "Priority": "5" if alert.get("severity") == "critical" else "3"}
    token_env = config.get("alert_ntfy_token_env")
    if token_env:
        headers["Authorization"] = f"Bearer {os.environ[token_env]}"
    _post(url, _format_alert(alert).encode("utf-8"), headers,
          float(config.get("alert_timeout_secs", 5)))


def _send_email(alert: OperatorAlert, config: OperatorConfig) -> None:
    message = EmailMessage()
    message["From"] = config["alert_smtp_from"]
    message["To"] = config["alert_email"]
    message["Subject"] = f"[Net Ward] {str(alert.get('severity', 'info')).upper()}: {alert.get('title', 'Alert')}"
    message.set_content(_format_alert(alert))
    security = config.get("alert_smtp_security", "starttls")
    port = int(config.get("alert_smtp_port", 465 if security == "ssl" else 587))
    timeout = float(config.get("alert_timeout_secs", 5))
    smtp_class = smtplib.SMTP_SSL if security == "ssl" else smtplib.SMTP
    with smtp_class(config["alert_smtp_host"], port, timeout=timeout) as smtp:
        if security == "starttls":
            smtp.starttls(context=ssl.create_default_context())
        if config.get("alert_smtp_username"):
            smtp.login(config["alert_smtp_username"], os.environ[config["alert_smtp_password_env"]])
        smtp.send_message(message)


def dedupe_alert(
    alert: OperatorAlert,
    recent: list[OperatorAlert],
) -> Optional[OperatorAlert]:
    """Roll up same-kind/source alerts inside the dedup window.

    Returns the merged alert when a recent match exists, otherwise returns
    the new alert for normal delivery.
    """
    alert_time = float(alert.get("triggered_at", 0))
    for candidate in recent:
        same_kind = candidate.get("kind") == alert.get("kind")
        same_source = candidate.get("source_id") == alert.get("source_id")
        same_pattern = candidate.get("pattern_id") == alert.get("pattern_id")
        candidate_time = float(candidate.get("triggered_at", 0))
        within_window = 0 <= alert_time - candidate_time <= ALERT_DEDUP_WINDOW_SECS
        if same_kind and same_source and same_pattern and within_window:
            merged = dict(candidate)
            merged["triggered_at"] = max(alert_time, candidate_time)
            merged["count"] = int(candidate.get("count", 1)) + 1
            merged["body"] = alert.get("body", candidate.get("body", ""))
            return merged
    return alert


def _validate_required_fields(config: dict) -> None:
    missing = sorted(
        field
        for field in _REQUIRED_CONFIG_FIELDS
        if not str(config.get(field, "")).strip()
    )
    if missing:
        raise ValidationError(f"missing required config fields: {', '.join(missing)}")


def _validate_alert_channels(config: dict) -> None:
    channels = _normalized_alert_channels(config)
    if any(not isinstance(channel, str) for channel in channels):
        raise ValidationError("alert_channels entries must be strings")
    unknown = sorted(set(channels) - _SUPPORTED_ALERT_CHANNELS)
    if unknown:
        raise ValidationError(f"unknown alert channels: {', '.join(unknown)}")


def _validate_optional_bounds(config: dict) -> None:
    for field in _POSITIVE_NUMBER_FIELDS:
        if field not in config or config[field] is None:
            continue
        value = config[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValidationError(f"{field} must be a positive number")
        if value <= 0:
            raise ValidationError(f"{field} must be a positive number")
        if field in _POSITIVE_INTEGER_FIELDS and int(value) != value:
            raise ValidationError(f"{field} must be a positive integer")


def _normalized_alert_channels(config: dict) -> list[str]:
    channels = config.get("alert_channels")
    if channels is None:
        return []
    if not isinstance(channels, list):
        raise ValidationError("alert_channels must be a list")
    return channels


def _storage_permission_target(storage_path: Optional[str]) -> Path:
    path = Path(storage_path or "netward.db")
    if path.exists():
        return path
    return path.parent if str(path.parent) else Path(".")


def _is_world_writable(path: Path) -> bool:
    return bool(path.stat().st_mode & stat.S_IWOTH)


def _format_alert(alert: OperatorAlert) -> str:
    severity = str(alert.get("severity", "info")).upper()
    kind = alert.get("kind", "alert")
    title = alert.get("title", "Net Ward alert")
    body = alert.get("body", "")
    return f"[NETWARD] {severity} {kind}: {title}\n{body}"
