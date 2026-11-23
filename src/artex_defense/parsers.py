"""Offline multi-surface log parsers for major edge appliances, proxies, web portals, and endpoints.

Supported formats (all strictly offline, zero network calls):
- Cisco ASA & Cisco FTD syslog (%ASA- / %FTD-)
- Citrix NetScaler ADC / Gateway syslog & HTTP logs
- Palo Alto PAN-OS CSV / syslog (TRAFFIC, THREAT, GLOBALPROTECT)
- F5 BIG-IP APM / LTM / ASM syslog & HTTP logs
- Zscaler ZIA / ZPA NSS JSONL & CSV logs
- Nginx / Apache Combined & JSON web access logs
- CERT NetSA YAF / super_mediator bidirectional IPFIX-JSON (RFC 5103: octetTotalCount, reverseOctetTotalCount, ja4, sslServerName, silkAppLabel)
- Identity Providers (IdP / 2FA): Okta System Log, Microsoft Entra ID, Duo Security, PingFederate, and Google Workspace Reports API JSON
- Normalized / Sysmon / EDR / CloudTrail JSONL
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Cisco ASA & FTD syslog: supports both ISO-8601 and RFC 3164 ("Nov 21 10:00:00") timestamps
SYSLOG_TS_PAT = r"(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\S+)"
ASA_FTD_RE = re.compile(
    rf"^(?P<ts>{SYSLOG_TS_PAT})\s+(?P<host>\S+)\s+%(?P<prod>ASA|FTD)-(?P<sev>\d)-(?P<msgid>\d+):\s*(?P<msg>.*)$"
)
ASA_USER_RE = re.compile(r"(?:user|Username)\s*[=:]\s*['\"]?(?P<user>[^\s:,;'\"]+)", re.IGNORECASE)
ASA_IP_RE = re.compile(
    r"(?:user IP|IP|src(?:_ip)?|from)\s*[=:]?\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3})", re.IGNORECASE
)
ASA_URI_RE = re.compile(r"(?P<uri>/(?:\+CSCOE\+|\+webvpn\+|CSCOE|admin|api)[^\s\"']*)", re.IGNORECASE)

# Citrix NetScaler ADC / Gateway syslog
CITRIX_RE = re.compile(
    rf"^(?P<ts>{SYSLOG_TS_PAT})\s+(?P<host>\S+)\s+.*?(?:PPE-\d|SSLVPN|AAATM|NS\S*)\s*:\s*(?P<msg>.*)$",
    re.IGNORECASE,
)
CITRIX_USER_RE = re.compile(r"User\s+(?P<user>[^\s-]+)", re.IGNORECASE)
CITRIX_IP_RE = re.compile(r"(?:Client_ip|Source|src)\s*[=:]?\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3})", re.IGNORECASE)
CITRIX_URI_RE = re.compile(r"(?P<uri>/(?:vpn|nf|logon|p/u|cgi|nitro)[^\s\"']*)", re.IGNORECASE)

# F5 BIG-IP APM / LTM / ASM syslog
F5_RE = re.compile(
    rf"^(?P<ts>{SYSLOG_TS_PAT})\s+(?P<host>\S+)\s+(?:err|warning|notice|info)?\s*(?P<daemon>apmd|tmm|httpd|restjavad|asm)\[\d+\]:\s*(?P<msg>.*)$",
    re.IGNORECASE,
)
F5_URI_RE = re.compile(r"(?P<uri>/(?:my\.policy|tmui|mgmt/tm|renderer|sam|api)[^\s\"']*)", re.IGNORECASE)
F5_USER_RE = re.compile(r"(?:user|username)\s*[=:'\"]+\s*(?P<user>[^\s,'\";]+)", re.IGNORECASE)

# Nginx / Apache Combined access log
NGINX_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[^"]+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

IPV4_ANY_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        num = float(value)
        # Support IPFIX flowStartMicroseconds (>=1e14) and flowStartMilliseconds (>=1e11)
        if num >= 1e14:
            num /= 1_000_000.0
        elif num >= 1e11:
            num /= 1_000.0
        return datetime.fromtimestamp(num, tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        # Try ISO-8601 first
        try:
            dt = datetime.fromisoformat(text)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        # Nginx/Apache CLF & YAF super_mediator timestamps
        for fmt in (
            "%d/%b/%Y:%H:%M:%S %z",
            "%Y/%m/%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(text, fmt)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        # RFC 3164 syslog ("Nov 21 10:00:00") — prepend current UTC year to avoid Python 3.15 leap-day warning
        try:
            cur_year = datetime.now(timezone.utc).year
            dt = datetime.strptime(f"{cur_year} {text}", "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    raise ValueError(f"Unsupported timestamp value: {value!r}")


def _extract_first(record: dict[str, Any], keys: tuple[str, ...], default: Any = None) -> Any:
    for k in keys:
        if k in record and record[k] is not None and record[k] != "":
            return record[k]
    return default


def _infer_surface(
    event_type: str,
    appliance: str | None,
    http_path: str,
    action: str,
    process: str,
) -> str:
    if appliance in {"cisco_asa_ftd", "citrix_netscaler", "panos", "f5_bigip"}:
        return "edge_appliance"
    if appliance == "zscaler":
        return "web_portal" if http_path else "network"
    et = event_type.lower()
    if et in {"vpn", "edge_auth", "edge_appliance", "firewall"}:
        return "edge_appliance"
    if et in {"cloud_iam", "entra_id", "cloudtrail", "iam"} or et.endswith(".amazonaws.com") or "serviceprincipal" in action.lower():
        return "cloud_iam"
    if et in {"process", "sysmon", "edr", "endpoint", "file"} or process:
        return "endpoint"
    if et in {"http", "web", "proxy", "waf"} or http_path:
        return "web_portal"
    if et in {"network", "dns", "zeek", "tls", "flow"}:
        return "network"
    return "unknown"


def _make_event(
    *,
    ts: datetime,
    source_host: str,
    actor: str,
    event_type: str,
    surface: str,
    appliance: str | None = None,
    process: str = "",
    parent_process: str = "",
    command_line: str = "",
    dest_host: str = "",
    dest_port: int | None = None,
    http_method: str = "",
    http_path: str = "",
    user_agent: str = "",
    ja4: str = "",
    ja4h: str = "",
    bytes_out: int | None = None,
    bytes_in: int | None = None,
    status_code: int | None = None,
    action: str = "",
    raw: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "ts_epoch": ts.timestamp(),
        "timestamp": ts.isoformat(),
        "source_host": source_host or "unknown",
        "actor": actor or source_host or "unknown",
        "event_type": event_type,
        "surface": surface,
        "appliance": appliance or "",
        "process": process,
        "parent_process": parent_process,
        "command_line": command_line,
        "dest_host": dest_host,
        "dest_port": dest_port,
        "http_method": http_method,
        "http_path": http_path,
        "user_agent": user_agent,
        "ja4": ja4,
        "ja4h": ja4h,
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
        "status_code": status_code,
        "action": action,
        "raw_json": json.dumps(raw or {}, ensure_ascii=False),
    }


def _flatten_ipfix_record(record: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Flatten CERT NetSA YAF / super_mediator JSON records (nested `flows`/`tls`/`http`/`dns` or flat IPFIX)."""
    merged = dict(record)
    if isinstance(record.get("flows"), dict):
        merged.update(record["flows"])
    for subkey in ("tls", "ssl", "http", "dns"):
        sub = merged.get(subkey)
        if isinstance(sub, dict):
            for k, v in sub.items():
                if k not in merged or merged[k] in (None, ""):
                    merged[k] = v
        elif isinstance(sub, list) and sub and isinstance(sub[0], dict):
            for k, v in sub[0].items():
                if k not in merged or merged[k] in (None, ""):
                    merged[k] = v

    is_ipfix = any(
        k in merged
        for k in (
            "flowStartMicroseconds",
            "flowStartMilliseconds",
            "flowStartSeconds",
            "octetTotalCount",
            "reverseOctetTotalCount",
            "silkAppLabel",
            "sourceIPv4Address",
            "sourceIPv6Address",
            "sslServerName",
        )
    )
    return merged, is_ipfix


def _normalize_okta_record(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize native Okta System Log JSON events (SSO, /api/v1/authn, MFA push/OTP, factor tampering)."""
    ts = parse_timestamp(record["published"])
    client = record.get("client") or {}
    actor_obj = record.get("actor") or {}
    outcome = record.get("outcome") or {}
    debug_data = (record.get("debugContext") or {}).get("debugData") or {}
    targets = record.get("target") or []
    first_target = targets[0] if isinstance(targets, list) and targets and isinstance(targets[0], dict) else {}

    src_ip = str(client.get("ipAddress") or client.get("device") or "okta")
    actor_id = str(
        actor_obj.get("alternateId")
        or actor_obj.get("displayName")
        or first_target.get("alternateId")
        or src_ip
    )
    dest_host = str(first_target.get("displayName") or first_target.get("alternateId") or "okta.system.log")
    ua = str((client.get("userAgent") or {}).get("rawUserAgent") or "")
    req_uri = str(debug_data.get("requestUri") or "")
    event_type = str(record.get("eventType") or "okta.event")
    result = str(outcome.get("result") or "").upper()
    reason = str(outcome.get("reason") or "")

    status_code = 401 if result in {"FAILURE", "DENY", "ABANDONED"} else 200
    action = f"{event_type}:{reason}" if reason else f"{event_type}:{result or 'EVENT'}"

    return _make_event(
        ts=ts,
        source_host=src_ip,
        actor=actor_id,
        event_type="idp_auth",
        surface="cloud_iam",
        appliance="okta",
        dest_host=dest_host,
        dest_port=443,
        http_method="POST" if req_uri else "",
        http_path=req_uri,
        user_agent=ua,
        status_code=status_code,
        action=action,
        raw=record,
    )


def _normalize_entra_record(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize native Microsoft Entra ID SigninLogs, AADServicePrincipalSignInLogs, and AuditLogs JSON."""
    ts_raw = _extract_first(record, ("createdDateTime", "activityDateTime", "time", "timestamp"))
    ts = parse_timestamp(ts_raw)
    status_obj = record.get("status") if isinstance(record.get("status"), dict) else {}
    initiated_by = record.get("initiatedBy") if isinstance(record.get("initiatedBy"), dict) else {}
    init_user = initiated_by.get("user") if isinstance(initiated_by.get("user"), dict) else {}
    init_app = initiated_by.get("app") if isinstance(initiated_by.get("app"), dict) else {}

    src_ip = str(record.get("ipAddress") or init_user.get("ipAddress") or "entra-id")
    actor = str(
        record.get("servicePrincipalName")
        or record.get("userPrincipalName")
        or init_app.get("displayName")
        or init_user.get("userPrincipalName")
        or record.get("appDisplayName")
        or src_ip
    )
    dest_host = str(
        record.get("resourceDisplayName")
        or record.get("appDisplayName")
        or "login.microsoftonline.com"
    )
    ua = str(record.get("userAgent") or "")
    op_name = str(record.get("operationName") or "")

    err_code = status_obj.get("errorCode")
    failure_reason = str(status_obj.get("failureReason") or record.get("resultReason") or "")
    result_str = str(record.get("result") or "").lower()

    is_sp = bool(record.get("servicePrincipalName") or record.get("servicePrincipalId")) or (
        record.get("isInteractive") is False
    )

    if err_code is not None and str(err_code).strip() != "":
        try:
            code_int = int(err_code)
            status_code = 200 if code_int == 0 else 401
            prefix = "entra_sp" if is_sp else "entra_signin"
            action = f"{prefix}_success" if code_int == 0 else f"{prefix}_err_{code_int}"
        except (ValueError, TypeError):
            code_str = str(err_code).strip()
            status_code = 200 if code_str in {"0", "success", "Success"} else 401
            prefix = "entra_sp" if is_sp else "entra_signin"
            action = f"{prefix}_success" if status_code == 200 else f"{prefix}_{code_str[:40]}"
        if failure_reason:
            action = f"{action}:{failure_reason[:60]}"
    elif op_name:
        status_code = 401 if result_str in {"failure", "failed"} else 200
        action = op_name
    else:
        status_code = 401 if result_str in {"failure", "failed"} else 200
        action = "entra_event"

    return _make_event(
        ts=ts,
        source_host=src_ip,
        actor=actor,
        event_type="idp_sp_auth" if is_sp else "idp_auth",
        surface="cloud_iam",
        appliance="entra_id",
        dest_host=dest_host,
        dest_port=443,
        http_path="/oauth2/v2.0/token" if is_sp else "/signin",
        user_agent=ua,
        status_code=status_code,
        action=action,
        raw=record,
    )


def _normalize_duo_record(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize Duo Security Admin API v2 Authentication & Admin Action JSON logs."""
    ts_raw = _extract_first(record, ("isotimestamp", "timestamp", "ts"))
    ts = parse_timestamp(ts_raw)
    access_dev = record.get("access_device") if isinstance(record.get("access_device"), dict) else {}
    user_obj = record.get("user") if isinstance(record.get("user"), dict) else {}
    app_obj = record.get("application") if isinstance(record.get("application"), dict) else {}

    src_ip = str(access_dev.get("ip") or record.get("ip") or "duo")
    actor = str(
        user_obj.get("name")
        or record.get("username")
        or record.get("object")
        or src_ip
    )
    dest_host = str(app_obj.get("name") or record.get("integration") or "duo.security")
    result = str(record.get("result") or "").lower()
    reason = str(record.get("reason") or "").lower()
    factor = str(record.get("factor") or "").lower()
    admin_action = str(record.get("action") or "").lower()

    if admin_action and not result:
        status_code = 200
        action = f"duo_admin:{admin_action}"
    elif result == "fraud" or reason in {"fraud_reported", "user_marked_fraud"}:
        status_code = 401
        action = f"duo_fraud_reported:{reason or result}"
    elif result in {"denied", "failure", "error"} or reason in {
        "denied_by_user",
        "user_cancelled",
        "no_response",
        "invalid_passcode",
        "locked_out",
    }:
        status_code = 401
        action = f"duo_mfa_denied:{reason or result}"
    else:
        status_code = 200
        action = f"duo_auth_success:{factor or result or 'allow'}"

    return _make_event(
        ts=ts,
        source_host=src_ip,
        actor=actor,
        event_type="idp_auth",
        surface="cloud_iam",
        appliance="duo",
        dest_host=dest_host,
        dest_port=443,
        http_method="POST",
        http_path="/auth/v2/auth" if not admin_action else "/admin/v1/logs",
        user_agent=str(access_dev.get("browser") or ""),
        status_code=status_code,
        action=action,
        raw=record,
    )


def _normalize_pingfederate_record(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize PingFederate JSON audit logs (AUTHN_ATTEMPT, OAuth, SSO, PingID MFA)."""
    ts_raw = _extract_first(record, ("timestamp", "time", "datetime", "eventTime"))
    ts = parse_timestamp(ts_raw)
    src_ip = str(_extract_first(record, ("ip", "clientIp", "remoteIp", "src_ip"), "pingfederate"))
    actor = str(_extract_first(record, ("subject", "user", "username", "client_id"), src_ip))
    dest_host = str(_extract_first(record, ("app", "connectionid", "partnerEntityId", "host"), "pingfederate.local"))
    pf_event = str(record.get("event") or "AUTHN_ATTEMPT")
    status_str = str(record.get("status") or "").lower()
    desc = str(record.get("description") or record.get("failureReason") or "")
    adapter = str(record.get("adapterid") or "")
    req_uri = str(record.get("requestUri") or ("/as/token.oauth2" if "oauth" in pf_event.lower() else "/as/authorization.oauth2"))

    failed = status_str in {"failure", "failed", "error", "denied"} or any(
        tok in desc.lower() for tok in ("invalid", "failed", "denied", "rejected", "locked")
    )
    status_code = 401 if failed else 200
    is_sp = bool(record.get("client_id") and not record.get("subject")) or ("oauth" in pf_event.lower() and "client_credentials" in desc.lower())
    action_parts = [p for p in (pf_event, adapter, desc[:60] if desc else status_str) if p]
    action = ":".join(action_parts)

    return _make_event(
        ts=ts,
        source_host=src_ip,
        actor=actor,
        event_type="idp_sp_auth" if is_sp else "idp_auth",
        surface="cloud_iam",
        appliance="pingfederate",
        dest_host=dest_host,
        dest_port=443,
        http_method="POST",
        http_path=req_uri,
        user_agent=str(record.get("userAgent") or ""),
        status_code=status_code,
        action=action,
        raw=record,
    )


def _normalize_google_workspace_record(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize Google Workspace Reports API (admin#reports#activity) Login/Token/Admin audit JSON."""
    id_obj = record.get("id") if isinstance(record.get("id"), dict) else {}
    actor_obj = record.get("actor") if isinstance(record.get("actor"), dict) else {}
    events_list = record.get("events") if isinstance(record.get("events"), list) else []
    first_ev = events_list[0] if events_list and isinstance(events_list[0], dict) else {}
    params_list = first_ev.get("parameters") if isinstance(first_ev.get("parameters"), list) else []
    params = {
        str(p.get("name")): str(p.get("value") or p.get("boolValue") or "")
        for p in params_list
        if isinstance(p, dict) and p.get("name")
    }

    ts = parse_timestamp(id_obj.get("time") or record.get("timestamp"))
    src_ip = str(record.get("ipAddress") or "google-workspace")
    actor = str(actor_obj.get("email") or actor_obj.get("profileId") or src_ip)
    app_name = str(id_obj.get("applicationName") or "login")
    ev_name = str(first_ev.get("name") or "workspace_event").lower()
    ev_type = str(first_ev.get("type") or "").lower()
    challenge_method = params.get("login_challenge_method", "")
    is_suspicious = params.get("is_suspicious", "").lower() == "true"
    app_display = params.get("app_name") or f"workspace.{app_name}"

    failed = (
        "failure" in ev_name
        or "failed" in ev_name
        or ev_name in {"suspicious_login", "login_challenge", "gov_attack_warning"}
        and (is_suspicious or params.get("login_challenge_status", "").lower() in {"failed", "denied"})
    )
    if ev_name == "login_verification" and params.get("login_challenge_status", "").lower() in {"failed", "denied"}:
        failed = True
    status_code = 401 if failed else 200

    action_suffix = f":{challenge_method}" if challenge_method else ""
    if failed and ev_name in {"login_verification", "login_challenge"}:
        action = f"gws_second_factor_failure:{ev_name}{action_suffix}"
    else:
        action = f"gws_{app_name}:{ev_name}{action_suffix}"

    return _make_event(
        ts=ts,
        source_host=src_ip,
        actor=actor,
        event_type="idp_auth",
        surface="cloud_iam",
        appliance="google_workspace",
        dest_host=str(app_display),
        dest_port=443,
        http_method="POST",
        http_path=f"/reports/v1/activity/{app_name}/{ev_type or ev_name}",
        user_agent="",
        status_code=status_code,
        action=action,
        raw=record,
    )


def _flatten_cloudtrail_params(params: Any, *, max_len: int = 500) -> str:
    """Flatten nested AWS CloudTrail requestParameters into a compact key=value string."""
    if not isinstance(params, dict):
        return str(params)[:max_len] if params else ""
    parts: list[str] = []
    for k, v in params.items():
        if isinstance(v, dict):
            parts.append(f"{k}={json.dumps(v, ensure_ascii=False)}")
        elif isinstance(v, list):
            parts.append(f"{k}={','.join(str(x) for x in v[:10])}")
        elif v is not None:
            parts.append(f"{k}={v}")
    return " ".join(parts)[:max_len]


def _normalize_cloudtrail_record(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize native AWS CloudTrail JSON records (nested userIdentity, requestParameters, camelCase userAgent)."""
    ts_raw = _extract_first(record, ("eventTime", "timestamp", "time"))
    if ts_raw is None:
        raise ValueError("CloudTrail record missing eventTime")
    ts = parse_timestamp(ts_raw)

    ui = record.get("userIdentity") if isinstance(record.get("userIdentity"), dict) else {}
    session_issuer = ((ui.get("sessionContext") or {}).get("sessionIssuer") or {}) if isinstance(ui.get("sessionContext"), dict) else {}

    src_ip = str(record.get("sourceIPAddress") or "cloudtrail")
    actor = str(
        ui.get("arn")
        or session_issuer.get("arn")
        or ui.get("userName")
        or ui.get("principalId")
        or src_ip
    )
    event_source = str(record.get("eventSource") or "amazonaws.com")
    event_name = str(record.get("eventName") or "")
    ua = str(record.get("userAgent") or "")
    err_code = str(record.get("errorCode") or "")
    err_msg = str(record.get("errorMessage") or "")
    vpc_ep = str(record.get("vpcEndpointId") or "")

    cmd_parts = [_flatten_cloudtrail_params(record.get("requestParameters"))]
    if err_code:
        cmd_parts.append(f"errorCode={err_code}")
    if err_msg:
        cmd_parts.append(err_msg[:120])
    if vpc_ep:
        cmd_parts.append(f"vpcEndpointId={vpc_ep}")
    cmd_line = " ".join(p for p in cmd_parts if p).strip()

    if err_code:
        err_low = err_code.lower()
        status_code = 401 if any(t in err_low for t in ("invalidclienttoken", "expiredtoken", "unauthorized")) else 403
    else:
        status_code = 200

    return _make_event(
        ts=ts,
        source_host=src_ip,
        actor=actor,
        event_type="cloudtrail",
        surface="cloud_iam",
        appliance="aws_cloudtrail",
        command_line=cmd_line,
        dest_host=event_source,
        dest_port=443,
        http_method="POST",
        user_agent=ua,
        status_code=status_code,
        action=event_name,
        raw=record,
    )


def _normalize_gcp_audit_record(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize native Google Cloud Audit Logs JSON (`protoPayload` AuditLog)."""
    ts_raw = _extract_first(record, ("timestamp", "receiveTimestamp", "time"))
    if ts_raw is None:
        raise ValueError("GCP Cloud Audit record missing timestamp")
    ts = parse_timestamp(ts_raw)

    pp = record.get("protoPayload") if isinstance(record.get("protoPayload"), dict) else {}
    auth = pp.get("authenticationInfo") if isinstance(pp.get("authenticationInfo"), dict) else {}
    meta = pp.get("requestMetadata") if isinstance(pp.get("requestMetadata"), dict) else {}
    status_obj = pp.get("status") if isinstance(pp.get("status"), dict) else {}

    src_ip = str(meta.get("callerIp") or "gcp-audit").strip() or "gcp-audit"
    actor = str(
        auth.get("principalEmail")
        or auth.get("principalSubject")
        or src_ip
    )
    service_name = str(pp.get("serviceName") or "googleapis.com")
    method_name = str(pp.get("methodName") or "")
    resource_name = str(pp.get("resourceName") or "")
    ua = str(meta.get("callerSuppliedUserAgent") or "")

    grpc_code_raw = status_obj.get("code")
    status_msg = str(status_obj.get("message") or "")
    msg_low = status_msg.lower()
    grpc_label = ""
    grpc_code: int | None = None
    if isinstance(grpc_code_raw, int) and not isinstance(grpc_code_raw, bool):
        grpc_code = grpc_code_raw
    elif isinstance(grpc_code_raw, str):
        code_str = grpc_code_raw.strip().upper()
        if code_str.isdigit():
            grpc_code = int(code_str)
        else:
            grpc_str_map = {
                "OK": 0,
                "INVALID_ARGUMENT": 3,
                "NOT_FOUND": 5,
                "PERMISSION_DENIED": 7,
                "RESOURCE_EXHAUSTED": 8,
                "FAILED_PRECONDITION": 9,
                "UNAUTHENTICATED": 16,
            }
            grpc_code = grpc_str_map.get(code_str)

    if grpc_code is not None:
        if grpc_code == 0:
            status_code = 200
        elif grpc_code == 7:
            status_code = 403
            grpc_label = "PERMISSION_DENIED"
        elif grpc_code == 16:
            status_code = 401
            grpc_label = "UNAUTHENTICATED"
        elif grpc_code == 5:
            status_code = 404
            grpc_label = "NOT_FOUND"
        elif grpc_code == 8:
            status_code = 429
            grpc_label = "RESOURCE_EXHAUSTED"
        elif grpc_code in (3, 9):
            status_code = 400
        else:
            status_code = 403 if ("permission" in msg_low and "denied" in msg_low) else 400
    elif "permission_denied" in msg_low or ("permission" in msg_low and "denied" in msg_low):
        status_code = 403
        grpc_label = "PERMISSION_DENIED"
    elif "unauthenticated" in msg_low:
        status_code = 401
        grpc_label = "UNAUTHENTICATED"
    else:
        status_code = 200

    cmd_parts: list[str] = []
    if resource_name:
        cmd_parts.append(f"resource={resource_name[:200]}")
    if grpc_label:
        cmd_parts.append(f"status={grpc_label}")
    if status_msg:
        cmd_parts.append(status_msg[:160])
    delegation = auth.get("serviceAccountDelegationInfo")
    if isinstance(delegation, list) and delegation:
        cmd_parts.append(f"delegation={json.dumps(delegation[:3], ensure_ascii=False)[:180]}")
    req_params = pp.get("request")
    if isinstance(req_params, dict) and req_params:
        cmd_parts.append(_flatten_cloudtrail_params(req_params, max_len=240))
    cmd_line = " ".join(p for p in cmd_parts if p).strip()[:500]

    return _make_event(
        ts=ts,
        source_host=src_ip,
        actor=actor,
        event_type="gcp_audit",
        surface="cloud_iam",
        appliance="gcp_audit",
        command_line=cmd_line,
        dest_host=service_name,
        dest_port=443,
        http_method="POST",
        http_path=resource_name,
        user_agent=ua,
        status_code=status_code,
        action=method_name,
        raw=record,
    )


def _is_multicast_or_mdns_eve(record: dict[str, Any]) -> bool:
    """Return True if a Suricata EVE record represents local mDNS/LLMNR/multicast chatter."""
    dport = record.get("dest_port")
    if dport in (5353, 5355):
        return True
    dest_ip = str(record.get("dest_ip") or "").lower()
    return dest_ip.startswith(("224.0.0.", "239.255.255.", "ff0"))


def _should_skip_suricata_eve_record(
    record: dict[str, Any],
    *,
    rich_flow_ids: set[Any] | None = None,
) -> bool:
    """Filter non-behavioral/duplicate Suricata EVE meta-records (`stats`, `fileinfo`, DNS answers, duplicate flows)."""
    et = str(record.get("event_type") or "").lower()
    if et == "stats" and isinstance(record.get("stats"), dict):
        return True
    if et == "fileinfo" and isinstance(record.get("fileinfo"), dict):
        return True
    is_eve = "flow_id" in record or "pkt_src" in record or any(
        isinstance(record.get(k), dict) for k in ("tls", "http", "dns", "flow", "alert")
    )
    if not is_eve:
        return False
    if et == "dns":
        dns_obj = record.get("dns")
        if isinstance(dns_obj, dict) and str(dns_obj.get("type") or "").lower() == "answer":
            return True
        if _is_multicast_or_mdns_eve(record):
            return True
    if et == "flow" and isinstance(record.get("flow"), dict):
        if _is_multicast_or_mdns_eve(record):
            return True
        fid = record.get("flow_id")
        if rich_flow_ids and fid is not None and fid in rich_flow_ids:
            return True
        if str(record.get("app_proto") or "").lower() in {"http", "dns"}:
            return True
    return False


def _flatten_suricata_eve_record(
    record: dict[str, Any],
    *,
    flow_bytes_by_id: dict[Any, tuple[int | None, int | None]] | None = None,
) -> tuple[dict[str, Any], bool]:
    """Unpack nested Suricata EVE JSON objects (`tls`, `http`, `dns`, `flow`, `alert`) into flat keys."""
    if "event_type" not in record or not any(k in record for k in ("src_ip", "dest_ip")):
        return record, False
    if not any(isinstance(record.get(k), dict) for k in ("tls", "http", "dns", "flow", "alert")):
        return record, False
    flat = dict(record)
    tls_obj = record.get("tls")
    if isinstance(tls_obj, dict):
        if tls_obj.get("sni") and not flat.get("dest_host"):
            flat["dest_host"] = tls_obj["sni"]
        if tls_obj.get("ja4") and not flat.get("ja4"):
            flat["ja4"] = tls_obj["ja4"]
    http_obj = record.get("http")
    if isinstance(http_obj, dict):
        if http_obj.get("hostname") and not flat.get("dest_host"):
            flat["dest_host"] = http_obj["hostname"]
        if http_obj.get("url") and not flat.get("http_path"):
            flat["http_path"] = http_obj["url"]
        if http_obj.get("http_user_agent") and not flat.get("user_agent"):
            flat["user_agent"] = http_obj["http_user_agent"]
        if http_obj.get("http_method") and not flat.get("http_method"):
            flat["http_method"] = http_obj["http_method"]
        if http_obj.get("status") is not None and flat.get("status_code") is None:
            flat["status_code"] = http_obj["status"]
        if http_obj.get("ja4h") and not flat.get("ja4h"):
            flat["ja4h"] = http_obj["ja4h"]
        if http_obj.get("http_request_body_printable") and not flat.get("request_body"):
            flat["request_body"] = http_obj["http_request_body_printable"]
        elif http_obj.get("http_request_body") and not flat.get("request_body"):
            flat["request_body"] = http_obj["http_request_body"]
    if record.get("payload_printable") and not flat.get("request_body"):
        flat["request_body"] = record["payload_printable"]
    dns_obj = record.get("dns")
    if isinstance(dns_obj, dict) and dns_obj.get("rrname") and not flat.get("dest_host"):
        flat["dest_host"] = dns_obj["rrname"]
    flow_obj = record.get("flow")
    if isinstance(flow_obj, dict):
        if str(record.get("event_type") or "").lower() == "flow" and flow_obj.get("start"):
            flat["timestamp"] = flow_obj["start"]
        if flow_obj.get("bytes_toserver") is not None and flat.get("bytes_out") is None:
            flat["bytes_out"] = flow_obj["bytes_toserver"]
        if flow_obj.get("bytes_toclient") is not None and flat.get("bytes_in") is None:
            flat["bytes_in"] = flow_obj["bytes_toclient"]
    if flow_bytes_by_id and record.get("flow_id") is not None:
        fb = flow_bytes_by_id.get(record["flow_id"])
        if fb:
            if flat.get("bytes_out") is None and fb[0] is not None:
                flat["bytes_out"] = fb[0]
            if flat.get("bytes_in") is None and fb[1] is not None:
                flat["bytes_in"] = fb[1]
    alert_obj = record.get("alert")
    if isinstance(alert_obj, dict) and alert_obj.get("signature") and not flat.get("action"):
        flat["action"] = alert_obj["signature"]
    if not flat.get("dest_host") and flat.get("dest_ip"):
        flat["dest_host"] = flat["dest_ip"]
    return flat, True


def _normalize_k8s_audit_record(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize native Kubernetes `audit.k8s.io/v1` Event JSON into canonical event dict."""
    ts_raw = _extract_first(record, ("requestReceivedTimestamp", "stageTimestamp", "timestamp"))
    if ts_raw is None:
        raise ValueError("Kubernetes audit record missing timestamp field")
    ts = parse_timestamp(ts_raw)
    source_ips = record.get("sourceIPs")
    src_ip = ""
    if isinstance(source_ips, list):
        for ip in source_ips:
            if isinstance(ip, str) and ip.strip():
                src_ip = ip.strip()
                break
    source_host = str(record.get("source_host") or src_ip or "k8s-apiserver")
    user_obj = record.get("user") if isinstance(record.get("user"), dict) else {}
    actor = str(user_obj.get("username") or record.get("actor") or source_host)
    obj_ref = record.get("objectRef") if isinstance(record.get("objectRef"), dict) else {}
    ns = str(obj_ref.get("namespace") or "")
    res = str(obj_ref.get("resource") or "")
    name = str(obj_ref.get("name") or "")
    dest_host = "/".join(p for p in (ns, res, name) if p) or "kubernetes"
    resp_status = record.get("responseStatus") if isinstance(record.get("responseStatus"), dict) else {}
    code_raw = resp_status.get("code")
    status_code = int(code_raw) if isinstance(code_raw, int) and not isinstance(code_raw, bool) else None
    return _make_event(
        ts=ts,
        source_host=source_host,
        actor=actor,
        event_type="k8s_audit",
        surface="cloud_iam",
        appliance="kubernetes_audit",
        dest_host=dest_host,
        http_path=str(record.get("requestURI") or ""),
        user_agent=str(record.get("userAgent") or ""),
        status_code=status_code,
        action=str(record.get("verb") or record.get("action") or "k8s_audit"),
        raw=record,
    )


def normalize_json_record(
    record: dict[str, Any],
    *,
    flow_bytes_by_id: dict[Any, tuple[int | None, int | None]] | None = None,
) -> dict[str, Any]:
    """Normalize JSONL records (generic, Sysmon, MDE, CrowdStrike, S1, Zscaler NSS, Suricata EVE, Kubernetes audit, CloudTrail, YAF/IPFIX, Okta, Entra, Duo, PingFederate, Google Workspace)."""
    # Detect native Kubernetes `audit.k8s.io/v1` Event JSON
    if (
        str(record.get("apiVersion", "")).startswith("audit.k8s.io/")
        or (record.get("kind") == "Event" and isinstance(record.get("objectRef"), dict))
        or ("requestReceivedTimestamp" in record and isinstance(record.get("objectRef"), dict))
    ):
        return _normalize_k8s_audit_record(record)

    # Detect native AWS CloudTrail JSON (eventSource + eventName + userIdentity / *.amazonaws.com[.cn])
    if (
        "eventName" in record
        and "eventSource" in record
        and (
            str(record.get("eventSource", "")).lower().endswith((".amazonaws.com", ".amazonaws.com.cn"))
            or isinstance(record.get("userIdentity"), dict)
        )
    ):
        return _normalize_cloudtrail_record(record)

    # Detect native Google Cloud Audit Logs JSON (protoPayload AuditLog)
    proto_payload = record.get("protoPayload")
    if isinstance(proto_payload, dict) and (
        "auditlog" in str(proto_payload.get("@type", "")).lower()
        or ("methodName" in proto_payload and "serviceName" in proto_payload)
    ):
        return _normalize_gcp_audit_record(record)

    # Detect native Okta System Log JSON
    if "published" in record and "eventType" in record and ("outcome" in record or "client" in record):
        return _normalize_okta_record(record)

    # Detect native Microsoft Entra ID SigninLogs / AADServicePrincipalSignInLogs / AuditLogs JSON
    if any(k in record for k in ("createdDateTime", "activityDateTime")) and any(
        k in record
        for k in (
            "userPrincipalName",
            "servicePrincipalName",
            "resourceDisplayName",
            "operationName",
            "conditionalAccessStatus",
        )
    ):
        return _normalize_entra_record(record)

    # Detect native Duo Security Auth/Admin JSON logs
    if any(k in record for k in ("txid", "access_device", "isotimestamp")) and any(
        k in record for k in ("factor", "result", "reason", "action")
    ):
        return _normalize_duo_record(record)

    # Detect native PingFederate JSON audit logs
    if "event" in record and any(k in record for k in ("trackingid", "adapterid", "connectionid", "partnerEntityId")):
        return _normalize_pingfederate_record(record)

    # Detect native Google Workspace Reports API (admin#reports#activity) JSON
    if (
        record.get("kind") == "admin#reports#activity"
        or (isinstance(record.get("id"), dict) and "applicationName" in record["id"] and isinstance(record.get("events"), list))
    ):
        return _normalize_google_workspace_record(record)

    record, is_ipfix = _flatten_ipfix_record(record)
    record, is_suricata_eve = _flatten_suricata_eve_record(record, flow_bytes_by_id=flow_bytes_by_id)

    # Detect Zscaler NSS JSON fields
    is_zscaler = any(k in record for k in ("ClientIP", "hostname", "urlcategory", "threatname", "reason")) and any(
        k in record for k in ("datetime", "user", "url")
    )

    ts_raw = _extract_first(
        record,
        (
            "timestamp",
            "ts",
            "@timestamp",
            "datetime",
            "eventTime",
            "UtcTime",
            "time",
            "Timestamp",
            "flowStartMicroseconds",
            "flowStartMilliseconds",
            "flowStartSeconds",
        ),
    )
    if ts_raw is None:
        raise ValueError("Record missing timestamp field")
    ts = parse_timestamp(ts_raw)

    appliance = _extract_first(record, ("appliance", "vendor_product", "device_type"))
    if not appliance and is_suricata_eve:
        appliance = "suricata_eve"
    elif not appliance and is_zscaler:
        appliance = "zscaler"
    elif not appliance and is_ipfix:
        appliance = "yaf_ipfix"

    source_host = str(
        _extract_first(
            record,
            (
                "source_host",
                "host",
                "Computer",
                "DeviceName",
                "ClientIP",
                "id.orig_h",
                "sourceIPAddress",
                "sourceIPv4Address",
                "sourceIPv6Address",
                "source_ip",
                "src_ip",
            ),
            "unknown",
        )
    )
    actor = str(
        _extract_first(
            record,
            (
                "actor",
                "user",
                "User",
                "AccountName",
                "InitiatingProcessAccountName",
                "userIdentity.arn",
                "principal",
                "src_user",
            ),
            source_host,
        )
    )
    event_type = str(
        _extract_first(
            record,
            ("event_type", "category", "eventSource", "ActionType", "type"),
            "http" if is_zscaler else ("network" if is_ipfix else "generic"),
        )
    )
    process = str(
        _extract_first(record, ("process", "Image", "FileName", "process_name", "exe"), "")
    )
    parent_process = str(
        _extract_first(
            record,
            ("parent_process", "ParentImage", "InitiatingProcessFileName", "parent_name"),
            "",
        )
    )
    command_line = str(
        _extract_first(
            record,
            ("command_line", "CommandLine", "ProcessCommandLine", "cmdline", "command"),
            "",
        )
    )
    dest_host = str(
        _extract_first(
            record,
            (
                "dest_host",
                "sslServerName",
                "httpHost",
                "dnsQName",
                "DestinationHostname",
                "RemoteUrl",
                "hostname",
                "host_header",
                "id.resp_h",
                "destinationIPv4Address",
                "destinationIPv6Address",
                "dest_ip",
                "dst_host",
                "domain",
            ),
            "",
        )
    )
    dest_port_raw = _extract_first(
        record,
        ("dest_port", "destinationTransportPort", "DestinationPort", "RemotePort", "id.resp_p", "dst_port"),
    )
    dest_port = int(dest_port_raw) if dest_port_raw is not None and str(dest_port_raw).isdigit() else None
    http_method = str(_extract_first(record, ("http_method", "requestmethod", "method"), ""))
    if not http_method and record.get("httpGet"):
        http_method = "GET"
    http_path = str(_extract_first(record, ("http_path", "httpGet", "httpRequest", "url", "uri", "path"), ""))
    user_agent = str(_extract_first(record, ("user_agent", "userAgent", "httpUserAgent", "useragent", "UserAgent", "ua"), ""))
    ja4 = str(_extract_first(record, ("ja4", "tls.ja4", "JA4"), ""))
    ja4h = str(_extract_first(record, ("ja4h", "http.ja4h", "JA4H"), ""))
    bytes_out_raw = _extract_first(
        record, ("bytes_out", "octetTotalCount", "requestsize", "orig_bytes", "cs_bytes")
    )
    bytes_in_raw = _extract_first(
        record, ("bytes_in", "reverseOctetTotalCount", "responsesize", "resp_bytes", "sc_bytes")
    )
    bytes_out = int(bytes_out_raw) if bytes_out_raw is not None and str(bytes_out_raw).isdigit() else None
    bytes_in = int(bytes_in_raw) if bytes_in_raw is not None and str(bytes_in_raw).isdigit() else None

    status_raw = _extract_first(
        record, ("status_code", "httpResponse", "status", "http_status", "responsecode", "errorCode")
    )
    status_code: int | None = None
    if isinstance(status_raw, bool):
        status_code = None
    elif isinstance(status_raw, int):
        status_code = status_raw
    elif isinstance(status_raw, str) and status_raw.isdigit():
        status_code = int(status_raw)
    elif isinstance(status_raw, str) and status_raw.strip():
        s_clean = status_raw.strip()
        m_code = re.match(r"^(\d{3})\b", s_clean)
        if m_code:
            status_code = int(m_code.group(1))
        else:
            s_low = s_clean.lower()
            if s_low in {"ok", "success", "succeeded", "allow", "allowed", "accept", "accepted", "pass", "passed"}:
                status_code = 200
            elif any(
                tok in s_low
                for tok in ("fail", "deny", "denied", "error", "block", "reject", "forbid", "unauth", "accessdenied")
            ):
                status_code = 403
            else:
                status_code = None

    action = str(_extract_first(record, ("action", "eventName", "operation", "ActionType"), ""))
    if not action and is_ipfix and record.get("silkAppLabel") is not None:
        action = f"ipfix_app_{record['silkAppLabel']}"
    surface = str(
        _extract_first(record, ("surface",), "")
        or _infer_surface(event_type, str(appliance) if appliance else None, http_path, action, process)
    )

    return _make_event(
        ts=ts,
        source_host=source_host,
        actor=actor,
        event_type=event_type,
        surface=surface,
        appliance=str(appliance) if appliance else None,
        process=process,
        parent_process=parent_process,
        command_line=command_line,
        dest_host=dest_host,
        dest_port=dest_port,
        http_method=http_method,
        http_path=http_path,
        user_agent=user_agent,
        ja4=ja4,
        ja4h=ja4h,
        bytes_out=bytes_out,
        bytes_in=bytes_in,
        status_code=status_code,
        action=action,
        raw=record,
    )


def parse_cisco_asa_ftd_syslog(lines: list[str]) -> list[dict[str, Any]]:
    """Parse Cisco ASA and Cisco FTD syslog lines (%ASA- / %FTD-)."""
    events: list[dict[str, Any]] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        m = ASA_FTD_RE.match(line)
        if not m:
            continue
        try:
            ts = parse_timestamp(m.group("ts"))
        except ValueError:
            continue
        host = m.group("host")
        prod = m.group("prod")
        msgid = m.group("msgid")
        msg = m.group("msg")

        user_m = ASA_USER_RE.search(msg)
        ip_m = ASA_IP_RE.search(msg)
        uri_m = ASA_URI_RE.search(msg)
        src_ip = ip_m.group("ip") if ip_m else (IPV4_ANY_RE.search(msg).group(0) if IPV4_ANY_RE.search(msg) else host)
        actor = user_m.group("user") if user_m else src_ip
        uri = uri_m.group("uri") if uri_m else ""

        msg_lower = msg.lower()
        is_failure = msgid in {"113005", "113015", "716039"} or any(
            w in msg_lower for w in ("rejected", "failed", "denied", "invalid", "block")
        )
        action = f"{prod.lower()}_{msgid}_" + ("auth_failed" if is_failure else "vpn_event")

        events.append(
            _make_event(
                ts=ts,
                source_host=src_ip,
                actor=actor,
                event_type="edge_auth",
                surface="edge_appliance",
                appliance="cisco_asa_ftd",
                dest_host=host,
                dest_port=443,
                http_path=uri,
                status_code=401 if is_failure else 200,
                action=action,
                raw={"raw": line, "msgid": f"{prod}-{msgid}", "event": {"code": msgid}},
            )
        )
    return events


def parse_citrix_netscaler_log(lines: list[str]) -> list[dict[str, Any]]:
    """Parse Citrix NetScaler ADC / Gateway syslog lines."""
    events: list[dict[str, Any]] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        m = CITRIX_RE.match(line)
        if not m:
            continue
        try:
            ts = parse_timestamp(m.group("ts"))
        except ValueError:
            continue
        host = m.group("host")
        msg = m.group("msg")

        user_m = CITRIX_USER_RE.search(msg)
        ip_m = CITRIX_IP_RE.search(msg)
        uri_m = CITRIX_URI_RE.search(msg)
        src_ip = ip_m.group("ip") if ip_m else (IPV4_ANY_RE.search(msg).group(0) if IPV4_ANY_RE.search(msg) else host)
        actor = user_m.group("user") if user_m else src_ip
        uri = uri_m.group("uri") if uri_m else ""

        msg_lower = msg.lower()
        status = 401 if any(k in msg_lower for k in ("login_failed", "failed", "denied", "403", "404")) else 200
        if "404" in msg_lower:
            status = 404
        elif "403" in msg_lower:
            status = 403
        action = "citrix_aaa_login_failed" if status >= 400 else "citrix_gateway_event"

        events.append(
            _make_event(
                ts=ts,
                source_host=src_ip,
                actor=actor,
                event_type="edge_auth",
                surface="edge_appliance",
                appliance="citrix_netscaler",
                dest_host=host,
                dest_port=443,
                http_path=uri,
                status_code=status,
                action=action,
                raw={"raw": line},
            )
        )
    return events


def parse_panos_log(lines: list[str]) -> list[dict[str, Any]]:
    """Parse Palo Alto PAN-OS CSV / syslog lines (GLOBALPROTECT, THREAT, TRAFFIC)."""
    events: list[dict[str, Any]] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            row = next(csv.reader(io.StringIO(line)))
        except (csv.Error, StopIteration):
            continue
        if len(row) < 6:
            continue
        # Expect common PAN-OS CSV format: receive_time,serial,type,subtype,src_ip,dst_host,user,status/action,uri_or_detail
        # Also support full PAN-OS syslog CSV where row[3] is TRAFFIC/THREAT/GLOBALPROTECT
        try:
            if row[2].upper() in {"TRAFFIC", "THREAT", "GLOBALPROTECT", "SYSTEM"}:
                ts = parse_timestamp(row[0])
                log_type = row[2].upper()
                subtype = row[3]
                src_ip = row[4]
                dest_host = row[5]
                actor = row[6] if len(row) > 6 and row[6] else src_ip
                outcome = row[7] if len(row) > 7 else ""
                uri = row[8] if len(row) > 8 else ""
                ua = row[9] if len(row) > 9 else ""
            elif len(row) >= 15 and row[3].upper() in {"TRAFFIC", "THREAT", "GLOBALPROTECT"}:
                ts = parse_timestamp(row[1])
                log_type = row[3].upper()
                subtype = row[4]
                src_ip = row[7]
                dest_host = row[8]
                actor = row[12] or src_ip
                outcome = row[14]
                uri = row[15] if len(row) > 15 else ""
                ua = ""
            else:
                continue
        except (ValueError, IndexError):
            continue

        out_low = outcome.lower()
        is_err = any(w in out_low for w in ("fail", "deny", "drop", "reset", "alert", "block", "401", "403"))
        events.append(
            _make_event(
                ts=ts,
                source_host=src_ip,
                actor=actor,
                event_type="edge_auth" if log_type == "GLOBALPROTECT" else "network",
                surface="edge_appliance",
                appliance="panos",
                dest_host=dest_host,
                dest_port=443,
                http_path=uri,
                user_agent=ua,
                status_code=401 if is_err else 200,
                action=f"panos_{log_type.lower()}_{subtype.lower()}_{out_low or 'event'}",
                raw={"raw": line},
            )
        )
    return events


def parse_f5_bigip_log(lines: list[str]) -> list[dict[str, Any]]:
    """Parse F5 BIG-IP APM / LTM / ASM syslog lines."""
    events: list[dict[str, Any]] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        m = F5_RE.match(line)
        if not m:
            continue
        try:
            ts = parse_timestamp(m.group("ts"))
        except ValueError:
            continue
        host = m.group("host")
        daemon = m.group("daemon").lower()
        msg = m.group("msg")

        user_m = F5_USER_RE.search(msg)
        uri_m = F5_URI_RE.search(msg)
        ip_m = IPV4_ANY_RE.search(msg)
        src_ip = ip_m.group(0) if ip_m else host
        actor = user_m.group("user") if user_m else src_ip
        uri = uri_m.group("uri") if uri_m else ""

        msg_low = msg.lower()
        status = 200
        if any(k in msg_low for k in ("failed", "denied", "rejected", "unauthorized", "401")):
            status = 401
        elif "403" in msg_low or "forbidden" in msg_low:
            status = 403
        elif "404" in msg_low:
            status = 404

        events.append(
            _make_event(
                ts=ts,
                source_host=src_ip,
                actor=actor,
                event_type="edge_auth",
                surface="edge_appliance",
                appliance="f5_bigip",
                dest_host=host,
                dest_port=443,
                http_path=uri,
                status_code=status,
                action=f"f5_{daemon}_{'error' if status >= 400 else 'event'}",
                raw={"raw": line, "daemon": daemon},
            )
        )
    return events


def parse_web_access_log(lines: list[str]) -> list[dict[str, Any]]:
    """Parse Nginx / Apache Combined access logs."""
    events: list[dict[str, Any]] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        m = NGINX_COMBINED_RE.match(line)
        if not m:
            continue
        try:
            ts = parse_timestamp(m.group("ts"))
        except ValueError:
            continue
        ip = m.group("ip")
        user = m.group("user")
        actor = ip if user in {"-", ""} else user
        path = m.group("path")
        status = int(m.group("status"))
        ua = m.group("ua")

        # Identify edge gateway URIs if proxied through Nginx/Apache
        appliance: str | None = None
        surface = "web_portal"
        path_low = path.lower()
        if any(p in path_low for p in ("/+cscoe+/", "/+webvpn+/")):
            appliance = "cisco_asa_ftd"
            surface = "edge_appliance"
        elif any(p in path_low for p in ("/vpn/", "/nf/auth/", "/logon/logonpoint/")):
            appliance = "citrix_netscaler"
            surface = "edge_appliance"
        elif any(p in path_low for p in ("/global-protect/", "/ssl-vpn/")):
            appliance = "panos"
            surface = "edge_appliance"
        elif any(p in path_low for p in ("/my.policy", "/tmui/", "/mgmt/tm/")):
            appliance = "f5_bigip"
            surface = "edge_appliance"

        events.append(
            _make_event(
                ts=ts,
                source_host=ip,
                actor=actor,
                event_type="http",
                surface=surface,
                appliance=appliance,
                http_method=m.group("method"),
                http_path=path,
                user_agent=ua,
                status_code=status,
                action="http_request",
                raw={"raw": line},
            )
        )
    return events


def detect_log_format(lines: list[str]) -> str:
    """Heuristically identify the log format from the first non-empty lines."""
    sample = [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")][:10]
    if not sample:
        return "jsonl"
    first = sample[0]
    if first.startswith(("{", "[")):
        return "jsonl"
    if any(ASA_FTD_RE.match(ln) for ln in sample):
        return "cisco_asa_ftd"
    if any(CITRIX_RE.match(ln) for ln in sample):
        return "citrix_netscaler"
    if any(F5_RE.match(ln) for ln in sample):
        return "f5_bigip"
    if any(NGINX_COMBINED_RE.match(ln) for ln in sample):
        return "web_access"
    if any(
        any(tok in ln.upper() for tok in (",GLOBALPROTECT,", ",THREAT,", ",TRAFFIC,"))
        for ln in sample
    ):
        return "panos"
    return "jsonl"


def parse_auto(file_path: str | Path, fmt: str = "auto") -> list[dict[str, Any]]:
    """Auto-detect and parse any supported JSONL, edge appliance, proxy, or web log file."""
    path = Path(file_path)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    chosen = detect_log_format(lines) if fmt == "auto" else fmt

    if chosen == "cisco_asa_ftd":
        return parse_cisco_asa_ftd_syslog(lines)
    if chosen == "citrix_netscaler":
        return parse_citrix_netscaler_log(lines)
    if chosen == "panos":
        return parse_panos_log(lines)
    if chosen == "f5_bigip":
        return parse_f5_bigip_log(lines)
    if chosen == "web_access":
        return parse_web_access_log(lines)

    # Default: JSON / JSONL (generic, Sysmon, MDE, CrowdStrike, S1, Zscaler NSS, CloudTrail S3 {"Records": [...]}, IdPs)
    parsed_records: list[dict[str, Any]] = []
    raw_text = "\n".join(lines).strip()
    whole: Any = None
    if raw_text.startswith("{") or raw_text.startswith("["):
        try:
            whole = json.loads(raw_text)
        except json.JSONDecodeError:
            whole = None
        if isinstance(whole, dict) and (
            isinstance(whole.get("Records"), list)
            or (
                isinstance(whole.get("entries"), list)
                and any(isinstance(rec, dict) and "protoPayload" in rec for rec in whole["entries"])
            )
            or (
                isinstance(whole.get("items"), list)
                and (
                    whole.get("kind") == "EventList"
                    or str(whole.get("apiVersion", "")).startswith("audit.k8s.io/")
                )
            )
        ):
            if isinstance(whole.get("Records"), list):
                batch = whole["Records"]
            elif isinstance(whole.get("entries"), list):
                batch = whole["entries"]
            else:
                batch = whole["items"]
            parsed_records = [rec for rec in batch if isinstance(rec, dict)]
        elif isinstance(whole, list):
            parsed_records = [rec for rec in whole if isinstance(rec, dict)]
        elif isinstance(whole, dict):
            parsed_records = [whole]

    if whole is None:
        # Resilient per-line JSONL parsing: skip individual malformed/truncated lines instead of aborting the whole file.
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                if isinstance(record.get("Records"), list):
                    parsed_records.extend(sub for sub in record["Records"] if isinstance(sub, dict))
                elif isinstance(record.get("entries"), list) and any(
                    isinstance(sub, dict) and "protoPayload" in sub for sub in record["entries"]
                ):
                    parsed_records.extend(sub for sub in record["entries"] if isinstance(sub, dict))
                elif isinstance(record.get("items"), list) and (
                    record.get("kind") == "EventList"
                    or str(record.get("apiVersion", "")).startswith("audit.k8s.io/")
                ):
                    parsed_records.extend(sub for sub in record["items"] if isinstance(sub, dict))
                else:
                    parsed_records.append(record)

    # Pre-pass for Suricata EVE JSON: correlate `flow` byte counters onto matching `tls`/`http`/`dns` `flow_id`s
    # and suppress duplicate/meta records (`stats`, `fileinfo`, DNS `answer` duplicates, mDNS, and redundant `flow` flushes).
    rich_flow_ids: set[Any] = set()
    flow_bytes_by_id: dict[Any, tuple[int | None, int | None]] = {}
    for rec in parsed_records:
        fid = rec.get("flow_id")
        if fid is None:
            continue
        et = str(rec.get("event_type") or "").lower()
        if et in {"http", "tls", "dns", "alert"}:
            rich_flow_ids.add(fid)
        elif et == "flow" and isinstance(rec.get("flow"), dict):
            fobj = rec["flow"]
            flow_bytes_by_id[fid] = (fobj.get("bytes_toserver"), fobj.get("bytes_toclient"))

    events = []
    for rec in parsed_records:
        if _should_skip_suricata_eve_record(rec, rich_flow_ids=rich_flow_ids):
            continue
        try:
            events.append(normalize_json_record(rec, flow_bytes_by_id=flow_bytes_by_id or None))
        except (ValueError, KeyError, TypeError):
            continue
    return events
