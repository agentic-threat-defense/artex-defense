# Databricks notebook source
# MAGIC %md
# MAGIC # ARTEX & Autonomous Agentic Threats — Read-Only Behavioral Hunt Dashboard (v0.2.6)
# MAGIC
# MAGIC > **Strict Read-Only Guarantee:** Every query in this notebook is strictly read-only (`SELECT` / CTEs only).
# MAGIC > It executes **zero** table edits (`CREATE TABLE`, `INSERT`, `MERGE`, `UPDATE`, `DELETE`, `DROP`, `ALTER`) and enforces a runtime SQL guard (`assert_read_only_sql`) before every query.
# MAGIC >
# MAGIC > **Dual-Mode Execution (Zero-Edit Spark SQL & DuckDB):**
# MAGIC > - **Databricks Free Edition / Enterprise Serverless:** Reads Unity Catalog table/column mappings from `dbutils.widgets` (defaulting to `workspace.default.artex_*`), emits native **Spark SQL** (`SPLIT`, `RLIKE`, `UNIX_TIMESTAMP`, `STRING`), queries via `spark.sql()`, and renders with `displayHTML()`.
# MAGIC > - **Local / Offline Preview:** Runs the exact same 11 hunts in DuckDB against built-in synthetic attack + benign telemetry and writes a self-contained offline HTML dashboard (`--out`).
# MAGIC >
# MAGIC > **Operational Safety:** Never browse or probe flagged external IPs from bare metal; triage strictly through passive intelligence platforms. Further testing, schema alignment, and threshold tuning will be required for live production environments.

# COMMAND ----------

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import html as html_lib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

RUNNING_IN_DBX = "dbutils" in globals() and "spark" in globals()

# Strict runtime guard blocking any DDL/DML write verbs on read-only workspaces
FORBIDDEN_WRITE_SQL_RE = re.compile(
    r"\b(CREATE\s+(?:OR\s+REPLACE\s+)?(?:TABLE|VIEW|SCHEMA|DATABASE|CATALOG)|"
    r"INSERT\s+INTO|INSERT\s+OVERWRITE|MERGE\s+INTO|UPDATE\s+\S+\s+SET|"
    r"DELETE\s+FROM|DROP\s+(?:TABLE|VIEW|SCHEMA|DATABASE)|ALTER\s+TABLE|"
    r"TRUNCATE\s+TABLE|COPY\s+INTO|REPLACE\s+TABLE)\b",
    re.IGNORECASE,
)


def assert_read_only_sql(sql: str) -> None:
    """Refuse execution if any DDL/DML write statement is present."""
    match = FORBIDDEN_WRITE_SQL_RE.search(sql)
    if match:
        raise PermissionError(f"Read-only guardrail blocked forbidden write SQL verb: {match.group(0)}")


# COMMAND ----------

# MAGIC %md
# MAGIC ## 1. Configuration & Schema Mapping (Single Place to Adapt Table / Column Names)

# COMMAND ----------

def _get_widget(name: str, default: str) -> str:
    if RUNNING_IN_DBX:
        try:
            dbutils.widgets.text(name, default)  # type: ignore[name-defined]
            val = dbutils.widgets.get(name)  # type: ignore[name-defined]
            return val.strip() if val else default
        except Exception:
            return default
    return default


def _default_table(local_name: str, dbx_name: str) -> str:
    return dbx_name if RUNNING_IN_DBX else local_name


CONFIG: dict[str, Any] = {
    "lookback_hours": int(_get_widget("lookback_hours", "72")),
    "flow_table": _get_widget("flow_table", _default_table("default_ipfix_flows", "workspace.default.artex_ipfix_flows")),
    "ssl_table": _get_widget("ssl_table", _default_table("ssl_flows", "workspace.default.artex_ssl_flows")),
    "http_table": _get_widget("http_table", _default_table("http_flows", "workspace.default.artex_http_flows")),
    "dns_table": _get_widget("dns_table", _default_table("dns_flows", "workspace.default.artex_dns_flows")),
    "entra_sp_table": _get_widget("entra_sp_table", _default_table("entra_sp_logs", "workspace.default.artex_entra_sp_logs")),
    "gcp_audit_table": _get_widget("gcp_audit_table", _default_table("gcp_audit_logs", "workspace.default.artex_gcp_audit_logs")),
    "scanner_allowlist_csv": _get_widget("scanner_allowlist_csv", "198.51.100.250"),
    "max_enrich_ips": int(_get_widget("max_enrich_ips", "50")),
    # Remap right-hand column names to match your production Databricks tables:
    "cols": {
        "ts": "flow_ts",
        "src_ip": "src_ip",
        "dst_ip": "dst_ip",
        "dst_port": "dst_port",
        "bytes_out": "octetTotalCount",
        "bytes_in": "reverseOctetTotalCount",
        "app_label": "silkAppLabel",
        "sni": "sslServerName",
        "ja4": "ja4",
        "ja4s": "ja4s",
        "ja4h": "ja4h",
        "ja4x": "ja4x",
        "http_method": "http_method",
        "http_path": "http_path",
        "http_status": "http_status",
        "http_ua": "http_ua",
        "http_bytes_out": "bytes_out",
        "dns_query": "dns_query",
        # Entra ID Service Principal sign-in columns
        "sp_ts": "created_ts",
        "sp_ip": "ip_address",
        "sp_name": "service_principal_name",
        "sp_resource": "resource_display_name",
        "sp_status": "result_type",
        # GCP Cloud Audit columns
        "gcp_ts": "event_ts",
        "gcp_ip": "caller_ip",
        "gcp_principal": "principal_email",
        "gcp_service": "service_name",
        "gcp_method": "method_name",
        "gcp_resource": "resource_name",
        "gcp_grpc_code": "grpc_code",
    },
}


def _scanner_sql_list(cfg: dict[str, Any]) -> str:
    ips = [ip.strip() for ip in cfg["scanner_allowlist_csv"].split(",") if ip.strip()]
    if not ips:
        return "('0.0.0.0')"
    escaped = ", ".join("'" + ip.replace("'", "") + "'" for ip in ips)
    return f"({escaped})"


def _sql_epoch(expr: str) -> str:
    """Cross-dialect timestamp -> Unix epoch seconds (Spark SQL vs DuckDB)."""
    return f"UNIX_TIMESTAMP({expr})" if RUNNING_IN_DBX else f"EXTRACT(EPOCH FROM {expr})"


def _sql_split_part(expr: str, delim: str, one_based_idx: int) -> str:
    """Cross-dialect ANSI-safe string split helper (Spark SQL GET(SPLIT(...), idx) vs DuckDB 1-based SPLIT_PART)."""
    if RUNNING_IN_DBX:
        spark_delim = "\\\\." if delim == "." else delim
        return f"GET(SPLIT({expr}, '{spark_delim}'), {one_based_idx - 1})"
    return f"SPLIT_PART({expr}, '{delim}', {one_based_idx})"


def _sql_lookback_filter(ts_col: str, cfg: dict[str, Any]) -> str:
    """Cross-dialect lookback window predicate enforcing CONFIG['lookback_hours'] on every hunt."""
    hours = max(1, int(cfg.get("lookback_hours", 72)))
    if RUNNING_IN_DBX:
        return f"{ts_col} >= TIMESTAMPADD(HOUR, -{hours}, CURRENT_TIMESTAMP())"
    return f"{ts_col} >= CURRENT_TIMESTAMP - INTERVAL '{hours} hours'"


def _sql_regex(expr: str, pattern: str) -> str:
    """Cross-dialect regex predicate (Spark SQL RLIKE with SQL-escaped backslashes vs DuckDB REGEXP_MATCHES)."""
    if RUNNING_IN_DBX:
        spark_pat = pattern.replace("\\", "\\\\")
        return f"{expr} RLIKE '{spark_pat}'"
    return f"REGEXP_MATCHES({expr}, '{pattern}')"


# COMMAND ----------

# MAGIC %md
# MAGIC ## 2. Dual-Mode Read-Only Query Engine (Spark SQL in DBX / In-Memory DuckDB Locally)

# COMMAND ----------

class LocalReadOnlyDuckDB:
    """In-memory synthetic telemetry store mirroring YAF IPFIX / SSL / HTTP / DNS / Entra / GCP schemas for local preview."""

    def __init__(self) -> None:
        import duckdb

        self.con = duckdb.connect(database=":memory:")
        self._seed_synthetic_demo_tables()

    def _seed_synthetic_demo_tables(self) -> None:
        now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)

        def _ago(hours: float = 0.0, minutes: float = 0.0, seconds: float = 0.0) -> str:
            return (now - timedelta(hours=hours, minutes=minutes, seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S")

        # 1. Bidirectional IPFIX / flow table
        self.con.execute(
            """
            CREATE TEMP TABLE default_ipfix_flows (
                flow_ts TIMESTAMP,
                src_ip VARCHAR,
                dst_ip VARCHAR,
                dst_port INTEGER,
                octetTotalCount BIGINT,
                reverseOctetTotalCount BIGINT,
                silkAppLabel INTEGER,
                sslServerName VARCHAR,
                ja4 VARCHAR
            )
            """
        )
        flow_rows = [
            # Attack 1: Encrypted TLS 1.3 Sawtooth growing-context LLM proxy (0 IOCs, port 443)
            (_ago(hours=2, minutes=10, seconds=0), "10.20.30.40", "198.51.100.244", 443, 4200, 1800, 443, "relay-01.example-vps.net", "t13d1516h2_8daaf6152771_b186095e22b6"),
            (_ago(hours=2, minutes=9, seconds=42), "10.20.30.40", "198.51.100.244", 443, 9800, 2100, 443, "relay-01.example-vps.net", "t13d1516h2_8daaf6152771_b186095e22b6"),
            (_ago(hours=2, minutes=9, seconds=21), "10.20.30.40", "198.51.100.244", 443, 17400, 1950, 443, "relay-01.example-vps.net", "t13d1516h2_8daaf6152771_b186095e22b6"),
            (_ago(hours=2, minutes=8, seconds=58), "10.20.30.40", "198.51.100.244", 443, 28900, 2300, 443, "relay-01.example-vps.net", "t13d1516h2_8daaf6152771_b186095e22b6"),
            (_ago(hours=2, minutes=8, seconds=32), "10.20.30.40", "198.51.100.244", 443, 44100, 2400, 443, "relay-01.example-vps.net", "t13d1516h2_8daaf6152771_b186095e22b6"),
            # Attack 2: Port-independent ARTEX console (:8787) + Raw-IP TLS (ja4 pos 4 = 'i')
            (_ago(hours=2, minutes=5, seconds=10), "10.20.30.41", "203.0.113.120", 8787, 3500, 6200, 80, "", "t13i1516h2_000011112222_333344445555"),
            (_ago(hours=2, minutes=5, seconds=0), "10.20.30.41", "203.0.113.121", 443, 22500, 3100, 443, "", "t13i1516h2_aaaa11112222_333344445555"),
            # Attack 5: Compromised web server 10.50.1.10 calling back to probing IP 203.0.113.88 on :8443
            (_ago(hours=1, minutes=49, seconds=35), "10.50.1.10", "203.0.113.88", 8443, 6400, 1200, 443, "", "t13i1516h2_111122223333_444455556666"),
            # Attack 7: Compromised app server 10.50.2.15 sweeping 5 internal hosts on SMB/WinRM in 12s
            (_ago(hours=1, minutes=30, seconds=12), "10.50.2.15", "10.50.9.11", 5985, 1400, 900, 0, "", ""),
            (_ago(hours=1, minutes=30, seconds=9), "10.50.2.15", "10.50.9.12", 445, 1400, 900, 0, "", ""),
            (_ago(hours=1, minutes=30, seconds=6), "10.50.2.15", "10.50.9.13", 5985, 1400, 900, 0, "", ""),
            (_ago(hours=1, minutes=30, seconds=3), "10.50.2.15", "10.50.9.14", 445, 1400, 900, 0, "", ""),
            (_ago(hours=1, minutes=30, seconds=0), "10.50.2.15", "10.50.9.15", 5985, 1400, 900, 0, "", ""),
            # Benign Baseline: Steady-size S3/CDN uploads (flat bytes_out, NOT sawtooth) + 2-host SMB backup
            (_ago(hours=2, minutes=8, seconds=20), "10.90.1.5", "198.51.100.10", 443, 250000, 450, 443, "s3.amazonaws.com", "t13d1516h2_8daaf6152771_b186095e22b6"),
            (_ago(hours=2, minutes=8, seconds=10), "10.90.1.5", "198.51.100.10", 443, 249800, 460, 443, "s3.amazonaws.com", "t13d1516h2_8daaf6152771_b186095e22b6"),
            (_ago(hours=2, minutes=8, seconds=0), "10.90.1.5", "198.51.100.10", 443, 250100, 440, 443, "s3.amazonaws.com", "t13d1516h2_8daaf6152771_b186095e22b6"),
            (_ago(hours=2, minutes=6, seconds=30), "10.90.1.8", "10.50.9.20", 445, 85000, 1200, 0, "", ""),
            (_ago(hours=2, minutes=6, seconds=0), "10.90.1.8", "10.50.9.21", 445, 84000, 1100, 0, "", ""),
        ]
        self.con.executemany("INSERT INTO default_ipfix_flows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", flow_rows)

        # 2. SSL/TLS cert metadata table (JA4X + JA4S clustering)
        self.con.execute(
            """
            CREATE TEMP TABLE ssl_flows (
                flow_ts TIMESTAMP,
                src_ip VARCHAR,
                dst_ip VARCHAR,
                dst_port INTEGER,
                sslServerName VARCHAR,
                ja4s VARCHAR,
                ja4x VARCHAR
            )
            """
        )
        ssl_rows = [
            # Attack 4: Self-signed bespoke cert cluster (ja4x_a == ja4x_b) across 2 operator consoles
            (_ago(hours=2, minutes=5), "10.20.30.41", "203.0.113.120", 8787, "", "t130200_1301_a56c5b993250", "7022c563de38_7022c563de38_e7b1c49d2a10"),
            (_ago(hours=2, minutes=4), "10.20.30.42", "203.0.113.122", 8090, "", "t130200_1301_a56c5b993250", "7022c563de38_7022c563de38_e7b1c49d2a10"),
            # Benign Baseline: Public CA cert (ja4x_a != ja4x_b) on :443
            (_ago(hours=2, minutes=9), "10.90.1.5", "198.51.100.10", 443, "s3.amazonaws.com", "t130200_1301_234abc", "2bab15409345_552211009988_112233445566"),
        ]
        self.con.executemany("INSERT INTO ssl_flows VALUES (?, ?, ?, ?, ?, ?, ?)", ssl_rows)

        # 3. HTTP table (JA4 whiplash, JA4 Proxy-Collapse, Browser-UA impersonation, Ruby2Shell 5xx ramp, callbacks)
        self.con.execute(
            """
            CREATE TEMP TABLE http_flows (
                flow_ts TIMESTAMP,
                src_ip VARCHAR,
                dst_ip VARCHAR,
                dst_port INTEGER,
                sslServerName VARCHAR,
                http_method VARCHAR,
                http_path VARCHAR,
                http_status INTEGER,
                http_ua VARCHAR,
                ja4 VARCHAR,
                ja4h VARCHAR,
                bytes_out BIGINT
            )
            """
        )
        http_rows = [
            # Attack 3: Spoofed identical UA cycling 3 distinct JA4/JA4H stacks with 403/404 errors
            (_ago(hours=1, minutes=55, seconds=8), "203.0.113.77", "10.50.1.10", 443, "portal.corp.local", "GET", "/api/v1/admin", 403, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_aaa111_bbb111", "ge11cn200000_111_000_000", 420),
            (_ago(hours=1, minutes=55, seconds=4), "203.0.113.77", "10.50.1.10", 443, "portal.corp.local", "GET", "/api/v1/users", 404, "Mozilla/5.0 Chrome/131.0", "t13d190900_ccc222_ddd222", "ge11nn040000_222_000_000", 430),
            (_ago(hours=1, minutes=55, seconds=0), "203.0.113.77", "10.50.1.10", 443, "portal.corp.local", "POST", "/api/v1/export", 401, "Mozilla/5.0 Chrome/131.0", "t12d080800_eee333_fff333", "po11nn030000_333_000_000", 440),
            # Attack 5 trigger: External IP 203.0.113.88 probes web server 10.50.1.10
            (_ago(hours=1, minutes=50, seconds=0), "203.0.113.88", "10.50.1.10", 443, "portal.corp.local", "POST", "/api/render", 200, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_444_000_000", 600),
            # Attack 6 trigger: External IP 203.0.113.99 probes web server 10.50.1.11
            (_ago(hours=1, minutes=40, seconds=14), "203.0.113.99", "10.50.1.11", 443, "api.corp.local", "POST", "/v2/import", 200, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_555_000_000", 620),
            # Attack 8: Recording-Proxy Collapse (1 JA4 from mitmproxy, 3 JA4Hs, 3 UA families, 3x 4xx)
            (_ago(hours=1, minutes=20, seconds=6), "203.0.113.150", "10.50.1.12", 443, "app.corp.local", "GET", "/api/v1/secrets", 403, "curl/8.5.0", "t13d1311h2_f57a46bbacb6_e7c285222651", "ge11nn030000_fe444ad14866_000000000000_000000000000", 210),
            (_ago(hours=1, minutes=20, seconds=3), "203.0.113.150", "10.50.1.12", 443, "app.corp.local", "GET", "/api/v1/tokens", 404, "python-httpx/0.28.1", "t13d1311h2_f57a46bbacb6_e7c285222651", "ge11nn050000_be0d0b335e46_000000000000_000000000000", 240),
            (_ago(hours=1, minutes=20, seconds=0), "203.0.113.150", "10.50.1.12", 443, "app.corp.local", "GET", "/_i6084_probe_missing", 404, "Go-http-client/1.1", "t13d1311h2_f57a46bbacb6_e7c285222651", "ge11nn030000_cd680697de12_000000000000_000000000000", 220),
            # Attack 9: Ruby2Shell Zero-IOC monotonic 500/502 heap-grooming ramp + 200 recovery
            (_ago(hours=1, minutes=10, seconds=3), "198.51.100.160", "10.50.1.15", 443, "rails.corp.local", "POST", "/api/v1/rails-form", 502, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_999_000_000", 64),
            (_ago(hours=1, minutes=10, seconds=2), "198.51.100.160", "10.50.1.15", 443, "rails.corp.local", "POST", "/api/v1/rails-form", 502, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_999_000_000", 128),
            (_ago(hours=1, minutes=10, seconds=1), "198.51.100.160", "10.50.1.15", 443, "rails.corp.local", "POST", "/api/v1/rails-form", 500, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_999_000_000", 256),
            (_ago(hours=1, minutes=10, seconds=0), "198.51.100.160", "10.50.1.15", 443, "rails.corp.local", "POST", "/api/v1/rails-form", 200, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_999_000_000", 384),
            # Benign Baseline A: Allowlisted scanner IP (excluded by scanner_allowlist_csv)
            (_ago(hours=1, minutes=51, seconds=2), "198.51.100.250", "10.50.1.10", 443, "portal.corp.local", "GET", "/test1", 404, "QualysGuard", "t13d111_1_1", "ge11_1_0_0", 180),
            (_ago(hours=1, minutes=51, seconds=1), "198.51.100.250", "10.50.1.10", 443, "portal.corp.local", "GET", "/test2", 404, "QualysGuard", "t13d222_2_2", "ge11_2_0_0", 180),
            (_ago(hours=1, minutes=51, seconds=0), "198.51.100.250", "10.50.1.10", 443, "portal.corp.local", "GET", "/test3", 404, "QualysGuard", "t13d333_3_3", "ge11_3_0_0", 180),
            # Benign Baseline B: Real Chrome user + honest curl client + random-size 503 API blip (0 FP!)
            (_ago(hours=1, minutes=5), "198.51.100.210", "10.50.1.15", 443, "rails.corp.local", "GET", "/dashboard", 200, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "ge11cn14enus_60a1_000_000", 320),
            (_ago(hours=1, minutes=4), "198.51.100.211", "10.50.1.15", 443, "rails.corp.local", "GET", "/healthz", 200, "curl/8.5.0", "t13d1311h2_f57a46_e7c285", "ge11nn030000_fe44_000_000", 120),
            (_ago(hours=1, minutes=3, seconds=4), "198.51.100.212", "10.50.1.15", 443, "rails.corp.local", "POST", "/api/v1/orders", 503, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_60a1_000_000", 512),
            (_ago(hours=1, minutes=3, seconds=2), "198.51.100.212", "10.50.1.15", 443, "rails.corp.local", "POST", "/api/v1/orders", 503, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_60a1_000_000", 190),
            (_ago(hours=1, minutes=3, seconds=0), "198.51.100.212", "10.50.1.15", 443, "rails.corp.local", "POST", "/api/v1/orders", 503, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_60a1_000_000", 410),
        ]
        self.con.executemany("INSERT INTO http_flows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", http_rows)

        # 4. DNS table (Custom-domain high-entropy OOB DNS callback after web probe + benign CDN DNS)
        self.con.execute(
            """
            CREATE TEMP TABLE dns_flows (
                flow_ts TIMESTAMP,
                src_ip VARCHAR,
                dst_ip VARCHAR,
                dst_port INTEGER,
                dns_query VARCHAR
            )
            """
        )
        dns_rows = [
            # Attack 6: High-entropy hex-prefixed OOB DNS lookup 14s after probe from 10.50.1.11
            (_ago(hours=1, minutes=40, seconds=0), "10.50.1.11", "10.50.0.53", 53, "f4a8c19e02b7d3.oob-collector.example"),
            # Benign Baseline: CloudFront hex-looking domain + normal Stripe API lookup (must NOT trigger)
            (_ago(hours=1, minutes=40, seconds=4), "10.50.1.11", "10.50.0.53", 53, "d111111abcdef8.cloudfront.net"),
            (_ago(hours=1, minutes=40, seconds=2), "10.50.1.11", "10.50.0.53", 53, "api.stripe.example"),
        ]
        self.con.executemany("INSERT INTO dns_flows VALUES (?, ?, ?, ?, ?)", dns_rows)

        # 5. Entra ID Service Principal Sign-In table (Storm-0940 zero-401 multi-IP /16 replay + benign SaaS backups)
        self.con.execute(
            """
            CREATE TEMP TABLE entra_sp_logs (
                created_ts TIMESTAMP,
                ip_address VARCHAR,
                service_principal_name VARCHAR,
                resource_display_name VARCHAR,
                result_type VARCHAR
            )
            """
        )
        sp_rows = [
            # Attack 10: Zero-401 stolen SP replayed across 3 distinct external /16 prefixes + 4 M365/Vault resources
            (_ago(minutes=50), "198.51.100.51", "Backup-Connector-SP", "Microsoft Graph", "0"),
            (_ago(minutes=48), "203.0.113.52", "Backup-Connector-SP", "Office 365 Exchange Online", "0"),
            (_ago(minutes=46), "192.0.2.53", "Backup-Connector-SP", "Office 365 SharePoint Online", "0"),
            (_ago(minutes=44), "192.0.2.54", "Backup-Connector-SP", "Azure Key Vault", "0"),
            # Benign Baseline: Static single-IP Veeam backup + single-/16 Azure cluster + RFC1918 sync SP
            (_ago(minutes=40, seconds=15), "203.0.113.200", "Veeam-O365-Backup-SP", "Microsoft Graph", "0"),
            (_ago(minutes=40, seconds=10), "203.0.113.200", "Veeam-O365-Backup-SP", "Office 365 Exchange Online", "0"),
            (_ago(minutes=40, seconds=5), "203.0.113.200", "Veeam-O365-Backup-SP", "Office 365 SharePoint Online", "0"),
            (_ago(minutes=40, seconds=0), "203.0.113.200", "Veeam-O365-Backup-SP", "Microsoft Teams Services", "0"),
            (_ago(minutes=35, seconds=20), "198.51.1.10", "Same16-Worker-SP", "Microsoft Graph", "0"),
            (_ago(minutes=35, seconds=10), "198.51.2.10", "Same16-Worker-SP", "Office 365 Exchange Online", "0"),
            (_ago(minutes=35, seconds=0), "198.51.3.10", "Same16-Worker-SP", "Office 365 SharePoint Online", "0"),
            (_ago(minutes=30, seconds=10), "10.50.0.10", "Internal-Sync-SP", "Microsoft Graph", "0"),
            (_ago(minutes=30, seconds=5), "10.51.0.11", "Internal-Sync-SP", "Office 365 Exchange Online", "0"),
            (_ago(minutes=30, seconds=0), "10.52.0.12", "Internal-Sync-SP", "Azure Key Vault", "0"),
        ]
        self.con.executemany("INSERT INTO entra_sp_logs VALUES (?, ?, ?, ?, ?)", sp_rows)

        # 6. GCP Cloud Audit table (Bitrise ARTEX multi-SA + PERMISSION_DENIED -> Secret Manager + benign baselines)
        self.con.execute(
            """
            CREATE TEMP TABLE gcp_audit_logs (
                event_ts TIMESTAMP,
                caller_ip VARCHAR,
                principal_email VARCHAR,
                service_name VARCHAR,
                method_name VARCHAR,
                resource_name VARCHAR,
                grpc_code INTEGER
            )
            """
        )
        gcp_rows = [
            # Attack 11: Single external IP operating 3 distinct SAs + PERMISSION_DENIED -> AccessSecretVersion
            (_ago(minutes=25, seconds=60), "198.51.100.77", "ci-worker-01@prod-proj.iam.gserviceaccount.com", "storage.googleapis.com", "storage.buckets.list", "projects/prod-proj", 7),
            (_ago(minutes=25, seconds=58), "198.51.100.77", "ci-worker-01@prod-proj.iam.gserviceaccount.com", "compute.googleapis.com", "v1.compute.instances.list", "projects/prod-proj", 7),
            (_ago(minutes=25, seconds=56), "198.51.100.77", "ci-worker-01@prod-proj.iam.gserviceaccount.com", "iam.googleapis.com", "google.iam.admin.v1.ListServiceAccounts", "projects/prod-proj", 7),
            (_ago(minutes=25, seconds=54), "198.51.100.77", "ci-worker-01@prod-proj.iam.gserviceaccount.com", "secretmanager.googleapis.com", "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion", "projects/123/secrets/prod-key/versions/latest", 0),
            (_ago(minutes=25, seconds=30), "198.51.100.77", "deploy-bot-02@prod-proj.iam.gserviceaccount.com", "cloudresourcemanager.googleapis.com", "GetIamPolicy", "projects/prod-proj", 7),
            (_ago(minutes=25, seconds=0), "198.51.100.77", "1234567890-compute@developer.gserviceaccount.com", "iamcredentials.googleapis.com", "GenerateAccessToken", "projects/prod-proj", 0),
            # Benign Baselines: Terraform SA + Google-managed service agents + 3 human NAT engineers + routine app fetching 2 secrets
            (_ago(minutes=20, seconds=6), "198.51.100.120", "terraform-deploy@prod-proj.iam.gserviceaccount.com", "iam.googleapis.com", "SetIamPolicy", "projects/prod-proj", 0),
            (_ago(minutes=20, seconds=4), "198.51.100.120", "service-123@gcp-sa-gke.iam.gserviceaccount.com", "compute.googleapis.com", "v1.compute.instances.list", "projects/prod-proj", 0),
            (_ago(minutes=20, seconds=2), "198.51.100.120", "123@cloudservices.gserviceaccount.com", "compute.googleapis.com", "v1.compute.instances.list", "projects/prod-proj", 0),
            (_ago(minutes=20, seconds=0), "198.51.100.120", "gke-system@prod-proj.iam.gserviceaccount.com", "container.googleapis.com", "GetCluster", "projects/prod-proj", 0),
            (_ago(minutes=18, seconds=10), "198.51.100.200", "alice@corp.example", "compute.googleapis.com", "v1.compute.instances.list", "projects/prod-proj", 0),
            (_ago(minutes=18, seconds=5), "198.51.100.200", "bob@corp.example", "storage.googleapis.com", "storage.buckets.list", "projects/prod-proj", 0),
            (_ago(minutes=18, seconds=0), "198.51.100.200", "carol@corp.example", "bigquery.googleapis.com", "jobservice.list", "projects/prod-proj", 0),
            (_ago(minutes=15, seconds=1), "203.0.113.15", "app-backend@prod-proj.iam.gserviceaccount.com", "secretmanager.googleapis.com", "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion", "projects/123/secrets/db-pass/versions/latest", 0),
            (_ago(minutes=15, seconds=0), "203.0.113.15", "app-backend@prod-proj.iam.gserviceaccount.com", "secretmanager.googleapis.com", "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion", "projects/123/secrets/stripe-key/versions/latest", 0),
        ]
        self.con.executemany("INSERT INTO gcp_audit_logs VALUES (?, ?, ?, ?, ?, ?, ?)", gcp_rows)

    def query(self, sql: str) -> list[dict[str, Any]]:
        assert_read_only_sql(sql)
        cur = self.con.execute(sql)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


_LOCAL_ENGINE: LocalReadOnlyDuckDB | None = None


def run_readonly_query(sql: str) -> list[dict[str, Any]]:
    """Execute strictly read-only SQL on Databricks Spark (in DBX) or in-memory DuckDB (locally)."""
    assert_read_only_sql(sql)
    if RUNNING_IN_DBX:
        df = spark.sql(sql)  # type: ignore[name-defined]
        return [row.asDict(recursive=True) for row in df.limit(500).collect()]
    global _LOCAL_ENGINE
    if _LOCAL_ENGINE is None:
        _LOCAL_ENGINE = LocalReadOnlyDuckDB()
    return _LOCAL_ENGINE.query(sql)


# COMMAND ----------

# MAGIC %md
# MAGIC ## 3. Positive-Control Schema Validator (Proves Tables & Columns Populate Before Hunting)

# COMMAND ----------

def run_positive_control_check(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    c = cfg["cols"]
    checks = [
        ("flow_table", cfg["flow_table"], c["ts"]),
        ("ssl_table", cfg["ssl_table"], c["ts"]),
        ("http_table", cfg["http_table"], c["ts"]),
        ("dns_table", cfg["dns_table"], c["ts"]),
        ("entra_sp_table", cfg["entra_sp_table"], c["sp_ts"]),
        ("gcp_audit_table", cfg["gcp_audit_table"], c["gcp_ts"]),
    ]
    results = []
    for label, table_name, ts_col in checks:
        if not table_name:
            results.append({"dataset": label, "table": "(unconfigured)", "status": "SKIPPED", "row_count": 0})
            continue
        sql = f"SELECT COUNT(*) AS row_count, MAX({ts_col}) AS latest_ts FROM {table_name}"
        try:
            rows = run_readonly_query(sql)
            cnt = int(rows[0]["row_count"]) if rows else 0
            results.append({"dataset": label, "table": table_name, "status": "OK" if cnt > 0 else "EMPTY", "row_count": cnt})
        except Exception as exc:
            results.append({"dataset": label, "table": table_name, "status": f"SCHEMA_ERROR: {exc}", "row_count": 0})
    return results


# COMMAND ----------

# MAGIC %md
# MAGIC ## 4. Plug-and-Play Read-Only Behavioral Hunt Registry (11 Built-In Hunts — v0.2.6 Parity)

# COMMAND ----------

@dataclass(frozen=True)
class HuntSpec:
    hunt_id: str
    title: str
    risk_score: int
    alert_tier: str
    required_datasets: tuple[str, ...]
    sql_builder: Callable[[dict[str, Any]], str]


HUNT_REGISTRY: list[HuntSpec] = []


def register_hunt(
    hunt_id: str,
    title: str,
    risk_score: int,
    alert_tier: str,
    required_datasets: tuple[str, ...] = ("flow_table",),
):
    """Decorator to plug any new strictly read-only behavioral hunt into the unified dashboard."""
    def _wrap(fn: Callable[[dict[str, Any]], str]) -> Callable[[dict[str, Any]], str]:
        HUNT_REGISTRY.append(HuntSpec(hunt_id, title, risk_score, alert_tier, required_datasets, fn))
        return fn
    return _wrap


@register_hunt("HUNT_01_SAWTOOTH_LLM_PROXY", "Encrypted TLS 1.3 Sawtooth Growing-Context LLM Proxy", 70, "alert", ("flow_table",))
def sql_hunt_01_sawtooth(cfg: dict[str, Any]) -> str:
    c = cfg["cols"]
    t = cfg["flow_table"]
    lb = _sql_lookback_filter(c["ts"], cfg)
    return f"""
    WITH ordered AS (
        SELECT
            {c['src_ip']} AS src_ip,
            COALESCE(NULLIF({c['sni']}, ''), {c['dst_ip']}) AS target,
            {c['ts']} AS ts,
            {c['bytes_out']} AS b_out,
            {c['bytes_in']} AS b_in,
            LAG({c['bytes_out']}) OVER (
                PARTITION BY {c['src_ip']}, COALESCE(NULLIF({c['sni']}, ''), {c['dst_ip']})
                ORDER BY {c['ts']}
            ) AS prev_out
        FROM {t}
        WHERE {lb}
          AND {c['dst_port']} = 443
          AND {c['bytes_in']} BETWEEN 300 AND 50000
    ),
    turns AS (
        SELECT *,
            CASE WHEN prev_out IS NOT NULL AND (b_out - prev_out) >= 1500 THEN 1 ELSE 0 END AS grow_turn,
            CASE WHEN prev_out IS NOT NULL AND b_out <= prev_out * 0.6 THEN 1 ELSE 0 END AS compact_drop
        FROM ordered
    )
    SELECT
        src_ip,
        target,
        COUNT(*) AS event_count,
        CAST(SUM(grow_turn) AS STRING) || ' growing turns, peak=' || CAST(MAX(b_out) AS STRING) || 'B' AS evidence
    FROM turns
    GROUP BY src_ip, target
    HAVING (SUM(grow_turn) >= 4 AND MAX(b_out) >= 12000 AND (MAX(b_out) * 1.0 / GREATEST(MIN(b_out), 1)) >= 2.5)
        OR (SUM(grow_turn) >= 5 AND SUM(compact_drop) >= 1 AND MAX(b_out) >= 10000)
    """


@register_hunt("HUNT_02_PORT_INDEP_CONSOLE_RAW_IP_TLS", "Port-Independent Console (:8787/:8788/:8790/:8890/:18899) & Raw-IP TLS (t13i)", 75, "alert", ("flow_table",))
def sql_hunt_02_console_raw_ip(cfg: dict[str, Any]) -> str:
    c = cfg["cols"]
    t = cfg["flow_table"]
    lb = _sql_lookback_filter(c["ts"], cfg)
    return f"""
    SELECT
        {c['src_ip']} AS src_ip,
        {c['dst_ip']} || ':' || CAST({c['dst_port']} AS STRING) AS target,
        COUNT(*) AS event_count,
        'app=' || CAST(MAX({c['app_label']}) AS STRING) || ', ja4=' || COALESCE(MAX({c['ja4']}), '') AS evidence
    FROM {t}
    WHERE {lb}
      AND (
        ({c['app_label']} IN (80, 443) AND {c['dst_port']} IN (8787, 8788, 8790, 8890, 18899))
        OR (SUBSTRING({c['ja4']}, 4, 1) = 'i' AND {c['dst_port']} = 443 AND {c['bytes_out']} >= 12000)
      )
    GROUP BY {c['src_ip']}, {c['dst_ip']}, {c['dst_port']}
    """


@register_hunt("HUNT_03_NAT_SAFE_JA4_WHIPLASH", "NAT-Safe JA4/JA4H Client Stack Whiplash", 70, "alert", ("http_table",))
def sql_hunt_03_ja4_whiplash(cfg: dict[str, Any]) -> str:
    c = cfg["cols"]
    t = cfg["http_table"]
    allow_sql = _scanner_sql_list(cfg)
    lb = _sql_lookback_filter(c["ts"], cfg)
    return f"""
    SELECT
        {c['src_ip']} AS src_ip,
        COALESCE(NULLIF({c['sni']}, ''), {c['dst_ip']}) AS target,
        COUNT(*) AS event_count,
        'distinct_ja4=' || CAST(COUNT(DISTINCT {c['ja4']}) AS STRING)
            || ', distinct_uas=' || CAST(COUNT(DISTINCT {c['http_ua']}) AS STRING)
            || ', errs=' || CAST(SUM(CASE WHEN {c['http_status']} >= 400 THEN 1 ELSE 0 END) AS STRING) AS evidence
    FROM {t}
    WHERE {lb}
      AND {c['src_ip']} NOT IN {allow_sql}
    GROUP BY {c['src_ip']}, COALESCE(NULLIF({c['sni']}, ''), {c['dst_ip']})
    HAVING (COUNT(DISTINCT {c['ja4']}) >= 3 OR COUNT(DISTINCT {c['ja4h']}) >= 3)
       AND (COUNT(DISTINCT {c['http_ua']}) <= 1 OR SUM(CASE WHEN {c['http_status']} >= 400 THEN 1 ELSE 0 END) >= 3)
    """


@register_hunt("HUNT_04_JA4X_C_SELF_SIGNED_CLUSTERS", "Self-Signed Bespoke Cert Clustering (JA4X_c + JA4S)", 65, "hunt", ("ssl_table",))
def sql_hunt_04_ja4x_clusters(cfg: dict[str, Any]) -> str:
    c = cfg["cols"]
    t = cfg["ssl_table"]
    lb = _sql_lookback_filter(c["ts"], cfg)
    part_a = f"COALESCE({_sql_split_part(c['ja4x'], '_', 1)}, '')"
    part_b = f"COALESCE({_sql_split_part(c['ja4x'], '_', 2)}, '')"
    part_c = f"COALESCE({_sql_split_part(c['ja4x'], '_', 3)}, '')"
    return f"""
    WITH parsed AS (
        SELECT
            {c['src_ip']} AS src_ip,
            {c['dst_ip']} AS dst_ip,
            {c['dst_port']} AS dst_port,
            COALESCE({c['ja4s']}, '') AS ja4s,
            {part_a} AS ja4x_a,
            {part_b} AS ja4x_b,
            {part_c} AS ja4x_c
        FROM {t}
        WHERE {lb}
          AND {c['ja4x']} IS NOT NULL AND {c['ja4x']} <> ''
    )
    SELECT
        MIN(src_ip) AS src_ip,
        'ja4x_c=' || ja4x_c || ' | ja4s=' || ja4s AS target,
        COUNT(DISTINCT dst_ip) AS event_count,
        'self_signed_cluster_ips=' || CAST(COUNT(DISTINCT dst_ip) AS STRING) AS evidence
    FROM parsed
    WHERE ja4x_a <> '' AND ja4x_a = ja4x_b AND ja4x_c <> ''
      AND (dst_port IN (8787, 8788, 8790, 8890, 8080, 8090, 8443) OR ja4x_c <> '')
    GROUP BY ja4x_c, ja4s
    HAVING COUNT(DISTINCT dst_ip) >= 1
    """


@register_hunt("HUNT_05_SERVER_CALLBACK_ON_PROBE", "Zero-IOC Server Callback to Probing IP (<=10m)", 90, "alert", ("http_table", "flow_table"))
def sql_hunt_05_server_callback(cfg: dict[str, Any]) -> str:
    c = cfg["cols"]
    ht = cfg["http_table"]
    ft = cfg["flow_table"]
    out_ts = f"out_f.{c['ts']}"
    in_ts = f"in_h.{c['ts']}"
    lb_in = _sql_lookback_filter(in_ts, cfg)
    lb_out = _sql_lookback_filter(out_ts, cfg)
    return f"""
    SELECT
        out_f.{c['src_ip']} AS src_ip,
        in_h.{c['src_ip']} || ':' || CAST(MAX(out_f.{c['dst_port']}) AS STRING) AS target,
        COUNT(*) AS event_count,
        'probing_ip=' || in_h.{c['src_ip']} || ' probed ' || MAX(in_h.{c['http_path']}) || ' then received callback' AS evidence
    FROM {ht} in_h
    JOIN {ft} out_f
      ON out_f.{c['src_ip']} = in_h.{c['dst_ip']}
     AND out_f.{c['dst_ip']} = in_h.{c['src_ip']}
     AND {out_ts} >= {in_ts}
     AND ({_sql_epoch(out_ts)} - {_sql_epoch(in_ts)}) <= 600
    WHERE {lb_in}
      AND {lb_out}
      AND in_h.{c['src_ip']} <> in_h.{c['dst_ip']}
    GROUP BY out_f.{c['src_ip']}, in_h.{c['src_ip']}
    """


@register_hunt("HUNT_06_OOB_DNS_AFTER_PROBE", "Custom-Domain High-Entropy OOB DNS Callback After Web Probe (<=90s)", 85, "alert", ("http_table", "dns_table"))
def sql_hunt_06_oob_dns(cfg: dict[str, Any]) -> str:
    c = cfg["cols"]
    ht = cfg["http_table"]
    dt = cfg["dns_table"]
    dns_col = f"d.{c['dns_query']}"
    d_ts = f"d.{c['ts']}"
    h_ts = f"h.{c['ts']}"
    lb_h = _sql_lookback_filter(h_ts, cfg)
    lb_d = _sql_lookback_filter(d_ts, cfg)
    left_label = f"LOWER(COALESCE({_sql_split_part(dns_col, '.', 1)}, ''))"
    hex_cond = _sql_regex(left_label, "^[a-f0-9]{10,}$")
    return f"""
    SELECT
        d.{c['src_ip']} AS src_ip,
        {dns_col} AS target,
        COUNT(*) AS event_count,
        'oob_dns_after_probe_by=' || MIN(h.{c['src_ip']}) AS evidence
    FROM {ht} h
    JOIN {dt} d
      ON d.{c['src_ip']} = h.{c['dst_ip']}
     AND {d_ts} >= {h_ts}
     AND ({_sql_epoch(d_ts)} - {_sql_epoch(h_ts)}) <= 90
    WHERE {lb_h}
      AND {lb_d}
      AND {hex_cond}
      AND LOWER({dns_col}) NOT LIKE '%.cloudfront.net'
      AND LOWER({dns_col}) NOT LIKE '%.amazonaws.com'
      AND LOWER({dns_col}) NOT LIKE '%.akamaiedge.net'
      AND LOWER({dns_col}) NOT LIKE '%.corp.local'
    GROUP BY d.{c['src_ip']}, {dns_col}
    """


@register_hunt("HUNT_07_LATERAL_FANOUT_SMB_WINRM", "Machine-Speed SMB / WinRM Lateral Fan-Out (>=4 Internal Targets)", 80, "alert", ("flow_table",))
def sql_hunt_07_lateral_fanout(cfg: dict[str, Any]) -> str:
    c = cfg["cols"]
    t = cfg["flow_table"]
    lb = _sql_lookback_filter(c["ts"], cfg)
    max_ts = f"MAX({c['ts']})"
    min_ts = f"MIN({c['ts']})"
    span_expr = f"({_sql_epoch(max_ts)} - {_sql_epoch(min_ts)})"
    return f"""
    SELECT
        {c['src_ip']} AS src_ip,
        CAST(COUNT(DISTINCT {c['dst_ip']}) AS STRING) || ' internal peers' AS target,
        COUNT(*) AS event_count,
        'ports_swept_span_sec=' || CAST(CAST({span_expr} AS INT) AS STRING) AS evidence
    FROM {t}
    WHERE {lb}
      AND {c['dst_port']} IN (445, 5985, 5986, 135, 3389, 22)
      AND {c['src_ip']} <> {c['dst_ip']}
    GROUP BY {c['src_ip']}
    HAVING COUNT(DISTINCT {c['dst_ip']}) >= 4
       AND {span_expr} <= 120
    """


@register_hunt("HUNT_08_JA4_PROXY_COLLAPSE_OR_IMPERSONATION", "Single-JA4 Recording-Proxy Collapse or Browser-UA Stack Impersonation", 75, "alert", ("http_table",))
def sql_hunt_08_ja4_proxy_collapse(cfg: dict[str, Any]) -> str:
    c = cfg["cols"]
    t = cfg["http_table"]
    allow_sql = _scanner_sql_list(cfg)
    lb = _sql_lookback_filter(c["ts"], cfg)
    ua_low = f"LOWER(COALESCE({c['http_ua']}, ''))"
    ja4h_low = f"LOWER(COALESCE({c['ja4h']}, ''))"
    stripped_ja4h = _sql_regex(ja4h_low, "^[a-z]{2}[0-9]{2}nn0[0-5]0000_")
    return f"""
    WITH tagged AS (
        SELECT
            {c['src_ip']} AS src_ip,
            COALESCE(NULLIF({c['sni']}, ''), {c['dst_ip']}) AS target,
            NULLIF({c['ja4']}, '') AS ja4,
            NULLIF({c['ja4h']}, '') AS ja4h,
            {c['http_status']} AS status_code,
            UPPER(COALESCE({c['http_method']}, '')) AS http_method,
            CASE
                WHEN {ua_low} = '' THEN NULL
                WHEN {ua_low} LIKE '%curl/%' THEN 'curl'
                WHEN {ua_low} LIKE '%python-httpx%' OR {ua_low} LIKE '%python-requests%' THEN 'python'
                WHEN {ua_low} LIKE '%go-http-client%' THEN 'go'
                WHEN {ua_low} LIKE '%chrome/%' OR {ua_low} LIKE '%firefox/%' OR {ua_low} LIKE '%safari/%' THEN 'browser'
                ELSE 'other'
            END AS ua_family,
            CASE
                WHEN ({ua_low} LIKE '%mozilla/5.0%' AND ({ua_low} LIKE '%chrome/%' OR {ua_low} LIKE '%firefox/%'))
                     AND {stripped_ja4h}
                     AND UPPER(COALESCE({c['http_method']}, '')) <> 'CONNECT'
                THEN 1 ELSE 0
            END AS is_ua_impersonation
        FROM {t}
        WHERE {lb}
          AND {c['src_ip']} NOT IN {allow_sql}
    )
    SELECT
        src_ip,
        target,
        COUNT(*) AS event_count,
        CASE
            WHEN COUNT(DISTINCT ja4) = 1 AND COUNT(DISTINCT ja4h) >= 3 AND COUNT(DISTINCT ua_family) >= 3
                 AND SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) >= 3
                THEN 'JA4_PROXY_COLLAPSE: ja4s=1, ja4hs=' || CAST(COUNT(DISTINCT ja4h) AS STRING) || ', ua_fams=' || CAST(COUNT(DISTINCT ua_family) AS STRING)
            ELSE 'BROWSER_UA_IMPERSONATION: stripped_ja4h_hits=' || CAST(SUM(is_ua_impersonation) AS STRING)
        END AS evidence
    FROM tagged
    GROUP BY src_ip, target
    HAVING (
            COUNT(DISTINCT ja4) = 1
            AND COUNT(DISTINCT ja4h) >= 3
            AND COUNT(DISTINCT ua_family) >= 3
            AND SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) >= 3
        )
        OR SUM(is_ua_impersonation) >= 2
    """


@register_hunt("HUNT_09_RUBY2SHELL_HEAP_GROOM_CRASH_LOOP", "Ruby2Shell Zero-IOC Monotonic 500/502 Heap-Grooming Crash Loop", 80, "alert", ("http_table",))
def sql_hunt_09_ruby2shell_crash_loop(cfg: dict[str, Any]) -> str:
    c = cfg["cols"]
    t = cfg["http_table"]
    allow_sql = _scanner_sql_list(cfg)
    lb = _sql_lookback_filter(c["ts"], cfg)
    return f"""
    WITH ordered AS (
        SELECT
            {c['src_ip']} AS src_ip,
            COALESCE(NULLIF({c['sni']}, ''), {c['dst_ip']}) || {c['http_path']} AS target,
            {c['ts']} AS ts,
            {c['http_status']} AS status_code,
            {c['http_bytes_out']} AS b_out,
            LAG({c['http_bytes_out']}) OVER (
                PARTITION BY {c['src_ip']}, COALESCE(NULLIF({c['sni']}, ''), {c['dst_ip']}), {c['http_path']}
                ORDER BY {c['ts']}
            ) AS prev_b_out,
            LAG({c['http_status']}) OVER (
                PARTITION BY {c['src_ip']}, COALESCE(NULLIF({c['sni']}, ''), {c['dst_ip']}), {c['http_path']}
                ORDER BY {c['ts']}
            ) AS prev_status
        FROM {t}
        WHERE {lb}
          AND {c['src_ip']} NOT IN {allow_sql}
          AND {c['http_status']} IN (200, 500, 502)
    ),
    stats AS (
        SELECT
            src_ip,
            target,
            COUNT(*) AS event_count,
            SUM(CASE WHEN status_code IN (500, 502) THEN 1 ELSE 0 END) AS crash_5xx,
            SUM(CASE WHEN status_code IN (500, 502) AND prev_status IN (500, 502) AND b_out > prev_b_out THEN 1 ELSE 0 END) AS monotonic_steps,
            SUM(CASE WHEN status_code = 200 AND prev_status IN (500, 502) THEN 1 ELSE 0 END) AS recovery_200,
            ({_sql_epoch('MAX(CASE WHEN status_code IN (500, 502) THEN ts END)')}
             - {_sql_epoch('MIN(CASE WHEN status_code IN (500, 502) THEN ts END)')}) AS crash_span_s
        FROM ordered
        GROUP BY src_ip, target
    )
    SELECT
        src_ip,
        target,
        event_count,
        'crashes=' || CAST(crash_5xx AS STRING) || ', monotonic_ramp_steps=' || CAST(monotonic_steps AS STRING) || ', span_s=' || CAST(CAST(crash_span_s AS INT) AS STRING) AS evidence
    FROM stats
    WHERE crash_5xx >= 3
      AND monotonic_steps >= 2
      AND recovery_200 >= 1
      AND (crash_span_s * 1.0 / GREATEST(crash_5xx - 1, 1)) <= 3.0
    """


@register_hunt("HUNT_10_STORM0940_PREAUTH_SP_REPLAY", "Storm-0940 Zero-401 Pre-Authorized Entra SP Multi-IP (/16) Replay", 85, "alert", ("entra_sp_table",))
def sql_hunt_10_storm0940_sp_replay(cfg: dict[str, Any]) -> str:
    c = cfg["cols"]
    t = cfg["entra_sp_table"]
    lb = _sql_lookback_filter(c["sp_ts"], cfg)
    ip_col = c["sp_ip"]
    p1 = f"COALESCE({_sql_split_part(ip_col, '.', 1)}, '')"
    p2 = f"COALESCE({_sql_split_part(ip_col, '.', 2)}, '')"
    v6_1 = f"COALESCE({_sql_split_part(ip_col, ':', 1)}, '')"
    v6_2 = f"COALESCE({_sql_split_part(ip_col, ':', 2)}, '')"
    v6_3 = f"COALESCE({_sql_split_part(ip_col, ':', 3)}, '')"
    rfc1918_re = _sql_regex(ip_col, "^(10\\.|127\\.|169\\.254\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|::1$|fe80:|f[cd][0-9a-f]{2}:)")
    return f"""
    WITH ext_ok AS (
        SELECT
            {c['sp_name']} AS sp_name,
            {ip_col} AS src_ip,
            CASE
                WHEN {ip_col} LIKE '%:%' THEN {v6_1} || ':' || {v6_2} || ':' || {v6_3}
                ELSE {p1} || '.' || {p2}
            END AS net_prefix,
            {c['sp_resource']} AS res_name,
            CASE
                WHEN LOWER({c['sp_resource']}) LIKE '%exchange%'
                  OR LOWER({c['sp_resource']}) LIKE '%sharepoint%'
                  OR LOWER({c['sp_resource']}) LIKE '%graph%'
                  OR LOWER({c['sp_resource']}) LIKE '%key vault%'
                  OR LOWER({c['sp_resource']}) LIKE '%teams%'
                THEN 1 ELSE 0
            END AS is_hv
        FROM {t}
        WHERE {lb}
          AND CAST({c['sp_status']} AS STRING) IN ('0', '200')
          AND {ip_col} IS NOT NULL AND {ip_col} <> ''
          AND NOT ({rfc1918_re})
    )
    SELECT
        MIN(src_ip) AS src_ip,
        sp_name AS target,
        COUNT(*) AS event_count,
        'distinct_ips=' || CAST(COUNT(DISTINCT src_ip) AS STRING)
            || ', distinct_prefixes=' || CAST(COUNT(DISTINCT net_prefix) AS STRING)
            || ', distinct_resources=' || CAST(COUNT(DISTINCT res_name) AS STRING) AS evidence
    FROM ext_ok
    GROUP BY sp_name
    HAVING (COUNT(DISTINCT net_prefix) >= 3 AND (COUNT(DISTINCT res_name) >= 2 OR SUM(is_hv) >= 1))
        OR (COUNT(DISTINCT src_ip) >= 3 AND COUNT(DISTINCT net_prefix) >= 2 AND COUNT(DISTINCT res_name) >= 3)
        OR (COUNT(DISTINCT src_ip) >= 3 AND COUNT(DISTINCT res_name) >= 4 AND SUM(is_hv) >= 1)
    """


@register_hunt("HUNT_11_GCP_BITRISE_MULTI_SA_AND_DENIED_PIVOT", "GCP Cloud Audit (Bitrise ARTEX): Multi-SA Single-IP Pivot & PERMISSION_DENIED -> Secret Manager", 90, "alert", ("gcp_audit_table",))
def sql_hunt_11_gcp_bitrise(cfg: dict[str, Any]) -> str:
    c = cfg["cols"]
    t = cfg["gcp_audit_table"]
    lb = _sql_lookback_filter(c["gcp_ts"], cfg)
    ip_col = c["gcp_ip"]
    pr_low = f"LOWER({c['gcp_principal']})"
    rfc1918_re = _sql_regex(ip_col, "^(10\\.|127\\.|169\\.254\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|::1$|fe80:|f[cd][0-9a-f]{2}:)")
    return f"""
    WITH filtered AS (
        SELECT
            {ip_col} AS caller_ip,
            {pr_low} AS principal,
            {c['gcp_method']} AS method_name,
            CAST({c['gcp_grpc_code']} AS STRING) AS code_str
        FROM {t}
        WHERE {lb}
          AND {ip_col} IS NOT NULL AND {ip_col} NOT IN ('', 'private', 'gce-internal-ip')
          AND NOT ({rfc1918_re})
          AND {pr_low} LIKE '%.gserviceaccount.com'
          AND {pr_low} NOT LIKE '%terraform%'
          AND {pr_low} NOT LIKE '%ansible%'
          AND {pr_low} NOT LIKE '%datadog%'
          AND {pr_low} NOT LIKE '%wiz%'
          AND {pr_low} NOT LIKE '%prisma%'
          AND {pr_low} NOT LIKE '%cspm%'
          AND {pr_low} NOT LIKE '%@gcp-sa-%'
          AND {pr_low} NOT LIKE '%@cloudservices.gserviceaccount.com'
          AND {pr_low} NOT LIKE '%-system@%'
    )
    SELECT
        caller_ip AS src_ip,
        CAST(COUNT(DISTINCT CASE WHEN code_str IN ('0', 'OK', '7', 'PERMISSION_DENIED') OR code_str IS NULL THEN principal END) AS STRING) || ' GCP service accounts' AS target,
        COUNT(*) AS event_count,
        'distinct_sas=' || CAST(COUNT(DISTINCT CASE WHEN code_str IN ('0', 'OK', '7', 'PERMISSION_DENIED') OR code_str IS NULL THEN principal END) AS STRING)
            || ', denied_apis=' || CAST(COUNT(DISTINCT CASE WHEN code_str IN ('7', 'PERMISSION_DENIED') THEN method_name END) AS STRING)
            || ', secret_reads_ok=' || CAST(SUM(CASE WHEN LOWER(method_name) LIKE '%accesssecretversion%' AND (code_str IN ('0', 'OK') OR code_str IS NULL) THEN 1 ELSE 0 END) AS STRING) AS evidence
    FROM filtered
    GROUP BY caller_ip
    HAVING COUNT(DISTINCT CASE WHEN code_str IN ('0', 'OK', '7', 'PERMISSION_DENIED') OR code_str IS NULL THEN principal END) >= 3
        OR COUNT(DISTINCT CASE WHEN code_str IN ('7', 'PERMISSION_DENIED') THEN method_name END) >= 5
        OR (
            COUNT(DISTINCT CASE WHEN code_str IN ('7', 'PERMISSION_DENIED') THEN method_name END) >= 3
            AND SUM(CASE WHEN LOWER(method_name) LIKE '%accesssecretversion%' AND (code_str IN ('0', 'OK') OR code_str IS NULL) THEN 1 ELSE 0 END) >= 1
        )
    """


# COMMAND ----------

# MAGIC %md
# MAGIC ## 5. Plug-In Slot for Future Custom Hunts
# MAGIC Copy and uncomment this template to register any future read-only hunt into the unified dashboard:
# MAGIC ```python
# MAGIC @register_hunt("HUNT_12_CUSTOM_EXAMPLE", "My Custom Read-Only Hunt", 75, "alert", ("flow_table",))
# MAGIC def sql_hunt_12_custom(cfg: dict[str, Any]) -> str:
# MAGIC     c = cfg["cols"]
# MAGIC     return f"SELECT {c['src_ip']} AS src_ip, {c['dst_ip']} AS target, COUNT(*) AS event_count, 'custom' AS evidence FROM {cfg['flow_table']} WHERE 1=0 GROUP BY {c['src_ip']}, {c['dst_ip']}"
# MAGIC ```

# COMMAND ----------

# MAGIC %md
# MAGIC ## 6. Execute All Hunts & Render Offline-Safe Interactive RBA Dashboard

# COMMAND ----------

def run_all_hunts(cfg: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    schema_checks = run_positive_control_check(cfg)
    healthy_datasets = {s["dataset"] for s in schema_checks if s["status"] == "OK"}
    findings: list[dict[str, Any]] = []
    for spec in HUNT_REGISTRY:
        if not set(spec.required_datasets).issubset(healthy_datasets):
            continue
        sql = spec.sql_builder(cfg)
        rows = run_readonly_query(sql)
        for row in rows:
            findings.append(
                {
                    "hunt_id": spec.hunt_id,
                    "title": spec.title,
                    "risk_score": spec.risk_score,
                    "alert_tier": spec.alert_tier,
                    "src_ip": str(row.get("src_ip", "")),
                    "target": str(row.get("target", "")),
                    "event_count": int(row.get("event_count", 0)),
                    "evidence": str(row.get("evidence", "")),
                }
            )
    findings.sort(key=lambda r: (-r["risk_score"], r["hunt_id"], r["src_ip"]))
    return schema_checks, findings


def render_dashboard_html(schema_checks: list[dict[str, Any]], findings: list[dict[str, Any]], max_enrich: int = 50) -> str:
    """Render a zero-CDN, air-gap-safe interactive HTML/SVG dashboard (works in Databricks displayHTML & local browsers)."""
    alert_cnt = sum(1 for f in findings if f["alert_tier"] == "alert")
    hunt_cnt = sum(1 for f in findings if f["alert_tier"] == "hunt")
    by_hunt: dict[str, int] = {}
    for f in findings:
        by_hunt[f["hunt_id"]] = by_hunt.get(f["hunt_id"], 0) + 1

    max_hits = max(by_hunt.values(), default=1)
    svg_bars = []
    y = 16
    for spec in HUNT_REGISTRY:
        cnt = by_hunt.get(spec.hunt_id, 0)
        bar_w = int((cnt / max_hits) * 260) if cnt > 0 else 4
        color = "#ef4444" if spec.alert_tier == "alert" and cnt > 0 else ("#f59e0b" if cnt > 0 else "#334155")
        svg_bars.append(
            f'<text x="0" y="{y + 12}" fill="#cbd5e1" font-size="11" font-family="monospace">{html_lib.escape(spec.hunt_id)}</text>'
            f'<rect x="335" y="{y}" width="{bar_w}" height="16" rx="3" fill="{color}"/>'
            f'<text x="{343 + bar_w}" y="{y + 12}" fill="#f8fafc" font-size="11" font-family="monospace">{cnt}</text>'
        )
        y += 26
    svg_height = max(y + 8, 80)

    candidate_ips = sorted({f["src_ip"] for f in findings if f["src_ip"]})[:max_enrich]

    rows_html = "\n".join(
        f"<tr>"
        f"<td><span class='badge {html_lib.escape(f['alert_tier'])}'>{f['risk_score']} ({html_lib.escape(f['alert_tier'])})</span></td>"
        f"<td><code>{html_lib.escape(f['hunt_id'])}</code></td>"
        f"<td><code>{html_lib.escape(f['src_ip'])}</code></td>"
        f"<td><code>{html_lib.escape(f['target'])}</code></td>"
        f"<td>{f['event_count']}</td>"
        f"<td>{html_lib.escape(f['evidence'])}</td>"
        f"</tr>"
        for f in findings
    )
    schema_html = "\n".join(
        f"<li><code>{html_lib.escape(s['table'])}</code> ({html_lib.escape(s['dataset'])}): <b>{html_lib.escape(s['status'])}</b> ({s['row_count']} rows)</li>"
        for s in schema_checks
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>ARTEX Read-Only Behavioral Hunt Dashboard</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; margin: 24px; }}
  h1, h2 {{ color: #f8fafc; }}
  .banner {{ background: #1e293b; border-left: 4px solid #38bdf8; padding: 12px 16px; margin-bottom: 20px; border-radius: 6px; font-size: 13px; }}
  .cards {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }}
  .card {{ background: #1e293b; border-radius: 8px; padding: 16px 20px; min-width: 170px; }}
  .card .num {{ font-size: 28px; font-weight: 700; }}
  .card.alert .num {{ color: #f87171; }}
  .card.hunt .num {{ color: #fbbf24; }}
  .card.ok .num {{ color: #34d399; }}
  table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; font-size: 13px; }}
  th, td {{ padding: 10px 12px; border-bottom: 1px solid #334155; text-align: left; }}
  th {{ background: #0b1220; color: #94a3b8; text-transform: uppercase; font-size: 11px; }}
  .badge {{ padding: 3px 8px; border-radius: 999px; font-weight: 600; font-size: 11px; }}
  .badge.alert {{ background: #7f1d1d; color: #fecaca; }}
  .badge.hunt {{ background: #78350f; color: #fde68a; }}
  code {{ color: #7dd3fc; }}
</style>
</head>
<body>
  <h1>ARTEX &amp; Autonomous Agentic Threats — Read-Only Behavioral Hunt Dashboard (v0.2.6)</h1>
  <div class="banner">
    <b>Read-Only Mode Verified:</b> Zero DDL/DML writes executed ({'Databricks Serverless Spark SQL' if RUNNING_IN_DBX else 'Local In-Memory DuckDB Preview'}). Never browse or probe flagged external IPs from bare metal; pivot strictly via passive intelligence platforms.
  </div>
  <div class="cards">
    <div class="card alert"><div>Tier A Alerts (&ge;70)</div><div class="num">{alert_cnt}</div></div>
    <div class="card hunt"><div>Tier B Hunt Hits (45-69)</div><div class="num">{hunt_cnt}</div></div>
    <div class="card ok"><div>Registered Hunts</div><div class="num">{len(HUNT_REGISTRY)}</div></div>
    <div class="card"><div>Unique Candidate Sources</div><div class="num">{len(candidate_ips)}</div></div>
  </div>
  <h2>Hits by Behavioral Hunt</h2>
  <svg width="660" height="{svg_height}" xmlns="http://www.w3.org/2000/svg">{''.join(svg_bars)}</svg>
  <h2>Unified RBA Triage Table</h2>
  <table>
    <thead><tr><th>Risk / Tier</th><th>Hunt ID</th><th>Source</th><th>Target</th><th>Count</th><th>Evidence</th></tr></thead>
    <tbody>{rows_html}</tbody>
  </table>
  <h2>Positive-Control Schema Check</h2>
  <ul>{schema_html}</ul>
  <h2>Read-Only In-Memory Passive Enrichment Queue (Cap={max_enrich})</h2>
  <p><code>{html_lib.escape(', '.join(candidate_ips) or 'none')}</code></p>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Run ARTEX read-only behavioral hunt dashboard locally.")
    parser.add_argument("--out", type=Path, default=None, help="Optional HTML file path to write offline dashboard preview.")
    args, _ = parser.parse_known_args()

    schema_checks, findings = run_all_hunts(CONFIG)
    dashboard_html = render_dashboard_html(schema_checks, findings, max_enrich=CONFIG["max_enrich_ips"])

    if RUNNING_IN_DBX:
        displayHTML(dashboard_html)  # type: ignore[name-defined]
    else:
        print(f"Schema checks: {len(schema_checks)} tables | Findings: {len(findings)} across {len(HUNT_REGISTRY)} hunts")
        for f in findings:
            print(f"  [{f['risk_score']} {f['alert_tier'].upper()}] {f['hunt_id']} | {f['src_ip']} -> {f['target']} ({f['evidence']})")
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(dashboard_html, encoding="utf-8")
            print(f"Wrote offline interactive dashboard preview to {args.out}")


if __name__ == "__main__" or RUNNING_IN_DBX:
    main()
