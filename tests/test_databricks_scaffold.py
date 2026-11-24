"""Tests verifying the read-only Databricks / Jupyter dashboard scaffold, 72h high-volume seeder, Lakeview JSON, and Spark SQL dialect parity."""

import importlib.util
import json
import re
import sys
from pathlib import Path

import duckdb
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
NB_PY = REPO_ROOT / "notebooks" / "artex_behavioral_hunt_dashboard.py"
NB_IPYNB = REPO_ROOT / "notebooks" / "artex_behavioral_hunt_dashboard.ipynb"
SEEDER_PY = REPO_ROOT / "notebooks" / "00_seed_databricks_free_edition_demo.py"
LAKEVIEW_JSON = REPO_ROOT / "notebooks" / "artex_lakeview_dashboard.lvdash.json"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_databricks_notebook_and_ipynb_contain_zero_write_sql_in_hunts() -> None:
    """Enforce read-only invariant & clean Spark SQL dialect across all 11 registered hunts, .ipynb, and Lakeview .lvdash.json."""
    mod = _load_module("artex_dbx_nb", NB_PY)
    assert len(mod.HUNT_REGISTRY) == 11
    assert SEEDER_PY.exists()
    assert LAKEVIEW_JSON.exists()

    # Check both DuckDB local SQL and Databricks Serverless Spark SQL modes
    for is_dbx in (False, True):
        mod.RUNNING_IN_DBX = is_dbx
        for hunt in mod.HUNT_REGISTRY:
            sql = hunt.sql_builder(mod.CONFIG)
            mod.assert_read_only_sql(sql)
            assert not re.search(
                r"\b(CREATE\s+TABLE|INSERT\s+INTO|MERGE\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|TRUNCATE)\b",
                sql,
                re.IGNORECASE,
            ), f"Hunt {hunt.hunt_id} contains forbidden write SQL"
            if is_dbx:
                assert "SPLIT_PART(" not in sql, f"{hunt.hunt_id} leaked DuckDB SPLIT_PART into Spark SQL"
                assert "REGEXP_MATCHES(" not in sql, f"{hunt.hunt_id} leaked DuckDB REGEXP_MATCHES into Spark SQL"
                assert "EXTRACT(EPOCH" not in sql, f"{hunt.hunt_id} leaked DuckDB EXTRACT(EPOCH into Spark SQL"
                assert "AS VARCHAR)" not in sql, f"{hunt.hunt_id} used bare VARCHAR instead of STRING in Spark SQL"
                assert not re.search(r"SPLIT\([^)]+\)\[", sql), (
                    f"{hunt.hunt_id} used ANSI-unsafe SPLIT()[idx] bracket indexing; use GET(SPLIT(...), idx)"
                )
                assert "TIMESTAMPADD(HOUR," in sql, f"{hunt.hunt_id} failed to enforce lookback_hours in Spark SQL"
                if hunt.hunt_id in {"HUNT_10_STORM0940_PREAUTH_SP_REPLAY", "HUNT_11_GCP_BITRISE_MULTI_SA_AND_DENIED_PIVOT"}:
                    assert r"10\\." in sql, f"{hunt.hunt_id} must double-escape dots for Spark SQL RLIKE literals"
            else:
                assert "INTERVAL '" in sql, f"{hunt.hunt_id} failed to enforce lookback_hours in DuckDB SQL"
    mod.RUNNING_IN_DBX = False

    # Runtime guard must actively block write attempts
    with pytest.raises(PermissionError):
        mod.assert_read_only_sql("MERGE INTO team_cymru_cache USING src ON src.ip = dst.ip")
    with pytest.raises(PermissionError):
        mod.assert_read_only_sql("CREATE TABLE tmp_hits AS SELECT * FROM flows")

    # Verify synchronized .ipynb is valid nbformat v4 JSON and includes all 11 hunts
    assert NB_IPYNB.exists()
    nb_data = json.loads(NB_IPYNB.read_text(encoding="utf-8"))
    assert nb_data["nbformat"] == 4
    assert len(nb_data["cells"]) >= 6
    nb_src = "\n".join("".join(c.get("source", [])) for c in nb_data["cells"])
    assert "HUNT_11_GCP_BITRISE_MULTI_SA_AND_DENIED_PIVOT" in nb_src

    # Verify Databricks AI/BI Lakeview .lvdash.json is valid JSON, strictly read-only, and pure Spark SQL
    lv = json.loads(LAKEVIEW_JSON.read_text(encoding="utf-8"))
    assert len(lv["datasets"]) == 5
    assert len(lv["pages"]) == 2
    for ds in lv["datasets"]:
        sql = "".join(ds["queryLines"])
        mod.assert_read_only_sql(sql)
        assert "SPLIT_PART(" not in sql and "REGEXP_MATCHES(" not in sql and "EXTRACT(EPOCH" not in sql
        assert not re.search(r"SPLIT\([^)]+\)\[", sql), (
            f"Lakeview dataset {ds['name']} used ANSI-unsafe SPLIT()[idx] bracket indexing; use GET(SPLIT(...), idx)"
        )
        assert "workspace.default.artex_" in sql
    for page in lv["pages"]:
        for item in page["layout"]:
            widget = item["widget"]
            for q in widget.get("queries", []):
                for f in q.get("query", {}).get("fields", []):
                    assert "COUNT_IF(" not in f.get("expression", ""), (
                        f"Lakeview widget {widget['name']} uses unsupported COUNT_IF() expression"
                    )
            spec = widget.get("spec", {})
            if spec.get("widgetType") == "table":
                for col in spec["encodings"]["columns"]:
                    assert "displayAs" in col and "type" not in col, (
                        f"Lakeview table widget {widget['name']} column must use 'displayAs', not 'type'"
                    )


def test_databricks_scaffold_runs_all_11_hunts_locally_with_zero_benign_fps(tmp_path: Path) -> None:
    """Execute all 11 read-only hunts locally via DuckDB and verify 11/11 attacks caught + 0 benign FPs + valid HTML."""
    mod = _load_module("artex_dbx_nb", NB_PY)
    schema_checks, findings = mod.run_all_hunts(mod.CONFIG)

    assert len(schema_checks) == 6
    assert all(s["status"] == "OK" and s["row_count"] > 0 for s in schema_checks)
    hit_ids = {f["hunt_id"] for f in findings}
    expected_ids = {h.hunt_id for h in mod.HUNT_REGISTRY}
    assert hit_ids == expected_ids, f"Missing hunt hits: {expected_ids - hit_ids}"

    flagged_sources = {f["src_ip"] for f in findings}
    for benign_ip in (
        "10.90.1.5",
        "10.90.1.8",
        "198.51.100.250",
        "198.51.100.210",
        "198.51.100.211",
        "198.51.100.212",
        "198.51.100.120",
        "198.51.100.200",
        "203.0.113.15",
    ):
        assert benign_ip not in flagged_sources, f"Benign baseline IP {benign_ip} falsely flagged!"
    flagged_targets = {f["target"] for f in findings}
    for benign_tgt in (
        "d111111abcdef8.cloudfront.net",
        "api.stripe.example",
        "Veeam-O365-Backup-SP",
        "Same16-Worker-SP",
        "Internal-Sync-SP",
    ):
        assert benign_tgt not in flagged_targets, f"Benign baseline target {benign_tgt} falsely flagged!"

    html_out = mod.render_dashboard_html(schema_checks, findings)
    assert "Read-Only Mode Verified" in html_out
    assert "<svg" in html_out
    assert "HUNT_11_GCP_BITRISE_MULTI_SA_AND_DENIED_PIVOT" in html_out


def test_databricks_72h_dashboard_seeder_triggers_11_of_11_hunts_with_zero_fps() -> None:
    """Load the full ~3,400-row 72-hour Databricks Free Edition demo dataset into DuckDB and verify 11/11 TP + 0 FP."""
    seeder = _load_module("artex_dbx_seeder", SEEDER_PY)
    nb = _load_module("artex_dbx_nb", NB_PY)

    datasets = seeder.generate_demo_datasets(scale="dashboard")
    total_rows = sum(len(v) for v in datasets.values())
    assert total_rows >= 3000, f"Expected >=3000 rows in dashboard scale, got {total_rows}"

    con = duckdb.connect(":memory:")
    con.execute("CREATE TEMP TABLE default_ipfix_flows (flow_ts TIMESTAMP, src_ip VARCHAR, dst_ip VARCHAR, dst_port INTEGER, octetTotalCount BIGINT, reverseOctetTotalCount BIGINT, silkAppLabel INTEGER, sslServerName VARCHAR, ja4 VARCHAR)")
    con.executemany("INSERT INTO default_ipfix_flows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", datasets["artex_ipfix_flows"])
    con.execute("CREATE TEMP TABLE ssl_flows (flow_ts TIMESTAMP, src_ip VARCHAR, dst_ip VARCHAR, dst_port INTEGER, sslServerName VARCHAR, ja4s VARCHAR, ja4x VARCHAR)")
    con.executemany("INSERT INTO ssl_flows VALUES (?, ?, ?, ?, ?, ?, ?)", datasets["artex_ssl_flows"])
    con.execute("CREATE TEMP TABLE http_flows (flow_ts TIMESTAMP, src_ip VARCHAR, dst_ip VARCHAR, dst_port INTEGER, sslServerName VARCHAR, http_method VARCHAR, http_path VARCHAR, http_status INTEGER, http_ua VARCHAR, ja4 VARCHAR, ja4h VARCHAR, bytes_out BIGINT)")
    con.executemany("INSERT INTO http_flows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", datasets["artex_http_flows"])
    con.execute("CREATE TEMP TABLE dns_flows (flow_ts TIMESTAMP, src_ip VARCHAR, dst_ip VARCHAR, dst_port INTEGER, dns_query VARCHAR)")
    con.executemany("INSERT INTO dns_flows VALUES (?, ?, ?, ?, ?)", datasets["artex_dns_flows"])
    con.execute("CREATE TEMP TABLE entra_sp_logs (created_ts TIMESTAMP, ip_address VARCHAR, service_principal_name VARCHAR, resource_display_name VARCHAR, result_type VARCHAR)")
    con.executemany("INSERT INTO entra_sp_logs VALUES (?, ?, ?, ?, ?)", datasets["artex_entra_sp_logs"])
    con.execute("CREATE TEMP TABLE gcp_audit_logs (event_ts TIMESTAMP, caller_ip VARCHAR, principal_email VARCHAR, service_name VARCHAR, method_name VARCHAR, resource_name VARCHAR, grpc_code INTEGER)")
    con.executemany("INSERT INTO gcp_audit_logs VALUES (?, ?, ?, ?, ?, ?, ?)", datasets["artex_gcp_audit_logs"])

    # Point notebook engine to the 72h seeded tables
    class _SeededEngine:
        def query(self, sql: str):
            nb.assert_read_only_sql(sql)
            cur = con.execute(sql)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    nb._LOCAL_ENGINE = _SeededEngine()
    schema_checks, findings = nb.run_all_hunts(nb.CONFIG)
    assert all(s["status"] == "OK" for s in schema_checks)
    hit_ids = {f["hunt_id"] for f in findings}
    assert hit_ids == {h.hunt_id for h in nb.HUNT_REGISTRY}, f"Missing hunts on 72h dataset: {set(h.hunt_id for h in nb.HUNT_REGISTRY) - hit_ids}"

    # Every single benign background IP / SP across all 3,000+ rows must remain unflagged
    flagged_sources = {f["src_ip"] for f in findings}
    for src in flagged_sources:
        assert not src.startswith("10.90.1."), f"Benign background host {src} falsely flagged!"
        assert src not in {"198.51.100.250", "198.51.100.210", "198.51.100.211", "198.51.100.212", "198.51.100.220", "198.51.100.221", "198.51.100.222", "198.51.100.223", "198.51.100.120", "198.51.100.200", "203.0.113.15"}
    flagged_targets = {f["target"] for f in findings}
    assert not (flagged_targets & {"Veeam-O365-Backup-SP", "Same16-Worker-SP", "Internal-Sync-SP", "d111111abcdef8.cloudfront.net", "api.stripe.example"})
