# Read-Only Databricks Free Edition & Enterprise Behavioral Hunt Dashboard Scaffold

> **Strict Read-Only Guarantee:** Both `artex_behavioral_hunt_dashboard.py` (native `# Databricks notebook source`), `artex_behavioral_hunt_dashboard.ipynb`, and `artex_lakeview_dashboard.lvdash.json` run **100% read-only SQL** (`SELECT` / CTEs only). A runtime guard (`assert_read_only_sql`) plus automated tests (`tests/test_databricks_scaffold.py`) enforce **zero** DDL/DML writes (`CREATE TABLE`, `INSERT`, `MERGE`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `TRUNCATE`).

## 1. Quick Start in Databricks Free Edition (Serverless + Unity Catalog + AI/BI Dashboards)
1. **Import the 2 notebooks** into your Databricks Free Edition workspace (`Workspace -> Import`):
   - `00_seed_databricks_free_edition_demo.py` *(sandbox demo seeder only — do not upload to read-only prod workspaces)*
   - `artex_behavioral_hunt_dashboard.py` *(or `artex_behavioral_hunt_dashboard.ipynb`)*
2. **Run `00_seed_databricks_free_edition_demo.py`** on Serverless Compute:
   - Leave `demo_scale = dashboard` (default) to seed **~3,400 synthetic RFC 5737 rows spanning the last 72 hours** across 6 Unity Catalog Delta tables in `workspace.default` (`artex_ipfix_flows`, `artex_ssl_flows`, `artex_http_flows`, `artex_dns_flows`, `artex_entra_sp_logs`, `artex_gcp_audit_logs`), or pick `smoke` for a compact ~75-row dataset.
3. **Import the native Databricks AI/BI Dashboard** (`Dashboards -> Import dashboard from file`):
   - Upload `artex_lakeview_dashboard.lvdash.json` — opens a 2-page interactive Lakeview dashboard (**Executive RBA Triage** + **Network, Entra & GCP Deep Dive**) wired directly to `workspace.default.artex_*`.
4. **Run `artex_behavioral_hunt_dashboard.py`** (zero widget edits needed!) to see the inline HTML/SVG RBA dashboard across all **11 behavioral hunts** (`11/11` caught, `0` benign FPs).

## 2. Promoting to a Read-Only Enterprise Work Workspace
1. Import **only** `artex_behavioral_hunt_dashboard.py` (and/or `artex_lakeview_dashboard.lvdash.json`).
2. Point the top widgets (`flow_table`, `ssl_table`, `http_table`, `dns_table`, `entra_sp_table`, `gcp_audit_table`, `scanner_allowlist_csv`) to your production Unity Catalog / Hive tables and remap `CONFIG["cols"]` in Cell 1. Any table widget left blank or unavailable is gracefully skipped without failing the remaining hunts.

## 3. Testing Locally (Zero Databricks Cluster Required)
```bash
# Run all 11 hunts locally via DuckDB and write an offline HTML dashboard preview
.venv/bin/python notebooks/artex_behavioral_hunt_dashboard.py --out quarantine/dashboard_preview.html

# Run read-only + 72h 3,400-row zero-FP + Spark SQL dialect + Lakeview JSON tests
.venv/bin/pytest -v tests/test_databricks_scaffold.py
```
