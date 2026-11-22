# Live-Lab & Purple-Team Evaluation Guide

Use this quickstart to evaluate `artex-defense` against an isolated lab or purple-team range running ARTEX (or an ARTEX fork / autonomous offensive agent). All commands below run **100% offline** with zero external network calls.

> [!CAUTION]
> Run live offensive-agent tests **strictly inside an isolated, host-only or air-gapped lab subnet**. Always pass `--sanitize` before exporting or sharing findings outside the lab.

---

## 1. Quick Clone & Local CLI Run (2 Minutes)

```bash
git clone https://github.com/agentic-threat-defense/artex-defense.git
cd artex-defense

# Option A: uv (recommended)
uv sync
uv run artex-hunt scan <exported_logs> --sanitize --out findings.json

# Option B: standard venv + pip
python3 -m venv .venv
.venv/bin/pip install -e ".[sigma]"
.venv/bin/artex-hunt scan <exported_logs> --sanitize --out findings.json
```

Useful companion CLI commands during a lab run:

```bash
# Multi-surface kill-chain correlation (<3h compressed + <=30d dormant-gap) on a merged JSONL export
uv run artex-hunt correlate <merged_multi_surface.jsonl> --sanitize

# Suppress an authorized baseline/control scanner IP or CIDR while keeping behavioral detectors active
uv run artex-hunt scan <exported_logs> --scanner-ip 10.50.0.10 --sanitize --out findings.json

# Operator-side forensic check on an ARTEX tasks/ artifact directory (optional, post-run)
uv run artex-hunt analyze-tasks <artex_tasks_dir>

# Read-only host triage against a target or transit Linux host (or mounted offline image via --root)
uv run artex-hunt host-triage --sanitize --out host_triage.json
```

---

## 2. Drop-In SIEM / XDR & Network Sensor Packs

If your lab already routes telemetry to a SIEM, XDR, or NSM sensor, you can deploy the precompiled rule packs directly without running the Python CLI:

| Layer | Repository Path | Notes |
| :--- | :--- | :--- |
| **SIEM / XDR Query Packs** | [`rules/queries/compiled_sigma/`](../rules/queries/compiled_sigma/) | Precompiled from 19 Sigma YAML rules for **Elastic ES\|QL & Lucene (ECS)**, **Microsoft KQL / Defender XDR / Sentinel ASIM**, **CrowdStrike LogScale (CQL)**, **Splunk SPL**, and **SentinelOne S1QL**. |
| **Raw Sigma Source Rules** | [`rules/sigma/`](../rules/sigma/) | Vendor-native field schemas (`eventName`, `requestParameters.*`, `eventType`, `status.errorCode`, `ComputerName`, `cs-host`, `event.code`). Recompile anytime via `artex-hunt sigma-compile`. |
| **Suricata / Snort Rules** | [`rules/network/artex_edge_and_harness.rules`](../rules/network/artex_edge_and_harness.rules) | Covers Norma/agentic UAs, Unit 42/GreyNoise canary probes, exposed console headers/titles, default ports (`8787`/`8788`/`8790`/`8890`), LLM relay TLS SNI, and webhook OAST domains. |
| **Zeek Behavioral Script** | [`rules/zeek/artex_agentic_cadence.zeek`](../rules/zeek/artex_agentic_cadence.zeek) | Tracks automated HTTP 4xx bursts, agentic UAs, canary URIs, and client stack changes on live wire traffic or offline PCAPs (`zeek -r capture.pcap rules/zeek/artex_agentic_cadence.zeek`). |
| **YARA Rules** | [`rules/yara/`](../rules/yara/) | Static host/artifact triage signatures for ARTEX / ScopeWeaver / BLOODALCHEMY staging artifacts. |

---

## 3. Highest-Value Telemetry to Capture in Your Lab

To get clean signal across both static retrohunt indicators and **Zero-IOC behavioral detectors**, prioritize these four telemetry surfaces:

### A. Target Web / Reverse-Proxy Access Logs
- **Accepted natively:** Nginx/Apache Common/Combined Log Format (`web_access`), Zscaler NSS JSON, or normalized JSONL.
- **What it exercises:**
  - Control-404 / nonexistent-user canary probes (`unit42_agentic_canary_probe`)
  - OpenAPI / Swagger spec discovery followed immediately by targeted verb calls (`spec_driven_api_targeting`)
  - Automated `4xx → 200` error-correction pivots (`web_error_correction_pivot`)
  - `PUT`/`POST` → immediate `GET` read-back verification (`write_then_readback_verification`)
  - Bimodal LLM Think-Act inference pauses (`think_act_bimodal_cadence`)

### B. Network Biflows + TLS / HTTP Fingerprints (Zero-IOC Core)
- **Accepted natively:** CERT NetSA **YAF IPFIX JSON** (RFC 5103 biflows with `bytes_out`/`bytes_in`) or JSONL enriched with `ja4`, `ja4h`, `bytes_out`, `bytes_in`; PCAPs can also be replayed directly through Zeek + `rules/zeek/artex_agentic_cadence.zeek` and Suricata.
- **What it exercises:**
  - Compaction-resilient TLS 1.3 growing-context flows to external or **self-hosted/local** LLM endpoints (`llm_sawtooth_context_flow`)
  - Multi-tool TLS/HTTP client stack whiplash under a spoofed browser UA (`ja4_client_stack_whiplash`)
  - Single-JA4 recording-proxy TLS collapse with multi-family User-Agents when ARTEX's Go traffic-recording proxy is enabled (`ja4_proxy_collapse_multi_ua`)

### C. Target Host Process Telemetry
- **Accepted natively:** JSONL containing `timestamp`, `source_host`, `actor`, `event_type` (`"process"`), `surface` (`"endpoint"`), `process`, `parent_process`, and `command_line`.
- **What it exercises:**
  - Sub-minute multi-command recon compression (`endpoint_compressed_recon_burst`)
  - Parallel sub-agent duplicate recon on the same host (`multi_worker_redundant_recon`)
  - LLM CLI context-budget idioms such as `| head -n`, `2>&1`, and `echo "=== ... ==="` (`llm_cli_context_idioms`)
  - Web-server/appliance shell spawning (`web_parent_shell_spawn`), EDR sensor discovery (`edr_sensor_enumeration`), on-box staging compilation, and Chisel/proxychains/NTLM relay pivots

### D. Cloud Control Plane & Identity Providers (If In-Scope)
- **Accepted natively:** Unmodified **AWS CloudTrail JSON** (JSONL or S3 `{"Records": [...]}`), **Okta System Log JSON**, **Microsoft Entra ID** (`SigninLogs`, `AADServicePrincipalSignInLogs`, `AuditLogs`), **Duo**, **PingFederate**, **Google Workspace Reports**, and **Cisco ASA/FTD / Citrix NetScaler / PAN-OS / F5 BIG-IP** logs.
- **What it exercises:** Sub-2s EC2 `userData` / SSM decryption bursts, external EC2 instance-role replay, multi-identity single-IP pivoting, CloudWatch secret searches, legacy `/api/v1/authn` password spraying, 2FA push fatigue, and Entra SP secret guessing.

---

## 4. Minimal Normalized JSONL Schema (For Custom Log Pipelines)

If your lab uses a custom log shipper or proprietary SIEM export, map events into one JSON object per line using any subset of these fields:

```json
{"timestamp":"2026-11-21T14:02:11.240Z","source_host":"10.99.0.15","actor":"svc-web","event_type":"http","surface":"web_portal","dest_host":"target.lab.local","dest_port":443,"http_method":"POST","http_path":"/api/v1/items","user_agent":"python-httpx/0.28.1","ja4":"t13d190900_9dc949149365_97f8aa674fd9","ja4h":"ge11nn040000_a3b8c9d0e1f2_000000000000_000000000000","bytes_out":15900,"bytes_in":3100,"status_code":422}
{"timestamp":"2026-11-21T14:03:02.110Z","source_host":"target.lab.local","actor":"www-data","event_type":"process","surface":"endpoint","process":"/bin/bash","parent_process":"nginx","command_line":"whoami && id && ip a 2>&1 | head -n 40","status_code":0}
```

### Practical Evaluation Notes
- **Cross-surface correlation:** `artex-hunt scan` and `artex-hunt correlate` inspect one file per invocation. To test cross-surface kill chains (`KC-*`), concatenate or sort web + network + endpoint JSONL exports into a single file.
- **Local / custom LLM backends:** If your testbed points ARTEX at a local or private LLM relay rather than public APIs, static LLM-domain IOCs will intentionally stay quiet — rely on `llm_sawtooth_context_flow` (biflow byte progression) and target-side behavioral detectors (`multi_worker_redundant_recon`, `llm_cli_context_idioms`, `ja4_proxy_collapse_multi_ua`).
- **Baseline calibration:** Run a 15–30 minute benign lab baseline (normal browsing, admin SSH, routine cron/CI) through `artex-hunt scan` alongside the attack capture to measure your real local false-positive floor before tuning thresholds in your own SIEM.
