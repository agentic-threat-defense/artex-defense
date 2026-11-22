# Blind Anti-Echo-Chamber Stress-Test Log (2026-11-20)

> **Methodology & Limitations:** To test beyond hand-written unit fixtures, a local LLM (**`gemma4-hunter`**, 26B MoE running via local Ollama) without access to `detectors.py`, `rules/`, `simulator.py`, or `tests/` generated out-of-distribution telemetry scenarios (benign enterprise chaos + stealthy agentic attacks) using the `NormalizedEvent` schema.
>
> **Important Caveat:** Because these rounds used small pre-normalized event snippets (`n=8` in Round 1; `n=5` benign / `n=5` attack in held-out Rounds 2–3) generated via our own Modelfile rather than raw vendor wire logs or uncurated production enterprise firehoses, treat these results as **synthetic logic checks—not proof of production false-positive rates**. Live shadow-mode validation and raw-wire parser testing remain essential.

---

## Round 1 — Baseline Before Fixes (`Benign FPs: 4/8` | `Attack FNs: 5/8`)

### False Positives Recorded (Benign Enterprise Chaos)
| # | Blind Benign Scenario | Baseline Result | Root Cause Exposed | Fix Applied |
| :---: | :--- | :--- | :--- | :--- |
| 1 | Corporate NAT Gateway (6 users, 5 browsers/JA4s) | `TN` (0 FP) | Passed (distinct source_hosts); still hardened `ja4_client_stack_whiplash` to require spoofed identical UA, `>=3` errors, or edge path for shared single-IP NATs | Hardened `ja4_client_stack_whiplash` |
| 2 | Authorized Qualys Scanner (`QualysGuard/1.0`, 10 `403`/`404`s in 20s) | **`FP`** (`machine_speed_burst`, `low_jitter`, `error_retry`) | No authorized scanner suppression + binary alerting on generic cadence | Added `AUTHORIZED_SCANNER_UAS` suppression + Risk-Based Alerting (RBA) weights |
| 3 | Ansible Read-Only Inventory across 5 Linux servers | `TN` (0 FP) | Clean | — |
| 4 | Datadog Non-Monotonic Batch Telemetry Uploads | `TN` (0 FP) | Clean | — |
| 5 | Broken Mobile OAuth Client retrying `POST /oauth/token` (`401`) 10x then `200` | **`FP`** (`machine_speed_burst`, `low_jitter`, `error_retry`) | Single user retrying 1 single OAuth refresh path (`unique_targets == 1`) triggered generic volumetric flags | Gated generic cadence on `unique_targets >= 2` (or corroborating signal) + RBA tiering |
| 6 | GitHub Actions CI Runner (`node`/`java` -> `bash`, `head`, `2>&1`) | `TN` (0 FP) | Clean (earlier `java`/`node` hardening held!) | — |
| 7 | Developer Laptop (`LAPTOP-DEV-88`) hitting `api.openai.com` / `api.anthropic.com` | **`FP`** (`llm_api_egress`) | Workstation tiering existed in Sigma but was missing in `detectors.py` | Added `WORKSTATION_HOST_PREFIXES` tiering in `detectors.py` (while still alerting on malicious relays `xcai.*`/`lanmao666.*`) |
| 8 | React SPA hitting 4 static-asset `404`s (`/favicon.ico`, `/robots.txt`, `.css.map`) -> `POST /api/search` -> `GET /api/search?q=billing` | **`FP`** (`write_then_readback_verification`) | `/api/search` matched `/api/` as a state write AND `/favicon.ico` `404` satisfied `saw_4xx_5xx` | Added `READONLY_POST_PATH_RE` (`/search`, `/query`, `/filter`, `/graphql`) + excluded `STATIC_ASSET_PATH_RE` from `saw_non_asset_4xx` |

### False Negatives Recorded (Blind Stealth Attacks)
| # | Blind Attack Scenario | Baseline Result | Root Cause Exposed | Fix Applied |
| :---: | :--- | :--- | :--- | :--- |
| 1 | Azure Service Principal `401` Fail → `200` Success → Key Vault Secrets & SAS Profiling | **`FN` (MISSED)** | No detector for cloud SP auth-fail→success→vault/SAS chain | Added `cloud_sp_fail_to_vault_pivot` (`85 pts`, `alert`) |
| 2 | Web SSRF (`169.254.169.254/latest/meta-data/`) + Upload Webshell (`POST /uploads/cache.php`) | **`FN` (MISSED)** | No detector for cloud metadata SSRF or executable scripts in `/uploads/` (all `200 OK`) | Added `web_ssrf_or_upload_webshell` (`85 pts`, `alert`) |
| 3 | AD Post-Exploitation (`mimikatz`, `lsadump::lsa`, `dcsync`) + Follow-on C2 (`vshell`, `AdaptixC2`, `sqlserver-sqlite[.]com`) | **`FN` (MISSED)** | AD credential dumping & Prophet/Brandefense follow-on C2 families not yet wired | Added `post_exploit_ad_or_followon_c2` (`95 pts`, `alert`) + Sigma rule #14 (`artex_post_exploit_ad_and_followon_c2.yml`) |
| 4 | Low-and-Slow Linux Agent (45–55s spacing, `sh -c` wrapped recon) | `TP` (`web_parent_shell_spawn`) | Caught | Retained (`85 pts`, `alert`) |
| 5 | External Edge Password Spray (`203.0.113.5` → 12× `401` at 4s on `/auth/login`, `actor=unknown`) | `TP` (Round 1 via generic cadence) → **`FN` (Intermediate Round 2)** | Reverse proxy didn't log POST body username (`actor=unknown`, `unique_targets=1`, `mean_interval=4.0s > 2.5s`) | Added throttled edge-spray clause (`>=10` edge auth fails, `>=90%` error ratio, `<=6.0s` spacing) + `multi_account_credential_spray` (`>=8` distinct accounts) |
| 6 | AWS Secret Discovery → `CreateAccessKey` → `AttachRolePolicy` (`action="allowed"`) | **`FN` (MISSED)** | Proxy/gateway logs put `action="allowed"` while real AWS ops live in `http_path` & `command_line` | Added `CLOUD_IAM_PATH_OR_CMD_RE` inspecting `http_path` & `command_line` alongside `action` (`80 pts`, `alert`) |
| 7 | Slow 35s Self-Hosted VPS LLM Proxy Sawtooth (`4.2KB -> 59KB`, TCP `443`, `/collect`) | `TP` (`llm_sawtooth_context_flow`) | Caught | Retained (`70 pts`, `alert`) |
| 8 | ConnectWise OAuth App → Microsoft Graph (`/addPassword`, `/admin/consent`, `action="allowed"`) | **`FN` (MISSED)** | Same proxy-log blind spot: Graph escalation paths lived in `http_path`, not `action` | Covered by `CLOUD_IAM_PATH_OR_CMD_RE` (`80 pts`, `alert`) |

---

## Round 2 — Post-Fix Re-Score (`Benign FPs: 0/8` | `Attack FNs: 0/8`)
- **Benign Enterprise Chaos:** **0/8 False Positives** (`100%` Specificity)
- **Blind Stealth Attacks:** **8/8 Caught — all scoring `70–95` (`alert` tier)** (`100%` Recall)
- **Standard Regression & Adversarial Suite (`.venv/bin/pytest`):** **27/27 tests passing** (`TP=13, FP=0, TN=11, FN=0`, **14/14 Sigma rules** compiling cleanly across all 8 SIEM/XDR backends with `0` schema errors).

---

## Held-Out Blind Round 2 — Zero-Edit Generalization Check (`Benign FPs: 0/5` | `Attack FNs: 0/5`)
> **Protocol:** Replaced UA-based scanner suppression (`AUTHORIZED_SCANNER_UAS`) with an operator-configured IP/CIDR allowlist (`--scanner-ip` / `authorized_scanner_ips`, preventing attacker UA spoofing), then had local `gemma4-hunter` generate **10 brand-new, unseen scenarios** (5 benign + 5 stealth attacks, including raw encrypted NetFlow/TLS 1.3) and evaluated them with **ZERO code edits allowed**.

| Set | Scenario | Result | Risk / Reasons |
| :--- | :--- | :---: | :--- |
| Benign | S3 Media Upload Stream (NetFlow ~250KB stable chunks) | **`TN`** | `0` FPs |
| Benign | Endpoint Observability Daemon (Splunk/OSQuery checks) | **`TN`** | `0` FPs |
| Benign | Standard E-Commerce User Flow (+ 1 `/help` 404) | **`TN`** | `0` FPs |
| Benign | Cloud Backup Service Principal (auth 200 + ListContainers) | **`TN`** | `0` FPs |
| Benign | Load Balancer Health Checks (4 LB nodes, `/health`) | **`TN`** | `0` FPs |
| Attack | Encrypted LLM-C2 Context Expansion (raw NetFlow/TLS 1.3, 0 HTTP) | **`TP`** | `70 (alert)` — `llm_sawtooth_context_flow` |
| Attack | IIS Web Server Post-Exploitation (`w3wp -> powershell` + EDR) | **`TP`** | `100 (alert)` — `web_parent_shell_spawn`, `edr_sensor_enumeration` (+ 2 Sigma) |
| Attack | Cloud Metadata SSRF (Alibaba `100.100.100.200`) → IAM Escalation | **`TP`** | `100 (alert)` — `web_ssrf_or_upload_webshell`, `cloud_iam_privilege_burst` |
| Attack | Distributed VPN/LB Probing (5 rotating exit IPs) | **`TP`** | `75 (alert)` — `distributed_proxy_pool_probe` |
| Attack | Single-IP Credential Spray (10 employee accounts, 7s spacing) | **`TP`** | `75 (alert)` — `multi_account_credential_spray` |

---

## Held-Out Blind Round 3 — Fork-Agnostic Blind-Spot Pivots (`Benign FPs: 0/5` | `Attack FNs: 0/5`)
> **Protocol:** After adding fork-agnostic blind-spot detectors (`cloud_stolen_key_multi_service_enum`, `dns_oob_callback_after_probe`, `graphql_or_ai_mcp_discovery_probe`, `config_and_secret_file_harvest_burst`, `agentic_server_callback_on_probe`, `agentic_lateral_fanout_smb_winrm`, `llm_api_key_harvesting`), local `gemma4-hunter` independently generated **10 brand-new unseen scenarios** (5 benign enterprise workloads + 5 stealthy zero-IOC attacks) evaluated with **ZERO code edits allowed**.

| Set | Scenario | Result | Risk / Reasons |
| :--- | :--- | :---: | :--- |
| Benign | Web server normal DNS lookups after checkout (`api.stripe.example`, `pod-abc123.svc.cluster.local`) | **`TN`** | `0` FPs |
| Benign | CI/CD AWS deploy (`aws-cli`: `sts`, `ecr`, `s3`, `ecs`, `cloudwatch` — all `200 OK`) | **`TN`** | `0` FPs |
| Benign | HR Okta onboarding (`3` `user.lifecycle.create` accounts over 50s) | **`TN`** | `0` FPs |
| Benign | IT Backup SMB connections (`3` file servers on `:445`, 15s spacing) | **`TN`** | `0` FPs |
| Benign | App startup reading `/srv/app/.env` + `package.json` | **`TN`** | `0` FPs |
| Attack | Custom-domain high-entropy OOB DNS callback `14s` after `POST /api/v1/render` | **`TP`** | `85 (alert)` — `dns_oob_callback_after_probe` |
| Attack | Reverse TCP callback on `:8443` back to probing IP `35s` after `GET /api/v2/export` | **`TP`** | `90 (alert)` — `agentic_server_callback_on_probe` |
| Attack | Stolen valid AWS admin key (`0` `AccessDenied`, `6` services `200 OK` in `10s` via `Boto3`) | **`TP`** | `80 (alert)` — `cloud_stolen_key_multi_service_enum` |
| Attack | Compromised Linux app harvesting `.env`, `~/.aws/credentials`, `~/.ssh/id_ed25519` + `ANTHROPIC_API_KEY` | **`TP`** | `100 (alert)` — `config_and_secret_file_harvest_burst`, `llm_api_key_harvesting` |
| Attack | WinRM lateral fan-out across `5` internal hosts (`:5985`, `3s` spacing) | **`TP`** | `80 (alert)` — `agentic_lateral_fanout_smb_winrm` |
