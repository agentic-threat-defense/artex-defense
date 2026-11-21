# ARTEX & Autonomous Agentic Threats — SOC SIEM Validation & Shadow-Mode Playbook

> **Purpose:** Ready-to-run playbook for validating and tuning the ARTEX / ScopeWeaver / AntiFox / VAPOR PANDA detection packs in **production shadow mode** across **Elastic (ECH / EQL / ES|QL)**, **Microsoft MDE & Sentinel (KQL)**, **CrowdStrike Falcon (LogScale CQL)**, **SentinelOne (S1QL)**, and **External TI (GTI / Censys / Hunt.io / GreyNoise / FoxIO JA4+)**.
>
> **Rule #1:** Never push a brand-new behavioral rule straight to paging alerts without running the **2-Step Positive-Control + 7-Day Dry-Run** below.
>
> **WARNING — Operational Safety (Zero Bare-Metal Exposure):** Never browse, curl, download, or inspect raw attacker directories (`SimpleHTTP`), exposed operator consoles, or suspect C2 infrastructure from a bare-metal host or corporate workstation. Use passive intelligence platforms (e.g., **Censys**, **Shodan**, **Hunt.io**, **Google Threat Intelligence (GTI)**, **GreyNoise**, **Team Cymru**, **FOFA**, **Validin**, **Silent Push**, **URLScan.io**, or equivalent passive TI services) for infrastructure triage, and inspect any retrieved artifacts strictly inside an isolated, snapshotted analysis VM with mandatory sanitization (`scripts/sandbox-analyze-tasks.sh` / `artex-hunt sanitize`) before offline analysis.

---

## 1. Where the Ready-to-Run Query Packs Live
- **Hand-crafted behavioral & sequence packs (highest signal):**
  - Elastic ECH (EQL + ES|QL): `rules/queries/elastic_ech_eql.eql`
  - Microsoft MDE & Sentinel (KQL): `rules/queries/microsoft_mde_kql.kql`
  - CrowdStrike Falcon (LogScale CQL): `rules/queries/crowdstrike_logscale_cql.cql`
  - SentinelOne (S1QL / PowerQuery): `rules/queries/sentinelone_s1ql.s1ql`
- **Auto-compiled pySigma packs (validated 0 schema errors via `artex-hunt sigma-compile`):**
  - `rules/queries/compiled_sigma/compiled_esql_ecs.esql` (16 rules)
  - `rules/queries/compiled_sigma/compiled_lucene_ecs.lucene` (16 rules)
  - `rules/queries/compiled_sigma/compiled_kusto_mde_xdr.kql` (5 Windows endpoint rules)
  - `rules/queries/compiled_sigma/compiled_kusto_sentinel_asim.kql` (5 Windows endpoint rules)
  - `rules/queries/compiled_sigma/compiled_crowdstrike_logscale.cql` (16 rules)
  - `rules/queries/compiled_sigma/compiled_sentinelone_s1ql.s1ql` (5 Windows endpoint rules)
  - `rules/queries/compiled_sigma/compiled_splunk_spl.spl` (16 rules)
- **YARA (GTI Enterprise Livehunt & Retrohunt — syntax verified):**
  - `rules/yara/gti_livehunt_artex_payloads_transcripts.yar`
  - `rules/yara/gti_retrohunt_vaporpanda_bloodalchemy_artex.yar`
- **External Intel & Infrastructure Hunting Templates (GTI, Censys, Hunt.io, Team Cymru, FoxIO JA4+, GreyNoise):**
  - `rules/intel_hunting/enterprise_intel_hunt_queries.md`

---

## 2. Mandatory 2-Step Production Validation (Prevents Silent Failures & Alert Storms)

### Step A — Positive-Control Schema Check (5 minutes per platform)
A query returning `0` hits over 7 days can mean either *"we are clean"* **or** *"the field name doesn't exist in our index."* Prove the schema works first:
1. Clone each query and temporarily substitute one known-benign value (e.g., change `artex-enrich/1.0` → `Mozilla/5.0`, or `CSFalcon` → `cmd.exe`, or `8787` → `443`).
2. Confirm rows return with populated `host`, `user`, `url`/`command_line`, and `source.ip` columns.
3. If `0` rows return on the benign control, remap the field name (common real-world variants: `http.request.headers.user-agent` vs `user_agent.original`, `RequestURL` vs `Url`, `DeviceName` vs `Computer`).

### Step B — 7-Day Historical Dry-Run (Shadow Mode)
Run every validated query across the **last 7 days** and record:
- **Hits/day (AVD)**
- **Top 10 Noisiest Entities** (usually: corporate NAT exits, Qualys/Tenable/Rapid7 auth scanners, Jenkins/GitHub Actions CI runners, Datadog/Splunk agents, SCCM/Ansible inventory accounts, developer laptops running AI IDEs).
- Apply asset-tier allowlists before promotion:
  - **LLM API egress (`api.openai.com`, `api.anthropic.com`, `api.deepseek.com`):** Alert ONLY on **Servers / DMZ / Domain Controllers / non-interactive service accounts (`SYSTEM`, `www-data`, `svc-*`)**. Treat laptops/workstations as enrichment only.
  - **Web-to-shell (`java` / `node`):** Always keep the recon/download argument filter on `java`/`node` parents; keep `w3wp.exe`/`nginx`/`httpd`/`php-fpm`/`restjavad` strict.
  - **JA4/JA4H stack whiplash:** Always require **spoofed identical User-Agent** OR **`4xx` error bursts** OR **auth/VPN portal URI** so shared corporate NAT gateways don't FP.

---

## 3. Recommended Alerting Tiers (Deploy Tier A First!)

| Tier | Deployment Mode | What Belongs Here |
| :--- | :--- | :--- |
| **Tier A — Page / High-Priority Alert** | Promote to active alerting after Step A/B | `BLOODALCHEMY` (`graphics-hook-filter64.dll`, `graphics-hook_config.bin`, `/Inform/logger/`), `mitmproxy-ca-cert.pem` + `HTTP_PROXY` injection, `/tasks/<id>/i<id>/cmd-output/`, `artex-enrich/1.0`, `norma/0.4`, `LLMLeak-RedTeam/`, `authorized-exposure-audit/`, `zz_no_such_user` / `zzzrandom` / `artex=`, `w3wp/nginx -> cmd/bash`, `Rubeus`/`DCSync`/`vshell`/`AdaptixC2`/`WISP` follow-on activity |
| **Tier B — Risk-Based / Correlated Alert** | Require **2+ signals** or high-value asset/TI match | Compressed endpoint recon burst (`>=5` cmds in 30s), EDR sensor query (`sc query CSFalcon`), Entra SP fail-to-success + Key Vault/SAS profiling, SSRF (`169.254.169.254`) + upload path script creation, password spray across `>=10` accounts, JA4/JA4H stack whiplash under spoofed UA, sawtooth `bytes_out` LLM proxy flows |
| **Tier C — Hunt / Enrichment Only** | Never page standalone; use for pivoting | Workstation LLM API calls, standalone `:8080` (`Sub2API` check only when co-located), standalone `HeadlessChrome`, perishable campaign IPs (short TTL!) |

---

## 4. Perishable Campaign Reference (Hunt / Retro-Pivot Only — Short TTL)

> **WARNING — Zero Bare-Metal Exposure:** Never browse, curl, download, or probe any listed IP, domain, exposed console, or open Python directory directly from a bare-metal host or corporate workstation. Query them passively through third-party intelligence platforms (e.g., **Censys**, **Shodan**, **Hunt.io**, **GTI**, **GreyNoise**, **Team Cymru**, **FOFA**, **Validin**, **Silent Push**, **URLScan.io**, or equivalent services).

Treat IPs and open directories as **ephemeral/perishable** (do not hardcode permanent firewall blocks without verifying current ownership):
- **Domains:** `xcai[.]com`, `xcai[.]pro`, `lanmao666[.]com`, `lanmao666[.]xyz`, `sqlserver-sqlite[.]com`
- **Reported Campaign IPs (Prophet Security / Brandefense / ThreatDefence — verify freshness in GTI/GreyNoise/Team Cymru):** `38.244.50[.]120`, `144.172.64[.]60`, `144.172.64[.]99`, `144.172.64[.]128`, `89.46.234[.]50`
- **Follow-on Post-Exploitation C2/RATs Observed Alongside ARTEX:** `BLOODALCHEMY`, `WISP`, `vshell`, `AdaptixC2`
- **Containment Priority:** Rate-limit by **account, session, and API key** (not source IP alone, since operators rotate residential proxy pools), and immediately revoke compromised sessions, OAuth tokens, service principal secrets, and cloud access keys.
