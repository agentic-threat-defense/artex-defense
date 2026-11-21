# ARTEX Public Defensive Advisories & IOC Dossier (November 2026)

> **Source Scope:** Compiled from public 2026 defensive advisories and threat-intelligence publications (FBI/IC3, Microsoft, CrowdStrike, Cisco Talos, Google Threat Intelligence Group / Mandiant, Elastic, Hunt.io, Censys, ThreatDefence). All domains/indicators are defanged for safe offline processing.

## 1. Threat Overview & Proliferation
- **ARTEX** (`Autumn-27/ARTEX`) is an LLM-driven autonomous penetration-testing and multi-agent C2/orchestration framework written in Go with an embedded Next.js console and PostgreSQL state store.
- Removed from GitHub in October 2026 after widespread weaponization, it continues proliferating via forks, localized versions, and commercial tiers: **ScopeWeaver**, **LUCK**, **Guanlan SEC**, **ARTEX PRO**, plus adjacent agentic frameworks (**Cairn**, **HexStrike**, **PentAGI**, **CyberStrikeAI**).
- Underlying agent SDK: **`norma`** (`github[.]com/Autumn-27/norma`) handling harness memory, permissions, tool execution, and worker transcripts.

## 2. Attributed Campaigns & Post-Exploitation
- **VAPOR PANDA (CrowdStrike):** China-nexus espionage actor running ARTEX + DeepSeek in parallel against 200+ global targets across 14+ countries (foreign ministries, defense, telecom, semiconductor). Queries endpoints for CrowdStrike Falcon / EDR sensors and selectively bypasses protected hosts to pivot into unmonitored/legacy systems, followed by deployment of the custom **BLOODALCHEMY** backdoor.
- **Storm-0940 (Microsoft):** China-aligned actor deploying ARTEX against supply-chain integrations (including ConnectWise Cloud Backup) and Microsoft 365/Entra ID tenants — abusing pre-granted OAuth / multi-tenant application credentials via **Microsoft Graph API with zero interactive user sign-ins**.
- **Onyx Sleet (North Korea) & Financially Motivated Actors:** Targeting South Korean financial institutions, global manufacturing, energy, and internet-facing edge appliances (**Cisco ASA/FTD**, **Citrix NetScaler**, **Palo Alto PAN-OS**, **F5 BIG-IP**).
- **Compression:** Multi-stage intrusions routinely move from initial edge touch to privileged cloud/domain access in **under 3 hours**.

## 3. Verified Technical Indicators & Signatures
- **Exact HTTP User-Agents & Probe Markers:**
  - `norma/0.4` (and `norma/` prefix from `WebFetch` inside the `norma` SDK)
  - `artex-enrich/1.0` & `Rex_Enrich` (internal enrichment scanner modules)
  - `ArtexProbe` / `artex-probe-*` (worker probe identifiers tracked by Hunt.io, Elastic, and Mandiant)
  - Self-proclaimed "authorized" LLM-invented User-Agents (Unit 42 + Will Thomas / `@BushidoToken` `2026-11-20`):
    - `Mozilla/5.0 (security-testing; authorized)`
    - `LLMLeak-RedTeam/1.0 (authorised-scan)`
    - `authorized-security-research/1.0 (+vulnerability-disclosure-policy-review)`
    - `authorized-exposure-audit/6`
  - Wrapped CLI scanners: `Nuclei`, `HeadlessChrome`, `nmap`, `sqlmap`, `Impacket`
- **Network / Console Footprints:**
  - Default console / agent API ports: **TCP `8787`** and **TCP `8790`**
  - Exposed Next.js console HTML title: `自主渗透测试控制台` (Autonomous Penetration Testing Console)
  - Cisco Talos official IPS coverage: **Snort 2 (`1:67494–1:67496`)**, **Snort 3 (`7:76–7:78`)** (covering ARTEX and `norma` agent harness)
  - Exfiltration / callback services: `webhook[.]site`, `oast[.]live`, `oast[.]fun`, `interact[.]sh`
  - Outbound LLM APIs from unexpected server/admin hosts: `api[.]anthropic[.]com`, `api[.]deepseek[.]com`, `api[.]openai[.]com`, `open[.]bigmodel[.]cn`, `api[.]x[.]ai`, `api[.]moonshot[.]cn`
- **Host / Endpoint Artifacts:**
  - Windows staging path: `C:\ProgramData\artx5v\`
  - Binary/config strings: `artex`, `ScopeWeaver`, `LUCK`, `Guanlan SEC`, `ARTEX PRO`, `norma-agent`, `BLOODALCHEMY`
  - Machine-speed command chains (dozens of commands within 5–25s, near-zero human think-time jitter)
  - Automated EDR sensor discovery queries (`sc query CSFalconService`, `Get-Service SentinelAgent`, `WinDefend`, `Sysmon`)

## 4. Exposed Threat-Actor Python Staging Directories (`TaskID` Forensic Artifacts)
- CrowdStrike, Microsoft, and Censys confirmed that multiple ARTEX threat actors left temporary Python HTTP staging servers (`SimpleHTTP` / `python3 -m http.server`, `"Directory listing for /"`) exposed publicly.
- Exposed directories contained:
  - ARTEX configuration files and helper scripts
  - Structured **`.jsonl` callback/result files**
  - Per-agent **`TaskID`** logs documenting exact goals, commands executed, outputs returned, and **failure → LLM retry mutation chains**
  - Complete AI/LLM session transcripts (including Claude Code session logs) revealing operator prompts and target workflows

## 5. Expanded Fork Taxonomy, Rebranded Consoles & Trojanized Spinoffs
- **Named Forks & Derivatives:**
  - **AntiFox (`github[.]com/AntiFox-AI/antifox`):** Forked from ARTEX v0.1.1 (Chinese-language UI, delivery-enhanced webshell deployment, default port `8787`, same planner/worker dual-graph architecture). Arctic Wolf (Nov 2026) linked Alibaba Cloud-hosted AntiFox instances to IIS `w3wp.exe` → ASPX webshell → `web.config` harvesting → machine-speed `Boto3` (`Boto3/1.43.125`) AWS IAM/EC2/S3/Lambda/SecretsManager/KMS/RDS/EKS/**Amazon Bedrock** `AccessDenied` sweeps latching onto `GetSecretValue` hits within ~30 minutes.
  - **ScopeWeaver:** English/Korean localization (`cskwork/scopeweaver`).
  - **ARTEX PRO:** Commercialized closed-source successor.
  - **Pojun** & **FORANG:** Tracked by GitGuardian; bolt a full C2 console onto the ARTEX agent loop.
  - **ycode:** Derivative modifying the core execution pipeline.
  - **Global Edition:** Community fork bundling defensive Sigma/Suricata artifacts.
- **Rebranded Console UIs & Operator Builds:**
  - Censys / ThreatDefence observed renamed backends under titles: **`ARTEX MX`**, **`ARTEX v2 · Agent Security Workbench`**, **`LUCK`**, and **`Guanlan SEC`**.
  - ReversingLabs cataloged 184 distinct operator binaries across 11 fork families (including `RuoJi6/ARTEX`, `jaykwok/ARTEX`, and clustered private builds such as **`sco-fix2`** across shared hosting fleets).
- **Trojanized Docker Images (Supply-Chain Risk):**
  - BadByte uncovered backdoored prebuilt Docker images **`tomicdd/artex`** and **`congdonglinux/artex`** (~8,000 pulls before removal) containing a pre-authentication RCE backdoor in the login handler.

## 6. Deep-Dive Intel: Hunt.io (`38.244.50[.]120`), ThreatDefence, Prophet Security & Brandefense
- **Hunt.io South Korean Banking Campaign Infrastructure (`hunt[.]io/blog/artex-south-korea-bank-infrastructure`):**
  - Primary ARTEX console at `38.244.50[.]120` (AS174 Cogent, LA; open staging dir on `:8000`, ARTEX login on `:443`/`:8090`) paired with a Hong Kong jump server at `23.248.226[.]250` (AS138415 Yancy Limited; open dirs on `:8907` and `:8001` hosting an UnboundID LDAP SDK JNDI/LDAP rig).
  - **Self-Signed ARTEX X.509 Cert Pivot:** `38.244.50[.]120` (and 19 other ARTEX hosts found by Hunt.io) served a 10-year self-signed TLS certificate with **`Issuer Organization = ARTEX`** and `CN=<IP>` (SHA-256 `C7A884AFCD7F91408921890D9617BEF6BFAC3DAE992BC25BB9C48C0395A60842`).
  - **LLM Routing Shim:** Operators wired **Claude Code** through **CCR (Claude Code Router)** + **`xcai-effort-shim.py`** (injecting `reasoning_effort`) into reseller **`xcai[.]pro`**, managed by `local-boot.sh`, `tunnel-watchdog.sh`, and `sync-memory.sh`.
- **ThreatDefence Detection & Hunting Deep Dive (`threatdefence[.]com/article/artex-agentic-attack-framework-detection-hunting`):**
  - **Threat Actors:** **Storm-3358** (financially motivated, Cambodia-linked, SEA financial orgs — pairs ARTEX with **`WISP`** [`199.19.95[.]66–68`], **`vshell`**, **`AdaptixC2`**); **VAPOR PANDA** (`BLOODALCHEMY`, `sqlserver-sqlite[.]com` / `89.46.234[.]50`, `xcai[.]pro`); **Storm-0940** (Okta, Entra ID, AWS Cognito, ConnectWise).
  - **High-Fidelity Web/Cloud/Endpoint Techniques:**
    - **`{"alg":"none"}` (`eyJhbGciOiJub25l`) JWT unsigned token spray** on SSO routes.
    - **AWS Cognito sign-up / PreSignUp abuse** (`cognito-idp.amazonaws.com`) followed by `CognitoIdentityCredentials` discovery sweeps (`154.64.252[.]77`, `154.36.136[.]197`, `154.36.136[.]23`).
    - **Azure App Service Kudu/SCM admin API** (`*.scm.azurewebsites.net`) & `/deployments/validate` sweeps; alternate ARTEX listener port **`8890`**.
    - **SQL Server Toolkit (`xp_cmdshell`) + BYOVD `WinRing0x64.sys` + masqueraded `svchost.exe` outside `System32`** (`down[.]zhzy999[.]net`, `ftp[.]vietnam852[.]com:88/test/WinRing0x64.sys`, `nginxmysql[.]com`).
  - **Perishable Campaign Domains (Retro-Hunt Only):** `xcai[.]com`, `xcai[.]pro`, `lanmao666[.]com`, `lanmao666[.]xyz`, `sqlserver-sqlite[.]com`, `artex[.]lol`, `staging[.]artex[.]lol`, `artex[.]noog2infra[.]site`, `artex[.]ok7777[.]eu[.]cc`, `artex[.]tokena2b[.]top`, `nginxmysql[.]com`, `down[.]zhzy999[.]net`, `ftp[.]vietnam852[.]com`, `www[.]ddduuuppp[.]com`, `site[.]jiancai008[.]com`.
  - **Perishable Campaign IPs (Retro-Hunt Only):** `38.244.50[.]120`, `23.248.226[.]250`, `144.172.64[.]60`, `144.172.64[.]99`, `144.172.64[.]128`, `89.46.234[.]50`, `199.19.95[.]66`, `199.19.95[.]67`, `199.19.95[.]68`.

## 7. Late-November 2026 Fresh Advisories (Amazon MadPot, Okta Threat Intel, Cloudflare & Peer Frameworks)
- **Amazon Security / MadPot (Nov 2026):** Decoy telemetry captured ARTEX agents harvesting AI model API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, `sk-ant-`, `sk-proj-`, AWS Bedrock credentials) to self-fund autonomous inference loops.
- **Okta Threat Intelligence (Oct/Nov 2026):** Large-scale autonomous identity reconnaissance across Okta/Auth0 tenants by **ARTEX** and **Cairn** workers running continuously (390+ hours) — mass fraudulent self-service probe account registrations (`user.lifecycle.create`), `user.risk.detect` spikes, Okta Workflows invoke-URL / `clientToken=` abuse, wildcard OAuth callback probing, and MCP-driven **OpenBullet 2** config generation.
- **Expanded Autonomous Offensive Ecosystem:** Additional ARTEX derivative **`Reaper`**, containerized web/API agent **`Strix`**, **`Shannon`**, **HexStrike** (MCP server exposing 150+ offensive tools), **CyberStrikeAI** (Go C2 + YAML recipes), **PentAGI** (Docker/GraphQL), **Cairn** (OODA blackboard), and GTIG/Mandiant's **`exploit_agent`** (automated patch-diff → N-day exploit crafting).
- **Cloudflare Telemetry:** Reported up to **30x baseline** automated scan/exploit traffic spikes driven by thousands of IPs executing daily LLM-orchestrated loops.
- **Elastic Security Labs (`cyberstrikeai-aws-cloudtrail-intrusion`, "56 AWS API calls in 141ms"):** Documented a CyberStrikeAI operator (`43.240.29[.]11`) pivoting across **4 AWS accounts and 8 stolen identities** (5 IAM users + 3 EC2 instance roles `assumed-role/.../i-*`), harvesting **56 EC2 `userData` startup scripts in 141 ms**, decrypting SSM parameters, executing `ssm:SendCommand`, and inserting a **14-day dormant gap** to defeat short correlation windows.

## 8. Community Defensive Repositories for Periodic Ingestion
- `github[.]com/ThreatDefence/artex-detections` — Structured IOC CSV (User-Agents, request artifacts, hashes, domains, URLs), 31 Sigma rules, and KQL hunting scripts.
- `github[.]com/jiwoochris/artex-global` — Community archive including `artex_host_triage.py` defensive endpoint checker.
