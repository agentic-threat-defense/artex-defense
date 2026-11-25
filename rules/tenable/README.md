# Tenable One (Tenable VM / ASM / Cloud / Identity) Detection & Exposure Pack

This pack adapts `artex-defense` specifically for **Tenable One** (**Tenable Vulnerability Management [formerly Tenable.io]**, **Tenable Attack Surface Management [Tenable ASM]**, **Tenable Cloud Security**, and **Tenable Identity Exposure**).

> **Why no unsigned `.nasl` plugins here?**
> Tenable Vulnerability Management (Tenable.io) cloud scanners and Tenable-managed Nessus Agents enforce plugin signature checks and **do not accept unsigned custom `.nasl` files**. Everything in this pack uses **officially supported Tenable One mechanisms** (`.audit` compliance uploads, Malware Scan custom YARA rules, ASM external filters, and Cloud/Identity exposure queries) with zero signature-bypass workarounds.
>
> **Scope Boundary:** Tenable One excels at **point-in-time host artifact triage, shadow-console discovery, and pre-exploitation exposure reduction**. Continuous behavioral detection (machine-speed bursts, TLS 1.3 sawtooth context growth, JA4/JA4H stack whiplash / proxy collapse) belongs in your SIEM/NSM/data-lake layer (`rules/sigma/`, `rules/network/`, `rules/queries/`).

---

## 1. Tenable Vulnerability Management (TVM) — Custom Compliance `.audit` Scans

Both `.audit` files work over **Credentialed SSH / SMB-WinRM Scans** *and* **Tenable Nessus Agents**:

- **Linux:** [artex_aof_linux_triage.audit](artex_aof_linux_triage.audit) (7 bounded, read-only `CMD_EXEC` checks — recording-proxy SQLite index, worker `cmd-output` spills/configs, active AOF processes, trojanized Docker images, `/tmp` & `/dev/shm` tunnel staging, default console ports `8787`/`8788`/`8790`/`8890`/`18899` excluding Zscaler, and non-loopback Ollama/LiteLLM/Open WebUI/Cairn exposure).
- **Windows:** [artex_aof_windows_triage.audit](artex_aof_windows_triage.audit) (6 scoped, read-only `AUDIT_POWERSHELL` checks — `C:\ProgramData\artx5v`, `BLOODALCHEMY` OBS/Brother sideload DLLs, active AOF/tunnel processes, Services/Scheduled Tasks tunnel persistence, default console ports excluding Zscaler, and non-loopback LLM/MCP exposure).

### Upload Steps in Tenable One / TVM
1. Go to **Vulnerability Management → Scans → Create a Scan → Policy Compliance Auditing** (or **Agent Policy Compliance Auditing** for Nessus Agents).
2. Under **Compliance**, choose **Upload a custom Unix audit file** (`artex_aof_linux_triage.audit`) and/or **Upload a custom Windows audit file** (`artex_aof_windows_triage.audit`).
3. Target your **DMZ, web/API, bastion, CI/CD, and cloud server asset tags** first (run on developer workstations in audit-only mode first to baseline legitimate `mitmproxy` / local `Ollama` usage). For credentialed Linux SSH scans, enable **root / `sudo` privilege escalation** so `ss -lntp` / `netstat -lntp` exposes owning process names (required for the Zscaler `ZSA*` exclusion on TCP `:8890`).
4. **Interpreting Results:** Every check emits `CLEAN_NO_MATCH` (`PASSED`) on clean hosts and prints the exact offending paths, PIDs, services, or sockets (`FAILED`) when artifacts or shadow exposures are found.

---

## 2. Tenable Vulnerability Management — Custom YARA Malware Scan

Tenable VM natively accepts custom YARA files in its **Malware Scan** template (Windows & Linux credentialed / Agent scans):

1. Go to **Vulnerability Management → Scans → Create a Scan → Malware Scan** (or **Basic Network Scan** with Malware enabled).
2. Navigate to **Assessment → Malware → Enable Malware Scan → Custom YARA Rules**.
3. Upload [../yara/artex_scopeweaver_artifacts.yar](../yara/artex_scopeweaver_artifacts.yar).
   - *Compatibility verified:* Uses strictly standard YARA primitives (zero `import "vt"` or `import "pe"` dependencies), bounded `< 50MB` filesize checks, and CTI-blog FP guards.
   - *Do NOT upload* `gti_livehunt_artex_payloads_transcripts.yar` (requires VirusTotal's `vt` module) to Tenable VM.

---

## 3. Tenable Attack Surface Management (Tenable ASM) — Shadow & Rebranded AOF Console Filters

Use these saved inventory filters in **Tenable ASM** to spot unauthorized or exposed **ARTEX, AntiFox, ScopeWeaver, CyberStrikeAI, PentAGI, Cairn, RedAmon, Strix, AutoCVE, and DeepAudit** consoles across external assets, shadow cloud accounts, and partner/subsidiary ranges (multi-framework pivots cross-referenced with `Athar-HQ/Athar`, DRL 1.1):

| ASM Hunt Objective | Filter Field(s) | Values / Patterns |
| :--- | :--- | :--- |
| **ARTEX & Rebrand Console Titles (CN/KR/EN)** | `Page Title` / `HTTP Title` | Contains any of: `自主渗透测试控制台`, `자율 침투 테스트 콘솔`, `Autonomous Penetration Testing Console`, `Agent Security Workbench`, `ARTEX MX`, `AntiFox`, `ScopeWeaver`, `CyberStrikeAI`, `PentAGI`, `RedAmon`, `AutoCVE`, `DeepAudit` |
| **ARTEX Basic-Auth Protected Consoles** | `HTTP Response Headers` (`WWW-Authenticate`) | Contains `Basic realm="ARTEX"` |
| **Default AOF Console & Staging Ports** | `Port` | `8787`, `8788`, `8790`, `8890`, `18899`, `8081`, `8443`, `5001`, `5002`, `5003`, `8082` (paired with HTTP/TLS service or non-approved ASN/tag) |
| **Default AOF TLS Certificates & SANs** | `SSL Cert Issuer` / `SSL Cert Subject` / `SAN` | `O=ARTEX`, `CN=CyberStrikeAI`, `CN=PentAGI CA`, `SAN=pentagi.local`, `O=Cairn Platform`, `CN` contains `Cairn auto-generated TLS certificate`, or `SAN` matches `antifox.*.nip.io` |
| **Favicon & Next.js Build Pivots** | `Favicon Hash` / `HTTP Body` | ARTEX `mmh3: -576220750`; see the full 8-framework `mmh3` + SHA-256 table in [../intel_hunting/enterprise_intel_hunt_queries.md](../intel_hunting/enterprise_intel_hunt_queries.md) |
| **Open Python `SimpleHTTP` Staging Dirs** | `Page Title` + `HTTP Server Header` | `Page Title = "Directory listing for /"` AND `Server` contains `SimpleHTTP` |

---

## 4. Tenable One Exposure Prioritization (TVM + Cloud Security + Identity Exposure)

Autonomous offensive agents compress recon → exploit → credential theft → exfiltration into **under 3 hours**. Build a **Tenable One Exposure Card / Tag** prioritizing these exact pre-conditions:

### A. Tenable VM — High-Velocity Agentic Initial-Access Findings
- **External Edge Appliances:** Cisco ASA/FTD, Citrix NetScaler ADC/Gateway, Palo Alto PAN-OS, F5 BIG-IP (filter by `Is Internet Facing = true` + `VPR >= 7.0` + `Exploit Available = true`).
- **API & App Reconnaissance Accelerators:** Exposed OpenAPI / Swagger specs (`/openapi.json`, `/swagger.json`), `.js.map` source maps, `.env` / `.git` exposure, unauthenticated GraphQL introspection, Apache `.htaccess` upload/misconfiguration, SAPControl SOAP endpoints, and Ruby/Rails `CVE-2026-132825` (Ruby2Shell).
- **Self-Hosted AI & MCP Surfaces:** Exposed Ollama (`:11434`), LiteLLM (`:4000`), Open WebUI (`:3000`/`:8080`), Langflow, Dify, RAGFlow, or unauthenticated MCP servers.

### B. Tenable Cloud Security (AWS / Azure / GCP)
- **AWS:** EC2 instances still permitting **IMDSv1** (`HttpTokens = optional` — primary SSRF target for `169.254.169.254` & `sslip.io`/`nip.io` bypasses), overly permissive EC2 Instance Roles (`secretsmanager:GetSecretValue`, `ssm:GetParameters`, `ssm:SendCommand`), and plaintext secrets in EC2 `userData` or CloudWatch logs.
- **GCP:** Over-privileged Compute/Developer Service Accounts (`*-compute@developer.gserviceaccount.com`) granted `roles/secretmanager.secretAccessor` (`AccessSecretVersion`) or `iam.serviceAccountKeys.create` (Bitrise ARTEX pattern).
- **Azure & Kubernetes:** App Service / Kudu SCM exposure, privileged/hostPath Kubernetes pods able to mount host filesystems or read cluster-admin ServiceAccount tokens.

### C. Tenable Identity Exposure (Active Directory & Entra ID)
- **Active Directory:** SMB/LDAP signing disabled (enables `Responder`/`Coercer`/`ntlmrelayx` pivots), ADCS ESC1–ESC8 certificate templates (`Certipy`), and Kerberoastable service accounts with weak encryption/passwords.
- **Entra ID (Storm-0940 Pattern):** Over-privileged Service Principals / Enterprise Apps holding `Mail.Read`, `Files.Read.All`, `Directory.Read.All`, or `RoleManagement.ReadWrite.Directory` with long-lived client secrets, missing Workload Identity Conditional Access, or stale unused app registrations.
