# Edge-to-Endpoint Hardening & Rapid Containment Runbook (ARTEX Defense)

Because ARTEX compresses reconnaissance, edge exploitation, credential harvesting, and cloud pivoting from days into **minutes (<3 hours)**, defensive controls must **slow down automated feedback loops** and **cut off lateral/cloud pivoting within 15 minutes**.

---

## 1. Major Edge & Perimeter Appliances

### Cisco ASA & Firepower Threat Defense (FTD)
- **Disable legacy WebVPN / clientless SSL portals** wherever unneeded; enforce certificate-based or phishing-resistant MFA on AnyConnect/IKEv2.
- Enable **Cisco Talos Snort 2 (`1:67494–1:67496`) / Snort 3 (`7:76–7:78`)** signatures on FTD to catch ARTEX and `norma` harness traffic inline.
- Rate-limit `/+CSCOE+/` and `/+webvpn+/` authentication endpoints and alert on `%ASA/%FTD-6-113005` / `113015` bursts with inter-event interval `<= 2s`.
- Keep management interfaces strictly off the public internet (out-of-band / ZTNA only).

### Citrix NetScaler ADC / Gateway
- Enforce strict patching cadence and lock down **NSIP / NITRO API (`/nitro/v1`)** to dedicated management VLANs only.
- Apply **Responder / AppFW policies** to block anomalous `HeadlessChrome`, `Nuclei`, and `norma` User-Agents and rate-limit `/nf/auth/` & `/vpn/` pre-auth failures.
- Monitor NetScaler `/var/nslog` & shell/cron/webshell integrity (`newnslog`, unexpected `.php`/`.py` writes).

### Palo Alto PAN-OS (GlobalProtect) & F5 BIG-IP
- **PAN-OS:** Restrict management interface strictly to internal jump networks; apply GlobalProtect vulnerability protection profiles, block known commercial VPS/proxy scanner lists (via EDLs), and alert on rapid `GLOBALPROTECT` auth-failure bursts.
- **F5 BIG-IP:** Never expose **TMUI (`/tmui/`)** or **iControl REST (`/mgmt/tm/`)** to the internet; enforce strict APM session limits and alert on `restjavad`/`httpd` spawning child shells.

### Zscaler (ZIA / ZPA)
- Create explicit **ZIA URL/Cloud App policies** restricting commercial LLM API domains (`api.anthropic.com`, `api.openai.com`, `api.deepseek.com`, `open.bigmodel.cn`, `api.x.ai`, `api.moonshot.cn`) and webhook/OAST dump sites (`webhook.site`, `interact.sh`, `oast.*`) to **approved developer/AI-gateway groups only** — block and high-severity alert from server subnets.
- Place legacy internal web portals and admin panels behind **ZPA** so autonomous external agents cannot reach them at all.

---

## 2. Web Portals, DMZ Egress & Breaking the LLM Feedback Loop
- **Zero-Trust DMZ Server Egress ("Servers Never Call Back Clients"):** Block web, application, and DMZ servers from initiating outbound TCP/UDP/DNS connections to arbitrary internet IPs (allow only explicit upstream APIs/proxies). One egress policy neutralizes reverse shells, custom-domain OOB callbacks, self-hosted LLM relays, and C2 staging across every ARTEX fork simultaneously.
- **Uniform Error Responses & Progressive Tarpitting (Starve the Planner):** Strip stack traces, internal framework versions, SQL/API validation hints, and debug headers; normalize external `400`/`404`/`405`/`422`/`500` response lengths/headers and apply progressive `429` delays so automated error-correction loops lose their differential feedback signal and burn their token/time budget.
- **Block Sensitive Exposure & AI/MCP Endpoints at the Edge:** Block public access to `/.env`, `/.git`, `/debug`, `/swagger`, `/actuator`, GraphQL introspection (`__schema`), and internal AI/MCP routes (`/mcp`, `/sse`, `/v1/models`, `/api/tags`).
- **Deploy JA4 / JA4H Anomaly Scoring:** Separate Go `net/http`, Python `httpx`, and CLI coding agents (`qwen-code`, `kimi-cli`, `opencode`) from legitimate browsers at the reverse proxy/WAF.

---

## 3. Local Endpoints, Identity Providers & Canary Tripwires
- **EDR Tamper Protection:** Enforce tamper protection on CrowdStrike Falcon, SentinelOne, and Microsoft MDE; alert immediately on rapid `sc query` / `Get-Service` EDR discovery bursts, rapid credential/config file harvesting (`.env`, `web.config`, `~/.aws/credentials`, `~/.kube/config`, `~/.ssh/id_*`), or `C:\ProgramData\artx5v\` file creation.
- **Canary LLM & Cloud API Keys (Zero-FP Tripwires):** Because agents actively scrape `.env`, `web.config`, and shell history for `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, and AWS keys to self-fund inference loops, plant monitored zero-privilege canary keys in decoy DMZ/staging paths for instant, zero-FP breach detection.
- **Identity Provider Kill-Switches (Okta & Microsoft Entra ID):** Enforce phishing-resistant MFA (FIDO2/Passkeys/Okta FastPass), set Okta ThreatInsight to **Block Mode**, disable legacy `/api/v1/authn` and unused self-service registration, restrict Okta Workflows invoke URLs (`clientToken`), and audit non-interactive Service Principal permissions.
- **Short-Lived Cloud Credentials & IMDSv2:** Enforce AWS **IMDSv2** (`HttpTokens=required`, hop limit `1`), replace static IAM keys and long-lived PATs with short-lived OIDC/STS tokens, and alert on `AddServicePrincipalCredentials`, `ConsentToApplication`, `AddAppRoleAssignment`, and multi-service cloud enumeration bursts (even at `200 OK`).

---

## 4. <15-Minute Rapid Containment Checklist (If Suspected ARTEX Activity Fires)
1. **Block source IP / ASN + LLM egress** at the perimeter firewall / Zscaler (breaks the Planner-Worker LLM decision loop immediately!).
2. **Isolate affected endpoint(s)** via MDE / CrowdStrike / SentinelOne network containment.
3. **Revoke active VPN sessions, refresh tokens, and recently created/modified Service Principal secrets & OAuth consents.**
4. **Preserve volatile & syslog telemetry** (export sanitized JSONL to `quarantine/` and run `./scripts/sandbox-scan.sh` + `artex-hunt correlate`).
