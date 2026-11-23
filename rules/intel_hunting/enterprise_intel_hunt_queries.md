# Enterprise Threat-Intel & Infrastructure Hunting Query Templates (Offline Reference)

> **WARNING — Operational Safety (Zero Bare-Metal Exposure):** These are **offline query templates** for passive intelligence platforms (e.g., **Censys Platform**, **Shodan**, **Hunt.io**, **Google Threat Intelligence (GTI)**, **GreyNoise**, **Team Cymru**, **FOFA**, **Validin**, **Silent Push**, **URLScan.io**, and **FoxIO JA4+**, or equivalent passive TI services). Never browse, curl, download, or inspect raw attacker directories (`SimpleHTTP`), exposed operator consoles, or suspect C2 infrastructure from a bare-metal host or corporate workstation. Inspect any retrieved artifacts or `TaskID` transcripts exclusively inside an isolated, snapshotted Tier 3 host-only KVM VM (`artex-lab-isolated`) and sanitize/redact them via `scripts/sandbox-analyze-tasks.sh` before offline analysis.

---

## 1. Google Threat Intelligence (GTI / VirusTotal Enterprise)

*(Note: VTGrep `content:` is case-sensitive. Always pair with `type:` filters to avoid HTML/document noise.)*

### A. Go Binaries & Fork Artifacts (ARTEX / AntiFox / ScopeWeaver / CyberStrikeAI / Pojun / FORANG / Guanlan SEC / `norma` SDK / BLOODALCHEMY / Follow-On C2)
```text
(content:"github.com/Autumn-27/artex" OR content:"artx5v" OR content:"ScopeWeaver" OR content:"AntiFox" OR content:"Pojun" OR content:"FORANG" OR content:"sco-fix2" OR content:"artex-enrich/1.0" OR content:"artex-readonly/1.0" OR content:"ARTEX-worker/1.0" OR content:"artex-selfupdate" OR content:"norma/0." OR content:"ArtexProbe" OR content:"CyberStrikeAI" OR content:"cyberstrikeai-" OR content:"adaptixc2" OR content:"wisp-c2" OR content:"ARTEX_WRITE_PROBE" OR content:"graphics-hook-filter64.dll" OR content:"/Inform/logger/" OR content:"xcai.pro" OR content:"lanmao666" OR content:"artex.lol" OR content:"sqlserver-sqlite.com" OR content:"Guanlan SEC") AND (type:peexe OR type:pedll OR type:elf OR type:macho)
```

### B. Exposed Console Title / Embedded Next.js Web UI Strings
```text
(content:"自主渗透测试控制台" OR content:"ARTEX MX" OR (content:"_next/static" AND (content:"ARTEX" OR content:"ScopeWeaver" OR content:"AntiFox" OR content:"ARTEX PRO" OR content:"Agent Security Workbench") AND (content:":8787" OR content:":8790" OR content:":8890"))) AND (type:html OR type:javascript OR type:peexe OR type:elf)
```

### C. Community OSINT Detection Feeds & Threat-Actor Collections
- Monitor GTI curated collections tracking **ARTEX**, **Storm-0940** (zero-interactive-signin OAuth/Graph abuse), **VAPOR PANDA** (`BLOODALCHEMY` backdoor + EDR-skipping logic), and **Onyx Sleet**.
- Cross-check structured community IOC CSVs & Sigma packs such as `ThreatDefence/agentic-attack-detections`, `jiwoochris/artex-global`, `kh20134/artex-defense-kit`, and `Kshot3000/artex-defense-kit`.
- Export sanitized GTI IOC JSON bundles to `quarantine/` and run `artex-hunt intel` (local `gemma4-hunter`, $0 cloud tokens) to extract new behavioral signatures and Sigma updates.

---

## 2. Censys Platform (CenQL) & Hunt.io (HuntSQL) — Exposed Consoles & Staging Directories

### A. Exposed ARTEX / Rebranded Fork / CyberStrikeAI Consoles (Ports 8787 / 8788 / 8790 / 8890 / 18899 / 5001–5003 / 8082 / `Basic realm="ARTEX"` / Co-Located `Sub2API`)

**Censys Platform (CenQL — scoped inside `host.services:(...)` so port & HTTP body match the same service; RE2 regex via `=~ "(?i)..."`):**
```text
host.services:(endpoints.http.headers:(key="WWW-Authenticate" and value=~'(?i)Basic realm="ARTEX"'))
or host.services:(
  port in [8787, 8788, 8790, 8890, 18899, 5001, 5002, 5003, 8082]
  and (
    endpoints.http.html_title=~"(?i)(自主渗透测试控制台|Agent Security Workbench|ARTEX MX|AntiFox|Guanlan SEC|ScopeWeaver|CyberStrikeAI)"
    or endpoints.http.body=~"(?i)(ScopeWeaver|AntiFox|Pojun|FORANG|sco-fix2|Autonomous Penetration|artex_token=|CyberStrikeAI|adaptixc2|ARTEX_WRITE_PROBE)"
  )
)
```

**Censys Platform (CenQL) — Co-Located `Sub2API` Subscription-to-API Gateways (Unit 42 Overlap Pivot):**
```text
host.services:(port=8080 and endpoints.http.body=~"(?i)(Sub2API|Subscription to API Conversion)")
```

**Censys / Hunt.io — Exact ARTEX Console Routes, Cookie, Cert & UI Asset MD5s (Theori AIPT / Hunt.io):**
- Unique ARTEX routes (`HTTP 200`): `/api/exploration/`, `/api/intercept/`, `/api/sync/scopesentry`, `/api/llm/profiles`, `/api/llm/records`, `/function/tasks`, `/function/findings`, `/system/intercept`
- Session cookie: `artex_token=`
- Self-signed ARTEX X.509 certificate (Hunt.io — observed on `38.244.50[.]120` + 19 consoles): **Issuer Organization (`O`) = `ARTEX`**, 10-year validity, CN = host IP (SHA-256 `C7A884AFCD7F91408921890D9617BEF6BFAC3DAE992BC25BB9C48C0395A60842`) — in CenQL pivot via `host.services.cert.parsed.issuer.organization="ARTEX"`; in HuntSQL pivot via `tls.issuer.organization = 'ARTEX' AND SPLIT(ja4x, '_')[1] = SPLIT(ja4x, '_')[2]`.
- Next.js UI asset MD5s: `cd3ebd16437d6d3963592f7365dd3980`, `16bf6c5653291854e8c56c8eff7ca20d`
- Observed operator ports: `8787` (default console), `8788` (recording proxy), `8790` / `8890` / `8090` (alternate consoles/APIs), `18899` (MCP/TAG-217 ARTEX console), `5001`–`5003` / `8082` (CyberStrikeAI web consoles), `8000` / `8001` / `8907` (open staging & UnboundID JNDI/LDAP dirs)
- Exact worker output spill directory layout (for open Python `SimpleHTTP` hunting): `<data>/tasks/<task-id>/i<intent-id>/cmd-output/` + `traffic/_ca/mitmproxy-ca-cert.pem` + `traffic/_index/index.sqlite`

**Hunt.io (HuntSQL — `httpv2` table):**
```sql
SELECT ip, port, html.head.title
FROM httpv2
WHERE http.headers.raw ILIKE '%WWW-Authenticate%realm="ARTEX"%'
   OR (port IN (8787, 8788, 8790, 8890, 18899, 5001, 5002, 5003, 8082) AND (
        html.head.title ILIKE '%自主渗透测试%'
     OR html.head.title ILIKE '%Agent Security Workbench%'
     OR html.head.title ILIKE '%ARTEX MX%'
     OR html.head.title ILIKE '%CyberStrikeAI%'
     OR http.body ILIKE '%ScopeWeaver%'
     OR http.body ILIKE '%AntiFox%'
     OR http.body ILIKE '%Pojun%'
     OR http.body ILIKE '%FORANG%'
     OR http.body ILIKE '%artex_token=%'
     OR http.body ILIKE '%CyberStrikeAI%'
     OR http.body ILIKE '%adaptixc2%'
     OR http.body ILIKE '%ARTEX_WRITE_PROBE%'
   ));
```
*(Tips: Unit 42 linked separate ARTEX intrusions via co-located `Sub2API` gateways on TCP `8080` and `lanmao666[.]com` / `lanmao666[.]xyz` multi-tenant LLM gateway infrastructure. Pivot AntiFox console hits against Alibaba Cloud ASNs — Arctic Wolf observed Alibaba Cloud-hosted AntiFox operators targeting AWS IAM credentials and production secrets.)*

### B. Open Python HTTP Staging Directories (Agent `TaskID` Logs & Action Outcomes)

> **WARNING — Do NOT Browse Live Staging Directories from Bare Metal:** Never browse, download, or inspect raw attacker directories (`SimpleHTTP`) from a bare-metal host or corporate workstation. Use indexed response metadata from passive internet-intelligence platforms (e.g., **Censys**, **Shodan**, **Hunt.io**, **FOFA**, **URLScan.io**, **Validin**, **Silent Push**, or equivalent services) for triage; if an isolated research team exports `TaskID` transcripts inside a host-only isolated Tier 3 VM, redact victim IPs/domains/credentials and run offline analysis strictly through `./scripts/sandbox-analyze-tasks.sh`.

Early and active ARTEX operators frequently spin up temporary Python HTTP servers (`python3 -m http.server`) exposing staging folders, agent `TaskID` logs, command outputs, and failed/retried task traces:

**Censys Platform (CenQL — service-scoped):**
```text
host.services:(
  endpoints.http.html_title="Directory listing for /"
  and endpoints.http.headers:(key="Server" and value=~"(?i)SimpleHTTP")
  and endpoints.http.body=~"(?i)(cmd-output|mitmproxy-ca-cert\.pem|index\.sqlite|artx5v|scopeweaver|cyberstrikeai|artex_config\.json|artex\.yaml|exploration_nodes|intent_id|ARTEX_WRITE_PROBE|ARTEX_PERSIST_OK)"
)
```

**Hunt.io (HuntSQL — `httpv2` table):**
```sql
SELECT ip, port, html.head.title
FROM httpv2
WHERE html.head.title = 'Directory listing for /'
  AND http.headers.raw ILIKE '%Server: SimpleHTTP%'
  AND (
       http.body ILIKE '%cmd-output%'
    OR http.body ILIKE '%mitmproxy-ca-cert.pem%'
    OR http.body ILIKE '%artx5v%'
    OR http.body ILIKE '%scopeweaver%'
    OR http.body ILIKE '%cyberstrikeai%'
    OR http.body ILIKE '%artex_config.json%'
    OR http.body ILIKE '%exploration_nodes%'
    OR http.body ILIKE '%ARTEX_WRITE_PROBE%'
  );
```
*(Note: ARTEX's Exploration Graph labels individual planner intents sequentially as `i1`, `i2`, `i12345`, etc. Pivot on ASN, SSL/TLS cert issuer, and co-hosted ports `8787`/`8788`/`8790`/`8890` to separate threat-actor staging servers from benign lab/CTF boxes. Any sanitized `TaskID` / `i<digits>` / `.jsonl` transcripts exported from an isolated Tier 3 VM can be digested locally via `artex-hunt analyze-tasks <path>`.)*

---

## 3. Team Cymru — Commercial VPS & Rotating Proxy Pool Enrichment

When edge appliances (Cisco ASA/FTD, Citrix NetScaler, PAN-OS, F5 BIG-IP) show low-dwell (`<= 2s`) authentication sprays or URI fingerprinting:
1. Extract distinct source IPs from Stage 1 candidates (`artex-hunt scan`).
2. Enrich via Team Cymru IP-to-ASN / Pure Signal Recon to cluster:
   - Rapidly rotating **bulletproof / commercial VPS ASNs** vs. **residential proxy exit pools**.
   - Co-occurring outbound flows to ports `8787`/`8788`/`8790`/`8890` or commercial LLM API endpoints from the same threat-actor control IP.
   - Shared passive DNS / TLS certificates linking edge scanners to exposed ARTEX consoles or open Python staging directories.

---

## 4. FoxIO JA4+ (JA4 / JA4H / JA4T / JA4S) — Separating Agentic Clients from Humans

ARTEX worker agents rely heavily on **Go `net/http`**, **Python `httpx`/`requests`/`aiohttp`**, **`nuclei`**, and **Headless Chromium** — all of which produce **JA4 (TLS)** and **JA4H (HTTP header order/count/language)** fingerprints that diverge sharply from standard corporate browsers hitting Cisco ASA/FTD, Citrix NetScaler, PAN-OS, and F5 BIG-IP:

| Client Profile | JA4 / JA4H Hunting Pivot | Defensive Signal |
| :--- | :--- | :--- |
| **Go `net/http` / `nuclei` / ARTEX Go worker** | Distinct Go TLS cipher/extension ordering (`JA4`), minimal HTTP headers with missing `Accept-Language` / `Sec-Fetch-*` (`JA4H` suffix `0000`) | High-signal anomaly when hitting interactive VPN portals (`/+CSCOE+/`, `/vpn/`, `/global-protect/`, `/my.policy`) |
| **Python `httpx` / `requests` / `urllib`** | OpenSSL-backed `JA4` + minimal `JA4H` header profile paired with `<= 2s` inter-arrival jitter | Strong indicator of scripted error-correction loops or credential spraying |
| **Headless Chromium (`Playwright` / `Puppeteer`)** | Browser-like `JA4`, **but** combined with machine-speed navigation cadence, missing human mouse/scroll think-time, and anomalous `JA4T` (Linux VPS TCP window/options hitting corporate VPNs) | Correlate `JA4T` (Linux cloud VPS TCP stack) + `JA4H` + low-jitter URI sequence |
| **Exposed ARTEX Server (`JA4S`)** | Go `net/http` or Next.js/Node TLS server response fingerprint on ports `8787` / `8788` / `8790` / `8890` | Pivot across Censys/FoxIO JA4+ database to cluster related operator consoles |

### Recommended Analyst Workflow
1. Capture `JA4` + `JA4H` on Zeek / F5 / Zscaler / proxy edge telemetry for 7 days to build a **known-good corporate VPN client baseline** (AnyConnect, Citrix Workspace, GlobalProtect, corporate Edge/Chrome).
2. Alert on **non-baseline `JA4`/`JA4H`** clients generating `>= 5` auth failures or `>= 4` distinct gateway URIs within 2 minutes.

---

## 5. GreyNoise (Visualizer / GNQL) — Internet-Wide ARTEX Scanner Tracking

GreyNoise actively tracks opportunistic and framework-specific ARTEX reconnaissance with dedicated tags:
- **`ARTEX-Enrichment User-Agent (Possible ARTEX)`** — IPs scanning web assets using `artex-enrich/1.0`, `norma/0.4`, or related ARTEX enrichment UAs.
- **`ARTEX Parameter Attempt (Possible ARTEX)`** — IPs sending HTTP requests containing `artex=` query parameters probing for ARTEX-related injection points or functionality.

**GNQL Hunting Queries (quote special characters `/` and `=` for Lucene parsing):**
```text
tags:"ARTEX-Enrichment User-Agent (Possible ARTEX)" OR tags:"ARTEX Parameter Attempt (Possible ARTEX)"
```
*GNQL v3 native fields (`raw_data.http.*` — recommended for strict v3 API endpoints):*
```text
raw_data.http.useragent:"*artex-enrich/*" OR raw_data.http.useragent:"*norma/0.*" OR raw_data.http.useragent:"*LLMLeak-RedTeam*" OR raw_data.http.useragent:"*authorized-exposure-audit*" OR raw_data.http.useragent:"*authorized-security-research*" OR raw_data.http.useragent:"*ArtexProbe*"
```
```text
raw_data.http.path:"*artex=*" OR raw_data.http.path:"*zz_no_such_user*" OR raw_data.http.path:"*zzzrandom*" OR raw_data.http.path:"*ARTEX_WRITE_PROBE*"
```
*Legacy GNQL v2 compatibility aliases (`raw_data.web.*`):*
```text
raw_data.web.useragents:"*artex-enrich/*" OR raw_data.web.useragents:"*norma/0.*" OR raw_data.web.useragents:"*LLMLeak-RedTeam*" OR raw_data.web.useragents:"*authorized-exposure-audit*" OR raw_data.web.useragents:"*authorized-security-research*" OR raw_data.web.useragents:"*ArtexProbe*"
```
```text
raw_data.web.paths:"*artex=*" OR raw_data.web.paths:"*zz_no_such_user*" OR raw_data.web.paths:"*zzzrandom*"
```
*(Cross-reference GreyNoise-tagged scanner IPs with your edge firewall/WAF/VPN logs, Team Cymru ASN enrichment, and FoxIO JA4+ to separate mass-scanning background noise from targeted intrusions.)*

---

## 6. Bidirectional IPFIX / CERT NetSA YAF + `super_mediator` (RFC 5103 Flow Hunting)

Because YAF (2.20+ with DPI) exports **bidirectional IPFIX records** pairing forward (`octetTotalCount`) and reverse (`reverseOctetTotalCount`, PEN 29305) volumes with CERT Enterprise TLS/App elements (PEN 6871: `ja4` IE 480, `sslServerName` IE 294, `sslClientJA3` IE 463, `sslServerJA3S` IE 465, `silkAppLabel` IE 33), you can hunt ARTEX **even over encrypted TLS 1.3 with zero HTTP decryption**:

### Key Field Mappings (Natively Parsed by `artex-hunt scan`)
| YAF / IPFIX Element | PEN / IE | Workbench Field | ARTEX Hunting Signal |
| :--- | :--- | :--- | :--- |
| `octetTotalCount` / `reverseOctetTotalCount` | IANA 85 / PEN 29305 | `bytes_out` / `bytes_in` | **Sawtooth LLM context growth** over TCP 443 to opaque VPS relays (monotonic `octetTotalCount` climbs + steady `1–5KB` `reverseOctetTotalCount`) |
| `ja4` (split on `_` → `ja4_a`, `ja4_b`, `ja4_c`) | CERT 6871 / IE 480 | `ja4` | **Raw-IP TLS (`ja4` starting with `t13i`/`t12i`, empty `sslServerName`)** + **JA4 stack whiplash** (`>=3` distinct `ja4` from one source IP against one `sslServerName`) |
| `silkAppLabel` + `destinationTransportPort` | CERT 6871 / IE 33 + IANA 11 | `action` + `dest_port` | **Port-independent DPI:** `silkAppLabel IN (80, 443)` on `destinationTransportPort IN (8787, 8788, 8790, 8890)` catches ARTEX consoles/proxies even without HTTP payload |
| `sslServerName` | CERT 6871 / IE 294 | `dest_host` | Commercial LLM APIs from server/DMZ VLANs + campaign relays (`xcai[.]com`, `xcai[.]pro`, `lanmao666[.]com`, `artex[.]lol`, `sqlserver-sqlite[.]com`) |

### Starter Spark SQL / Data-Lake Pattern (YAF Bidirectional IPFIX + `ja4` Sub-Component Split)
*(Note: `split(ja4, '_')[0]` is 0-indexed Spark SQL; use 1-indexed `split_part(ja4, '_', 1)` in DuckDB/PostgreSQL.)*
```sql
-- 1. Raw-IP TLS (no SNI: ja4_a has 'i' at pos 4) or Non-Standard Port HTTP/TLS (8787/8788/8790/8890)
SELECT
  flowStartMicroseconds,
  sourceIPv4Address,
  destinationIPv4Address,
  destinationTransportPort,
  silkAppLabel,
  sslServerName,
  ja4,
  split(ja4, '_')[0] AS ja4_a,
  split(ja4, '_')[1] AS ja4_b,
  octetTotalCount AS bytes_out,
  reverseOctetTotalCount AS bytes_in
FROM default_ipfix_flows
WHERE (silkAppLabel IN (80, 443) AND destinationTransportPort IN (8787, 8788, 8790, 8890))
   OR (substring(ja4, 4, 1) = 'i' AND destinationTransportPort = 443 AND octetTotalCount >= 12000)
ORDER BY flowStartMicroseconds DESC;
```

---

## 7. Wildcard IP-Reflecting DNS (`sslip.io` / `nip.io` / `xip.io` / `traefik.me`) — IP-Evasion & Throwaway-TLS Hunting

Wildcard IP-reflecting DNS services resolve embedded IPv4/IPv6 addresses directly from the hostname (e.g., `169-254-169-254.sslip.io`, `192-168-1-1.nip.io`, `a9fea9fe.nip.io`). Attackers and autonomous web-exploitation agents abuse them in three ways:
1. **SSRF & IP-blocklist evasion:** Bypassing naive URL filters that block literal `169.254.169.254`, `127.0.0.1`, or RFC1918 strings.
2. **Throwaway HTTPS C2 / LLM relays:** Obtaining free Let's Encrypt TLS certificates for a raw VPS IP (`203-0-113-5.sslip.io`) without registering a domain.
3. **OAuth / webhook callback fallback:** Supplying `*.sslip.io` / `*.nip.io` in `redirect_uri=` when `oast.*` / `interact.sh` / `webhook.site` are blocked.

> **False-Positive Discipline:** Do **not** alert globally on developer workstations or K8s/Rancher/k3s lab clusters (which routinely use `192-168-x-x.sslip.io` or `127-0-0-1.nip.io`). Scope DNS/TLS hunting to **production servers / DMZ hosts** and pair with SSRF query parameters, post-probe server DNS callbacks, or autonomous TLS turn-loop telemetry.

### Microsoft Defender for Endpoint (KQL — Server / DMZ Hunt)
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where DeviceName has_any ("srv", "web", "api", "app", "dmz", "edge", "prod")
| where RemoteUrl matches regex @"(?i)(?:^|\.|//)(?:sslip\.io|nip\.io|xip\.io|traefik\.me)(?:[:/]|$)"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Splunk SPL (DNS / Proxy — Server Outbound & SSRF Parameter Hunt)
```spl
(index=dns OR index=proxy OR index=web)
(query="*.sslip.io" OR query="*.nip.io" OR query="*.xip.io" OR query="*.traefik.me"
 OR url="*sslip.io*" OR url="*nip.io*" OR url="*xip.io*" OR url="*localtest.me*" OR url="*lvh.me*")
| eval target_str=lower(coalesce(query, url)),
       is_workstation=if(match(lower(coalesce(host, src_host, "")), "^(wks|lt|lap|mac|desktop|dev)[-_0-9]") OR cidrmatch("10.200.0.0/16", coalesce(src, "")), 1, 0),
       signal=case(
         match(target_str, "(?:^|[./:@=-])(169[.-]254[.-]169[.-]254|169[.-]254[.-]170[.-]2|a9fea9fe)"), "1_CRITICAL_IMDS_SSRF",
         is_workstation=0 AND match(target_str, "(?:^|[./:@=-])(127[.-]0[.-]0[.-]1|7f000001|192[.-]168[.-]|10[.-]\\d+[.-]\\d+[.-]\\d+|172[.-](1[6-9]|2\\d|3[01])[.-]|localtest\\.me|lvh\\.me)"), "2_HIGH_SERVER_SSRF",
         1=1, "3_DEV_LOOPBACK_OR_PUBLIC_BASELINE"
       )
| where signal!="3_DEV_LOOPBACK_OR_PUBLIC_BASELINE"
| stats count values(signal) as signal values(dest) as targets by src, host, sourcetype
| sort + signal, - count
```
*(Tune the `is_workstation` host prefix / workstation CIDR `10.200.0.0/16` to match your environment so developer OAuth callbacks on `localtest.me` / `127-0-0-1.nip.io` stay out of Tier 1 while cloud IMDS bypasses alert from any host.)*
