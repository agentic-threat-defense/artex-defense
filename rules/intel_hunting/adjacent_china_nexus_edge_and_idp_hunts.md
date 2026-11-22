# Companion Threat-Hunting Templates: Storm-0940, Crystal Typhoon & Salt Typhoon

> **Scope Boundary:** `artex-defense`'s core engine (`src/`, `rules/sigma/`, `rules/network/`) stays **laser-focused on autonomous agentic threats** (Zero-IOC LLM control-plane physics, encrypted persistent-TLS turn loops, agentic harness artifacts, and machine-speed behavioral chains). This companion hunting sheet provides ready-to-run SIEM, network-device, and defensive exposure-audit templates for three overlapping China-nexus actors — **Storm-0940** *(confirmed ARTEX operator)*, **Crystal Typhoon** *(Microsoft alias for `Storm-1849` / `UAT4356`)*, and **Salt Typhoon** *(`UNC5807` / `Operator Panda` / `Earth Estries`)* — without diluting core agentic detections.
>
> **Operational Safety:** Run these queries strictly against **your own enterprise telemetry** (SIEM, TACACS+, syslog, NetFlow/Zeek) or passive exposure platforms scoped to **your own organization's ASNs/CIDRs**. All query syntax below uses vendor-native table/field names; replace placeholder indexes, CIDRs, and allowlists to match your environment.

---

## Quick Coverage Map

| Actor | Primary Target Surface | Overlap with `artex-defense` Core | Key Companion Hunts Below |
| :--- | :--- | :--- | :--- |
| **Storm-0940** | Cloud IdP (Entra ID, Okta), OAuth/Graph SPs, supply-chain apps, edge VPN sprays | **Direct core coverage** (`artex_entra_sp_secret_abuse_and_mfa_tampering.yml`, `artex_okta_mfa_fatigue_and_authn_spray.yml`, `distributed_proxy_pool_probe`) | Zero-interactive-signin Graph/SP abuse; low-and-slow distributed ORB/residential-proxy spray |
| **Crystal Typhoon** (`Storm-1849` / `UAT4356`) | Perimeter **Cisco ASA / FTD** (`ArcaneDoor`, `Line Dancer`, `Line Runner`, CVE-2024-20353 / 20359) | Edge WebVPN spray (`artex_cisco_asa_ftd_rapid_vpn_spray.yml`, Suricata `sid:9100005`, native ASA syslog parser) | ASA `111008`/`111010` logging-suppression & `webvpn` tampering; unscheduled crash/reload + syslog silence; ASA forensic checklist |
| **Salt Typhoon** (`UNC5807` / `Operator Panda` / `Earth Estries`) | Core/PE/CE routers (**Cisco IOS XE / NX-OS**, Juniper, PAN-OS), telecom & enterprise edge (`GuestShell`, GRE, `monitor capture`, `JumbledPath`, `GhostSpider`, `Demodex`, `SNAPPYBEE`) | Edge gateway probing, AD lateral movement, Chisel/Ligolo/Proxychains pivots, relocated DLL sideloading | Router `guestshell` / `monitor capture` / rogue GRE / TACACS+ accounting hunts; unauthorized `ip.proto == 47` (GRE) egress; router CLI audit checklist |

---

## 1. Storm-0940 (Cloud Identity, Non-Interactive OAuth/SP Abuse & Distributed Proxy Sprays)

Storm-0940 combines distributed ORB/residential-proxy password spraying with autonomous ARTEX cloud pivoting and zero-interactive-signin Microsoft Graph / Entra ID Service Principal abuse. Pair these hunts with [`rules/sigma/artex_entra_sp_secret_abuse_and_mfa_tampering.yml`](../sigma/artex_entra_sp_secret_abuse_and_mfa_tampering.yml) and [`rules/queries/microsoft_mde_kql.kql`](../queries/microsoft_mde_kql.kql).

### 1A. Microsoft Sentinel (KQL) — Non-Interactive Service Principal Multi-Resource Fan-Out & Credential Addition
```kql
// Hunt: Entra ID Service Principal authenticating across >=4 distinct resources after secret errors
// or immediately following a new client secret / certificate addition (zero interactive user sign-ins)
let lookback = 7d;
let sp_cred_adds = AuditLogs
| where TimeGenerated >= ago(lookback)
| where OperationName in~ (
    "Add service principal credentials",
    "Update application - Certificates and secrets management",
    "Add app role assignment to service principal",
    "Consent to application"
  )
| extend TargetSP = tostring(TargetResources[0].displayName)
| project CredAddTime = TimeGenerated, TargetSP, InitiatedBy = tostring(InitiatedBy);
AADServicePrincipalSignInLogs
| where TimeGenerated >= ago(lookback)
| summarize
    FailCount = countif(ResultType in ("7000215", "7000222", "700027")),
    SuccessCount = countif(ResultType == "0"),
    DistinctResources = dcount(ResourceDisplayName),
    Resources = make_set(ResourceDisplayName, 12),
    DistinctIPs = dcount(IPAddress),
    IPs = make_set(IPAddress, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by ServicePrincipalName, ServicePrincipalId
| where (FailCount >= 2 and SuccessCount >= 1) or DistinctResources >= 4
| join kind=leftouter sp_cred_adds on $left.ServicePrincipalName == $right.TargetSP
| order by FailCount desc, DistinctResources desc
```

### 1B. Microsoft Sentinel (KQL) — Low-and-Slow Distributed ORB / Residential-Proxy Spray (Many IPs, Low Per-IP Volume)
```kql
// Hunt: Catches Quad7 / residential-proxy-pool sprays that evade per-IP brute-force thresholds
// (>=15 distinct source IPs hitting >=8 distinct accounts with uniform bad-password failures in 30m)
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType in ("50126", "50053", "50056")
| summarize
    FailEvents = count(),
    DistinctIPs = dcount(IPAddress),
    DistinctUsers = dcount(UserPrincipalName),
    DistinctASNs = dcount(AutonomousSystemNumber),
    SampleUsers = make_set(UserPrincipalName, 10),
    SampleIPs = make_set(IPAddress, 10)
  by bin(TimeGenerated, 30m), AppDisplayName
| where DistinctIPs >= 15 and DistinctUsers >= 8 and (todouble(FailEvents) / todouble(DistinctIPs)) <= 5.0
| order by TimeGenerated desc
```

### 1C. Elastic ES|QL — Distributed Edge/IdP Spray (With Optional Success Correlation)
```esql
// Requires Elastic ES|QL 8.15+ (CASE support). Append `AND successes >= 1` to alert only when spray succeeds.
FROM logs-okta.system-*, logs-azure.signinlogs-*
| WHERE @timestamp >= NOW() - 24 HOURS
| EVAL outcome_fail = CASE(
    azure.signinlogs.result_type IN ("50126", "50053") OR event.code IN ("50126", "50053") OR TO_LOWER(event.outcome) == "failure", 1,
    0
  ),
  outcome_ok = CASE(
    azure.signinlogs.result_type == "0" OR event.code == "0" OR TO_LOWER(event.outcome) == "success", 1,
    0
  )
| STATS
    fails = SUM(outcome_fail),
    successes = SUM(outcome_ok),
    distinct_ips = COUNT_DISTINCT(source.ip),
    distinct_users = COUNT_DISTINCT(user.name)
  BY bucket = BUCKET(@timestamp, 30 MINUTES)
| WHERE fails >= 25 AND distinct_ips >= 12 AND distinct_users >= 8
| SORT bucket DESC
```

---

## 2. Crystal Typhoon (`Storm-1849` / `UAT4356` — Cisco ASA / FTD `ArcaneDoor`)

Crystal Typhoon targets perimeter **Cisco ASA and FTD** appliances (e.g., CVE-2024-20353, CVE-2024-20359), deploying memory-resident and persistent Lua backdoors (**Line Dancer** / **Line Runner**) while suppressing syslog, tampering with `webvpn` customizations, and triggering or leaving behind anomalous reloads/`crashinfo` dumps.

### 2A. Splunk SPL — Cisco ASA Logging Suppression, AAA/Config Tampering & WebVPN Modification (`111008` / `111010`)
```spl
index=cisco_asa OR sourcetype="cisco:asa"
("ASA-5-111008" OR "ASA-5-111010" OR "ASA-5-111009")
(
  "no logging" OR "clear logging" OR "no logging host" OR "no logging enable"
  OR "logging trap" OR "import webvpn" OR "customization" OR "webvpn"
  OR "aaa authentication" OR "username " OR "privilege 15"
  OR "capture " OR "copy " OR "crashinfo"
)
| stats count values(user) as users values(src_ip) as src_ips values(_raw) as sample_cmds min(_time) as first_seen max(_time) as last_seen by host
| sort - count
```

### 2B. Elastic ES|QL — Cisco ASA/FTD Audit-Tampering & Unscheduled Reload/Crash Hunt
```esql
FROM logs-cisco_asa.*
| WHERE @timestamp >= NOW() - 14 DAYS
| EVAL msg_low = TO_LOWER(message)
| WHERE event.code IN ("111008", "111010", "101001", "105003", "199017", "199019", "605005")
  AND (
    msg_low LIKE "*no logging*"
    OR msg_low LIKE "*clear logging*"
    OR msg_low LIKE "*import webvpn*"
    OR msg_low LIKE "*webvpn*customization*"
    OR msg_low LIKE "*crashinfo*"
    OR msg_low LIKE "*reloaded*"
    OR msg_low LIKE "*aaa authentication*"
  )
| KEEP @timestamp, host.name, event.code, source.ip, user.name, message
| SORT @timestamp DESC
| LIMIT 200
```

### 2C. Microsoft Sentinel (KQL) — Perimeter ASA/FTD Syslog Silence ("Heartbeat Drop") Detection
```kql
// Hunt: ArcaneDoor operators frequently disable syslog or trigger device reloads to evade detection.
// Flag perimeter Cisco ASA/FTD hosts that logged steadily over the prior 24h but went silent >15m.
let active_hosts = CommonSecurityLog
| where TimeGenerated between (ago(24h) .. ago(15m))
| where DeviceVendor has "Cisco" and DeviceProduct has_any ("ASA", "FTD", "Firepower")
| summarize PriorEvents = count(), LastSeen = max(TimeGenerated) by DeviceName
| where PriorEvents >= 500;
let recent_hosts = CommonSecurityLog
| where TimeGenerated >= ago(15m)
| where DeviceVendor has "Cisco" and DeviceProduct has_any ("ASA", "FTD", "Firepower")
| distinct DeviceName;
active_hosts
| where DeviceName !in (recent_hosts)
| order by LastSeen desc
```

### 2D. Cisco ASA / FTD Live Device Forensic Triage Checklist (Read-Only Commands)
Run via out-of-band console or verified management jump host (compare against known-good golden configs):
```text
show version                              ! Verify uptime for unexpected reloads & check patched build
dir disk0:/crashinfo*                     ! Preserve any unexpected crashinfo files for vendor/DFIR review
show running-config logging               ! Confirm centralized syslog hosts/traps were not removed
show running-config webvpn                ! Audit for unauthorized WebVPN customizations / Lua zip imports
show running-config username              ! Audit local privileged accounts
show capture                              ! Check for unauthorized live packet captures on the firewall
show aaa-server                           ! Verify AAA/TACACS+/RADIUS server targets
```

### 2E. Defensive Asset Exposure Inventory (Censys CenQL — Your Own Org ASN/CIDR Only)
```text
host.autonomous_system.asn=<YOUR_ORG_ASN> and host.services.endpoints.path="/+CSCOE+/logon.html"
```

---

## 3. Salt Typhoon (`UNC5807` / `Operator Panda` / `Earth Estries` — Router & Telecom Edge Espionage)

Salt Typhoon prioritizes long-term, low-noise persistence on core/PE/CE network infrastructure (**Cisco IOS XE / NX-OS**, Juniper, PAN-OS) using living-off-the-land router features (**`GuestShell`** Linux containers, native **`monitor capture`** / SPAN credential harvesting, rogue **GRE tunnels**, non-standard high SSH ports, ACL/TACACS+ modifications) alongside specialized tools (`JumbledPath`, `siet.py`, `TCLproxy.tcl`, `map.tcl`, `GhostSpider`, `Demodex`, `SNAPPYBEE`).

### 3A. Splunk SPL — Cisco IOS XE / NX-OS Syslog & TACACS+ Accounting Hunt (`GuestShell`, `monitor capture`, Rogue GRE, Tcl/EEM)
```spl
(index=network_syslog OR index=tacacs OR sourcetype IN ("cisco:ios", "cisco:iosxe", "cisco:nxos", "tacacs:accounting"))
(
  "guestshell" OR "app-hosting" OR "iox"
  OR "monitor capture" OR "monitor session" OR "erspan"
  OR "tunnel mode gre" OR "interface Tunnel" OR "tunnel destination"
  OR "ip ssh port" OR "rotary"
  OR "tclsh" OR "siet.py" OR "TCLproxy" OR "map.tcl" OR "event manager applet"
  OR "no logging" OR "clear logging" OR "tacacs-server host"
)
| stats count values(user) as users values(src_ip) as src_ips values(cmd) as cmds values(_raw) as sample_events min(_time) as first_seen max(_time) as last_seen by host
| sort - count
```

### 3B. Elastic ES|QL — Router Management Plane Tampering & Container Execution Hunt
```esql
FROM logs-cisco_ios.*, logs-network_devices.*, logs-tacacs.*
| WHERE @timestamp >= NOW() - 30 DAYS
| EVAL raw_low = TO_LOWER(COALESCE(process.command_line, message))
| WHERE raw_low LIKE "*guestshell*"
  OR raw_low LIKE "*app-hosting*"
  OR raw_low LIKE "*monitor capture*"
  OR raw_low LIKE "*monitor session*"
  OR raw_low LIKE "*tunnel mode gre*"
  OR raw_low LIKE "*ip ssh port*"
  OR raw_low LIKE "*tclsh*"
  OR raw_low LIKE "*event manager*"
  OR raw_low LIKE "*no logging*"
| KEEP @timestamp, host.name, source.ip, user.name, process.command_line, message
| SORT @timestamp DESC
| LIMIT 200
```

### 3C. Microsoft Sentinel (KQL) / Zeek / NetFlow — Unauthorized GRE (`Proto 47`) or Non-Standard High-Port SSH from Router Subnets
```kql
// Hunt: Detect router/network-infrastructure subnets initiating unexpected GRE (IP protocol 47)
// or non-standard high-port SSH tunnels to unapproved external peers.
let router_cidrs = dynamic(["10.0.250.0/24", "172.16.250.0/24"]); // Replace with your router loopback/mgmt CIDRs
let approved_gre_peers = dynamic(["198.51.100.10"]);             // Replace with documented WAN GRE peers
CommonSecurityLog
| where TimeGenerated >= ago(7d)
| where ipv4_is_in_any_range(SourceIP, router_cidrs) or ipv4_is_in_any_range(DestinationIP, router_cidrs)
| where Protocol in~ ("47", "GRE") or (DestinationPort >= 10000 and ApplicationProtocol has "ssh")
| where DestinationIP !in (approved_gre_peers) and SourceIP !in (approved_gre_peers)
| summarize FlowCount = count(), TotalBytes = sum(coalesce(SentBytes, 0) + coalesce(ReceivedBytes, 0)), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
  by SourceIP, DestinationIP, Protocol, DestinationPort
| order by TotalBytes desc
```

### 3D. Cisco IOS XE / NX-OS Router Live Audit Checklist (CISA / NSA / FBI Joint Guidance)
Run read-only checks on PE/CE/core routers and diff against offline golden configurations:
```text
show guestshell detail                                          ! Confirm GuestShell is disabled unless explicitly authorized
show app-hosting list                                           ! Audit all IOx / hosted containers
show monitor capture                                            ! Check for hidden native packet captures
show monitor session all                                        ! Audit SPAN / RSPAN / ERSPAN mirroring sessions
show running-config | include interface Tunnel|tunnel dest|tunnel source|tunnel mode
show running-config | include ip ssh port|rotary|access-list|tacacs|radius|username
show running-config | section event manager                   ! Audit Embedded Event Manager (EEM) applets/scripts
dir /all /recursive flash: | include \.py|\.tcl|\.pcap|\.sh     ! IOS XE: look for staged Python/Tcl scripts or packet captures
dir bootflash: | include \.py|\.tcl|\.pcap|\.sh                 ! NX-OS: equivalent check (NX-OS uses bootflash: without /recursive)
```
*(If `guestshell` is enabled on any device, also inspect container persistence: unauthorized entries in `/etc/passwd`, `/etc/shadow`, `~/.ssh/authorized_keys`, unexpected listening sockets `ss -tulpn`, and unexpected binaries under `/tmp` or `/var/tmp`.)*

### 3E. Follow-On Host / Server Endpoint Overlap (Windows & Linux)
Where Salt Typhoon pivots from edge routers into internal servers (AD/AAA/jump hosts), correlate the router hunts above with:
- **Relocated DLL sideloading & unsigned kernel drivers** (`Demodex` rootkit / `GhostSpider` / `SNAPPYBEE` loader behavior) — covered behaviorally in [`rules/sigma/artex_ad_ntlm_relay_chisel_sideload_pivots.yml`](../sigma/artex_ad_ntlm_relay_chisel_sideload_pivots.yml) and `detectors.py` (`dll_sideload_relocated_binary_with_config`).
- **On-box Go packet-sniffer execution (`JumbledPath`-style)** — hunt Linux/jump-host `auditd` for non-standard binaries invoking `AF_PACKET` raw sockets (`cap_net_raw`) or spawning from `/tmp`, `/dev/shm`, or `/var/tmp` outside `/usr/bin/tcpdump` and `/usr/bin/dumpcap`.

---

## Primary Public References
- **CISA / NSA / FBI / International Partners:** *Enhanced Visibility and Hardening Guidance for Communications Infrastructure* (Dec 2024) & *Countering Chinese State-Sponsored Actors Compromise of Networks Worldwide to Feed Global Espionage System* (Aug 2025).
- **Cisco Talos:** *ArcaneDoor — New Espionage-Focused Campaign Found Targeting Perimeter Network Devices* (`UAT4356` / `Line Dancer` / `Line Runner`).
- **Microsoft Threat Intelligence:** Storm-0940 (Entra ID / OAuth / ConnectWise Cloud Backup / ARTEX) & Crystal Typhoon (`Storm-1849`).
