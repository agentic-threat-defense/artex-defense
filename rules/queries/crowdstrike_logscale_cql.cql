// ============================================================================
// ARTEX / Autonomous Agentic Offensive Framework — CrowdStrike Falcon (LogScale CQL)
//
// HOW TO USE THIS PACK (Validated in Live Falcon Advanced Event Search):
//   - Start with TIER 1 (30-second high-confidence triage, near-zero FPs across ALL hosts).
//   - Move to TIER 2 for behavioral hunting (use Least-Frequency-of-Occurrence ascending sorts
//     and compare first_seen/last_seen against a 30-365d baseline before escalating).
//
// Known Enterprise FP Caveats:
//   - Zscaler Client Connector (ZSATunnel / ZSA*) legitimately uses TCP 8890 (excluded in T2-A).
//   - RStudio Server / Cloudflare Wrangler may use TCP 8787; IBM MQ probes use localhost:1414.
//   - Dev browsers, Postman, MsSense, and ZSATunnel legitimately hit webhook.site (excluded in T2-B).
//   - GCP/cloud-aware Java & Node apps routinely wget/curl metadata.google.internal for zone/project
//     checks (excluded in T2-C unless chained or touching tokens/service-accounts/ssh-keys).
//   - Falcon table() defaults to limit=200; queries below use LFO groupBy or explicit limit=2000.
// ============================================================================


// ============================================================================
// TIER 1 — HIGH-CONFIDENCE TRIAGE (Run First — Near-Zero FPs, ALL Hosts)
// ============================================================================

// T1-A. Confirmed ARTEX / BLOODALCHEMY C2 & Relay Domains (ALL Hosts — Any Hit = Escalate)
#event_simpleName=DnsRequest
| DomainName=/(?:^|\.)(xcai\.(com|pro)|lanmao666\.(com|xyz)|artex\.lol|nginxmysql\.com|vietnam852\.com|zhzy999\.net|sqlserver-sqlite\.com|artex\.noog2infra\.site|artex\.ok7777\.eu\.cc|artex\.tokena2b\.top)\.?$/i
| default(field=[ContextBaseFileName], value="-")
| groupBy([ComputerName, ContextBaseFileName, DomainName], function=[count(as=hits), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=desc)

// T1-B. Explicit ARTEX / BLOODALCHEMY / ScopeWeaver Artifacts, EDR Sensor Enumeration, & Follow-On C2
//       (Note: DLL/config files like graphics-hook-filter64.dll also appear in PeFileWritten / ImageLoad)
#event_simpleName=ProcessRollup2
| (CommandLine=/(?i)(sc(\.exe)?\s+query|get-service|tasklist|systemctl\s+status|pgrep)/ AND CommandLine=/(?i)(csfalcon|falcon-sensor|crowdstrike|sentinelagent|windefend|cbdefense|sysmon)/)
  OR ImageFileName=/(?i)(\\ProgramData\\artx5v\\|ScopeWeaver|artex-server|artex-worker|\\vshell\.exe$|\\wisp\.exe$)/
  OR CommandLine=/(?i)(artx5v|ScopeWeaver|AntiFox|Pojun|FORANG|sco-fix2|guanlan\s*sec|tomicdd\/artex|congdonglinux\/artex|norma-agent|norma\/[0-9]|artex-enrich\/|artex-readonly\/|ARTEX-worker\/|artex-selfupdate|LLMLeak-RedTeam\/|authorized-exposure-audit|authorized-security-research|ArtexProbe|graphics-hook-filter64\.dll|graphics-hook_config\.bin|artex_config\.json|artex\.yaml|mitmproxy-ca-cert\.pem|traffic\/_index\/index\.sqlite|\/Inform\/logger\/|(?:^|[\s\/:"'])xcai\.(com|pro)\b|lsadump::|sekurlsa::|adaptixc2|\bwisp[-_]?c2\b|ligolo-agent|\bntlmrelayx\b)/
  OR (CommandLine=/(?i)\bchisel\b/ AND CommandLine=/(?i)\bclient\b/)
  OR (CommandLine=/(?i)\bvshell\b/ AND NOT CommandLine=/(?i)(VsDevShell|VisualStudio\.DevShell)/)
| table([@timestamp, ComputerName, ParentBaseFileName, ImageFileName, CommandLine], limit=2000)


// ============================================================================
// TIER 2 — BEHAVIORAL & BASELINE-REQUIRED HUNTS (Expect Org-Specific Tuning)
// ============================================================================

// T2-A. External Console Ports 8787/8788/8790/8890 (External Non-RFC1918 IPs Only, Excl. Zscaler 8890)
//       (Drop the `not cidr(...)` line only if hunting for an internal lateral staging server)
#event_simpleName=NetworkConnectIP4
| RemotePort=/^(8787|8788|8790|8890)$/
| not (RemotePort=8890 AND ContextBaseFileName=/^ZSA/i)
| not cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"])
| default(field=[ContextBaseFileName], value="-")
| groupBy([ComputerName, ContextBaseFileName, RemoteAddressIP4, RemotePort], function=[count(as=hits), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=asc)

// T2-B. Webhook / OAST Exfiltration DNS (Excludes Interactive Dev Browsers, Postman, MsSense & Zscaler on webhook.site)
#event_simpleName=DnsRequest
| DomainName=/(?:^|\.)(webhook\.site|oast\.(live|fun|me)|interact\.sh|dnslog\.cn)\.?$/i
| not (DomainName=/webhook\.site/i AND ContextBaseFileName=/^(chrome|msedge|firefox|brave|safari|postman|code|mssense|zsa)/i)
| default(field=[ContextBaseFileName], value="-")
| groupBy([ComputerName, ContextBaseFileName, DomainName], function=[count(as=hits), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=asc)

// T2-C. Web Server / Edge Daemon Spawning Shell — Least-Frequency-of-Occurrence (LFO) Fleet Hunt
//       (Uses ImageFileName for Win+Linux parity; scopes GCP metadata.google.internal exemption strictly to
//        standalone curl/wget probes so chained recon/RCE commands like whoami or /dev/tcp always alert)
#event_simpleName=ProcessRollup2
| ImageFileName=/[\/\\](cmd\.exe|powershell\.exe|pwsh(\.exe)?|sh|bash)$/i
| (ParentBaseFileName=/^(w3wp\.exe|nginx(\.exe)?|httpd(\.exe)?|apache2|php-fpm|restjavad|tomcat(\.exe)?|sqlservr\.exe)$/i)
  OR (ParentBaseFileName=/^(java(\.exe)?|node(\.exe)?)$/i AND (
      CommandLine=/(whoami|\bid\b|nltest|sc\s+query|invoke-webrequest|-enc(?:odedcommand)?\s|base64|\/dev\/tcp|\bnc\s)/i
      OR (CommandLine=/(curl|wget)\s/i AND NOT (CommandLine=/metadata\.google\.internal/i AND NOT CommandLine=/(service-accounts|\/token\b|ssh-keys|kube-env|recursive=true|iam\/security-credentials|;|&&|\|\||\||`|\$\()/i))
  ))
| groupBy([ParentBaseFileName, ImageFileName, CommandLine], function=[count(as=hits), count(field=ComputerName, distinct=true, as=hosts), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=asc)

// T2-D. Compressed Endpoint Recon & Cloud-CLI Burst (>= 5 Unique Discovery Cmds in 30s)
//       (Buckets by [aid, ComputerName] because UserName can be empty on raw ProcessRollup2 events)
#event_simpleName=ProcessRollup2
| CommandLine=/(?i)\b(whoami|ipconfig|nltest|net\s+localgroup|aws\s+sts|az\s+account|kubectl\s+get|sc\s+query|tasklist|get-service)\b/
| bucket(span=30s, field=[aid, ComputerName], function=[count(as=cmd_count), count(field=CommandLine, distinct=true, as=unique_cmds), collect([CommandLine], limit=10)])
| unique_cmds >= 5
| sort(unique_cmds, order=desc)

// T2-E. Server / DMZ Commercial LLM API & Wildcard-IP DNS Lookups (Baseline Required)
//       (Recommended: enrich via Falcon aid_master lookup for ProductType="Server" / "Domain Controller"
//        rather than relying solely on ComputerName prefixes; tune the exclusion regex to your naming scheme)
#event_simpleName=DnsRequest
| DomainName=/(?:^|\.)(api\.anthropic\.com|api\.openai\.com|api\.deepseek\.com|open\.bigmodel\.cn|api\.x\.ai|api\.moonshot\.(cn|ai)|dashscope\.aliyuncs\.com|openrouter\.ai|api\.siliconflow\.cn|sslip\.io|nip\.io|xip\.io|traefik\.me)\.?$/i
| not ComputerName=/^(DEV-AI-GW-|WKSTN-|LAPTOP-|MACBOOK-|DESKTOP-)/i
| default(field=[ContextBaseFileName], value="-")
| groupBy([ComputerName, ContextBaseFileName, DomainName], function=[count(as=hits), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=asc)
