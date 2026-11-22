// ============================================================================
// ARTEX / Autonomous Agentic Offensive Framework — CrowdStrike Falcon (LogScale CQL)
// Enterprise Caveats (Validated in Live Falcon Advanced Event Search):
//   - Zscaler Client Connector (ZSATunnel / ZSA*) legitimately uses TCP 8890 (excluded in 4A).
//   - RStudio Server / Cloudflare Wrangler may use TCP 8787; IBM MQ probes use localhost:1414.
//   - GCP/cloud-aware Java & Node apps routinely run wget/curl against metadata.google.internal
//     for zone/project checks (excluded in Query 3 unless touching token/service-accounts/ssh-keys).
//   - Falcon table() defaults to limit=200; fleet hunts below use LFO groupBy + sort(hits, order=asc)
//     so rare attacker commands float to the top instead of getting truncated.
// ============================================================================

// 1. Compressed Endpoint Recon & Cloud-CLI Burst (>= 5 Unique Discovery Cmds in 30s)
//    (Buckets by [aid, ComputerName] because UserName can be empty on raw ProcessRollup2 events)
#event_simpleName=ProcessRollup2
| CommandLine=/(?i)\b(whoami|ipconfig|nltest|net\s+localgroup|aws\s+sts|az\s+account|kubectl\s+get|sc\s+query|tasklist|get-service)\b/
| bucket(span=30s, field=[aid, ComputerName], function=[count(as=cmd_count), count(field=CommandLine, distinct=true, as=unique_cmds), collect([CommandLine], limit=10)])
| unique_cmds >= 5
| sort(unique_cmds, order=desc)

// 2. EDR Sensor Enumeration (CSFalcon / falcon-sensor / Sysmon / Defender) & ARTEX Artifacts
//    (Note: DLL/config files like graphics-hook-filter64.dll appear in CommandLine or PeFileWritten/ImageLoad, not ProcessRollup2 ImageFileName)
#event_simpleName=ProcessRollup2
| (CommandLine=/(?i)(sc(\.exe)?\s+query|get-service|tasklist|systemctl\s+status|pgrep)/ AND CommandLine=/(?i)(csfalcon|falcon-sensor|crowdstrike|sentinelagent|windefend|cbdefense|sysmon)/)
  OR ImageFileName=/(?i)(\\ProgramData\\artx5v\\|ScopeWeaver|artex-server|artex-worker|\\vshell\.exe$|\\wisp\.exe$)/
  OR CommandLine=/(?i)(artx5v|ScopeWeaver|AntiFox|Pojun|FORANG|sco-fix2|guanlan\s*sec|tomicdd\/artex|congdonglinux\/artex|norma-agent|norma\/[0-9]|artex-enrich\/|artex-readonly\/|ARTEX-worker\/|artex-selfupdate|LLMLeak-RedTeam\/|authorized-exposure-audit|authorized-security-research|ArtexProbe|graphics-hook-filter64\.dll|graphics-hook_config\.bin|artex_config\.json|artex\.yaml|mitmproxy-ca-cert\.pem|traffic\/_index\/index\.sqlite|\/Inform\/logger\/|(?:^|[\s\/:"'])xcai\.(com|pro)\b)/
  OR (CommandLine=/(?i)\bvshell\b/ AND NOT CommandLine=/(?i)(VsDevShell|VisualStudio\.DevShell)/)
| table([@timestamp, ComputerName, ParentBaseFileName, ImageFileName, CommandLine], limit=2000)

// 3. Web Server / Edge Daemon Spawning Shell — Least-Frequency-of-Occurrence (LFO) Fleet Hunt
//    (Uses ImageFileName for Win+Linux parity; scopes GCP metadata.google.internal exemption strictly to
//     standalone curl/wget probes so chained recon/RCE commands like whoami or /dev/tcp always alert)
#event_simpleName=ProcessRollup2
| ImageFileName=/[\/\\](cmd\.exe|powershell\.exe|pwsh(\.exe)?|sh|bash)$/i
| (ParentBaseFileName=/^(w3wp\.exe|nginx(\.exe)?|httpd(\.exe)?|apache2|php-fpm|restjavad|tomcat(\.exe)?|sqlservr\.exe)$/i)
  OR (ParentBaseFileName=/^(java(\.exe)?|node(\.exe)?)$/i AND (
      CommandLine=/(whoami|\bid\b|nltest|sc\s+query|invoke-webrequest|-enc(?:odedcommand)?\s|base64|\/dev\/tcp|\bnc\s)/i
      OR (CommandLine=/(curl|wget)\s/i AND NOT (CommandLine=/metadata\.google\.internal/i AND NOT CommandLine=/(service-accounts|\/token\b|ssh-keys|kube-env|recursive=true|iam\/security-credentials|;|&&|\|\||\||`|\$\()/i))
  ))
| groupBy([ParentBaseFileName, ImageFileName, CommandLine], function=[count(as=hits), count(field=ComputerName, distinct=true, as=hosts), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=asc)

// 4A. High-Confidence C2 Relays, Webhook/OAST Exfil, or Console Ports 8787/8788/8790/8890 (ALL Hosts)
//     (Excludes Zscaler Client Connector ZSA* on TCP 8890; surfaces ContextBaseFileName for instant port triage)
#event_simpleName=/^(DnsRequest|NetworkConnectIP4)$/
| (#event_simpleName=DnsRequest AND DomainName=/(?:^|\.)(xcai\.(com|pro)|lanmao666\.(com|xyz)|artex\.lol|nginxmysql\.com|vietnam852\.com|zhzy999\.net|sqlserver-sqlite\.com|artex\.noog2infra\.site|artex\.ok7777\.eu\.cc|artex\.tokena2b\.top|webhook\.site|oast\.(live|fun|me)|interact\.sh|dnslog\.cn)\.?$/i)
  OR (#event_simpleName=NetworkConnectIP4 AND RemotePort=/^(8787|8788|8790|8890)$/ AND NOT (RemotePort=8890 AND ContextBaseFileName=/^ZSA/i))
| default(field=[ContextBaseFileName, DomainName, RemoteAddressIP4, RemotePort], value="-")
| groupBy([ComputerName, ContextBaseFileName, DomainName, RemoteAddressIP4, RemotePort], function=[count(as=hits), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=desc)

// 4B. Anomalous Server/DMZ Commercial LLM API & Wildcard-IP DNS Lookups (Excludes Approved Gateways & Workstations)
//     (Adjust the ComputerName exclusion regex to match your organization's laptop/workstation naming prefixes)
#event_simpleName=DnsRequest
| DomainName=/(?:^|\.)(api\.anthropic\.com|api\.openai\.com|api\.deepseek\.com|open\.bigmodel\.cn|api\.x\.ai|api\.moonshot\.(cn|ai)|dashscope\.aliyuncs\.com|openrouter\.ai|api\.siliconflow\.cn|sslip\.io|nip\.io|xip\.io|traefik\.me)\.?$/i
| not ComputerName=/^(DEV-AI-GW-|WKSTN-|LAPTOP-|MACBOOK-|DESKTOP-)/i
| groupBy([ComputerName, DomainName], function=[count(as=hits), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=desc)
