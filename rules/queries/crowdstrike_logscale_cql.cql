// ============================================================================
// ARTEX / Autonomous Agentic Offensive Framework — CrowdStrike Falcon (LogScale CQL)
// ============================================================================

// 1. Compressed Endpoint Recon & Cloud-CLI Burst (>= 5 Unique Discovery Cmds in 30s)
#event_simpleName=ProcessRollup2
| CommandLine=/(?i)\b(whoami|ipconfig|nltest|net\s+localgroup|aws\s+sts|az\s+account|kubectl\s+get|sc\s+query|tasklist|get-service)\b/
| bucket(span=30s, field=[aid, ComputerName, UserName], function=[count(as=cmd_count), count(field=CommandLine, distinct=true, as=unique_cmds), collect([CommandLine], limit=10)])
| unique_cmds >= 5
| sort(unique_cmds, order=desc)

// 2. EDR Sensor Enumeration (CSFalcon / falcon-sensor / Sysmon / Defender) & ARTEX Artifacts
//    (Note: DLL/config files like graphics-hook-filter64.dll appear in CommandLine or PeFileWritten/ImageLoad, not ProcessRollup2 ImageFileName)
#event_simpleName=ProcessRollup2
| (CommandLine=/(?i)(sc(\.exe)?\s+query|get-service|tasklist|systemctl\s+status|pgrep)/ AND CommandLine=/(?i)(csfalcon|falcon-sensor|crowdstrike|sentinelagent|windefend|cbdefense|sysmon)/)
  OR ImageFileName=/(?i)(\\ProgramData\\artx5v\\|ScopeWeaver|artex-server|artex-worker)/
  OR CommandLine=/(?i)(artx5v|ScopeWeaver|AntiFox|Pojun|FORANG|sco-fix2|guanlan\s*sec|tomicdd\/artex|congdonglinux\/artex|norma-agent|norma\/[0-9]|artex-enrich\/|artex-readonly\/|ARTEX-worker\/|artex-selfupdate|LLMLeak-RedTeam\/|authorized-exposure-audit|authorized-security-research|ArtexProbe|graphics-hook-filter64\.dll|graphics-hook_config\.bin|artex_config\.json|artex\.yaml|\/Inform\/logger\/|(?:^|[\s\/:"'])xcai\.(com|pro)\b)/
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine])

// 3. Web Server / Edge Daemon Spawning Shell (Post-Exploit Pivot — java/node require recon/download args)
#event_simpleName=ProcessRollup2
| FileName=/(?i)^(cmd\.exe|powershell\.exe|pwsh(\.exe)?|sh|bash)$/
| ParentBaseFileName=/(?i)^(w3wp\.exe|nginx(\.exe)?|httpd(\.exe)?|apache2|php-fpm|restjavad|tomcat(\.exe)?|sqlservr\.exe)$/
  OR (ParentBaseFileName=/(?i)^(java(\.exe)?|node(\.exe)?)$/ AND CommandLine=/(?i)(whoami|nltest|sc\s+query|curl\s|wget\s|invoke-webrequest|-enc\s|-encodedcommand|base64|\/dev\/tcp)/)
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])

// 4A. High-Confidence C2 Relays, Webhook/OAST Exfil, or Console Ports 8787/8788/8790/8890 (ALL Hosts — NEVER Suppress Workstations)
(#event_simpleName=DnsRequest AND DomainName=/(?i)(?:^|\.)(xcai\.(com|pro)|lanmao666\.(com|xyz)|artex\.lol|nginxmysql\.com|vietnam852\.com|zhzy999\.net|sqlserver-sqlite\.com|artex\.noog2infra\.site|artex\.ok7777\.eu\.cc|artex\.tokena2b\.top|webhook\.site|oast\.(live|fun|me)|interact\.sh|dnslog\.cn)$/)
OR (#event_simpleName=NetworkConnectIP4 AND in(RemotePort, values=[8787, 8788, 8790, 8890]))
| default(field=[DomainName, RemoteAddressIP4, RemotePort], value="-")
| groupBy([ComputerName, DomainName, RemoteAddressIP4, RemotePort], function=[count(as=hits), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=desc)

// 4B. Anomalous Server/DMZ Commercial LLM API DNS Lookups (Excludes Approved AI Gateways & User Workstations)
#event_simpleName=DnsRequest
| DomainName=/(?i)(?:^|\.)(api\.anthropic\.com|api\.openai\.com|api\.deepseek\.com|open\.bigmodel\.cn|api\.x\.ai|api\.moonshot\.(cn|ai)|dashscope\.aliyuncs\.com|openrouter\.ai|api\.siliconflow\.cn)$/
| not ComputerName=/^(DEV-AI-GW-|WKSTN-|LAPTOP-|MACBOOK-|DESKTOP-)/i
| groupBy([ComputerName, DomainName], function=[count(as=hits), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=desc)
