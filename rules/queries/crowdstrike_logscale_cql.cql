// ============================================================================
// ARTEX / Autonomous Agentic Offensive Framework — CrowdStrike Falcon (LogScale CQL)
// ============================================================================

// 1. Compressed Endpoint Recon & Cloud-CLI Burst (>= 5 Unique Discovery Cmds in 30s)
#event_simpleName=ProcessRollup2
| CommandLine=/(?i)\b(whoami|ipconfig|nltest|net\s+localgroup|aws\s+sts|az\s+account|kubectl\s+get|sc\s+query|tasklist|get-service)\b/
| bucket(span=30s, field=[aid, ComputerName, UserName], function=[count(as=cmd_count), count(field=CommandLine, distinct=true, as=unique_cmds), collect([CommandLine], limit=10)])
| unique_cmds >= 5
| sort(unique_cmds, order=desc)

// 2. EDR Sensor Enumeration (CSFalcon / CrowdStrike / Sysmon / Defender) & ARTEX Artifacts
#event_simpleName=ProcessRollup2
| (CommandLine=/(?i)(sc\s+query|get-service|tasklist|systemctl\s+status|pgrep)/ AND CommandLine=/(?i)(csfalcon|crowdstrike|sentinelagent|windefend|cbdefense|sysmon)/)
  OR ImageFileName=/(?i)(\\ProgramData\\artx5v\\|ScopeWeaver|artex-server|artex-worker|BLOODALCHEMY|graphics-hook-filter64\.dll|graphics-hook_config\.bin|artex_config\.json|artex\.yaml)/
  OR CommandLine=/(?i)(artx5v|ScopeWeaver|AntiFox|Pojun|FORANG|sco-fix2|Guanlan|tomicdd\/artex|congdonglinux\/artex|norma-agent|norma\/0\.|artex-enrich\/|artex-readonly\/|ARTEX-worker\/|LLMLeak-RedTeam\/|authorized-exposure-audit|authorized-security-research|ArtexProbe|BLOODALCHEMY|\/Inform\/logger\/|xcai\.(com|pro))/
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine])

// 3. Web Server / Edge Daemon Spawning Shell (Post-Exploit Pivot — java/node require recon/download args)
#event_simpleName=ProcessRollup2
| FileName=/(?i)^(cmd\.exe|powershell\.exe|pwsh\.exe|sh|bash)$/
| ParentBaseFileName=/(?i)^(w3wp\.exe|nginx|httpd|apache2|php-fpm|restjavad)$/
  OR (ParentBaseFileName=/(?i)^(java(\.exe)?|node(\.exe)?)$/ AND CommandLine=/(?i)(whoami|nltest|sc\s+query|curl\s|wget\s|invoke-webrequest|-enc\s|base64|\/dev\/tcp)/)
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])

// 4. Anomalous Server/DMZ LLM API DNS Lookups, Webhook/DNSLog Exfil, or Ports 8787 / 8788 / 8790
(#event_simpleName=DnsRequest AND DomainName=/(?i)(api\.anthropic\.com|api\.openai\.com|api\.deepseek\.com|open\.bigmodel\.cn|api\.x\.ai|api\.moonshot\.(cn|ai)|dashscope\.aliyuncs\.com|openrouter\.ai|api\.siliconflow\.cn|xcai\.(com|pro)|lanmao666\.(com|xyz)|webhook\.site|oast\.(live|fun|me)|interact\.sh|dnslog\.cn)$/)
OR (#event_simpleName=NetworkConnectIP4 AND RemotePort IN [8787, 8788, 8790])
| ComputerName!=/^(DEV-AI-GW-|WKSTN-|LAPTOP-)/i
| groupBy([ComputerName, DomainName, RemoteAddressIP4, RemotePort], function=[count(as=hits), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=desc)
