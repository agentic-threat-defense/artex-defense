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
in(#event_simpleName, values=["DnsRequest", "DnsLookup"])
| DomainName=/(?:^|\.)(xcai\.(com|pro)|lanmao666\.(com|xyz)|artex\.lol|nginxmysql\.com|vietnam852\.com|zhzy999\.net|sqlserver-sqlite\.com|artex\.noog2infra\.site|artex\.ok7777\.eu\.cc|artex\.tokena2b\.top)\.?$/i
| default(field=[ContextBaseFileName], value="-")
| groupBy([ComputerName, ContextBaseFileName, DomainName], function=[count(as=hits), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=desc)

// T1-B. Explicit ARTEX / BLOODALCHEMY / ScopeWeaver Artifacts, EDR Sensor Enumeration, & Follow-On C2
//       (Covers both Windows backslashes and Linux forward slashes; excludes read-only local repo/grep tools on artex-defense;
//        scopes Responder/Coercer to exact tool folder boundaries so look-alike folders like autoresponder/ produce 0 FP)
#event_simpleName=ProcessRollup2
| not (ImageFileName=/[\/\\](git|rg|grep|egrep|fgrep|less|cat|vim|nvim|code|pytest|python3?)(\.exe)?$/i AND CommandLine=/artex[-_]defense/i)
| (CommandLine=/(?i)(sc(\.exe)?\s+query|get-service|tasklist|systemctl\s+status|pgrep)/ AND CommandLine=/(?i)(csfalcon|falcon-sensor|crowdstrike|sentinelagent|windefend|cbdefense|sysmon)/)
  OR ImageFileName=/([\/\\]ProgramData[\/\\]artx5v[\/\\]|[\/\\]ScopeWeaver(\.exe)?$|[\/\\]artex-(server|worker|pro|mx)(\.exe)?$|[\/\\](vshell|wisp)(\.exe)?$)/i
  OR CommandLine=/(?i)(artx5v|ScopeWeaver|AntiFox|Pojun|FORANG|sco-fix2|guanlan\s*sec|tomicdd\/artex|congdonglinux\/artex|norma-agent|norma\/[0-9]|artex-enrich\/|artex-readonly\/|ARTEX-worker\/|artex-selfupdate|LLMLeak-RedTeam\/|authorized-exposure-audit|authorized-security-research|ArtexProbe|CyberStrikeAI|graphics-hook-filter64\.dll|graphics-hook_config\.bin|artex_config\.json|artex\.yaml|mitmproxy-ca-cert\.pem|traffic\/_index\/index\.sqlite|\/Inform\/logger\/|(?:^|[\s\/:"'])xcai\.(com|pro)\b|lsadump::|sekurlsa::|adaptixc2|\bwisp[-_]?c2\b|ligolo-agent|\bntlmrelayx\b|\bsmbserver\.py\b|\bsecretsdump\b|\bpetitpotam\b|\bcertipy\b|\bkerbrute\b|\bbloodhound\b|\bldapdomaindump\b|\bevil-winrm\b|\bnetexec\b)/
  OR CommandLine=/(?:^|[\s"'\/\\])(responder[\/\\]responder\.py|coercer[\/\\]coercer\.py)(?:$|[\s"'])/i
  OR CommandLine=/\bcoercer(?:\.py)?\s+(coerce|scan|fuzz)\b/i
  OR (CommandLine=/(?i)\bchisel\b/ AND CommandLine=/(?i)\bclient\b/)
  OR (CommandLine=/(?i)\bvshell\b/ AND NOT CommandLine=/(?i)(VsDevShell|VisualStudio\.DevShell)/)
| table([@timestamp, ComputerName, ParentBaseFileName, ImageFileName, CommandLine], limit=2000)

// T1-C. BLOODALCHEMY Sideloaded DLL & ARTEX Host Staging Files Written to Disk (ALL Hosts)
//       (Catches graphics-hook-filter64.dll / graphics-hook_config.bin / artex_config.json / artx5v even when ProcessRollup2 only logs the host binary)
in(#event_simpleName, values=["PeFileWritten", "NewExecutableWritten", "ElfFileWritten", "FileWritten"])
| TargetFileName=/([\/\\]graphics-hook-filter64\.dll$|[\/\\]graphics-hook_config\.bin$|[\/\\]artx5v[\/\\]|[\/\\]artex_config\.json$|[\/\\]artex\.yaml$|[\/\\]xcai-effort-shim\.py$|[\/\\]mitmproxy-ca-cert\.pem$)/i
| default(field=[ContextBaseFileName], value="-")
| table([@timestamp, ComputerName, #event_simpleName, ContextBaseFileName, TargetFileName], limit=2000)


// ============================================================================
// TIER 2 — BEHAVIORAL & BASELINE-REQUIRED HUNTS (Expect Org-Specific Tuning)
// ============================================================================

// T2-A. External Console Ports 8787/8788/8790/8890/18899 (External Non-RFC1918 IPs Only, Excl. Zscaler 8890)
//       (Note: For targeted CyberStrikeAI hunts, optionally append 5001, 5002, 5003, 8082 after baselining dev/proxy apps)
#event_simpleName=NetworkConnectIP4
| in(RemotePort, values=[8787, 8788, 8790, 8890, 18899])
| not (RemotePort=8890 AND ContextBaseFileName=/^ZSA/i)
| not cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"])
| default(field=[ContextBaseFileName], value="-")
| groupBy([ComputerName, ContextBaseFileName, RemoteAddressIP4, RemotePort], function=[count(as=hits), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=asc)

// T2-B. Webhook / OAST Exfiltration & IMDS Wildcard-DNS Evasion (Excludes Dev Browsers/Postman/MsSense/ZSA on webhook.site)
//       (Covers full ProjectDiscovery oast.* fleet plus IMDS-only wildcard DNS like 169-254-169-254.sslip.io / a9fea9fe.nip.io)
in(#event_simpleName, values=["DnsRequest", "DnsLookup"])
| DomainName=/(?:^|\.)(webhook\.site|oast\.(live|fun|me|pro|site|online)|interact\.sh|dnslog\.cn)\.?$/i
  OR DomainName=/(?:^|[.\-])(169[.\-]254[.\-](169[.\-]254|170[.\-]2)|a9fea9fe)\.(sslip\.io|nip\.io|xip\.io|traefik\.me)\.?$/i
| not (DomainName=/webhook\.site/i AND ContextBaseFileName=/^(chrome|msedge|firefox|brave|safari|postman|code|mssense|zsa)/i)
| default(field=[ContextBaseFileName], value="-")
| groupBy([ComputerName, ContextBaseFileName, DomainName], function=[count(as=hits), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=asc)

// T2-C. Web Server / Edge / Ruby App Daemon Spawning Shell — Least-Frequency-of-Occurrence (LFO) Fleet Hunt
//       (Covers Ruby2Shell CVE-2026-132825 parents puma/unicorn/unicorn_rails/passenger + ruby runtime with suspicious shell args;
//        scopes GCP metadata.google.internal exemption strictly to standalone curl/wget probes)
#event_simpleName=ProcessRollup2
| ImageFileName=/[\/\\](cmd\.exe|powershell\.exe|pwsh(\.exe)?|sh|bash)$/i
| (ParentBaseFileName=/^(w3wp\.exe|nginx(\.exe)?|httpd(\.exe)?|apache2|php-fpm|restjavad|tomcat(\.exe)?|sqlservr\.exe|puma|unicorn|unicorn_rails|passenger)$/i)
  OR (ParentBaseFileName=/^(java(\.exe)?|node(\.exe)?|ruby(\.exe)?)$/i AND (
      CommandLine=/(whoami|\bid\b|nltest|sc\s+query|invoke-webrequest|-enc(?:odedcommand)?\s|base64|\/dev\/tcp|\bnc\s)/i
      OR (CommandLine=/(curl|wget)\s/i AND NOT (CommandLine=/metadata\.google\.internal/i AND NOT CommandLine=/(service-accounts|\/token\b|ssh-keys|kube-env|recursive=true|iam\/security-credentials|;|&&|\|\||\||`|\$\()/i))
  ))
| groupBy([ParentBaseFileName, ImageFileName, CommandLine], function=[count(as=hits), count(field=ComputerName, distinct=true, as=hosts), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=asc)

// T2-D1. Compressed Endpoint Recon & Tri-Cloud CLI Burst (>= 5 Unique Discovery Cmds in 30s — Windows + Linux Parity)
//        (Buckets by [aid, ComputerName] because UserName can be empty on raw ProcessRollup2 events)
#event_simpleName=ProcessRollup2
| CommandLine=/(?i)(\b(whoami|id|uname|hostname|ipconfig|ifconfig|ip\s+(?:a|addr|route)|ss\s+-|netstat|ps\s+(?:aux|-ef)|nltest|net\s+localgroup|aws\s+sts|az\s+account|gcloud\s+(?:auth|iam|secrets)|kubectl\s+get|sc\s+query|tasklist|get-service)\b|\/etc\/passwd)/
| bucket(span=30s, field=[aid, ComputerName], function=[count(as=cmd_count), count(field=CommandLine, distinct=true, as=unique_cmds), collect([CommandLine], limit=10)])
| unique_cmds >= 5
| sort(unique_cmds, order=desc)

// T2-D2. Single-Shell Chained Multi-Recon Evasion (Catches `bash -c "whoami; id; uname -a; ip a; cat /etc/passwd"` in 1 ProcessRollup2 event)
#event_simpleName=ProcessRollup2
| CommandLine=/(?i)(\b(?:whoami|id|uname|hostname|ipconfig|ifconfig|ip\s+(?:a|addr|route)|ss\s+-|netstat|nltest|sc\s+query|gcloud\s+auth)\b|\/etc\/passwd)[^\r\n]*[;&|]+[^\r\n]*(\b(?:whoami|id|uname|hostname|ipconfig|ifconfig|ip\s+(?:a|addr|route)|ss\s+-|netstat|nltest|sc\s+query|gcloud\s+auth)\b|\/etc\/passwd)[^\r\n]*[;&|]+[^\r\n]*(\b(?:whoami|id|uname|hostname|ipconfig|ifconfig|ip\s+(?:a|addr|route)|ss\s+-|netstat|nltest|sc\s+query|gcloud\s+auth)\b|\/etc\/passwd)/
| groupBy([ParentBaseFileName, ImageFileName, CommandLine], function=[count(as=hits), count(field=ComputerName, distinct=true, as=hosts), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=asc)

// T2-E. Server / DMZ Commercial LLM API & Wildcard-IP DNS Lookups (Baseline Required)
//       (Recommended: enrich via Falcon aid_master lookup for ProductType="Server" / "Domain Controller"
//        rather than relying solely on ComputerName prefixes; tune the exclusion regex to your naming scheme)
in(#event_simpleName, values=["DnsRequest", "DnsLookup"])
| DomainName=/(?:^|\.)(api\.anthropic\.com|api\.openai\.com|api\.deepseek\.com|open\.bigmodel\.cn|api\.x\.ai|api\.moonshot\.(cn|ai)|dashscope\.aliyuncs\.com|openrouter\.ai|api\.siliconflow\.cn|sslip\.io|nip\.io|xip\.io|traefik\.me)\.?$/i
| not ComputerName=/^(DEV-AI-GW-|WKSTN-|LAPTOP-|MACBOOK-|DESKTOP-)/i
| default(field=[ContextBaseFileName], value="-")
| groupBy([ComputerName, ContextBaseFileName, DomainName], function=[count(as=hits), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=asc)

// T2-F. Server-Scoped Ephemeral Quick Tunnels (`cloudflared tunnel --url`, Temp-Staged `cloudflared`, `devtunnel host`)
//       (Recommended: enrich via Falcon aid_master lookup for ProductType="Server" / "Domain Controller";
//        excludes standard `/usr/bin/cloudflared tunnel run <named-tunnel>` ingress daemons; covers Linux & Windows temp dirs)
#event_simpleName=ProcessRollup2
| not ComputerName=/^(DEV-AI-GW-|WKSTN-|LAPTOP-|MACBOOK-|DESKTOP-)/i
| (CommandLine=/\bcloudflared(\.exe)?\s+tunnel\b[^\r\n]*--url\b/i)
  OR (ImageFileName=/(\/(tmp|dev\/shm|var\/tmp)\/|\\Temp\\)[^\s]*cloudflared/i AND CommandLine=/\btunnel\b/i)
  OR (CommandLine=/\bdevtunnel(\.exe)?\s+host\b/i)
| groupBy([ComputerName, ParentBaseFileName, ImageFileName, CommandLine], function=[count(as=hits), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=asc)

// T2-G. AI Coding Agent / Harness Spawning Explicit Offensive Pentest Tools
//       (Excludes read-only git/rg/grep/pytest dev utilities, Ory Hydra OAuth2 CLI, and dev-laptop tunnels which are server-scoped in T2-F)
#event_simpleName=ProcessRollup2
| not ImageFileName=/[\/\\](git|rg|grep|egrep|fgrep|pytest|cat|less|vim|nvim|sed|awk)(\.exe)?$/i
| (ParentBaseFileName=/^(claude|codex|opencode|qwen-code|kimi-cli|hermes-agent|agent[-_]zero)(\.exe)?$/i
   OR CommandLine=/(shell-snapshots|claude_code_shell_launcher_script)/i)
| (ImageFileName=/[\/\\](nmap|masscan|nuclei|sqlmap|ffuf|gobuster|chisel|ntlmrelayx|netexec|nxc|evil-winrm|certipy|bloodhound|sharphound|rubeus|secretsdump|wpscan|nikto|msfconsole|coercer)(\.exe)?$/i
   OR CommandLine=/(?:^|[\s;&|'"\/\\])(nmap|masscan|nuclei|sqlmap|ffuf|gobuster|chisel|ntlmrelayx|netexec|nxc|evil-winrm|certipy|bloodhound|sharphound|rubeus|secretsdump|wpscan|nikto|msfconsole|coercer)(\.exe|\.py|\.rb|\.pl)?(?:\s|$|["';|&])/i
   OR CommandLine=/(?:^|[\s"'\/\\])(responder[\/\\]responder\.py|coercer[\/\\]coercer\.py)(?:$|[\s"'])/i)
| groupBy([ComputerName, ParentBaseFileName, ImageFileName, CommandLine], function=[count(as=hits), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(hits, order=asc)
