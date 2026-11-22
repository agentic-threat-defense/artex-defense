# ============================================================================
# ARTEX / Autonomous Agentic Offensive Framework — Starter Zeek 6/7 Script
# Detects:
#   - High-confidence ARTEX/BLOODALCHEMY C2 & LLM relay SNI/DNS (NEVER allowlisted)
#   - Commercial LLM API egress from non-approved server/DMZ hosts
#   - Webhook/OAST exfiltration domains (TLS SNI & DNS)
#   - ARTEX/Norma/self-proclaimed-authorized User-Agents (bounded suppression key)
#   - HTTP 4xx rapid error bursts across distinct non-asset URIs
#   - External TCP connections to default ARTEX console ports (8787/8788/8790/8890)
# ============================================================================

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/utils/site

module ArtexDefense;

export {
    redef enum Notice::Type += {
        Malicious_LLM_Relay_C2,
        Agentic_Default_Port,
        Anomalous_LLM_API_Egress,
        Webhook_Exfil_Traffic,
        Agentic_Harness_UserAgent,
        Agentic_HTTP_Error_Burst
    };

    const agentic_ports: set[port] = { 8787/tcp, 8788/tcp, 8790/tcp, 8890/tcp } &redef;

    # High-confidence ARTEX / BLOODALCHEMY relay & C2 domains — NEVER suppressed by approved_llm_sources
    const malicious_llm_relay_suffixes: pattern =
        /(^|\.)(xcai\.com|xcai\.pro|lanmao666\.com|lanmao666\.xyz|artex\.lol|nginxmysql\.com|vietnam852\.com|zhzy999\.net|sqlserver-sqlite\.com|artex\.noog2infra\.site|artex\.ok7777\.eu\.cc|artex\.tokena2b\.top)$/i &redef;

    # Commercial LLM APIs (scoped via approved_llm_sources so Server/DMZ tiers alert while workstations are quiet)
    const commercial_llm_api_suffixes: pattern =
        /(^|\.)(api\.anthropic\.com|api\.openai\.com|api\.deepseek\.com|open\.bigmodel\.cn|api\.x\.ai|api\.moonshot\.cn|api\.moonshot\.ai|api\.siliconflow\.cn|openrouter\.ai|generativelanguage\.googleapis\.com|api\.groq\.com|api\.together\.xyz|api\.fireworks\.ai|dashscope\.aliyuncs\.com|ark\.cn-beijing\.volces\.com)$/i &redef;

    const webhook_exfil_suffixes: pattern =
        /(^|\.)(webhook\.site|oast\.live|oast\.fun|oast\.me|interact\.sh|dnslog\.cn)$/i &redef;

    # Tightened to avoid FP hits on benign strings ("normal", "smartex") or standalone QA HeadlessChrome
    const agentic_ua_pattern: pattern =
        /(norma\/[0-9]|norma-agent|artex-enrich\/|rex_enrich|artex-readonly\/|ARTEX-worker\/|(^|[^a-zA-Z0-9_])artex-(agent($|[^a-zA-Z0-9_])|judge-[a-zA-Z0-9_-]+)|artex-selfupdate|ArtExVerify\/|ArtEx\/1\.0|Mozilla\/5\.0 \(ARTEX\)|security-testing; authorized|LLMLeak-RedTeam\/|authorized-security-research\/|authorized-exposure-audit\/|authori[sz]ed[-_ ;\/]+(scan|audit|pentest|exposure|security|recon|research)|vulnerability-disclosure-policy-review|recon-audit|Fuzz Faster U Fool|ArtexProbe|artex-probe|ScopeWeaver|hermes-agent\/|strix\/|Nuclei)/i &redef;

    const static_asset_uri_pattern: pattern =
        /(\/favicon\.ico|\.(png|jpe?g|gif|svg|ico|css|js|map|woff2?|ttf)(\?|$))/i &redef;

    # Populate with corporate user-workstation & approved AI gateway subnets so commercial LLM alerts focus on Server/DMZ
    const approved_llm_sources: set[subnet] = {} &redef;
    # Separate allowlist for authorized web/vuln scanners exempt from HTTP 4xx burst notices
    const http_error_ignore_sources: set[subnet] = {} &redef;
    # Ignore purely internal RFC1918/Site::local_nets traffic on ports 8787-8890 (e.g., internal RStudio Server)
    const ignore_internal_default_ports: bool = T &redef;
    const error_burst_threshold: double = 20.0 &redef;
    const error_burst_unique_uris: count = 5 &redef;
    const error_burst_window: interval = 60sec &redef;
}

event zeek_init()
    {
    local r_cnt = SumStats::Reducer($stream="artex.http_4xx_errors", $apply=set(SumStats::SUM));
    local r_uri = SumStats::Reducer($stream="artex.http_4xx_uris", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="artex-http-error-burst",
                      $epoch=error_burst_window,
                      $reducers=set(r_cnt, r_uri),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                          {
                          if ( "artex.http_4xx_errors" !in result )
                              return 0.0;
                          return result["artex.http_4xx_errors"]$sum;
                          },
                      $threshold=error_burst_threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          local uniq: count = 0;
                          if ( "artex.http_4xx_uris" in result )
                              uniq = result["artex.http_4xx_uris"]$unique;
                          if ( uniq < error_burst_unique_uris )
                              return;
                          NOTICE([$note=Agentic_HTTP_Error_Burst,
                                  $src=key$host,
                                  $msg=fmt("Rapid HTTP 4xx error burst from %s (%.0f errors across %d distinct URIs in %s)", key$host, result["artex.http_4xx_errors"]$sum, uniq, error_burst_window),
                                  $identifier=fmt("%s|http_err_burst", key$host),
                                  $suppress_for=15mins]);
                          }]);
    }

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    # Count client-side 4xx errors only (exclude 5xx upstream outages and benign static assets)
    if ( code >= 400 && code < 500 && ! (c$id$orig_h in http_error_ignore_sources) )
        {
        local uri = "";
        if ( c?$http && c$http?$uri )
            {
            uri = c$http$uri;
            if ( static_asset_uri_pattern in uri )
                return;
            }
        SumStats::observe("artex.http_4xx_errors", [$host=c$id$orig_h], [$num=1]);
        if ( |uri| > 0 )
            SumStats::observe("artex.http_4xx_uris", [$host=c$id$orig_h], [$str=uri]);
        }
    }

event connection_established(c: connection)
    {
    if ( c$id$resp_p in agentic_ports )
        {
        if ( ignore_internal_default_ports && Site::is_local_addr(c$id$resp_h) )
            return;
        NOTICE([$note=Agentic_Default_Port,
                $conn=c,
                $msg=fmt("External connection to ARTEX/agentic default console port %s", c$id$resp_p),
                $identifier=fmt("%s|%s|%s", c$id$orig_h, c$id$resp_h, c$id$resp_p),
                $suppress_for=15mins]);
        }
    }

event ssl_extension_server_name(c: connection, is_orig: bool, names: string_vec)
    {
    if ( ! is_orig )
        return;
    for ( i in names )
        {
        local sni = names[i];
        if ( malicious_llm_relay_suffixes in sni )
            {
            NOTICE([$note=Malicious_LLM_Relay_C2,
                    $conn=c,
                    $msg=fmt("Host %s connected to confirmed ARTEX/BLOODALCHEMY relay/C2 SNI %s", c$id$orig_h, sni),
                    $identifier=fmt("%s|c2|%s", c$id$orig_h, sni),
                    $suppress_for=15mins]);
            }
        else if ( webhook_exfil_suffixes in sni )
            {
            NOTICE([$note=Webhook_Exfil_Traffic,
                    $conn=c,
                    $msg=fmt("Host %s connected to webhook/OAST exfil domain %s", c$id$orig_h, sni),
                    $identifier=fmt("%s|oast|%s", c$id$orig_h, sni),
                    $suppress_for=15mins]);
            }
        else if ( commercial_llm_api_suffixes in sni && ! (c$id$orig_h in approved_llm_sources) )
            {
            NOTICE([$note=Anomalous_LLM_API_Egress,
                    $conn=c,
                    $msg=fmt("Unapproved host %s connected to commercial LLM API SNI %s", c$id$orig_h, sni),
                    $identifier=fmt("%s|llm|%s", c$id$orig_h, sni),
                    $suppress_for=30mins]);
            }
        }
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( malicious_llm_relay_suffixes in query )
        {
        NOTICE([$note=Malicious_LLM_Relay_C2,
                $conn=c,
                $msg=fmt("Host %s resolved confirmed ARTEX/BLOODALCHEMY relay/C2 domain %s", c$id$orig_h, query),
                $identifier=fmt("%s|dns_c2|%s", c$id$orig_h, query),
                $suppress_for=15mins]);
        }
    else if ( webhook_exfil_suffixes in query )
        {
        NOTICE([$note=Webhook_Exfil_Traffic,
                $conn=c,
                $msg=fmt("Host %s resolved webhook/OAST exfil domain %s", c$id$orig_h, query),
                $identifier=fmt("%s|dns_oast|%s", c$id$orig_h, query),
                $suppress_for=15mins]);
        }
    }

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( ! is_orig )
        return;
    if ( name == "USER-AGENT" && agentic_ua_pattern in value )
        {
        # Bounded suppression key (never embed raw attacker-controlled UA value into $identifier)
        NOTICE([$note=Agentic_Harness_UserAgent,
                $conn=c,
                $msg=fmt("Suspicious agentic/harness User-Agent from %s: %s", c$id$orig_h, value),
                $identifier=fmt("%s|agentic_ua", c$id$orig_h),
                $suppress_for=15mins]);
        }
    }
