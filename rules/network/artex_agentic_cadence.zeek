# ============================================================================
# ARTEX / Autonomous Agentic Offensive Framework — Starter Zeek Detection Script
# Detects: Default console ports (8787/8790), unexpected LLM API TLS SNI egress,
#          webhook/OAST exfiltration, and norma/nuclei/HeadlessChrome headers.
# ============================================================================

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssl

module ArtexDefense;

export {
    redef enum Notice::Type += {
        Agentic_Default_Port,
        Anomalous_LLM_API_Egress,
        Webhook_Exfil_Traffic,
        Agentic_Harness_UserAgent,
        Agentic_HTTP_Error_Burst
    };

    const agentic_ports: set[port] = { 8787/tcp, 8788/tcp, 8790/tcp, 8890/tcp } &redef;

    const llm_api_suffixes: pattern =
        /(^|\.)(api\.anthropic\.com|api\.openai\.com|api\.deepseek\.com|open\.bigmodel\.cn|api\.x\.ai|api\.moonshot\.cn|openrouter\.ai|generativelanguage\.googleapis\.com|api\.groq\.com|api\.together\.xyz|api\.fireworks\.ai|dashscope\.aliyuncs\.com|ark\.cn-beijing\.volces\.com|xcai\.com|xcai\.pro|lanmao666\.com|lanmao666\.xyz|artex\.lol|nginxmysql\.com|vietnam852\.com)$/i &redef;

    const webhook_exfil_suffixes: pattern =
        /(^|\.)(webhook\.site|oast\.live|oast\.fun|oast\.me|interact\.sh|dnslog\.cn)$/i &redef;

    # Tightened to avoid FP hits on benign strings ("normal", "smartex") or standalone QA HeadlessChrome
    const agentic_ua_pattern: pattern =
        /(norma\/[0-9]|norma-agent|artex-enrich\/|rex_enrich|artex-readonly\/|ARTEX-worker\/|artex-selfupdate|ArtExVerify\/|ArtEx\/1\.0|Mozilla\/5\.0 \(ARTEX\)|security-testing; authorized|LLMLeak-RedTeam\/|authorized-security-research\/|authorized-exposure-audit\/|authori[sz]ed[-_ ;\/]+(scan|audit|pentest|exposure|security|recon|research)|vulnerability-disclosure-policy-review|recon-audit|Fuzz Faster U Fool|ArtexProbe|artex-probe|ScopeWeaver|qwen-code\/|kimi-cli\/|opencode\/|hermes-agent\/|strix\/|Nuclei)/i &redef;

    # Populate with corporate user-workstation & approved AI gateway subnets so LLM alerts focus on Server/DMZ tiers
    const approved_llm_sources: set[subnet] = {} &redef;
    # Separate allowlist for authorized web/vuln scanners exempt from HTTP 4xx burst notices
    const http_error_ignore_sources: set[subnet] = {} &redef;
    const error_burst_threshold: double = 20.0 &redef;
    const error_burst_window: interval = 60sec &redef;
}

event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="artex.http_4xx_errors", $apply=set(SumStats::SUM));
    SumStats::create([$name="artex-http-error-burst",
                      $epoch=error_burst_window,
                      $reducers=set(r1),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                          {
                          return result["artex.http_4xx_errors"]$sum;
                          },
                      $threshold=error_burst_threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          NOTICE([$note=Agentic_HTTP_Error_Burst,
                                  $src=key$host,
                                  $msg=fmt("Rapid HTTP 4xx/5xx error burst from %s (%.0f errors in %s)", key$host, result["artex.http_4xx_errors"]$sum, error_burst_window),
                                  $identifier=cat(key$host, "http_err_burst")]);
                          }]);
    }

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    if ( code >= 400 && ! (c$id$orig_h in http_error_ignore_sources) )
        {
        SumStats::observe("artex.http_4xx_errors", [$host=c$id$orig_h], [$num=1]);
        }
    }

event connection_established(c: connection)
    {
    if ( c$id$resp_p in agentic_ports )
        {
        NOTICE([$note=Agentic_Default_Port,
                $conn=c,
                $msg=fmt("Connection to ARTEX/agentic default console port %s", c$id$resp_p),
                $identifier=cat(c$id$orig_h, c$id$resp_h, c$id$resp_p)]);
        }
    }

event ssl_extension_server_name(c: connection, is_orig: bool, names: string_vec)
    {
    if ( ! is_orig )
        return;
    for ( i in names )
        {
        local sni = names[i];
        if ( llm_api_suffixes in sni && ! (c$id$orig_h in approved_llm_sources) )
            {
            NOTICE([$note=Anomalous_LLM_API_Egress,
                    $conn=c,
                    $msg=fmt("Unapproved host %s connected to LLM API SNI %s", c$id$orig_h, sni),
                    $identifier=cat(c$id$orig_h, sni)]);
            }
        else if ( webhook_exfil_suffixes in sni )
            {
            NOTICE([$note=Webhook_Exfil_Traffic,
                    $conn=c,
                    $msg=fmt("Host %s connected to webhook/OAST exfil domain %s", c$id$orig_h, sni),
                    $identifier=cat(c$id$orig_h, sni)]);
            }
        }
    }

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( ! is_orig )
        return;
    if ( name == "USER-AGENT" && agentic_ua_pattern in value )
        {
        NOTICE([$note=Agentic_Harness_UserAgent,
                $conn=c,
                $msg=fmt("Suspicious agentic/harness User-Agent from %s: %s", c$id$orig_h, value),
                $identifier=cat(c$id$orig_h, value)]);
        }
    }
