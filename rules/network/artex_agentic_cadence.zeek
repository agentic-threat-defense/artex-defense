# ============================================================================
# ARTEX / Autonomous Agentic Offensive Framework — Starter Zeek Detection Script
# Detects: Default console ports (8787/8790), unexpected LLM API TLS SNI egress,
#          webhook/OAST exfiltration, and norma/nuclei/HeadlessChrome headers.
# ============================================================================

@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssl

module ArtexDefense;

export {
    redef enum Notice::Type += {
        Agentic_Default_Port,
        Anomalous_LLM_API_Egress,
        Webhook_Exfil_Traffic,
        Agentic_Harness_UserAgent
    };

    const agentic_ports: set[port] = { 8787/tcp, 8788/tcp, 8790/tcp } &redef;

    const llm_api_suffixes: pattern =
        /(^|\.)(api\.anthropic\.com|api\.openai\.com|api\.deepseek\.com|open\.bigmodel\.cn|api\.x\.ai|api\.moonshot\.cn|xcai\.com|xcai\.pro|lanmao666\.com|lanmao666\.xyz)$/i &redef;

    const webhook_exfil_suffixes: pattern =
        /(^|\.)(webhook\.site|oast\.live|oast\.fun|oast\.me|interact\.sh|dnslog\.cn)$/i &redef;

    # Tightened to avoid FP hits on benign strings ("normal", "smartex") or standalone QA HeadlessChrome
    const agentic_ua_pattern: pattern =
        /(norma\/[0-9]|norma-agent|artex-enrich\/|rex_enrich|artex-readonly\/|ARTEX-worker\/|artex-selfupdate|ArtExVerify\/|ArtEx\/1\.0|Mozilla\/5\.0 \(ARTEX\)|security-testing; authorized|LLMLeak-RedTeam\/|authorized-security-research\/|authorized-exposure-audit\/|authori[sz]ed[-_ ;\/]+(scan|audit|pentest|exposure|security|recon|research)|vulnerability-disclosure-policy-review|recon-audit|Fuzz Faster U Fool|ArtexProbe|artex-probe|ScopeWeaver|qwen-code\/|kimi-cli\/|opencode\/|hermes-agent\/|strix\/|Nuclei)/i &redef;

    # Populate with corporate user-workstation & approved AI gateway subnets so LLM alerts focus on Server/DMZ tiers
    const approved_llm_sources: set[subnet] = {} &redef;
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
