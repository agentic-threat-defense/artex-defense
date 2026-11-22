/*
  Google Threat Intelligence (GTI) Livehunt Ruleset (requires VirusTotal `vt` module)
  Note: Load in VirusTotal Livehunt — local `yara` CLI does not bundle the `vt` module.
  Learn more: https://gtidocs.virustotal.com/docs/livehunt-guide
*/
import "vt"

rule ARTEX_Payloads_and_Agent_Transcripts {
    meta:
        description = "Livehunt rule for unsigned BLOODALCHEMY PE drops, ARTEX/ScopeWeaver Go binaries, and agent transcripts/configs"
        author = "ARTEX Defensive Research Workbench"
        entity = "file"
        date = "2026-11-22"
        version = "1.2"

    strings:
        // High-confidence BLOODALCHEMY masqueraded sideload artifacts (PE-gated)
        $ba_dll = "graphics-hook-filter64.dll" ascii wide nocase
        $ba_cfg = "graphics-hook_config.bin" ascii wide nocase
        $ba_uri = "/Inform/logger/" ascii wide

        // Strong ARTEX / norma SDK anchors
        $mod_artex = "github.com/Autumn-27/artex" ascii wide nocase
        $mod_norma = "github.com/Autumn-27/norma" ascii wide nocase
        $art_path  = "artx5v" ascii wide nocase
        $art_yaml  = "artex.yaml" ascii wide nocase
        $art_json  = "artex_config.json" ascii wide nocase
        $art_ua1   = "artex-enrich/1.0" ascii wide
        $art_ua2   = "artex-readonly/1.0" ascii wide
        $art_ua3   = "ARTEX-worker/1.0" ascii wide
        $art_ua4   = "artex-selfupdate" ascii wide
        $art_norma = "norma/0." ascii wide
        $art_probe = "ArtexProbe" ascii wide nocase
        $art_scope = "ScopeWeaver" ascii wide nocase
        $art_fork1 = "AntiFox" ascii wide nocase
        $art_fork2 = "sco-fix2" ascii wide nocase
        $art_fork3 = "Agent Security Workbench" ascii wide
        $go_marker = "runtime.main" ascii
        $port_8787 = ":8787" ascii wide
        $port_8790 = ":8790" ascii wide

        // Campaign LLM relay & C2 domains
        $c2_xcai1  = "xcai.com" ascii wide nocase
        $c2_xcai2  = "xcai.pro" ascii wide nocase
        $c2_lan1   = "lanmao666.com" ascii wide nocase
        $c2_lan2   = "lanmao666.xyz" ascii wide nocase
        $c2_artex  = "artex.lol" ascii wide nocase
        $c2_sql    = "sqlserver-sqlite.com" ascii wide nocase
        $c2_nginx  = "nginxmysql.com" ascii wide nocase
        $c2_vn     = "vietnam852.com" ascii wide nocase
        $c2_zhzy   = "zhzy999.net" ascii wide nocase

        // Supporting transcript / prompt-harness markers (never matched alone)
        $ctx_claude = "CLAUDE.md" ascii wide
        $ctx_tmpl   = "prompt_templates" ascii wide
        $ctx_intent = /"intent_id"\s*:\s*"i[0-9]{1,6}"/ ascii
        $ctx_graph  = "exploration_nodes" ascii wide

    condition:
        vt.metadata.new_file and
        filesize < 25MB and (
            // 1. Unsigned BLOODALCHEMY PE binaries / sideloaded DLLs (strictly PE-gated so CTI PDFs/rules never FP)
            (
                uint16(0) == 0x5A4D and
                not (for any tag in vt.metadata.tags : ( tag == "signed" )) and
                any of ($ba_dll, $ba_cfg, $ba_uri)
            )
            or
            // 2. Compiled Go ARTEX / ScopeWeaver / AntiFox binaries
            (
                (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE) and
                $go_marker and (
                    any of ($mod_artex, $mod_norma, $art_ua1, $art_ua2, $art_ua3, $art_ua4, $art_fork2) or
                    (any of ($art_scope, $art_fork1, $art_fork3, $art_probe, $art_path) and any of ($port_8787, $port_8790, $c2_*))
                )
            )
            or
            // 3. Direct ARTEX configs or transcripts pairing framework anchors with prompt/intent/C2 context
            (
                filesize < 5MB and (
                    any of ($mod_artex, $mod_norma, $art_yaml, $art_json) or
                    (any of ($art_path, $art_norma, $art_probe, $art_scope, $art_fork1, $art_fork2, $art_ua1, $art_ua2, $art_ua3, $art_ua4, $c2_*) and any of ($ctx_claude, $ctx_tmpl, $ctx_intent, $ctx_graph))
                )
            )
            or
            // 4. Dual-graph Exploration Graph intent logs with harness templates
            (
                filesize < 5MB and
                $ctx_intent and $ctx_graph and any of ($ctx_claude, $ctx_tmpl)
            )
        )
}
