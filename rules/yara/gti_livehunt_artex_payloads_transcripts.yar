/*
  Google Threat Intelligence (GTI) Livehunt Ruleset (requires VirusTotal `vt` module)
  Note: Load in VirusTotal Livehunt — local `yara` CLI does not bundle the `vt` module.
  Learn more: https://gtidocs.virustotal.com/docs/livehunt-guide
*/
import "vt"

rule ARTEX_Payloads_and_Agent_Transcripts {
    meta:
        description = "Livehunt rule for unsigned BLOODALCHEMY PE drops, ARTEX/ScopeWeaver/CyberStrikeAI binaries, and agent transcripts/configs"
        author = "ARTEX Defensive Research Workbench"
        entity = "file"
        date = "2026-11-24"
        version = "1.4"

    strings:
        // High-confidence BLOODALCHEMY masqueraded sideload artifacts (PE-gated)
        $ba_dll    = "graphics-hook-filter64.dll" ascii wide nocase
        $ba_cfg    = "graphics-hook_config.bin" ascii wide nocase
        $ba_uri    = "/Inform/logger/" ascii wide
        $ba_path1  = "\\Test\\test.exe" ascii wide
        $ba_dll_br = "BrLogApi.dll" ascii wide nocase

        // Strong ARTEX / norma / CyberStrikeAI / follow-on C2 anchors
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
        $name_csai = "CyberStrikeAI" ascii wide nocase
        $name_csai_bin = "cyberstrikeai-" ascii wide nocase
        $name_exploit_agent = "exploit_agent" ascii wide
        $name_adaptix = "adaptixc2" ascii wide nocase
        $name_wisp = "wisp-c2" ascii wide nocase
        // Multi-marker Go runtime anchors (survives `-ldflags="-s -w"` and garble symbol stripping)
        $go_buildinf = { FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A }
        $go_ver      = "go1.2" ascii
        $go_main     = "runtime.main" ascii
        $port_8787 = ":8787" ascii wide
        $port_8788 = ":8788" ascii wide
        $port_8790 = ":8790" ascii wide
        $cfg_scope = "scope_targets" ascii wide
        $cfg_llm   = "llm_providers" ascii wide
        $cfg_port  = "port: 8787" ascii wide

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

        // Supporting transcript / prompt-harness / Nov 2026 audit & canary markers
        $ctx_claude = "CLAUDE.md" ascii wide
        $ctx_tmpl   = "prompt_templates" ascii wide
        $ctx_intent = /"intent_id"\s*:\s*"i[0-9]{1,6}"/ ascii
        $ctx_graph  = "exploration_nodes" ascii wide
        $canary_write   = "ARTEX_WRITE_PROBE" ascii wide
        $canary_persist = "ARTEX_PERSIST_OK" ascii wide
        // UTF-8: 【ARTEX 平台管控·非目标防御】
        $audit_zh = { E3 80 90 41 52 54 45 58 20 E5 B9 B3 E5 8F B0 E7 AE A1 E6 8E A7 C2 B7 E9 9D 9E E7 9B AE E6 A0 87 E9 98 B2 E5 BE A1 E3 80 91 }
        // Fork-resilient ARTEX recording-proxy CA + SQLite traffic index pair (survives brand-stripping & i18n forks)
        $mitm_ca     = "mitmproxy-ca-cert.pem" ascii wide
        $traffic_idx = "traffic/_index/index.sqlite" ascii wide
        $doc_html    = "<html" nocase ascii
        $doc_doctype = "<!doctype" nocase ascii

    condition:
        vt.metadata.new_file and
        filesize < 25MB and (
            // 1. Unsigned BLOODALCHEMY PE binaries / sideloaded DLLs (strictly PE-gated; /Inform/logger/ requires secondary anchor)
            (
                uint16(0) == 0x5A4D and
                not (for any tag in vt.metadata.tags : ( tag == "signed" )) and (
                    any of ($ba_dll, $ba_cfg) or
                    ($ba_uri and any of ($ba_path1, $ba_dll_br, $c2_*))
                )
            )
            or
            // 2. Compiled PE / ELF / Mach-O / Universal Fat Mach-O ARTEX / ScopeWeaver / CyberStrikeAI / de-branded fork binaries
            (
                (
                    uint16(0) == 0x5A4D or
                    uint32(0) == 0x464C457F or
                    uint32(0) == 0xFEEDFACF or
                    uint32(0) == 0xCFFAEDFE or
                    uint32(0) == 0xBEBAFECA
                ) and (
                    any of ($mod_artex, $mod_norma, $art_ua1, $art_ua2, $art_ua3, $art_ua4, $art_fork2, $name_csai, $name_csai_bin, $name_adaptix, $name_wisp) or
                    ($mitm_ca and $traffic_idx) or
                    (
                        any of ($go_*) and
                        any of ($art_scope, $art_fork1, $art_fork3, $art_probe, $art_path, $name_exploit_agent) and
                        any of ($port_8787, $port_8788, $port_8790, $c2_*)
                    )
                )
            )
            or
            // 3. Direct ARTEX configs or transcripts (excludes PDF/HTML CTI writeups; requires config-key pairing on artex.yaml/artex_config.json)
            (
                filesize < 5MB and
                not uint32(0) == 0x46445025 and
                not any of ($doc_html, $doc_doctype) and (
                    any of ($mod_artex, $mod_norma, $audit_zh) or
                    (any of ($art_yaml, $art_json) and any of ($ctx_graph, $ctx_tmpl, $cfg_scope, $cfg_llm, $cfg_port, $port_8787, $port_8788, $port_8790, $c2_*)) or
                    (any of ($art_path, $art_norma, $art_probe, $art_scope, $art_fork1, $art_fork2, $art_ua1, $art_ua2, $art_ua3, $art_ua4, $name_csai, $name_csai_bin, $c2_*) and any of ($ctx_claude, $ctx_tmpl, $ctx_intent, $ctx_graph, $canary_write, $canary_persist))
                )
            )
            or
            // 4. Dual-graph Exploration Graph intent logs with harness templates
            (
                filesize < 5MB and
                not uint32(0) == 0x46445025 and
                not any of ($doc_html, $doc_doctype) and
                $ctx_intent and $ctx_graph and any of ($ctx_claude, $ctx_tmpl)
            )
            or
            // 5. Fork-resilient recording-proxy CA + SQLite index pair in source tarballs/scripts/configs (blocks PDF & HTML pages without dropping .tar bundles containing Next.js layout.tsx)
            (
                not uint32(0) == 0x46445025 and
                not ($doc_html in (0..511) or $doc_doctype in (0..511)) and
                $mitm_ca and $traffic_idx
            )
        )
}
