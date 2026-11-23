import "pe"

rule HUNT_APT_VAPORPANDA_BloodAlchemy_ARTEX_Loader {
    meta:
        description = "Retrohunt rule targeting unsigned BLOODALCHEMY PE payloads/sideloaders and ARTEX/ScopeWeaver/CyberStrikeAI binaries and configs"
        author = "ARTEX Defensive Research Workbench"
        threat_actor = "VAPOR PANDA / REF5961"
        date = "2026-11-22"
        reference = "CrowdStrike VAPOR PANDA / Elastic BLOODALCHEMY"
        version = "1.3"

    strings:
        // BLOODALCHEMY C2 & OBS/Brother masquerading artifacts
        $ba_uri     = "/Inform/logger/" ascii wide
        $ba_reg     = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii wide
        $ba_path1   = "\\Test\\test.exe" ascii wide
        $ba_dll_br  = "BrLogApi.dll" ascii wide nocase
        $ba_dll_obs = "graphics-hook-filter64.dll" ascii wide nocase
        $ba_cfg     = "graphics-hook_config.bin" ascii wide nocase

        // ARTEX / ScopeWeaver / norma / CyberStrikeAI / follow-on C2 scaffolding
        $mod_artex  = "github.com/Autumn-27/artex" ascii wide nocase
        $mod_norma  = "github.com/Autumn-27/norma" ascii wide nocase
        $art_path1  = "\\ProgramData\\artx5v\\" ascii wide nocase
        $art_path2  = "artx5v" ascii wide nocase
        $art_cfg1   = "artex_config.json" ascii wide nocase
        $art_cfg2   = "artex.yaml" ascii wide nocase
        $art_ua1    = "artex-enrich/1.0" ascii wide
        $art_ua2    = "artex-readonly/1.0" ascii wide
        $art_ua3    = "ARTEX-worker/1.0" ascii wide
        $art_ua4    = "norma/0." ascii wide
        $art_ua5    = "artex-selfupdate" ascii wide
        $art_probe  = "ArtexProbe" ascii wide nocase
        $art_scope  = "ScopeWeaver" ascii wide nocase
        $art_fork1  = "AntiFox" ascii wide nocase
        $art_fork2  = "sco-fix2" ascii wide nocase
        $art_fork3  = "Agent Security Workbench" ascii wide
        $name_csai  = "CyberStrikeAI" ascii wide nocase
        $name_csai_bin = "cyberstrikeai-" ascii wide nocase
        $name_exploit_agent = "exploit_agent" ascii wide
        $name_adaptix = "adaptixc2" ascii wide nocase
        $name_wisp  = "wisp-c2" ascii wide nocase
        $art_tmpl   = "prompt_templates" ascii wide
        $cfg_graph  = "exploration_nodes" ascii wide
        $cfg_scope  = "scope_targets" ascii wide
        $cfg_llm    = "llm_providers" ascii wide
        $cfg_port   = "port: 8787" ascii wide
        $canary_write   = "ARTEX_WRITE_PROBE" ascii wide
        $canary_persist = "ARTEX_PERSIST_OK" ascii wide
        // UTF-8: 【ARTEX 平台管控·非目标防御】
        $audit_zh = { E3 80 90 41 52 54 45 58 20 E5 B9 B3 E5 8F B0 E7 AE A1 E6 8E A7 C2 B7 E9 9D 9E E7 9B AE E6 A0 87 E9 98 B2 E5 BE A1 E3 80 91 }
        $doc_html    = "<html" nocase ascii
        $doc_doctype = "<!doctype" nocase ascii
        // Multi-marker Go runtime anchors (survives `-ldflags="-s -w"` and garble symbol stripping)
        $go_buildinf = { FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A }
        $go_ver      = "go1.2" ascii
        $go_main     = "runtime.main" ascii
        $port_8787  = ":8787" ascii wide
        $port_8788  = ":8788" ascii wide
        $port_8790  = ":8790" ascii wide

        // Campaign LLM relay & C2 domains
        $c2_xcai1   = "xcai.com" ascii wide nocase
        $c2_xcai2   = "xcai.pro" ascii wide nocase
        $c2_lan1    = "lanmao666.com" ascii wide nocase
        $c2_lan2    = "lanmao666.xyz" ascii wide nocase
        $c2_artex   = "artex.lol" ascii wide nocase
        $c2_sql     = "sqlserver-sqlite.com" ascii wide nocase
        $c2_nginx   = "nginxmysql.com" ascii wide nocase
        $c2_vn      = "vietnam852.com" ascii wide nocase
        $c2_zhzy    = "zhzy999.net" ascii wide nocase

    condition:
        filesize < 35MB and (
            // Path A: Unsigned BLOODALCHEMY PEs / sideloaded DLLs ($ba_reg only as 3-of-N with confirmed C2)
            (
                filesize > 1KB and
                pe.is_pe and pe.number_of_sections > 0 and pe.number_of_signatures == 0 and (
                    any of ($ba_dll_obs, $ba_cfg) or
                    ($ba_uri and any of ($ba_path1, $ba_dll_br)) or
                    ($ba_uri and $ba_reg and any of ($c2_*)) or
                    ($ba_dll_br and $ba_path1)
                )
            )
            or
            // Path B: Compiled PE / ELF / Mach-O / Universal Fat Mach-O ARTEX / ScopeWeaver / CyberStrikeAI binaries
            (
                filesize > 10KB and
                (
                    uint16(0) == 0x5A4D or
                    uint32(0) == 0x464C457F or
                    uint32(0) == 0xFEEDFACF or
                    uint32(0) == 0xCFFAEDFE or
                    uint32(0) == 0xBEBAFECA
                ) and (
                    any of ($mod_artex, $mod_norma, $art_ua1, $art_ua2, $art_ua3, $art_ua5, $art_fork2, $name_csai, $name_csai_bin, $name_adaptix, $name_wisp) or
                    (
                        any of ($go_*) and
                        any of ($art_scope, $art_fork1, $art_fork3, $art_probe, $art_path2, $name_exploit_agent) and
                        any of ($port_8787, $port_8788, $port_8790, $c2_*)
                    )
                )
            )
            or
            // Path C: ARTEX / ScopeWeaver configs & staging artifacts (allows <1KB artex.yaml/artex_config.json paired with config keys; blocks PDF/HTML CTI writeups)
            (
                filesize < 5MB and
                not uint32(0) == 0x46445025 and
                not any of ($doc_html, $doc_doctype) and (
                    any of ($mod_artex, $mod_norma, $art_path1, $audit_zh) or
                    (any of ($art_cfg1, $art_cfg2) and any of ($art_tmpl, $cfg_graph, $cfg_scope, $cfg_llm, $cfg_port, $port_8787, $port_8788, $port_8790, $c2_*)) or
                    ($art_path2 and any of ($art_tmpl, $art_ua4, $art_probe, $art_scope, $art_fork1, $canary_write, $canary_persist, $c2_*)) or
                    (any of ($c2_*) and any of ($art_tmpl, $art_ua4, $art_probe, $art_scope, $art_fork1, $art_ua1, $art_ua2, $art_ua3, $art_ua5, $name_csai, $canary_write, $canary_persist))
                )
            )
        )
}
