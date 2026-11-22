import "pe"

rule HUNT_APT_VAPORPANDA_BloodAlchemy_ARTEX_Loader {
    meta:
        description = "Retrohunt rule targeting unsigned BLOODALCHEMY PE payloads/sideloaders and ARTEX/ScopeWeaver binaries and configs"
        author = "ARTEX Defensive Research Workbench"
        threat_actor = "VAPOR PANDA / REF5961"
        date = "2026-11-22"
        reference = "CrowdStrike VAPOR PANDA / Elastic BLOODALCHEMY"
        version = "1.2"

    strings:
        // BLOODALCHEMY C2 & OBS/Brother masquerading artifacts
        $ba_uri     = "/Inform/logger/" ascii wide
        $ba_reg     = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii wide
        $ba_path1   = "\\Test\\test.exe" ascii wide
        $ba_dll_br  = "BrLogApi.dll" ascii wide nocase
        $ba_dll_obs = "graphics-hook-filter64.dll" ascii wide nocase
        $ba_cfg     = "graphics-hook_config.bin" ascii wide nocase

        // ARTEX / ScopeWeaver / norma SDK scaffolding
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
        $art_tmpl   = "prompt_templates" ascii wide
        $go_marker  = "runtime.main" ascii
        $port_8787  = ":8787" ascii wide
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
            // Path A: Unsigned BLOODALCHEMY PEs / sideloaded DLLs
            (
                filesize > 1KB and
                pe.is_pe and pe.number_of_sections > 0 and pe.number_of_signatures == 0 and (
                    any of ($ba_dll_obs, $ba_cfg) or
                    ($ba_uri and any of ($ba_reg, $ba_path1, $ba_dll_br)) or
                    ($ba_dll_br and $ba_path1)
                )
            )
            or
            // Path B: Compiled Go ARTEX / ScopeWeaver / AntiFox binaries
            (
                filesize > 10KB and
                (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE) and
                $go_marker and (
                    any of ($mod_artex, $mod_norma, $art_ua1, $art_ua2, $art_ua3, $art_ua5, $art_fork2) or
                    (any of ($art_scope, $art_fork1, $art_fork3, $art_probe, $art_path2) and any of ($port_8787, $port_8790, $c2_*))
                )
            )
            or
            // Path C: ARTEX / ScopeWeaver configs & staging artifacts (allows <1KB artex.yaml / artex_config.json)
            (
                filesize < 5MB and (
                    any of ($mod_artex, $mod_norma, $art_path1, $art_cfg1, $art_cfg2) or
                    ($art_path2 and any of ($art_tmpl, $art_ua4, $art_probe, $art_scope, $art_fork1, $c2_*)) or
                    (any of ($c2_*) and any of ($art_tmpl, $art_ua4, $art_probe, $art_scope, $art_fork1, $art_ua1, $art_ua2, $art_ua3, $art_ua5))
                )
            )
        )
}
