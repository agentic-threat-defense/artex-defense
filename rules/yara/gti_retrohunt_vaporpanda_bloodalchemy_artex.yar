import "pe"

rule HUNT_APT_VAPORPANDA_BloodAlchemy_ARTEX_Loader {
    meta:
        description = "Retrohunt rule targeting BLOODALCHEMY payloads/sideloaders and ARTEX staging/config artifacts"
        author = "Threat Hunt"
        threat_actor = "VAPOR PANDA / REF5961"
        date = "2026-11-20"
        reference = "CrowdStrike VAPOR PANDA / Elastic BLOODALCHEMY"
        version = "1.1"

    strings:
        // BLOODALCHEMY C2 & OBS/Brother masquerading artifacts
        $ba_uri     = "/Inform/logger/" ascii wide
        $ba_reg     = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii wide
        $ba_path1   = "\\Test\\test.exe" ascii wide
        $ba_dll_br  = "BrLogApi.dll" ascii wide nocase
        $ba_dll_obs = "graphics-hook-filter64.dll" ascii wide nocase
        $ba_cfg     = "graphics-hook_config.bin" ascii wide nocase

        // ARTEX / ScopeWeaver / norma SDK scaffolding
        $art_path1  = "\\ProgramData\\artx5v\\" ascii wide nocase
        $art_path2  = "artx5v" ascii wide
        $art_cfg1   = "artex_config.json" ascii wide nocase
        $art_cfg2   = "artex.yaml" ascii wide nocase
        $art_ua1    = "artex-enrich/1.0" ascii wide
        $art_ua2    = "artex-readonly/1.0" ascii wide
        $art_ua3    = "ARTEX-worker/1.0" ascii wide
        $art_ua4    = "norma/0." ascii wide
        $art_probe  = "ArtexProbe" ascii wide nocase
        $art_scope  = "ScopeWeaver" ascii wide nocase
        $art_fork1  = "AntiFox" ascii wide nocase
        $art_fork2  = "sco-fix2" ascii wide nocase
        $art_fork3  = "Agent Security Workbench" ascii wide
        $art_tmpl   = "prompt_templates" ascii wide
        $art_proxy1 = "://xcai.com" ascii wide nocase
        $art_proxy2 = ".xcai.com" ascii wide nocase

    condition:
        filesize > 1KB and filesize < 35MB and (
            // Path A: Unsigned BLOODALCHEMY PEs / sideloaded DLLs
            (
                uint16(0) == 0x5A4D and pe.number_of_sections > 0 and pe.number_of_signatures == 0 and (
                    any of ($ba_dll_obs, $ba_cfg) or
                    ($ba_uri and any of ($ba_reg, $ba_path1, $ba_dll_br)) or
                    ($ba_dll_br and $ba_path1)
                )
            )
            or
            // Path B: ARTEX / ScopeWeaver binaries, configs, and staging artifacts
            (
                any of ($art_path1, $art_cfg1, $art_cfg2, $art_ua1, $art_ua2, $art_ua3, $art_fork2, $art_fork3) or
                ($art_path2 and any of ($art_tmpl, $art_ua4, $art_probe, $art_scope, $art_fork1, $art_proxy*)) or
                (any of ($art_proxy*) and any of ($art_tmpl, $art_ua4, $art_probe, $art_scope, $art_fork1))
            )
        )
}
