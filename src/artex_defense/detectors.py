"""Stage 1 deterministic multi-surface behavioral & artifact detectors + cross-surface correlator."""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import duckdb

from .parsers import parse_auto
from .schemas import CadenceStats, CandidateWindow, KillChainStoryline, SurfaceType

# Known ARTEX / ScopeWeaver / BLOODALCHEMY / agentic framework indicators (defensive reference set)
KNOWN_ARTIFACT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("artex_staging_path", re.compile(r"programdata[/\\]+artx5v", re.IGNORECASE)),
    (
        "artex_cmd_output_spill",
        re.compile(r"/tasks/[0-9]+/i[0-9]+/cmd-output/", re.IGNORECASE),
    ),
    (
        "artex_host_forensics",
        re.compile(
            r"(mitmproxy-ca-cert\.pem|traffic/_index/index\.sqlite|artex_token=|"
            r"artex-selfupdate|【ARTEX 平台管控·非目标防御】|/artex/jwt\.key)",
            re.IGNORECASE,
        ),
    ),
    (
        "artex_console_route",
        re.compile(
            r"(/api/exploration/|/api/intercept/|/api/sync/scopesentry|"
            r"/api/llm/profiles|/api/llm/records|/api/update/stream|"
            r"/function/(?:tasks|findings|traffic|llm-records)|"
            r"/system/(?:intercept|llm|mcp|skills))",
            re.IGNORECASE,
        ),
    ),
    (
        "artex_config_artifact",
        re.compile(r"\b(artex_config\.json|artex\.yaml|xcai-effort-shim\.py)\b", re.IGNORECASE),
    ),
    (
        "bloodalchemy_artifact",
        re.compile(
            r"(graphics-hook-filter64\.dll|graphics-hook_config\.bin|/Inform/logger/)",
            re.IGNORECASE,
        ),
    ),
    (
        "artex_family_keyword",
        re.compile(
            r"\b(artex|artex-enrich|artex-readonly|artex-worker|artex-audit|artex-pentest|"
            r"artex-verify|artex-spawn|artex-agent|artex-judge-[a-z0-9_-]+|artex-i\d+-canary|"
            r"artexprobe|artex-probe|scopeweaver|antifox|pojun|forang|sco-fix2|guanlan\s*sec|"
            r"bloodalchemy|artex\s*mx|agent\s+security\s+workbench|tomicdd/artex|congdonglinux/artex|"
            r"cyberstrikeai|pentagi|hexstrike|cairn|reaper-agent|strix-agent|shannon-agent|"
            r"hermes-agent|agent-zero|carbonato|exploit_agent|openbullet)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "norma_harness",
        re.compile(r"\bnorma/\d+\.\d+|\bnorma[-_/]?agent\b|x-norma-|\bnorma\b.*harness", re.IGNORECASE),
    ),
    (
        "unit42_canary_probe",
        re.compile(
            r"(zz_no_such_user|zzq\.nonexistent|precheck\.not-a-user|zzzrandom\d+|"
            r"nonexistent-i\d+|zz-no-such-key|zz-notexist-|artex_control_marker|"
            r"artex_write_probe|artex-probe-\d+|artex_persist_ok|x-artx-key|"
            r"illegal_redirect_uri_enhanced|[?&]artex=)",
            re.IGNORECASE,
        ),
    ),
    ("python_open_staging", re.compile(r"(simplehttp/|directory listing for /|taskid=)", re.IGNORECASE)),
]

KNOWN_LLM_API_DOMAINS: tuple[str, ...] = (
    "api.anthropic.com",
    "api.openai.com",
    "api.deepseek.com",
    "open.bigmodel.cn",
    "api.x.ai",
    "api.moonshot.cn",
    "api.moonshot.ai",
    "generativelanguage.googleapis.com",
    "dashscope.aliyuncs.com",
    "dashscope-intl.aliyuncs.com",
    "openrouter.ai",
    "api.groq.com",
    "api.mistral.ai",
    "api.together.xyz",
    "api.minimax.chat",
    "api.z.ai",
    "ark.cn-beijing.volces.com",
    "api.cohere.com",
    "api.fireworks.ai",
    "api.perplexity.ai",
    "api.cerebras.ai",
    "api.siliconflow.cn",
)

# High-confidence ARTEX-linked LLM relay / campaign C2 domains (alert even from workstations)
MALICIOUS_LLM_RELAY_DOMAINS: tuple[str, ...] = (
    "xcai.com",
    "xcai.pro",
    "lanmao666.com",
    "lanmao666.xyz",
    "artex.lol",
    "artex.noog2infra.site",
    "artex.ok7777.eu.cc",
    "artex.tokena2b.top",
    "nginxmysql.com",
    "zhzy999.net",
    "vietnam852.com",
)

# Standard corporate workstation prefixes suppressed from standalone commercial LLM API alerts
WORKSTATION_HOST_PREFIXES: tuple[str, ...] = (
    "laptop-",
    "wkstn-",
    "dev-ai-gw-",
    "macbook-",
    "desktop-",
)

def _is_allowlisted_scanner_ip(
    source_host: str,
    authorized_scanner_ips: list[str] | set[str] | tuple[str, ...] | None,
) -> bool:
    """Return True if source_host matches an operator-supplied authorized scanner IP or CIDR."""
    if not authorized_scanner_ips or not source_host:
        return False
    try:
        src_ip = ipaddress.ip_address(source_host.strip())
    except ValueError:
        return source_host.strip().lower() in {s.strip().lower() for s in authorized_scanner_ips}
    for entry in authorized_scanner_ips:
        try:
            net = ipaddress.ip_network(entry.strip(), strict=False)
            if src_ip in net:
                return True
        except ValueError:
            continue
    return False

# Risk-Based Alerting (RBA) weights per detection reason (alert >= 70, hunt >= 45, info < 45)
REASON_RISK_WEIGHTS: dict[str, int] = {
    "malicious_llm_relay_c2": 95,
    "artex_console_or_host_forensics": 95,
    "post_exploit_ad_or_followon_c2": 95,
    "idp_spray_then_success": 95,
    "idp_mfa_fatigue_or_2fa_tampering": 90,
    "idp_sp_secret_guess_then_success": 90,
    "agentic_server_callback_on_probe": 90,
    "dll_sideload_relocated_binary_with_config": 90,
    "cloud_ec2_role_external_replay": 90,
    "cloud_multi_identity_from_single_ip": 90,
    "known_artex_artifact": 90,
    "web_ssrf_or_upload_webshell": 85,
    "cloud_ec2_userdata_or_ssm_burst": 85,
    "ad_ntlm_relay_or_ldap_kerb_enum": 85,
    "socks_chisel_pivot_tunnel_mesh": 85,
    "dns_oob_callback_after_probe": 85,
    "config_and_secret_file_harvest_burst": 85,
    "jwt_alg_none_spray": 85,
    "cloud_sp_fail_to_vault_pivot": 85,
    "web_parent_shell_spawn": 85,
    "idp_sp_multi_resource_fanout": 80,
    "idp_probe_registration_or_workflow_abuse": 80,
    "idp_federated_trust_probe": 80,
    "agentic_lateral_fanout_smb_winrm": 80,
    "cloud_stolen_key_multi_service_enum": 80,
    "llm_api_key_harvesting": 80,
    "unit42_agentic_canary_probe": 80,
    "edr_sensor_enumeration": 80,
    "cloud_iam_privilege_burst": 80,
    "cloud_secret_search_or_dryrun_burst": 80,
    "web_error_correction_pivot": 80,
    "on_box_compiler_in_staging_path": 75,
    "webhook_exfil_egress": 75,
    "agentic_default_port": 75,
    "agentic_user_agent_burst": 75,
    "edge_vpn_rapid_spray": 75,
    "edge_appliance_path_probe": 75,
    "endpoint_compressed_recon_burst": 75,
    "spec_driven_api_targeting": 75,
    "distributed_proxy_pool_probe": 75,
    "multi_account_credential_spray": 75,
    "llm_sawtooth_context_flow": 70,
    "web_error_handling_calibration": 70,
    "graphql_or_ai_mcp_discovery_probe": 70,
    "ja4_client_stack_whiplash": 70,
    "ja4_proxy_collapse_multi_ua": 70,
    "touch_and_bail_edr_evasion": 70,
    "multi_worker_redundant_recon": 65,
    "think_act_bimodal_cadence": 65,
    "ua_diversity_on_errors": 65,
    "llm_api_egress": 65,
    "llm_cli_context_idioms": 60,
    "write_then_readback_verification": 60,
    "ai_agent_spawns_offensive_tool": 55,
    "automated_error_retry_loop": 25,
    "machine_speed_burst": 20,
    "low_jitter_programmatic_cadence": 20,
}


def compute_risk_score(reasons: list[str]) -> tuple[int, str]:
    """Compute Risk-Based Alerting (RBA) score (0-100) and tier (`alert`, `hunt`, `info`)."""
    score = min(100, sum(REASON_RISK_WEIGHTS.get(r, 30) for r in reasons))
    if score >= 70:
        return score, "alert"
    if score >= 45:
        return score, "hunt"
    return score, "info"

SELF_HOSTED_LLM_PATH_RE = re.compile(
    r"(/v1/chat/completions|/v1/messages|/v1/responses|/api/chat|/api/generate)$",
    re.IGNORECASE,
)

WEBHOOK_EXFIL_DOMAINS: tuple[str, ...] = (
    "webhook.site",
    "oast.live",
    "oast.fun",
    "oast.me",
    "interact.sh",
    "dnslog.cn",
    "requestbin",
)

# Server-only C2/exfil bot APIs (e.g. Hermes Agent Telegram C2 — suppressed on user workstations)
SERVER_ONLY_BOT_C2_DOMAINS: tuple[str, ...] = (
    "api.telegram.org",
)

KNOWN_AGENTIC_PORTS: set[int] = {8787, 8788, 8790, 8890}

AGENTIC_USER_AGENTS: tuple[str, ...] = (
    "norma/",
    "artex-enrich/",
    "rex_enrich",
    "artex-readonly/",
    "artex-worker/",
    "artex-audit/",
    "artex-pentest/",
    "artex-verify/",
    "artex-spawn/",
    "artex-selfupdate",
    "artex-i",
    "artex/1.0",
    "artexverify/",
    "mozilla/5.0 (artex)",
    "mozilla/5.0 artex",
    "artex-authorized-pentest",
    "security-testing; authorized",
    "llmleak-redteam/",
    "authorized-security-research/",
    "authorized-exposure-audit/",
    "authorised-scan",
    "vulnerability-disclosure-policy-review",
    "recon-audit",
    "spa-api-recon",
    "reconprobe/",
    "azure-toolkit/1.0",
    "hexstrike-",
    "cyberstrikeai-",
    "strix/",
    "shannon/",
    "openbullet/",
    "qwen-code/",
    "kimi-cli/",
    "opencode/",
    "hermes-agent/",
    "fuzz faster u fool",
    "artexprobe",
    "artex-probe",
    "headlesschrome",
    "nuclei",
    "norma-agent",
    "artex/",
    "scopeweaver",
    "python-httpx",
    "go-http-client",
)

# High-confidence explicit framework UAs that warrant immediate flagging even on a single hit
EXPLICIT_FRAMEWORK_UAS: tuple[str, ...] = (
    "norma/",
    "artex-enrich/",
    "rex_enrich",
    "artex-readonly/",
    "artex-worker/",
    "artex-audit/",
    "artex-pentest/",
    "artex-verify/",
    "artex-spawn/",
    "artex-selfupdate",
    "artex/1.0",
    "artexverify/",
    "mozilla/5.0 (artex)",
    "artex-authorized-pentest",
    "llmleak-redteam/",
    "authorized-security-research/",
    "authorized-exposure-audit/",
    "authorised-scan",
    "vulnerability-disclosure-policy-review",
    "spa-api-recon",
    "reconprobe/",
    "hexstrike-",
    "cyberstrikeai-",
    "strix/",
    "shannon/",
    "openbullet/",
    "qwen-code/",
    "kimi-cli/",
    "opencode/",
    "hermes-agent/",
)

# Token-bounded Dragos/CloudTrail ARTEX UAs (avoids unanchored `smartex-agent` / `smartex-judge-*` FPs)
EXPLICIT_BOUNDED_ARTEX_UA_RE = re.compile(
    r"(?:^|[^a-z0-9_])artex-(?:agent(?=$|[^a-z0-9_])|judge-[a-z0-9_-]+)",
    re.IGNORECASE,
)

# Behavioral catch-all for LLM-invented "self-proclaimed authorized" scanner User-Agents
# (e.g. BushidoToken 2026-11-20 & Unit 42: authorized-exposure-audit/6, authorised-scan, security-testing; authorized)
SELF_PROCLAIMED_AUTH_UA_RE = re.compile(
    r"authori[sz]ed[-_ ;/]+(?:scan|audit|pentest|exposure|security|recon|research|testing)",
    re.IGNORECASE,
)

SPEC_HARVEST_PATH_RE = re.compile(
    r"(\.js\.map|/openapi\.json|/swagger\.json|/redoc\b|runtime-config\.json|app-config\.json)",
    re.IGNORECASE,
)

EDGE_PROBE_PATH_RE = re.compile(
    r"(/(\+cscoe\+|\+webvpn\+|vpn|nf/auth|logon/logonpoint|p/u|global-protect|ssl-vpn|my\.policy|tmui|mgmt/tm|nitro/v1))",
    re.IGNORECASE,
)

SENSITIVE_WEB_PIVOT_RE = re.compile(
    r"(/\.env|/admin|/config|/debug|/secrets|/export|/backup|/\.git|/shell\.php|/cmd\.jsp|/api/v\d+/(?:secrets|export|users|token))",
    re.IGNORECASE,
)

EDR_DISCOVERY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "edr_sensor_probe",
        re.compile(
            r"(csfalcon|crowdstrike|sentinelagent|cbdefense|defender|windefend|sysmon|edr)"
            r".*(query|status|sc\s+query|get-service|tasklist|ps\s|pgrep|systemctl)",
            re.IGNORECASE,
        ),
    ),
    (
        "edr_sensor_probe_rev",
        re.compile(
            r"(sc\s+query|get-service|tasklist|systemctl\s+status|pgrep)"
            r".*(csfalcon|crowdstrike|sentinel|carbonblack|windefend|sysmon|falcon-sensor)",
            re.IGNORECASE,
        ),
    ),
]

RECON_CMD_RE = re.compile(
    r"\b(whoami|id|uname|ipconfig|ifconfig|ip\s+(?:a|addr|route)|nltest|net\s+user|net\s+group|net\s+localgroup|"
    r"systeminfo|hostname|quser|qwinsta|arp\s+-a|route\s+print|ss\s+-|netstat|"
    r"aws\s+sts|aws\s+iam|aws\s+s3|az\s+account|az\s+ad|az\s+keyvault|gcloud\s+auth|kubectl\s+get|"
    r"gh\s+auth|sc\s+query|tasklist|get-service|get-aduser)\b|/etc/passwd",
    re.IGNORECASE,
)

# High-confidence web/appliance daemon parents (any shell spawn is suspicious)
WEB_PARENT_PROCESSES: tuple[str, ...] = (
    "w3wp.exe",
    "nginx",
    "httpd",
    "apache2",
    "php-fpm",
    "tomcat",
    "nitro",
    "restjavad",
    "sqlservr.exe",
)

# Noisy runtime parents (java/node spawn shells legitimately in CI/builds; require suspicious shell args)
RUNTIME_WEB_PARENTS: tuple[str, ...] = ("java", "java.exe", "node", "node.exe")
SUSPICIOUS_RUNTIME_SHELL_ARG_RE = re.compile(
    r"(whoami|\bid\b|nltest|sc\s+query|curl\s|wget\s|invoke-webrequest|-enc\s|base64|/dev/tcp|\bnc\s)",
    re.IGNORECASE,
)

SHELL_CHILD_BASES: frozenset[str] = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "pwsh",
        "bash",
        "sh",
    }
)
# Direct interpreter / downloader children spawned by web daemons (nginx/w3wp/httpd/php-fpm)
WEB_DAEMON_EXTRA_CHILDREN: frozenset[str] = frozenset(
    {
        "python",
        "python3",
        "perl",
        "php",
        "curl",
        "wget",
        "socat",
        "certutil.exe",
        "wmic.exe",
    }
)

CLOUD_IAM_HIGH_RISK_ACTIONS: set[str] = {
    "addserviceprincipalcredentials",
    "addapplicationpassword",
    "consenttoapplication",
    "addapproleassignment",
    "createaccesskey",
    "attachrolepolicy",
    "putrolepolicy",
    "updateassumerolepolicy",
    "passrole",
    "createkeypair",
    "allocateaddress",
    "runinstances",
    "grant_oauth_consent",
    "create_service_principal",
    "getsecretvalue",
    "keyvault_secret_get",
}

CLOUD_SECRET_SEARCH_RE = re.compile(r"(password|akia|secret|token|bearer|limit=1000)", re.IGNORECASE)

# Generalized synthetic negative-control canary stems on 4xx responses (defeats mutated LLM canaries beyond zzq)
MUTATED_CANARY_STEM_RE = re.compile(
    r"(?:non[-_]?existent|no[-_]?such[-_]?(?:user|acct|account|key|item|path|file|page)|"
    r"not[-_]?a[-_]?(?:user|valid|real)|does[-_]?not[-_]?exist|zzz[a-z0-9]{4,}|"
    r"fake[-_]?user[-_]?[0-9a-f]{2,}|invalid[-_]?user[-_]?test)",
    re.IGNORECASE,
)

# API/admin path guard for write-then-readback verification (avoids FPs on normal POST /cart -> GET /cart or /api/search)
API_VERIFY_PATH_RE = re.compile(
    r"(/api/|/v[0-9]+/|/documents|/config|/users|/roles|/settings|/policies|/secrets|/admin/)",
    re.IGNORECASE,
)
READONLY_POST_PATH_RE = re.compile(
    r"/(?:search|query|filter|lookup|graphql|autocomplete|suggest|health|metrics)(?:/|$)",
    re.IGNORECASE,
)
STATIC_ASSET_PATH_RE = re.compile(
    r"(?:/favicon\.ico|/robots\.txt|\.(?:png|jpe?g|gif|svg|ico|css|css\.map|js|woff2?|ttf|eot))$",
    re.IGNORECASE,
)
UUID_SEG_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
PROBE_SLUG_EXT_RE = re.compile(r"\.(?:php\d?|json|html?|jsp|aspx?|txt|xml|bak)$", re.IGNORECASE)
YEAR_TOKEN_RE = re.compile(r"(?:19|20)\d{2}")


def _is_high_entropy_probe_slug(path: str) -> bool:
    """Detect keyword-free random-slug control-404 / soft-404 calibration paths (e.g. /k9x2m8q4p1, /a7f3b9c2.php).

    Strictly excludes standard UUIDs, pure numeric IDs, static assets, and normal human/date slugs.
    """
    base = path.split("?", 1)[0].rstrip("/")
    if not base or STATIC_ASSET_PATH_RE.search(base):
        return False
    seg = base.rsplit("/", 1)[-1]
    if not seg or UUID_SEG_RE.match(seg) or seg.isdigit() or YEAR_TOKEN_RE.search(seg):
        return False
    stem = PROBE_SLUG_EXT_RE.sub("", seg)
    if len(stem) < 7 or "-" in stem or "_" in stem:
        return False
    if not stem.isalnum():
        return False
    digits = sum(c.isdigit() for c in stem)
    letters = sum(c.isalpha() for c in stem)
    return digits >= 2 and letters >= 2 and len(set(stem.lower())) >= 6

# Cloud IAM / Microsoft Graph / Key Vault & AWS Secrets REST path & CLI escalation patterns
CLOUD_IAM_PATH_OR_CMD_RE = re.compile(
    r"(?:/get-secret-value|\bget-secret-value\b|/create-access-key|\bcreate-access-key\b|"
    r"/attach-role-policy|\battach-role-policy\b|/put-role-policy|\bput-role-policy\b|"
    r"/update-assume-role-policy|/addpassword|/addkey|/admin/consent|/approleassignments|"
    r"/oauth2permissiongrants|listaccountsas|\bgetsecret\b|\blistsecrets\b|"
    r"scm\.azurewebsites\.net|/deployments/validate|cognitoidentitycredentials)",
    re.IGNORECASE,
)

# Unsigned JWT ("alg":"none") SSO spray (ThreatDefence — base64url header eyJhbGciOiJub25l)
JWT_ALG_NONE_RE = re.compile(r'(eyJhbGciOiJub25l|"alg"\s*:\s*"none")', re.IGNORECASE)

# IdP (Okta / Entra ID / Duo / PingFederate / Google Workspace) 2FA fatigue, factor tampering, & SP client-secret guessing patterns
IDP_MFA_FAIL_RE = re.compile(
    r"(deny_push|verification_error|auth_via_mfa.*(?:fail|error|deny)|mfa_denied|invalid_otp|"
    r"err_500121|err_50074|mfa_challenge_failed|duo_mfa_denied|denied_by_user|no_response|"
    r"pingid.*(?:fail|reject|deny)|mfa_rejected|second_factor_failure|challenge_failed)",
    re.IGNORECASE,
)
IDP_MFA_TAMPER_RE = re.compile(
    r"(user\.mfa\.factor\.(?:activate|deactivate|reset_all|update)|"
    r"register\s+security\s+info|user\s+registered\s+security\s+info|"
    r"user\s+deleted\s+security\s+info|mfa\.attempt_bypass|"
    r"duo_fraud_reported|fraud_reported|user_marked_fraud|"
    r"duo_admin:(?:phone_create|bypass_create|token_create|2fa_device_enroll)|"
    r"pingid_device_paired|mfa_device_enrolled|"
    r"gws_(?:login|admin):(?:2sv_disable|2sv_enroll|recovery_phone_edit|recovery_email_edit|add_recovery_phone))",
    re.IGNORECASE,
)
IDP_SP_SECRET_FAIL_RE = re.compile(
    r"(err_7000215|err_7000222|invalid_client_secret|invalid_client)",
    re.IGNORECASE,
)
# Okta Threat Intel (Oct/Nov 2026): high-velocity user.risk.detect, Workflows invoke-URL/clientToken abuse, wildcard OAuth callbacks
IDP_WORKFLOW_OR_OAUTH_ABUSE_RE = re.compile(
    r"(workflows\.user\.invoke|/api/flo/|clienttoken=|redirect_uri=[^&\s]*(?:\*|%2a|interact\.sh|oast\.|webhook\.site))",
    re.IGNORECASE,
)
IDP_RISK_DETECT_RE = re.compile(r"user\.risk\.detect", re.IGNORECASE)
OAUTH_CLIENT_ID_RE = re.compile(r"(?:client_id|clientid|audience|sp_entity_id|relay_party)[=:]\s*([a-z0-9._:/-]{3,80})", re.IGNORECASE)
OAUTH_PATH_OR_ERROR_RE = re.compile(
    r"(/oauth2?/authorize|/oidc/|/saml|/sso/|invalid_client|unauthorized_client|invalid_scope|"
    r"invalid_redirect_uri|illegal_redirect_uri|access_denied|acr_values|prompt=none)",
    re.IGNORECASE,
)
IDP_FRESH_SIGNUP_RE = re.compile(r"(user\.lifecycle\.create|user\.account\.register|auth0_signup|/oauth/register)", re.IGNORECASE)

# Amazon MadPot (Nov 2026): Self-funding LLM API-key harvesting across env/files/shell history
LLM_API_KEY_HARVEST_RE = re.compile(
    r"(\b(?:OPENAI|ANTHROPIC|DEEPSEEK|GEMINI|XAI|OPENROUTER|MOONSHOT|DASHSCOPE)_API_KEY\b|"
    r"\bsk-(?:ant|proj|or-v1)-[a-z0-9_-]*|(?:/\.claude|/\.anthropic|/\.codex|~/?\.(?:claude|anthropic|codex))\b)",
    re.IGNORECASE,
)

# Fork-agnostic blind-spot pivots: stolen valid cloud keys (0 AccessDenied), GraphQL/MCP discovery,
# rapid config/credential file harvesting, and custom-domain OOB DNS callbacks after web probing.
CLOUD_SERVICE_TOKEN_RE = re.compile(
    r"\b(sts|iam|secretsmanager|s3|ec2|kms|rds|eks|lambda|bedrock|cloudtrail|cognito|ssm|keyvault|graph|arm)\b",
    re.IGNORECASE,
)
CLOUD_HIGH_VALUE_SERVICES: frozenset[str] = frozenset(
    {"iam", "secretsmanager", "kms", "bedrock", "keyvault", "cognito", "ssm"}
)
CLOUD_IAC_AUTOMATION_UA_RE = re.compile(
    r"(terraform|ansible|cloudcustodian|aws-config|datadog|wiz\.io|orca-security|prisma-cloud)",
    re.IGNORECASE,
)
# Identity-backed IaC / CSPM automation actor check (prevents attacker User-Agent: Terraform/1.9 spoofing
# while refusing broad terms like "service-role" or bare "wiz" that match compromised Lambda roles or "wizard").
CLOUD_IAC_ACTOR_ROLE_RE = re.compile(
    r"(?:^|[:/_-])(?:terraform(?:[-_][a-z0-9]+)?|ansible(?:[-_][a-z0-9]+)?|cloudcustodian|aws-config|"
    r"datadog[-_](?:cspm|integration|scanner)|wiz[-_](?:scanner|sensor|cspm|role)|"
    r"orca[-_](?:scanner|security)|prisma[-_]cloud)(?:$|[:/_-])",
    re.IGNORECASE,
)
# Elastic Security Labs ("56 AWS API calls in 141ms" / CyberStrikeAI CloudTrail):
# EC2 userData harvesting, SSM parameter decryption + SendCommand, and stolen EC2 instance-role replay
EC2_INSTANCE_ROLE_ACTOR_RE = re.compile(r"assumed-role/[^/\s]+/i-[0-9a-f]{8,17}\b", re.IGNORECASE)
EC2_USERDATA_ACTION_RE = re.compile(r"(describeinstanceattribute.*userdata|userdata.*describeinstanceattribute)", re.IGNORECASE)
SSM_SENSITIVE_ACTION_RE = re.compile(r"(sendcommand|getparametersbypath|getparameter.*withdecryption)", re.IGNORECASE)
GRAPHQL_INTROSPECTION_RE = re.compile(r"(__schema|__type\b|introspectionquery)", re.IGNORECASE)
AI_MCP_DISCOVERY_PATH_RE = re.compile(
    r"(^|/)(?:mcp(?:/|$)|mcp-rest/|sse(?:/|$)|\.well-known/agent\.json|v1/models|api/tags|api/ps|gradio_api|v1/assistants)",
    re.IGNORECASE,
)
# Behavioral process-tree signal (ThreatDefence v2.7.0): AI agent / coding harness shell spawning
# explicit offensive pentest/exploitation tools (benign dev tools like git/grep/pytest/npm/curl are never flagged)
AI_AGENT_PARENT_RE = re.compile(
    r"(?:^|[/\\])(?:claude(?:\.exe)?|codex(?:\.exe)?|opencode(?:\.exe)?|qwen-code(?:\.exe)?|"
    r"kimi-cli(?:\.exe)?|hermes-agent(?:\.exe)?)$|shell-snapshots|claude_code_shell_launcher_script",
    re.IGNORECASE,
)
AI_AGENT_CMD_WRAPPER_RE = re.compile(
    r"(?:shell-snapshots|claude_code_shell_launcher_script)",
    re.IGNORECASE,
)
AI_AGENT_SHELL_PROC_RE = re.compile(
    r"(?:^|[/\\])(?:sh|bash|zsh|dash|fish|cmd\.exe|powershell\.exe|pwsh(?:\.exe)?|python(?:\d+(?:\.\d+)?)?(?:\.exe)?)$",
    re.IGNORECASE,
)
OFFENSIVE_TOOL_PROC_RE = re.compile(
    r"(?:^|[/\\])(?:nmap|masscan|nuclei|sqlmap|ffuf|gobuster|chisel|ntlmrelayx|"
    r"netexec|nxc|evil-winrm|certipy|hydra|bloodhound|sharphound|rubeus|secretsdump)(?:\.exe)?$",
    re.IGNORECASE,
)
OFFENSIVE_TOOL_CMD_HEAD_RE = re.compile(
    r"(?:^|(?:&&|\|\||[;|]|-c\s+['\"]?|\bsudo\s+|\beval\s+))\s*(?:[^\s;|&'\"]*[/\\])?"
    r"(?:nmap|masscan|nuclei|sqlmap|ffuf|gobuster|chisel|ntlmrelayx|"
    r"netexec|nxc|evil-winrm|certipy|hydra|bloodhound|sharphound|rubeus|secretsdump)(?:\.exe)?(?=$|[\s\"';|&])",
    re.IGNORECASE,
)
SENSITIVE_CONFIG_FILE_RE = re.compile(
    r"((?:^|[\s/\\'\";|])\.env(?:\.[a-z0-9_-]+)?(?=$|[\s'\"|;])|\bweb\.config\b|\.git/config\b|"
    r"\.aws/credentials\b|\.aws/config\b|\.kube/config\b|\.ssh/id_[a-z0-9_]+\b|"
    r"\.(?:bash|zsh)_history\b|\.netrc\b|\.pgpass\b|\bappsettings(?:\.[a-z]+)?\.json\b|"
    r"\bapplication\.(?:yml|yaml|properties)\b|\.npmrc\b|\.pypirc\b|credentials\.json\b|"
    r"secrets\.ya?ml\b|\.claude\b)",
    re.IGNORECASE,
)
BENIGN_OOB_DNS_SUFFIXES: tuple[str, ...] = (
    ".amazonaws.com",
    ".cloudfront.net",
    ".akamaiedge.net",
    ".akadns.net",
    ".azureedge.net",
    ".googleapis.com",
    ".gstatic.com",
    ".cloudflare.net",
    ".fastly.net",
    ".in-addr.arpa",
    ".ip6.arpa",
    ".corp.local",
    ".internal",
    ".local",
)


def _is_oob_high_entropy_dns_fqdn(fqdn: str) -> bool:
    """Return True if an outbound DNS query uses a high-entropy hex/random subdomain typical of OOB callbacks."""
    host = fqdn.strip().rstrip(".").lower()
    if not host or "." not in host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    if any(host.endswith(sfx) for sfx in BENIGN_OOB_DNS_SUFFIXES):
        return False
    left = host.split(".", 1)[0]
    if len(left) < 10 or len(left) > 63:
        return False
    has_digit = any(ch.isdigit() for ch in left)
    has_alpha = any(ch.isalpha() for ch in left)
    if not (has_digit and has_alpha):
        return False
    # Pure hex token >= 10 chars (e.g. a9f3c2d81e04.oob-collector.example) or long mixed-alnum token >= 16 chars
    if re.fullmatch(r"[a-f0-9]{10,}", left):
        return True
    if len(left) >= 16 and re.fullmatch(r"[a-z0-9]{16,}", left) and sum(ch.isdigit() for ch in left) >= 4:
        return True
    return False
CLOUD_VAULT_OR_SAS_RE = re.compile(
    r"(\.vault\.azure\.net|/secrets(?:/|\?|$)|restype=sas|listaccountsas|secretsmanager\.|get-secret-value)",
    re.IGNORECASE,
)
CLOUD_AUTH_TOKEN_RE = re.compile(
    r"(/oauth2?/v?2?\.?0?/token|login\.microsoftonline\.com|authentication_failure|authentication_success)",
    re.IGNORECASE,
)

# Web SSRF (cloud metadata) & upload-directory executable script creation/execution
WEB_SSRF_METADATA_RE = re.compile(
    r"(169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal|100\.100\.100\.200/latest)",
    re.IGNORECASE,
)
UPLOAD_WEBSHELL_PATH_RE = re.compile(
    r"/(?:uploads?|media|attachments|files|static/uploads|sites/default/files|wp-content/uploads)/"
    r"(?:[^?\s]+/)*(?:\.htaccess|[^?\s]+\.(?:php\d?|phtml|phar|pht|shtml|jsp|jspx|asp|aspx|ashx|sh|py|pl|cgi))\b",
    re.IGNORECASE,
)

# Generalized DLL sideloading outside standard install paths + adjacent config.bin (relocated browser/app hosts)
SIDELOAD_HOST_BIN_RE = re.compile(
    r"\b(?:msedge|edge|chrome|obs64|vlc|teams|onedrive)\.exe\b",
    re.IGNORECASE,
)
STANDARD_WIN_INSTALL_PATH_RE = re.compile(
    r"(?:\\program files(?: \(x86\))?\\|\\windows\\system32\\|\\windows\\syswow64\\|\\appdata\\local\\microsoft\\)",
    re.IGNORECASE,
)
SIDELOAD_CONFIG_OR_DLL_RE = re.compile(
    r"(\bconfig\.bin\b|graphics-hook_config\.bin|graphics-hook-filter64\.dll|\bmsedge\.dll\b)",
    re.IGNORECASE,
)

# Internal AD NTLM capture/relay, EPA probing, Kerberos/LDAP enum, SAMR/SRVSVC RPC, & offline Impacket wheel staging
AD_NTLM_RELAY_OR_ENUM_RE = re.compile(
    r"(\bntlmrelayx\b|\bsmbserver\.py\b|\bsecretsdump\b|\bpetitpotam\b|\bcoercer\b|\bcertipy\b|"
    r"\bkerbrute\b|\bbloodhound\b|\bldapdomaindump\b|ntlm[-_ ]?(?:relay|epa|capture|coerce)|"
    r"ldapsearch\s+[^|;\n]*-x\b.*(?:-b\s|namingcontexts|rootdse|samaccountname)|"
    r"(?:samr|srvsvc|lsarpc)[-_ ]?(?:probe|enum|dump)|"
    r"pip\d?\s+install\s+[^|;\n]*--no-index[^|;\n]*(?:impacket|cryptography|cffi))",
    re.IGNORECASE,
)

# Multi-tunnel Chisel / Ligolo / FRP / Proxychains SOCKS pivot meshes
SOCKS_CHISEL_PIVOT_RE = re.compile(
    r"(\bchisel(?:\.exe)?\s+(?:client|server)\b|\bligolo[-_ ]?(?:agent|proxy)\b|\bfrpc\b|"
    r"\bproxychains4?\s+-f\s+\S+|\bsocks5?[-_ ]?proxy\b|r:socks\b)",
    re.IGNORECASE,
)

# On-box C/C++ compilation directly inside temp/public/staging paths on non-workstation servers
ON_BOX_STAGING_COMPILER_RE = re.compile(
    r"\b(?:gcc|g\+\+|cc|clang|x86_64-w64-mingw32-gcc)\b[^|;\n]*"
    r"(?:/tmp/|/var/tmp/|/dev/shm/|\\programdata\\|\\users\\public\\)[^|;\n]*\.c(?:pp)?\b",
    re.IGNORECASE,
)

# Post-exploitation AD credential dumping (Kerberoasting/DCSync/Mimikatz), SQL xp_cmdshell/BYOVD, & ARTEX follow-on C2s
POST_EXPLOIT_AD_OR_C2_RE = re.compile(
    r"(\bmimikatz\b|lsadump::|sekurlsa::|\brubeus\b|kerberoast|getuserspns|\bdcsync\b|"
    r"ds-replication-get-changes|\bxp_cmdshell\b|winring0x64\.sys|\bvshell\b|adaptixc2|"
    r"\bwisp[-_]?c2\b|sqlserver-sqlite\.com)",
    re.IGNORECASE,
)

# Zero-IOC behavioral patterns (catch IOC-stripped LLM loops)
SHELL_WRAPPER_PREFIX_RE = re.compile(
    r"^\s*(?:/bin/)?(?:ba|da|z)?sh\s+-[a-z]*c\s+|^\s*cmd(?:\.exe)?\s+/[ck]\s+|"
    r"^\s*(?:powershell|pwsh)(?:\.exe)?\s+(?:-[a-z]+\s+)*-c(?:ommand)?\s+",
    re.IGNORECASE,
)
SHELL_TRAIL_REDIR_RE = re.compile(r"(?:\s+2>&1|\s+2>/dev/null|\s*\|\s*(?:head|tail)\s+-n\s*\d+)+\s*$", re.IGNORECASE)

READONLY_RECON_NORMALIZE_RE = re.compile(
    r"^\s*(whoami(?:\s+/all)?|id(?:\s+-a)?|hostname|uname(?:\s+-[a-z]+)?|ipconfig(?:\s+/all)?|"
    r"ifconfig|ip\s+(?:a|addr|route)|ss\s+-[a-z]+|cat\s+/etc/passwd|env|"
    r"nltest\s+/domain_trusts|net\s+localgroup\s+administrators|systeminfo|"
    r"aws\s+sts\s+get-caller-identity|az\s+account\s+show|gcloud\s+auth\s+list|"
    r"kubectl\s+get\s+(?:pods|secrets|nodes))\s*$",
    re.IGNORECASE,
)


def _normalize_shell_cmd(cmd_raw: str) -> str:
    """Strip common shell wrappers (bash -c, cmd /c, quotes, 2>&1, | head) before recon normalization."""
    s = cmd_raw.strip()
    s = SHELL_WRAPPER_PREFIX_RE.sub("", s).strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in {"'", '"'}:
        s = s[1:-1].strip()
    s = SHELL_TRAIL_REDIR_RE.sub("", s).strip()
    return re.sub(r"\s+", " ", s).lower()


def _normalize_api_path(path: str) -> str:
    """Strip query parameters and trailing slashes for REST write->readback matching."""
    base = path.split("?", 1)[0].rstrip("/")
    return base or "/"


LLM_TOOLBOX_INVENTORY_RE = re.compile(
    r"(which\s+(?:\S+\s+){2,}|command\s+-v\s+\S+.*command\s+-v|Get-Command\s+)",
    re.IGNORECASE,
)
LLM_TRUNCATION_IDIOM_RE = re.compile(
    r"(\|\s*(?:head|tail)\s+-n\s*\d+|\|\s*Select-Object\s+-First\s+\d+|--max-time\s+\d+|curl\s+-[a-zA-Z]*sSk)",
    re.IGNORECASE,
)
LLM_STRUCTURED_FRAMING_RE = re.compile(
    r"(echo\s+['\"]===\s|echo\s+['\"]---\s|\|\s*ConvertTo-Json|\s2>&1)",
    re.IGNORECASE,
)
GENERIC_PROC_CHECK_RE = re.compile(
    r"\b(tasklist|ps\s+aux|ps\s+-ef|get-process|get-service|sc\s+query|systemctl\s+list-units)\b",
    re.IGNORECASE,
)


def _detect_sawtooth_context_flow(events: list[dict[str, Any]]) -> list[str]:
    """Detect monotonically growing bytes_out (accumulating LLM context window) or compacted sawtooth cycles.

    Catches self-hosted/VPS-proxied LLM API calls on port 443 with ZERO domain or UA indicators,
    including agents that periodically compact/reset context mid-session.
    """
    by_dest: dict[str, list[tuple[float, int, int]]] = {}
    for ev in events:
        b_out = ev.get("bytes_out")
        b_in = ev.get("bytes_in")
        dest = ev.get("dest_host") or ""
        ts = ev.get("ts_epoch")
        if dest and b_out is not None and b_in is not None and ts is not None:
            by_dest.setdefault(dest, []).append((float(ts), int(b_out), int(b_in)))

    hits: list[str] = []
    for dest, pts in by_dest.items():
        if len(pts) < 5:
            continue
        pts.sort(key=lambda x: x[0])
        best_run = 1
        cur_run = 1
        run_start_bytes = pts[0][1]
        cur_peak = pts[0][1]
        best_ratio = 1.0
        best_peak = 0
        compacted_climbs = 0
        compaction_drops = 0

        for i in range(1, len(pts)):
            dt = pts[i][0] - pts[i - 1][0]
            prev_out, cur_out = pts[i - 1][1], pts[i][1]
            cur_in = pts[i][2]
            # LLM turn: growing context (+>=1500B), non-trivial streamed completion (300B-50KB), turn gap >= 3s
            if cur_out >= prev_out + 1500 and 300 <= cur_in <= 50000 and dt >= 3.0:
                cur_run += 1
                cur_peak = max(cur_peak, cur_out)
                ratio = cur_out / max(run_start_bytes, 1)
                if cur_run > best_run or (cur_run == best_run and cur_out > best_peak):
                    best_run = cur_run
                    best_peak = cur_out
                    best_ratio = ratio
            else:
                # Record completed climb before reset (for context-compaction sawtooth detection)
                if cur_run >= 3 and cur_peak >= 10000 and (cur_peak / max(run_start_bytes, 1)) >= 2.0:
                    compacted_climbs += 1
                    if cur_out <= prev_out * 0.6:
                        compaction_drops += 1
                cur_run = 1
                run_start_bytes = cur_out
                cur_peak = cur_out

        # Finalize trailing climb
        if cur_run >= 3 and cur_peak >= 10000 and (cur_peak / max(run_start_bytes, 1)) >= 2.0:
            compacted_climbs += 1

        if best_run >= 4 and best_peak >= 12000 and best_ratio >= 2.5:
            hits.append(f"sawtooth_flow:{dest}(turns={best_run},peak={best_peak}B,ratio={best_ratio:.1f}x)")
        elif compacted_climbs >= 2 and compaction_drops >= 1:
            hits.append(f"sawtooth_compacted:{dest}(climbs={compacted_climbs},drops={compaction_drops},peak={best_peak}B)")
    return hits


def load_events(file_path: str | Path, fmt: str = "auto") -> list[dict[str, Any]]:
    """Load and normalize events from JSONL or supported appliance/web log files."""
    return parse_auto(file_path, fmt=fmt)


def _count_think_act_cycles(
    timestamps: list[float],
    *,
    min_pause_sec: float = 18.0,
    max_pause_sec: float = 60.0,
    burst_window_sec: float = 12.0,
    min_burst_events: int = 3,
) -> int:
    """Count Unit 42 / Theori Think-Act cycles (burst -> 18-60s LLM inference pause -> burst)."""
    if len(timestamps) < min_burst_events * 2:
        return 0
    ordered = sorted(timestamps)
    cycles = 0
    for i in range(1, len(ordered)):
        gap = ordered[i] - ordered[i - 1]
        if min_pause_sec <= gap <= max_pause_sec:
            # Verify there was a burst before the pause AND a burst starting at i
            pre_count = sum(1 for t in ordered[:i] if ordered[i - 1] - t <= burst_window_sec)
            post_count = sum(1 for t in ordered[i:] if t - ordered[i] <= burst_window_sec)
            if pre_count >= min_burst_events and post_count >= min_burst_events:
                cycles += 1
    return cycles


def _ua_client_family(ua: str) -> str:
    """Collapse minor browser version drift while distinguishing true HTTP client stacks."""
    low = ua.strip().lower()
    if not low:
        return ""
    if "edg/" in low or "edge/" in low:
        return "browser_edge"
    if "firefox/" in low:
        return "browser_firefox"
    if "chrome/" in low or "crios/" in low:
        return "browser_chrome"
    if "safari/" in low and "mozilla/" in low:
        return "browser_safari"
    if "curl/" in low or low.startswith("curl"):
        return "cli_curl"
    if any(tok in low for tok in ("python", "urllib", "requests/", "httpx", "aiohttp")):
        return "cli_python"
    if "wget/" in low or low.startswith("wget"):
        return "cli_wget"
    if "go-http-client" in low or "golang" in low:
        return "cli_go"
    if "powershell" in low or "pwsh" in low:
        return "cli_powershell"
    if any(tok in low for tok in ("java/", "okhttp", "apache-httpclient")):
        return "cli_java"
    if any(tok in low for tok in ("ruby", "faraday")):
        return "cli_ruby"
    if any(tok in low for tok in ("perl", "libwww-perl")):
        return "cli_perl"
    if any(tok in low for tok in ("node", "undici", "axios")):
        return "cli_node"
    head = re.split(r"[\s/]+", low, maxsplit=1)[0]
    return f"other_{head[:24]}" if head else "other_unknown"


def _inspect_window_signals(
    events: list[dict[str, Any]],
    *,
    source_host: str = "",
    mean_interval: float | None,
    stddev_interval: float | None,
    span_seconds: float,
    error_count: int,
) -> tuple[list[str], list[str], SurfaceType, str | None]:
    reasons: set[str] = set()
    indicators: set[str] = set()

    iam_hits = 0
    edr_hits = 0
    edge_auth_failures = 0
    edge_path_probes: set[str] = set()
    recon_cmds: set[str] = set()
    readonly_recon_counts: Counter[str] = Counter()
    llm_idiom_types: set[str] = set()
    llm_idiom_has_recon_or_net = False
    ja4_fingerprints: set[str] = set()
    ja4h_fingerprints: set[str] = set()
    distinct_uas: set[str] = set()
    distinct_ua_families: set[str] = set()
    proc_check_hosts: set[str] = set()
    error_uas: set[str] = set()
    error_ua_families: set[str] = set()
    cloud_dryrun_hits = 0
    cloud_secret_search_hits = 0
    cloud_denied_apis: set[str] = set()
    cloud_services_seen: set[str] = set()
    cloud_is_iac_automation = False
    cloud_userdata_hits = 0
    cloud_ssm_sendcmd_hits = 0
    cloud_ssm_decrypt_hits = 0
    cloud_ec2_role_external_sensitive = False
    cloud_api_event_count = 0
    saw_cloud_secret_read_200 = False
    saw_graphql_introspection = False
    post_introspection_api_hits = 0
    ai_mcp_discovery_paths: set[str] = set()
    sensitive_files_touched: set[str] = set()
    saw_relocated_sideload_host = False
    saw_sideload_config_bin = False
    ad_ldap_kerb_failures = 0
    ad_ldap_kerb_targets: set[str] = set()
    surfaces: Counter[str] = Counter()
    appliances: Counter[str] = Counter()

    saw_4xx_5xx = False
    saw_non_asset_4xx = False
    non_asset_error_count = 0
    non_asset_error_codes: set[int] = set()
    random_slug_probe_paths: set[str] = set()
    saw_sensitive_2xx_after_error = False
    saw_spec_harvest = False
    api_calls_after_spec = 0
    last_write_base: str | None = None
    last_write_ts: float | None = None
    write_readback_count = 0
    mutated_canary_4xx_hits = 0
    saw_cloud_auth_fail = False
    saw_cloud_auth_success_after_fail = False
    saw_vault_or_sas_after_auth = False
    idp_mfa_failures = 0
    saw_idp_mfa_tamper = False
    okta_legacy_authn_fails = 0
    idp_risk_detect_hits = 0
    saw_idp_workflow_or_oauth_abuse = False
    llm_key_harvest_hits = 0
    idp_sp_secret_fails = 0
    saw_idp_sp_success_after_secret_fail = False
    idp_sp_resources: set[str] = set()
    oauth_failing_clients: set[str] = set()
    saw_fresh_signup_in_session = False
    post_signup_rps: set[str] = set()

    is_workstation = source_host.lower().startswith(WORKSTATION_HOST_PREFIXES)

    timestamps: list[float] = []

    for ev in events:
        if ev.get("ts_epoch") is not None:
            timestamps.append(float(ev["ts_epoch"]))
        if ev.get("surface") and ev["surface"] != "unknown":
            surfaces[ev["surface"]] += 1
        if ev.get("appliance"):
            appliances[ev["appliance"]] += 1

        searchable = " ".join(
            [
                ev.get("actor", ""),
                ev.get("process", ""),
                ev.get("command_line", ""),
                ev.get("dest_host", ""),
                ev.get("http_path", ""),
                ev.get("user_agent", ""),
                ev.get("action", ""),
            ]
        )
        for label, pattern in KNOWN_ARTIFACT_PATTERNS:
            m = pattern.search(searchable)
            if m:
                if label == "unit42_canary_probe":
                    reasons.add("unit42_agentic_canary_probe")
                elif label in {"artex_cmd_output_spill", "artex_host_forensics", "artex_console_route"}:
                    reasons.add("artex_console_or_host_forensics")
                else:
                    reasons.add("known_artex_artifact")
                indicators.add(f"{label}:{m.group(0)}")

        # Spec-driven targeting: .js.map / openapi.json / runtime-config -> rapid API calls
        ev_path = ev.get("http_path", "")
        ev_method = ev.get("http_method", "").upper()
        if ev_path and SPEC_HARVEST_PATH_RE.search(ev_path):
            saw_spec_harvest = True
            indicators.add(f"spec_harvest:{ev_path[:80]}")
        elif saw_spec_harvest and ev_path and (
            "/api/" in ev_path.lower() or ev_method in {"POST", "PUT", "PATCH"}
        ):
            api_calls_after_spec += 1

        # Goal verification: PUT/POST/PATCH (excluding read-only /search|/query) followed <=3s by GET read-back
        ev_ts = ev.get("ts_epoch")
        norm_path = _normalize_api_path(ev_path) if ev_path else ""
        if (
            ev_method in {"PUT", "POST", "PATCH"}
            and norm_path
            and API_VERIFY_PATH_RE.search(norm_path)
            and not READONLY_POST_PATH_RE.search(norm_path)
        ):
            last_write_base = norm_path
            last_write_ts = float(ev_ts) if ev_ts is not None else None
        elif (
            ev_method == "GET"
            and last_write_base
            and norm_path
            and (norm_path == last_write_base or norm_path.startswith(last_write_base + "/"))
            and ev_ts is not None
            and last_write_ts is not None
            and 0.0 <= (float(ev_ts) - last_write_ts) <= 3.0
        ):
            write_readback_count += 1
            indicators.add(f"write_readback:{ev_path[:80]}")

        # Generalized mutated negative-control canary probes on 4xx responses
        ev_status_pre = ev.get("status_code")
        if ev_status_pre in {400, 401, 403, 404, 422}:
            canary_target = f"{ev_path} {ev.get('actor', '')}"
            m_can = MUTATED_CANARY_STEM_RE.search(canary_target)
            if m_can:
                mutated_canary_4xx_hits += 1
                indicators.add(f"mutated_canary_4xx:{m_can.group(0)}")

        # Web SSRF (cloud metadata), JWT alg:none SSO spray, & upload-directory executable scripts
        if WEB_SSRF_METADATA_RE.search(f"{ev_path} {ev.get('command_line', '')}"):
            reasons.add("web_ssrf_or_upload_webshell")
            indicators.add(f"web_ssrf_metadata:{ev_path[:80]}")
        if ev_path and UPLOAD_WEBSHELL_PATH_RE.search(ev_path):
            reasons.add("web_ssrf_or_upload_webshell")
            indicators.add(f"upload_webshell:{ev_path[:80]}")
        if JWT_ALG_NONE_RE.search(searchable):
            reasons.add("jwt_alg_none_spray")
            indicators.add("jwt_alg_none_header")

        # Generalized DLL sideloading outside standard install paths + adjacent config.bin
        proc_and_cmd = f"{ev.get('process', '')} {ev.get('command_line', '')}"
        if SIDELOAD_HOST_BIN_RE.search(proc_and_cmd) and not STANDARD_WIN_INSTALL_PATH_RE.search(proc_and_cmd):
            if any(tok in proc_and_cmd.lower() for tok in ("\\programdata\\", "\\users\\public\\", "\\temp\\", "/tmp/", "i4")):
                saw_relocated_sideload_host = True
        if SIDELOAD_CONFIG_OR_DLL_RE.search(proc_and_cmd) and not STANDARD_WIN_INSTALL_PATH_RE.search(proc_and_cmd):
            saw_sideload_config_bin = True

        # Internal AD NTLM relay/EPA/RPC/LDAP/Kerberos enumeration, SOCKS/Chisel pivots, & on-box /tmp C compilation
        m_ad = AD_NTLM_RELAY_OR_ENUM_RE.search(searchable)
        if m_ad:
            reasons.add("ad_ntlm_relay_or_ldap_kerb_enum")
            indicators.add(f"ad_ntlm_or_enum:{m_ad.group(0)[:60]}")
        if ev.get("dest_port") in {389, 636, 88}:
            if ev.get("dest_host"):
                ad_ldap_kerb_targets.add(ev["dest_host"])
            if ev.get("status_code") is not None and ev["status_code"] >= 400:
                ad_ldap_kerb_failures += 1
        m_piv = SOCKS_CHISEL_PIVOT_RE.search(searchable)
        if m_piv:
            reasons.add("socks_chisel_pivot_tunnel_mesh")
            indicators.add(f"socks_pivot:{m_piv.group(0)[:60]}")
        if not is_workstation and ON_BOX_STAGING_COMPILER_RE.search(ev.get("command_line", "")):
            reasons.add("on_box_compiler_in_staging_path")
            indicators.add(f"staging_compiler:{ev.get('command_line', '')[:70]}")

        # Post-exploitation AD credential dumping (Kerberoasting/DCSync/Mimikatz) & ARTEX follow-on C2s
        m_c2 = POST_EXPLOIT_AD_OR_C2_RE.search(f"{ev.get('event_type', '')} {searchable}")
        if m_c2:
            reasons.add("post_exploit_ad_or_followon_c2")
            indicators.add(f"post_exploit_or_c2:{m_c2.group(0)}")

        if ev.get("dest_port") in KNOWN_AGENTIC_PORTS:
            reasons.add("agentic_default_port")
            indicators.add(f"dest_port:{ev['dest_port']}")

        dest_lower = ev.get("dest_host", "").lower()
        cmd_lower = ev.get("command_line", "").lower()
        path_lower = ev_path.lower()
        ua_raw = ev.get("user_agent", "")
        ua_lower = ua_raw.lower()
        ua_family = _ua_client_family(ua_raw) if ua_raw else ""
        if ua_raw:
            distinct_uas.add(ua_raw)
        if ua_family:
            distinct_ua_families.add(ua_family)

        for domain in MALICIOUS_LLM_RELAY_DOMAINS:
            if domain in dest_lower or domain in cmd_lower or domain in path_lower:
                reasons.add("malicious_llm_relay_c2")
                reasons.add("llm_api_egress")
                indicators.add(f"malicious_llm_relay:{domain}")

        if not is_workstation:
            for domain in KNOWN_LLM_API_DOMAINS:
                if domain in dest_lower or domain in cmd_lower or domain in path_lower:
                    reasons.add("llm_api_egress")
                    indicators.add(f"llm_domain:{domain}")

            # Self-hosted / proxied LLM API endpoint on non-workstation hosts (strip query string before matching)
            clean_llm_path = ev_path.split("?", 1)[0]
            if ev_method == "POST" and SELF_HOSTED_LLM_PATH_RE.search(clean_llm_path):
                reasons.add("llm_api_egress")
                indicators.add(f"self_hosted_llm_path:{ev_path[:80]}")

        for domain in WEBHOOK_EXFIL_DOMAINS:
            if domain in dest_lower or domain in cmd_lower or domain in path_lower:
                reasons.add("webhook_exfil_egress")
                indicators.add(f"webhook_domain:{domain}")

        if not is_workstation:
            for domain in SERVER_ONLY_BOT_C2_DOMAINS:
                if domain in dest_lower or domain in cmd_lower or domain in path_lower:
                    reasons.add("webhook_exfil_egress")
                    indicators.add(f"server_bot_c2:{domain}")

        if (
            any(sig in ua_lower for sig in EXPLICIT_FRAMEWORK_UAS)
            or (ua_raw and EXPLICIT_BOUNDED_ARTEX_UA_RE.search(ua_raw))
            or (ua_raw and SELF_PROCLAIMED_AUTH_UA_RE.search(ua_raw))
        ):
            reasons.add("agentic_user_agent_burst")
            indicators.add(f"explicit_framework_ua:{ua_raw[:60]}")
        else:
            for ua_sig in AGENTIC_USER_AGENTS:
                if ua_sig in ua_lower:
                    indicators.add(f"agentic_ua:{ua_raw[:60]}")
                    if len(events) >= 4:
                        reasons.add("agentic_user_agent_burst")
                    break

        for label, pattern in EDR_DISCOVERY_PATTERNS:
            if pattern.search(ev.get("command_line", "")):
                edr_hits += 1
                indicators.add(f"{label}:{ev['command_line'][:80]}")

        # Edge appliance VPN/auth failures & management URI probing
        if ev.get("surface") == "edge_appliance" or EDGE_PROBE_PATH_RE.search(ev_path):
            if ev.get("status_code") is not None and ev["status_code"] >= 400:
                edge_auth_failures += 1
            if ev_path and EDGE_PROBE_PATH_RE.search(ev_path):
                edge_path_probes.add(ev_path)

        # Web error-correction loop, error-handling calibration (multi-code forcing / random-slug 404), & UA diversity
        status = ev.get("status_code")
        if status is not None and status >= 400:
            saw_4xx_5xx = True
            if not (ev_path and STATIC_ASSET_PATH_RE.search(ev_path)):
                saw_non_asset_4xx = True
                non_asset_error_count += 1
                if ev.get("surface") in {"web_portal", "edge_appliance"} or ev_path:
                    non_asset_error_codes.add(int(status))
                if ua_family:
                    error_ua_families.add(ua_family)
            if ua_raw:
                error_uas.add(ua_raw)
        elif (
            saw_4xx_5xx
            and status is not None
            and 200 <= status < 300
            and SENSITIVE_WEB_PIVOT_RE.search(ev_path)
        ):
            saw_sensitive_2xx_after_error = True
            indicators.add(f"sensitive_pivot_2xx:{ev_path}")

        if ev_path and _is_high_entropy_probe_slug(ev_path):
            clean_p = ev_path.split("?", 1)[0]
            parts = [seg for seg in clean_p.strip("/").split("/") if seg]
            slug_base = parts[-1].split(".", 1)[0] if parts else ""
            is_pure_hex_id = bool(re.fullmatch(r"[0-9a-fA-F]{8,64}", slug_base))
            # Soft-404 (200 OK) only applies to root-level probes (depth <= 1), never /api/orders/<ULID>
            if status == 404 or (status == 200 and saw_non_asset_4xx and len(parts) <= 1 and not is_pure_hex_id):
                random_slug_probe_paths.add(clean_p)

        # Endpoint compressed recon commands, wrapper-stripped redundant worker recon, LLM CLI idioms, & touch-and-bail
        cmd_raw = ev.get("command_line", "")
        cmd_norm = _normalize_shell_cmd(cmd_raw)
        cmd_m = RECON_CMD_RE.search(cmd_norm)
        if cmd_m:
            recon_cmds.add((cmd_m.group(1) or cmd_m.group(0)).lower())
            llm_idiom_has_recon_or_net = True
        if READONLY_RECON_NORMALIZE_RE.match(cmd_norm):
            readonly_recon_counts[cmd_norm] += 1
        if LLM_TOOLBOX_INVENTORY_RE.search(cmd_raw):
            llm_idiom_types.add("toolbox_inventory")
            llm_idiom_has_recon_or_net = True
        if LLM_TRUNCATION_IDIOM_RE.search(cmd_raw):
            llm_idiom_types.add("context_truncation")
            if "curl" in cmd_raw.lower():
                llm_idiom_has_recon_or_net = True
        if LLM_STRUCTURED_FRAMING_RE.search(cmd_raw):
            llm_idiom_types.add("structured_framing")
        if GENERIC_PROC_CHECK_RE.search(cmd_raw) and ev.get("dest_host"):
            proc_check_hosts.add(ev["dest_host"])
        if not is_workstation and cmd_raw and LLM_API_KEY_HARVEST_RE.search(cmd_raw):
            llm_key_harvest_hits += 1
            indicators.add(f"llm_api_key_harvest:{cmd_raw[:80]}")
        parent_raw = str(ev.get("parent_process") or "")
        proc_raw = str(ev.get("process") or "")
        is_ai_agent_parent = bool(
            (parent_raw and AI_AGENT_PARENT_RE.search(parent_raw))
            or (cmd_raw and AI_AGENT_CMD_WRAPPER_RE.search(cmd_raw))
        )
        is_offensive_child = bool(
            (proc_raw and OFFENSIVE_TOOL_PROC_RE.search(proc_raw))
            or (
                cmd_raw
                and (not proc_raw or AI_AGENT_SHELL_PROC_RE.search(proc_raw))
                and OFFENSIVE_TOOL_CMD_HEAD_RE.search(cmd_raw)
            )
        )
        if ev.get("surface") == "endpoint" and is_ai_agent_parent and is_offensive_child:
            reasons.add("ai_agent_spawns_offensive_tool")
            indicators.add(f"ai_agent_tool:{parent_raw or 'shell'}->{proc_raw or cmd_raw[:50]}")
        if ev.get("surface") == "endpoint" and cmd_raw:
            for fm in SENSITIVE_CONFIG_FILE_RE.finditer(cmd_raw):
                tok = fm.group(1).strip(" '\"\t;|/\\").lower()
                if tok:
                    sensitive_files_touched.add(tok)

        # GraphQL introspection -> follow-on API probing & internal AI/MCP endpoint discovery
        gql_blob = f"{ev_path} {cmd_raw} {ev.get('action', '')}"
        if GRAPHQL_INTROSPECTION_RE.search(gql_blob):
            saw_graphql_introspection = True
            indicators.add(f"graphql_introspection:{ev_path[:60] or 'query'}")
        elif saw_graphql_introspection and (
            "/graphql" in path_lower or "/api/" in path_lower or (status is not None and status >= 400)
        ):
            post_introspection_api_hits += 1
        if not is_workstation and ev_path and AI_MCP_DISCOVERY_PATH_RE.search(ev_path):
            ai_mcp_discovery_paths.add(_normalize_api_path(ev_path).lower())

        # FoxIO JA4 / JA4H stack whiplash tracking
        if ev.get("ja4"):
            ja4_fingerprints.add(ev["ja4"])
        if ev.get("ja4h"):
            ja4h_fingerprints.add(ev["ja4h"])

        parent_low = ev.get("parent_process", "").lower()
        proc_low = ev.get("process", "").lower()
        proc_base = proc_low.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if parent_low and proc_low:
            parent_base = parent_low.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            if any(wp in parent_low for wp in WEB_PARENT_PROCESSES) and (
                proc_base in SHELL_CHILD_BASES or proc_base in WEB_DAEMON_EXTRA_CHILDREN
            ):
                reasons.add("web_parent_shell_spawn")
                indicators.add(f"parent_child:{ev['parent_process']}->{ev['process']}")
            elif (
                parent_base in RUNTIME_WEB_PARENTS
                and proc_base in SHELL_CHILD_BASES
                and SUSPICIOUS_RUNTIME_SHELL_ARG_RE.search(cmd_raw)
            ):
                reasons.add("web_parent_shell_spawn")
                indicators.add(f"runtime_parent_susp_shell:{ev['parent_process']}->{ev['process']}")

        # Cloud IAM privilege bursts (action, REST http_path, OR CLI command_line), SP fail->vault pivot, & DryRun
        action_raw = ev.get("action", "")
        action_norm = action_raw.lower().replace("-", "").replace(" ", "")
        cloud_ctx = f"{ev.get('event_type', '')} {ev.get('dest_host', '')} {ev_path} {ev.get('command_line', '')}"
        if action_norm in CLOUD_IAM_HIGH_RISK_ACTIONS:
            iam_hits += 1
            indicators.add(f"iam_action:{action_raw}")
        else:
            m_iam = CLOUD_IAM_PATH_OR_CMD_RE.search(f"{ev_path} {ev.get('command_line', '')}")
            if m_iam:
                iam_hits += 1
                indicators.add(f"iam_rest_or_cli:{m_iam.group(0)}")
        if action_norm == "filterlogevents" and CLOUD_SECRET_SEARCH_RE.search(
            f"{ev.get('command_line', '')} {ev_path}"
        ):
            cloud_secret_search_hits += 1
            indicators.add(f"cloudwatch_secret_search:{ev.get('command_line', '')[:60]}")
        if "dryrun" in action_norm or "dryrunoperation" in searchable.lower():
            cloud_dryrun_hits += 1
        # AntiFox / Arctic Wolf pattern: high-velocity AWS AccessDenied sweep across >=5 distinct APIs/services
        # PLUS stolen valid cloud-key multi-service enumeration (0 AccessDenied) & CyberStrikeAI CloudTrail TTPs
        if ev.get("surface") == "cloud_iam":
            cloud_api_event_count += 1
            actor_str = str(ev.get("actor", ""))
            # Require verified IaC/CSPM role identity (NEVER suppress on attacker-spoofable User-Agent alone)
            if CLOUD_IAC_ACTOR_ROLE_RE.search(actor_str) and not EC2_INSTANCE_ROLE_ACTOR_RE.search(actor_str):
                cloud_is_iac_automation = True
            for sm in CLOUD_SERVICE_TOKEN_RE.finditer(f"{ev.get('event_type', '')} {ev.get('dest_host', '')} {action_raw} {ev_path} {cmd_raw}"):
                cloud_services_seen.add(sm.group(1).lower())
            cloud_action_blob = f"{action_raw} {ev_path} {cmd_raw}"
            if EC2_USERDATA_ACTION_RE.search(cloud_action_blob) or (
                action_norm == "describeinstanceattribute" and "userdata" in searchable.lower()
            ):
                cloud_userdata_hits += 1
            if "sendcommand" in action_norm:
                cloud_ssm_sendcmd_hits += 1
                indicators.add(f"aws_ssm_sendcommand:{action_raw[:60]}")
            if SSM_SENSITIVE_ACTION_RE.search(cloud_action_blob) and "sendcommand" not in action_norm:
                cloud_ssm_decrypt_hits += 1
            # Stolen EC2 instance role (assumed-role/.../i-<hex>) used from non-RFC1918 external IP on sensitive APIs
            if EC2_INSTANCE_ROLE_ACTOR_RE.search(ev.get("actor", "")):
                try:
                    src_ip_obj = ipaddress.ip_address(source_host.strip())
                    rfc1918_or_local = (
                        src_ip_obj.is_loopback
                        or src_ip_obj.is_link_local
                        or (
                            isinstance(src_ip_obj, ipaddress.IPv4Address)
                            and any(
                                src_ip_obj in net
                                for net in (
                                    ipaddress.ip_network("10.0.0.0/8"),
                                    ipaddress.ip_network("172.16.0.0/12"),
                                    ipaddress.ip_network("192.168.0.0/16"),
                                )
                            )
                        )
                    )
                    is_external_ip = not rfc1918_or_local
                except ValueError:
                    is_external_ip = False
                if is_external_ip and (
                    "getsecretvalue" in action_norm
                    or "sendcommand" in action_norm
                    or "getparameter" in action_norm
                    or "describeinstanceattribute" in action_norm
                    or action_norm in CLOUD_IAM_HIGH_RISK_ACTIONS
                ):
                    cloud_ec2_role_external_sensitive = True
                    indicators.add(f"ec2_role_external_replay:{ev.get('actor', '')[:70]}")
            if status in {403, 401} or any(
                tok in searchable.lower() for tok in ("accessdenied", "unauthorizedoperation")
            ):
                denied_key = action_norm or ev_path or ev.get("dest_host", "")
                if denied_key:
                    cloud_denied_apis.add(denied_key)
            elif status is not None and 200 <= status < 300 and (
                "getsecretvalue" in action_norm
                or "get-secret-value" in cloud_ctx.lower()
                or "getsecret" in action_norm
            ):
                saw_cloud_secret_read_200 = True

        # Entra / Cloud Service Principal auth failure -> success -> Key Vault / SAS profiling
        if status in {401, 403} and CLOUD_AUTH_TOKEN_RE.search(cloud_ctx):
            saw_cloud_auth_fail = True
        elif saw_cloud_auth_fail and status is not None and 200 <= status < 300 and CLOUD_AUTH_TOKEN_RE.search(cloud_ctx):
            saw_cloud_auth_success_after_fail = True
        elif saw_cloud_auth_success_after_fail and CLOUD_VAULT_OR_SAS_RE.search(cloud_ctx):
            saw_vault_or_sas_after_auth = True
            indicators.add(f"sp_fail_to_vault:{ev.get('dest_host', '')}{ev_path[:60]}")

        # IdP (Okta / Entra ID): 2FA fatigue/OTP brute-force, rogue MFA factor tampering, legacy /api/v1/authn,
        # SP invalid client-secret guessing -> success, and non-interactive SP multi-resource fan-out
        idp_blob = f"{action_raw} {ev_path}"
        if IDP_MFA_FAIL_RE.search(idp_blob) and (status is None or status >= 400):
            idp_mfa_failures += 1
            indicators.add(f"idp_mfa_fail:{action_raw[:60]}")
        if IDP_MFA_TAMPER_RE.search(action_raw):
            saw_idp_mfa_tamper = True
            indicators.add(f"idp_mfa_tamper:{action_raw[:60]}")
        if "/api/v1/authn" in path_lower and status in {401, 403}:
            okta_legacy_authn_fails += 1
        if IDP_RISK_DETECT_RE.search(action_raw):
            idp_risk_detect_hits += 1
        if IDP_WORKFLOW_OR_OAUTH_ABUSE_RE.search(idp_blob):
            saw_idp_workflow_or_oauth_abuse = True
            indicators.add(f"idp_workflow_or_oauth:{idp_blob[:70]}")
        if IDP_SP_SECRET_FAIL_RE.search(action_raw) and status in {401, 403}:
            idp_sp_secret_fails += 1
            indicators.add(f"idp_sp_secret_fail:{action_raw[:60]}")
        elif (
            idp_sp_secret_fails >= 2
            and status is not None
            and 200 <= status < 300
            and ev.get("event_type") in {"idp_sp_auth", "idp_auth", "authentication_success"}
        ):
            saw_idp_sp_success_after_secret_fail = True
            indicators.add(f"idp_sp_secret_compromise:{ev.get('actor', '')}")
        if ev.get("event_type") == "idp_sp_auth" and ev.get("dest_host"):
            idp_sp_resources.add(ev["dest_host"])

        # Tightly scoped Federated Cross-RP / Multi-client_id Trust Probing (0 FP on Monday-morning SSO bursts):
        # (A) >=3 distinct failing OAuth client_ids/RPs (4xx errors), OR (B) fresh signup -> >=3 distinct RPs in same session
        oauth_blob = f"{action_raw} {ev_path} {cmd_raw}"
        m_cid = OAUTH_CLIENT_ID_RE.search(oauth_blob)
        rp_id = (m_cid.group(1).lower() if m_cid else "") or (
            ev.get("dest_host", "").lower() if ev.get("surface") == "cloud_iam" and ev.get("dest_host") else ""
        )
        if IDP_FRESH_SIGNUP_RE.search(oauth_blob):
            saw_fresh_signup_in_session = True
        elif saw_fresh_signup_in_session and rp_id and rp_id not in {"okta.system.log", "login.microsoftonline.com"}:
            if OAUTH_PATH_OR_ERROR_RE.search(oauth_blob) or ev.get("event_type") in {"idp_auth", "idp_sp_auth", "http"}:
                post_signup_rps.add(rp_id)
        if (
            rp_id
            and status is not None
            and status in {400, 401, 403}
            and OAUTH_PATH_OR_ERROR_RE.search(oauth_blob)
            and "prompt=none" not in oauth_blob.lower()
            and "login_required" not in oauth_blob.lower()
        ):
            oauth_failing_clients.add(rp_id)

    if edr_hits >= 1:
        reasons.add("edr_sensor_enumeration")
    if iam_hits >= 2:
        reasons.add("cloud_iam_privilege_burst")
    if saw_vault_or_sas_after_auth:
        reasons.add("cloud_sp_fail_to_vault_pivot")
    if idp_mfa_failures >= 4 or saw_idp_mfa_tamper or okta_legacy_authn_fails >= 5:
        reasons.add("idp_mfa_fatigue_or_2fa_tampering")
        if idp_mfa_failures >= 4:
            indicators.add(f"idp_mfa_fail_count:{idp_mfa_failures}")
        if okta_legacy_authn_fails >= 5:
            indicators.add(f"okta_legacy_authn_fails:{okta_legacy_authn_fails}")
    if saw_idp_sp_success_after_secret_fail:
        reasons.add("idp_sp_secret_guess_then_success")
    if len(idp_sp_resources) >= 5:
        reasons.add("idp_sp_multi_resource_fanout")
        indicators.add(f"sp_distinct_resources:{len(idp_sp_resources)}")
    if saw_idp_workflow_or_oauth_abuse or idp_risk_detect_hits >= 3:
        reasons.add("idp_probe_registration_or_workflow_abuse")
        if idp_risk_detect_hits >= 3:
            indicators.add(f"okta_user_risk_detect:{idp_risk_detect_hits}")
    if len(oauth_failing_clients) >= 3 or (saw_fresh_signup_in_session and len(post_signup_rps) >= 3):
        reasons.add("idp_federated_trust_probe")
        if len(oauth_failing_clients) >= 3:
            indicators.add(f"failing_oauth_clients:{len(oauth_failing_clients)}")
        if len(post_signup_rps) >= 3:
            indicators.add(f"post_signup_rp_fanout:{len(post_signup_rps)}")
    if llm_key_harvest_hits >= 1:
        reasons.add("llm_api_key_harvesting")
    if (
        len(cloud_services_seen) >= 5
        and span_seconds <= 120.0
        and bool(cloud_services_seen & CLOUD_HIGH_VALUE_SERVICES)
        and not cloud_is_iac_automation
    ):
        reasons.add("cloud_stolen_key_multi_service_enum")
        indicators.add("cloud_services_enum:" + ",".join(sorted(cloud_services_seen)))
    if (
        cloud_ssm_sendcmd_hits >= 1
        or (
            not cloud_is_iac_automation
            and (
                cloud_userdata_hits >= 3
                or (cloud_ssm_decrypt_hits >= 3 and span_seconds <= 30.0)
                or (cloud_api_event_count >= 10 and span_seconds <= 2.0)
            )
        )
    ):
        reasons.add("cloud_ec2_userdata_or_ssm_burst")
        if cloud_userdata_hits >= 3:
            indicators.add(f"ec2_userdata_burst:{cloud_userdata_hits}")
        if cloud_api_event_count >= 10 and span_seconds <= 2.0:
            indicators.add(f"subsecond_cloud_api_burst:{cloud_api_event_count}_in_{span_seconds:.2f}s")
    if cloud_ec2_role_external_sensitive:
        reasons.add("cloud_ec2_role_external_replay")
    if (saw_graphql_introspection and post_introspection_api_hits >= 2) or len(ai_mcp_discovery_paths) >= 2:
        reasons.add("graphql_or_ai_mcp_discovery_probe")
        if ai_mcp_discovery_paths:
            indicators.add("ai_mcp_paths:" + ",".join(sorted(ai_mcp_discovery_paths)))
    if len(sensitive_files_touched) >= 3 and span_seconds <= 45.0:
        reasons.add("config_and_secret_file_harvest_burst")
        indicators.add("harvested_config_files:" + ",".join(sorted(sensitive_files_touched)))
    if saw_relocated_sideload_host and saw_sideload_config_bin:
        reasons.add("dll_sideload_relocated_binary_with_config")
        indicators.add("relocated_sideload_host_plus_config_bin")
    if ad_ldap_kerb_failures >= 8 and span_seconds <= 60.0:
        reasons.add("ad_ntlm_relay_or_ldap_kerb_enum")
        indicators.add(f"ldap_kerb_auth_fails:{ad_ldap_kerb_failures}")
    if (
        cloud_secret_search_hits >= 1
        or cloud_dryrun_hits >= 4
        or len(cloud_denied_apis) >= 5
        or (len(cloud_denied_apis) >= 3 and saw_cloud_secret_read_200)
    ):
        reasons.add("cloud_secret_search_or_dryrun_burst")
        if cloud_dryrun_hits >= 4:
            indicators.add(f"cloud_dryrun_count:{cloud_dryrun_hits}")
        if len(cloud_denied_apis) >= 3:
            indicators.add(f"cloud_access_denied_apis:{len(cloud_denied_apis)}")
        if saw_cloud_secret_read_200:
            indicators.add("cloud_secret_read_after_denials:true")

    # Multi-UA rotation on 4xx errors from a single source (Theori / ThreatDefence signal)
    if len(error_uas) >= 3:
        reasons.add("ua_diversity_on_errors")
        indicators.add(f"distinct_error_uas:{len(error_uas)}")

    # Edge appliance / login rapid spray & path probing
    # Catches both fast sprays (<=2.5s, >=5 fails) AND throttled 4-6s sprays on edge/login endpoints (>=10 fails, >=90% fail)
    err_ratio_local = (error_count / len(events)) if events else 0.0
    if edge_auth_failures >= 5 and mean_interval is not None and mean_interval <= 2.5:
        reasons.add("edge_vpn_rapid_spray")
        indicators.add(f"edge_auth_failures:{edge_auth_failures}")
    elif (
        edge_auth_failures >= 10
        and err_ratio_local >= 0.9
        and mean_interval is not None
        and mean_interval <= 6.0
    ):
        reasons.add("edge_vpn_rapid_spray")
        indicators.add(f"throttled_edge_spray_failures:{edge_auth_failures}")
    if len(edge_path_probes) >= 4 and mean_interval is not None and mean_interval <= 3.0:
        reasons.add("edge_appliance_path_probe")
        indicators.add(f"unique_edge_paths:{len(edge_path_probes)}")

    # Web error-correction pivot, forced error-handling calibration, spec-driven targeting, & read-back
    if saw_sensitive_2xx_after_error and error_count >= 3:
        reasons.add("web_error_correction_pivot")
    fault_codes = non_asset_error_codes & {405, 415, 422, 500}
    if (
        (len(non_asset_error_codes) >= 3 and non_asset_error_count >= 3)
        or (
            len(fault_codes) >= 1
            and bool(non_asset_error_codes & {400, 404})
            and len(non_asset_error_codes) >= 2
            and non_asset_error_count >= 3
        )
        or len(random_slug_probe_paths) >= 3
    ):
        reasons.add("web_error_handling_calibration")
        if non_asset_error_codes:
            indicators.add("forced_error_codes:" + ",".join(str(c) for c in sorted(non_asset_error_codes)))
        if len(random_slug_probe_paths) >= 3:
            indicators.add(f"random_slug_404_probes:{len(random_slug_probe_paths)}")
    if saw_spec_harvest and api_calls_after_spec >= 2:
        reasons.add("spec_driven_api_targeting")
    if mutated_canary_4xx_hits >= 2:
        reasons.add("unit42_agentic_canary_probe")
    if write_readback_count >= 2 or (write_readback_count >= 1 and (saw_non_asset_4xx or saw_spec_harvest)):
        reasons.add("write_then_readback_verification")

    # Bimodal LLM Think-Act cadence (Unit 42 / Theori)
    think_act_cycles = _count_think_act_cycles(timestamps)
    if think_act_cycles >= 1:
        reasons.add("think_act_bimodal_cadence")
        indicators.add(f"think_act_cycles:{think_act_cycles}")

    # Endpoint compressed recon burst (e.g. >=5 distinct recon commands in <=35s)
    if len(recon_cmds) >= 5 and span_seconds <= 35.0:
        reasons.add("endpoint_compressed_recon_burst")
        indicators.add(f"recon_cmd_variety:{len(recon_cmds)}")

    # Zero-IOC Detector 1: Self-hosted LLM proxy sawtooth growing-context flow
    sawtooth_hits = _detect_sawtooth_context_flow(events)
    if sawtooth_hits:
        reasons.add("llm_sawtooth_context_flow")
        indicators.update(sawtooth_hits)

    # Zero-IOC Detector 2: Multi-worker redundant read-only recon collision
    repeated_recon = {cmd: cnt for cmd, cnt in readonly_recon_counts.items() if cnt >= 2}
    if any(cnt >= 3 for cnt in repeated_recon.values()) or len(repeated_recon) >= 2:
        reasons.add("multi_worker_redundant_recon")
        indicators.add(
            "redundant_recon:" + ",".join(f"{c}x{n}" for c, n in sorted(repeated_recon.items()))
        )

    # Zero-IOC Detector 3: LLM CLI context-budget & toolbox-inventory idioms
    if len(llm_idiom_types) >= 3 and llm_idiom_has_recon_or_net:
        reasons.add("llm_cli_context_idioms")
        indicators.add("llm_idioms:" + ",".join(sorted(llm_idiom_types)))

    # Zero-IOC Detector 4: NAT-safe FoxIO JA4 / JA4H client stack whiplash from single IP
    # Single-browser sessions legitimately emit 3+ JA4H hashes across GET/cookie/POST even on 2 mistyped VPN
    # passwords, so require TLS JA4 whiplash (>=3 JA4s) OR JA4H whiplash with >=2 distinct UAs + errors.
    if (
        (len(ja4_fingerprints) >= 3 and (len(distinct_uas) <= 1 or non_asset_error_count >= 3 or edge_auth_failures >= 2))
        or (
            len(ja4h_fingerprints) >= 3
            and len(distinct_uas) >= 2
            and (non_asset_error_count >= 3 or edge_auth_failures >= 2)
        )
    ):
        reasons.add("ja4_client_stack_whiplash")
        indicators.add(f"distinct_ja4:{len(ja4_fingerprints)},ja4h:{len(ja4h_fingerprints)}")

    # Zero-IOC Detector 4b: Traffic-recording proxy TLS collapse (single JA4 + >=3 distinct UA families)
    # Complements ja4_client_stack_whiplash when an agent routes curl/python/browser tools through an
    # optional recording proxy (e.g., ARTEX's Go traffic recorder collapsing all tools to one Go TLS stack).
    # SWG/NAT-safe: requires non-browser CLI UA mixed in (or >=3 erroring UA families) so corporate SWGs
    # forwarding Chrome/Firefox/Edge VPN typos never alert.
    has_non_browser_ua = any(not fam.startswith("browser_") for fam in distinct_ua_families)
    if (
        len(ja4_fingerprints) == 1
        and len(distinct_ua_families) >= 3
        and (
            (edge_auth_failures >= 2 and has_non_browser_ua)
            or (
                saw_non_asset_4xx
                and non_asset_error_count >= 3
                and (has_non_browser_ua or len(error_ua_families) >= 3)
            )
        )
    ):
        reasons.add("ja4_proxy_collapse_multi_ua")
        indicators.add(
            f"single_ja4_proxy_collapse:{next(iter(ja4_fingerprints))}"
            f"|ua_families:{','.join(sorted(distinct_ua_families))}"
        )

    # Zero-IOC Detector 5: Touch-and-bail multi-host process/EDR check sweep
    if len(proc_check_hosts) >= 4:
        reasons.add("touch_and_bail_edr_evasion")
        indicators.add(f"probed_hosts:{len(proc_check_hosts)}")

    primary_surface: SurfaceType = "unknown"
    if surfaces:
        top = surfaces.most_common(1)[0][0]
        if top in {"edge_appliance", "web_portal", "endpoint", "cloud_iam", "network"}:
            primary_surface = top  # type: ignore[assignment]
    primary_appliance = appliances.most_common(1)[0][0] if appliances else None

    return sorted(reasons), sorted(indicators), primary_surface, primary_appliance


def scan_telemetry_file(
    file_path: str | Path,
    *,
    fmt: str = "auto",
    bucket_seconds: int = 120,
    burst_event_threshold: int = 8,
    low_jitter_stddev_threshold: float = 1.25,
    error_retry_ratio_threshold: float = 0.35,
    max_sample_events: int = 15,
    authorized_scanner_ips: list[str] | set[str] | tuple[str, ...] | None = None,
) -> list[CandidateWindow]:
    """Run Stage 1 deterministic DuckDB + Python behavioral & artifact detection.

    Supports JSONL plus native Cisco ASA/FTD, Citrix NetScaler, PAN-OS, F5 BIG-IP,
    Zscaler NSS, and Nginx/Apache access logs via auto-detection.
    """
    events = load_events(file_path, fmt=fmt)
    if not events:
        return []

    con = duckdb.connect(database=":memory:")
    con.execute(
        """
        CREATE TABLE events (
            ts_epoch DOUBLE,
            timestamp VARCHAR,
            source_host VARCHAR,
            actor VARCHAR,
            event_type VARCHAR,
            surface VARCHAR,
            appliance VARCHAR,
            process VARCHAR,
            parent_process VARCHAR,
            command_line VARCHAR,
            dest_host VARCHAR,
            dest_port INTEGER,
            http_method VARCHAR,
            http_path VARCHAR,
            user_agent VARCHAR,
            ja4 VARCHAR,
            ja4h VARCHAR,
            bytes_out INTEGER,
            bytes_in INTEGER,
            status_code INTEGER,
            action VARCHAR,
            raw_json VARCHAR
        )
        """
    )
    con.executemany(
        """
        INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                e["ts_epoch"],
                e["timestamp"],
                e["source_host"],
                e["actor"],
                e["event_type"],
                e["surface"],
                e["appliance"],
                e["process"],
                e["parent_process"],
                e["command_line"],
                e["dest_host"],
                e["dest_port"],
                e["http_method"],
                e["http_path"],
                e["user_agent"],
                e["ja4"],
                e["ja4h"],
                e["bytes_out"],
                e["bytes_in"],
                e["status_code"],
                e["action"],
                e["raw_json"],
            )
            for e in events
        ],
    )

    # Gap-based sessionization (defeats clock-boundary straddling evasion while splitting idle gaps > bucket_seconds)
    session_gap = max(int(bucket_seconds), 60)
    con.execute(
        f"""
        CREATE TEMP TABLE sessionized_events AS
        WITH ordered AS (
            SELECT
                *,
                ts_epoch - LAG(ts_epoch) OVER (
                    PARTITION BY source_host, actor
                    ORDER BY ts_epoch
                ) AS raw_delta
            FROM events
        )
        SELECT
            *,
            SUM(CASE WHEN raw_delta IS NULL OR raw_delta > {session_gap} THEN 1 ELSE 0 END) OVER (
                PARTITION BY source_host, actor
                ORDER BY ts_epoch
                ROWS UNBOUNDED PRECEDING
            ) AS session_id
        FROM ordered
        """
    )

    summary_rows = con.execute(
        """
        WITH per_session AS (
            SELECT
                source_host,
                actor,
                session_id,
                ts_epoch,
                dest_host,
                http_path,
                status_code,
                ts_epoch - LAG(ts_epoch) OVER (
                    PARTITION BY source_host, actor, session_id
                    ORDER BY ts_epoch
                ) AS delta_sec
            FROM sessionized_events
        )
        SELECT
            source_host,
            actor,
            session_id,
            COUNT(*) AS event_count,
            MIN(ts_epoch) AS min_ts,
            MAX(ts_epoch) AS max_ts,
            AVG(delta_sec) AS mean_interval,
            STDDEV_POP(delta_sec) AS stddev_interval,
            SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS error_count,
            COUNT(DISTINCT NULLIF(COALESCE(NULLIF(http_path, ''), dest_host), '')) AS unique_targets
        FROM per_session
        GROUP BY source_host, actor, session_id
        ORDER BY min_ts ASC
        """
    ).fetchall()

    candidates: list[CandidateWindow] = []

    for idx, row in enumerate(summary_rows, start=1):
        (
            source_host,
            actor,
            session_id,
            event_count,
            min_ts,
            max_ts,
            mean_interval,
            stddev_interval,
            error_count,
            unique_targets,
        ) = row

        window_events_rows = con.execute(
            """
            SELECT timestamp, ts_epoch, event_type, surface, appliance, process, parent_process,
                   command_line, dest_host, dest_port, http_method, http_path,
                   user_agent, ja4, ja4h, bytes_out, bytes_in, status_code, action
            FROM sessionized_events
            WHERE source_host = ?
              AND actor = ?
              AND session_id = ?
            ORDER BY ts_epoch ASC
            """,
            [source_host, actor, session_id],
        ).fetchall()

        window_events = [
            {
                "timestamp": r[0],
                "ts_epoch": r[1],
                "actor": actor,
                "event_type": r[2],
                "surface": r[3],
                "appliance": r[4],
                "process": r[5],
                "parent_process": r[6],
                "command_line": r[7],
                "dest_host": r[8],
                "dest_port": r[9],
                "http_method": r[10],
                "http_path": r[11],
                "user_agent": r[12],
                "ja4": r[13],
                "ja4h": r[14],
                "bytes_out": r[15],
                "bytes_in": r[16],
                "status_code": r[17],
                "action": r[18],
            }
            for r in window_events_rows
        ]

        span = max(float(max_ts - min_ts), 1.0)
        epm = round((event_count / span) * 60.0, 2)
        err_ratio = round((error_count / event_count) if event_count else 0.0, 3)

        reasons, indicators, primary_surface, primary_appliance = _inspect_window_signals(
            window_events,
            source_host=source_host,
            mean_interval=float(mean_interval) if mean_interval is not None else None,
            stddev_interval=float(stddev_interval) if stddev_interval is not None else None,
            span_seconds=span,
            error_count=int(error_count),
        )

        # General behavioral cadence detections (suppressed only for operator-allowlisted scanner IPs/CIDRs
        # or single-path broken retry loops — never by attacker-spoofable User-Agent strings)
        is_auth_scanner = _is_allowlisted_scanner_ip(source_host, authorized_scanner_ips)
        if event_count >= burst_event_threshold and not is_auth_scanner and (unique_targets >= 2 or reasons):
            if mean_interval is not None and mean_interval <= 3.0:
                reasons.append("machine_speed_burst")
            if (
                stddev_interval is not None
                and mean_interval is not None
                and mean_interval <= 5.0
                and stddev_interval <= low_jitter_stddev_threshold
            ):
                reasons.append("low_jitter_programmatic_cadence")
            if err_ratio >= error_retry_ratio_threshold and error_count >= 3:
                reasons.append("automated_error_retry_loop")

        reasons = sorted(set(reasons))
        if not reasons:
            continue

        risk_score, alert_tier = compute_risk_score(reasons)

        compact_samples = [
            {k: v for k, v in ev.items() if k != "ts_epoch" and v not in ("", None)}
            for ev in window_events[:max_sample_events]
        ]

        candidates.append(
            CandidateWindow(
                window_id=f"W{idx:03d}-{source_host}-S{session_id}",
                source_host=source_host,
                actor=actor,
                surface=primary_surface,
                appliance=primary_appliance,
                start_time=datetime.fromtimestamp(min_ts, tz=timezone.utc),
                end_time=datetime.fromtimestamp(max_ts, tz=timezone.utc),
                reasons=reasons,
                risk_score=risk_score,
                alert_tier=alert_tier,  # type: ignore[arg-type]
                matched_indicators=indicators,
                cadence=CadenceStats(
                    event_count=int(event_count),
                    window_seconds=round(span, 2),
                    events_per_minute=epm,
                    mean_interval_sec=round(float(mean_interval), 3) if mean_interval is not None else None,
                    stddev_interval_sec=(
                        round(float(stddev_interval), 3) if stddev_interval is not None else None
                    ),
                    error_count=int(error_count),
                    error_ratio=err_ratio,
                    unique_targets=int(unique_targets),
                ),
                sample_events=compact_samples,
            )
        )

    # Second pass: Target-Centric Distributed Proxy-Pool Aggregation
    # Catches attackers rotating residential proxy exit IPs per request against the same target portal/VPN
    dist_rows = con.execute(
        f"""
        WITH target_ordered AS (
            SELECT
                *,
                ts_epoch - LAG(ts_epoch) OVER (
                    PARTITION BY dest_host
                    ORDER BY ts_epoch
                ) AS raw_delta
            FROM events
            WHERE dest_host <> ''
              AND surface IN ('edge_appliance', 'web_portal')
        ),
        target_sess AS (
            SELECT
                *,
                SUM(CASE WHEN raw_delta IS NULL OR raw_delta > {session_gap} THEN 1 ELSE 0 END) OVER (
                    PARTITION BY dest_host
                    ORDER BY ts_epoch
                    ROWS UNBOUNDED PRECEDING
                ) AS tsess_id
            FROM target_ordered
        ),
        target_deltas AS (
            SELECT
                *,
                ts_epoch - LAG(ts_epoch) OVER (
                    PARTITION BY dest_host, tsess_id
                    ORDER BY ts_epoch
                ) AS delta_sec
            FROM target_sess
        )
        SELECT
            dest_host,
            tsess_id,
            COUNT(*) AS event_count,
            COUNT(DISTINCT source_host) AS unique_sources,
            MIN(ts_epoch) AS min_ts,
            MAX(ts_epoch) AS max_ts,
            AVG(delta_sec) AS mean_interval,
            STDDEV_POP(delta_sec) AS stddev_interval,
            SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS error_count,
            COUNT(DISTINCT NULLIF(http_path, '')) AS unique_paths
        FROM target_deltas
        GROUP BY dest_host, tsess_id
        HAVING COUNT(DISTINCT source_host) >= 3
           AND SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) >= 5
        ORDER BY min_ts ASC
        """
    ).fetchall()

    for d_idx, drow in enumerate(dist_rows, start=1):
        (
            dest_host,
            tsess_id,
            d_count,
            d_sources,
            d_min_ts,
            d_max_ts,
            d_mean,
            d_std,
            d_errs,
            d_paths,
        ) = drow
        d_span = max(float(d_max_ts - d_min_ts), 1.0)
        d_err_ratio = round(d_errs / d_count, 3) if d_count else 0.0

        d_events_rows = con.execute(
            """
            SELECT timestamp, ts_epoch, source_host, actor, event_type, surface, appliance,
                   http_method, http_path, user_agent, ja4, ja4h, status_code
            FROM events
            WHERE dest_host = ?
              AND ts_epoch >= ?
              AND ts_epoch <= ?
              AND surface IN ('edge_appliance', 'web_portal')
            ORDER BY ts_epoch ASC
            """,
            [dest_host, d_min_ts, d_max_ts],
        ).fetchall()

        edge_hits = sum(
            1 for r in d_events_rows if r[5] == "edge_appliance" or (r[8] and EDGE_PROBE_PATH_RE.search(r[8]))
        )
        canary_hits = sum(
            1
            for r in d_events_rows
            if r[12] in {400, 401, 403, 404, 422}
            and MUTATED_CANARY_STEM_RE.search(f"{r[8] or ''} {r[3] or ''}")
        )
        if d_err_ratio >= 0.70 and ((edge_hits >= 5 and d_mean is not None and d_mean <= 15.0) or canary_hits >= 3):
            d_reasons = ["distributed_proxy_pool_probe"]
            d_indicators = [
                f"target:{dest_host}",
                f"distinct_source_ips:{d_sources}",
                f"error_count:{d_errs}",
            ]
            if canary_hits >= 3:
                d_reasons.append("unit42_agentic_canary_probe")
                d_indicators.append(f"distributed_canary_4xx:{canary_hits}")

            d_samples = [
                {
                    "timestamp": r[0],
                    "source_host": r[2],
                    "actor": r[3],
                    "http_method": r[7],
                    "http_path": r[8],
                    "user_agent": r[9],
                    "status_code": r[12],
                }
                for r in d_events_rows[:max_sample_events]
            ]
            d_risk, d_tier = compute_risk_score(d_reasons)
            candidates.append(
                CandidateWindow(
                    window_id=f"DIST{d_idx:03d}-{dest_host}-S{tsess_id}",
                    source_host=f"distributed:{dest_host}",
                    actor=f"{d_sources}_rotating_ips",
                    surface="edge_appliance" if edge_hits >= 5 else "web_portal",
                    appliance=d_events_rows[0][6] if d_events_rows else None,
                    start_time=datetime.fromtimestamp(d_min_ts, tz=timezone.utc),
                    end_time=datetime.fromtimestamp(d_max_ts, tz=timezone.utc),
                    reasons=sorted(d_reasons),
                    risk_score=d_risk,
                    alert_tier=d_tier,  # type: ignore[arg-type]
                    matched_indicators=sorted(d_indicators),
                    cadence=CadenceStats(
                        event_count=int(d_count),
                        window_seconds=round(d_span, 2),
                        events_per_minute=round((d_count / d_span) * 60.0, 2),
                        mean_interval_sec=round(float(d_mean), 3) if d_mean is not None else None,
                        stddev_interval_sec=round(float(d_std), 3) if d_std is not None else None,
                        error_count=int(d_errs),
                        error_ratio=d_err_ratio,
                        unique_targets=int(d_paths or 1),
                    ),
                    sample_events=d_samples,
                )
            )

    # Third pass: Single-IP Multi-Account Credential Spraying & Spray-Then-Success (IdP / Web / Edge)
    # Catches >=8 distinct failing accounts OR >=5 distinct failing accounts followed by a 200/SUCCESS sign-in!
    spray_rows = con.execute(
        f"""
        WITH src_ordered AS (
            SELECT
                *,
                ts_epoch - LAG(ts_epoch) OVER (
                    PARTITION BY source_host
                    ORDER BY ts_epoch
                ) AS raw_delta
            FROM events
            WHERE actor <> ''
              AND actor <> source_host
              AND (status_code IN (401, 403) OR (status_code = 200 AND event_type IN ('idp_auth', 'idp_sp_auth', 'edge_auth', 'authentication_success')))
        ),
        src_sess AS (
            SELECT
                *,
                SUM(CASE WHEN raw_delta IS NULL OR raw_delta > {session_gap} THEN 1 ELSE 0 END) OVER (
                    PARTITION BY source_host
                    ORDER BY ts_epoch
                    ROWS UNBOUNDED PRECEDING
                ) AS ssess_id
            FROM src_ordered
        )
        SELECT
            source_host,
            ssess_id,
            SUM(CASE WHEN status_code IN (401, 403) THEN 1 ELSE 0 END) AS fail_count,
            COUNT(DISTINCT CASE WHEN status_code IN (401, 403) THEN actor END) AS failed_accounts,
            SUM(CASE WHEN status_code = 200 THEN 1 ELSE 0 END) AS success_count,
            MAX(CASE WHEN status_code = 200 THEN ts_epoch END) AS max_success_ts,
            MIN(CASE WHEN status_code IN (401, 403) THEN ts_epoch END) AS min_fail_ts,
            MIN(ts_epoch) AS min_ts,
            MAX(ts_epoch) AS max_ts,
            MAX(surface) AS sample_surface,
            MAX(appliance) AS sample_appliance
        FROM src_sess
        GROUP BY source_host, ssess_id
        HAVING COUNT(DISTINCT CASE WHEN status_code IN (401, 403) THEN actor END) >= 8
            OR (
                COUNT(DISTINCT CASE WHEN status_code IN (401, 403) THEN actor END) >= 5
                AND SUM(CASE WHEN status_code = 200 THEN 1 ELSE 0 END) >= 1
                AND MAX(CASE WHEN status_code = 200 THEN ts_epoch END) >= MIN(CASE WHEN status_code IN (401, 403) THEN ts_epoch END)
            )
        ORDER BY min_ts ASC
        """
    ).fetchall()

    for sp_idx, srow in enumerate(spray_rows, start=1):
        (
            sp_host,
            sp_sess,
            sp_fails,
            sp_accts,
            sp_succ,
            _max_succ_ts,
            _min_fail_ts,
            sp_min,
            sp_max,
            sp_surf,
            sp_app,
        ) = srow
        sp_span = max(float(sp_max - sp_min), 1.0)
        sp_reasons: list[str] = []
        sp_indicators = [f"sprayed_accounts:{sp_accts}", f"auth_failures:{sp_fails}"]
        if sp_accts >= 8:
            sp_reasons.append("multi_account_credential_spray")
        if sp_accts >= 5 and sp_succ >= 1:
            sp_reasons.append("idp_spray_then_success")
            sp_indicators.append(f"post_spray_successes:{sp_succ}")
        sp_risk, sp_tier = compute_risk_score(sp_reasons)
        resolved_surface: SurfaceType = (
            sp_surf if sp_surf in {"edge_appliance", "web_portal", "endpoint", "cloud_iam", "network"} else "cloud_iam"
        )  # type: ignore[assignment]
        candidates.append(
            CandidateWindow(
                window_id=f"SPRAY{sp_idx:03d}-{sp_host}-S{sp_sess}",
                source_host=sp_host,
                actor=f"{sp_accts}_sprayed_accounts",
                surface=resolved_surface,
                appliance=sp_app or None,
                start_time=datetime.fromtimestamp(sp_min, tz=timezone.utc),
                end_time=datetime.fromtimestamp(sp_max, tz=timezone.utc),
                reasons=sorted(sp_reasons),
                risk_score=sp_risk,
                alert_tier=sp_tier,  # type: ignore[arg-type]
                matched_indicators=sp_indicators,
                cadence=CadenceStats(
                    event_count=int(sp_fails + sp_succ),
                    window_seconds=round(sp_span, 2),
                    events_per_minute=round(((sp_fails + sp_succ) / sp_span) * 60.0, 2),
                    error_count=int(sp_fails),
                    error_ratio=round(sp_fails / max(sp_fails + sp_succ, 1), 3),
                    unique_targets=int(sp_accts),
                ),
                sample_events=[],
            )
        )

    # Fourth pass: Single-IP / Single-Source Okta MFA Fatigue or Factor Tampering spanning multiple user/target records
    idp_mfa_rows = con.execute(
        f"""
        WITH mfa_ordered AS (
            SELECT
                *,
                ts_epoch - LAG(ts_epoch) OVER (
                    PARTITION BY source_host
                    ORDER BY ts_epoch
                ) AS raw_delta
            FROM events
            WHERE appliance IN ('okta', 'entra_id', 'duo', 'pingfederate', 'google_workspace')
              AND (
                LOWER(action) LIKE '%deny_push%'
                OR LOWER(action) LIKE '%verification_error%'
                OR LOWER(action) LIKE '%err_500121%'
                OR LOWER(action) LIKE '%user.mfa.factor.activate%'
                OR LOWER(action) LIKE '%user.mfa.factor.deactivate%'
                OR LOWER(action) LIKE '%register security info%'
                OR LOWER(action) LIKE '%duo_mfa_denied%'
                OR LOWER(action) LIKE '%duo_fraud_reported%'
                OR LOWER(action) LIKE '%duo_admin:bypass_create%'
                OR LOWER(action) LIKE '%duo_admin:phone_create%'
                OR LOWER(action) LIKE '%second_factor_failure%'
                OR LOWER(action) LIKE '%2sv_disable%'
                OR LOWER(action) LIKE '%recovery_phone_edit%'
                OR LOWER(action) LIKE '%pingid%'
                OR LOWER(http_path) LIKE '%/api/v1/authn%'
              )
        ),
        mfa_sess AS (
            SELECT
                *,
                SUM(CASE WHEN raw_delta IS NULL OR raw_delta > {session_gap} THEN 1 ELSE 0 END) OVER (
                    PARTITION BY source_host
                    ORDER BY ts_epoch
                    ROWS UNBOUNDED PRECEDING
                ) AS msess_id
            FROM mfa_ordered
        )
        SELECT
            source_host,
            msess_id,
            COUNT(*) AS ev_cnt,
            SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS fail_cnt,
            SUM(CASE WHEN LOWER(action) LIKE '%factor.activate%'
                       OR LOWER(action) LIKE '%factor.deactivate%'
                       OR LOWER(action) LIKE '%register security info%'
                       OR LOWER(action) LIKE '%duo_fraud_reported%'
                       OR LOWER(action) LIKE '%bypass_create%'
                       OR LOWER(action) LIKE '%phone_create%'
                       OR LOWER(action) LIKE '%2sv_disable%'
                       OR LOWER(action) LIKE '%recovery_phone_edit%' THEN 1 ELSE 0 END) AS tamper_cnt,
            MIN(ts_epoch) AS min_ts,
            MAX(ts_epoch) AS max_ts,
            MAX(appliance) AS sample_app
        FROM mfa_sess
        GROUP BY source_host, msess_id
        HAVING SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) >= 4
            OR SUM(CASE WHEN LOWER(action) LIKE '%factor.activate%'
                          OR LOWER(action) LIKE '%factor.deactivate%'
                          OR LOWER(action) LIKE '%register security info%'
                          OR LOWER(action) LIKE '%duo_fraud_reported%'
                          OR LOWER(action) LIKE '%bypass_create%'
                          OR LOWER(action) LIKE '%phone_create%'
                          OR LOWER(action) LIKE '%2sv_disable%'
                          OR LOWER(action) LIKE '%recovery_phone_edit%' THEN 1 ELSE 0 END) >= 1
        ORDER BY min_ts ASC
        """
    ).fetchall()

    existing_idp_mfa_hosts = {c.source_host for c in candidates if "idp_mfa_fatigue_or_2fa_tampering" in c.reasons}
    for m_idx, mrow in enumerate(idp_mfa_rows, start=1):
        m_host, m_sess, m_cnt, m_fails, m_tamper, m_min, m_max, m_app = mrow
        if m_host in existing_idp_mfa_hosts:
            continue
        m_span = max(float(m_max - m_min), 1.0)
        m_reasons = ["idp_mfa_fatigue_or_2fa_tampering"]
        m_risk, m_tier = compute_risk_score(m_reasons)
        candidates.append(
            CandidateWindow(
                window_id=f"IDPMFA{m_idx:03d}-{m_host}-S{m_sess}",
                source_host=m_host,
                actor=f"{m_app}_2fa_activity",
                surface="cloud_iam",
                appliance=m_app or None,
                start_time=datetime.fromtimestamp(m_min, tz=timezone.utc),
                end_time=datetime.fromtimestamp(m_max, tz=timezone.utc),
                reasons=m_reasons,
                risk_score=m_risk,
                alert_tier=m_tier,  # type: ignore[arg-type]
                matched_indicators=[f"mfa_or_authn_fails:{m_fails}", f"factor_tamper_events:{m_tamper}"],
                cadence=CadenceStats(
                    event_count=int(m_cnt),
                    window_seconds=round(m_span, 2),
                    events_per_minute=round((m_cnt / m_span) * 60.0, 2),
                    error_count=int(m_fails),
                    error_ratio=round(m_fails / max(m_cnt, 1), 3),
                    unique_targets=1,
                ),
                sample_events=[],
            )
        )

    # Fifth pass: Single-IP Mass Self-Service Probe Account Registration (Okta/Auth0 Threat Intel Oct/Nov 2026)
    reg_rows = con.execute(
        f"""
        WITH reg_ordered AS (
            SELECT
                *,
                ts_epoch - LAG(ts_epoch) OVER (
                    PARTITION BY source_host
                    ORDER BY ts_epoch
                ) AS raw_delta
            FROM events
            WHERE (
                LOWER(action) LIKE '%user.lifecycle.create%'
                OR LOWER(action) LIKE '%user.account.register%'
                OR LOWER(action) LIKE '%auth0_signup%'
                OR LOWER(http_path) LIKE '%/oauth/register%'
                OR (LOWER(http_path) LIKE '%/api/v1/users%' AND UPPER(http_method) = 'POST')
            )
        ),
        reg_sess AS (
            SELECT
                *,
                SUM(CASE WHEN raw_delta IS NULL OR raw_delta > {session_gap} THEN 1 ELSE 0 END) OVER (
                    PARTITION BY source_host
                    ORDER BY ts_epoch
                    ROWS UNBOUNDED PRECEDING
                ) AS rsess_id
            FROM reg_ordered
        )
        SELECT
            source_host,
            rsess_id,
            COUNT(*) AS reg_cnt,
            COUNT(DISTINCT actor) AS reg_accts,
            MIN(ts_epoch) AS min_ts,
            MAX(ts_epoch) AS max_ts,
            MAX(appliance) AS sample_app
        FROM reg_sess
        GROUP BY source_host, rsess_id
        HAVING COUNT(*) >= 5
        ORDER BY min_ts ASC
        """
    ).fetchall()

    for r_idx, rrow in enumerate(reg_rows, start=1):
        r_host, r_sess, r_cnt, r_accts, r_min, r_max, r_app = rrow
        r_span = max(float(r_max - r_min), 1.0)
        r_reasons = ["idp_probe_registration_or_workflow_abuse"]
        r_risk, r_tier = compute_risk_score(r_reasons)
        candidates.append(
            CandidateWindow(
                window_id=f"IDPREG{r_idx:03d}-{r_host}-S{r_sess}",
                source_host=r_host,
                actor=f"{r_accts}_registered_probe_accounts",
                surface="cloud_iam",
                appliance=r_app or "okta",
                start_time=datetime.fromtimestamp(r_min, tz=timezone.utc),
                end_time=datetime.fromtimestamp(r_max, tz=timezone.utc),
                reasons=r_reasons,
                risk_score=r_risk,
                alert_tier=r_tier,  # type: ignore[arg-type]
                matched_indicators=[f"probe_account_registrations:{r_cnt}", f"distinct_actors:{r_accts}"],
                cadence=CadenceStats(
                    event_count=int(r_cnt),
                    window_seconds=round(r_span, 2),
                    events_per_minute=round((r_cnt / r_span) * 60.0, 2),
                    error_count=0,
                    error_ratio=0.0,
                    unique_targets=int(r_accts or 1),
                ),
                sample_events=[],
            )
        )

    # Sixth pass: Server Callback to Probing IP (Zero-IOC cross-direction RCE/SSRF/OOB correlation)
    # Catches any target server initiating an outbound connection back to the exact IP that probed it <=10m prior
    callback_rows = con.execute(
        """
        SELECT
            in_ev.dest_host AS target_server,
            in_ev.source_host AS probing_ip,
            MIN(in_ev.ts_epoch) AS first_probe_ts,
            MIN(out_ev.ts_epoch) AS first_callback_ts,
            MAX(out_ev.ts_epoch) AS last_callback_ts,
            COUNT(DISTINCT in_ev.ts_epoch) AS probe_count,
            COUNT(DISTINCT out_ev.ts_epoch) AS callback_count,
            MAX(out_ev.dest_port) AS sample_cb_port
        FROM events in_ev
        JOIN events out_ev
          ON out_ev.source_host = in_ev.dest_host
         AND out_ev.dest_host = in_ev.source_host
         AND out_ev.ts_epoch >= in_ev.ts_epoch
         AND (out_ev.ts_epoch - in_ev.ts_epoch) <= 600
        WHERE in_ev.surface IN ('web_portal', 'edge_appliance')
          AND in_ev.source_host <> ''
          AND in_ev.dest_host <> ''
          AND in_ev.source_host <> in_ev.dest_host
        GROUP BY in_ev.dest_host, in_ev.source_host
        ORDER BY first_callback_ts ASC
        """
    ).fetchall()

    for cb_idx, cbrow in enumerate(callback_rows, start=1):
        cb_srv, cb_ip, cb_probe_ts, cb_first_ts, cb_last_ts, cb_probes, cb_outs, cb_port = cbrow
        cb_delay = round(max(0.0, float(cb_first_ts - cb_probe_ts)), 2)
        cb_span = max(float(cb_last_ts - cb_probe_ts), 1.0)
        cb_reasons = ["agentic_server_callback_on_probe"]
        cb_risk, cb_tier = compute_risk_score(cb_reasons)
        cb_indicators = [
            f"callback_server:{cb_srv}",
            f"probing_ip:{cb_ip}",
            f"callback_delay_sec:{cb_delay}",
        ]
        if cb_port:
            cb_indicators.append(f"callback_port:{cb_port}")
        candidates.append(
            CandidateWindow(
                window_id=f"CALLBACK{cb_idx:03d}-{cb_srv}",
                source_host=cb_srv,
                actor=f"callback_to_{cb_ip}",
                surface="network",
                appliance=None,
                start_time=datetime.fromtimestamp(cb_probe_ts, tz=timezone.utc),
                end_time=datetime.fromtimestamp(cb_last_ts, tz=timezone.utc),
                reasons=cb_reasons,
                risk_score=cb_risk,
                alert_tier=cb_tier,  # type: ignore[arg-type]
                matched_indicators=cb_indicators,
                cadence=CadenceStats(
                    event_count=int(cb_probes + cb_outs),
                    window_seconds=round(cb_span, 2),
                    events_per_minute=round(((cb_probes + cb_outs) / cb_span) * 60.0, 2),
                    error_count=0,
                    error_ratio=0.0,
                    unique_targets=1,
                ),
                sample_events=[],
            )
        )

    # Seventh pass: Machine-Speed SMB / WinRM / Remote-Admin Lateral Fan-Out
    # Catches compromised hosts sweeping >=4 distinct internal peers on 445/5985/5986/135/3389/22 at machine cadence
    lateral_rows = con.execute(
        f"""
        WITH lat_ordered AS (
            SELECT
                *,
                ts_epoch - LAG(ts_epoch) OVER (
                    PARTITION BY source_host
                    ORDER BY ts_epoch
                ) AS raw_delta
            FROM events
            WHERE dest_port IN (445, 5985, 5986, 135, 3389, 22)
              AND dest_host <> ''
              AND dest_host <> source_host
        ),
        lat_sess AS (
            SELECT
                *,
                SUM(CASE WHEN raw_delta IS NULL OR raw_delta > {session_gap} THEN 1 ELSE 0 END) OVER (
                    PARTITION BY source_host
                    ORDER BY ts_epoch
                    ROWS UNBOUNDED PRECEDING
                ) AS lsess_id
            FROM lat_ordered
        ),
        lat_deltas AS (
            SELECT
                *,
                ts_epoch - LAG(ts_epoch) OVER (
                    PARTITION BY source_host, lsess_id
                    ORDER BY ts_epoch
                ) AS delta_sec
            FROM lat_sess
        )
        SELECT
            source_host,
            lsess_id,
            COUNT(*) AS ev_cnt,
            COUNT(DISTINCT dest_host) AS distinct_targets,
            STRING_AGG(DISTINCT CAST(dest_port AS VARCHAR), ',') AS ports_csv,
            MIN(ts_epoch) AS min_ts,
            MAX(ts_epoch) AS max_ts,
            AVG(delta_sec) AS mean_interval
        FROM lat_deltas
        GROUP BY source_host, lsess_id
        HAVING COUNT(DISTINCT dest_host) >= 4
           AND ((MAX(ts_epoch) - MIN(ts_epoch)) <= 120.0 OR AVG(delta_sec) <= 5.0)
        ORDER BY min_ts ASC
        """
    ).fetchall()

    for l_idx, lrow in enumerate(lateral_rows, start=1):
        l_host, l_sess, l_cnt, l_tgts, l_ports, l_min, l_max, l_mean = lrow
        if _is_allowlisted_scanner_ip(l_host, authorized_scanner_ips):
            continue
        l_span = max(float(l_max - l_min), 1.0)
        l_reasons = ["agentic_lateral_fanout_smb_winrm"]
        l_risk, l_tier = compute_risk_score(l_reasons)
        candidates.append(
            CandidateWindow(
                window_id=f"LATERAL{l_idx:03d}-{l_host}-S{l_sess}",
                source_host=l_host,
                actor=f"lateral_sweep_{l_tgts}_hosts",
                surface="network",
                appliance=None,
                start_time=datetime.fromtimestamp(l_min, tz=timezone.utc),
                end_time=datetime.fromtimestamp(l_max, tz=timezone.utc),
                reasons=l_reasons,
                risk_score=l_risk,
                alert_tier=l_tier,  # type: ignore[arg-type]
                matched_indicators=[f"lateral_targets:{l_tgts}", f"lateral_ports:{l_ports}"],
                cadence=CadenceStats(
                    event_count=int(l_cnt),
                    window_seconds=round(l_span, 2),
                    events_per_minute=round((l_cnt / l_span) * 60.0, 2),
                    mean_interval_sec=round(float(l_mean), 3) if l_mean is not None else None,
                    error_count=0,
                    error_ratio=0.0,
                    unique_targets=int(l_tgts),
                ),
                sample_events=[],
            )
        )

    # Eighth pass: Custom-Domain Out-of-Band (OOB) DNS Callback Immediately After Web/Edge Probing
    # Catches private interactsh / blind SSRF / XXE / RCE DNS callbacks regardless of callback domain!
    dns_oob_rows = con.execute(
        """
        SELECT
            in_ev.dest_host AS target_server,
            in_ev.source_host AS probing_ip,
            dns_ev.dest_host AS oob_fqdn,
            MIN(in_ev.ts_epoch) AS probe_ts,
            MIN(dns_ev.ts_epoch) AS dns_ts
        FROM events in_ev
        JOIN events dns_ev
          ON dns_ev.source_host = in_ev.dest_host
         AND dns_ev.ts_epoch >= in_ev.ts_epoch
         AND (dns_ev.ts_epoch - in_ev.ts_epoch) <= 90
        WHERE in_ev.surface IN ('web_portal', 'edge_appliance')
          AND in_ev.dest_host <> ''
          AND dns_ev.dest_host <> ''
          AND (LOWER(dns_ev.event_type) LIKE '%dns%' OR dns_ev.dest_port = 53)
        GROUP BY in_ev.dest_host, in_ev.source_host, dns_ev.dest_host
        ORDER BY dns_ts ASC
        """
    ).fetchall()

    oob_idx = 0
    for d_srv, d_ip, d_fqdn, d_probe_ts, d_dns_ts in dns_oob_rows:
        if not _is_oob_high_entropy_dns_fqdn(d_fqdn):
            continue
        oob_idx += 1
        d_delay = round(max(0.0, float(d_dns_ts - d_probe_ts)), 2)
        d_reasons = ["dns_oob_callback_after_probe"]
        d_risk, d_tier = compute_risk_score(d_reasons)
        candidates.append(
            CandidateWindow(
                window_id=f"OOBDNS{oob_idx:03d}-{d_srv}",
                source_host=d_srv,
                actor=f"dns_oob_after_{d_ip}",
                surface="network",
                appliance=None,
                start_time=datetime.fromtimestamp(d_probe_ts, tz=timezone.utc),
                end_time=datetime.fromtimestamp(d_dns_ts, tz=timezone.utc),
                reasons=d_reasons,
                risk_score=d_risk,
                alert_tier=d_tier,  # type: ignore[arg-type]
                matched_indicators=[
                    f"probing_ip:{d_ip}",
                    f"oob_dns_fqdn:{d_fqdn}",
                    f"callback_delay_sec:{d_delay}",
                ],
                cadence=CadenceStats(
                    event_count=2,
                    window_seconds=max(d_delay, 1.0),
                    events_per_minute=round((2 / max(d_delay, 1.0)) * 60.0, 2),
                    error_count=0,
                    error_ratio=0.0,
                    unique_targets=1,
                ),
                sample_events=[],
            )
        )

    # Ninth pass: Single Source IP Operating Multiple Distinct Stolen Cloud Identities (200 OK)
    # Catches Elastic's CyberStrikeAI pattern (single IP operating >=3 distinct IAM users / EC2 instance roles across accounts)
    multi_id_rows = con.execute(
        """
        SELECT
            source_host,
            COUNT(*) AS ev_cnt,
            COUNT(DISTINCT actor) AS distinct_identities,
            MIN(ts_epoch) AS min_ts,
            MAX(ts_epoch) AS max_ts,
            STRING_AGG(DISTINCT actor, ',') AS actors_csv
        FROM events
        WHERE surface = 'cloud_iam'
          AND actor <> ''
          AND actor <> source_host
          AND (status_code IS NULL OR (status_code >= 200 AND status_code < 300))
          AND (
            LOWER(actor) LIKE 'arn:aws:%'
            OR LOWER(actor) LIKE '%assumed-role/%'
            OR LOWER(actor) LIKE '%serviceprincipal%'
            OR LOWER(event_type) LIKE '%cloudtrail%'
            OR LOWER(dest_host) LIKE '%.amazonaws.com'
          )
          AND NOT (
            LOWER(actor) LIKE '%terraform%'
            OR LOWER(actor) LIKE '%ansible%'
            OR LOWER(actor) LIKE '%datadog%'
            OR LOWER(actor) LIKE '%wiz%'
            OR LOWER(actor) LIKE '%prisma%'
            OR LOWER(actor) LIKE '%cspm%'
          )
        GROUP BY source_host
        HAVING COUNT(DISTINCT actor) >= 3
        ORDER BY min_ts ASC
        """
    ).fetchall()

    for mi_idx, mirow in enumerate(multi_id_rows, start=1):
        mi_host, mi_cnt, mi_ids, mi_min, mi_max, mi_actors = mirow
        # Require a valid IP address (excludes AWS service principals like cloudformation.amazonaws.com / AWS Internal)
        try:
            ipaddress.ip_address(str(mi_host).strip())
        except ValueError:
            continue
        if _is_allowlisted_scanner_ip(mi_host, authorized_scanner_ips):
            continue
        mi_span = max(float(mi_max - mi_min), 1.0)
        mi_reasons = ["cloud_multi_identity_from_single_ip"]
        mi_risk, mi_tier = compute_risk_score(mi_reasons)
        candidates.append(
            CandidateWindow(
                window_id=f"CLOUDMULTIID{mi_idx:03d}-{mi_host}",
                source_host=mi_host,
                actor=f"{mi_ids}_stolen_cloud_identities",
                surface="cloud_iam",
                appliance="aws_cloudtrail",
                start_time=datetime.fromtimestamp(mi_min, tz=timezone.utc),
                end_time=datetime.fromtimestamp(mi_max, tz=timezone.utc),
                reasons=mi_reasons,
                risk_score=mi_risk,
                alert_tier=mi_tier,  # type: ignore[arg-type]
                matched_indicators=[
                    f"distinct_cloud_identities:{mi_ids}",
                    f"sample_identities:{str(mi_actors)[:120]}",
                ],
                cadence=CadenceStats(
                    event_count=int(mi_cnt),
                    window_seconds=round(mi_span, 2),
                    events_per_minute=round((mi_cnt / mi_span) * 60.0, 2),
                    error_count=0,
                    error_ratio=0.0,
                    unique_targets=int(mi_ids),
                ),
                sample_events=[],
            )
        )

    con.close()
    return candidates


_SYNTHETIC_ACTOR_RE = re.compile(
    r"(?:rotating_ips|identities|lateral_sweep_|distributed:|probe_signups|sprayed_accounts|"
    r"_2fa_activity|registered_probe_accounts|unknown|^(?:\d{1,3}\.){3}\d{1,3}$)",
    re.IGNORECASE,
)


def _window_entity_sets(cand: CandidateWindow) -> tuple[set[str], set[str], set[str], set[str]]:
    """Extract (source_hosts, dest_hosts, distributed_targets, non_ip_actors) for bipartite graph correlation."""
    src_hosts: set[str] = set()
    dst_hosts: set[str] = set()
    dist_targets: set[str] = set()
    actors: set[str] = set()

    sh = (cand.source_host or "").strip().lower()
    if sh:
        if sh.startswith("distributed:"):
            target = sh.split(":", 1)[1].strip()
            if target:
                dist_targets.add(target)
        else:
            src_hosts.add(sh)

    act = (cand.actor or "").strip().lower()
    if act and act != sh and not _SYNTHETIC_ACTOR_RE.search(act):
        actors.add(act)

    for ev in cand.sample_events:
        dh = str(ev.get("dest_host") or "").strip().lower()
        if dh and dh != sh:
            dst_hosts.add(dh)
        ev_act = str(ev.get("actor") or "").strip().lower()
        if ev_act and ev_act != sh and not _SYNTHETIC_ACTOR_RE.search(ev_act):
            actors.add(ev_act)
    return src_hosts, dst_hosts, dist_targets, actors


def _windows_entity_linked(
    ent_a: tuple[set[str], set[str], set[str], set[str]],
    ent_b: tuple[set[str], set[str], set[str], set[str]],
) -> bool:
    """Return True if two windows share a source host, stolen identity, external->internal pivot, or distributed target."""
    src_a, dst_a, dist_a, act_a = ent_a
    src_b, dst_b, dist_b, act_b = ent_b
    return bool(
        (src_a & src_b)
        or (act_a & act_b)
        or (dst_a & src_b)
        or (dst_b & src_a)
        or (dist_a & (src_b | dst_b))
        or (dist_b & (src_a | dst_a))
    )


def _cluster_entity_linked(
    ordered: list[CandidateWindow],
    entities: list[tuple[set[str], set[str], set[str], set[str]]],
    *,
    max_gap_seconds: float,
) -> list[list[CandidateWindow]]:
    """Connected-component clustering over entity-linked windows using a rolling inter-stage gap."""
    n = len(ordered)
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for i in range(n):
        for j in range(i + 1, n):
            gap = (ordered[j].start_time - ordered[i].end_time).total_seconds()
            if gap > max_gap_seconds:
                continue
            if _windows_entity_linked(entities[i], entities[j]):
                union(i, j)

    comps: dict[int, list[CandidateWindow]] = {}
    for i, cand in enumerate(ordered):
        comps.setdefault(find(i), []).append(cand)
    return list(comps.values())


def correlate_kill_chains(
    candidates: list[CandidateWindow],
    *,
    horizon_minutes: int = 180,
    long_horizon_days: int = 30,
) -> list[KillChainStoryline]:
    """Correlate flagged windows via bipartite entity-graph edges across short (<3h) & rolling long-horizon (<=30d) gaps."""
    if not candidates:
        return []

    ordered = sorted(candidates, key=lambda c: c.start_time)
    entities = [_window_entity_sets(c) for c in ordered]
    short_max_sec = horizon_minutes * 60
    long_max_sec = long_horizon_days * 86400

    groups = _cluster_entity_linked(ordered, entities, max_gap_seconds=short_max_sec)

    storylines: list[KillChainStoryline] = []
    short_window_sets: set[frozenset[str]] = set()
    kc_idx = 0
    for grp in groups:
        surfaces = sorted({c.surface for c in grp if c.surface != "unknown"})
        appliances = sorted({c.appliance for c in grp if c.appliance})
        if len(surfaces) < 2 and len(grp) < 2:
            continue

        start = min(c.start_time for c in grp)
        end = max(c.end_time for c in grp)
        if (end - start).total_seconds() > short_max_sec:
            continue
        kc_idx += 1
        duration_min = round(max((end - start).total_seconds() / 60.0, 0.01), 2)
        progression = " -> ".join(f"{c.surface}({c.source_host})" for c in grp)
        wids = [c.window_id for c in grp]
        short_window_sets.add(frozenset(wids))

        storylines.append(
            KillChainStoryline(
                storyline_id=f"KC-{kc_idx:03d}",
                start_time=start,
                end_time=end,
                duration_minutes=duration_min,
                surfaces_involved=surfaces,
                appliances_involved=appliances,
                actors=sorted({c.actor for c in grp}),
                hosts=sorted({c.source_host for c in grp}),
                window_ids=wids,
                combined_reasons=sorted({r for c in grp for r in c.reasons}),
                combined_indicators=sorted({i for c in grp for i in c.matched_indicators}),
                progression_summary=progression,
            )
        )

    # Long-horizon rolling-gap correlation (links shared IP, stolen actor, or external->internal pivots across >3h / <=30d gaps)
    long_groups = _cluster_entity_linked(ordered, entities, max_gap_seconds=long_max_sec)
    long_idx = 0
    for lgrp in long_groups:
        if len(lgrp) < 2:
            continue
        start = min(c.start_time for c in lgrp)
        end = max(c.end_time for c in lgrp)
        span_sec = (end - start).total_seconds()
        if span_sec <= short_max_sec:
            continue
        wids = [c.window_id for c in lgrp]
        if frozenset(wids) in short_window_sets:
            continue
        long_idx += 1
        duration_min = round(max(span_sec / 60.0, 0.01), 2)
        gap_days = round(span_sec / 86400.0, 2)
        hosts_involved = sorted({c.source_host for c in lgrp})
        storylines.append(
            KillChainStoryline(
                storyline_id=f"KC-LONG-{long_idx:03d}",
                start_time=start,
                end_time=end,
                duration_minutes=duration_min,
                surfaces_involved=sorted({c.surface for c in lgrp if c.surface != "unknown"}),
                appliances_involved=sorted({c.appliance for c in lgrp if c.appliance}),
                actors=sorted({c.actor for c in lgrp}),
                hosts=hosts_involved,
                window_ids=wids,
                combined_reasons=sorted({r for c in lgrp for r in c.reasons}),
                combined_indicators=sorted(
                    {i for c in lgrp for i in c.matched_indicators}
                    | {f"long_horizon_dormant_gap_days:{gap_days}"}
                ),
                progression_summary=f"long_horizon({','.join(hosts_involved[:3])}, {gap_days}d): "
                + " -> ".join(f"{c.surface}({c.actor})" for c in lgrp),
            )
        )
    return storylines
