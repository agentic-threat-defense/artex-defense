"""Automated multi-backend pySigma compilation and BushidoToken self-proclaimed UA regression tests."""

import json
from pathlib import Path

from artex_defense.detectors import scan_telemetry_file
from artex_defense.eval_harness import evaluate_sigma_rule_on_events
from artex_defense.sigma_compiler import compile_sigma_directory
import yaml

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "sigma"


def test_all_sigma_rules_compile_across_enterprise_siem_backends(tmp_path: Path) -> None:
    report = compile_sigma_directory(RULES_DIR, export_dir=tmp_path)

    assert report["total_rules"] >= 13
    assert report["schema_issues"] == [], f"pySigma schema issues: {report['schema_issues']}"
    assert report["all_ok"] is True, f"Sigma compilation failures: {report['targets']}"

    by_key = {t["key"]: t for t in report["targets"]}

    # Full-pack compilation targets (all 13 rules)
    for full_key in ("esql_ecs", "lucene_ecs", "kusto_generic", "crowdstrike_logscale", "splunk_spl"):
        t = by_key[full_key]
        assert t["applicable"] == report["total_rules"]
        assert t["compiled"] == report["total_rules"], f"{full_key} failures: {t['failures']}"
        assert t["failed"] == 0
        assert t["exported_file"] is not None and Path(t["exported_file"]).stat().st_size > 200
        # Guard against backends returning a raw str being iterated char-by-char
        for item in t["rules"]:
            assert len(item["query"].splitlines()) < 30, f"{full_key}/{item['file']} query looks malformed"

    # Strict Windows endpoint schema targets (>=6 Windows process/network rules)
    for ep_key in ("kusto_mde_xdr", "kusto_sentinel_asim", "sentinelone_s1ql"):
        t = by_key[ep_key]
        assert t["applicable"] >= 6
        assert t["compiled"] == t["applicable"], f"{ep_key} failures: {t['failures']}"
        assert t["failed"] == 0
        assert t["exported_file"] is not None and Path(t["exported_file"]).stat().st_size > 100


def test_bushidotoken_self_proclaimed_authorized_uas_detected_by_engine_and_sigma(tmp_path: Path) -> None:
    events = [
        {
            "timestamp": "2026-11-20T20:00:01.000Z",
            "source_host": "198.51.100.210",
            "actor": "198.51.100.210",
            "event_type": "http",
            "surface": "web_portal",
            "http_method": "GET",
            "http_path": "/api/v1/status",
            "user_agent": "LLMLeak-RedTeam/1.0 (authorised-scan)",
            "status_code": 200,
        },
        {
            "timestamp": "2026-11-20T20:00:15.000Z",
            "source_host": "198.51.100.211",
            "actor": "198.51.100.211",
            "event_type": "http",
            "surface": "web_portal",
            "http_method": "GET",
            "http_path": "/.well-known/security.txt",
            "user_agent": "authorized-security-research/1.0 (+vulnerability-disclosure-policy-review)",
            "status_code": 200,
        },
        {
            "timestamp": "2026-11-20T20:00:30.000Z",
            "source_host": "198.51.100.212",
            "actor": "198.51.100.212",
            "event_type": "http",
            "surface": "web_portal",
            "http_method": "GET",
            "http_path": "/robots.txt",
            "user_agent": "authorized-exposure-audit/6",
            "status_code": 200,
        },
    ]
    log_path = tmp_path / "bushidotoken_uas.jsonl"
    log_path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")

    candidates = scan_telemetry_file(log_path)
    assert len(candidates) == 3, f"Expected all 3 BushidoToken UAs flagged individually: {candidates}"
    for cand in candidates:
        assert "agentic_user_agent_burst" in cand.reasons

    rule_doc = yaml.safe_load((RULES_DIR / "artex_unit42_canary_and_spec_targeting.yml").read_text(encoding="utf-8"))
    assert evaluate_sigma_rule_on_events(rule_doc, events) == 3


def test_compiled_siem_packs_pass_real_wire_schema_and_syntax_linter(tmp_path: Path) -> None:
    """Seat 4 regression guard: catch double-quoted KQL fields, quoted int ports,
    uppercase ES|QL .caseless literals, bad S1QL numeric operators, and broken DNS Computer mappings."""
    import re

    report = compile_sigma_directory(RULES_DIR, export_dir=tmp_path)
    assert report["all_ok"] is True
    by_key = {t["key"]: t for t in report["targets"]}

    # 1. KQL packs: no double-quoted identifiers, no bracket-quoted dotted JSON paths,
    #    no quoted string ports on integer columns, and no `=~` on booleans
    for kql_key in ("kusto_generic", "kusto_mde_xdr", "kusto_sentinel_asim"):
        text = Path(by_key[kql_key]["exported_file"]).read_text(encoding="utf-8")
        assert "''c-uri''" not in text, f"{kql_key} emitted double-quoted field"
        assert "''" not in text, f"{kql_key} emitted double-quoted identifier"
        assert "['requestParameters." not in text, f"{kql_key} bracket-quoted nested JSON path"
        assert "['status.errorCode']" not in text, f"{kql_key} bracket-quoted nested JSON path"
        assert "['debugContext." not in text, f"{kql_key} bracket-quoted nested JSON path"
        assert 'in~ ("8787"' not in text, f"{kql_key} emitted quoted string ports on integer column"
        assert 'in~ ("7000215"' not in text, f"{kql_key} emitted quoted string Entra errorCode"
        assert "=~ true" not in text and "=~ false" not in text, f"{kql_key} used string operator =~ on bool"
        if kql_key == "kusto_generic":
            assert "requestParameters.withDecryption == true" in text
            assert "status.errorCode in (7000215, 7000222, 500121)" in text
        if kql_key in ("kusto_mde_xdr", "kusto_sentinel_asim"):
            assert "in (8787, 8788, 8790, 8890)" in text, f"{kql_key} missing unquoted integer port list"

    # 2. Elastic ES|QL pack: every *.caseless like/in literal must be all-lowercase,
    #    ECS keyword fields (event.code, azure.signinlogs.result_type) must use quoted strings,
    #    and DNS ComputerName must map to ECS winlog.computer_name/host.name (never winlog.event_data.Computer)
    esql_text = Path(by_key["esql_ecs"]["exported_file"]).read_text(encoding="utf-8")
    assert "winlog.event_data.Computer" not in esql_text
    assert "winlog.computer_name" in esql_text or "host.name" in esql_text
    assert 'event.code in ("113015", "716039")' in esql_text
    assert 'azure.signinlogs.result_type in ("7000215", "7000222", "500121")' in esql_text
    for match in re.finditer(r'\b[\w.]+\.caseless\s+like\s+"([^"]+)"', esql_text):
        lit = match.group(1)
        assert lit == lit.lower(), f"ES|QL .caseless literal contains uppercase chars: {lit!r}"
    for match in re.finditer(r"\b[\w.]+\.caseless\s+in\s*\(([^)]+)\)", esql_text):
        lit_list = match.group(1)
        assert lit_list == lit_list.lower(), f"ES|QL .caseless in(...) contains uppercase chars: {lit_list!r}"
    # Lucene/ES|QL RLIKE uses Apache Lucene DFA (no PCRE `(?:`, `^`, `$` anchors, or empty `(|` alternation)
    for match in re.finditer(r'\brlike\s+"([^"]+)"', esql_text):
        pat = match.group(1)
        assert "(?:" not in pat and "^" not in pat and "$" not in pat and "(|" not in pat, (
            f"Invalid Lucene ES|QL rlike regex: {pat!r}"
        )

    lucene_text = Path(by_key["lucene_ecs"]["exported_file"]).read_text(encoding="utf-8")
    for match in re.finditer(r":/((?:[^/\\]|\\.)+)/", lucene_text):
        pat = match.group(1)
        assert "(?:" not in pat and "^" not in pat and "$" not in pat and "(|" not in pat, (
            f"Invalid Lucene regex: {pat!r}"
        )

    cql_text = Path(by_key["crowdstrike_logscale"]["exported_file"]).read_text(encoding="utf-8")
    assert "=//" not in cql_text, "Unescaped leading '/' in LogScale regex emits '//' single-line comment!"

    # 3. SentinelOne S1QL: numeric port list must use exact `In`, and single numeric port must use exact `=`
    s1_text = Path(by_key["sentinelone_s1ql"]["exported_file"]).read_text(encoding="utf-8")
    assert "In Contains AnyCase (8787" not in s1_text
    assert "DstPort In (8787,8788,8790,8890)" in s1_text

    from sigma.collection import SigmaCollection
    from artex_defense.sigma_compiler import HardenedSentinelOneBackend

    single_port_rule = SigmaCollection.from_yaml(
        "title: Single Port Test\nstatus: experimental\nlogsource:\n  category: network_connection\n  product: windows\n"
        "detection:\n  sel:\n    DstPort: 8787\n  condition: sel\n"
    )
    single_s1ql = HardenedSentinelOneBackend().convert(single_port_rule)[0]
    assert "DstPort = 8787" in single_s1ql
    assert "Contains AnyCase" not in single_s1ql

    # 4. Splunk SPL: web/proxy fields mapped to CIM AND Linux process_creation mapped to CIM Endpoint.Processes
    spl_text = Path(by_key["splunk_spl"]["exported_file"]).read_text(encoding="utf-8")
    assert '"c-uri"' not in spl_text
    assert "uri_path IN " in spl_text or "uri_path=" in spl_text
    linux_spl_item = next(
        r for r in by_key["splunk_spl"]["rules"] if r["file"] == "artex_linux_staging_compiler_and_proxychains_pivot.yml"
    )
    assert "process_path IN " in linux_spl_item["query"]
    assert "parent_process_path IN " in linux_spl_item["query"]
    assert "process IN " in linux_spl_item["query"]
    assert "Image IN " not in linux_spl_item["query"]
    assert "ParentImage IN " not in linux_spl_item["query"]
    assert "CommandLine IN " not in linux_spl_item["query"]


def test_sigma_rules_match_unmodified_raw_vendor_json_without_parser() -> None:
    """Seat 4 real-wire test: raw AWS CloudTrail, Okta, and Entra ID JSON must match
    Sigma YAML rules directly with zero parser pre-normalization."""
    # Raw unmodified AWS CloudTrail JSON (FilterLogEvents secret search + DryRun + CyberStrikeAI userData/SSM)
    raw_cloudtrail = [
        {
            "eventVersion": "1.09",
            "eventSource": "logs.amazonaws.com",
            "eventName": "FilterLogEvents",
            "requestParameters": {"filterPattern": "password OR AKIA"},
        },
        {
            "eventVersion": "1.09",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "RunInstances",
            "errorCode": "Client.DryRunOperation",
        },
        {
            "eventVersion": "1.09",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstanceAttribute",
            "userIdentity": {"arn": "arn:aws:sts::111122223333:assumed-role/WebRole/i-0123456789abcdef0"},
            "requestParameters": {"attribute": "userData", "instanceId": "i-0123456789abcdef0"},
        },
        {
            "eventVersion": "1.09",
            "eventSource": "ssm.amazonaws.com",
            "eventName": "GetParametersByPath",
            "requestParameters": {"path": "/prod/", "withDecryption": True},
        },
        {
            "eventVersion": "1.09",
            "eventSource": "ssm.amazonaws.com",
            "eventName": "SendCommand",
            "requestParameters": {"documentName": "AWS-RunShellScript"},
        },
    ]
    cw_rule = yaml.safe_load((RULES_DIR / "artex_aws_cloudwatch_and_dryrun_sweep.yml").read_text(encoding="utf-8"))
    cs_rule = yaml.safe_load(
        (RULES_DIR / "artex_aws_cyberstrikeai_userdata_ssm_and_ec2_role.yml").read_text(encoding="utf-8")
    )
    assert evaluate_sigma_rule_on_events(cw_rule, raw_cloudtrail) == 2
    assert evaluate_sigma_rule_on_events(cs_rule, raw_cloudtrail) == 3

    # Raw unmodified Okta System Log JSON
    raw_okta = [
        {
            "eventType": "user.mfa.okta_verify.deny_push",
            "outcome": {"result": "FAILURE", "reason": "VERIFICATION_ERROR"},
            "debugContext": {"debugData": {"requestUri": "/api/v1/authn/factors/verify"}},
        },
        {
            "eventType": "user.session.start",
            "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
            "debugContext": {"debugData": {"requestUri": "/api/v1/authn"}},
        },
    ]
    okta_rule = yaml.safe_load((RULES_DIR / "artex_okta_mfa_fatigue_and_authn_spray.yml").read_text(encoding="utf-8"))
    assert evaluate_sigma_rule_on_events(okta_rule, raw_okta) == 2

    # Raw unmodified Microsoft Entra ID SigninLogs + AuditLogs JSON
    raw_entra = [
        {
            "servicePrincipalName": "sp-backup",
            "status": {"errorCode": 7000215, "failureReason": "Invalid client secret"},
        },
        {
            "operationName": "Add service principal credentials",
            "result": "success",
        },
    ]
    entra_rule = yaml.safe_load(
        (RULES_DIR / "artex_entra_sp_secret_abuse_and_mfa_tampering.yml").read_text(encoding="utf-8")
    )
    assert evaluate_sigma_rule_on_events(entra_rule, raw_entra) == 2


def test_k8s_privileged_pod_staging_scoped_msedge_dll_and_soap_osexecute_with_zero_fp(tmp_path: Path) -> None:
    """Validate unmodified native audit.k8s.io/v1 Event & EventList, initContainers, signer-scoped msedge.dll, and SOAP OSExecute."""
    # 1. Benign native audit.k8s.io/v1 DaemonSet (kube-proxy, NO inline base64/coercion) + Microsoft-signed msedge.dll -> 0 FP!
    benign_k8s_native = {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "stage": "ResponseComplete",
        "requestReceivedTimestamp": "2026-11-22T22:00:00.000000Z",
        "stageTimestamp": "2026-11-22T22:00:00.100000Z",
        "verb": "create",
        "user": {"username": "system:serviceaccount:kube-system:daemon-set-controller"},
        "sourceIPs": ["10.40.0.5"],
        "userAgent": "kube-controller-manager/v1.31.0",
        "requestURI": "/api/v1/namespaces/kube-system/pods",
        "objectRef": {"resource": "pods", "namespace": "kube-system", "name": "kube-proxy-abc"},
        "responseStatus": {"code": 201},
        "requestObject": {
            "kind": "Pod",
            "metadata": {"name": "kube-proxy-abc"},
            "spec": {
                "hostNetwork": True,
                "containers": [
                    {
                        "name": "kube-proxy",
                        "image": "registry.k8s.io/kube-proxy:v1.31.0",
                        "securityContext": {"privileged": True},
                        "command": ["/usr/local/bin/kube-proxy", "--config=/var/lib/kube-proxy/config.conf"],
                    }
                ],
            },
        },
    }
    benign_msedge = {
        "timestamp": "2026-11-22T22:00:05.000Z",
        "source_host": "win-wks-01",
        "actor": "alice",
        "event_type": "image_load",
        "surface": "endpoint",
        "process": r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\134.0\msedge.dll",
        "ImageLoaded": r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\134.0\msedge.dll",
        "Signed": True,
        "Signature": "Microsoft Corporation",
        "SignatureStatus": "Valid",
    }
    benign_path = tmp_path / "benign_k8s_edge.jsonl"
    benign_path.write_text(json.dumps(benign_k8s_native) + "\n" + json.dumps(benign_msedge) + "\n", encoding="utf-8")
    assert scan_telemetry_file(benign_path) == []

    # 2. TP: Unmodified native `audit.k8s.io/v1` Event JSON (NO synthetic timestamp/actor/source_host!)
    k8s_tp_native = {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "stage": "ResponseComplete",
        "requestReceivedTimestamp": "2026-11-22T22:05:00.000000Z",
        "stageTimestamp": "2026-11-22T22:05:00.120000Z",
        "verb": "create",
        "user": {"username": "ci-deployer"},
        "sourceIPs": ["198.51.100.77"],
        "userAgent": "kubectl/v1.31.0",
        "requestURI": "/api/v1/namespaces/default/pods",
        "objectRef": {"resource": "pods", "namespace": "default", "name": "diag-runner"},
        "responseStatus": {"code": 201},
        "requestObject": {
            "kind": "Pod",
            "metadata": {"name": "diag-runner"},
            "spec": {
                "hostPID": True,
                "hostNetwork": True,
                "volumes": [{"name": "host-root", "hostPath": {"path": "/"}}],
                "containers": [
                    {
                        "name": "runner",
                        "image": "python:3.12-slim",
                        "securityContext": {"privileged": True},
                        "command": ["/bin/sh", "-c"],
                        "args": ["echo ZWNobyB0ZXN0 | base64 -d | sh"],
                    }
                ],
            },
        },
    }
    k8s_path = tmp_path / "k8s_tp_native.jsonl"
    k8s_path.write_text(json.dumps(k8s_tp_native) + "\n", encoding="utf-8")
    k8s_cands = scan_telemetry_file(k8s_path)
    assert k8s_cands and "k8s_privileged_pod_staging" in k8s_cands[0].reasons
    assert k8s_cands[0].alert_tier == "alert"
    assert k8s_cands[0].actor == "ci-deployer" and k8s_cands[0].source_host == "198.51.100.77"

    # 2b. TP: Native `audit.k8s.io/v1` EventList wrapper with privileged `initContainers` bypass test!
    k8s_init_event = {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "requestReceivedTimestamp": "2026-11-22T22:05:30.000000Z",
        "verb": "create",
        "user": {"username": "svc-cicd"},
        "sourceIPs": ["198.51.100.78"],
        "requestURI": "/api/v1/namespaces/prod/pods",
        "objectRef": {"resource": "pods", "namespace": "prod", "name": "init-stage-01"},
        "requestObject": {
            "kind": "Pod",
            "metadata": {"name": "init-stage-01"},
            "spec": {
                "initContainers": [
                    {
                        "name": "bootstrap",
                        "image": "alpine:3.20",
                        "securityContext": {"privileged": True},
                        "command": ["/bin/sh", "-c"],
                        "args": ["echo ZWNobyB0ZXN0 | base64 -d | sh"],
                    }
                ],
                "containers": [{"name": "sleep", "image": "alpine:3.20", "command": ["sleep", "3600"]}],
            },
        },
    }
    k8s_list_path = tmp_path / "k8s_eventlist.json"
    k8s_list_path.write_text(
        json.dumps({"apiVersion": "audit.k8s.io/v1", "kind": "EventList", "items": [benign_k8s_native, k8s_init_event]}),
        encoding="utf-8",
    )
    list_cands = scan_telemetry_file(k8s_list_path)
    assert len(list_cands) == 1
    assert "k8s_privileged_pod_staging" in list_cands[0].reasons
    assert list_cands[0].actor == "svc-cicd"

    # 3. TP: Expired non-Microsoft msedge.dll + masqueraded cookie_exporter.exe -> dll_sideload_relocated_binary_with_config
    dll_tp = {
        "timestamp": "2026-11-22T22:06:00.000Z",
        "source_host": "win-srv-02",
        "actor": "svc_deploy",
        "event_type": "image_load",
        "surface": "endpoint",
        "process": r"C:\Users\Public\stage\msedge.dll",
        "ImageLoaded": r"C:\Users\Public\stage\msedge.dll",
        "Signed": True,
        "Signature": "ThirdParty Publisher Inc.",
        "SignatureStatus": "Expired",
    }
    dll_path = tmp_path / "dll_tp.jsonl"
    dll_path.write_text(json.dumps(dll_tp) + "\n", encoding="utf-8")
    dll_cands = scan_telemetry_file(dll_path)
    assert dll_cands and "dll_sideload_relocated_binary_with_config" in dll_cands[0].reasons

    # 4. TP: SOAP OSExecute request envelope (including nested Suricata EVE http.http_request_body) -> web_ssrf_or_upload_webshell
    soap_tp = {
        "timestamp": "2026-11-22T22:07:00.000000+0000",
        "event_type": "http",
        "src_ip": "198.51.100.88",
        "dest_ip": "10.0.0.25",
        "dest_port": 50013,
        "http": {
            "hostname": "sap-app.corp.local",
            "url": "/SAPControl",
            "http_method": "POST",
            "status": 200,
            "http_request_body": "<soapenv:Envelope><soapenv:Body><urn:OSExecute><command>whoami</command></urn:OSExecute></soapenv:Body></soapenv:Envelope>",
        },
    }
    soap_path = tmp_path / "soap_tp.jsonl"
    soap_path.write_text(json.dumps(soap_tp) + "\n", encoding="utf-8")
    soap_cands = scan_telemetry_file(soap_path)
    assert soap_cands and "web_ssrf_or_upload_webshell" in soap_cands[0].reasons

    # 5. Sigma YAML matches raw K8s audit JSON directly (both containers & initContainers; skips benign DaemonSet)
    k8s_rule = yaml.safe_load((RULES_DIR / "artex_k8s_privileged_pod_staging_and_coercion.yml").read_text(encoding="utf-8"))
    assert evaluate_sigma_rule_on_events(k8s_rule, [benign_k8s_native, k8s_tp_native, k8s_init_event]) == 2

    # 6. Gap-closure regressions: K8s chroot host-escape WITHOUT base64, SAPControl GetEnvironment, .htaccess PHP, & K8s SA token read
    gap_events = [
        {
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "requestReceivedTimestamp": "2026-11-22T22:08:00.000000Z",
            "verb": "create",
            "user": {"username": "ops-pivot"},
            "sourceIPs": ["198.51.100.79"],
            "objectRef": {"resource": "pods", "namespace": "default", "name": "chroot-direct"},
            "requestObject": {
                "kind": "Pod",
                "metadata": {"name": "chroot-direct"},
                "spec": {
                    "hostPID": True,
                    "volumes": [{"name": "r", "hostPath": {"path": "/"}}],
                    "containers": [
                        {
                            "name": "esc",
                            "image": "alpine:3.20",
                            "securityContext": {"privileged": True},
                            "command": ["sh", "-c"],
                            "args": ["chroot /host /bin/sh -c 'id'"],
                        }
                    ],
                },
            },
        },
        {
            "timestamp": "2026-11-22T22:08:10.000000+0000",
            "event_type": "http",
            "src_ip": "198.51.100.89",
            "dest_ip": "10.0.0.25",
            "dest_port": 50013,
            "http": {
                "hostname": "sap-app.corp.local",
                "url": "/SAPControl",
                "http_method": "POST",
                "status": 200,
                "http_request_body_printable": "<SOAP-ENV:Envelope><SOAP-ENV:Body><m:GetEnvironment/></SOAP-ENV:Body></SOAP-ENV:Envelope>",
            },
        },
        {
            "timestamp": "2026-11-22T22:08:20.000Z",
            "source_host": "198.51.100.90",
            "actor": "198.51.100.90",
            "event_type": "http",
            "surface": "web_portal",
            "http_method": "POST",
            "http_path": "/sites/default/files/sub/.htaccess",
            "request_body": "php_flag engine on\nSetHandler application/x-httpd-php\n",
            "status_code": 200,
        },
        {
            "timestamp": "2026-11-22T22:08:25.000Z",
            "source_host": "web-pod-01",
            "actor": "www-data",
            "event_type": "process",
            "surface": "endpoint",
            "process": "/bin/sh",
            "command_line": "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
            "status_code": 0,
        },
    ]
    gap_path = tmp_path / "gap_closures.jsonl"
    gap_path.write_text("\n".join(json.dumps(e) for e in gap_events) + "\n", encoding="utf-8")
    gap_cands = scan_telemetry_file(gap_path)
    gap_reasons = {r for c in gap_cands for r in c.reasons}
    assert "k8s_privileged_pod_staging" in gap_reasons
    assert "web_ssrf_or_upload_webshell" in gap_reasons
    assert "config_and_secret_file_harvest_burst" in gap_reasons
    assert evaluate_sigma_rule_on_events(k8s_rule, [gap_events[0]]) == 1

    # 7. Benign enterprise zero-FP regressions for K8s /ca.crt, /namespace, Prometheus, and JSON docs mentioning .htaccess
    benign_gap_fps = [
        {
            "timestamp": "2026-11-22T22:09:00.000Z",
            "source_host": "app-pod-01",
            "actor": "appuser",
            "event_type": "process",
            "surface": "endpoint",
            "process": "/bin/sh",
            "command_line": "curl --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt https://kubernetes.default.svc/healthz",
            "status_code": 0,
        },
        {
            "timestamp": "2026-11-22T22:09:05.000Z",
            "source_host": "app-pod-02",
            "actor": "appuser",
            "event_type": "process",
            "surface": "endpoint",
            "process": "/bin/sh",
            "command_line": "NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)",
            "status_code": 0,
        },
        {
            "timestamp": "2026-11-22T22:09:10.000Z",
            "source_host": "mon-pod-01",
            "actor": "prometheus",
            "event_type": "process",
            "surface": "endpoint",
            "process": "/bin/prometheus",
            "command_line": "/bin/prometheus --config.file=/etc/prometheus/prometheus.yml --web.ca=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            "status_code": 0,
        },
        {
            "timestamp": "2026-11-22T22:09:15.000Z",
            "source_host": "198.51.100.20",
            "actor": "doc_editor",
            "event_type": "http",
            "surface": "web_portal",
            "http_method": "POST",
            "http_path": "/api/docs/articles",
            "request_body": '{"title":"Legacy Apache Fix","body":"Remove php_flag engine on or SetHandler application/x-httpd-php from .htaccess"}',
            "status_code": 200,
        },
    ]
    benign_gap_path = tmp_path / "benign_gap_fps.jsonl"
    benign_gap_path.write_text("\n".join(json.dumps(e) for e in benign_gap_fps) + "\n", encoding="utf-8")
    assert scan_telemetry_file(benign_gap_path) == []
