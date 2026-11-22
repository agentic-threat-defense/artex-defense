"""Automated Precision/Recall evaluation harness and offline Sigma YAML rule validator."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import yaml

from .detectors import correlate_kill_chains, load_events, scan_telemetry_file
from .simulator import generate_synthetic_suite
from .worker import GemmaWorker

# Mapping from Sigma field names to normalized event dictionary keys
SIGMA_FIELD_MAP: dict[str, str] = {
    "DestinationPort": "dest_port",
    "DestinationHostname": "dest_host",
    "QueryName": "dest_host",
    "cs-host": "dest_host",
    "Image": "process",
    "ParentImage": "parent_process",
    "CommandLine": "command_line",
    "cs-uri-stem": "http_path",
    "c-uri": "http_path",
    "cs-user-agent": "user_agent",
    "sc-status": "status_code",
    "Action": "action",
    "Computer": "source_host",
    "ComputerName": "source_host",
    "eventName": "action",
    "eventType": "action",
    "operationName": "action",
    "errorCode": "command_line",
    "userIdentity.arn": "actor",
    "debugContext.debugData.requestUri": "http_path",
}


def _extract_dotted(obj: Any, parts: list[str]) -> list[Any]:
    """Traverse nested dicts and lists of dicts to extract scalar leaf values for a dotted Sigma field."""
    if obj is None:
        return []
    if not parts:
        if isinstance(obj, (str, int, float, bool)):
            return [obj]
        if isinstance(obj, list):
            out: list[Any] = []
            for item in obj:
                if isinstance(item, (str, int, float, bool)):
                    out.append(item)
            return out
        return []

    head, rest = parts[0], parts[1:]
    if isinstance(obj, dict):
        if head in obj:
            return _extract_dotted(obj[head], rest)
        # Also support flat dotted keys stored verbatim in dicts (e.g. {"event.code": "113015"})
        full_key = ".".join(parts)
        if full_key in obj:
            return _extract_dotted(obj[full_key], [])
        return []
    if isinstance(obj, list):
        results: list[Any] = []
        for item in obj:
            results.extend(_extract_dotted(item, parts))
        return results
    return []


def _resolve_field_values(
    event_val: dict[str, Any],
    field: str,
    raw_obj: dict[str, Any] | None = None,
) -> list[Any]:
    parts = field.split(".")

    # 1. Direct lookup on the event (handles raw unmodified CloudTrail/Okta/Entra/GWS JSON)
    direct = _extract_dotted(event_val, parts)
    if direct:
        return direct

    # 2. Nested lookup inside preserved raw_json (handles normalized events from parsers.py)
    parsed_raw = raw_obj
    if parsed_raw is None:
        raw_str = event_val.get("raw_json")
        if isinstance(raw_str, str) and raw_str.startswith("{"):
            try:
                loaded = json.loads(raw_str)
                if isinstance(loaded, dict):
                    parsed_raw = loaded
            except Exception:
                parsed_raw = None
    if isinstance(parsed_raw, dict):
        from_raw = _extract_dotted(parsed_raw, parts)
        if from_raw:
            return from_raw

    # 3. Fallback to normalized event field map
    norm_key = SIGMA_FIELD_MAP.get(field)
    if norm_key is not None:
        val = event_val.get(norm_key)
        if val is not None and val != "":
            return [val]
    return []


def _match_field_condition(
    event_val: dict[str, Any],
    key_spec: str,
    expected: Any,
    raw_obj: dict[str, Any] | None = None,
) -> bool:
    parts = key_spec.split("|")
    field = parts[0]
    modifiers = parts[1:]

    actuals = _resolve_field_values(event_val, field, raw_obj=raw_obj)
    if not actuals:
        return False

    values = expected if isinstance(expected, list) else [expected]
    actual_strs = [str(a).lower() for a in actuals]

    def single_match(v: Any) -> bool:
        v_str = str(v).lower()
        for actual_str in actual_strs:
            if "contains" in modifiers:
                if v_str in actual_str:
                    return True
            elif "startswith" in modifiers:
                if actual_str.startswith(v_str):
                    return True
            elif "endswith" in modifiers:
                if actual_str.endswith(v_str):
                    return True
            else:
                if actual_str == v_str:
                    return True
        return False

    if "all" in modifiers:
        return all(single_match(v) for v in values)
    return any(single_match(v) for v in values)


def _match_selection(
    event: dict[str, Any],
    selection: dict[str, Any],
    raw_obj: dict[str, Any] | None = None,
) -> bool:
    return all(_match_field_condition(event, k, v, raw_obj=raw_obj) for k, v in selection.items())


def evaluate_sigma_rule_on_events(rule_doc: dict[str, Any], events: list[dict[str, Any]]) -> int:
    """Lightweight offline Sigma condition evaluator for unit/regression validation."""
    detection = rule_doc.get("detection", {})
    condition = str(detection.get("condition", "")).strip()
    selections = {k: v for k, v in detection.items() if k != "condition" and isinstance(v, dict)}
    if not selections or not condition:
        return 0

    # Strip trailing "| count()..." aggregation suffixes for event-level matching
    base_cond = condition.split("|")[0].strip()

    hits = 0
    for ev in events:
        raw_obj: dict[str, Any] | None = None
        raw_str = ev.get("raw_json")
        if isinstance(raw_str, str) and raw_str.startswith("{"):
            try:
                loaded = json.loads(raw_str)
                if isinstance(loaded, dict):
                    raw_obj = loaded
            except Exception:
                raw_obj = None

        results = {name: _match_selection(ev, sel, raw_obj=raw_obj) for name, sel in selections.items()}
        # Handle common Sigma boolean expressions cleanly
        expr = base_cond
        if "1 of selection*" in expr:
            any_sel = any(v for k, v in results.items() if k.startswith("selection"))
            expr = expr.replace("1 of selection*", str(any_sel))
        if "all of selection*" in expr:
            all_sel = all(v for k, v in results.items() if k.startswith("selection"))
            expr = expr.replace("all of selection*", str(all_sel))
        for name in sorted(results.keys(), key=len, reverse=True):
            expr = expr.replace(name, str(results[name]))
        try:
            if bool(eval(expr, {"__builtins__": {}}, {})):  # noqa: S307
                hits += 1
        except Exception:
            continue
    return hits


def validate_sigma_directory(rules_dir: str | Path) -> list[dict[str, Any]]:
    """Lint all Sigma YAML rules in a directory for required metadata and detection blocks."""
    results: list[dict[str, Any]] = []
    for path in sorted(Path(rules_dir).glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        errors: list[str] = []
        for req in ("title", "id", "status", "logsource", "detection"):
            if req not in doc or not doc[req]:
                errors.append(f"missing {req}")
        if "detection" in doc and "condition" not in doc["detection"]:
            errors.append("detection missing condition")
        results.append(
            {
                "file": path.name,
                "title": doc.get("title", ""),
                "valid": not errors,
                "errors": errors,
                "doc": doc,
            }
        )
    return results


def run_evaluation(
    *,
    rules_dir: str | Path | None = None,
    work_dir: str | Path | None = None,
    with_gemma4: bool = False,
    model: str | None = None,
) -> dict[str, Any]:
    """Run the full synthetic benign + attack-pattern Precision/Recall evaluation suite."""
    cleanup_dir = None
    if work_dir is None:
        cleanup_dir = tempfile.TemporaryDirectory(prefix="artex_eval_")
        target_dir = Path(cleanup_dir.name)
    else:
        target_dir = Path(work_dir)

    try:
        manifest = generate_synthetic_suite(target_dir)

        tp = fp = tn = fn = 0
        scenario_results: list[dict[str, Any]] = []
        all_baseline_events: list[dict[str, Any]] = []
        all_attack_events: list[dict[str, Any]] = []
        worker = GemmaWorker(model=model) if with_gemma4 else None

        for name, meta in manifest.items():
            path = Path(meta["path"])
            expected_pos = bool(meta["expected_positive"])
            candidates = scan_telemetry_file(path)
            storylines = correlate_kill_chains(candidates)
            detected = len(candidates) > 0

            raw_events = load_events(path)
            if expected_pos:
                all_attack_events.extend(raw_events)
            else:
                all_baseline_events.extend(raw_events)

            if expected_pos and detected:
                tp += 1
                outcome = "TP"
            elif expected_pos and not detected:
                fn += 1
                outcome = "FN"
            elif not expected_pos and detected:
                fp += 1
                outcome = "FP"
            else:
                tn += 1
                outcome = "TN"

            observed_reasons = sorted({r for c in candidates for r in c.reasons})
            missing_expected = [
                r for r in meta.get("expected_reasons", []) if r not in observed_reasons
            ]
            kill_chain_ok = (not meta.get("expect_kill_chain")) or (len(storylines) >= 1)

            gemma_verdict = None
            if worker is not None and candidates:
                verdict = worker.triage_window(candidates[0])
                gemma_verdict = {
                    "severity": verdict.severity,
                    "likelihood_agentic": verdict.likelihood_agentic,
                    "mitre_count": len(verdict.mitre_techniques),
                }

            scenario_results.append(
                {
                    "dataset": name,
                    "expected_positive": expected_pos,
                    "detected": detected,
                    "outcome": outcome,
                    "candidate_count": len(candidates),
                    "storyline_count": len(storylines),
                    "kill_chain_ok": kill_chain_ok,
                    "observed_reasons": observed_reasons,
                    "missing_expected_reasons": missing_expected,
                    "gemma4_verdict": gemma_verdict,
                }
            )

        precision = round(tp / (tp + fp), 4) if (tp + fp) else 1.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) else 1.0

        sigma_summary: list[dict[str, Any]] = []
        if rules_dir is not None and Path(rules_dir).exists():
            for rule_info in validate_sigma_directory(rules_dir):
                doc = rule_info["doc"]
                attack_hits = evaluate_sigma_rule_on_events(doc, all_attack_events)
                baseline_hits = evaluate_sigma_rule_on_events(doc, all_baseline_events)
                sigma_summary.append(
                    {
                        "file": rule_info["file"],
                        "title": rule_info["title"],
                        "valid": rule_info["valid"],
                        "errors": rule_info["errors"],
                        "synthetic_attack_hits": attack_hits,
                        "synthetic_baseline_fp_hits": baseline_hits,
                    }
                )

        return {
            "metrics": {
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "precision": precision,
                "recall": recall,
            },
            "scenarios": scenario_results,
            "sigma_rules": sigma_summary,
        }
    finally:
        if cleanup_dir is not None:
            cleanup_dir.cleanup()
