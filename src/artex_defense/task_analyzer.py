"""Offline analyzer for sanitized threat-actor staging / agent TaskID JSONL & transcript files.

Designed strictly for defensive detection engineering: parses sanitized TaskID logs
(exported from isolated Tier 3 VM analysis or enterprise threat-intel platforms),
quantifies command sequences, failure-to-retry mutations, and tool distributions, and
produces a compact summary ready for local Gemma 4 rule drafting.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .sanitizer import sanitize_payload

MAX_TASK_FILES = 2000
MAX_TASK_FILE_BYTES = 10 * 1024 * 1024

TASK_ID_LINE_RE = re.compile(
    r"(?:(?:task[_-]?id|taskid|intent[_-]?id|intent)\s*[:=]\s*['\"]?(?P<tid>[A-Za-z0-9_\-]+)|\b(?P<intent>i\d{1,8})\b)",
    re.IGNORECASE,
)
INTENT_FILENAME_RE = re.compile(r"^(i\d{1,8})\b", re.IGNORECASE)
CMD_LINE_RE = re.compile(
    r"(?:cmd|command|exec|tool)\s*[:=]\s*['\"]?(?P<cmd>.+?)(?:['\"]?(?:\s+(?:status|exit|result)=|$))",
    re.IGNORECASE,
)
FAIL_RE = re.compile(r"\b(fail|failed|error|denied|401|403|404|timeout|blocked|rejected)\b", re.IGNORECASE)
SUCCESS_RE = re.compile(r"\b(ok|success|succeeded|200|201|found|extracted|granted)\b", re.IGNORECASE)
TOOL_TOKENS = (
    "nmap",
    "nuclei",
    "curl",
    "impacket",
    "sqlmap",
    "playwright",
    "headlesschrome",
    "webfetch",
    "norma",
    "powershell",
    "cmd.exe",
    "sc query",
    "nltest",
    "aws ",
    "az ",
    "kubectl",
    "gh ",
)


def _extract_task_record(
    record: dict[str, Any], fallback_idx: int, *, file_intent: str | None = None
) -> dict[str, Any]:
    task_id = str(
        record.get("intent_id")
        or record.get("IntentID")
        or record.get("intent")
        or record.get("task_id")
        or record.get("TaskID")
        or record.get("taskId")
        or record.get("id")
        or file_intent
        or f"task-{fallback_idx:04d}"
    )
    command = str(
        record.get("command")
        or record.get("cmd")
        or record.get("input")
        or record.get("tool_input")
        or ""
    )
    tool = str(record.get("tool") or record.get("agent") or record.get("worker") or "")
    status = str(record.get("status") or record.get("outcome") or record.get("result") or "")
    output = str(record.get("output") or record.get("stdout") or record.get("error") or "")
    combined = f"{status} {output}"

    if FAIL_RE.search(combined) and not SUCCESS_RE.search(status):
        normalized_outcome = "failed"
    elif SUCCESS_RE.search(combined) or record.get("exit_code") == 0:
        normalized_outcome = "succeeded"
    else:
        normalized_outcome = "unknown"

    return {
        "task_id": task_id,
        "tool": tool,
        "command": command[:240],
        "outcome": normalized_outcome,
        "snippet": output[:200],
    }


def analyze_task_artifacts(
    target_path: str | Path,
    *,
    sanitize: bool = True,
    max_files: int = MAX_TASK_FILES,
    max_file_bytes: int = MAX_TASK_FILE_BYTES,
) -> dict[str, Any]:
    """Parse a sanitized TaskID JSONL/log file or directory and extract defensive TTP summaries."""
    path = Path(target_path)
    files: list[Path] = []
    if path.is_dir():
        for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
            dirnames.sort()
            cur = Path(dirpath)
            for fname in sorted(filenames):
                fp = cur / fname
                if fp.is_symlink() or not fp.is_file():
                    continue
                files.append(fp)
                if len(files) >= max_files:
                    break
            if len(files) >= max_files:
                break
    elif path.is_file() and not path.is_symlink():
        files = [path]

    tasks: list[dict[str, Any]] = []
    tool_counts: Counter[str] = Counter()
    outcome_counts: Counter[str] = Counter()

    for fpath in files:
        try:
            if fpath.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue
        fn_m = INTENT_FILENAME_RE.match(fpath.stem) or INTENT_FILENAME_RE.match(fpath.parent.name)
        file_intent = fn_m.group(1) if fn_m else None
        text = fpath.read_text(encoding="utf-8", errors="replace")
        for idx, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        entry = _extract_task_record(obj, idx, file_intent=file_intent)
                        tasks.append(entry)
                        continue
                except json.JSONDecodeError:
                    pass

            # Plain-text log fallback
            tid_m = TASK_ID_LINE_RE.search(line)
            if tid_m or file_intent:
                tid = (
                    (tid_m.group("tid") or tid_m.group("intent")) if tid_m else file_intent
                ) or f"task-{idx:04d}"
                cmd_m = CMD_LINE_RE.search(line)
                outcome = "failed" if FAIL_RE.search(line) else ("succeeded" if SUCCESS_RE.search(line) else "unknown")
                tasks.append(
                    {
                        "task_id": tid,
                        "tool": "",
                        "command": cmd_m.group("cmd").strip()[:240] if cmd_m else line[:240],
                        "outcome": outcome,
                        "snippet": line[:200],
                    }
                )

    # Identify failure -> retry/success mutation chains on the same TaskID or adjacent tasks
    retry_chains: list[dict[str, Any]] = []
    by_task: dict[str, list[dict[str, Any]]] = {}
    for t in tasks:
        outcome_counts[t["outcome"]] += 1
        searchable = f"{t['tool']} {t['command']}".lower()
        for tok in TOOL_TOKENS:
            if tok in searchable:
                tool_counts[tok.strip()] += 1
        by_task.setdefault(t["task_id"], []).append(t)

    for tid, entries in by_task.items():
        outcomes = [e["outcome"] for e in entries]
        if "failed" in outcomes and len(entries) >= 2:
            retry_chains.append(
                {
                    "task_id": tid,
                    "attempts": len(entries),
                    "resolved": "succeeded" in outcomes,
                    "sequence": [
                        {"outcome": e["outcome"], "command": e["command"]} for e in entries[:8]
                    ],
                }
            )

    summary = {
        "source": str(path),
        "files_scanned": len(files),
        "total_task_events": len(tasks),
        "unique_task_ids": len(by_task),
        "outcomes": dict(outcome_counts),
        "observed_tools": dict(tool_counts.most_common(15)),
        "retry_mutation_chains": retry_chains[:20],
        "sample_tasks": tasks[:20],
    }
    return sanitize_payload(summary) if sanitize else summary
