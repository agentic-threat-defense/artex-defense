"""Stage 2 local Gemma 4 worker client speaking to localhost Ollama."""

from __future__ import annotations

import json
import os
from typing import Any, Literal
from urllib.parse import urlparse

import httpx

from .sanitizer import fence_untrusted_text
from .schemas import CandidateWindow, IntelExtraction, TriageVerdict

DEFAULT_OLLAMA_URL = os.environ.get("ARTEX_OLLAMA_URL", "http://127.0.0.1:11434")
DEFAULT_OLLAMA_MODEL = os.environ.get("ARTEX_OLLAMA_MODEL", "gemma4-hunter")
LOCALHOST_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})


class GemmaWorkerError(RuntimeError):
    """Raised when the local Ollama / Gemma 4 worker fails or returns invalid output."""


def _validate_ollama_url(url: str) -> str:
    """Enforce localhost-only Ollama connections unless ARTEX_ALLOW_REMOTE_OLLAMA=1 is explicitly set."""
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported Ollama URL scheme '{parsed.scheme}': {url}")
    host = (parsed.hostname or "").lower()
    allow_remote = os.environ.get("ARTEX_ALLOW_REMOTE_OLLAMA", "").strip() == "1"
    if not allow_remote and host not in LOCALHOST_HOSTS:
        raise ValueError(
            f"Refusing non-localhost Ollama URL '{url}'. "
            "Set ARTEX_ALLOW_REMOTE_OLLAMA=1 explicitly if routing to a remote host."
        )
    return url.rstrip("/")


class GemmaWorker:
    """Thin, deterministic client for delegating defensive hunting tasks to local Gemma 4."""

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float = 180.0,
    ) -> None:
        raw_url = base_url or os.environ.get("ARTEX_OLLAMA_URL", DEFAULT_OLLAMA_URL)
        self.base_url = _validate_ollama_url(raw_url)
        self.model = model or os.environ.get("ARTEX_OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
        self.timeout = timeout

    def health_check(self) -> dict[str, Any]:
        """Return Ollama reachability, installed models, and loaded GPU/VRAM status."""
        with httpx.Client(base_url=self.base_url, timeout=15.0) as client:
            tags_resp = client.get("/api/tags")
            tags_resp.raise_for_status()
            ps_resp = client.get("/api/ps")
            ps_resp.raise_for_status()

        installed = [m.get("name") for m in tags_resp.json().get("models", [])]
        running = [
            {
                "name": m.get("name"),
                "size_mb": round(m.get("size", 0) / (1024 * 1024), 1),
                "size_vram_mb": round(m.get("size_vram", 0) / (1024 * 1024), 1),
                "context_length": m.get("context_length"),
            }
            for m in ps_resp.json().get("models", [])
        ]
        return {
            "ollama_url": self.base_url,
            "configured_model": self.model,
            "model_installed": any(
                name == self.model or (name and name.startswith(f"{self.model}:"))
                for name in installed
            ),
            "installed_models": installed,
            "running_models": running,
        }

    def _chat(
        self,
        user_prompt: str,
        *,
        system_prompt: str | None = None,
        json_schema: dict[str, Any] | None = None,
        temperature: float = 0.2,
    ) -> str:
        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if json_schema is not None:
            payload["format"] = json_schema

        try:
            with httpx.Client(base_url=self.base_url, timeout=self.timeout) as client:
                resp = client.post("/api/chat", json=payload)
                resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise GemmaWorkerError(f"Ollama request failed ({self.base_url}): {exc}") from exc

        data = resp.json()
        content = data.get("message", {}).get("content", "")
        if not content:
            raise GemmaWorkerError(f"Empty response from Ollama model {self.model!r}")
        return content

    def triage_window(self, window: CandidateWindow) -> TriageVerdict:
        """Ask local Gemma 4 to triage a Stage 1 candidate window into a structured verdict."""
        fenced = fence_untrusted_text(window.model_dump_json(indent=2), label="CANDIDATE_WINDOW")
        prompt = (
            "Analyze this behavioral/artifact telemetry window flagged by deterministic ARTEX "
            "pre-filters. Assess whether it resembles autonomous agentic offensive tooling "
            "(e.g., ARTEX / ScopeWeaver machine-speed loops, automated error-correction retries, "
            "EDR sensor enumeration, anomalous LLM API egress, or IAM bursts) versus benign "
            "automation/administration.\n\n"
            "Requirements for the JSON output:\n"
            "- Always populate `mitre_techniques` with relevant MITRE ATT&CK technique IDs and names (e.g., `T1518.001 - Security Software Discovery`).\n"
            "- Always populate `key_evidence` with concise concrete facts from the window.\n"
            "- Always populate `false_positive_considerations` with realistic benign explanations to rule out.\n"
            "- Always populate `recommended_next_queries` with concrete follow-up hunt pivots.\n\n"
            f"{fenced}"
        )
        raw = self._chat(prompt, json_schema=TriageVerdict.model_json_schema())
        try:
            parsed = json.loads(raw)
            parsed["window_id"] = window.window_id
            return TriageVerdict.model_validate(parsed)
        except Exception as exc:
            raise GemmaWorkerError(f"Failed to parse TriageVerdict JSON: {exc}\nRaw: {raw}") from exc

    def extract_intel(self, text: str, *, source_name: str = "document") -> IntelExtraction:
        """Summarize a threat-intel report and extract defensive IOCs, TTPs, and detection ideas."""
        trimmed = text[:60000]
        fenced = fence_untrusted_text(trimmed, label="THREAT_INTEL_DOCUMENT")
        prompt = (
            f"Extract structured defensive threat intelligence from the following document ({source_name}). "
            "Focus strictly on detection engineering: IOCs, behavioral signatures, MITRE ATT&CK IDs, "
            "practical Sigma/YARA/KQL/Zeek detection ideas, and hardening actions.\n"
            "Requirements for the JSON output:\n"
            "- Always populate `iocs` with concrete ports, User-Agents, paths, filenames, and defanged domains from the document.\n"
            "- Always populate `behavioral_signatures` with specific timing, cadence, and execution-pattern signatures.\n"
            "- Always populate `mitre_techniques`, `detection_ideas`, and `hardening_actions`.\n\n"
            f"{fenced}"
        )
        raw = self._chat(prompt, json_schema=IntelExtraction.model_json_schema())
        try:
            return IntelExtraction.model_validate_json(raw)
        except Exception as exc:
            raise GemmaWorkerError(
                f"Failed to parse IntelExtraction JSON: {exc}\nRaw: {raw}"
            ) from exc

    def draft_rule(
        self,
        finding: dict[str, Any],
        *,
        rule_format: Literal["sigma", "yara", "kql", "zeek"] = "sigma",
    ) -> str:
        """Draft a defensive detection rule from a structured finding."""
        prompt = (
            f"Draft a clean, production-minded defensive {rule_format.upper()} detection rule "
            "based on this validated finding. Include clear metadata, false-positive notes, "
            "and MITRE ATT&CK tags where appropriate. Return only the rule content.\n\n"
            f"Finding JSON:\n{json.dumps(finding, indent=2)}"
        )
        return self._chat(prompt, temperature=0.15)

    def delegate(self, task: str, *, context: str | None = None) -> str:
        """General bounded defensive worker call for bulk text/log/code analysis."""
        if not context:
            return self._chat(task, temperature=0.2)
        fenced = fence_untrusted_text(context[:60000], label="LOCAL_CONTEXT")
        return self._chat(f"{task}\n\n{fenced}", temperature=0.2)
