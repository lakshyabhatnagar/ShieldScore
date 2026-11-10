import asyncio
import json
import logging
import hashlib
import os
import re
import shutil
import subprocess

from app.graph.state import AuditState, Finding
from app.graph.finding_quality import classify_source_context
from app.graph.secret_context import classify_secret_exposure

logger = logging.getLogger(__name__)

# Semgrep severity levels differ from our 4-tier system.
# https://semgrep.dev/docs/writing-rules/rule-syntax/#severity
SEMGREP_SEVERITY_MAP = {
    "error": "critical",
    "warning": "high",
    "inventory": "low",
    "info": "low",
}


def _map_severity(semgrep_severity: str) -> str:
    """Map semgrep severity to our 4-tier system (critical/high/medium/low)."""
    mapped = SEMGREP_SEVERITY_MAP.get(semgrep_severity.lower())
    if mapped:
        return mapped
    # Fallback: treat anything unrecognized as medium
    return "medium"


def _run_semgrep_sync(repo_path: str) -> list[Finding]:
    """Run semgrep synchronously in a thread."""
    semgrep_path = shutil.which("semgrep")
    if not semgrep_path:
        raise RuntimeError("semgrep is not installed or not on PATH")

    result = subprocess.run(
        [
            semgrep_path,
            "--config",
            "auto",
            "--json",
            "--no-force-color",
            "--exclude",
            ".venv",
            "--exclude",
            "node_modules",
            "--exclude",
            "vendor",
            "--exclude",
            "dist",
            "--exclude",
            "build",
            "--exclude",
            "docs",
            "--exclude",
            "examples",
            "--exclude",
            "scripts",
            "--exclude",
            "docs_src",
            repo_path,
        ],
        capture_output=True,
        timeout=300,
    )

    out = result.stdout.decode(errors="replace") if result.stdout else ""
    err = result.stderr.decode(errors="replace") if result.stderr else ""

    # semgrep exits non-zero when it finds issues.
    # Only treat as real error if stdout is empty.
    if result.returncode != 0 and not out:
        raise RuntimeError(
            err.strip() or out.strip() or f"semgrep exited with code {result.returncode}"
        )

    data = json.loads(out or "{}")
    findings: list[Finding] = []
    for sem_result in data.get("results", []):
        extra = sem_result.get("extra", {})
        raw_severity = extra.get("severity", "warning")
        metadata = extra.get("metadata") or {}
        line = (sem_result.get("start") or {}).get("line", 0)
        column = (sem_result.get("start") or {}).get("col", 0)
        path = sem_result.get("path") or ""
        content = ""
        try:
            full_path = os.path.abspath(os.path.join(repo_path, path))
            if os.path.commonpath([os.path.abspath(repo_path), full_path]) == os.path.abspath(repo_path):
                with open(full_path, encoding="utf-8") as source:
                    content = source.read(1_048_576)
        except (OSError, UnicodeError, ValueError):
            pass
        source_context = classify_source_context(path, content, line)
        confidence = {"HIGH": 1.0, "MEDIUM": 0.75, "LOW": 0.4}.get(str(metadata.get("confidence", "HIGH")).upper(), 1.0)
        observation = "likely_vulnerability"
        if metadata.get("category") in ("best-practice", "maintainability") or "audit" in (metadata.get("subcategory") or []) or re.search(r"(?:manual.*saniti[sz]|unsafe.format|audit)", sem_result["check_id"], re.I):
            confidence = min(confidence, 0.35)
            observation = "hardening_recommendation"
        quality = {
            "raw_severity": raw_severity,
            "line_number": line,
            "column": column,
            "source_context": source_context,
            "confidence": confidence,
            "applicability": 0.25 if source_context != "production" else 1.0,
            "assessment": observation,
            "sources": ["semgrep"],
            "scanner_metadata": {k: metadata[k] for k in ("confidence", "category", "subcategory", "impact", "likelihood", "technology") if k in metadata},
        }
        description = extra.get("message", "")
        rule_id = sem_result["check_id"]
        if re.search(r"(?:jwt|hardcoded|secret|private.key|api.key)", rule_id, re.I):
            description = "Credential candidate detected by Semgrep; matched value redacted."
            lines = content.splitlines()
            source_line = lines[line - 1] if 0 < line <= len(lines) else ""
            assignment = re.search(
                r"[\"']?([A-Za-z_]\w*)[\"']?\s*[:=]\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s,;{}\[\]()\"']+))",
                source_line,
            )
            if assignment:
                name = assignment.group(1)
                value = next(v for v in assignment.groups()[1:] if v is not None)
                exposure = classify_secret_exposure(name, value, rule_id, source_line, source_context)
                if exposure["exposure_classification"] in {"placeholder", "identifier", "false_positive"}:
                    continue
                quality.update(exposure)
                quality["raw_severity"] = raw_severity
                quality["secret_hash"] = hashlib.sha256(value.encode()).hexdigest()
                quality["finding_type"] = "jwt_exposed" if value.startswith("eyJ") else "hardcoded_secret"
                quality["assessment"] = "confirmed_vulnerability" if exposure["secret_class"] == "private_service_token" else "likely_vulnerability"
                quality["column"] = 0
                description = "Credential candidate detected by Semgrep; matched value redacted."
        findings.append(
            {
                "tool": "semgrep",
                "severity": _map_severity(raw_severity),
                "title": sem_result["check_id"],
                "description": description,
                "file_path": sem_result.get("path"),
                "rule_id": sem_result["check_id"],
                **quality,
            }
        )

    return findings


async def run_semgrep(state: AuditState) -> dict:
    if state.get("error"):
        return {}

    repo_path = state.get("local_path")
    if not repo_path:
        return {"semgrep_findings": []}

    try:
        findings = await asyncio.to_thread(_run_semgrep_sync, repo_path)
        logger.info("Semgrep found %d findings", len(findings))
        return {"semgrep_findings": findings}
    except Exception as exc:
        err_text = str(exc) or "Unknown error"
        logger.error("Semgrep scan failed: %s", err_text)
        return {"semgrep_findings": []}
