import asyncio
import json
import logging
import shutil
import subprocess

from app.graph.state import AuditState, Finding

logger = logging.getLogger(__name__)


def _run_osv_sync(repo_path: str) -> list[Finding]:
    """Run osv-scanner synchronously in a thread."""
    osv_path = shutil.which("osv-scanner")
    if not osv_path:
        raise RuntimeError("osv-scanner is not installed or not on PATH")

    result = subprocess.run(
        [osv_path, "--format", "json", repo_path],
        capture_output=True,
        timeout=300,
    )

    stdout_str = (result.stdout.decode(errors="replace") if result.stdout else "").strip()
    stderr_str = (result.stderr.decode(errors="replace") if result.stderr else "").strip()

    # osv-scanner exits non-zero when it finds vulnerabilities.
    # If we got JSON on stdout, proceed — it found stuff.
    if not stdout_str:
        raise RuntimeError(
            stderr_str or f"osv-scanner exited with code {result.returncode} (no output)"
        )

    data = json.loads(stdout_str)

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    packages: dict[tuple, dict] = {}
    for scan_result in data.get("results", []):
        for pkg in scan_result.get("packages", []):
            package = pkg.get("package") or {}
            key = (package.get("ecosystem", ""), package.get("name", "unknown"), package.get("version", ""))
            info = packages.setdefault(key, {"advisories": {}, "paths": set(), "scopes": set(), "direct": set()})
            source_path = (scan_result.get("source") or {}).get("path")
            if source_path:
                info["paths"].add(source_path)
            groups = pkg.get("dependency_groups") or []
            info["scopes"].update(str(g).lower() for g in groups)
            if isinstance(pkg.get("is_direct"), bool):
                info["direct"].add(pkg["is_direct"])
            for vuln in pkg.get("vulnerabilities", []):
                if vuln.get("id"):
                    info["advisories"].setdefault(vuln["id"], []).append(vuln)

    findings: list[Finding] = []
    for (ecosystem, name, version), info in packages.items():
        # Alias-connected records are one advisory, including GHSA/CVE duplicates.
        records: list[dict] = []
        vulnerabilities = [v for group in info["advisories"].values() for v in group]
        for vuln in sorted(vulnerabilities, key=lambda v: (v["id"], _severity(v))):
            ids = {vuln["id"], *vuln.get("aliases", [])}
            matches = [r for r in records if ids & set(r["aliases"])]
            severity = _severity(vuln)
            summaries = [vuln.get("summary") or vuln.get("details") or vuln["id"]]
            for record in matches:
                ids.update(record["aliases"])
                summaries.extend(record["summaries"])
                if severity_rank[record["severity"]] > severity_rank[severity]:
                    severity = record["severity"]
                records.remove(record)
            records.append({"id": min(ids), "aliases": sorted(ids), "severity": severity, "summaries": sorted(set(summaries))})
        if not records:
            continue
        records.sort(key=lambda r: r["id"])
        severity = max((r["severity"] for r in records), key=severity_rank.get)
        dev_only = bool(info["scopes"]) and info["scopes"] <= {"dev", "development", "test", "build"}
        findings.append({
            "tool": "osv",
            "severity": severity,
            "raw_severity": severity,
            "title": records[0]["id"] if len(records) == 1 else f"{name}: {len(records)} known vulnerabilities",
            "description": f"{name}@{version}: " + "; ".join(f"{r['id']}: {'; '.join(r['summaries'])}" for r in records),
            "file_path": None,
            "rule_id": records[0]["id"] if len(records) == 1 else f"osv_{name}",
            "package": name,
            "package_version": version,
            "ecosystem": ecosystem,
            "advisories": records,
            "dependency_scope": "development" if dev_only else "runtime" if "runtime" in info["scopes"] else "unknown",
            "direct_dependency": True if True in info["direct"] else False if info["direct"] else None,
            "manifest_paths": sorted(info["paths"]),
            "confidence": 1.0,
            "applicability": 0.4 if dev_only else 0.75,
            "quality_reason": "Known advisory; runtime reachability is not established by OSV.",
            "personal_data_relevance": "unknown",
            "sources": ["osv"],
        })

    if result.returncode != 0 and stderr_str:
        logger.info(
            "osv-scanner exited %d with stderr (expected): %s",
            result.returncode,
            stderr_str[:200],
        )

    return findings


async def run_osv(state: AuditState) -> dict:
    if state.get("error"):
        return {}

    repo_path = state.get("local_path")
    if not repo_path:
        return {"osv_findings": []}

    try:
        findings = await asyncio.to_thread(_run_osv_sync, repo_path)
        logger.info("OSV found %d findings", len(findings))
        return {"osv_findings": findings}
    except Exception as exc:
        err_text = str(exc) or "Unknown error"
        logger.error("OSV scan failed: %s", err_text)
        return {"osv_findings": []}


def _severity(vuln: dict) -> str:
    severities = vuln.get("severity") or []
    if not severities:
        return "medium"

    score = severities[0].get("score")
    if score is None:
        return "medium"

    score_text = str(score).lower()
    for label in ("critical", "high", "medium", "low"):
        if label in score_text:
            return label

    try:
        numeric_score = float(score_text.split("/")[0])
    except ValueError:
        return "medium"

    if numeric_score >= 9:
        return "critical"
    if numeric_score >= 7:
        return "high"
    if numeric_score >= 4:
        return "medium"
    return "low"
