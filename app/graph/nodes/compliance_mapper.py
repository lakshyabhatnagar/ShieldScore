import logging
import re

from app.graph.state import AuditState, Finding, MappedControl

from app.mapper.controls import (
    GDPR_DPDP_EXCLUDED_TYPES,
    REMEDIATION_MAP,
    _classify_finding_type,
    batch_map_findings_soc2_iso,
    get_controls,
)
from app.mapper.rag_mapper import enrich_gdpr_dpdp_explanations
from app.graph.finding_quality import canonicalize_findings, SECRET_TYPES

logger = logging.getLogger(__name__)

# Privacy applicability requires repository evidence, not vulnerability keywords alone.
DIRECT_PERSONAL_DATA_TYPES = {"pii_in_source", "pii_field_unencrypted", "sensitive_category_data_detected"}
BACKEND_PRIVACY_TYPES = {
    "sql_injection", "sql_injection_format", "ldap_injection", "broken_authz",
    "missing_authn", "sensitive_data_logged", "path_traversal", "file_inclusion",
    "ssrf", "unsafe_deserialization", "weak_cipher", "weak_hash", "tls_disabled",
    "hardcoded_crypto_key", "crypto_misuse", "cookie_missing_secure", "plaintext_http",
}


def _personal_data_relevance(finding: Finding, has_personal_schema: bool = False) -> str:
    rule_id = finding.get("rule_id") or ""
    finding_type = _classify_finding_type(rule_id, finding.get("description", ""), finding.get("finding_type"))
    if finding.get("tool") in {"github", "governance", "sbom", "cicd"} or finding_type in GDPR_DPDP_EXCLUDED_TYPES:
        return "none"
    if finding_type in DIRECT_PERSONAL_DATA_TYPES:
        return "confirmed"
    # Explicit scanner evidence can establish a connection; an LLM subtype cannot.
    if finding.get("personal_data_relevance") in {"confirmed", "likely", "none"}:
        return finding["personal_data_relevance"]
    path = (finding.get("file_path") or "").replace("\\", "/").lower()
    backend = any(part in {"api", "backend", "server", "controllers", "models", "routes", "services"} for part in path.split("/"))
    if has_personal_schema and finding_type in SECRET_TYPES and finding.get("severity") in {"critical", "high"}:
        if backend or path.rsplit("/", 1)[-1].startswith(".env"):
            return "likely"
    if has_personal_schema and backend and finding_type in BACKEND_PRIVACY_TYPES and finding.get("tool") != "osv":
        return "likely"
    return "unknown"


def _curated_gdpr_dpdp(findings: list[Finding]) -> list[MappedControl]:
    """Map privacy controls only when scanner evidence connects a finding to personal data."""
    has_personal_schema = any(
        f.get("tool") == "data_classification" and f.get("finding_type") in DIRECT_PERSONAL_DATA_TYPES
        for f in findings
    )
    mapped: list[MappedControl] = []
    for finding in findings:
        relevance = _personal_data_relevance(finding, has_personal_schema)
        finding["personal_data_relevance"] = relevance
        if relevance not in {"confirmed", "likely"}:
            continue
        controls = get_controls(finding.get("rule_id") or "", finding.get("description", ""), finding.get("finding_type"))
        for control in controls:
            if control["framework"] not in {"gdpr", "dpdp"}:
                continue
            mapped.append({
                "finding": finding,
                **control,
                "explanation": (
                    f"This finding has {relevance} relevance to personal data and warrants review "
                    f"against {control['control_name']}. Applicability and any violation require contextual assessment."
                ),
                "confidence": min(float(finding.get("confidence", 0.9)), 0.9 if relevance == "confirmed" else 0.6),
                "applicability": min(float(finding.get("applicability", 1.0)), 1.0 if relevance == "confirmed" else 0.5),
                "personal_data_relevance": relevance,
                "sources": [f"control_map:{control['control_id']}", f"scanner:{finding.get('tool', 'unknown')}"],
            })
    return mapped


async def _preclassify_cve_findings(findings: list[Finding]) -> None:
    """Use deterministic subtype hints; model text cannot decide privacy applicability."""
    for finding in findings:
        if finding.get("tool") == "osv":
            finding["finding_type"] = _classify_finding_type(
                finding.get("rule_id") or "", finding.get("description", "")
            )


async def run_compliance_mapper(state: AuditState) -> dict:
    if state.get("error"):
        return {}

    try:
        # Collect and validate all findings from scanner nodes
        raw_findings = []
        findings_sources = [
            ("semgrep", *state.get("semgrep_findings", [])),
            ("osv", *state.get("osv_findings", [])),
            ("github", *state.get("github_findings", [])),
            ("secrets", *state.get("secrets_findings", [])),
            ("governance", *state.get("governance_findings", [])),
            ("sbom", *state.get("sbom_findings", [])),
            ("iac", *state.get("iac_findings", [])),
            ("cicd", *state.get("cicd_findings", [])),
            ("data_class", *state.get("data_classification_findings", [])),
        ]
        for source, *items in findings_sources:
            for item in items:
                if not isinstance(item, dict):
                    logger.warning("Mapper: %s finding is not a dict: %s (type=%s)",
                                   source, item, type(item).__name__)
                    continue
                raw_findings.append(item)

        # Strip local temp path prefix from all file_path values
        local_path = state.get("local_path") or ""
        _strip_path_prefix(raw_findings, local_path)

        deduplicated_findings = await _deduplicate_by_rule_id(raw_findings)

        # Classify dependencies without sending repository evidence to a model.
        await _preclassify_cve_findings(deduplicated_findings)
        logger.info("Step 0 done: %d deduplicated findings", len(deduplicated_findings))

        # Step 0b: Enrich findings with remediation text from REMEDIATION_MAP.
        # Each finding's remediation is determined by its finding_type (which
        # the classifier sets). Findings not covered by the map get None.
        for f in deduplicated_findings:
            if f.get("remediation"):
                continue
            ftype = f.get("finding_type")
            if not ftype:
                desc = f.get("description", "")
                rid = f.get("rule_id", "")
                ftype = _classify_finding_type(rid, desc, None)
            if ftype in REMEDIATION_MAP:
                f["remediation"] = REMEDIATION_MAP[ftype]

        gdpr_dpdp_mapped = _curated_gdpr_dpdp(deduplicated_findings)
        soc2_iso_mapped = await batch_map_findings_soc2_iso(deduplicated_findings)

        # Log finding types for debugging.
        # The raw finding_type field is the scanner-set value (None for Semgrep/GitHub).
        # The resolved type comes from _classify_finding_type() which runs during mapping.
        for f in deduplicated_findings:
            if not isinstance(f, dict):
                continue
            rid = f.get("rule_id", "")
            raw_type = f.get("finding_type")
            raw_label = raw_type or "unset"
            resolved = _classify_finding_type(rid, f.get("description", ""), raw_type)
            has_gdpr = any(
                isinstance(m, dict) and m.get("finding", {}).get("rule_id") == rid
                and m.get("framework") == "gdpr"
                for m in gdpr_dpdp_mapped
            )
            logger.info("  %s -> raw=%s resolved=%s GDPR=%s", rid, raw_label, resolved, has_gdpr)

        # Step 3: RAG enrichment
        if gdpr_dpdp_mapped:
            try:
                enriched = await enrich_gdpr_dpdp_explanations(
                    gdpr_dpdp_mapped, deduplicated_findings
                )
                if enriched:
                    gdpr_dpdp_mapped = enriched
                    logger.info("Step 3: RAG enriched %d explanations", len(enriched))
            except Exception as exc:
                logger.debug(
                    "RAG enrichment failed, keeping curated explanations: %s", exc
                )

        mapped_controls: list[MappedControl] = [
            *soc2_iso_mapped,
            *gdpr_dpdp_mapped,
        ]

        logger.info("Mapped %d controls total", len(mapped_controls))
        return {"mapped_controls": mapped_controls}
    except Exception as exc:
        logger.error("Compliance mapping failed: %s", exc)
        return {"mapped_controls": [], "error": str(exc)}


def _strip_path_prefix(findings: list[Finding], local_path: str) -> None:
    """Strip local temp path prefix from all finding file_paths in-place.

    Turns 'C:\\Users\\...\\tmpXXXX\\Dockerfile' into 'Dockerfile'
    and 'C:\\Users\\...\\tmpXXXX\\src\\db\\prisma.ts' into 'src/db/prisma.ts'.
    Handles Windows backslashes too.
    """
    if not local_path:
        return
    # Normalize: strip trailing slash, then prepend as prefix to match
    prefix = local_path.rstrip("/\\").replace("\\", "/") + "/"
    for finding in findings:
        fp = finding.get("file_path")
        if not fp or not isinstance(fp, str):
            continue
        normalized = fp.replace("\\", "/")
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]

        # Strip Linux and Windows temp clone prefixes even when local_path was
        # not an exact string match for the scanner output.
        normalized = re.sub(r"^/tmp/tmp[^/]+/", "", normalized)
        normalized = re.sub(r"^.*?[/\\]Temp[/\\]tmp[^/\\]+[/\\]", "", normalized)
        stripped = normalized.lstrip("/")

        if stripped != fp:
            finding["file_path"] = stripped
            logger.debug("Stripped path: %s -> %s", fp, finding["file_path"])


async def _deduplicate_by_rule_id(findings: list[Finding]) -> list[Finding]:
    """Compatibility entry point for occurrence-aware canonicalization."""
    return canonicalize_findings(findings)
