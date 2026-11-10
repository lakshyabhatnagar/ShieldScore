"""Occurrence identity, privacy evidence, and category-specific mapping regressions."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.graph.finding_quality import finding_fingerprint
from app.graph.nodes.compliance_mapper import (
    _curated_gdpr_dpdp,
    _deduplicate_by_rule_id,
    run_compliance_mapper,
)
from app.graph.nodes.scan_data_classification import run_scan_data_classification
from app.mapper.controls import (
    REMEDIATION_MAP,
    _classify_finding_type,
    _resolve_controls,
    batch_map_findings_soc2_iso,
)
from app.mapper.rag_mapper import enrich_gdpr_dpdp_explanations


def finding(rule="python.audit.sqli", **kwargs):
    return {
        "tool": "semgrep", "severity": "high", "rule_id": rule,
        "title": rule, "description": "Potential SQL injection", "file_path": "src/query.py",
        "line_number": 12, **kwargs,
    }


def run(coro):
    return asyncio.run(coro)


@pytest.mark.parametrize("field", ["email", "password", "password_hash", "password_salt", "auth_token", "criminal_record", "sensitive_value"])
def test_authentication_and_non_article9_fields_are_not_special_categories(tmp_path, field):
    (tmp_path / "schema.prisma").write_text(f"model User {{\n {field} String\n}}")
    scanned = run(run_scan_data_classification({"local_path": str(tmp_path)}))
    mapped = _curated_gdpr_dpdp(scanned["data_classification_findings"])
    assert not any(m["control_id"] == "gdpr_article_9" for m in mapped)


@pytest.mark.parametrize("field", ["health_condition", "genetic", "biometric_template", "religion", "sexual_orientation", "political_opinion"])
def test_article9_schema_indicators_get_article9_but_no_dpdp_equivalence(tmp_path, field):
    (tmp_path / "schema.prisma").write_text(f"model Patient {{\n {field} String\n}}")
    scanned = run(run_scan_data_classification({"local_path": str(tmp_path)}))
    mapped = _curated_gdpr_dpdp(scanned["data_classification_findings"])
    assert any(m["control_id"] == "gdpr_article_9" for m in mapped)
    assert not any(m["control_id"] == "dpdp_rule_4" for m in mapped)
    assert all("DPDP Rule 4" not in f["description"] for f in scanned["data_classification_findings"])


def test_generic_findings_do_not_establish_personal_data_processing():
    findings = [
        finding(),
        finding("osv_example", tool="osv", finding_type="dependency_cve_data", description="CVE affects authentication"),
        finding("github_mfa", tool="github"),
        finding("gitleaks_generic-api-key", tool="secrets", finding_type="hardcoded_secret"),
    ]
    assert _curated_gdpr_dpdp(findings) == []
    assert [f["personal_data_relevance"] for f in findings] == ["unknown", "unknown", "none", "unknown"]


def test_schema_evidence_applies_only_to_relevant_backend_findings():
    schema = finding("dc_unencrypted_user", tool="data_classification", finding_type="pii_field_unencrypted")
    backend = finding(file_path="backend/routes/users.py", personal_data_relevance="unknown")
    frontend = finding(file_path="frontend/client.js")
    build_cve = finding("osv_vite", tool="osv", file_path="package-lock.json", finding_type="dependency_cve_data")
    mapped = _curated_gdpr_dpdp([schema, backend, frontend, build_cve])
    assert schema["personal_data_relevance"] == "confirmed"
    assert backend["personal_data_relevance"] == "likely"
    assert frontend["personal_data_relevance"] == build_cve["personal_data_relevance"] == "unknown"
    assert {m["finding"]["file_path"] for m in mapped} == {schema["file_path"], backend["file_path"]}
    assert all(isinstance(m["confidence"], float) and isinstance(m["applicability"], float) for m in mapped)


def test_same_rule_distinct_occurrences_survive_dedup_resolution_and_mapping():
    first = finding(description="first location")
    second = finding(line_number=40, description="second location")
    distinct = run(_deduplicate_by_rule_id([first, second, dict(first)]))
    assert len(distinct) == len(_resolve_controls(distinct)) == 2
    with patch("app.mapper.controls.GROQ_API_KEY", ""):
        mapped = run(batch_map_findings_soc2_iso(distinct))
    assert len(mapped) == 4
    assert {m["finding"]["line_number"] for m in mapped} == {12, 40}


def test_llm_cannot_drop_occurrences_or_change_controls_or_numeric_metadata():
    first, second = finding(confidence=0.7), finding(line_number=40, confidence=0.6)
    response = [{"finding_id": finding_fingerprint(first), "soc2_explanation": "review required",
                 "control_id": "attacker", "confidence": 0, "applicability": 0, "score": 100}]
    with patch("app.mapper.controls.GROQ_API_KEY", "test"), patch("app.mapper.controls.AsyncGroq"), patch(
        "app.mapper.controls._batch_chunk", AsyncMock(return_value=response)
    ):
        mapped = run(batch_map_findings_soc2_iso([first, second]))
    assert len(mapped) == 4
    assert {m["control_id"] for m in mapped} == {"CC6.6", "A.14.2.5"}
    assert {m["confidence"] for m in mapped} == {0.6, 0.7}
    assert all(m["applicability"] == 1 for m in mapped)


def test_mapping_prompts_do_not_contain_source_secrets():
    secret = "example-secret-value-must-never-leave"
    f = finding("hardcoded_secret", description=secret, title=secret)
    batch = AsyncMock(return_value=[])
    with patch("app.mapper.controls.GROQ_API_KEY", "test"), patch("app.mapper.controls.AsyncGroq"), patch(
        "app.mapper.controls._batch_chunk", batch
    ):
        run(batch_map_findings_soc2_iso([f]))
    assert secret not in str(batch.call_args)


@pytest.mark.parametrize("rule, expected", [
    ("python.audit.unknown-sast-rule", "general_security"),
    ("javascript.crypto.gcm-nonce", "crypto_misuse"),
    ("java.audit.unsafe-deserialization", "unsafe_deserialization"),
    ("java.audit.des", "weak_cipher"),
])
def test_remediation_matches_category(rule, expected):
    category = _classify_finding_type(rule)
    assert category == expected
    remediation = REMEDIATION_MAP[category]
    assert "Update the affected package" not in remediation
    if expected != "weak_cipher":
        assert "Replace DES" not in remediation


def test_full_mapper_retains_locations_and_keeps_privacy_unproven():
    with patch("app.mapper.controls.GROQ_API_KEY", ""):
        result = run(run_compliance_mapper({"semgrep_findings": [finding(), finding(line_number=40)]}))
    assert "error" not in result
    assert len(result["mapped_controls"]) == 4
    assert {m["finding"]["line_number"] for m in result["mapped_controls"]} == {12, 40}
    assert all(m["framework"] in {"soc2", "iso27001"} for m in result["mapped_controls"])


def test_rag_changes_only_explanation_and_sources_and_omits_secret():
    f = finding("pii_in_source", description="never-transmit-this-value")
    original = _curated_gdpr_dpdp([f])
    response = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="Review this control."))])
    create = AsyncMock(return_value=response)
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    with patch("app.mapper.rag_mapper._get_supabase", return_value=object()), patch(
        "app.mapper.rag_mapper.GROQ_API_KEY", "test"
    ), patch("app.mapper.rag_mapper.AsyncGroq", return_value=client), patch(
        "app.mapper.rag_mapper._retrieve_control_text", AsyncMock(return_value="Regulation text")
    ):
        enriched = run(enrich_gdpr_dpdp_explanations(original, [f]))
    assert len(enriched) == len(original)
    for before, after in zip(original, enriched):
        assert {k: v for k, v in before.items() if k not in {"explanation", "sources"}} == {
            k: v for k, v in after.items() if k not in {"explanation", "sources"}
        }
    assert "never-transmit-this-value" not in str(create.call_args_list)


def test_recordly_sql_auth_fields_are_not_article9(tmp_path):
    (tmp_path / "users.sql").write_text('''CREATE TABLE videos (
        password_hash TEXT,
        password_salt TEXT
    );
    CREATE TABLE comment_users (
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL
    );''')
    findings = run(run_scan_data_classification({"local_path": str(tmp_path)}))["data_classification_findings"]
    assert not any(f["finding_type"] == "sensitive_category_data_detected" for f in findings)
    assert not any(m["control_id"] == "gdpr_article_9" for m in _curated_gdpr_dpdp(findings))


def test_private_backend_credentials_need_personal_data_evidence_for_privacy():
    credential = finding("gitleaks_jwt", tool="secrets_pii", finding_type="jwt_exposed", severity="critical", file_path=".env.example")
    assert _curated_gdpr_dpdp([dict(credential)]) == []
    schema = finding("dc_sensitive_patient", tool="data_classification", finding_type="sensitive_category_data_detected")
    mapped = _curated_gdpr_dpdp([credential, schema])
    assert credential["personal_data_relevance"] == "likely"
    assert {m["framework"] for m in mapped if m["finding"] is credential} == {"gdpr", "dpdp"}
