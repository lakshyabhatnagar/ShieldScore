import json
from types import SimpleNamespace
from unittest.mock import patch

from app.graph.finding_quality import canonicalize_findings, classify_source_context
from app.graph.nodes.osv import _run_osv_sync
from app.graph.nodes.report_generator import _per_framework_scores, _severity_breakdown
from tests.conftest import make_finding, make_mapped_control


def test_duplicate_secret_retains_both_sources_without_double_penalty():
    secret = dict(make_finding(severity="critical"), finding_type="jwt_exposed", line_number=4, secret_hash="sha256-only", confidence=1.0, applicability=1.0)
    other = dict(secret, tool="secrets_pii", rule_id="gitleaks_jwt", sources=["gitleaks"])
    findings = canonicalize_findings([secret, other])
    assert len(findings) == 1
    assert findings[0]["sources"] == ["gitleaks", "semgrep"]
    assert len(findings[0]["evidence"]) == 2
    controls = [make_mapped_control(f) for f in (secret, other)]
    assert _per_framework_scores(controls)["soc2"] == 80
    assert _severity_breakdown(controls)["critical"] == 1


def test_same_rule_separate_locations_and_different_secrets_remain_distinct():
    original = dict(make_finding(), line_number=4)
    assert len(canonicalize_findings([original, dict(original, line_number=8)])) == 2
    original.update(finding_type="jwt_exposed", secret_hash="first")
    assert len(canonicalize_findings([original, dict(original, secret_hash="second")])) == 2


def test_same_pii_line_distinct_values_remain_distinct():
    original = dict(make_finding("pii_email_address"), line_number=4, match_hash="first")
    assert len(canonicalize_findings([original, dict(original, match_hash="second")])) == 2


def test_quality_reduces_penalty_without_hiding_findings():
    original = dict(make_finding(severity="critical"), confidence=0.35, applicability=0.25)
    controls = [make_mapped_control(original)]
    assert _severity_breakdown(controls)["critical"] == 1
    assert _per_framework_scores(controls)["soc2"] == 98
    serious = [make_mapped_control(dict(make_finding(f"critical-{i}", "critical"), line_number=i+1, confidence=1, applicability=1)) for i in range(5)]
    assert _per_framework_scores(serious)["soc2"] == 0


def test_context_test_names_docs_and_inline_rust():
    assert classify_source_context("electron/authFlowRelay.test.ts") == "test"
    assert classify_source_context("README.md") == "documentation"
    content = '#[tokio::test]\nasync fn check() {\n let password = "secret";\n}\nfn production() {\n'
    assert classify_source_context("src/net.rs", content, 3) == "test"
    assert classify_source_context("src/net.rs", content, 5) == "production"


def test_osv_keeps_versions_aliases_advisories_and_dependency_scope():
    advisory = {"id": "GHSA-first", "aliases": ["CVE-2026-1234"], "summary": "Vulnerable package", "severity": [{"score": "HIGH"}]}
    pkg = {"package": {"name": "package", "version": "1.0", "ecosystem": "npm"}, "dependency_groups": ["dev"], "is_direct": True, "vulnerabilities": [advisory, advisory, dict(advisory, id="CVE-2026-1234"), {"id": "CVE-2026-9999", "summary": "Second advisory"}]}
    data = {"results": [{"source": {"path": "package-lock.json"}, "packages": [pkg, dict(pkg, package=dict(pkg["package"], version="2.0"))]}]}
    with patch("app.graph.nodes.osv.shutil.which", return_value="osv-scanner"), patch("app.graph.nodes.osv.subprocess.run", return_value=SimpleNamespace(stdout=json.dumps(data).encode(), stderr=b"", returncode=1)):
        findings = _run_osv_sync("/repo")
    assert len(findings) == 2
    assert all(len(f["advisories"]) == 2 for f in findings)
    assert findings[0]["advisories"][0]["aliases"] == ["CVE-2026-1234", "GHSA-first"]
    assert findings[0]["dependency_scope"] == "development"
    assert findings[0]["direct_dependency"] is True
    duplicate = dict(findings[0], description="Other manifest repeats same vulnerability")
    controls = [make_mapped_control(f) for f in (findings[0], duplicate)]
    assert _per_framework_scores(controls)["soc2"] == 96


def test_osv_duplicate_severity_is_order_independent():
    critical = {"id": "GHSA-same", "severity": [{"score": "CRITICAL"}], "aliases": ["CVE-2026-1234"]}
    low = {"id": "GHSA-same", "severity": [{"score": "LOW"}]}
    def scan(vulnerabilities):
        data = {"results": [{"packages": [{"package": {"name": "x", "version": "1"}, "vulnerabilities": vulnerabilities}]}]}
        with patch("app.graph.nodes.osv.shutil.which", return_value="osv-scanner"), patch("app.graph.nodes.osv.subprocess.run", return_value=SimpleNamespace(stdout=json.dumps(data).encode(), stderr=b"", returncode=1)):
            return _run_osv_sync("/repo")
    assert scan([critical, low]) == scan([low, critical])
    finding = scan([critical, low])[0]
    assert finding["severity"] == "critical"
    assert len(finding["advisories"]) == 1


def test_framework_specific_relevance_reduces_only_that_framework_penalty():
    f = dict(make_finding(severity="critical"), confidence=1.0, applicability=1.0)
    soc2 = make_mapped_control(f)
    gdpr = dict(make_mapped_control(f, framework="gdpr"), confidence=0.6, applicability=0.5)
    scores = _per_framework_scores([soc2, gdpr])
    assert scores["soc2"] == 80
    assert scores["gdpr"] == 94
