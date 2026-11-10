"""Tests for semgrep severity mapping."""

from app.graph.nodes.semgrep import _map_severity


class TestMapSeverity:
    def test_error_maps_to_critical(self):
        assert _map_severity("error") == "critical"

    def test_warning_maps_to_high(self):
        assert _map_severity("warning") == "high"

    def test_inventory_maps_to_low(self):
        assert _map_severity("inventory") == "low"

    def test_info_maps_to_low(self):
        assert _map_severity("info") == "low"

    def test_unknown_severity_maps_to_medium(self):
        assert _map_severity("none") == "medium"

    def test_case_insensitive(self):
        assert _map_severity("ERROR") == "critical"
        assert _map_severity("Warning") == "high"

    def test_empty_string(self):
        assert _map_severity("") == "medium"


def test_semgrep_retains_test_findings_and_critical_production_evidence(tmp_path):
    import json
    from types import SimpleNamespace
    from unittest.mock import patch
    from app.graph.nodes.semgrep import _run_semgrep_sync
    from app.graph.nodes.report_generator import effective_penalty

    cases = [
        ("electron/authFlowRelay.test.ts", "javascript.node-crypto.security.gcm-no-tag-length.gcm-no-tag-length", 'decipher.setAuthTag(value.subarray(-16));', {}),
        ("src/api.ts", "javascript.sql-injection", 'database.query(request.body.query);', {"confidence": "HIGH", "category": "security"}),
        ("services/email/render-email.mjs", "javascript.manual-sanitization", 'value.replaceAll("<", "&lt;");', {"subcategory": ["audit"]}),
        ("src/log.ts", "javascript.unsafe-format-string", 'console.warn(`[native-export] Encoder probe failed for ${encoderName}:`, stderrOutput.trim());', {}),
    ]
    results = []
    for path, rule, source, metadata in cases:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)
        results.append({"path": path, "check_id": rule, "start": {"line": 1, "col": 1}, "extra": {"severity": "ERROR", "message": "Scanner observation", "metadata": metadata}})
    with patch("app.graph.nodes.semgrep.shutil.which", return_value="semgrep"), patch("app.graph.nodes.semgrep.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps({"results": results}).encode(), stderr=b"")) as scanner:
        findings = _run_semgrep_sync(str(tmp_path))
    assert len(findings) == 4
    assert "auto" in scanner.call_args.args[0]
    assert findings[0]["raw_severity"] == "ERROR"
    assert findings[0]["applicability"] == 0.25
    assert effective_penalty(findings[0]) == 5
    assert findings[1]["confidence"] == 1
    assert effective_penalty(findings[1]) == 20
    assert all(f["assessment"] == "hardening_recommendation" for f in findings[2:])
    assert all(effective_penalty(f) == 7 for f in findings[2:])


def test_same_jwt_from_real_adapters_merges_and_never_emits_secret(tmp_path):
    import base64
    import json
    import hashlib
    from types import SimpleNamespace
    from unittest.mock import patch
    from app.graph.nodes.semgrep import _run_semgrep_sync
    from app.graph.finding_quality import canonicalize_findings

    payload = base64.urlsafe_b64encode(json.dumps({"role": "service_role", "iss": "supabase"}).encode()).decode().rstrip("=")
    token = f"eyJhbGciOiJIUzI1NiJ9.{payload}.unmistakable-signature"
    (tmp_path / ".env.example").write_text(f"SUPABASE_SERVICE_ROLE_KEY={token}\n")
    result = {"path": ".env.example", "check_id": "generic.secrets.jwt", "start": {"line": 1, "col": 1}, "extra": {"severity": "ERROR", "message": f"JWT found {token}"}}
    with patch("app.graph.nodes.semgrep.shutil.which", return_value="semgrep"), patch("app.graph.nodes.semgrep.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps({"results": [result]}).encode(), stderr=b"")):
        finding = _run_semgrep_sync(str(tmp_path))[0]
    assert finding["severity"] == "critical"
    assert finding["applicability"] == 1
    assert finding["secret_hash"] == hashlib.sha256(token.encode()).hexdigest()
    assert token not in json.dumps(finding)
    gitleaks = dict(finding, tool="secrets_pii", sources=["gitleaks"], rule_id="gitleaks_jwt", column=1)
    assert len(canonicalize_findings([finding, gitleaks])) == 1
