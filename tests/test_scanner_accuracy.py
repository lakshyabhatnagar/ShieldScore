"""Adapter regressions for contextual PII and credential classification."""

import base64
import hashlib
import json
import subprocess

import pytest

from app.graph.nodes import scan_secrets_pii as scanner
from app.graph.secret_context import classify_secret_exposure


def scan_files(monkeypatch, tmp_path, files):
    for path, content in files.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content if isinstance(content, bytes) else content.encode())
    monkeypatch.setattr(scanner.shutil, "which", lambda _: "git")
    monkeypatch.setattr(scanner.subprocess, "run", lambda command, **kwargs: subprocess.CompletedProcess(
        command, 0, stdout="\0".join(files) + "\0", stderr=""
    ))
    return scanner._run_pii_scan(str(tmp_path))


def test_binary_assets_and_numeric_noise_are_not_pii(monkeypatch, tmp_path):
    files = {
        "public/recording.wav": b"RIFF phone=9876123450 customer@example.net",
        "public/snapshot.png": b"PNG customer@example.net",
        "public/raw": b"\0phone=9876123450 customer@example.net",
        "src/constants.py": '\n'.join([
            'timestamp = 9876123450', 'uploaded_at = 234567890123',
            'image = "9876123450.png"', 'url = "/image?v=9876123450"',
            'query_hash = "dead9876123450beef"', 'phone = "9999999999"',
            'number = "1234567890123456"', 'card_number = "4111111111111112"',
            'numeric_id = "234567890123"',
            'url = "/view?auth_key=9999999999-0-0-deadbeef"',
            'filename = "recording-1720588800000.mp4"',
        ]),
    }
    assert scan_files(monkeypatch, tmp_path, files) == []


def test_real_contextual_pii_survives_and_nearby_credentials_are_never_echoed(monkeypatch, tmp_path):
    card, phone, aadhaar = "4532015112830366", "9876123450", "234567890123"
    secret = "Cobalt-Lantern-Private-7842"
    content = f'card_number = "{card}"\nphone = "{phone}"\naadhaar = "{aadhaar}"\n"password": "{secret}", "email": "jane@company.net"\n'
    findings = scan_files(monkeypatch, tmp_path, {"src/customers.py": content})
    assert {f["rule_id"] for f in findings} >= {
        "pii_credit_card", "pii_phone_india", "pii_aadhaar_like", "pii_inline_credential", "pii_email_address",
    }
    serialized = json.dumps(findings)
    for value in (card, phone, aadhaar, secret, "jane@company.net"):
        assert value not in serialized
    credential = next(f for f in findings if f["rule_id"] == "pii_inline_credential")
    assert credential["secret_hash"] == hashlib.sha256(secret.encode()).hexdigest()
    assert credential["line_number"] == 4
    assert isinstance(credential["confidence"], float)


def test_placeholders_docs_support_and_rust_test_context(monkeypatch, tmp_path):
    findings = scan_files(monkeypatch, tmp_path, {
        "src/settings.py": 'password = "your_password"\n{"secret": "${SECRET}"}\napi_key = "<api-key>"\nSUPABASE_SERVICE_ROLE_KEY = "your_secret"\nsecretary = "Jane Doe"',
        "README.md": 'Demo contact demo@myproduct.io. Support support@myproduct.io.\n## Demo / judge account\nEmail: judge@h4i.com',
        "src/main.rs": '#[cfg(test)]\nmod tests {\n    #[test]\n    fn customer() { let phone = "9876123450"; }\n}\n',
    })
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "pii_phone_india"
    assert findings[0]["source_context"] == "test"
    assert findings[0]["severity"] == "low"


def jwt(role):
    payload = base64.urlsafe_b64encode(json.dumps({"iss": "supabase", "role": role}).encode()).decode().rstrip("=")
    return "eyJhbGciOiJIUzI1NiJ9." + payload + ".signature-for-fixture"


def test_gitleaks_semantic_exposure_and_safe_metadata(monkeypatch, tmp_path, caplog):
    values = [jwt("anon"), jwt("service_role"), "sk-or-v1-" + "a1b2c3d4" * 8, "access_token"]
    leaks = [
        {"RuleID": "generic-api-key", "Secret": value, "File": ".env.example", "StartLine": i + 1,
         "Match": f'{name} = "{value}"', "Description": "found " + value}
        for i, (name, value) in enumerate(zip(
            ["SUPABASE_ANON_KEY", "SUPABASE_SERVICE_ROLE_KEY", "OPENROUTER_API_KEY", 'localStorage.getItem'], values
        ))
    ]
    leaks[-1]["Match"] = 'localStorage.getItem("access_token")'
    monkeypatch.setattr(scanner, "_find_gitleaks", lambda: "gitleaks")

    def run(command, **kwargs):
        with open(command[command.index("--report-path") + 1], "w") as report:
            json.dump(leaks, report)
        return subprocess.CompletedProcess(command, 1, stdout=values[2], stderr=values[1])

    monkeypatch.setattr(scanner.subprocess, "run", run)
    caplog.set_level("DEBUG")
    findings = scanner._run_gitleaks_scan(str(tmp_path))
    assert len(findings) == 3
    assert [f["severity"] for f in findings] == ["info", "critical", "critical"]
    assert [f["secret_class"] for f in findings] == [
        "public_anon_token", "private_service_token", "credential",
    ]
    for value, finding in zip(values, findings):
        assert finding["secret_hash"] == hashlib.sha256(value.encode()).hexdigest()
        assert finding["sources"] == ["gitleaks"]
        assert finding["raw_severity"] == "critical"
        assert value not in finding["description"]
        assert value not in caplog.text


@pytest.mark.parametrize("value", [jwt("service_role"), "sk-or-v1-" + "0123456789abcdef" * 4])
def test_real_secrets_survive_example_and_test_paths(monkeypatch, tmp_path, value):
    findings = scan_files(monkeypatch, tmp_path, {"tests/config.example.py": f'api_key = "{value}"'})
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert findings[0]["applicability"] == 1.0


def test_service_role_cannot_be_disguised_as_public():
    assert classify_secret_exposure("NEXT_PUBLIC_SUPABASE_ANON_KEY", jwt("service_role"))["severity"] == "critical"
    assert classify_secret_exposure("NEXT_PUBLIC_OPENROUTER_KEY", "sk-or-v1-" + "a" * 64)["severity"] == "critical"


def test_namespaced_storage_key_is_information():
    metadata = classify_secret_exposure("const HIDDEN_KEY", "recordly.raw-hidden.v1", "generic-api-key")
    assert metadata["secret_class"] == "storage_identifier"
    assert metadata["severity"] == "info"
    assert metadata["applicability"] == 0.0


def test_assignment_values_allow_other_quotes_and_exclude_unrelated_names(monkeypatch, tmp_path):
    value = "don't-expose-private-7731"
    findings = scan_files(monkeypatch, tmp_path, {"config.py": f'password = "{value}"\nsecretary = "Jane Doe"'})
    assert len(findings) == 1
    assert findings[0]["secret_hash"] == hashlib.sha256(value.encode()).hexdigest()


def test_exact_hghub_and_recordly_text_cases(monkeypatch, tmp_path):
    assert scan_files(monkeypatch, tmp_path, {
        "src-tauri/src/net.rs": '#[tokio::test]\nasync fn rejects_credentials() {\nlet body = json!({"password":"secret"});\nlet base = "https://cdn.example/videos5/abc/abc.m3u8?auth_key=9999999999-0-0-deadbeef&v=3&via=hgdj";\n}\n',
        "src/auth/RecordlySignInFields.tsx": 'data-signin-step={sentTo ? "code" : passwordMode ? "password" : "email"}',
        "electron/ipc/recording/storagePath.test.ts": '"recording-1720588800000.mp4"; "recording-1720588800000-webcam.webm";',
    }) == []


@pytest.mark.parametrize("filename, prefix", [
    ("icon.png", b"\x89PNG\r\n\x1a\n"), ("wallpaper.jpg", b"\xff\xd8\xff"),
    ("no-extension", b"\x00\x01\x02"), ("wrong-extension.txt", b"\xff\xd8\xff"),
])
def test_binary_file_with_nonreserved_email_aadhaar_and_phone(monkeypatch, tmp_path, filename, prefix):
    content = prefix + b' customer="jane@company.net" aadhaar="234567890123" phone="9876123450"'
    assert scan_files(monkeypatch, tmp_path, {filename: content}) == []


def test_weak_but_usable_production_credentials_are_not_suppressed(monkeypatch, tmp_path):
    findings = scan_files(monkeypatch, tmp_path, {"backend/config.py": 'password = "password123"\nsecret = "secret123"'})
    assert len(findings) == 2
    assert all(f["severity"] == "critical" and f["applicability"] == 1 for f in findings)


def test_distinct_pii_occurrences_on_same_line_keep_columns(monkeypatch, tmp_path):
    from app.graph.finding_quality import canonicalize_findings
    findings = scan_files(monkeypatch, tmp_path, {"customers.py": 'emails = ["jane@company.net", "jane@company.net"]'})
    assert len(findings) == len(canonicalize_findings(findings)) == 2
    assert findings[0]["column"] != findings[1]["column"]


def test_public_prefix_does_not_hide_private_credential():
    assert classify_secret_exposure("PUBLIC_KEY", "pk_live_client_identifier")["severity"] == "info"
    assert classify_secret_exposure("PUBLIC_KEY", "sk_live_private_secret")["severity"] == "critical"
    assert classify_secret_exposure("NAMES_KEY", "recordly.raw-names.v1")["severity"] == "info"


@pytest.mark.parametrize("name", ["SERVICE_ROLE_KEY", "SUPABASE_SERVICE_ROLE_KEY", "API_KEY", "PRIVATE_KEY", "ADMIN_KEY"])
def test_versioned_private_values_cannot_be_hidden_as_storage_identifiers(name):
    result = classify_secret_exposure(name, "customer.production.v1")
    assert result["severity"] == "critical"
    assert result["applicability"] == 1


def test_binary_magic_overrides_misleading_text_extension(monkeypatch, tmp_path):
    assert scan_files(monkeypatch, tmp_path, {"document.txt": b'%PDF-1.7 phone="9876123450" jane@company.net'}) == []
