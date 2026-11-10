"""Production follow-up regressions for synthetic secrets and non-PII content."""

import json
import subprocess

import pytest

from app.graph.finding_quality import classify_source_context
from app.graph.nodes import scan_secrets_pii as scanner
from app.graph.secret_context import classify_secret_exposure
from tests.test_scanner_accuracy import jwt, scan_files

TEST_FILES = [
    "electron/recordingFileWriter.test.ts", "services/abuseProtection.test.js",
    "electron/recordlyAuth.test.ts", "electron/diagnosticRedaction.test.ts",
    "vitest.config.mjs",
]
SYNTHETIC_VALUES = ["secret", "wrong", "correct password", "private recording", "test-secret"]


def gitleaks(monkeypatch, tmp_path, leaks):
    monkeypatch.setattr(scanner, "_find_gitleaks", lambda: "gitleaks")
    def run(command, **kwargs):
        with open(command[command.index("--report-path") + 1], "w") as report:
            json.dump(leaks, report)
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="")
    monkeypatch.setattr(scanner.subprocess, "run", run)
    return scanner._run_gitleaks_scan(str(tmp_path))


@pytest.mark.parametrize("path", TEST_FILES)
@pytest.mark.parametrize("value", SYNTHETIC_VALUES)
def test_synthetic_test_credentials_are_suppressed_by_both_adapters(monkeypatch, tmp_path, path, value):
    content = f'export const config = {{API_SECRET: "{value}"}};'
    assert scan_files(monkeypatch, tmp_path, {path: content}) == []
    leaks = [{"RuleID": "generic-api-key", "File": path, "StartLine": 1, "Match": content, "Secret": value}]
    assert gitleaks(monkeypatch, tmp_path, leaks) == []


@pytest.mark.parametrize("path, expected", [
    ("vitest.config.mjs", "test"), ("jest.config.ts", "test"),
    ("src/__mocks__/auth.js", "test"), ("fixtures/auth.json", "test"),
    ("src/i18n/en.json", "localization"), ("public/locales/fr/common.json", "localization"),
    ("ThirdPartyNotices.txt", "legal"), ("LICENSE", "legal"),
    ("legal/attribution.txt", "legal"), ("generated/attributions.txt", "generated_attribution"),
])
def test_source_context_recognizes_nonproduction_content(path, expected):
    assert classify_source_context(path) == expected


def test_translations_do_not_create_repeated_credential_findings(monkeypatch, tmp_path):
    labels = {
        "en": "Password", "fr": "Mot de passe", "de": "Passwort", "es": "Contraseña",
        "ja": "パスワード", "hi": "पासवर्ड",
    }
    files = {f"src/locales/{locale}.json": json.dumps({"password": value, "secret": "Private recording"}, ensure_ascii=False)
             for locale, value in labels.items()}
    assert scan_files(monkeypatch, tmp_path, files) == []
    leaks = [{"RuleID": "generic-api-key", "File": f"src/locales/{locale}.json", "StartLine": 1,
              "Match": json.dumps({"password": value}, ensure_ascii=False), "Secret": value}
             for locale, value in labels.items()]
    assert gitleaks(monkeypatch, tmp_path, leaks) == []


@pytest.mark.parametrize("path", ["src/components/form.tsx", "config.json", "src/i18n/en.json"])
def test_password_ui_label_is_not_secret_assignment(monkeypatch, tmp_path, path):
    key = "password" if "/i18n/" in path else "password_label"
    assert scan_files(monkeypatch, tmp_path, {path: json.dumps({key: "Password"})}) == []


@pytest.mark.parametrize("path", [
    "ThirdPartyNotices.txt", "THIRD_PARTY_NOTICES.txt", "LICENSE", "LICENSE.md",
    "licenses/package.txt", "legal/attribution.txt", "generated/attributions.txt",
])
def test_legal_and_attribution_emails_are_not_privacy_findings(monkeypatch, tmp_path, path):
    assert scan_files(monkeypatch, tmp_path, {path: 'Copyright 2026 Jane Author <jane.author@company.net>\nAll rights reserved.'}) == []


@pytest.mark.parametrize("source", [
    'const statusId = "2050536037789905227";',
    'const profile = "https://x.com/i/user/2050536037789905227";',
    'const status = "https://twitter.com/user/status/2050536037789905227";',
    'const x = 0.4980544747081712;', 'const latitude = -0.4980544747081712;',
    'const longitude = 0.4532015112830366;',
    'const id = "4532015112830366";', 'const timestamp = "1720588800000";',
    'const filename = "recording-4532015112830366-webcam.webm";',
    'const url = "https://cdn.company.net/videos/4532015112830366";',
])
def test_decimal_social_timestamp_and_file_identifiers_are_not_cards(monkeypatch, tmp_path, source):
    assert scan_files(monkeypatch, tmp_path, {"src/constants.ts": source}) == []


def test_actual_luhn_card_survives_and_invalid_one_does_not(monkeypatch, tmp_path):
    findings = scan_files(monkeypatch, tmp_path, {"backend/payment.py": 'card_number = "4532015112830366"\ncard_number = "4532015112830367"'})
    assert [f["rule_id"] for f in findings] == ["pii_credit_card"]


@pytest.mark.parametrize("path", [*TEST_FILES, "src/locales/en.json", "ThirdPartyNotices.txt", ".env.example"])
@pytest.mark.parametrize("value", [jwt("service_role"), "sk-or-v1-" + "f4a8c1d7e290b356" * 4])
def test_genuine_private_credentials_survive_every_source_context(monkeypatch, tmp_path, path, value):
    content = f'API_SECRET = "{value}"'
    findings = scan_files(monkeypatch, tmp_path, {path: content})
    assert len(findings) == 1 and findings[0]["severity"] == "critical"
    assert findings[0]["applicability"] == 1
    leaks = [{"RuleID": "generic-api-key", "File": path, "StartLine": 1, "Match": content, "Secret": value}]
    findings = gitleaks(monkeypatch, tmp_path, leaks)
    assert len(findings) == 1 and findings[0]["severity"] == "critical"
    assert value not in json.dumps(findings)


def test_unknown_generic_match_is_likely_not_automatically_critical(monkeypatch, tmp_path):
    value = "aB7qP9mN2xR4vT6zC8dF0gH3jK5lS1uW"
    leaks = [{"RuleID": "generic-api-key", "File": "src/api.ts", "StartLine": 1,
              "Match": f'const API_KEY = "{value}"', "Secret": value}]
    findings = gitleaks(monkeypatch, tmp_path, leaks)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["exposure_classification"] == "likely_secret"


def test_generic_nonsecret_identifier_is_suppressed(monkeypatch, tmp_path):
    leaks = [{"RuleID": "generic-api-key", "File": "src/cache.ts", "StartLine": 1,
              "Match": 'const NAMES_KEY = "recordly.raw-names.v1"', "Secret": "recordly.raw-names.v1"}]
    assert gitleaks(monkeypatch, tmp_path, leaks) == []


def test_luhn_valid_timestamp_is_not_card_evidence(monkeypatch, tmp_path):
    assert scan_files(monkeypatch, tmp_path, {"data.json": '{"created_at": "1720588800005"}'}) == []


def test_ordinary_production_password_assignments_and_private_passphrases_survive(monkeypatch, tmp_path):
    files = {
        "backend/config.py": 'password = "password"\npassword = "correct horse battery staple"',
        "tests/cloud.test.ts": 'ADMIN_KEY = "correct horse battery staple"',
    }
    findings = scan_files(monkeypatch, tmp_path, files)
    # ADMIN_KEY is outside the inline pattern, but Gitleaks must preserve it.
    assert len(findings) == 2
    assert all(f["severity"] == "critical" for f in findings)
    leaks = [{"RuleID": "generic-api-key", "File": "tests/cloud.test.ts", "StartLine": 1,
              "Match": 'ADMIN_KEY = "correct horse battery staple"', "Secret": "correct horse battery staple"}]
    findings = gitleaks(monkeypatch, tmp_path, leaks)
    assert len(findings) == 1 and findings[0]["severity"] == "critical"


@pytest.mark.parametrize("path,value", [
    ("src/i18n/en.json", "Password"), ("test/authentication.spec.ts", "correct password"),
    ("vitest.config.mjs", "test-secret"),
])
def test_semgrep_does_not_reintroduce_suppressed_synthetic_secrets(monkeypatch, tmp_path, path, value):
    from app.graph.nodes import semgrep
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(f'const config = {{password: "{value}"}};')
    result = {"path": path, "check_id": "generic.secrets.hardcoded-password", "start": {"line": 1},
              "extra": {"severity": "ERROR", "message": "Credential candidate"}}
    monkeypatch.setattr(semgrep.shutil, "which", lambda _: "semgrep")
    monkeypatch.setattr(semgrep.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(
        args[0], 0, stdout=json.dumps({"results": [result]}).encode(), stderr=b""))
    assert semgrep._run_semgrep_sync(str(tmp_path)) == []


@pytest.mark.parametrize("source", ['{"password": "password"}', 'password: "password"'])
def test_production_colon_assignments_are_not_mistaken_for_translations(monkeypatch, tmp_path, source):
    findings = scan_files(monkeypatch, tmp_path, {"backend/config.yaml": source})
    assert len(findings) == 1 and findings[0]["severity"] == "critical"


def test_unmarked_passphrases_are_not_blanket_filtered_as_test_or_locale_prose(monkeypatch, tmp_path):
    cases = {
        "tests/config.test.py": 'password = "My Real Production Password"',
        "src/locales/en.json": '{"api_key": "my actual private api key"}',
    }
    findings = scan_files(monkeypatch, tmp_path, cases)
    assert len(findings) == 2
    assert all(f["severity"] in {"high", "critical"} for f in findings)


@pytest.mark.parametrize("number", ["4567891234567891230", "4012345678909"])
def test_luhn_valid_card_candidates_are_not_discarded_by_length_or_epoch_overlap(monkeypatch, tmp_path, number):
    findings = scan_files(monkeypatch, tmp_path, {"backend/payment.py": f'value = "{number}"'})
    assert [f["rule_id"] for f in findings] == ["pii_credit_card"]


@pytest.mark.parametrize("name,value", [
    ("api_key", "correct horse battery staple"), ("admin_password", "private island passphrase"),
])
def test_fixture_qualifiers_do_not_hide_real_passphrases(monkeypatch, tmp_path, name, value):
    findings = scan_files(monkeypatch, tmp_path, {"tests/config.test.py": f'{name} = "{value}"'})
    assert len(findings) == 1 and findings[0]["severity"] in {"high", "critical"}
    leaks = [{"RuleID": "generic-api-key", "File": "tests/config.test.py", "StartLine": 1,
              "Match": f'{name} = "{value}"', "Secret": value}]
    findings = gitleaks(monkeypatch, tmp_path, leaks)
    assert len(findings) == 1 and findings[0]["severity"] in {"high", "critical"}
