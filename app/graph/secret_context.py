"""Classify credential intent without exposing credential values downstream."""

import base64
from collections import Counter
import json
import math
import re
import unicodedata


def _token_shaped(value: str) -> bool:
    if len(value) < 16 or not re.fullmatch(r"[A-Za-z0-9_+/=.\-]+", value):
        return False
    entropy = -sum((count / len(value)) * math.log2(count / len(value)) for count in Counter(value).values())
    return entropy >= 3.5


def _ordinary_text(value: str) -> bool:
    words = re.findall(r"[^\W\d_]+", value, re.UNICODE)
    return bool(words) and all(word == word.lower() or word.istitle() or word == word.upper() for word in words) and all(
        character.isalpha() or unicodedata.category(character).startswith("M") or character.isspace() or character in "'’.,!?():;…-" for character in value
    )


def classify_secret_exposure(
    name: str, value: str, rule_id: str = "", context: str = "", source_context: str = "production"
) -> dict:
    names = re.findall(r"[A-Za-z_][A-Za-z0-9_-]*", name)
    label = names[-1].lower() if names else ""
    value = value.strip()
    secret_class, exposure = "credential", "likely_secret"
    severity, confidence, applicability = "high", 0.7, 1.0
    claims = {}
    pieces = value.split(".")
    if len(pieces) == 3:
        try:
            payload = pieces[1] + "=" * (-len(pieces[1]) % 4)
            decoded = json.loads(base64.urlsafe_b64decode(payload))
            if isinstance(decoded, dict):
                claims = decoded
        except (ValueError, UnicodeError):
            pass

    role = str(claims.get("role", "")).lower()
    provider_token = bool(re.match(r"(?:sk-or-v1-|sk_live_|sk_test_|gh[pousr]_|github_pat_|glpat-|xox[baprs]-|AKIA|ASIA|sb_secret_)", value))
    private_pem = bool(re.search(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", value))
    private_role = role in {"service_role", "service", "admin", "administrator"}
    private_label = bool(re.search(r"(?:service[_-]role|(?:admin|service|private)[_-](?:key|password|secret|token)|secret[_-]key)", label))
    token_shaped = _token_shaped(value)
    ordinary_text = _ordinary_text(value)
    fixture_context = source_context in {"test", "documentation"}
    configured_credential = bool(re.search(r"(?:api[_-]?(?:key|secret)|auth[_-]?token|access[_-]?(?:token|key))", label))
    placeholder = (
        not value
        or (fixture_context and value.lower() in {
            "password", "password123", "passwd", "secret", "secret123", "test", "test123", "wrong",
            "changeme", "change-me", "change_me", "example", "dummy", "dummy_secret", "redacted",
        })
        or (fixture_context and re.fullmatch(
            r"(?:test|dummy|fake|mock|example|sample)[_-](?:password|passwd|secret|token|key|api[_-]key)(?:[_-]?\d+)?",
            value, re.I,
        ))
        or (source_context == "test" and ordinary_text and not private_label and re.fullmatch(
            r"(?:correct|incorrect|wrong|valid|invalid|expected)\s+(?:password|passwd|secret|token|key|credential|value)|(?:public|private)\s+[^\W\d_]+", value, re.I,
        ))
        or value.lower() in {
            "replace_me", "replace-me", "placeholder",
            "your_api_key", "your-api-key", "your_secret", "your_password", "your_token",
            "api_key_here", "token_here",
        }
        or re.fullmatch(r"(?:x{4,}|\*{4,}|\.{3,})", value, re.I)
        or re.fullmatch(r"(?:\$\{[^}]+\}|\{\{.*\}\}|<[^>]+>)", value)
        or re.fullmatch(r"(?:your|replace|insert)[_-].*(?:key|token|secret|password|here)", value, re.I)
    )
    if private_role:
        secret_class, exposure = "private_service_token", "confirmed_secret"
        severity, confidence = "critical", 0.99
    elif provider_token or private_pem:
        exposure = "confirmed_secret"
        severity, confidence = "critical", 0.99
    elif placeholder:
        secret_class, exposure = "placeholder", "placeholder"
        severity, confidence, applicability = "info", 0.99, 0.0
    elif ordinary_text and not token_shaped and (
        (source_context == "localization" and re.sub(r"[\s_-]+", " ", value.casefold()) == re.sub(r"[\s_-]+", " ", label))
        or re.search(r"_(?:label|placeholder)$", label)
    ):
        secret_class, exposure = "false_positive", "false_positive"
        severity, confidence, applicability = "info", 0.95, 0.0
    elif private_label:
        secret_class, exposure = "private_service_token", "confirmed_secret"
        severity, confidence = "critical", 0.95
    elif (role == "anon" and (str(claims.get("iss", "")).lower() == "supabase" or "supabase" in label)) or value.startswith(("sb_publishable_", "pk_live_", "pk_test_")):
        secret_class, exposure = "public_anon_token", "public_key"
        severity, confidence, applicability = "info", 0.99, 0.0
    elif re.search(r"-----BEGIN (?:RSA )?PUBLIC KEY-----", value):
        secret_class, exposure = "public_key", "public_key"
        severity, confidence, applicability = "info", 0.99, 0.0
    elif (
        re.search(r"(?:localStorage|sessionStorage)\s*\.\s*(?:getItem|setItem|removeItem)", context, re.I)
        and re.fullmatch(r"(?:[a-z][a-z0-9]*[_-])*(?:token|key|session|auth)(?:[_-][a-z0-9]+)*", value, re.I)
    ) or (
        re.search(r"\b(?:hidden|names|storage|cache|local_storage|session_storage)_key\b", name, re.I)
        and re.fullmatch(r"[a-z][a-z0-9_-]*(?:\.[a-z0-9_-]+)+\.v\d+", value)
    ):
        secret_class, exposure = "storage_identifier", "identifier"
        severity, confidence, applicability = "info", 0.95, 0.0
    elif source_context == "localization" and ordinary_text and not token_shaped and not configured_credential:
        secret_class, exposure = "false_positive", "false_positive"
        severity, confidence, applicability = "info", 0.95, 0.0
    elif re.search(r"(?:^|\W|_)(?:password|passwd|secret)(?:$|\W|_)", label) or (
        not rule_id
        and re.search(r"(?:^|\W|_)(?:api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?(?:token|key))(?:$|\W|_)", label)
    ):
        exposure = "confirmed_secret"
        severity, confidence = "critical", 0.95
    elif token_shaped:
        confidence = 0.85

    return {
        "severity": severity,
        "raw_severity": "critical",
        "confidence": confidence,
        "applicability": applicability,
        "secret_class": secret_class,
        "exposure_classification": exposure,
    }
