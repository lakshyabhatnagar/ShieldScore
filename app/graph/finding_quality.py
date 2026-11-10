"""Deterministic finding context and identities shared by adapters and reports."""

import hashlib
import json
import posixpath
import re

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SECRET_TYPES = {"jwt_exposed", "private_key_exposed", "cloud_credentials_exposed", "hardcoded_secret"}


def classify_source_context(path: str, content: str = "", line_number: int = 0) -> str:
    path = path.replace("\\", "/").lower()
    basename = path.rsplit("/", 1)[-1]
    if (
        re.search(r"(^|/)(tests?|__tests__|specs?|__specs__|fixtures?|__fixtures__|mocks?|__mocks__|examples?|samples?|demos?|seeds?|snapshots?)(/|$)", path)
        or re.search(r"(^|/)(test_|.*[._](test|spec)\.)", path)
        or re.fullmatch(r"(?:vitest|jest|playwright|cypress|karma|ava|mocha)\.(?:config|workspace)\.[a-z0-9]+", basename)
        or basename in {"conftest.py", "pytest.ini", "tox.ini"}
    ):
        return "test"
    legal_name = re.fullmatch(
        r"(?:(?:third|3rd)[_ -]?party[_ -]?)?(?:notices?|licen[cs]es?|copying|copyright|authors|contributors|attributions?|acknowledgements?)(?:[._-].*)?",
        basename,
    )
    legal_path = re.search(r"(^|/)(legal|licen[cs]es?|attributions?|notices?)(/|$)", path)
    header = content[:2048].lower()
    generated_legal = bool(re.search(
        r"generated[^\n]{0,80}(?:third.party notices|licen[cs]e notices|attributions?)|(?:third.party notices|attributions?)[^\n]{0,80}generated",
        header,
    ))
    if generated_legal or ((legal_name or legal_path) and re.search(r"(^|/)(generated|gen)(/|$)", path)):
        return "generated_attribution"
    if legal_name or legal_path:
        return "legal"
    if re.search(r"(^|/)(i18n|l10n|locales?|translations?|localizations?)(/|$)", path):
        return "localization"
    if re.search(r"(^|/)(docs?|readme[^/]*)(/|$)", path) or path.endswith((".md", ".rst")):
        return "documentation"
    if content and line_number:
        scopes = []
        pending_test = False
        token_pattern = r'"(?:\\.|[^"\\])*"|//[^\n]*|#\[(?:(?:tokio::)?test|cfg\(test\))\]|[{}]'
        for token in re.finditer(token_pattern, content):
            token_line = content.count("\n", 0, token.start()) + 1
            if token_line > line_number:
                break
            if token_line == line_number and any(scopes):
                return "test"
            text = token.group()
            if text.startswith("#["):
                pending_test = True
                if token_line == line_number:
                    return "test"
            elif text == "{":
                scopes.append(pending_test)
                pending_test = False
                if token_line == line_number and any(scopes):
                    return "test"
            elif text == "}" and scopes:
                scopes.pop()
        if any(scopes):
            return "test"
    return "production"


def finding_fingerprint(finding: dict) -> str:
    path = posixpath.normpath((finding.get("file_path") or "").replace("\\", "/"))
    rule = finding.get("rule_id") or finding.get("title", "")
    line = finding.get("line_number") or 0
    column = finding.get("column") or 0
    kind = finding.get("finding_type")
    if finding.get("tool") == "osv" and finding.get("package"):
        identity = ("dependency", finding.get("ecosystem", ""), finding["package"], finding.get("package_version", ""))
    elif kind in SECRET_TYPES or finding.get("secret_hash"):
        # Match hashes across tools only when both refer to the same source line.
        identity = ("secret", path, line, finding.get("secret_hash") or rule)
    elif str(rule).startswith("pii_"):
        identity = ("pii", path, line, column, rule, finding.get("match_hash", ""))
    else:
        identity = (finding.get("tool", ""), path, rule, line, column)
        if not line:
            identity += (finding.get("description", ""),)
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


def canonicalize_findings(findings: list[dict]) -> list[dict]:
    canonical: dict[str, dict] = {}
    for original in findings:
        if not isinstance(original, dict):
            continue
        finding = dict(original)
        fingerprint = finding_fingerprint(finding)
        finding["fingerprint"] = fingerprint
        finding["sources"] = sorted(set(finding.get("sources") or [finding.get("tool", "unknown")]))
        evidence = {k: finding.get(k) for k in ("tool", "rule_id", "file_path", "line_number", "column", "raw_severity") if finding.get(k) is not None}
        finding["evidence"] = list(finding.get("evidence") or [evidence])
        existing = canonical.get(fingerprint)
        if existing is None:
            canonical[fingerprint] = finding
            continue
        sources = sorted(set(existing["sources"] + finding["sources"]))
        evidence_items = existing["evidence"] + [e for e in finding["evidence"] if e not in existing["evidence"]]
        if SEVERITY_RANK.get(finding.get("severity"), 0) > SEVERITY_RANK.get(existing.get("severity"), 0):
            canonical[fingerprint] = finding
        merged = canonical[fingerprint]
        merged["sources"] = sources
        merged["evidence"] = evidence_items
        for key in ("confidence", "applicability"):
            if key in existing or key in finding:
                merged[key] = max(existing.get(key, 1.0), finding.get(key, 1.0))
        if finding.get("advisories"):
            advisories = {a["id"]: a for a in existing.get("advisories", []) + finding["advisories"]}
            merged["advisories"] = [advisories[key] for key in sorted(advisories)]
    return list(canonical.values())
