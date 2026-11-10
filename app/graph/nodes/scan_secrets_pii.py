import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile

from app.graph.finding_quality import classify_source_context
from app.graph.secret_context import classify_secret_exposure
from app.graph.state import AuditState, Finding

logger = logging.getLogger(__name__)

PII_PATTERNS: list[dict] = [
    {"name": "email_address", "severity_base": "low", "regex": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")},
    {"name": "phone_india", "severity_base": "medium", "regex": re.compile(r"(?<![\w+])(?:\+?91[-. ]?)?[6-9]\d{9}(?!\w)")},
    {"name": "aadhaar_like", "severity_base": "high", "regex": re.compile(r"(?<!\w)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\w)")},
    {"name": "pan_card", "severity_base": "high", "regex": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")},
    {"name": "credit_card", "severity_base": "high", "regex": re.compile(r"(?<!\w)\d(?:[ -]?\d){12,18}(?!\w|[ -]?\d)")},
    {"name": "ip_address", "severity_base": "medium", "regex": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")},
    {
        "name": "inline_credential", "severity_base": "high",
        "regex": re.compile(
            r'''(?<!\w)["']?(?P<name>(?:\w+_)?(?:password|passwd|secret|api_key|apikey|api_secret|auth_token|access_token|access_key|private_key)(?:_\w+)?)["']?\s*(?P<assignment>[:=])\s*(?P<quote>["'])(?P<value>(?:\\.|(?!(?P=quote))[^\r\n]){4,})(?P=quote)''',
            re.I,
        ),
    },
]

_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".avif", ".pdf",
    ".wav", ".mp3", ".mp4", ".ogg", ".flac", ".avi", ".mov", ".webm",
    ".woff", ".woff2", ".ttf", ".eot", ".zip", ".gz", ".bz2", ".xz", ".7z",
    ".jar", ".class", ".pyc", ".so", ".dll", ".exe", ".db", ".sqlite", ".wasm",
    ".tiff", ".tif", ".heic", ".psd", ".rar", ".tar", ".o", ".a", ".dylib", ".bin",
}


def _read_source(path: str) -> str | None:
    if os.path.splitext(path.lower())[1] in _BINARY_EXTENSIONS:
        return None
    try:
        with open(path, "rb") as source:
            data = source.read(1_048_577)
        if data.startswith((b"%PDF-", b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"PK\x03\x04", b"\x7fELF", b"MZ", b"wOFF", b"wOF2", b"RIFF", b"OggS", b"ID3")) or data[4:8] == b"ftyp":
            return None
        if len(data) > 1_048_576 or b"\0" in data:
            return None
        if data and sum(byte < 32 and byte not in (9, 10, 13) for byte in data) / len(data) > 0.01:
            return None
        return data.decode("utf-8")
    except (OSError, UnicodeError):
        return None


def _line_at(content: str, start: int, end: int) -> str:
    line_end = content.find("\n", end)
    return content[content.rfind("\n", 0, start) + 1:line_end if line_end >= 0 else len(content)]


def _is_false_positive(matched_text: str, file_path: str, content: str, match: re.Match, pattern_name: str = "") -> bool:
    line = _line_at(content, match.start(), match.end())
    lower = line.lower()
    if pattern_name == "inline_credential":
        prefix = content[content.rfind("\n", 0, match.start()) + 1:match.start()].rstrip()
        return match.group("assignment") == ":" and bool(prefix) and not prefix.endswith(("{", ","))
    if "@" in matched_text:
        address = matched_text.lower()
        local, domain = address.rsplit("@", 1)
        if domain in {"example.com", "example.org", "example.net", "test.com", "domain.com"} or domain.endswith(".example"):
            return True
        if local in {"support", "help", "info", "contact", "sales", "security", "noreply", "no-reply"}:
            return True
        source = classify_source_context(file_path, content, content[:match.start()].count("\n") + 1)
        if source in {"legal", "generated_attribution"}:
            return True
        if source != "production":
            headings = re.findall(r"(?m)^#{1,6}\s+(.+)$", content[:match.start()])
            doc_context = lower + " " + (headings[-1].lower() if headings else "")
            if re.search(r"\b(?:example|sample|demo|dummy|test|usage|judge)\b", doc_context):
                return True
        return "placeholder" in lower
    if pattern_name == "ip_address":
        try:
            address = ipaddress.ip_address(matched_text)
        except ValueError:
            return True
        return not address.is_global or not bool(re.search(r"\b(?:client|customer|user|visitor)[_ -]?(?:ip|address)\b", lower))
    if pattern_name in {"phone_india", "aadhaar_like", "credit_card"}:
        digits = re.sub(r"\D", "", matched_text)
        if len(set(digits)) <= 2 or digits in {"1234567890", "9876543210", "123456789012", "1234567890123456"}:
            return True
        before = content[max(0, match.start() - 80):match.start()].split("\n")[-1]
        after = content[match.end():match.end() + 20]
        if re.search(r"(?:timestamp|epoch|uploaded_at|created_at|updated_at|hash|checksum|query_key|querykey|numeric_id)[\"']?\s*[:=]\s*[\"']?$", before, re.I):
            return True
        if re.match(r"\.(?:png|jpe?g|gif|webp|wav|mp[34]|json)\b", after, re.I) or re.search(r"[?&][\w-]+=$", before):
            return True
        if pattern_name == "phone_india":
            return not (matched_text.startswith("+91") or re.search(r"\b(?:phone|mobile|telephone|tel|contact|whatsapp)(?:_number)?\b", lower))
        if pattern_name == "aadhaar_like":
            return not bool(re.search(r"\b(?:aadhaar|aadhar|uidai)(?:_number|_id)?\b", lower))
        # Luhn-valid substrings can still be coordinates, filenames, or platform IDs.
        if (
            content[max(0, match.start() - 1):match.start()] == "."
            or (content[match.end():match.end() + 1] == "." and content[match.end() + 1:match.end() + 2].isdigit())
        ):
            return True
        token_start, token_end = match.start(), match.end()
        delimiters = " \t\r\n\"'`<>(){},;[]"
        while token_start > 0 and content[token_start - 1] not in delimiters:
            token_start -= 1
        while token_end < len(content) and content[token_end] not in delimiters:
            token_end += 1
        token = content[token_start:token_end]
        if "://" in token or token.startswith(("/", "www.")) or re.search(r"[-_/]\d{13,19}(?:[-_.]|$)", token):
            return True
        if re.search(r"\b(?:[a-z_]*id|timestamp|epoch|[a-z_]*(?:filename|file_name))\b[\"']?\s*[:=]\s*[\"']?$", before, re.I):
            return True
        total = sum((digit * 2 - 9 if digit * 2 > 9 else digit * 2) if index % 2 else digit
                    for index, digit in enumerate(map(int, reversed(digits))))
        return total % 10 != 0
    return False


def _run_pii_scan(repo_path: str) -> list[Finding]:
    """Inspect tracked text sources and retain only contextual PII evidence."""
    findings: list[Finding] = []
    git_path = shutil.which("git")
    if not os.path.isdir(repo_path) or not git_path:
        return findings
    try:
        result = subprocess.run([git_path, "-C", repo_path, "ls-files", "-z"], capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            logger.warning("PII scan: git ls-files failed with code %s", result.returncode)
            return findings
    except (OSError, subprocess.SubprocessError):
        logger.warning("PII scan: unable to list tracked files")
        return findings

    for rel_path in filter(None, result.stdout.split("\0")):
        full_path = os.path.join(repo_path, rel_path)
        if os.path.commonpath((os.path.realpath(repo_path), os.path.realpath(full_path))) != os.path.realpath(repo_path):
            continue
        content = _read_source(full_path)
        if content is None:
            continue
        for pattern in PII_PATTERNS:
            for match in pattern["regex"].finditer(content):
                name = pattern["name"]
                if _is_false_positive(match.group(), rel_path, content, match, name):
                    continue
                line_number = content[:match.start()].count("\n") + 1
                source = classify_source_context(rel_path, content, line_number)
                raw_severity = pattern["severity_base"]
                severity = raw_severity
                if source != "production":
                    severity = {"high": "medium", "medium": "low"}.get(severity, severity)
                value = match.group()
                metadata = {
                    "raw_severity": raw_severity, "confidence": 0.9,
                    "applicability": 1.0 if source == "production" else 0.25,
                }
                if name == "inline_credential":
                    value = match.group("value")
                    metadata = classify_secret_exposure(match.group("name"), value, context=_line_at(content, match.start(), match.end()), source_context=source)
                    if metadata["exposure_classification"] in {"placeholder", "identifier", "false_positive"}:
                        continue
                    severity = metadata["severity"]
                findings.append({
                    "tool": "secrets_pii", "severity": severity,
                    "title": f"PII: {name} detected",
                    "description": f"PII pattern '{name}' matched in {rel_path}:{line_number}. Matched value: [REDACTED].",
                    "file_path": rel_path, "line_number": line_number,
                    "column": match.start() - content.rfind("\n", 0, match.start()),
                    "rule_id": f"pii_{name}",
                    "finding_type": "hardcoded_secret" if name == "inline_credential" else "pii_in_source",
                    "sources": ["pii_regex"], "source_context": source,
                    ("secret_hash" if name == "inline_credential" else "match_hash"): hashlib.sha256(value.encode("utf-8")).hexdigest(),
                    **metadata,
                })
    logger.info("PII scan found %d findings", len(findings))
    return findings


def _find_gitleaks() -> str | None:
    """Resolve gitleaks binary path."""
    gitleaks = shutil.which("gitleaks")
    if gitleaks:
        return gitleaks
    # Common Windows install locations
    for candidate in [
        os.path.expanduser("~/go/bin/gitleaks.exe"),
        os.path.expanduser("~/go/bin/gitleaks"),
        "C:\\Program Files\\gitleaks\\gitleaks.exe",
    ]:
        if os.path.isfile(candidate):
            return candidate
    return None


def _run_gitleaks_scan(repo_path: str) -> list[Finding]:
    """Run gitleaks against full git history and return findings.

    Gitleaks scans the entire commit history for secrets/credentials.
    Uses --log-opts='--all' to scan all branches.
    """
    gitleaks = _find_gitleaks()
    if not gitleaks:
        logger.warning("Gitleaks not installed — secrets scan will be empty. "
                       "Install from https://github.com/gitleaks/gitleaks/releases")
        return []

    try:
        with tempfile.TemporaryDirectory(prefix="compliance-gitleaks-") as temp_dir:
            report_path = os.path.join(temp_dir, "gitleaks-report.json")
            result = subprocess.run(
                [
                    gitleaks,
                    "detect",
                    "--source",
                    repo_path,
                    "--log-opts",
                    "--all",
                    "--report-format",
                    "json",
                    "--report-path",
                    report_path,
                    "--no-color",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )

            stdout = result.stdout or ""
            stderr = result.stderr or ""
            logger.info(
                "Gitleaks rc=%s stdout_len=%s stderr_len=%s",
                result.returncode,
                len(stdout),
                len(stderr),
            )

            # Gitleaks normally exits 1 when leaks are found and 0 when none
            # are found. Parse the report for either code because behavior can
            # differ between versions.
            if result.returncode not in (0, 1):
                logger.warning(
                    "Gitleaks failed with exit code %s",
                    result.returncode,
                )
                return []

            if not os.path.isfile(report_path) or os.path.getsize(report_path) == 0:
                if result.returncode == 1:
                    logger.warning(
                        "Gitleaks reported findings but produced no JSON report"
                    )
                else:
                    logger.info("Gitleaks: no secrets found")
                return []

            try:
                with open(report_path, encoding="utf-8") as report_file:
                    leaks = json.load(report_file)
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Gitleaks: failed to read JSON report (%s)", type(exc).__name__)
                return []
    except subprocess.TimeoutExpired:
        logger.warning("Gitleaks scan timed out after 300s")
        return []
    except FileNotFoundError:
        logger.warning("Gitleaks binary not found at %s", gitleaks)
        return []
    except Exception as exc:
        logger.warning("Gitleaks scan failed (%s)", type(exc).__name__)
        return []

    findings: list[Finding] = []
    if isinstance(leaks, dict):
        leaks = [leaks]
    for leak in leaks:
        if not isinstance(leak, dict):
            continue

        rule_id = (leak.get("RuleID") or leak.get("rule_id", "gitleaks_match"))
        description = (leak.get("Description") or leak.get("description", "") or "")
        file_path = (leak.get("File") or leak.get("file", ""))
        start_line = leak.get("StartLine") or leak.get("start_line", 0)
        commit = (leak.get("Commit") or leak.get("commit", ""))[:8]
        secret = leak.get("Secret") or leak.get("secret", "") or ""
        match_context = str(leak.get("Match") or leak.get("match") or "")
        source_path = os.path.join(repo_path, file_path)
        content = ""
        if os.path.commonpath((os.path.realpath(repo_path), os.path.realpath(source_path))) == os.path.realpath(repo_path):
            content = _read_source(source_path) or ""
        try:
            start_line = max(0, int(start_line))
        except (TypeError, ValueError):
            start_line = 0
        if not match_context and start_line and start_line <= len(content.splitlines()):
            match_context = content.splitlines()[start_line - 1]
        name = match_context.split("=", 1)[0].split(":", 1)[0]
        metadata = classify_secret_exposure(name, secret, rule_id, match_context,
                                            classify_source_context(file_path, content, start_line))
        if metadata["exposure_classification"] in {"placeholder", "identifier", "false_positive"}:
            continue
        finding_type = _classify_gitleaks_rule(rule_id, description, secret)
        findings.append({
            "tool": "secrets_pii",
            "title": f"Secret: {rule_id}",
            "description": (
                f"Secret detected by gitleaks in {file_path}:{start_line} "
                f"(commit: {commit}). Matched value: [REDACTED]."
            ),
            "file_path": file_path,
            "line_number": start_line,
            "rule_id": f"gitleaks_{rule_id}",
            "finding_type": finding_type,
            "sources": ["gitleaks"],
            "source_context": classify_source_context(file_path, content, start_line),
            "secret_hash": hashlib.sha256(secret.encode("utf-8")).hexdigest(),
            **metadata,
        })

    logger.info("Gitleaks found %d findings", len(findings))
    return findings


def _classify_gitleaks_rule(rule_id: str, description: str, secret: str) -> str:
    """Map gitleaks rule IDs to finding_type keys matching CONTROL_MAP."""
    rid = rule_id.lower()
    desc = description.lower()
    secret_lower = secret.lower()

    # JWT patterns
    if "jwt" in rid or "json" in rid and "token" in rid:
        return "jwt_exposed"

    # Private key patterns
    if "private-key" in rid or "private_key" in rid or "ssh" in rid:
        return "private_key_exposed"
    if "pem" in secret_lower or "begin" in secret_lower and "key" in secret_lower:
        return "private_key_exposed"
    if "rsa" in rid or "dsa" in rid or "ec" in rid and "key" in rid:
        return "private_key_exposed"

    # Cloud provider patterns
    if "aws" in rid or "amazon" in rid or "gcp" in rid or "google" in rid or "azure" in rid:
        return "cloud_credentials_exposed"
    if "github" in rid or "gitlab" in rid or "slack" in rid or "discord" in rid and "token" in rid:
        return "cloud_credentials_exposed"
    if "generic-api-key" in rid or "api_key" in rid:
        return "cloud_credentials_exposed"

    # Default: generic hardcoded secret
    return "hardcoded_secret"


# ---------------------------------------------------------------------------
# NODE ENTRY POINT
# ---------------------------------------------------------------------------

async def run_scan_secrets_pii(state: AuditState) -> dict:
    """LangGraph node: run gitleaks + PII scans in parallel.

    Returns secrets_findings appended to state.
    """
    if state.get("error"):
        return {}

    repo_path = state.get("local_path")
    if not repo_path:
        return {"secrets_findings": []}

    try:
        # Run gitleaks and PII scans concurrently
        gitleaks_findings, pii_findings = await asyncio.gather(
            asyncio.to_thread(_run_gitleaks_scan, repo_path),
            asyncio.to_thread(_run_pii_scan, repo_path),
        )

        all_findings = gitleaks_findings + pii_findings
        logger.info("Secrets+PII scan: %d gitleaks + %d PII = %d total",
                     len(gitleaks_findings), len(pii_findings), len(all_findings))
        return {"secrets_findings": all_findings}
    except Exception as exc:
        logger.error("Secrets+PII scan failed (%s)", type(exc).__name__)
        return {"secrets_findings": []}
