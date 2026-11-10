ShieldScore scanner quality changes
==================================

This patch fixes scanner noise, occurrence loss, privacy over-mapping, and severity-only penalties while preserving the repository ingestion, scanner fan-out, aggregation, mapping, and report flow. `app/graph/graph.py` and `app/routers/audit.py` match their original copies. No endpoint, frontend, deployment, or AuditState key changed. Existing finding fields remain, with optional evidence metadata added.

The original PII scanner decoded arbitrary bytes as UTF-8 with errors ignored and accepted numeric patterns without validation. Gitleaks promoted generic matches to critical without checking their meaning. Semgrep discarded locations and confidence metadata. Deduplication and explanation association used rule IDs, losing distinct occurrences while preserving cross-tool duplicates. Privacy mapping inferred personal-data processing from generic vulnerability words. Scoring applied full scanner severity to every surviving issue.

The implementation changes these files.

| File | Change |
| --- | --- |
| `app/graph/finding_quality.py` | Shared source context, fingerprints, canonicalization, and combined scanner evidence. |
| `app/graph/secret_context.py` | Private credentials, publishable keys, placeholders, and storage identifiers have deterministic classifications. Private roles and credential prefixes take precedence. |
| `app/graph/state.py` | Optional finding and mapping metadata. AuditState keys and reducers stay unchanged. |
| `app/graph/nodes/scan_secrets_pii.py` | Binary extension, signature, null-byte, control-byte, and UTF-8 checks. Contextual numeric validation, Luhn checks, assignment semantics, and redacted output. Gitleaks context validation retains genuine secrets in examples. |
| `app/graph/nodes/semgrep.py` | Preserve raw severity, rule, location, selected scanner metadata, and normalized severity. Test applicability and audit-rule confidence affect penalties. `--config auto` stays. |
| `app/graph/nodes/osv.py` | Preserve package version, ecosystem, available scope/directness, manifests, and all advisory summaries and aliases. Repeated advisory records retain maximum severity independent of input order. |
| `app/graph/nodes/compliance_mapper.py` | Canonicalization replaces rule-only deduplication. Deterministic personal-data relevance gates privacy mapping. Backend issues and private credentials can gain likely relevance from schema evidence. |
| `app/mapper/controls.py` | Associate explanations by fingerprint, retain deterministic mappings when model enrichment fails, and select application-code remediation without package-update fallbacks. AES-GCM advice addresses nonce and authentication-tag handling. |
| `app/mapper/rag_mapper.py` | Models receive categories and selected controls instead of source evidence. Enrichment changes explanation text and provenance only. Embedding imports occur only when needed. |
| `app/data_scan/pii_field_patterns.py` | Authentication fields are excluded from Article 9 categories. True special-category indicators remain. |
| `app/graph/nodes/scan_data_classification.py` | Schema observations carry evidence confidence and personal-data relevance. DPDP safeguards are not described as an Article 9 equivalent. |

Scoring retains the existing severity deductions and framework weighting. Each canonical issue contributes once per framework. The deduction is severity weight multiplied by confidence and applicability, each constrained to the range zero to one. Mapping-specific factors can lower a framework's deduction. Missing metadata retains legacy full weight when scoring findings directly. OSV package versions contribute their maximum advisory severity once, with applicability reflecting available dependency scope and unproven reachability. All advisories remain visible. Five independent high-confidence production critical issues still reduce a framework to zero. Model output cannot select controls, eligibility, confidence, applicability, or numeric scores.

The regression results for the supplied cases are fixture results, not new audits of the complete public repositories.

| Case | Before | Tested result |
| --- | --- | --- |
| HGhub | Test password, query-token digits, and image bytes became PII. | The supplied inline Rust test and URL produce no findings. PNG, JPG, and disguised binary fixtures produce no findings. Genuine private credentials in tests remain critical. |
| Recordly | Timestamp filenames and a UI ternary became PII. Storage identifiers and audit rules could receive critical penalties. Password schema fields became Article 9 data. | Exact timestamp and UI fixtures produce no PII findings. Versioned storage identifiers are informational. Test-only Semgrep evidence remains visible with lower applicability. Audit/manual-sanitization and format-string rules have lower confidence. SQL email, password-hash, and salt fields do not map to Article 9. Health, biometric-template, and political-opinion fields still do. |
| ArthaSutra | Duplicate JWT findings, public client tokens, and a README demo email inflated penalties. | Same-value JWT findings at the same file and line merge with both scanner sources. Service-role and OpenRouter credentials remain critical in `.env.example`. Public anon keys are informational. The documented judge email produces no PII finding. |

A comparison against the original PII adapter reproduced nine noisy findings across the supplied text and binary fixtures. The patched adapter produces zero for that comparison. Positive controls independently retain real contextual email, phone, card, Aadhaar, and secret findings.

The tests added are `tests/test_finding_quality.py`, `tests/test_scanner_accuracy.py`, and `tests/test_mapping_accuracy.py`. `tests/test_semgrep.py` adds adapter regressions. Together they cover the sixteen requested failure modes, real-secret controls, multiple source locations, advisory aliases, severity ordering, model-output constraints, and review findings.

Verification uses Python 3.11 and the repository's pinned LangGraph, Pydantic, FastAPI, and Supabase versions. The complete suite passes with 211 tests, including the general scanner-context follow-up regressions. `python -m compileall -q app tests` also passes. In this environment, async tests hang under the sandbox's thread-wakeup restrictions on both Python 3.11 and 3.14. The full suite completes outside the sandbox. No real scanner binaries, remote model endpoints, or production audit services were invoked by these regression tests.

Remaining limits are explicit.

- Phone and Aadhaar detection requires contextual evidence and can miss unlabeled real values. Aadhaar validation uses context rather than a Verhoeff checksum.
- Binary and text checks skip non-UTF-8 sources and files larger than 1 MB.
- Secret classification does not verify a credential against its provider. An unknown credential remains serious. Supported public-key semantics do not cover every provider.
- Cross-tool secret merging requires the same normalized path, source line, and value hash. Different scanner line ranges or historical line movement can leave duplicates. Distinct source locations remain visible.
- Schema names and backend paths are evidence heuristics. They do not prove runtime processing or exploitability. Unknown privacy relevance receives no automatic privacy mapping.
- Dependency directness and scope remain unknown when OSV does not supply them. OSV alone does not prove runtime reachability.
- The existing PII scanner requires `git ls-files`. ZIP uploads without Git metadata still do not receive local regex PII scanning.
- Cached reports retain the existing cache policy, including the 24-hour TTL for commit-based keys. Previously cached scores are not rewritten by this patch.
- Scores for the complete HGhub, Recordly, and ArthaSutra repositories have not been recomputed. Historical score comparisons require fresh full audits.

Article 9 categories were checked against the official [GDPR text](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679). DPDP references were checked against [India Code](https://www.indiacode.nic.in/indiacode/handle/123456789/22037?view_type=browse) and the [MeitY rules publication](https://www.meity.gov.in/documents/act-and-policies/digital-personal-data-protection-rules-2025-gDOxUjMtQWa?pageTitle=Digital-Personal-Data-Protection-Rules-2025). This patch does not replace the product's regulatory catalog.

The follow-up scanner changes classify test-runner configs, localization files, legal notices, and generated attributions. Clear fixtures, UI labels, and storage identifiers are suppressed before mapping. Generic Gitleaks candidates remain likely findings unless private credential evidence establishes a confirmed exposure. Credit-card filtering rejects decimal, URL, filename, and identifier contexts before Luhn validation. Tests preserve weak production credentials, real API and admin passphrases in fixtures, and valid 13- and 19-digit card candidates. No repository-specific production rules were added.
