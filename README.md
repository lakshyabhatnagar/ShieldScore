# ShieldScore

ShieldScore audits a source-code repository and turns technical security findings into a report organised around SOC 2, ISO 27001, GDPR, and India's DPDP framework. It accepts a GitHub, GitLab, Bitbucket, or other Git URL, as well as a ZIP upload.

It is a developer-assistance tool, not a certification service or a substitute for a professional security assessment.

Maintained by Lakshya.

## What happens during an audit

```text
Repository URL or ZIP
        ↓
Orchestrator prepares a temporary local copy
        ↓
Nine scanners run in parallel
        ↓
Scanner Merge collects their findings
        ↓
Compliance Mapper links findings to controls
        ↓
Report Generator calculates scores and writes the summary
```

The pipeline has 14 LangGraph nodes: two setup nodes, nine scanners, a merge node, a compliance-mapping node, and a report-generation node. A **node** is one step in the workflow; LangGraph coordinates the order and parallel execution of those steps.

| Area | Scanner | Examples of checks |
| --- | --- | --- |
| Application code | Semgrep | insecure patterns, injection risks, XSS, and configuration issues |
| Dependencies | OSV-Scanner | known vulnerabilities in package dependencies |
| GitHub configuration | GitHub API | repository visibility and branch-protection signals |
| Secrets and personal data | Gitleaks and local patterns | credentials, emails, phone numbers, Aadhaar-like values |
| Repository governance | local files and GitHub data | `SECURITY.md`, `CODEOWNERS`, signing and review signals |
| Software supply chain | Syft and package metadata | SBOM data, license concerns, stale dependencies |
| Infrastructure as code | Checkov | Terraform, CloudFormation, and Kubernetes misconfiguration |
| CI/CD | YAML parser | plaintext secrets and missing pipeline safeguards |
| Data modelling | schema parsers | potentially sensitive fields and encryption signals |

## Repository layout

```text
app/
  graph/          LangGraph workflow, node state, and progress tracking
  graph/nodes/    individual scanners, mapper, and report generator
  mapper/         framework control mappings and optional RAG support
  middleware/     API-key and rate-limit middleware
  routers/        FastAPI audit endpoints
  utils/          configuration, Git/ZIP handling, caching, and LLM helpers
frontend/         Next.js audit dashboard
tests/            backend unit tests
scripts/          optional setup and diagnostic scripts
```

## Requirements

- Python 3.11 or newer
- [uv](https://docs.astral.sh/uv/)
- Git
- Node.js 22.13 or newer for the frontend
- A Groq API key to generate mapped reports

Optional scanners improve coverage but are not required for the server to start: Semgrep, OSV-Scanner, Syft, Checkov, and Gitleaks. If one is not installed, its node reports no findings; that does **not** mean the repository is clean in that area.

## Run locally

### 1. Configure the backend

```bash
cp .env.example .env
```

Open `.env` and set at least:

```dotenv
GROQ_API_KEY=your_groq_key
# Required when using the frontend on port 3001:
CORS_ORIGINS=http://localhost:3001
```

Optional values:

| Variable | Purpose |
| --- | --- |
| `GITHUB_TOKEN` | increases GitHub API access and rate limits |
| `SUPABASE_URL`, `SUPABASE_KEY` | enables the optional cache/vector-store integration |
| `AUDIT_API_KEY` | protects `/api/*`; leave empty only for local development |
| `LLM_MODEL` | overrides the default Groq model |
| `ALLOWED_HOSTS` | accepted HTTP host names in a deployment |

Never commit `.env`. It is ignored by Git; `.env.example` is the safe template.

### 2. Start the backend

```bash
uv sync
uv run uvicorn app.main:app --reload --port 8000
```

Confirm that it is running:

```bash
curl http://127.0.0.1:8000/health
```

### 3. Start the frontend

In a second terminal:

```bash
cd frontend
source /Users/dinesh/.nvm/nvm.sh  # only if you use nvm
nvm use 22
npm install
npm run dev -- --port 3001
```

Open `http://localhost:3001`. The dashboard calls `http://127.0.0.1:8000` by default. To use another backend address, create `frontend/.env` with:

```dotenv
NEXT_PUBLIC_API_BASE_URL=https://api.example.com
```

## Use the dashboard

1. Enter `AUDIT_API_KEY` if the backend has one configured.
2. Choose **GitHub**, **Git URL**, or **Upload ZIP**.
3. Supply a public repository URL or select a ZIP file.
4. Select **Audit**.
5. Watch node status in the pipeline graph, then filter the completed findings by framework or severity.

The frontend shows a clearly labelled demonstration report if it cannot reach the backend. A real report requires the backend and its configured services/tools.

## API overview

All routes are prefixed with `/api`. When `AUDIT_API_KEY` is configured, send it in the `X-API-Key` header.

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/audit/start` | starts an asynchronous URL-based audit |
| `POST` | `/audit/upload` | uploads a ZIP and starts an audit |
| `GET` | `/audit/{audit_id}/status` | returns node-level progress |
| `GET` | `/audit/{audit_id}/results` | returns the completed report |
| `GET` | `/audit/status` | returns the static graph-node list |
| `POST` | `/audit` | legacy synchronous audit endpoint |

For `POST /api/audit/start`, use JSON such as:

```json
{ "repo_url": "https://github.com/owner/repository" }
```

## Scores and framework mapping

Each framework starts at 100. Findings reduce it by severity:

```text
critical −20 | high −10 | medium −3 | low −1 | info 0
```

The overall score is a weighted result:

```text
SOC 2 × 35% + ISO 27001 × 25% + GDPR × 25% + DPDP × 15%
```

A mapping is evidence for prioritisation, not proof of legal compliance. Control applicability depends on the organisation, systems, contracts, and jurisdiction.

## Temporary repository handling

The browser does not clone a Git repository. The backend clones or extracts it into the temporary storage of the machine/container where the API is running. Scanner paths are stripped from report output, and normal completion cleans up the temporary directory.

For a production deployment, use ephemeral container storage and a cleanup policy: an unexpected process crash can leave temporary data until the host or platform removes it.

## Test and build

Backend:

```bash
uv run pytest
```

Frontend:

```bash
cd frontend
source /Users/dinesh/.nvm/nvm.sh
nvm use 22
npx tsc --noEmit
npm run lint
npm run build
npm test
```

## Deploy the backend

The Docker image listens on port `8080`. The production Compose configuration binds it to `127.0.0.1:8080`, so place a reverse proxy such as Nginx in front of it.

```bash
cp .env.example .env
# Set production secrets and allowed origins/hosts in .env
docker compose -f compose.production.yml up -d --build
```

Use `nginx.conf.example` as the reverse-proxy starting point. Expose only HTTPS through the proxy; keep port `8080` private. Set a strong `AUDIT_API_KEY`, the deployed frontend URL in `CORS_ORIGINS`, and the API domain in `ALLOWED_HOSTS`.

## Useful terms

- **SAST**: static application security testing—checking source code without running it.
- **SBOM**: software bill of materials—a dependency inventory.
- **CVE**: a published identifier for a known security vulnerability.
- **PII**: personally identifiable information, such as an email address or phone number.
- **IaC**: infrastructure as code—cloud configuration stored as files.
- **RAG**: retrieval-augmented generation—supplying relevant stored reference material to an LLM before it answers.
