# ShieldScore frontend

The ShieldScore frontend is a Next.js dashboard for starting repository audits, following the 14-node execution graph, and reading the resulting framework scores and findings.

## Requirements

- Node.js 22.13 or newer
- The ShieldScore backend running locally or deployed somewhere reachable

## Setup

```bash
source /Users/dinesh/.nvm/nvm.sh  # only if you use nvm
nvm use 22
npm install
```

By default, the dashboard calls `http://127.0.0.1:8000`. To use a different backend, create `.env` in this directory:

```dotenv
NEXT_PUBLIC_API_BASE_URL=https://api.example.com
```

`NEXT_PUBLIC_*` values are bundled into the browser application. Never put `AUDIT_API_KEY`, Groq keys, or any other secret in this file.

## Run

```bash
npm run dev -- --port 3001
```

Open `http://localhost:3001`. When running locally, set the backend's `CORS_ORIGINS` value to `http://localhost:3001`.

## Commands

```bash
npm run dev -- --port 3001  # development server
npx tsc --noEmit            # type check
npm run lint                # lint
npm run build               # production build
npm test                    # build plus frontend source test
```

## User flow

1. Enter the backend access key if one is configured.
2. Choose a GitHub URL, generic Git URL, or ZIP archive.
3. Start the audit and follow setup, parallel scanning, merge, mapping, and reporting states.
4. Review framework scores, severity totals, executive summary, and filtered findings.

The UI provides a labelled demo result when the API cannot be reached. It is useful for trying the interface; it is not a real audit result.

## Project structure

| Path | Responsibility |
| --- | --- |
| `app/components/audit-dashboard.tsx` | source form, API calls, polling, and demo fallback |
| `app/components/pipeline.tsx` | responsive execution graph and node-state animation |
| `app/components/report.tsx` | score cards, severity chart, and finding filters |
| `app/lib/audit.ts` | types, graph definitions, API base URL, and demo data |
| `app/globals.css` | shared design tokens and responsive styles |
| `public/favicon.svg` | ShieldScore favicon |

## Accessibility and interaction

All controls use native form elements or buttons, have keyboard focus styles, and react visibly to disabled, loading, completed, error, and filter states. The pipeline scrolls horizontally inside its panel on narrow screens so the page itself does not overflow.
