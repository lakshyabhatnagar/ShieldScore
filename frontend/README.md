# ShieldScore frontend

ShieldScore is a responsive repository-security audit dashboard. It visualises
the 14-node audit pipeline and presents framework scores, severity totals, and
evidence-backed findings.

## Setup

Use Node.js 22 or newer, then install dependencies:

```bash
npm install
```

## Commands

```bash
npm run dev
npm run build
npm run lint
npx tsc --noEmit
```

The app calls `http://127.0.0.1:8000` by default. Set
`NEXT_PUBLIC_API_BASE_URL` when the backend is elsewhere.

## Project structure

- `app/components/audit-dashboard.tsx` — source form, audit execution, and demo fallback
- `app/components/pipeline.tsx` — animated audit graph
- `app/components/report.tsx` — scores, severity summary, and filtered findings
- `app/lib/audit.ts` — shared types, graph definitions, and demo report data
- `app/globals.css` — responsive design tokens and component styles

## Implemented interactions

- GitHub URL, generic Git URL, and ZIP source tabs
- Session-only audit key, validation, and clear/cancel action
- Live backend polling when the API is available
- Local animated demonstration report if the backend cannot be reached
- Framework and severity filtering for findings
- Keyboard-focusable controls and responsive layouts
