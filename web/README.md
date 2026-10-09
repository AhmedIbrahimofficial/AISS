# AISS Web — Autonomous Security (Vercel)

Unified Next.js product: one dashboard, Security Gate, incident pipeline, and Groq tool-calling AI.

## What works

- **One-time setup** → admin account + org
- **Security Gate** — inspect file / URL / IP / process / text → ALLOW · HOLD · QUARANTINE · BLOCK
- **Incident pipeline** — Detect → Isolate → Analyze → Contain → Remediate → Verify → Learn
- **Approval gates** for HIGH / CRITICAL containment
- **Groq Security Reasoning Layer** with real tools (`inspect_artifact`, `list_threats`, approvals, etc.)
- **Health checks** at `/api/health`

> Host OS kill/quarantine from a laptop agent is still in `../backend` (Python). This Vercel app is the cloud control plane that actually stores decisions, runs the gate, and drives AI tooling.

## Quick start (local)

```bash
cd web
cp .env.example .env.local
# set GROQ_API_KEY and SECRET_KEY
npm install
npm run dev
```

Open http://localhost:3000 → complete setup → dashboard.

## Deploy to Vercel

1. Import this repo (set **Root Directory** to `web`)
2. Add env vars: `GROQ_API_KEY`, `SECRET_KEY`
3. Deploy
4. Open the URL → one-time setup

```bash
cd web
npx vercel
```

## Demo the Gate

1. Security Gate tab → leave the EICAR sample → **Run Security Gate** → expect **BLOCK** + incident
2. AI Reasoning → “List threats and explain the highest risk one”
3. For HIGH/CRITICAL with approval required → Pipeline tab → Approve / Reject

## Scripts

| Command        | Purpose              |
|----------------|----------------------|
| `npm run dev`  | Local development    |
| `npm run build`| Production build     |
| `npm run start`| Serve production     |
