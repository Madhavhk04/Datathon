# Sentinel SOC Command Center

Professional, local-only React/Vite dashboard for the committed Track 2
analytics. It is read-only: the UI and API never write to `data/`.

## Run locally

From the repository root:

```powershell
# Terminal 1
python -m venv .venv
.\.venv\Scripts\pip install -r backend\requirements.txt
.\.venv\Scripts\python -m uvicorn backend.main:app --reload --port 8000

# Terminal 2
cd dashboard
npm install
npm run dev
```

Open http://localhost:5173. If the API is unavailable, the frontend shows a
small clearly-labelled demo fallback so the shell remains navigable.

## Data contract

`backend/main.py` resolves paths relative to the repository and reads:
`data/analytics/investigation_queue.csv`, `threat_detections.csv`, and
`user_risk_scores.csv`. CSV schemas remain owned by the analytics pipeline.
`GET /api/snapshot` returns `{meta, queue, threats, risk}` and
`GET /api/health` is a lightweight readiness check.

The Analyst workspace is deliberately a placeholder. Its documented contract
is `POST /api/analyst/query` with `{question, context?}` and a response
`{answer, citations: [{source, row_id, field}], suggested_actions: []}`.
The teammate integration must remain local, cite evidence, and not mutate CSVs.
