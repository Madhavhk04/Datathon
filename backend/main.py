import sys
from pathlib import Path
import csv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any

ROOT = Path(__file__).resolve().parents[1]
AGENT_DIR = ROOT / "agent"
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except ImportError:
    pass

try:
    from agent import investigate_user, chat_with_analyst
    from tools import resolve_target_user_id
    AGENT_AVAILABLE = True
except Exception as e:
    print(f"[WARN] Failed to load agent modules: {e}")
    AGENT_AVAILABLE = False

ANALYTICS = ROOT / "data" / "analytics"
PROCESSED = ROOT / "data" / "processed"

app = FastAPI(title="Sentinel API", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def normalize_path_middleware(request, call_next):
    import re
    path = request.scope.get("path", "")
    if "//" in path:
        request.scope["path"] = re.sub(r"/+", "/", path)
    return await call_next(request)

def load(name: str):
    with (ANALYTICS / name).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

def number(row, key):
    try: return float(row.get(key, "") or 0)
    except (TypeError, ValueError): return 0

class AnalystQueryRequest(BaseModel):
    question: Optional[str] = None
    query: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    context_user_id: Optional[str] = None
    history: Optional[list] = None

@app.get("/api/health")
@app.get("/health")
def health():
    return {"status": "ok", "mode": "read-only", "agent_available": AGENT_AVAILABLE}

@app.get("/api/snapshot")
@app.get("/snapshot")
def snapshot():
    queue, threats, risk = load("investigation_queue.csv"), load("threat_detections.csv"), load("user_risk_scores.csv")
    for r in risk: r["risk_score"] = number(r, "risk_score")
    for r in queue:
        r["risk_score"] = number(r, "risk_score")
        r["threat_detection_count"] = int(number(r, "threat_detection_count"))
    critical = sum(1 for r in risk if str(r.get("risk_level", "")).strip().capitalize() == "Critical")
    quality = []
    for path in sorted(PROCESSED.glob("*.csv")):
        with path.open(encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            rows = sum(1 for _ in reader)
            quality.append({"source": path.stem.replace("_clean", "").replace("track2_", "").replace("_", " ").title(),
                            "status": "Reviewed", "coverage": f"{rows:,} rows", "issues": "Schema available"})
    return {"meta": {"users": len(risk), "threats": len(threats), "queue": len(queue), "critical": critical},
            "risk": risk, "threats": threats, "queue": queue, "quality": quality}

@app.post("/api/analyst/query")
@app.post("/analyst/query")
def analyst_query(req: AnalystQueryRequest):
    if not AGENT_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI Analyst Agent not loaded")
    
    q = (req.question or req.query or "").strip()
    context_user = ""
    if req.context and isinstance(req.context, dict) and req.context.get("user_id"):
        context_user = str(req.context["user_id"]).strip()
    elif req.context_user_id:
        context_user = str(req.context_user_id).strip()
    
    history = req.history or []
    
    return chat_with_analyst(q, history=history, context_user_id=context_user)


@app.get("/api/investigate/{user_id}")
@app.post("/api/investigate/{user_id}")
@app.get("/investigate/{user_id}")
@app.post("/investigate/{user_id}")
def investigate(user_id: str):
    if not AGENT_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI Analyst Agent not loaded")
    res = investigate_user(user_id)
    if isinstance(res, dict) and "overall_risk" in res and "risk" not in res:
        res["risk"] = res["overall_risk"]
    return res

# Sentinel API reloaded v3


