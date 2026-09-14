"""Read-only local API for the SOC dashboard.

CSV paths are resolved from this file, so the API works regardless of the
directory from which uvicorn is launched. The source files are never written.
"""
from pathlib import Path
import csv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

ROOT = Path(__file__).resolve().parents[1]
ANALYTICS = ROOT / "data" / "analytics"
PROCESSED = ROOT / "data" / "processed"
app = FastAPI(title="Sentinel SOC local API", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["GET"], allow_headers=["*"])

def load(name: str):
    with (ANALYTICS / name).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

def number(row, key):
    try: return float(row.get(key, "") or 0)
    except (TypeError, ValueError): return 0

@app.get("/api/health")
def health(): return {"status": "ok", "mode": "read-only"}

@app.get("/api/snapshot")
def snapshot():
    queue, threats, risk = load("investigation_queue.csv"), load("threat_detections.csv"), load("user_risk_scores.csv")
    for r in risk: r["risk_score"] = number(r, "risk_score")
    for r in queue:
        r["risk_score"] = number(r, "risk_score")
        r["threat_detection_count"] = int(number(r, "threat_detection_count"))
    critical = sum(1 for r in risk if r.get("risk_level") == "Critical")
    quality = []
    for path in sorted(PROCESSED.glob("*.csv")):
        with path.open(encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            rows = sum(1 for _ in reader)
            quality.append({"source": path.stem.replace("_clean", "").replace("track2_", "").replace("_", " ").title(),
                            "status": "Reviewed", "coverage": f"{rows:,} rows", "issues": "Schema available"})
    return {"meta": {"users": len(risk), "threats": len(threats), "queue": len(queue), "critical": critical},
            "risk": risk, "threats": threats, "queue": queue, "quality": quality}
