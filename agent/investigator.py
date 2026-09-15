from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class RiskOverview(BaseModel):
    score: float
    band: str
    breakdown: Optional[Dict[str, float]] = None

class EvidenceItem(BaseModel):
    timestamp: str
    source: str
    event_type: str
    severity: str
    details: str

class ChartPoint(BaseModel):
    timestamp: str
    severity_level: int
    event_source: str
    event_type: str

class InvestigationReport(BaseModel):
    user_id: str
    user_name: str
    employment_status: str
    investigation_timestamp: str
    overall_risk: RiskOverview
    key_drivers: List[str] = Field(description="Primary factors contributing to the risk score")
    active_threats: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_timeline: List[EvidenceItem] = Field(default_factory=list)
    chart_data: List[ChartPoint] = Field(default_factory=list, description="Severity over time chart dataset")
    critical_findings: List[str] = Field(description="Evidence-backed critical security findings, including post-termination alerts if present")
    recommended_next_steps: List[str] = Field(description="Actionable containment and mitigation recommendations")
