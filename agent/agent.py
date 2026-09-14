import os
import sys
import json
import argparse
from datetime import datetime

from tools import (
    get_user_risk,
    get_user_threats,
    get_identity_context,
    build_evidence_timeline
)
from prompts import SYSTEM_INSTRUCTION
from investigator import InvestigationReport, RiskOverview, EvidenceItem, ChartPoint

# Try importing google.genai
try:
    from google import genai
    from google.genai import types
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

def run_local_investigation(user_id: str) -> dict:
    """
    Local deterministic investigation engine.
    Executes the 4 tools, analyzes evidence, applies guardrails (e.g. post-termination check),
    and structures the JSON output according to InvestigationReport schema.
    """
    risk_data = get_user_risk(user_id)
    threat_data = get_user_threats(user_id)
    identity_data = get_identity_context(user_id)
    timeline_data = build_evidence_timeline(user_id)

    user_name = identity_data.get("user_name", "Unknown User")
    emp_status = identity_data.get("employment_status", "ACTIVE")
    term_date = identity_data.get("termination_date", "")

    score = risk_data.get("risk_score", 0)
    band = risk_data.get("risk_band", "LOW")
    breakdown = risk_data.get("score_breakdown", {})

    key_drivers = []
    critical_findings = []
    next_steps = []

    # Check breakdown high scores
    for dim, dscore in breakdown.items():
        if dscore >= 75:
            key_drivers.append(f"Elevated risk in {dim.replace('_', ' ').title()} ({dscore}/100)")

    # Check active threats
    active_threats = threat_data.get("threat_detections", [])
    for t in active_threats:
        key_drivers.append(f"Active Threat Detection: {t.get('threat_name')} ({t.get('severity')})")

    # Check timeline for post-termination activity
    events = timeline_data.get("timeline", [])
    post_term_detected = False
    if emp_status == "TERMINATED" and term_date:
        for ev in events:
            if ev.get("timestamp", "") > term_date:
                post_term_detected = True
                break

    if post_term_detected:
        critical_findings.append(
            f"CRITICAL: Post-termination activity detected for user {user_id} ({user_name}) after termination date {term_date}."
        )
        next_steps.append("Immediately revoke all active identity credentials and SSO tokens.")
        next_steps.append("Isolate all assigned endpoints associated with former employee.")

    if active_threats:
        critical_findings.append(f"Found {len(active_threats)} active threat detection(s) requiring analyst review.")

    if score >= 80:
        next_steps.append("Escalate case to Tier 2 Incident Response Team.")
        next_steps.append("Perform full memory and disk forensic dump on compromised host.")
    elif score >= 50:
        next_steps.append("Schedule identity credential rotation and MFA reset.")
    else:
        next_steps.append("Monitor user activity in standard triage log queue.")

    if not next_steps:
        next_steps.append("No immediate containment action required. Continue standard monitoring.")

    # Build Pydantic model to guarantee schema validation
    report = InvestigationReport(
        user_id=str(user_id),
        user_name=str(user_name),
        employment_status=str(emp_status),
        investigation_timestamp=datetime.utcnow().isoformat() + "Z",
        overall_risk=RiskOverview(score=score, band=band, breakdown=breakdown),
        key_drivers=key_drivers if key_drivers else ["Routine activity monitoring"],
        active_threats=active_threats,
        evidence_timeline=[
            EvidenceItem(
                timestamp=ev.get("timestamp", ""),
                source=ev.get("source", ""),
                event_type=ev.get("event_type", ""),
                severity=ev.get("severity", ""),
                details=ev.get("details", "")
            )
            for ev in events
        ],
        chart_data=[
            ChartPoint(
                timestamp=cp.get("timestamp", ""),
                severity_level=cp.get("severity_level", 0),
                event_source=cp.get("event_source", ""),
                event_type=cp.get("event_type", "")
            )
            for cp in timeline_data.get("chart_data", [])
        ],
        critical_findings=critical_findings if critical_findings else ["No critical security anomalies detected."],
        recommended_next_steps=next_steps
    )

    return report.model_dump()

def run_genai_investigation(user_id: str, api_key: str) -> dict:
    """
    Investigation runner using Google GenAI SDK with tool function calling loop.
    """
    if not HAS_GENAI:
        print("[WARN] google-genai library not available. Falling back to local engine.")
        return run_local_investigation(user_id)

    client = genai.Client(api_key=api_key)

    # Tool definitions mapping
    tool_map = {
        "get_user_risk": get_user_risk,
        "get_user_threats": get_user_threats,
        "get_identity_context": get_identity_context,
        "build_evidence_timeline": build_evidence_timeline,
    }

    tools_list = [get_user_risk, get_user_threats, get_identity_context, build_evidence_timeline]

    prompt = f"Conduct a security investigation for user ID: {user_id}. Retrieve risk, threats, identity context, and timeline, then return a structured investigation report JSON."

    config = types.GenerateContentConfig(
        system_instruction=SYSTEM_INSTRUCTION,
        tools=tools_list,
        temperature=0.1,
        response_mime_type="application/json",
        response_schema=InvestigationReport
    )

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config=config
        )
        if response.text:
            return json.loads(response.text)
    except Exception as e:
        print(f"[WARN] Gemini API call exception: {e}. Falling back to local engine.")

    return run_local_investigation(user_id)

def investigate_user(user_id: str) -> dict:
    """
    Main entrypoint for investigating a user ID.
    Checks for GEMINI_API_KEY environment variable.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if api_key:
        return run_genai_investigation(user_id, api_key)
    else:
        return run_local_investigation(user_id)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Security Investigation Agent")
    parser.add_argument("--user", type=str, default="USR-1001", help="Target User ID to investigate")
    args = parser.parse_args()

    print(f"\n==================================================")
    print(f"  AI SECURITY INVESTIGATION AGENT")
    print(f"  Target User: {args.user}")
    print(f"==================================================\n")

    result = investigate_user(args.user)
    print(json.dumps(result, indent=2))
