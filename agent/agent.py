import os
import sys
import json
import argparse
from datetime import datetime

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from tools import (
    get_user_risk,
    get_user_threats,
    get_identity_context,
    build_evidence_timeline,
    get_iam_events,
    get_endpoint_events,
    get_firewall_events,
    get_related_hosts
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
    Executes real analytics tools against production datasets, analyzes evidence,
    applies guardrails (post-termination check, temporal correlation),
    and structures the JSON output strictly matching InvestigationReport schema.
    """
    risk_data = get_user_risk(user_id)
    threat_data = get_user_threats(user_id)
    identity_data = get_identity_context(user_id)
    timeline_data = build_evidence_timeline(user_id)

    uid = identity_data.get("user_id") or risk_data.get("user_id") or str(user_id)
    user_name = identity_data.get("user_name", "Unknown User")
    emp_status = str(identity_data.get("employment_status", "Active"))
    term_date = str(identity_data.get("termination_date", "")).strip()

    score = float(risk_data.get("risk_score", 0.0))
    band = str(risk_data.get("risk_band", "Low")).upper()
    breakdown = risk_data.get("score_breakdown", {})

    key_drivers = []
    critical_findings = []
    next_steps = []

    # 1. Parse real analytical risk drivers
    raw_drivers = risk_data.get("risk_drivers", "")
    if raw_drivers and raw_drivers != "Routine activity monitoring.":
        for part in raw_drivers.split(";"):
            part_clean = part.strip()
            if part_clean:
                key_drivers.append(part_clean[0].upper() + part_clean[1:])

    # 2. Check active threats from threat_detections.csv
    active_threats = threat_data.get("threat_detections", [])
    for t in active_threats:
        t_name = t.get("threat_name")
        t_sev = t.get("severity")
        key_drivers.append(f"Active Threat Detection: {t_name} ({t_sev})")

    # 3. Check post-termination activity
    events = timeline_data.get("timeline", [])
    post_term_detected = risk_data.get("post_termination_flag", False)
    
    if not post_term_detected and term_date and term_date.lower() != "nan" and emp_status.upper() in ["DISABLED", "INACTIVE", "TERMINATED"]:
        for ev in events:
            ev_ts = str(ev.get("timestamp", ""))
            if ev_ts and ev_ts > term_date:
                post_term_detected = True
                break

    if post_term_detected:
        critical_findings.append(
            f"CRITICAL: Unauthorized post-termination activity detected for user {uid} ({user_name}) after termination date {term_date}."
        )
        next_steps.append("Immediately revoke all active identity credentials, SSO tokens, and IAM session access.")
        assigned_host = identity_data.get("hostname")
        if assigned_host and assigned_host != "N/A":
            next_steps.append(f"Isolate assigned endpoint device ({assigned_host}) from the enterprise network.")

    # 4. Critical findings from threats and telemetry
    for t in active_threats:
        ev_note = f" — Evidence: {t.get('evidence')}" if t.get("evidence") else ""
        critical_findings.append(
            f"Threat Detection [{t.get('threat_id')}]: {t.get('threat_name')} ({t.get('severity')}){ev_note}"
        )

    # 5. Device ID conflict
    if identity_data.get("device_id_conflict"):
        critical_findings.append(
            f"Device Ownership Conflict: Device {identity_data.get('device_id')} is linked to {identity_data.get('device_user_count')} different users."
        )

    # 6. Queue recommendations
    queue_info = threat_data.get("investigation_queue")
    if queue_info and queue_info.get("recommended_action"):
        next_steps.append(queue_info["recommended_action"])

    # 7. Escalation recommendations based on overall risk score
    if score >= 80:
        next_steps.append("Escalate case to Tier 2 Incident Response Team for priority containment.")
        next_steps.append("Collect endpoint forensic memory dump and inspect authentication audit logs.")
    elif score >= 50:
        next_steps.append("Schedule mandatory credential rotation and verify multi-factor authentication enrollment.")
    else:
        next_steps.append("Continue standard telemetry monitoring in triage queue.")

    # De-duplicate next steps while preserving order
    seen_steps = set()
    unique_steps = []
    for step in next_steps:
        if step not in seen_steps:
            seen_steps.add(step)
            unique_steps.append(step)

    # Build Pydantic model to guarantee schema validation
    report = InvestigationReport(
        user_id=str(uid),
        user_name=str(user_name),
        employment_status=str(emp_status),
        investigation_timestamp=datetime.utcnow().isoformat() + "Z",
        overall_risk=RiskOverview(score=score, band=band, breakdown=breakdown),
        key_drivers=key_drivers if key_drivers else ["Routine activity monitoring."],
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
        recommended_next_steps=unique_steps
    )

    return report.model_dump()

def run_genai_investigation(user_id: str, api_key: str) -> dict:
    """
    Investigation runner using Google GenAI SDK with tool function calling loop
    connected to real production telemetry tools.
    """
    if not HAS_GENAI:
        print("[WARN] google-genai library not available. Falling back to local engine.")
        return run_local_investigation(user_id)

    client = genai.Client(api_key=api_key)

    tools_list = [
        get_user_risk,
        get_user_threats,
        get_identity_context,
        get_iam_events,
        get_endpoint_events,
        get_firewall_events,
        get_related_hosts,
        build_evidence_timeline
    ]

    prompt = (
        f"Conduct a security investigation for user: {user_id}. Retrieve risk, threats, identity context, "
        f"and evidence timeline from the telemetry datasets, then synthesize a structured investigation report JSON."
    )

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
    Main entrypoint for investigating a target user ID.
    Checks for GEMINI_API_KEY environment variable.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if api_key:
        return run_genai_investigation(user_id, api_key)
    else:
        return run_local_investigation(user_id)

if __name__ == "__main__":
    from tools import resolve_target_user_id
    parser = argparse.ArgumentParser(description="AI Security Investigation Agent")
    parser.add_argument("--user", type=str, default=None, help="Target User ID to investigate (defaults to highest risk user)")
    args = parser.parse_args()

    target_user = args.user or resolve_target_user_id("")
    print(f"\n==================================================")
    print(f"  AI SECURITY INVESTIGATION AGENT")
    print(f"  Target User: {target_user}")
    print(f"==================================================\n")

    result = investigate_user(target_user)
    print(json.dumps(result, indent=2))
