import os
import sys
import json
import re
import argparse
from datetime import datetime

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from tools import (
    _get_df,
    get_user_risk,
    get_user_threats,
    get_identity_context,
    build_evidence_timeline,
    get_iam_events,
    get_endpoint_events,
    get_firewall_events,
    get_related_hosts,
    resolve_target_user_id,
    resolve_target_user_ids
)
from prompts import SYSTEM_INSTRUCTION
from investigator import InvestigationReport, RiskOverview, EvidenceItem, ChartPoint

# Try importing google.genai SDK
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

MODEL_CANDIDATES = [
    "gemini-3.6-flash",
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-1.5-flash"
]

def _call_genai(client, prompt: str, system_instruction: str = None, schema=None, temperature=0.1) -> str:
    """Helper to try candidate models in order until one succeeds."""
    from google.genai import types
    config_args = {"temperature": temperature}
    if system_instruction:
        config_args["system_instruction"] = system_instruction
    if schema:
        config_args["response_mime_type"] = "application/json"
        config_args["response_schema"] = schema

    config = types.GenerateContentConfig(**config_args)

    for m in MODEL_CANDIDATES:
        try:
            res = client.models.generate_content(model=m, contents=prompt, config=config)
            if res and res.text:
                return res.text
        except Exception as e:
            continue
    raise RuntimeError("All Gemini model candidates failed or returned empty response.")

def run_genai_investigation(user_id: str, api_key: str) -> dict:
    """
    Investigation runner using Google GenAI SDK to synthesize structured investigation report JSON.
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
        for model_name in MODEL_CANDIDATES:
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=config
                )
                if response.text:
                    return json.loads(response.text)
            except Exception as e:
                continue

    except Exception as e:
        return run_local_investigation(user_id)

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
    Investigation runner using Google GenAI SDK to synthesize structured investigation report JSON.
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
        for model_name in MODEL_CANDIDATES:
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=config
                )
                if response.text:
                    return json.loads(response.text)
            except Exception as e:
                continue

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

# ==============================================================================
# REAL GROUNDED LLM ANALYST CHAT ENGINE
# ==============================================================================

def chat_with_analyst(question: str, history: list = None, context_user_id: str = None) -> dict:
    """
    Conversational LLM Analyst engine with multi-model fallback and deterministic safety.
    """
    from pydantic import BaseModel, Field
    import json
    import os
    
    q_strip = (question or "").strip()
    q_lower = q_strip.lower()

    # Determine if query mentions personal pronouns referencing a user
    has_pronouns = any(p in q_lower.split() for p in ["he", "she", "him", "her", "his", "hers", "this", "they", "them", "their", "user", "user's"])

    api_key = os.getenv("GEMINI_API_KEY")
    client = None
    if api_key and HAS_GENAI:
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
        except Exception as e:
            print(f"[WARN] Failed to initialize GenAI client: {e}")
            client = None

    if not client:
        return generate_grounded_fallback_response(q_strip, target_users=[], evidence_bundle={}, context_user_id=context_user_id)

    class QueryIntent(BaseModel):
        greeting: bool = Field(description="True if the query is a simple greeting or general help question like 'hello' or 'what can you do'")
        target_users: list[str] = Field(description="List of user IDs extracted from query or history")
        data_needed: list[str] = Field(description="List of data domains needed, e.g. 'identity', 'risk', 'endpoint', 'firewall', 'iam', 'threats'")
        ambiguous_context: bool = Field(description="True if context was ambiguous")

    history_str = ""
    if history and isinstance(history, list):
        recent_turns = history[-4:]
        history_str = "\n".join([f"{t.get('sender', 'user')}: {t.get('text', '')}" for t in recent_turns])

    intent_prompt = f"### CONVERSATION HISTORY\n{history_str if history_str else 'None'}\n\n### CURRENT CONTEXT USER ID: {context_user_id}\n\n### USER QUERY\n{q_strip}"

    intent = None
    try:
        from prompts import INTENT_SYSTEM_INSTRUCTION
        raw_intent = _call_genai(client, intent_prompt, system_instruction=INTENT_SYSTEM_INSTRUCTION, schema=QueryIntent, temperature=0.0)
        intent = json.loads(raw_intent)
    except Exception as e:
        print(f"[WARN] Intent parsing via Gemini failed: {e}")
        intent = {"greeting": False, "target_users": [], "data_needed": ["identity", "risk", "threats", "iam", "endpoint", "firewall"], "ambiguous_context": False}

    if intent and intent.get("greeting"):
        return {
            "answer": (
                "Hello! I am Sentinel AI, your Security Assistant connected to live enterprise telemetry streams.\n\n"
                "Here are some ways I can assist your security operations:\n"
                "• **Investigate a user**: *\"Investigate EMP11218\"*\n"
                "• **Explain risk drivers**: *\"Why is EMP11218 critical?\"*\n"
                "• **Inspect evidence**: *\"Show me the evidence for EMP11218\"* or *\"What happened on the endpoint?\"*\n"
                "• **Analyze network telemetry**: *\"How much network traffic occurred?\"*\n"
                "• **Compare users**: *\"Compare EMP11218 and EMP10296\"*\n"
                "• **Review IAM activity**: *\"What MFA failures did EMP11218 have?\"*\n"
                "• **System Overview**: *\"Show summary of threats\"* or *\"Summarize high risk users\"*"
            ),
            "active_user_id": context_user_id or "EMP11218",
            "target_users": [context_user_id] if context_user_id else [],
            "suggested_actions": ["Investigate EMP11218", "Why is EMP11218 critical?", "Compare EMP11218 and EMP10296"],
            "data_sources": ["Identity Asset Master", "IAM Audit Trail", "Endpoint Alerts", "Firewall Logs", "User Risk Scores", "Threat Detections"]
        }

    # 1. Check if query is a general concept question (e.g. "Explain MFA", "What is ITDR")
    explicit_q_users = resolve_target_user_ids(q_strip)
    concept_keywords = ["what is", "explain", "how does", "tell me about", "definition", "best practices", "cybersecurity"]
    is_concept_query = not explicit_q_users and any(k in q_lower for k in concept_keywords)

    if is_concept_query:
        return generate_grounded_fallback_response(q_strip, target_users=[], evidence_bundle={}, context_user_id=context_user_id)

    # 1b. Direct deterministic extraction from current question FIRST
    if explicit_q_users:
        not_found_users = [u.replace("NOT_FOUND:", "") for u in explicit_q_users if str(u).startswith("NOT_FOUND:")]
        if not_found_users:
            missing_id = not_found_users[0]
            answer = f"I don't have information for account **{missing_id}** in the available security datasets. Please verify the account ID (e.g., EMP11218, EMP10296) or select a valid account from the triage matrix."
            return {
                "answer": answer,
                "active_user_id": context_user_id or "EMP11218",
                "target_users": [],
                "evidence": {},
                "quick_actions": ["Investigate EMP11218", "Which accounts are critical?", "Show summary of threats"],
                "suggested_actions": ["Investigate EMP11218", "Which accounts are critical?"],
                "data_sources": ["Identity Asset Master"]
            }
        resolved_users = [u for u in explicit_q_users if not str(u).startswith("NOT_FOUND:")]
    else:
        raw_users = intent.get("target_users", []) if intent else []
        if not raw_users and context_user_id and has_pronouns:
            raw_users = [context_user_id]

        resolved_users = []
        for u in raw_users:
            res = resolve_target_user_ids(u)
            if res:
                resolved_users.extend(res)

        if not resolved_users and raw_users:
            resolved_users = [resolve_target_user_id(u) for u in raw_users]

    target_users = list(dict.fromkeys([u for u in resolved_users if u and not str(u).startswith("NOT_FOUND:")]))

    not_found_users = [u.replace("NOT_FOUND:", "") for u in resolved_users if str(u).startswith("NOT_FOUND:")]
    if not_found_users:
        missing_id = not_found_users[0]
        answer = f"I don't have information for account **{missing_id}** in the available security datasets. Please verify the account ID (e.g., EMP11218, EMP10296) or select a valid account from the triage matrix."
        return {
            "answer": answer,
            "active_user_id": context_user_id or "EMP11218",
            "target_users": [],
            "evidence": {},
            "quick_actions": ["Investigate EMP11218", "Which accounts are critical?", "Show summary of threats"],
            "suggested_actions": ["Investigate EMP11218", "Which accounts are critical?"],
            "data_sources": ["Identity Asset Master"]
        }

    needed = intent.get("data_needed", ["identity", "risk", "threats", "iam", "endpoint", "firewall"]) if intent else ["identity", "risk", "threats", "iam", "endpoint", "firewall"]
    if not needed:
        needed = ["identity", "risk", "threats", "iam", "endpoint", "firewall"]

    evidence_bundle = {}
    for uid in target_users:
        bundle = {}
        if "identity" in needed or "all" in needed:
            bundle["identity_master"] = get_identity_context(uid)
        if "risk" in needed or "all" in needed:
            bundle["risk_scores_and_drivers"] = get_user_risk(uid)
        if "threats" in needed or "all" in needed:
            bundle["active_threat_detections"] = get_user_threats(uid)
        if "iam" in needed or "all" in needed:
            bundle["iam_audit_events"] = get_iam_events(uid, limit=20)
        if "endpoint" in needed or "all" in needed:
            bundle["endpoint_edr_alerts"] = get_endpoint_events(uid, limit=20)
        if "firewall" in needed or "all" in needed:
            bundle["firewall_network_logs"] = get_firewall_events(uid, limit=20)
        if "evidence" in needed or "timeline" in needed or "all" in needed:
            bundle["evidence_timeline"] = build_evidence_timeline(uid, limit=30)

        evidence_bundle[uid] = bundle

    if not target_users:
        r_df = _get_df(os.path.join("analytics", "user_risk_scores.csv"))
        t_df = _get_df(os.path.join("analytics", "threat_detections.csv"))
        evidence_bundle["system_telemetry_snapshot"] = {
            "critical_risk_accounts": r_df[r_df["risk_level"].astype(str).str.lower() == "critical"][["user_id", "risk_score", "department", "risk_drivers"]].head(5).to_dict("records") if not r_df.empty else [],
            "top_threat_detections": t_df[["user_id", "threat_type", "severity"]].head(5).to_dict("records") if not t_df.empty else []
        }

    answer_text = ""
    try:
        from prompts import SYSTEM_INSTRUCTION
        prompt = (
            f"### SYSTEM INSTRUCTION\n{SYSTEM_INSTRUCTION}\n\n"
            f"### RECENT CONVERSATION HISTORY\n{history_str if history_str else 'None'}\n\n"
            f"### RETRIEVED TELEMETRY EVIDENCE (GROUNDED FACTS FROM DATASETS)\n"
            f"```json\n{json.dumps(evidence_bundle, indent=2)}\n```\n\n"
            f"### USER NATURAL-LANGUAGE QUESTION\n"
            f"\"{q_strip}\"\n\n"
            f"Answer the user's natural language question accurately and concisely based on retrieved telemetry evidence or general cybersecurity knowledge as appropriate."
        )

        answer_text = _call_genai(client, prompt, system_instruction=SYSTEM_INSTRUCTION, temperature=0.2)
    except Exception as e:
        print(f"[WARN] GenAI response generation failed: {e}. Falling back to grounded response generator.")
        return generate_grounded_fallback_response(q_strip, target_users=target_users, evidence_bundle=evidence_bundle, context_user_id=context_user_id)

    primary_user = target_users[0] if target_users else (context_user_id or "EMP11218")
    actions = [f"Investigate {primary_user}", f"Why is {primary_user} critical?", "Show evidence", "Compare EMP11218 and EMP10296"]

    return {
        "answer": answer_text,
        "active_user_id": primary_user,
        "target_users": target_users,
        "evidence": evidence_bundle,
        "quick_actions": actions,
        "suggested_actions": actions,
        "data_sources": [
            "Identity Asset Master",
            "IAM Audit Trail",
            "Endpoint Alerts",
            "Firewall Logs",
            "User Risk Scores",
            "Threat Detections"
        ]
    }


def generate_grounded_fallback_response(question: str, target_users: list = None, evidence_bundle: dict = None, context_user_id: str = None) -> dict:
    """
    Deterministic grounded response generator used if Gemini API is unreachable or fails.
    Answers specific questions strictly using retrieved telemetry or general cybersecurity knowledge.
    Returns a dictionary structured for the API endpoint.
    """
    q_strip = (question or "").strip()
    q_lower = q_strip.lower()
    
    if target_users is None:
        target_users = []
    if evidence_bundle is None:
        evidence_bundle = {}

    explicit_users = resolve_target_user_ids(q_strip)
    has_pronouns = any(p in q_lower.split() for p in ["he", "she", "him", "her", "his", "hers", "this", "they", "them", "their", "user", "user's"])
    
    # Check if query is a general concept query without explicit user ID
    concept_keywords = ["what is", "explain", "how does", "tell me about", "definition", "best practices", "cybersecurity"]
    is_concept = not explicit_users and any(k in q_lower for k in concept_keywords)

    if is_concept:
        target_users = []
    else:
        if not target_users:
            if explicit_users:
                target_users = explicit_users
            elif context_user_id and has_pronouns:
                target_users = [resolve_target_user_id(context_user_id)]

    not_found_users = [u.replace("NOT_FOUND:", "") for u in target_users if str(u).startswith("NOT_FOUND:")]
    if not_found_users:
        missing_id = not_found_users[0]
        answer = f"I don't have information for account **{missing_id}** in the available security datasets. Please verify the account ID (e.g., EMP11218, EMP10296) or select a valid account from the triage matrix."
        return {
            "answer": answer,
            "active_user_id": context_user_id or "EMP11218",
            "target_users": [],
            "evidence": {},
            "quick_actions": ["Investigate EMP11218", "Which accounts are critical?", "Show summary of threats"],
            "suggested_actions": ["Investigate EMP11218", "Which accounts are critical?"],
            "data_sources": ["Identity Asset Master"]
        }

    # Auto-populate evidence_bundle if needed
    for uid in target_users:
        if uid not in evidence_bundle:
            evidence_bundle[uid] = {
                "identity_master": get_identity_context(uid),
                "risk_scores_and_drivers": get_user_risk(uid),
                "active_threat_detections": get_user_threats(uid),
                "iam_audit_events": get_iam_events(uid, limit=20),
                "endpoint_edr_alerts": get_endpoint_events(uid, limit=20),
                "firewall_network_logs": get_firewall_events(uid, limit=20),
                "evidence_timeline": build_evidence_timeline(uid, limit=30)
            }

    # 1. Greetings & Help / Capabilities
    if not q_lower or any(k in q_lower for k in ["hello", "hi", "hey", "greetings", "good morning", "good evening", "what can you do", "help", "who are you", "what is this"]):
        answer = (
            "Hello! I am Sentinel AI, your Security Assistant connected to live enterprise telemetry streams.\n\n"
            "Here are some actions you can ask me to perform:\n"
            "• **Investigate a user**: *\"Investigate EMP11218\"*\n"
            "• **Explain risk drivers**: *\"Why is EMP11218 critical?\"*\n"
            "• **Inspect evidence**: *\"Show me the evidence for EMP11218\"* or *\"What happened on the endpoint?\"*\n"
            "• **Analyze network telemetry**: *\"How much network traffic occurred?\"*\n"
            "• **Compare users**: *\"Compare EMP11218 and EMP10296\"*\n"
            "• **Review IAM activity**: *\"What MFA failures did EMP11218 have?\"*\n"
            "• **System Overview**: *\"Show recent threats\"* or *\"Summarize high risk users\"*"
        )
        primary_user = target_users[0] if target_users else (context_user_id or "EMP11218")
        return {
            "answer": answer,
            "active_user_id": primary_user,
            "target_users": target_users,
            "evidence": evidence_bundle,
            "quick_actions": ["Investigate EMP11218", "Why is EMP11218 critical?", "Compare EMP11218 and EMP10296"],
            "suggested_actions": ["Investigate EMP11218", "Why is EMP11218 critical?", "Compare EMP11218 and EMP10296"],
            "data_sources": ["Identity Asset Master", "IAM Audit Trail", "Endpoint Alerts", "Firewall Logs", "User Risk Scores", "Threat Detections"]
        }

    # 2. General Cybersecurity Concept Queries (No specific target user)
    concept_keywords = ["what is", "explain", "how does", "tell me about", "definition", "best practices", "cybersecurity"]
    is_concept_query = not explicit_users and any(k in q_lower for k in concept_keywords)
    
    if is_concept_query:
        if "soc" in q_lower or "itdr" in q_lower:
            answer = (
                "### Identity Threat Detection & Response (ITDR)\n\n"
                "**ITDR** focuses on protecting identity infrastructure, detecting credential abuse, tracking account anomalies, and mitigating insider or post-termination risk across enterprise telemetry.\n\n"
                "**Key Capabilities of Sentinel AI:**\n"
                "• **Identity Threat Detection**: Correlating IAM login anomalies, credential abuse, and post-termination access.\n"
                "• **Endpoint Security (EDR)**: Tracking suspicious process executions (e.g. PowerShell obfuscation, credential dumping).\n"
                "• **Network Telemetry**: Monitoring firewall byte volumes and suspicious outbound connection destinations.\n"
                "• **Risk Scoring & Triage**: Prioritizing compromised accounts for immediate containment."
            )
        elif "mfa" in q_lower or "multi-factor" in q_lower:
            answer = (
                "### Multi-Factor Authentication (MFA)\n\n"
                "**Multi-Factor Authentication (MFA)** requires users to provide two or more verification factors to gain access to resources.\n\n"
                "• **Common Attacks against MFA**: MFA fatigue (push bombing), SIM swapping, adversary-in-the-middle (AiTM) phishing, and stale session token reuse.\n"
                "• **Security Action**: Check for multiple failed MFA challenges followed by a successful authentication from an unfamiliar IP or post-termination account."
            )
        elif "exfiltration" in q_lower or "200 mb" in q_lower:
            answer = (
                "### Data Exfiltration Analysis\n\n"
                "Data exfiltration refers to the unauthorized transfer of sensitive data from a target system.\n\n"
                "> **Important Note**: High network traffic volume (e.g., 200 MB of outbound firewall traffic) indicates elevated data transfer, but observed volume alone does not prove exfiltration without corroborating payload analysis or threat alerts."
            )
        else:
            answer = (
                "### Cybersecurity Guidance\n\n"
                "To investigate threat activity across enterprise telemetry:\n"
                "1. **Triage High-Risk Users**: Prioritize users with risk scores above 80/100.\n"
                "2. **Verify Identity Context**: Check employment status, manager, and asset ownership.\n"
                "3. **Inspect Endpoint Alerts**: Audit suspicious command-line executions, process spawning, and unapproved scripts.\n"
                "4. **Analyze Network Logs**: Cross-reference byte transfer volumes and foreign destination IPs."
            )
        
        primary_user = context_user_id or "EMP11218"
        return {
            "answer": answer,
            "active_user_id": primary_user,
            "target_users": [],
            "evidence": {},
            "quick_actions": ["Investigate EMP11218", "Which accounts are critical?", "Show summary of threats"],
            "suggested_actions": ["Investigate EMP11218", "Which accounts are critical?"],
            "data_sources": ["Identity Asset Master"]
        }

    # 2.5. Critical Risk Accounts Queries (e.g., "Which accounts are critical?", "Which users are critical?")
    if not target_users and any(k in q_lower for k in ["critical", "high risk accounts", "who is critical", "which accounts", "which users"]):
        r_df = _get_df(os.path.join("analytics", "user_risk_scores.csv"))
        crit_users = []
        if not r_df.empty:
            crit_df = r_df[r_df["risk_level"].astype(str).str.lower() == "critical"]
            if crit_df.empty:
                crit_df = r_df.sort_values(by="risk_score", ascending=False).head(5)
            crit_users = crit_df[["user_id", "risk_score", "risk_level", "department", "risk_drivers"]].head(5).to_dict("records")

        lines = ["### Critical Risk Accounts Overview\n"]
        lines.append(f"The following **{len(crit_users)} accounts** are currently classified at **Critical Risk** based on live correlated telemetry:\n")
        for u in crit_users:
            lines.append(f"• **{u.get('user_id')}** (Score: `{u.get('risk_score')}/100` • Dept: `{u.get('department', 'N/A')}`) — {u.get('risk_drivers', 'High risk score')}")
        lines.append("\n*Tip: Ask 'Investigate EMP11218' to inspect full forensic timeline for any account.*")

        answer = "\n".join(lines)
        top_user = crit_users[0].get("user_id", "EMP11218") if crit_users else "EMP11218"
        return {
            "answer": answer,
            "active_user_id": top_user,
            "target_users": [u.get("user_id") for u in crit_users],
            "evidence": {},
            "quick_actions": [f"Investigate {top_user}", f"Why is {top_user} critical?", "Show summary of threats"],
            "suggested_actions": [f"Investigate {top_user}", f"Why is {top_user} critical?"],
            "data_sources": ["User Risk Scores"]
        }

    # 3. Overall System Summary / Metrics Queries
    if not target_users and any(k in q_lower for k in ["summary", "overview", "threats", "threat", "high risk", "metric", "metrics", "recent", "all users"]):
        t_df = _get_df(os.path.join("analytics", "threat_detections.csv"))
        r_df = _get_df(os.path.join("analytics", "user_risk_scores.csv"))
        num_threats = len(t_df) if not t_df.empty else 0
        num_critical = len(r_df[r_df["risk_level"].astype(str).str.lower() == "critical"]) if not r_df.empty and "risk_level" in r_df.columns else 0
        
        top_threats = []
        if not t_df.empty and "threat_type" in t_df.columns:
            top_threats = t_df[["user_id", "threat_type", "severity"]].head(5).to_dict("records")

        lines = ["### Live System Telemetry Summary\n"]
        lines.append(f"• **Active Threat Detections**: `{num_threats}` total detections logged.")
        lines.append(f"• **Critical-Risk Users**: `{num_critical}` accounts flagged for immediate review.\n")
        lines.append("#### Primary Active Threat Detections:")
        for t in top_threats:
            lines.append(f"• **{t.get('user_id')}**: {t.get('threat_type')} (`{t.get('severity', 'HIGH')}`)")

        answer = "\n".join(lines)
        return {
            "answer": answer,
            "active_user_id": context_user_id or "EMP11218",
            "target_users": [],
            "evidence": {},
            "quick_actions": ["Investigate EMP11218", "Why is EMP11218 critical?", "Compare EMP11218 and EMP10296"],
            "suggested_actions": ["Investigate EMP11218", "Why is EMP11218 critical?"],
            "data_sources": ["Threat Detections", "User Risk Scores"]
        }

    # If still no target user found, fallback to context_user_id or EMP11218
    if not target_users:
        target_users = [resolve_target_user_id(context_user_id or "EMP11218")]
        for uid in target_users:
            if uid not in evidence_bundle:
                evidence_bundle[uid] = {
                    "identity_master": get_identity_context(uid),
                    "risk_scores_and_drivers": get_user_risk(uid),
                    "active_threat_detections": get_user_threats(uid),
                    "iam_audit_events": get_iam_events(uid, limit=20),
                    "endpoint_edr_alerts": get_endpoint_events(uid, limit=20),
                    "firewall_network_logs": get_firewall_events(uid, limit=20),
                    "evidence_timeline": build_evidence_timeline(uid, limit=30)
                }

    # 4. Out-of-bounds Knowledge Check (Salary, SSN)
    if any(k in q_lower for k in ["salary", "ssn", "pay", "wage", "compensation", "credit card"]):
        answer = "I don't have that information in the available security datasets."
        return {
            "answer": answer,
            "active_user_id": target_users[0],
            "target_users": target_users,
            "evidence": evidence_bundle,
            "quick_actions": [f"Investigate {target_users[0]}", f"Why is {target_users[0]} critical?"],
            "suggested_actions": [f"Investigate {target_users[0]}"],
            "data_sources": ["Identity Asset Master"]
        }

    # 5. Multi-user comparison query
    if len(target_users) >= 2 or any(k in q_lower for k in ["compare", "versus", "vs"]):
        lines = ["### Multi-User Security Telemetry Comparison\n"]
        for uid in target_users:
            bundle = evidence_bundle.get(uid, {})
            ident = bundle.get("identity_master", {})
            risk = bundle.get("risk_scores_and_drivers", {})
            threats = bundle.get("active_threat_detections", {}).get("threat_detections", [])
            uname = ident.get("user_name", uid)
            score = risk.get("risk_score", 0)
            band = risk.get("risk_band", "Low")
            lines.append(f"#### **{uname}** (`{uid}`)")
            lines.append(f"• **Recorded Risk Score**: `{score}/100` ({band.upper()} RISK)")
            lines.append(f"• **Employment Status**: `{ident.get('employment_status', 'Active')}`")
            lines.append(f"• **Active Threat Detections**: {len(threats)}")
            if threats:
                lines.append(f"• **Primary Threat**: {threats[0].get('threat_name')} ({threats[0].get('severity')})")
            lines.append("")
        answer = "\n".join(lines)
        return {
            "answer": answer,
            "active_user_id": target_users[0],
            "target_users": target_users,
            "evidence": evidence_bundle,
            "quick_actions": [f"Investigate {target_users[0]}", f"Investigate {target_users[1]}"],
            "suggested_actions": [f"Investigate {target_users[0]}"],
            "data_sources": ["User Risk Scores", "Threat Detections"]
        }

    # Single target user context
    uid = target_users[0]
    bundle = evidence_bundle.get(uid, {})
    ident = bundle.get("identity_master", {})
    risk = bundle.get("risk_scores_and_drivers", {})
    threats = bundle.get("active_threat_detections", {}).get("threat_detections", [])
    edr = bundle.get("endpoint_edr_alerts", [])
    fw = bundle.get("firewall_network_logs", [])
    iam = bundle.get("iam_audit_events", [])
    uname = ident.get("user_name", uid)
    score = risk.get("risk_score", 0)
    band = risk.get("risk_band", "Low")

    # 6. Endpoint query
    if any(k in q_lower for k in ["endpoint", "edr", "process", "powershell", "host"]):
        if not edr:
            answer = f"### Endpoint Activity: {uname} (`{uid}`)\n\nNo endpoint alert events recorded in `track2_endpoint_alerts_clean.csv` for user `{uid}`."
        else:
            lines = [f"### Endpoint Security Activity: {uname} (`{uid}`)\n"]
            for a in edr[:5]:
                lines.append(f"• **{a.get('detected_timestamp')}** — `{a.get('alert_name')}` ({a.get('severity')})")
                lines.append(f"  Process: `{a.get('process_name')}`, Host: `{a.get('hostname')}`, File: `{a.get('file_path')}`")
            answer = "\n".join(lines)

    # 7. Network / Firewall / Exfiltration query
    elif any(k in q_lower for k in ["network", "firewall", "traffic", "byte", "exfiltration", "200 mb", "mb"]):
        if not fw:
            answer = f"### Network Telemetry: {uname} (`{uid}`)\n\nNo firewall log records found for user `{uid}`'s associated host."
        else:
            total_bytes = sum(int(e.get("total_bytes", 0)) for e in fw)
            mb_total = round(total_bytes / (1024 * 1024), 2)
            lines = [f"### Network Telemetry: {uname} (`{uid}`)\n"]
            lines.append(f"• **Observed Network Traffic**: `{mb_total} MB` across {len(fw)} log entries.")
            if "exfiltration" in q_lower or "prove" in q_lower:
                lines.append("\n> **Note**: High network traffic volume indicates elevated transfer activity, but observed byte volume alone does not prove data exfiltration without corroborating payload analysis or threat alerts.")
            for e in fw[:5]:
                lines.append(f"• `{e.get('timestamp')}` — Dst: `{e.get('dst_ip')}:{e.get('dst_port')}` | Bytes: `{e.get('total_bytes'):,}` | Action: `{e.get('action')}`")
            answer = "\n".join(lines)

    # 8. MFA failure query
    elif any(k in q_lower for k in ["mfa", "multi-factor", "failed login"]):
        mfa_fails = [e for e in iam if not e.get("mfa_passed", True) or "MFA" in e.get("event_type", "").upper()]
        if not mfa_fails:
            answer = f"### MFA Telemetry: {uname} (`{uid}`)\n\nThere is no confirmed MFA-failure evidence in the available IAM audit telemetry for user `{uid}`."
        else:
            lines = [f"### MFA Telemetry: {uname} (`{uid}`)\n"]
            for m in mfa_fails[:5]:
                ev_type = str(m.get('event_type') or 'AUTHENTICATION').strip()
                method = str(m.get('auth_method') or 'N/A').strip()
                reason = str(m.get('failure_reason') or 'N/A').strip()
                ts = str(m.get('timestamp') or 'Unknown Time').strip()
                lines.append(f"• `{ts}` — Event: `{ev_type}`, Method: `{method}`, Reason: `{reason}`")
            answer = "\n".join(lines)

    # 9. Why critical / Risk breakdown query
    elif any(k in q_lower for k in ["why", "critical", "risk"]):
        drivers = risk.get("risk_drivers", "Routine activity monitoring.")
        lines = [f"### Risk Explanation: {uname} (`{uid}`)\n"]
        lines.append(f"• **Recorded Risk Score**: `{score}/100` ({band.upper()} RISK)")
        lines.append(f"• **Key Risk Drivers**: {drivers}")
        if threats:
            lines.append("\n#### Correlated Threat Detections:")
            for t in threats:
                lines.append(f"• **{t.get('threat_name')}** ({t.get('severity')}) — Evidence: {t.get('evidence')}")
        answer = "\n".join(lines)

    # 10. Default Investigation Brief
    else:
        drivers = risk.get("risk_drivers", "Routine activity monitoring.")
        lines = [f"### Security Investigation Brief: {uname} (`{uid}`)\n"]
        lines.append(f"• **Employment Status**: `{ident.get('employment_status', 'Active')}`")
        lines.append(f"• **Recorded Risk Score**: `{score}/100` ({band.upper()} RISK)\n")
        lines.append(f"#### Key Risk Drivers\n• {drivers}\n")
        if threats:
            lines.append("#### Active Threat Detections")
            for t in threats:
                lines.append(f"• **{t.get('threat_name')}** ({t.get('severity')}) — {t.get('evidence')}")
        else:
            lines.append("#### Active Threat Detections\n• No critical threat detections flagged.")
        answer = "\n".join(lines)

    return {
        "answer": answer,
        "active_user_id": uid,
        "target_users": target_users,
        "evidence": evidence_bundle,
        "quick_actions": [f"Investigate {uid}", f"Why is {uid} critical?", "Show evidence", "Compare USR-1001 and USR-1002"],
        "suggested_actions": [f"Investigate {uid}", f"Why is {uid} critical?"],
        "data_sources": [
            "Identity Asset Master",
            "IAM Audit Trail",
            "Endpoint Alerts",
            "Firewall Logs",
            "User Risk Scores",
            "Threat Detections"
        ]
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Security Investigation Agent")
    parser.add_argument("--user", type=str, default=None, help="Target User ID to investigate")
    args = parser.parse_args()

    target_user = args.user or resolve_target_user_id("")
    print(f"\n==================================================")
    print(f"  AI SECURITY INVESTIGATION AGENT")
    print(f"  Target User: {target_user}")
    print(f"==================================================\n")

    result = investigate_user(target_user)
    print(json.dumps(result, indent=2))

