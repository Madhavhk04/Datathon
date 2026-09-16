import os
import pandas as pd
from typing import Dict, List, Any, Optional

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

# In-memory DataFrame cache with mtime validation
_CACHE: Dict[str, Any] = {}
_MTIMES: Dict[str, float] = {}

def _get_df(subpath: str) -> pd.DataFrame:
    """Retrieve or load a CSV dataframe with timestamp-based cache invalidation."""
    full_path = os.path.join(DATA_DIR, subpath)
    if not os.path.exists(full_path):
        return pd.DataFrame()
    mtime = os.path.getmtime(full_path)
    if subpath not in _CACHE or _MTIMES.get(subpath) != mtime:
        _CACHE[subpath] = pd.read_csv(full_path, low_memory=False)
        _MTIMES[subpath] = mtime
    return _CACHE[subpath]

def _clean_val(v: Any, default: Any = "") -> Any:
    """Helper to replace NaN / None with safe defaults."""
    if pd.isna(v) or v is None:
        return default
    return v

def user_exists_in_dataset(user_id: str) -> bool:
    """Check if a user ID exists in either Identity Master or User Risk Scores datasets."""
    if not user_id or str(user_id).startswith("NOT_FOUND:"):
        return False
    uid = str(user_id).strip().upper()
    id_df = _get_df(os.path.join("processed", "track2_identity_asset_master_clean.csv"))
    if not id_df.empty and "user_id" in id_df.columns:
        if uid in id_df["user_id"].astype(str).str.upper().values:
            return True
    risk_df = _get_df(os.path.join("analytics", "user_risk_scores.csv"))
    if not risk_df.empty and "user_id" in risk_df.columns:
        if uid in risk_df["user_id"].astype(str).str.upper().values:
            return True
    return False

def resolve_target_user_id(query_or_id: str) -> str:
    """
    Resolves natural language name or user ID to canonical uppercase user ID (e.g. EMP11218).
    Returns NOT_FOUND:ID if an explicit ID was provided that does not exist in the datasets.
    """
    raw = str(query_or_id).strip()
    if not raw:
        return ""
    
    import re
    clean = raw.upper()

    # Demo alias map for USR-100x IDs to dataset EMP IDs
    alias_map = {
        "USR-1001": "EMP11218",
        "USR-1002": "EMP10296",
        "USR-1003": "EMP11241",
        "USR-1004": "EMP12745"
    }
    if clean in alias_map:
        return alias_map[clean]

    # Check if string contains explicit EMP or USR pattern
    emp_match = re.search(r'\b(EMP\s*[-_]?\s*\d{1,6}|USR\s*[-_]?\s*\d{1,6})\b', raw, re.IGNORECASE)
    if emp_match:
        raw_m = emp_match.group(1).upper()
        matched_id = re.sub(r'[\s\-_]', '', raw_m)
        if raw_m.startswith("USR") and "-" in raw_m:
            matched_id = raw_m
        resolved = alias_map.get(matched_id, matched_id)
        if user_exists_in_dataset(resolved):
            return resolved
        return f"NOT_FOUND:{matched_id}"

    # Direct match in Risk Scores or Identity Master
    if user_exists_in_dataset(clean):
        return clean

    # Name match or Username match in Identity Master
    id_df = _get_df(os.path.join("processed", "track2_identity_asset_master_clean.csv"))
    if not id_df.empty:
        raw_lower = raw.lower()
        if "full_name" in id_df.columns:
            name_matches = id_df[id_df["full_name"].astype(str).str.lower() == raw_lower]
            if not name_matches.empty:
                return str(name_matches.iloc[0]["user_id"]).upper()
        if "username" in id_df.columns:
            uname_matches = id_df[id_df["username"].astype(str).str.lower() == raw_lower]
            if not uname_matches.empty:
                return str(uname_matches.iloc[0]["user_id"]).upper()

    return ""

def resolve_target_user_ids(query_or_id: str) -> list:
    """
    Extracts ALL target user IDs or names mentioned in a query string.
    Returns NOT_FOUND:ID entries for explicit user IDs not present in datasets.
    """
    raw = str(query_or_id).strip()
    if not raw:
        return []
    
    import re
    found_ids = []

    alias_map = {
        "USR-1001": "EMP11218",
        "USR-1002": "EMP10296",
        "USR-1003": "EMP11241",
        "USR-1004": "EMP12745"
    }

    # 1. Regex search for explicit user ID patterns: USR-XXXX or EMPXXXXX / EMP789
    matches = re.findall(r'\b(EMP\s*[-_]?\s*\d{1,6}|USR\s*[-_]?\s*\d{1,6})\b', raw, re.IGNORECASE)
    for m in matches:
        raw_m = m.upper()
        uid_raw = re.sub(r'[\s\-_]', '', raw_m)
        if raw_m.startswith("USR") and "-" in raw_m:
            uid_raw = raw_m
        uid = alias_map.get(uid_raw, uid_raw)
        if user_exists_in_dataset(uid):
            if uid not in found_ids:
                found_ids.append(uid)
        else:
            not_found_tag = f"NOT_FOUND:{uid_raw}"
            if not_found_tag not in found_ids:
                found_ids.append(not_found_tag)
            
    # 2. Match names against Identity Master
    id_df = _get_df(os.path.join("processed", "track2_identity_asset_master_clean.csv"))
    if not id_df.empty and "full_name" in id_df.columns:
        for idx, row in id_df.iterrows():
            fname = str(row.get("full_name", "")).strip()
            uname = str(row.get("username", "")).strip()
            uid = str(row.get("user_id", "")).strip().upper()
            if uid and uid not in found_ids:
                if fname and len(fname) >= 4 and re.search(r'\b' + re.escape(fname) + r'\b', raw, re.IGNORECASE):
                    found_ids.append(uid)
                elif uname and len(uname) >= 4 and re.search(r'\b' + re.escape(uname) + r'\b', raw, re.IGNORECASE):
                    found_ids.append(uid)

    return found_ids



def get_identity_context(user_id: str) -> dict:
    """
    Retrieve identity, employment status, manager, assets, and context for a user
    from track2_identity_asset_master_clean.csv.
    """
    uid = resolve_target_user_id(user_id)
    id_df = _get_df(os.path.join("processed", "track2_identity_asset_master_clean.csv"))
    
    if id_df.empty or "user_id" not in id_df.columns:
        return {"error": "Identity Master dataset unavailable", "user_id": uid}
    
    rows = id_df[id_df["user_id"].astype(str).str.upper() == uid]
    if rows.empty:
        return {"error": f"User {uid} not found in Identity Master", "user_id": uid}
    
    row = rows.iloc[0].to_dict()
    hostname = _clean_val(row.get("hostname"), "")
    device_id = _clean_val(row.get("device_id"), "")
    assets = [x for x in [hostname, device_id] if x]

    return {
        "user_id": uid,
        "original_query_id": str(user_id),
        "user_name": str(_clean_val(row.get("full_name"), row.get("username") or uid)),
        "username": str(_clean_val(row.get("username"), "")),
        "department": str(_clean_val(row.get("department"), "Unknown")),
        "role": str(_clean_val(row.get("role"), "Employee")),
        "location": str(_clean_val(row.get("location"), "Unknown")),
        "employment_status": str(_clean_val(row.get("status"), "Active")),
        "hire_date": str(_clean_val(row.get("hire_date"), "")),
        "termination_date": str(_clean_val(row.get("termination_date"), "")),
        "hostname": str(hostname),
        "device_id": str(device_id),
        "manager": str(_clean_val(row.get("manager_username"), "None")),
        "device_id_conflict": bool(row.get("device_id_conflict", False)),
        "device_user_count": int(_clean_val(row.get("device_user_count"), 1) or 1),
        "assigned_assets": ", ".join(assets) if assets else "None"
    }

def get_user_risk(user_id: str) -> dict:
    """
    Retrieve 6-dimensional risk score, risk band, and exact risk drivers for a user
    from user_risk_scores.csv.
    """
    uid = resolve_target_user_id(user_id)
    risk_df = _get_df(os.path.join("analytics", "user_risk_scores.csv"))
    
    if risk_df.empty or "user_id" not in risk_df.columns:
        return {"error": "user_risk_scores.csv not found", "user_id": uid}
    
    rows = risk_df[risk_df["user_id"].astype(str).str.upper() == uid]
    if rows.empty:
        return {"error": f"User {uid} not found in risk scores", "user_id": uid}
    
    row = rows.iloc[0].to_dict()
    
    def _num(key, default=0.0):
        v = row.get(key)
        try:
            val = float(v)
            return 0.0 if pd.isna(val) else val
        except (ValueError, TypeError):
            return default

    score = round(_num("risk_score", 0.0), 1)
    band = str(_clean_val(row.get("risk_band") or row.get("risk_level"), "Low")).title()
    drivers = str(_clean_val(row.get("risk_drivers"), "Routine activity monitoring."))

    return {
        "user_id": uid,
        "original_query_id": str(user_id),
        "username": str(_clean_val(row.get("username"), "")),
        "department": str(_clean_val(row.get("department"), "")),
        "role": str(_clean_val(row.get("role"), "")),
        "status": str(_clean_val(row.get("status"), "Active")),
        "risk_score": score,
        "risk_band": band,
        "risk_drivers": drivers,
        "post_termination_flag": str(row.get("post_termination_activity_flag", "False")).lower() in ["true", "1"],
        "score_breakdown": {
            "authentication": round(_num("authentication_risk", 0.0), 1),
            "iam": round(_num("iam_risk", 0.0), 1),
            "endpoint": round(_num("endpoint_severity_risk", 0.0), 1),
            "threat_behaviour": round(_num("threat_behavior_risk", 0.0), 1),
            "context": round(_num("contextual_risk", 0.0), 1),
            "cross_signal": round(_num("cross_signal_bonus", 0.0), 1)
        },
        "metrics": {
            "iam_events": int(_num("iam_events")),
            "iam_failed_auth": int(_num("iam_failed_auth")),
            "iam_mfa_failures": int(_num("iam_mfa_failures")),
            "iam_high_risk_events": int(_num("iam_high_risk_events")),
            "endpoint_alerts": int(_num("endpoint_alerts")),
            "endpoint_critical_alerts": int(_num("endpoint_critical_alerts")),
            "endpoint_malware_alerts": int(_num("endpoint_malware_alerts")),
            "endpoint_powershell": int(_num("endpoint_powershell")),
            "post_termination_iam_events": int(_num("post_termination_iam_events")),
            "post_termination_endpoint_events": int(_num("post_termination_endpoint_events"))
        }
    }

def get_user_threats(user_id: str) -> dict:
    """
    Retrieve active threat detection rules and investigation queue status for a user
    from threat_detections.csv and investigation_queue.csv.
    """
    uid = resolve_target_user_id(user_id)
    t_df = _get_df(os.path.join("analytics", "threat_detections.csv"))
    q_df = _get_df(os.path.join("analytics", "investigation_queue.csv"))

    detections = []
    if not t_df.empty and "user_id" in t_df.columns:
        u_t = t_df[t_df["user_id"].astype(str).str.upper() == uid]
        for _, r in u_t.iterrows():
            detections.append({
                "threat_id": str(_clean_val(r.get("threat_id"))),
                "threat_name": str(_clean_val(r.get("threat_type"))),
                "threat_type": str(_clean_val(r.get("threat_type"))),
                "severity": str(_clean_val(r.get("severity"), "Medium")).upper(),
                "confidence": str(_clean_val(r.get("confidence"), "Medium")),
                "evidence": str(_clean_val(r.get("evidence"), "")),
                "first_observed": str(_clean_val(r.get("first_observed"), "")),
                "last_observed": str(_clean_val(r.get("last_observed"), "")),
                "related_hostname": str(_clean_val(r.get("related_hostname"), "")),
                "recommended_action": str(_clean_val(r.get("recommended_action"), ""))
            })

    queue_entry = None
    if not q_df.empty and "user_id" in q_df.columns:
        u_q = q_df[q_df["user_id"].astype(str).str.upper() == uid]
        if not u_q.empty:
            qr = u_q.iloc[0].to_dict()
            queue_entry = {
                "priority_rank": int(_clean_val(qr.get("priority_rank"), 0) or 0),
                "investigation_priority": str(_clean_val(qr.get("investigation_priority"), "Medium")),
                "investigation_priority_score": float(_clean_val(qr.get("investigation_priority_score"), 0) or 0),
                "threat_detection_count": int(_clean_val(qr.get("threat_detection_count"), 0) or 0),
                "distinct_threat_types": int(_clean_val(qr.get("distinct_threat_types"), 0) or 0),
                "threat_types": str(_clean_val(qr.get("threat_types"), "")),
                "investigation_reason": str(_clean_val(qr.get("investigation_reason"), "")),
                "recommended_action": str(_clean_val(qr.get("recommended_action"), ""))
            }

    return {
        "user_id": uid,
        "original_query_id": str(user_id),
        "active_threats_count": len(detections),
        "threat_detections": detections,
        "investigation_queue": queue_entry
    }

def get_iam_events(user_id: str, limit: int = 50) -> list:
    """
    Retrieve raw IAM audit trail events for a user from track2_iam_audit_trail_clean.csv.
    """
    uid = resolve_target_user_id(user_id)
    iam_df = _get_df(os.path.join("processed", "track2_iam_audit_trail_clean.csv"))
    
    if iam_df.empty or "user_id" not in iam_df.columns:
        return []
    
    u_iam = iam_df[iam_df["user_id"].astype(str).str.upper() == uid]
    if u_iam.empty:
        return []
    
    events = []
    for _, r in u_iam.sort_values(by="timestamp", ascending=True).head(limit).iterrows():
        events.append({
            "event_id": str(_clean_val(r.get("event_id"))),
            "timestamp": str(_clean_val(r.get("timestamp"))),
            "event_type": str(_clean_val(r.get("event_type"))),
            "auth_method": str(_clean_val(r.get("auth_method"))),
            "mfa_passed": bool(r.get("mfa_passed", True)),
            "source_ip": str(_clean_val(r.get("source_ip"))),
            "hostname": str(_clean_val(r.get("hostname"))),
            "device_id": str(_clean_val(r.get("device_id"))),
            "risk_score": float(_clean_val(r.get("risk_score"), 0) or 0),
            "risk_level": str(_clean_val(r.get("risk_level"))),
            "failure_reason": str(_clean_val(r.get("failure_reason"))),
            "geo_location": str(_clean_val(r.get("geo_location")))
        })
    return events

def get_endpoint_events(user_id: str, limit: int = 50) -> list:
    """
    Retrieve endpoint security alerts for a user from track2_endpoint_alerts_clean.csv.
    """
    uid = resolve_target_user_id(user_id)
    edr_df = _get_df(os.path.join("processed", "track2_endpoint_alerts_clean.csv"))
    
    if edr_df.empty or "user_id" not in edr_df.columns:
        return []
    
    u_edr = edr_df[edr_df["user_id"].astype(str).str.upper() == uid]
    if u_edr.empty:
        return []
    
    alerts = []
    for _, r in u_edr.sort_values(by="detected_timestamp", ascending=True).head(limit).iterrows():
        alerts.append({
            "alert_id": str(_clean_val(r.get("alert_id"))),
            "detected_timestamp": str(_clean_val(r.get("detected_timestamp"))),
            "alert_name": str(_clean_val(r.get("alert_name"))),
            "severity": str(_clean_val(r.get("severity"), "Medium")).upper(),
            "status": str(_clean_val(r.get("status"), "New")),
            "process_name": str(_clean_val(r.get("process_name"), "N/A")),
            "file_path": str(_clean_val(r.get("file_path"), "N/A")),
            "hostname": str(_clean_val(r.get("hostname"), "N/A")),
            "description": str(_clean_val(r.get("description"), ""))
        })
    return alerts

def get_related_hosts(user_id: str) -> list:
    """
    Identify all hostnames correlated with a user across Identity, IAM, and Endpoint datasets.
    """
    uid = resolve_target_user_id(user_id)
    hosts = set()

    ident = get_identity_context(uid)
    if ident.get("hostname"):
        hosts.add(str(ident["hostname"]).strip())

    iam_events = get_iam_events(uid, limit=100)
    for ev in iam_events:
        if ev.get("hostname") and ev["hostname"] != "nan":
            hosts.add(str(ev["hostname"]).strip())

    endpoint_events = get_endpoint_events(uid, limit=100)
    for ev in endpoint_events:
        if ev.get("hostname") and ev["hostname"] != "N/A":
            hosts.add(str(ev["hostname"]).strip())

    return sorted(list(hosts))

def get_firewall_events(user_id: str, limit: int = 50) -> list:
    """
    Retrieve firewall logs associated with the user's host(s) from track2_firewall_logs_clean.csv.
    """
    uid = resolve_target_user_id(user_id)
    fw_df = _get_df(os.path.join("processed", "track2_firewall_logs_clean.csv"))
    
    if fw_df.empty:
        return []

    hosts = get_related_hosts(uid)
    if not hosts:
        return []

    host_keys = [h.lower() for h in hosts]
    u_fw = fw_df[fw_df["hostname_join_key"].astype(str).str.lower().isin(host_keys)]
    if u_fw.empty and "hostname" in fw_df.columns:
        u_fw = fw_df[fw_df["hostname"].astype(str).str.lower().isin(host_keys)]

    if u_fw.empty:
        return []

    events = []
    for _, r in u_fw.sort_values(by="timestamp", ascending=True).head(limit).iterrows():
        b_sent_raw = pd.to_numeric(r.get("bytes_sent"), errors="coerce")
        b_sent = 0.0 if pd.isna(b_sent_raw) else float(b_sent_raw)

        b_rec_raw = pd.to_numeric(r.get("bytes_received"), errors="coerce")
        b_rec = 0.0 if pd.isna(b_rec_raw) else float(b_rec_raw)

        events.append({
            "log_id": str(_clean_val(r.get("log_id"))),
            "timestamp": str(_clean_val(r.get("timestamp"))),
            "hostname": str(_clean_val(r.get("hostname"))),
            "src_ip": str(_clean_val(r.get("src_ip"))),
            "dst_ip": str(_clean_val(r.get("dst_ip"))),
            "dst_port": str(_clean_val(r.get("dst_port"))),
            "protocol": str(_clean_val(r.get("protocol"), "TCP")),
            "action": str(_clean_val(r.get("action"), "ALLOW")),
            "bytes_sent": int(b_sent),
            "bytes_received": int(b_rec),
            "total_bytes": int(b_sent + b_rec),
            "threat_flag": bool(r.get("threat_flag", False)),
            "rule_name": str(_clean_val(r.get("rule_name"))),
            "geo_country": str(_clean_val(r.get("geo_country")))
        })
    return events

def build_evidence_timeline(user_id: str, limit: int = 100) -> dict:
    """
    Chronologically merge events from real IAM audit, Endpoint alerts, and Firewall logs.
    Includes severity scoring and chart point generation for visualization.
    """
    uid = resolve_target_user_id(user_id)
    events = []

    # 1. IAM Events
    iam_list = get_iam_events(uid, limit=limit)
    for ev in iam_list:
        ts = ev.get("timestamp", "")
        if ts and ts != "nan":
            sev = "HIGH" if (not ev.get("mfa_passed") or "FAIL" in ev.get("event_type", "").upper()) else "MEDIUM"
            det = f"Event: {ev.get('event_type')}, Method: {ev.get('auth_method')}, IP: {ev.get('source_ip')}, MFA: {ev.get('mfa_passed')}"
            if ev.get("failure_reason"):
                det += f", Reason: {ev.get('failure_reason')}"
            events.append({
                "timestamp": ts,
                "source": "IAM Audit Trail",
                "event_type": ev.get("event_type", "IAM_EVENT"),
                "severity": sev,
                "details": det
            })

    # 2. Endpoint Events
    edr_list = get_endpoint_events(uid, limit=limit)
    for ev in edr_list:
        ts = ev.get("detected_timestamp", "")
        if ts and ts != "nan":
            events.append({
                "timestamp": ts,
                "source": "Endpoint Alert (EDR)",
                "event_type": ev.get("alert_name", "EDR_ALERT"),
                "severity": ev.get("severity", "MEDIUM"),
                "details": f"Process: {ev.get('process_name')}, Host: {ev.get('hostname')}, Status: {ev.get('status')}"
            })

    # 3. Firewall Events
    fw_list = get_firewall_events(uid, limit=limit)
    for ev in fw_list:
        ts = ev.get("timestamp", "")
        if ts and ts != "nan":
            b_total = ev.get("total_bytes", 0)
            sev = "CRITICAL" if ev.get("threat_flag") else ("HIGH" if b_total > 10000000 else "MEDIUM")
            events.append({
                "timestamp": ts,
                "source": "Firewall Logs",
                "event_type": f"NETWORK_TRAFFIC ({ev.get('protocol', 'TCP')})",
                "severity": sev,
                "details": f"Host: {ev.get('hostname')}, Dst: {ev.get('dst_ip')}:{ev.get('dst_port')}, Bytes: {b_total:,}, Action: {ev.get('action')}, Country: {ev.get('geo_country')}"
            })

    # Sort events chronologically
    events.sort(key=lambda x: str(x.get("timestamp", "")))
    trimmed_events = events[:limit]

    sev_map = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
    chart_data = []
    for ev in trimmed_events:
        ts = ev.get("timestamp")
        if ts and ts != "nan":
            numeric_sev = sev_map.get(str(ev.get("severity", "MEDIUM")).upper(), 3)
            chart_data.append({
                "timestamp": str(ts),
                "severity_level": numeric_sev,
                "event_source": str(ev.get("source")),
                "event_type": str(ev.get("event_type"))
            })

    return {
        "user_id": uid,
        "original_query_id": str(user_id),
        "total_events": len(trimmed_events),
        "timeline": trimmed_events,
        "chart_data": chart_data
    }
