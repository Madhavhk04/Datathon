import os
import pandas as pd

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

# Synthetic Demo User Profiles for USR-1001..USR-1004
DEMO_RISK = {
    "USR-1001": {
        "user_id": "USR-1001",
        "username": "alex.vance",
        "department": "Finance / Core Admin",
        "role": "Senior Systems Administrator",
        "risk_score": 92,
        "risk_band": "CRITICAL",
        "risk_drivers": "Post-termination credential access; LSASS memory dump; 200 MB egress to external IP",
        "post_termination_flag": True,
        "score_breakdown": {
            "authentication": 95,
            "iam": 90,
            "endpoint": 88,
            "threat_behaviour": 94,
            "context": 85,
            "cross_signal": 92
        }
    },
    "USR-1002": {
        "user_id": "USR-1002",
        "username": "elena.rostova",
        "department": "Engineering",
        "role": "DevOps Engineer",
        "risk_score": 76,
        "risk_band": "HIGH",
        "risk_drivers": "Privilege escalation attempts; AWS IAM Admin role access",
        "post_termination_flag": False,
        "score_breakdown": {
            "authentication": 70,
            "iam": 85,
            "endpoint": 60,
            "threat_behaviour": 72,
            "context": 50,
            "cross_signal": 65
        }
    },
    "USR-1003": {
        "user_id": "USR-1003",
        "username": "marcus.chen",
        "department": "Sales",
        "role": "Account Executive",
        "risk_score": 45,
        "risk_band": "MEDIUM",
        "risk_drivers": "Multiple failed auth attempts; travel context anomaly",
        "post_termination_flag": False,
        "score_breakdown": {
            "authentication": 50,
            "iam": 30,
            "endpoint": 40,
            "threat_behaviour": 42,
            "context": 35,
            "cross_signal": 40
        }
    },
    "USR-1004": {
        "user_id": "USR-1004",
        "username": "sarah.jenkins",
        "department": "Marketing",
        "role": "Content Specialist",
        "risk_score": 25,
        "risk_band": "LOW",
        "risk_drivers": "Routine monitoring; single failed login",
        "post_termination_flag": False,
        "score_breakdown": {
            "authentication": 20,
            "iam": 15,
            "endpoint": 25,
            "threat_behaviour": 20,
            "context": 10,
            "cross_signal": 15
        }
    }
}

DEMO_IDENTITY = {
    "USR-1001": {
        "user_id": "USR-1001",
        "user_name": "Alex Vance",
        "username": "alex.vance",
        "email": "alex.vance@company.com",
        "department": "Finance",
        "role": "Systems Administrator",
        "employment_status": "TERMINATED",
        "termination_date": "2026-09-10",
        "hostname": "DEV-LAPTOP-088",
        "device_id": "DEV-0101",
        "manager": "david.chen",
        "location": "Headquarters",
        "assigned_assets": "DEV-LAPTOP-088"
    },
    "USR-1002": {
        "user_id": "USR-1002",
        "user_name": "Elena Rostova",
        "username": "elena.rostova",
        "email": "elena.rostova@company.com",
        "department": "Engineering",
        "role": "DevOps Engineer",
        "employment_status": "ACTIVE",
        "termination_date": "",
        "hostname": "DEV-LAPTOP-042",
        "device_id": "DEV-0102",
        "manager": "sam.wilson",
        "location": "Remote",
        "assigned_assets": "DEV-LAPTOP-042"
    },
    "USR-1003": {
        "user_id": "USR-1003",
        "user_name": "Marcus Chen",
        "username": "marcus.chen",
        "email": "marcus.chen@company.com",
        "department": "Sales",
        "role": "Account Executive",
        "employment_status": "ACTIVE",
        "termination_date": "",
        "hostname": "WS-1003",
        "device_id": "DEV-0103",
        "manager": "rachel.green",
        "location": "Regional Office",
        "assigned_assets": "WS-1003"
    },
    "USR-1004": {
        "user_id": "USR-1004",
        "user_name": "Sarah Jenkins",
        "username": "sarah.jenkins",
        "email": "sarah.jenkins@company.com",
        "department": "Marketing",
        "role": "Content Specialist",
        "employment_status": "ACTIVE",
        "termination_date": "",
        "hostname": "WS-1004",
        "device_id": "DEV-0104",
        "manager": "paul.walker",
        "location": "Headquarters",
        "assigned_assets": "WS-1004"
    }
}

DEMO_THREATS = {
    "USR-1001": [
        {
            "detection_id": "DET-5001",
            "threat_name": "Data Exfiltration via Encrypted Tunnel",
            "severity": "CRITICAL",
            "status": "ACTIVE",
            "timestamp": "2026-09-14T14:28:00Z",
            "description": "200 MB total egress transferred to external IP 198.51.100.44 following credential dumping."
        },
        {
            "detection_id": "DET-5002",
            "threat_name": "Encoded PowerShell Execution",
            "severity": "HIGH",
            "status": "ACTIVE",
            "timestamp": "2026-09-14T14:10:00Z",
            "description": "Suspicious encoded PowerShell script execution detected on host DEV-LAPTOP-088."
        }
    ],
    "USR-1002": [
        {
            "detection_id": "DET-5003",
            "threat_name": "Privilege Escalation via IAM Role Elevation",
            "severity": "HIGH",
            "status": "ACTIVE",
            "timestamp": "2026-09-14T11:20:00Z",
            "description": "Unauthorized role elevation attempt to AWS_IAM_AdminRole."
        }
    ]
}

DEMO_TIMELINE = {
    "USR-1001": [
        {
            "timestamp": "2026-09-14T14:05:00Z",
            "source": "IAM Audit Trail",
            "event_type": "IAM_PRIVILEGE_ELEVATION",
            "severity": "HIGH",
            "details": "Action: ElevateRole, Resource: AWS_IAM_AdminRole, Status: SUCCESS, IP: 198.51.100.44"
        },
        {
            "timestamp": "2026-09-14T14:10:00Z",
            "source": "Endpoint Alert (EDR)",
            "event_type": "SUSPICIOUS_POWERSHELL",
            "severity": "HIGH",
            "details": "Device: DEV-LAPTOP-088, Process: powershell.exe, Action: ENCODED_COMMAND"
        },
        {
            "timestamp": "2026-09-14T14:15:00Z",
            "source": "Endpoint Alert (EDR)",
            "event_type": "LSASS_MEMORY_DUMP",
            "severity": "CRITICAL",
            "details": "Device: DEV-LAPTOP-088, Process: procdump.exe, Action: MEMORY_READ_LSASS"
        },
        {
            "timestamp": "2026-09-14T14:25:00Z",
            "source": "Firewall Logs",
            "event_type": "NETWORK_TRAFFIC (TCP)",
            "severity": "HIGH",
            "details": "Src: 10.0.4.12, Dst: 198.51.100.44:443, Bytes: 52,428,800, Action: ALLOW"
        },
        {
            "timestamp": "2026-09-14T14:28:00Z",
            "source": "Firewall Logs",
            "event_type": "NETWORK_TRAFFIC (TCP)",
            "severity": "HIGH",
            "details": "Src: 10.0.4.12, Dst: 198.51.100.44:8443, Bytes: 157,286,400, Action: ALLOW"
        }
    ],
    "USR-1002": [
        {
            "timestamp": "2026-09-14T11:20:00Z",
            "source": "IAM Audit Trail",
            "event_type": "IAM_ROLE_ELEVATION",
            "severity": "HIGH",
            "details": "Action: AssumeRole, Resource: AWS_IAM_AdminRole, Status: SUCCESS, IP: 10.20.4.15"
        }
    ],
    "USR-1003": [
        {
            "timestamp": "2026-09-14T09:15:00Z",
            "source": "IAM Audit Trail",
            "event_type": "FAILED_LOGIN",
            "severity": "MEDIUM",
            "details": "User: marcus.chen, Event: FAILED_LOGIN, Method: PASSWORD, IP: 192.168.1.50"
        }
    ]
}

def resolve_target_user_id(user_id: str) -> str:
    """
    Resolves user_id aliases.
    """
    uid_str = str(user_id).strip().upper()
    if uid_str in DEMO_RISK:
        return uid_str

    risk_path = os.path.join(DATA_DIR, "analytics", "user_risk_scores.csv")
    ident_path = os.path.join(DATA_DIR, "processed", "track2_identity_asset_master_clean.csv")

    if os.path.exists(risk_path):
        df = pd.read_csv(risk_path)
        if uid_str in df["user_id"].astype(str).str.upper().values:
            return uid_str

    if os.path.exists(ident_path):
        df_id = pd.read_csv(ident_path)
        if uid_str in df_id["user_id"].astype(str).str.upper().values:
            return uid_str

    # Synthetic demo mappings fallback
    if uid_str in ["ALEX VANCE", "ALEX"]:
        return "USR-1001"
    if uid_str in ["ELENA ROSTOVA", "ELENA"]:
        return "USR-1002"
    if uid_str in ["MARCUS CHEN"]:
        return "USR-1003"

    return uid_str

def get_user_risk(user_id: str) -> dict:
    """
    Retrieve risk score, risk band, and dimension score breakdown for a specific user.
    """
    resolved_id = resolve_target_user_id(user_id)
    if resolved_id in DEMO_RISK:
        return DEMO_RISK[resolved_id]

    csv_path = os.path.join(DATA_DIR, "analytics", "user_risk_scores.csv")
    if not os.path.exists(csv_path):
        return {"error": "user_risk_scores.csv not found", "user_id": user_id}

    df = pd.read_csv(csv_path)
    user_rows = df[df["user_id"].astype(str).str.upper() == resolved_id]
    if user_rows.empty:
        return {"error": f"User {user_id} not found in risk scores", "user_id": user_id}

    row = user_rows.iloc[0].to_dict()
    return {
        "user_id": str(row["user_id"]),
        "original_query_id": str(user_id),
        "username": str(row.get("username", "")),
        "department": str(row.get("department", "")),
        "role": str(row.get("role", "")),
        "risk_score": int(float(row.get("risk_score", 0))),
        "risk_band": str(row.get("risk_band") or row.get("risk_level") or "LOW").upper(),
        "risk_drivers": str(row.get("risk_drivers", "")),
        "post_termination_flag": str(row.get("post_termination_activity_flag", "False")).lower() in ["true", "1"],
        "score_breakdown": {
            "authentication": int(float(row.get("authentication_risk", row.get("auth_score", 0)))),
            "iam": int(float(row.get("iam_risk", row.get("iam_score", 0)))),
            "endpoint": int(float(row.get("endpoint_severity_risk", row.get("endpoint_score", 0)))),
            "threat_behaviour": int(float(row.get("threat_behavior_risk", row.get("threat_score", 0)))),
            "context": int(float(row.get("contextual_risk", row.get("context_score", 0)))),
            "cross_signal": int(float(row.get("cross_signal_bonus", row.get("cross_signal_score", 0))))
        }
    }

def get_user_threats(user_id: str) -> dict:
    """
    Retrieve threat detections and investigation queue status for a specific user.
    """
    resolved_id = resolve_target_user_id(user_id)
    if resolved_id in DEMO_THREATS:
        return {
            "user_id": resolved_id,
            "original_query_id": str(user_id),
            "active_threats_count": len(DEMO_THREATS[resolved_id]),
            "threat_detections": DEMO_THREATS[resolved_id],
            "investigation_queue": []
        }

    threats_path = os.path.join(DATA_DIR, "analytics", "threat_detections.csv")
    queue_path = os.path.join(DATA_DIR, "analytics", "investigation_queue.csv")

    detections = []
    if os.path.exists(threats_path):
        df_t = pd.read_csv(threats_path)
        if "user_id" in df_t.columns:
            u_t = df_t[df_t["user_id"].astype(str).str.upper() == resolved_id]
            for _, r in u_t.iterrows():
                rec = r.to_dict()
                clean_rec = {k: ("" if pd.isna(v) else v) for k, v in rec.items()}
                detections.append(clean_rec)

    queue_info = []
    if os.path.exists(queue_path):
        df_q = pd.read_csv(queue_path)
        if "user_id" in df_q.columns:
            u_q = df_q[df_q["user_id"].astype(str).str.upper() == resolved_id]
            for _, r in u_q.iterrows():
                rec = r.to_dict()
                clean_rec = {k: ("" if pd.isna(v) else v) for k, v in rec.items()}
                queue_info.append(clean_rec)

    return {
        "user_id": resolved_id,
        "original_query_id": str(user_id),
        "active_threats_count": len(detections),
        "threat_detections": detections,
        "investigation_queue": queue_info
    }

def get_identity_context(user_id: str) -> dict:
    """
    Retrieve identity, employment status, manager, assets, and context for a user.
    """
    resolved_id = resolve_target_user_id(user_id)
    if resolved_id in DEMO_IDENTITY:
        return DEMO_IDENTITY[resolved_id]

    path = os.path.join(DATA_DIR, "processed", "track2_identity_asset_master_clean.csv")
    if not os.path.exists(path):
        return {"error": "identity master clean CSV not found", "user_id": user_id}

    df = pd.read_csv(path)
    rows = df[df["user_id"].astype(str).str.upper() == resolved_id]
    if rows.empty:
        return {"error": f"User {user_id} not found in identity master", "user_id": user_id}

    row = rows.iloc[0].to_dict()
    clean_row = {k: ("" if pd.isna(v) else v) for k, v in row.items()}
    return {
        "user_id": str(clean_row["user_id"]),
        "original_query_id": str(user_id),
        "user_name": str(clean_row.get("full_name") or clean_row.get("user_name") or clean_row.get("username") or "Unknown User"),
        "username": str(clean_row.get("username", "")),
        "department": str(clean_row.get("department", "")),
        "role": str(clean_row.get("role", "")),
        "employment_status": str(clean_row.get("status") or clean_row.get("employment_status") or "ACTIVE").upper(),
        "termination_date": str(clean_row.get("termination_date", "")),
        "hostname": str(clean_row.get("hostname", "")),
        "device_id": str(clean_row.get("device_id", "")),
        "manager": str(clean_row.get("manager_username") or clean_row.get("manager", "")),
        "location": str(clean_row.get("location", "")),
        "assigned_assets": str(clean_row.get("hostname") or clean_row.get("device_id") or clean_row.get("assigned_assets", ""))
    }

def build_evidence_timeline(user_id: str) -> dict:
    """
    Chronologically merge events from IAM audit, Endpoint alerts, and Firewall logs.
    """
    resolved_id = resolve_target_user_id(user_id)
    if resolved_id in DEMO_TIMELINE:
        events = DEMO_TIMELINE[resolved_id]
        sev_map = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
        chart_data = [
            {
                "timestamp": ev["timestamp"],
                "severity_level": sev_map.get(ev["severity"].upper(), 3),
                "event_source": ev["source"],
                "event_type": ev["event_type"]
            }
            for ev in events if ev.get("timestamp")
        ]
        return {
            "user_id": resolved_id,
            "original_query_id": str(user_id),
            "total_events": len(events),
            "timeline": events,
            "chart_data": chart_data
        }

    iam_path = os.path.join(DATA_DIR, "processed", "track2_iam_audit_trail_clean.csv")
    edr_path = os.path.join(DATA_DIR, "processed", "track2_endpoint_alerts_clean.csv")
    fw_path = os.path.join(DATA_DIR, "processed", "track2_firewall_logs_clean.csv")

    events = []

    # 1. IAM events
    if os.path.exists(iam_path):
        df_iam = pd.read_csv(iam_path)
        if "user_id" in df_iam.columns:
            u_iam = df_iam[df_iam["user_id"].astype(str).str.upper() == resolved_id]
            for _, r in u_iam.iterrows():
                ts = str(r.get("timestamp", ""))
                events.append({
                    "timestamp": ts,
                    "source": "IAM Audit Trail",
                    "event_type": str(r.get("event_type", "IAM_EVENT")),
                    "severity": "HIGH" if (r.get("mfa_passed") is False or r.get("event_type") in ["MFA_FAILURE", "FAILED_LOGIN"]) else "MEDIUM",
                    "details": f"User: {r.get('username')}, Event: {r.get('event_type')}, Method: {r.get('auth_method')}, IP: {r.get('source_ip')}, Location: {r.get('geo_location')}"
                })

    # 2. Endpoint events
    if os.path.exists(edr_path):
        df_edr = pd.read_csv(edr_path)
        if "user_id" in df_edr.columns:
            u_edr = df_edr[df_edr["user_id"].astype(str).str.upper() == resolved_id]
            for _, r in u_edr.iterrows():
                ts = str(r.get("detected_timestamp") or r.get("timestamp", ""))
                events.append({
                    "timestamp": ts,
                    "source": "Endpoint Alert (EDR)",
                    "event_type": str(r.get("alert_name", "ENDPOINT_ALERT")),
                    "severity": str(r.get("severity", "MEDIUM")).upper(),
                    "details": f"Host: {r.get('hostname')}, Product: {r.get('endpoint_product')}, Process: {r.get('process_name') or 'N/A'}, Status: {r.get('status')}"
                })

    # 3. Firewall events
    if os.path.exists(fw_path):
        df_fw = pd.read_csv(fw_path)
        ident = get_identity_context(resolved_id)
        user_host = str(ident.get("hostname", "")).lower()

        if "user_id" in df_fw.columns:
            u_fw = df_fw[df_fw["user_id"].astype(str).str.upper() == resolved_id]
        elif user_host and "hostname" in df_fw.columns:
            u_fw = df_fw[df_fw["hostname"].astype(str).str.lower() == user_host]
        elif user_host and "hostname_join_key" in df_fw.columns:
            u_fw = df_fw[df_fw["hostname_join_key"].astype(str).str.lower() == user_host]
        else:
            u_fw = pd.DataFrame()

        if not u_fw.empty:
            for _, r in u_fw.head(10).iterrows():
                try:
                    b_sent = float(r.get("bytes_sent", 0) or 0)
                except (ValueError, TypeError):
                    b_sent = 0.0
                if pd.isna(b_sent): b_sent = 0.0

                try:
                    b_rec = float(r.get("bytes_received", 0) or 0)
                except (ValueError, TypeError):
                    b_rec = 0.0
                if pd.isna(b_rec): b_rec = 0.0

                bytes_tf = b_sent + b_rec
                sev = "HIGH" if bytes_tf > 10000000 else "MEDIUM"
                ts = str(r.get("timestamp", ""))
                events.append({
                    "timestamp": ts,
                    "source": "Firewall Logs",
                    "event_type": f"NETWORK_TRAFFIC ({r.get('protocol', 'TCP')})",
                    "severity": sev,
                    "details": f"Host: {r.get('hostname') or 'N/A'}, Dst: {r.get('dst_ip') or 'N/A'}:{r.get('dst_port') or 'N/A'}, Bytes: {int(bytes_tf):,}, Action: {r.get('action') or 'N/A'}, Country: {r.get('geo_country') or 'N/A'}"
                })

    # Sort events chronologically
    events.sort(key=lambda x: x["timestamp"])

    sev_map = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}

    chart_data = []
    for ev in events:
        if ev["timestamp"]:
            numeric_sev = sev_map.get(ev["severity"].upper(), 3)
            chart_data.append({
                "timestamp": ev["timestamp"],
                "severity_level": numeric_sev,
                "event_source": ev["source"],
                "event_type": ev["event_type"]
            })

    return {
        "user_id": resolved_id,
        "original_query_id": str(user_id),
        "total_events": len(events),
        "timeline": events,
        "chart_data": chart_data
    }


