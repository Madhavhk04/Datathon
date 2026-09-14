from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = ROOT / "data" / "processed"
ANALYTICS_DIR = ROOT / "data" / "analytics"
REPORT_DIR = ROOT / "reports" / "analytics"

IDENTITY_PATH = DATA_DIR / "track2_identity_asset_master_clean.csv"
IAM_PATH = DATA_DIR / "track2_iam_audit_trail_clean.csv"
ENDPOINT_PATH = DATA_DIR / "track2_endpoint_alerts_clean.csv"


def normalize_key(value):
    """Normalize identifiers while preserving missing values."""
    if pd.isna(value):
        return pd.NA

    value = str(value).strip().upper()

    return value if value else pd.NA


def normalize_hostname(value):
    """Normalize hostnames for cross-source comparison."""
    if pd.isna(value):
        return pd.NA

    value = str(value).strip().lower()
    value = value.replace("_", "-")

    if value.endswith(".corp.local"):
        value = value[:-10]

    return value if value else pd.NA


def load_data():
    """Load production-cleaned datasets."""
    identity = pd.read_csv(IDENTITY_PATH)
    iam = pd.read_csv(IAM_PATH)
    endpoint = pd.read_csv(ENDPOINT_PATH)

    return identity, iam, endpoint


def prepare_identity(identity):
    """Prepare identity records for threat detection."""

    identity = identity.copy()

    identity["user_key"] = identity["user_id"].map(
        normalize_key
    )

    identity["hostname_key"] = identity["hostname"].map(
        normalize_hostname
    )

    identity["termination_date"] = pd.to_datetime(
        identity["termination_date"],
        errors="coerce",
    )

    # One canonical identity record per user.
    identity_user = (
        identity
        .dropna(subset=["user_key"])
        .groupby("user_key")
        .agg(
            username=("username", "first"),
            department=("department", "first"),
            role=("role", "first"),
            status=("status", "first"),
            termination_date=("termination_date", "max"),
        )
        .reset_index()
    )

    return identity, identity_user


def prepare_iam(iam):
    """Prepare IAM telemetry for threat detection."""

    iam = iam.copy()

    iam["user_key"] = iam["user_id"].map(
        normalize_key
    )

    iam["hostname_key"] = iam["hostname"].map(
        normalize_hostname
    )

    iam["timestamp"] = pd.to_datetime(
        iam["timestamp"],
        errors="coerce",
    )

    event_type = (
        iam["event_type"]
        .fillna("")
        .astype(str)
        .str.lower()
    )

    failure_reason = (
        iam["failure_reason"]
        .fillna("")
        .astype(str)
        .str.lower()
    )

    iam["failed_auth_flag"] = (
        event_type.str.contains(
            r"fail|denied|reject",
            regex=True,
            na=False,
        )
        | failure_reason.str.len().gt(0)
    )

    iam["mfa_failure_flag"] = (
        iam["mfa_passed"]
        .astype("string")
        .str.upper()
        == "FALSE"
    )

    iam["high_risk_flag"] = (
        pd.to_numeric(
            iam["risk_score"],
            errors="coerce",
        )
        >= 70
    )

    return iam


def prepare_endpoint(endpoint):
    """Prepare endpoint telemetry for threat detection."""

    endpoint = endpoint.copy()

    endpoint["user_key"] = endpoint["user_id"].map(
        normalize_key
    )

    endpoint["hostname_key"] = endpoint["hostname"].map(
        normalize_hostname
    )

    endpoint["detected_timestamp"] = pd.to_datetime(
        endpoint["detected_timestamp"],
        errors="coerce",
    )

    text = (
        endpoint[
            [
                "alert_name",
                "description",
                "process_name",
            ]
        ]
        .fillna("")
        .astype(str)
        .agg(" ".join, axis=1)
        .str.lower()
    )

    endpoint["malware_flag"] = text.str.contains(
        r"malware|ransomware|trojan",
        regex=True,
        na=False,
    )

    endpoint["credential_flag"] = text.str.contains(
        r"credential|keylogger",
        regex=True,
        na=False,
    )

    endpoint["lateral_flag"] = text.str.contains(
        r"lateral|admin share",
        regex=True,
        na=False,
    )

    endpoint["powershell_flag"] = text.str.contains(
        r"powershell",
        regex=True,
        na=False,
    )

    endpoint["tampering_flag"] = text.str.contains(
        r"disable security|tamper",
        regex=True,
        na=False,
    )

    severity = (
        endpoint["severity"]
        .fillna("")
        .astype(str)
        .str.lower()
    )

    endpoint["critical_flag"] = severity.eq("critical")

    return endpoint


def build_detection(
    user_key,
    threat_type,
    severity,
    confidence,
    evidence,
    first_observed=pd.NaT,
    last_observed=pd.NaT,
    related_hostname=pd.NA,
    related_alert_count=0,
    recommended_action="Review user activity",
):
    """Create a standardized threat detection record."""

    return {
        "user_id": user_key,
        "threat_type": threat_type,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "first_observed": first_observed,
        "last_observed": last_observed,
        "related_hostname": related_hostname,
        "related_alert_count": related_alert_count,
        "recommended_action": recommended_action,
    }


def _temporal_pairs(left, right, left_time, right_time, window_hours=24):
    """Return same-user event pairs occurring within a time window."""
    left_valid = left[left[left_time].notna()].copy()
    right_valid = right[right[right_time].notna()].copy()

    if left_valid.empty or right_valid.empty:
        return pd.DataFrame()

    pairs = left_valid.merge(
        right_valid,
        on="user_key",
        how="inner",
        suffixes=("_left", "_right"),
    )

    if pairs.empty:
        return pairs

    col_left = f"{left_time}_left" if f"{left_time}_left" in pairs.columns else left_time
    col_right = f"{right_time}_right" if f"{right_time}_right" in pairs.columns else right_time

    delta_hours = (
        pairs[col_right] - pairs[col_left]
    ).abs().dt.total_seconds() / 3600.0

    matched = pairs.loc[delta_hours <= window_hours].copy()
    if matched.empty:
        return matched

    matched["_delta_hours"] = delta_hours.loc[matched.index]
    matched[f"{left_time}_left"] = matched[col_left]
    matched[f"{right_time}_right"] = matched[col_right]
    matched["timestamp_left"] = matched[col_left]
    matched["timestamp_right"] = matched[col_right]

    return matched


def detect_post_termination_activity(identity_user, iam, endpoint):
    """Detect post-termination telemetry, consolidated to one detection per user."""
    detections = []

    dates = identity_user[["user_key", "termination_date"]].dropna(
        subset=["user_key", "termination_date"]
    )

    iam_check = iam.merge(dates, on="user_key", how="inner")
    iam_check = iam_check[
        iam_check["timestamp"].notna()
        & (iam_check["timestamp"] > iam_check["termination_date"])
    ]

    endpoint_check = endpoint.merge(dates, on="user_key", how="inner")
    endpoint_check = endpoint_check[
        endpoint_check["detected_timestamp"].notna()
        & (endpoint_check["detected_timestamp"] > endpoint_check["termination_date"])
    ]

    affected_users = sorted(
        set(iam_check["user_key"].dropna())
        | set(endpoint_check["user_key"].dropna())
    )

    for user_key in affected_users:
        ig = iam_check[iam_check["user_key"] == user_key]
        eg = endpoint_check[endpoint_check["user_key"] == user_key]

        timestamps = ig["timestamp"].dropna().tolist()
        timestamps += eg["detected_timestamp"].dropna().tolist()
        hostnames = ig["hostname"].dropna().tolist() + eg["hostname"].dropna().tolist()

        source_parts = []
        if not ig.empty:
            source_parts.append(f"{len(ig)} IAM")
        if not eg.empty:
            source_parts.append(f"{len(eg)} endpoint")

        corroborated = len(source_parts) == 2
        detections.append(
            build_detection(
                user_key=user_key,
                threat_type="Post-Termination Activity",
                severity="Critical",
                confidence="High" if corroborated else "Medium",
                evidence=(
                    f"{' and '.join(source_parts)} events occurred after the recorded termination date"
                    + ("; corroborated across IAM and endpoint telemetry" if corroborated else "")
                ),
                first_observed=min(timestamps) if timestamps else pd.NaT,
                last_observed=max(timestamps) if timestamps else pd.NaT,
                related_hostname=hostnames[0] if hostnames else pd.NA,
                related_alert_count=len(timestamps),
                recommended_action=(
                    "Immediately review account status and both IAM and endpoint activity; revoke unauthorized access if confirmed"
                    if corroborated
                    else "Review post-termination telemetry, account status, and access authorization"
                ),
            )
        )

    return detections


def detect_credential_compromise(iam, endpoint, window_hours=24):
    """Detect failed-authentication/MFA activity with credential-access evidence in one 24-hour window."""
    detections = []

    iam_events = iam[iam["user_key"].notna() & iam["timestamp"].notna()].copy()
    endpoint_events = endpoint[
        endpoint["user_key"].notna()
        & endpoint["detected_timestamp"].notna()
        & endpoint["credential_flag"]
    ].copy()

    if iam_events.empty or endpoint_events.empty:
        return detections

    for user_key, iam_group in iam_events.groupby("user_key"):
        credential_group = endpoint_events[endpoint_events["user_key"] == user_key]
        if credential_group.empty:
            continue

        iam_group = iam_group.sort_values("timestamp")
        detected = False

        for _, anchor in iam_group.iterrows():
            start = anchor["timestamp"]
            end = start + pd.Timedelta(hours=window_hours)
            iw = iam_group[(iam_group["timestamp"] >= start) & (iam_group["timestamp"] <= end)]
            ew = credential_group[
                (credential_group["detected_timestamp"] >= start)
                & (credential_group["detected_timestamp"] <= end)
            ]

            failed_auth = int(iw["failed_auth_flag"].sum())
            mfa_failures = int(iw["mfa_failure_flag"].sum())
            credential_alerts = len(ew)

            if failed_auth >= 3 and mfa_failures >= 2 and credential_alerts > 0:
                timestamps = iw["timestamp"].dropna().tolist() + ew["detected_timestamp"].dropna().tolist()
                hostnames = [normalize_hostname(x) for x in iw["hostname"].dropna().tolist() + ew["hostname"].dropna().tolist()]
                hostnames = [x for x in hostnames if pd.notna(x)]

                detections.append(
                    build_detection(
                        user_key=user_key,
                        threat_type="Potential Credential Compromise",
                        severity="High",
                        confidence="High",
                        evidence=(
                            f"{failed_auth} failed authentication events, {mfa_failures} MFA failures, "
                            f"and {credential_alerts} credential-access endpoint alerts within {window_hours} hours"
                        ),
                        first_observed=min(timestamps),
                        last_observed=max(timestamps),
                        related_hostname=hostnames[0] if hostnames else pd.NA,
                        related_alert_count=credential_alerts,
                        recommended_action="Investigate the authentication sequence, MFA failures, and credential-access activity",
                    )
                )
                detected = True
                break

        if detected:
            continue

    return detections


def detect_malware_lateral_movement(endpoint, window_hours=24):
    """Detect temporally correlated malware and lateral-movement activity."""
    detections = []

    events = endpoint[endpoint["user_key"].notna() & endpoint["detected_timestamp"].notna()].copy()
    malware = events[events["malware_flag"]].copy()
    lateral = events[events["lateral_flag"]].copy()

    if malware.empty or lateral.empty:
        return detections

    for user_key in sorted(set(malware["user_key"]) & set(lateral["user_key"])):
        mg = malware[malware["user_key"] == user_key]
        lg = lateral[lateral["user_key"] == user_key]

        same_host_pairs = _temporal_pairs(
            mg[["user_key", "hostname_key", "detected_timestamp"]],
            lg[["user_key", "hostname_key", "detected_timestamp"]],
            "detected_timestamp", "detected_timestamp", window_hours
        )
        same_host_pairs = same_host_pairs[
            same_host_pairs["hostname_key_left"].notna()
            & same_host_pairs["hostname_key_right"].notna()
            & (same_host_pairs["hostname_key_left"] == same_host_pairs["hostname_key_right"])
        ]

        if not same_host_pairs.empty:
            pair = same_host_pairs.sort_values("_delta_hours").iloc[0]
            detections.append(
                build_detection(
                    user_key=user_key,
                    threat_type="Malware + Lateral Movement",
                    severity="Critical",
                    confidence="High",
                    evidence=(
                        f"Malware and lateral-movement alerts were observed on the same hostname "
                        f"({pair['hostname_key_left']}) within {window_hours} hours"
                    ),
                    first_observed=min(pair["detected_timestamp_left"], pair["detected_timestamp_right"]),
                    last_observed=max(pair["detected_timestamp_left"], pair["detected_timestamp_right"]),
                    related_hostname=pair["hostname_key_left"],
                    related_alert_count=2,
                    recommended_action="Isolate the affected endpoint and investigate lateral-movement indicators immediately",
                )
            )
            continue

        pairs = _temporal_pairs(
            mg[["user_key", "detected_timestamp"]],
            lg[["user_key", "detected_timestamp"]],
            "detected_timestamp", "detected_timestamp", window_hours
        )
        if pairs.empty:
            continue

        pair = pairs.sort_values("_delta_hours").iloc[0]
        detections.append(
            build_detection(
                user_key=user_key,
                threat_type="Malware + Lateral Movement",
                severity="High",
                confidence="Medium",
                evidence=(
                    f"Malware and lateral-movement alerts were observed for the same user within {window_hours} hours, "
                    "but same-host corroboration was unavailable"
                ),
                first_observed=min(pair["detected_timestamp_left"], pair["detected_timestamp_right"]),
                last_observed=max(pair["detected_timestamp_left"], pair["detected_timestamp_right"]),
                related_hostname=pd.NA,
                related_alert_count=2,
                recommended_action="Review endpoint telemetry and validate the affected asset before escalation",
            )
        )

    return detections


def detect_administrative_abuse(iam, endpoint, window_hours=24):
    """Detect high-risk IAM activity temporally correlated with PowerShell/tampering."""
    detections = []

    iam_events = iam[iam["user_key"].notna() & iam["timestamp"].notna() & iam["high_risk_flag"]].copy()
    endpoint_events = endpoint[
        endpoint["user_key"].notna()
        & endpoint["detected_timestamp"].notna()
        & (endpoint["powershell_flag"] | endpoint["tampering_flag"])
    ].copy()

    if iam_events.empty or endpoint_events.empty:
        return detections

    for user_key in sorted(set(iam_events["user_key"]) & set(endpoint_events["user_key"])):
        ig = iam_events[iam_events["user_key"] == user_key]
        eg = endpoint_events[endpoint_events["user_key"] == user_key]

        same_host_pairs = _temporal_pairs(
            ig[["user_key", "hostname_key", "timestamp"]],
            eg[["user_key", "hostname_key", "detected_timestamp", "powershell_flag", "tampering_flag"]],
            "timestamp", "detected_timestamp", window_hours
        )
        same_host_pairs = same_host_pairs[
            same_host_pairs["hostname_key_left"].notna()
            & same_host_pairs["hostname_key_right"].notna()
            & (same_host_pairs["hostname_key_left"] == same_host_pairs["hostname_key_right"])
        ]

        if not same_host_pairs.empty:
            pair = same_host_pairs.sort_values("_delta_hours").iloc[0]
            indicators = []
            if bool(pair["powershell_flag"]):
                indicators.append("PowerShell")
            if bool(pair["tampering_flag"]):
                indicators.append("security-tampering")

            detections.append(
                build_detection(
                    user_key=user_key,
                    threat_type="Suspicious Administrative Activity",
                    severity="High",
                    confidence="High",
                    evidence=(
                        f"A high-risk IAM event and {' and '.join(indicators)} activity were observed on the same hostname "
                        f"({pair['hostname_key_left']}) within {window_hours} hours"
                    ),
                    first_observed=min(pair["timestamp_left"], pair["detected_timestamp_right"]),
                    last_observed=max(pair["timestamp_left"], pair["detected_timestamp_right"]),
                    related_hostname=pair["hostname_key_left"],
                    related_alert_count=2,
                    recommended_action="Review the administrative command/process activity and associated account actions",
                )
            )
            continue

        pairs = _temporal_pairs(
            ig[["user_key", "timestamp"]],
            eg[["user_key", "detected_timestamp", "powershell_flag", "tampering_flag"]],
            "timestamp", "detected_timestamp", window_hours
        )
        if pairs.empty:
            continue

        pair = pairs.sort_values("_delta_hours").iloc[0]
        indicators = []
        if bool(pair["powershell_flag"]):
            indicators.append("PowerShell")
        if bool(pair["tampering_flag"]):
            indicators.append("security-tampering")

        detections.append(
            build_detection(
                user_key=user_key,
                threat_type="Suspicious Administrative Activity",
                severity="High",
                confidence="Medium",
                evidence=(
                    f"A high-risk IAM event and {' and '.join(indicators)} activity were observed for the same user "
                    f"within {window_hours} hours, but same-host corroboration was unavailable"
                ),
                first_observed=min(pair["timestamp_left"], pair["detected_timestamp_right"]),
                last_observed=max(pair["timestamp_left"], pair["detected_timestamp_right"]),
                related_hostname=pd.NA,
                related_alert_count=2,
                recommended_action="Review the administrative command/process activity and validate the associated account actions",
            )
        )

    return detections


def detect_identity_hostname_mismatch(identity, iam, endpoint):
    """Detect repeated observed hostnames not assigned to the user in the identity master."""
    detections = []

    identity_pairs = identity[["user_key", "hostname_key"]].dropna().drop_duplicates()
    valid_pairs = set(zip(identity_pairs["user_key"], identity_pairs["hostname_key"]))

    telemetry = pd.concat(
        [
            iam[["user_key", "hostname_key", "timestamp"]].rename(columns={"timestamp": "observed_timestamp"}),
            endpoint[["user_key", "hostname_key", "detected_timestamp"]].rename(columns={"detected_timestamp": "observed_timestamp"}),
        ],
        ignore_index=True,
    ).dropna(subset=["user_key", "hostname_key"])

    telemetry["valid_identity_pair"] = list(zip(telemetry["user_key"], telemetry["hostname_key"]))
    telemetry = telemetry[~telemetry["valid_identity_pair"].isin(valid_pairs)]

    grouped = telemetry.groupby(["user_key", "hostname_key"]).agg(
        event_count=("user_key", "size"),
        first_observed=("observed_timestamp", "min"),
        last_observed=("observed_timestamp", "max"),
    ).reset_index()

    grouped = grouped[grouped["event_count"] >= 2]

    for _, row in grouped.iterrows():
        detections.append(
            build_detection(
                user_key=row["user_key"],
                threat_type="Identity / Hostname Mismatch",
                severity="Medium",
                confidence="Medium",
                evidence=(
                    f"{int(row['event_count'])} telemetry events observed on hostname {row['hostname_key']}, "
                    "which is not assigned to this user in the identity master"
                ),
                first_observed=row["first_observed"],
                last_observed=row["last_observed"],
                related_hostname=row["hostname_key"],
                related_alert_count=int(row["event_count"]),
                recommended_action="Verify asset ownership, account sharing, and recent device changes",
            )
        )

    return detections

def main():

    print("=" * 60)
    print("THREAT DETECTION ANALYTICS")
    print("=" * 60)

    identity, iam, endpoint = load_data()

    print("\nLoaded datasets:")
    print(f"Identity : {identity.shape}")
    print(f"IAM      : {iam.shape}")
    print(f"Endpoint : {endpoint.shape}")

    identity, identity_user = prepare_identity(
        identity
    )

    iam = prepare_iam(iam)
    endpoint = prepare_endpoint(endpoint)

    detections = []

    print("\nRunning detection scenarios...")

    detections.extend(
        detect_post_termination_activity(
            identity_user,
            iam,
            endpoint,
        )
    )

    detections.extend(
        detect_credential_compromise(
            iam,
            endpoint,
            window_hours=24,
        )
    )

    detections.extend(
        detect_malware_lateral_movement(
            endpoint,
            window_hours=24,
        )
    )

    detections.extend(
        detect_administrative_abuse(
            iam,
            endpoint,
            window_hours=24,
        )
    )

    detections.extend(
        detect_identity_hostname_mismatch(
            identity,
            iam,
            endpoint,
        )
    )

    result = pd.DataFrame(detections)

    if result.empty:
        print("\nNo threat detections generated.")
        return

    # Add stable detection IDs.
    result.insert(
        0,
        "threat_id",
        [
            f"THR{i:05d}"
            for i in range(1, len(result) + 1)
        ],
    )

    result["first_observed"] = pd.to_datetime(
        result["first_observed"],
        errors="coerce",
    )

    result["last_observed"] = pd.to_datetime(
        result["last_observed"],
        errors="coerce",
    )

    result = result.sort_values(
    ["severity", "confidence", "threat_type"],
    ascending=[True, True, True],
    )

    ANALYTICS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path = (
        ANALYTICS_DIR / "threat_detections.csv"
    )

    result.to_csv(
        output_path,
        index=False,
    )

    # Summary reports.
    threat_summary = (
        result["threat_type"]
        .value_counts()
        .rename_axis("threat_type")
        .reset_index(name="detection_count")
    )

    severity_summary = (
        result["severity"]
        .value_counts()
        .rename_axis("severity")
        .reset_index(name="detection_count")
    )

    threat_summary.to_csv(
        REPORT_DIR / "threat_type_summary.csv",
        index=False,
    )

    severity_summary.to_csv(
        REPORT_DIR / "threat_severity_summary.csv",
        index=False,
    )

    print("\n" + "=" * 60)
    print("THREAT DETECTION SUMMARY")
    print("=" * 60)

    print(
        threat_summary.to_string(index=False)
    )

    print("\nSeverity:")
    print(
        severity_summary.to_string(index=False)
    )

    print("\nTotal detections:", len(result))
    print(
        "Affected users:",
        result["user_id"].nunique(),
    )

    print("\n" + "=" * 60)
    print("FILES SAVED")
    print("=" * 60)

    print(f"✓ Threat detections : {output_path}")
    print(
        "✓ Threat type summary : "
        f"{REPORT_DIR / 'threat_type_summary.csv'}"
    )
    print(
        "✓ Severity summary    : "
        f"{REPORT_DIR / 'threat_severity_summary.csv'}"
    )

    print("\n" + "=" * 60)
    print("THREAT DETECTION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()