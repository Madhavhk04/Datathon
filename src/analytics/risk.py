from pathlib import Path

import numpy as np
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
    if not value or value in {"NAN", "NONE", "NULL", "NA", "<NA>"}:
        return pd.NA

    if value.isdigit():
        return f"EMP{value}"

    return value


def load_data():
    """Load production-cleaned datasets."""
    identity = pd.read_csv(IDENTITY_PATH)
    iam = pd.read_csv(IAM_PATH)
    endpoint = pd.read_csv(ENDPOINT_PATH)

    return identity, iam, endpoint


def prepare_identity(identity):
    """Create the user-level identity reference."""
    identity = identity.copy()

    identity["user_key"] = identity["user_id"].map(
        normalize_key
    )

    # One user can legitimately have multiple identity/asset records.
    # Aggregate rather than duplicating telemetry during joins.
    identity_user = (
        identity.dropna(subset=["user_key"])
        .groupby("user_key")
        .agg(
            username=("username", "first"),
            department=("department", "first"),
            role=("role", "first"),
            status=("status", "first"),
            hostname_count=("hostname", "nunique"),
            device_count=("device_id", "nunique"),
        )
        .reset_index()
    )

    return identity_user


def prepare_iam(iam):
    """Generate user-level IAM threat and temporal activity evidence."""

    iam = iam.copy()

    iam["user_key"] = iam["user_id"].map(normalize_key)

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

    risk_col = "risk_score" if "risk_score" in iam.columns else "risk_score_numeric"
    risk_score = pd.to_numeric(
        iam[risk_col],
        errors="coerce",
    )

    failed_auth = (
        event_type.str.contains(
            r"fail|denied|reject",
            regex=True,
            na=False,
        )
        | failure_reason.str.len().gt(0)
    )

    mfa_failure = (
        iam["mfa_passed"].astype("string").str.upper()
        == "FALSE"
    )

    high_risk = risk_score >= 70

    iam["failed_auth_flag"] = failed_auth
    iam["mfa_failure_flag"] = mfa_failure
    iam["high_risk_flag"] = high_risk

    aggregation = (
        iam.dropna(subset=["user_key"])
        .groupby("user_key")
        .agg(
            iam_events=("event_id", "count"),
            iam_failed_auth=("failed_auth_flag", "sum"),
            iam_mfa_failures=("mfa_failure_flag", "sum"),
            iam_high_risk_events=("high_risk_flag", "sum"),
            iam_avg_risk_score=(risk_col, "mean"),
            iam_max_risk_score=(risk_col, "max"),
            iam_hostname_count=("hostname", "nunique"),
            iam_session_count=("session_id", "nunique"),
        )
        .reset_index()
    )

    return aggregation


def classify_endpoint_alerts(endpoint):
    """Create transparent endpoint threat-category flags."""

    endpoint = endpoint.copy()

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

    endpoint["credential_access_flag"] = text.str.contains(
        r"credential|keylogger",
        regex=True,
        na=False,
    )

    endpoint["lateral_movement_flag"] = text.str.contains(
        r"lateral|admin share",
        regex=True,
        na=False,
    )

    endpoint["powershell_flag"] = text.str.contains(
        r"powershell",
        regex=True,
        na=False,
    )

    endpoint["usb_flag"] = text.str.contains(
        r"usb",
        regex=True,
        na=False,
    )

    endpoint["tampering_flag"] = text.str.contains(
        r"disable security|tamper",
        regex=True,
        na=False,
    )

    return endpoint


def prepare_endpoint(endpoint):
    """Generate user-level endpoint threat evidence."""

    endpoint = endpoint.copy()

    endpoint["user_key"] = endpoint["user_id"].map(
        normalize_key
    )

    endpoint = classify_endpoint_alerts(endpoint)

    severity = (
        endpoint["severity"]
        .fillna("")
        .astype(str)
        .str.lower()
    )

    status = (
        endpoint["status"]
        .fillna("")
        .astype(str)
        .str.lower()
    )

    endpoint["critical_flag"] = severity.eq(
        "critical"
    )

    endpoint["high_flag"] = severity.eq(
        "high"
    )

    endpoint["unresolved_critical_flag"] = (
        endpoint["critical_flag"]
        & endpoint["unresolved_alert_flag"].fillna(False)
    )

    endpoint["impossible_resolution_flag"] = (
        endpoint["impossible_resolution_flag"]
        .fillna(False)
    )

    aggregation = (
        endpoint.dropna(subset=["user_key"])
        .groupby("user_key")
        .agg(
            endpoint_alerts=("alert_id", "count"),
            endpoint_critical_alerts=(
                "critical_flag",
                "sum",
            ),
            endpoint_high_alerts=(
                "high_flag",
                "sum",
            ),
            endpoint_unresolved_critical=(
                "unresolved_critical_flag",
                "sum",
            ),
            endpoint_malware_alerts=(
                "malware_flag",
                "sum",
            ),
            endpoint_credential_alerts=(
                "credential_access_flag",
                "sum",
            ),
            endpoint_lateral_movement=(
                "lateral_movement_flag",
                "sum",
            ),
            endpoint_powershell=(
                "powershell_flag",
                "sum",
            ),
            endpoint_tampering=(
                "tampering_flag",
                "sum",
            ),
            endpoint_usb=(
                "usb_flag",
                "sum",
            ),
            endpoint_impossible_resolution=(
                "impossible_resolution_flag",
                "sum",
            ),
            endpoint_hostname_count=(
                "hostname",
                "nunique",
            ),
        )
        .reset_index()
    )

    return aggregation


def add_identity_activity_flags(result, iam, endpoint, identity):
    """
    Identify telemetry occurring after an identity's termination date.

    Only activity with a valid timestamp strictly after a known
    termination date is counted as post-termination activity.
    """

    result = result.copy()

    identity_dates = identity.copy()
    if "user_key" not in identity_dates.columns:
        identity_dates["user_key"] = identity_dates["user_id"].map(
            normalize_key
        )

    identity_dates = identity_dates[
        ["user_key", "termination_date"]
    ].copy()

    identity_dates["termination_date"] = pd.to_datetime(
        identity_dates["termination_date"],
        errors="coerce",
    )

    # One termination date per user.
    identity_dates = (
        identity_dates
        .dropna(subset=["user_key"])
        .groupby("user_key")["termination_date"]
        .max()
        .reset_index()
    )

    result = result.merge(
        identity_dates,
        on="user_key",
        how="left",
    )

    iam_activity = iam[
        ["user_id", "timestamp"]
    ].copy()

    iam_activity["user_key"] = iam_activity["user_id"].map(
        normalize_key
    )

    iam_activity["timestamp"] = pd.to_datetime(
        iam_activity["timestamp"],
        errors="coerce",
    )

    iam_activity = iam_activity.merge(
        identity_dates,
        on="user_key",
        how="left",
    )

    iam_activity["post_termination_flag"] = (
        iam_activity["termination_date"].notna()
        & iam_activity["timestamp"].notna()
        & (
            iam_activity["timestamp"]
            > iam_activity["termination_date"]
        )
    )

    iam_post = (
        iam_activity
        .groupby("user_key")["post_termination_flag"]
        .sum()
        .rename("post_termination_iam_events")
        .reset_index()
    )

    endpoint_activity = endpoint[
        ["user_id", "detected_timestamp"]
    ].copy()

    endpoint_activity["user_key"] = (
        endpoint_activity["user_id"]
        .map(normalize_key)
    )

    endpoint_activity["detected_timestamp"] = pd.to_datetime(
        endpoint_activity["detected_timestamp"],
        errors="coerce",
    )

    endpoint_activity = endpoint_activity.merge(
        identity_dates,
        on="user_key",
        how="left",
    )

    endpoint_activity["post_termination_flag"] = (
        endpoint_activity["termination_date"].notna()
        & endpoint_activity["detected_timestamp"].notna()
        & (
            endpoint_activity["detected_timestamp"]
            > endpoint_activity["termination_date"]
        )
    )

    endpoint_post = (
        endpoint_activity
        .groupby("user_key")["post_termination_flag"]
        .sum()
        .rename("post_termination_endpoint_events")
        .reset_index()
    )

    result = result.merge(
        iam_post,
        on="user_key",
        how="left",
    )

    result = result.merge(
        endpoint_post,
        on="user_key",
        how="left",
    )

    result["post_termination_iam_events"] = (
        result["post_termination_iam_events"]
        .fillna(0)
        .astype(int)
    )

    result["post_termination_endpoint_events"] = (
        result["post_termination_endpoint_events"]
        .fillna(0)
        .astype(int)
    )

    result["post_termination_activity"] = (
        result["post_termination_iam_events"]
        + result["post_termination_endpoint_events"]
    )

    result["post_termination_activity_flag"] = (
        result["post_termination_activity"] > 0
    )

    return result


def calculate_risk_score(result):
    """
    Calculate an explainable 0-100 user risk score.

    Repeated events are capped so high telemetry volume alone does not
    dominate the score. The model prioritizes combinations of strong
    security signals while retaining transparent component scores.

    This is a triage/prioritization score, not proof of compromise.
    """

    result = result.copy()

    numeric_columns = [
        "iam_failed_auth",
        "iam_mfa_failures",
        "iam_high_risk_events",
        "endpoint_critical_alerts",
        "endpoint_high_alerts",
        "endpoint_unresolved_critical",
        "endpoint_malware_alerts",
        "endpoint_credential_alerts",
        "endpoint_lateral_movement",
        "endpoint_powershell",
        "endpoint_tampering",
        "endpoint_usb",
        "endpoint_impossible_resolution",
        "post_termination_activity",
    ]

    for column in numeric_columns:
        result[column] = pd.to_numeric(
            result[column],
            errors="coerce",
        ).fillna(0)

    # ----------------------------------------------------------
    # 1. AUTHENTICATION RISK — maximum 20 points
    # ----------------------------------------------------------

    result["authentication_risk"] = (
        np.minimum(result["iam_failed_auth"], 10)
        + np.minimum(result["iam_mfa_failures"] * 1.5, 10)
    )

    result["authentication_risk"] = np.minimum(
        result["authentication_risk"],
        20,
    )

    # ----------------------------------------------------------
    # 2. IAM RISK — maximum 20 points
    # ----------------------------------------------------------

    result["iam_risk"] = np.minimum(
        result["iam_high_risk_events"] * 2,
        15,
    )

    # Repeated authentication + high-risk IAM activity is stronger
    # than either signal alone.
    result["iam_risk"] += np.where(
        (
            (result["iam_failed_auth"] >= 5)
            & (result["iam_high_risk_events"] >= 3)
        ),
        5,
        0,
    )

    result["iam_risk"] = np.minimum(
        result["iam_risk"],
        20,
    )

    # ----------------------------------------------------------
    # 3. ENDPOINT SEVERITY RISK — maximum 20 points
    # ----------------------------------------------------------

    result["endpoint_severity_risk"] = (
        np.minimum(
            result["endpoint_critical_alerts"] * 5,
            15,
        )
        + np.minimum(
            result["endpoint_high_alerts"] * 2,
            5,
        )
    )

    result["endpoint_severity_risk"] = np.minimum(
        result["endpoint_severity_risk"],
        20,
    )

    # ----------------------------------------------------------
    # 4. THREAT BEHAVIOR RISK — maximum 30 points
    # ----------------------------------------------------------

    result["threat_behavior_risk"] = (
        np.minimum(
            result["endpoint_malware_alerts"] * 6,
            12,
        )
        + np.minimum(
            result["endpoint_credential_alerts"] * 6,
            8,
        )
        + np.minimum(
            result["endpoint_lateral_movement"] * 6,
            8,
        )
        + np.minimum(
            result["endpoint_powershell"] * 3,
            4,
        )
        + np.minimum(
            result["endpoint_tampering"] * 4,
            5,
        )
        + np.minimum(
            result["endpoint_usb"] * 1,
            2,
        )
    )

    result["threat_behavior_risk"] = np.minimum(
        result["threat_behavior_risk"],
        30,
    )

    # ----------------------------------------------------------
    # 5. CONTEXTUAL / IDENTITY RISK — maximum 15 points
    # ----------------------------------------------------------

    result["contextual_risk"] = np.minimum(
        result["post_termination_activity"] * 3,
        10,
    )

    result["contextual_risk"] += np.minimum(
        result["endpoint_unresolved_critical"] * 2,
        5,
    )

    result["contextual_risk"] = np.minimum(
        result["contextual_risk"],
        15,
    )

    # ----------------------------------------------------------
    # CROSS-SIGNAL ESCALATION
    # ----------------------------------------------------------
    #
    # Strong combinations receive a limited bonus.
    # This prevents isolated noisy indicators from dominating
    # while rewarding corroborating evidence.

    result["cross_signal_bonus"] = 0

    # Authentication + endpoint threat
    result.loc[
        (
            (result["authentication_risk"] >= 8)
            & (result["threat_behavior_risk"] >= 6)
        ),
        "cross_signal_bonus",
    ] += 5

    # Malware + credential access
    result.loc[
        (
            (result["endpoint_malware_alerts"] > 0)
            & (result["endpoint_credential_alerts"] > 0)
        ),
        "cross_signal_bonus",
    ] += 5

    # Malware + lateral movement
    result.loc[
        (
            (result["endpoint_malware_alerts"] > 0)
            & (result["endpoint_lateral_movement"] > 0)
        ),
        "cross_signal_bonus",
    ] += 5

    # MFA failures + high-risk IAM activity
    result.loc[
        (
            (result["iam_mfa_failures"] >= 3)
            & (result["iam_high_risk_events"] >= 3)
        ),
        "cross_signal_bonus",
    ] += 3

    result["cross_signal_bonus"] = np.minimum(
        result["cross_signal_bonus"],
        10,
    )

    # ----------------------------------------------------------
    # FINAL SCORE — 0 to 100
    # ----------------------------------------------------------

    result["risk_score"] = (
        result["authentication_risk"]
        + result["iam_risk"]
        + result["endpoint_severity_risk"]
        + result["threat_behavior_risk"]
        + result["contextual_risk"]
        + result["cross_signal_bonus"]
    )

    result["risk_score"] = np.minimum(
        result["risk_score"],
        100,
    )

    # ----------------------------------------------------------
    # RISK BANDS
    # ----------------------------------------------------------

    result["risk_band"] = pd.cut(
        result["risk_score"],
        bins=[
            -np.inf,
            24,
            49,
            74,
            np.inf,
        ],
        labels=[
            "Low",
            "Medium",
            "High",
            "Critical",
        ],
    ).astype(str)

    result["risk_level"] = result["risk_band"]

    return result


def generate_risk_drivers(result):
    """Create human-readable explanations of risk drivers."""

    def drivers(row):

        evidence = []

        if row["authentication_risk"] >= 8:
            evidence.append(
                f"elevated authentication risk "
                f"({int(row['iam_failed_auth'])} failed auth, "
                f"{int(row['iam_mfa_failures'])} MFA failures)"
            )

        elif row["iam_failed_auth"] > 0:
            evidence.append(
                f"{int(row['iam_failed_auth'])} failed authentication events"
            )

        if row["iam_high_risk_events"] > 0:
            evidence.append(
                f"{int(row['iam_high_risk_events'])} high-risk IAM events"
            )

        if row["endpoint_malware_alerts"] > 0:
            evidence.append(
                f"{int(row['endpoint_malware_alerts'])} malware alerts"
            )

        if row["endpoint_credential_alerts"] > 0:
            evidence.append(
                f"{int(row['endpoint_credential_alerts'])} credential-access alerts"
            )

        if row["endpoint_lateral_movement"] > 0:
            evidence.append(
                f"{int(row['endpoint_lateral_movement'])} lateral-movement alerts"
            )

        if row["endpoint_powershell"] > 0:
            evidence.append(
                f"{int(row['endpoint_powershell'])} PowerShell alerts"
            )

        if row["endpoint_tampering"] > 0:
            evidence.append(
                f"{int(row['endpoint_tampering'])} security-tampering alerts"
            )

        if row["endpoint_critical_alerts"] > 0:
            evidence.append(
                f"{int(row['endpoint_critical_alerts'])} critical endpoint alerts"
            )

        if row["post_termination_activity"] > 0:
            evidence.append(
                f"{int(row['post_termination_activity'])} "
                "events after identity termination"
            )

        if row["endpoint_unresolved_critical"] > 0:
            evidence.append(
                f"{int(row['endpoint_unresolved_critical'])} unresolved critical alerts"
            )

        if not evidence:
            evidence.append(
                "No high-priority risk drivers"
            )

        return "; ".join(evidence)

    result["risk_drivers"] = result.apply(
        drivers,
        axis=1,
    )

    return result


def main():

    print("=" * 60)
    print("USER RISK ANALYTICS")
    print("=" * 60)

    identity, iam, endpoint = load_data()

    print("\nLoaded datasets:")
    print(f"Identity : {identity.shape}")
    print(f"IAM      : {iam.shape}")
    print(f"Endpoint : {endpoint.shape}")

    identity_user = prepare_identity(identity)
    iam_user = prepare_iam(iam)
    endpoint_user = prepare_endpoint(endpoint)

    result = identity_user.merge(
        iam_user,
        on="user_key",
        how="left",
    )

    result = result.merge(
        endpoint_user,
        on="user_key",
        how="left",
    )

    numeric_columns = [
        column
        for column in result.columns
        if column not in {"user_key", "username", "department", "role", "status"}
    ]

    for column in numeric_columns:
        if pd.api.types.is_numeric_dtype(result[column]):
            result[column] = result[column].fillna(0)

    result = add_identity_activity_flags(
        result,
        iam,
        endpoint,
        identity,
    )

    result = calculate_risk_score(result)

    result = generate_risk_drivers(result)

    result = result.rename(
        columns={
            "user_key": "user_id",
        }
    )

    # Round analytical averages.
    for column in [
        "iam_avg_risk_score",
        "iam_max_risk_score",
    ]:
        if column in result.columns:
            result[column] = result[column].round(2)

    # Put the most important columns first.
    preferred_columns = [
        "user_id",
        "username",
        "department",
        "role",
        "status",
        "hostname_count",
        "device_count",
        "iam_events",
        "iam_failed_auth",
        "iam_mfa_failures",
        "iam_high_risk_events",
        "iam_avg_risk_score",
        "iam_max_risk_score",
        "iam_hostname_count",
        "iam_session_count",
        "endpoint_alerts",
        "endpoint_critical_alerts",
        "endpoint_high_alerts",
        "endpoint_unresolved_critical",
        "endpoint_malware_alerts",
        "endpoint_credential_alerts",
        "endpoint_lateral_movement",
        "endpoint_powershell",
        "endpoint_tampering",
        "endpoint_usb",
        "endpoint_impossible_resolution",
        "endpoint_hostname_count",
        "termination_date",
        "post_termination_iam_events",
        "post_termination_endpoint_events",
        "post_termination_activity",
        "post_termination_activity_flag",
        "authentication_risk",
        "iam_risk",
        "endpoint_severity_risk",
        "threat_behavior_risk",
        "contextual_risk",
        "cross_signal_bonus",
        "risk_score",
        "risk_level",
        "risk_band",
        "risk_drivers",
    ]

    preferred_columns = [
        column
        for column in preferred_columns
        if column in result.columns
    ]

    result = result[
        preferred_columns
        + [
            column
            for column in result.columns
            if column not in preferred_columns
        ]
    ]

    ANALYTICS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path = (
        ANALYTICS_DIR / "user_risk_scores.csv"
    )

    result.to_csv(
        output_path,
        index=False,
    )

    # Risk distribution report.
    distribution = (
        result["risk_band"]
        .value_counts()
        .reindex(
            [
                "Low",
                "Medium",
                "High",
                "Critical",
            ],
            fill_value=0,
        )
        .rename_axis("risk_band")
        .reset_index(name="user_count")
    )

    distribution["percentage"] = (
        distribution["user_count"]
        / len(result)
        * 100
    ).round(2)

    distribution.to_csv(
        REPORT_DIR / "risk_band_distribution.csv",
        index=False,
    )

    # Top-risk users.
    top_risk = (
        result.sort_values(
            ["risk_score", "endpoint_critical_alerts"],
            ascending=False,
        )
        .head(100)
    )

    top_risk.to_csv(
        REPORT_DIR / "top_100_risk_users.csv",
        index=False,
    )

    print("\n" + "=" * 60)
    print("RISK DISTRIBUTION")
    print("=" * 60)

    print(
        distribution.to_string(index=False)
    )

    print("\n" + "=" * 60)
    print("TOP RISK USERS")
    print("=" * 60)

    print(
        result[
            [
                "user_id",
                "username",
                "department",
                "risk_score",
                "risk_band",
                "risk_drivers",
            ]
        ]
        .sort_values(
            "risk_score",
            ascending=False,
        )
        .head(10)
        .to_string(index=False)
    )

    print("\n" + "=" * 60)
    print("FILES SAVED")
    print("=" * 60)

    print(f"✓ User risk scores : {output_path}")
    print(
        "✓ Risk distribution : "
        f"{REPORT_DIR / 'risk_band_distribution.csv'}"
    )
    print(
        "✓ Top 100 users     : "
        f"{REPORT_DIR / 'top_100_risk_users.csv'}"
    )

    print("\n" + "=" * 60)
    print("USER RISK ANALYTICS COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()