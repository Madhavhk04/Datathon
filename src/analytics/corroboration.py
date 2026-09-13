from pathlib import Path

import pandas as pd


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

THREAT_PATH = (
    ROOT
    / "data"
    / "analytics"
    / "threat_detections.csv"
)

RISK_PATH = (
    ROOT
    / "data"
    / "analytics"
    / "user_risk_scores.csv"
)

IDENTITY_PATH = (
    ROOT
    / "data"
    / "processed"
    / "track2_identity_asset_master_clean.csv"
)

OUTPUT_PATH = (
    ROOT
    / "data"
    / "analytics"
    / "investigation_queue.csv"
)

REPORT_PATH = (
    ROOT
    / "reports"
    / "analytics"
    / "investigation_queue_summary.csv"
)


# ============================================================
# HELPERS
# ============================================================

SEVERITY_ORDER = {
    "Critical": 3,
    "High": 2,
    "Medium": 1,
    "Low": 0,
}

CONFIDENCE_ORDER = {
    "High": 3,
    "Medium": 2,
    "Low": 1,
}


def normalize_text(series):
    return (
        series
        .astype("string")
        .str.strip()
    )


def normalize_user_key(series):
    cleaned = series.astype("string").str.strip().str.upper()
    return cleaned.apply(
        lambda x: f"EMP{x}" if pd.notna(x) and str(x).isdigit() else x
    )


# ============================================================
# LOAD DATA
# ============================================================

def load_data():
    threats = pd.read_csv(THREAT_PATH)
    risk = pd.read_csv(RISK_PATH)
    identity = pd.read_csv(IDENTITY_PATH)

    print("Loaded datasets:")
    print(f"Threat detections : {threats.shape}")
    print(f"Risk scores       : {risk.shape}")
    print(f"Identity          : {identity.shape}")

    return threats, risk, identity


# ============================================================
# PREPARE THREAT DATA
# ============================================================

def prepare_threats(threats):

    threats = threats.copy()

    threats["user_id"] = normalize_user_key(threats["user_id"])
    threats["threat_type"] = normalize_text(threats["threat_type"])
    threats["severity"] = normalize_text(threats["severity"])
    threats["confidence"] = normalize_text(threats["confidence"])

    threats["severity_rank"] = (
        threats["severity"]
        .map(SEVERITY_ORDER)
        .fillna(0)
    )

    threats["confidence_rank"] = (
        threats["confidence"]
        .map(CONFIDENCE_ORDER)
        .fillna(0)
    )

    return threats


# ============================================================
# PREPARE RISK DATA
# ============================================================

def prepare_risk(risk):

    risk = risk.copy()

    risk["user_id"] = normalize_user_key(risk["user_id"])

    risk["risk_score"] = pd.to_numeric(
        risk["risk_score"],
        errors="coerce"
    ).fillna(0)

    risk_level_col = (
        "risk_level"
        if "risk_level" in risk.columns
        else "risk_band"
    )

    risk["risk_level"] = normalize_text(
        risk[risk_level_col]
    )

    return risk


# ============================================================
# PREPARE IDENTITY DATA
# ============================================================

def prepare_identity(identity):

    identity = identity.copy()

    identity["user_id"] = normalize_user_key(
        identity["user_id"]
    )

    # Keep only the identity/asset context needed by
    # the investigation queue.
    columns = [
        "user_id",
        "full_name",
        "role",
        "department",
        "location",
        "status",
        "username",
        "hostname",
        "device_id",
        "manager_username",
        "device_id_conflict",
        "device_user_count",
    ]

    columns = [
        col for col in columns
        if col in identity.columns
    ]

    identity = identity[columns].copy()

    # Identity can contain multiple records for a user.
    # Keep the first canonical record while preserving
    # conflict indicators already calculated upstream.
    identity = (
        identity
        .sort_values(
            ["user_id"],
            na_position="last"
        )
        .drop_duplicates(
            subset=["user_id"],
            keep="first"
        )
    )

    return identity


# ============================================================
# BUILD USER-LEVEL CORROBORATION
# ============================================================

def build_corroboration(threats):

    grouped = (
        threats
        .groupby("user_id", dropna=False)
        .agg(
            threat_detection_count=(
                "threat_type",
                "size"
            ),
            distinct_threat_types=(
                "threat_type",
                "nunique"
            ),
            threat_types=(
                "threat_type",
                lambda x: " | ".join(sorted(x.dropna().unique()))
            ),
            critical_detections=(
                "severity",
                lambda x: (x == "Critical").sum()
            ),
            high_detections=(
                "severity",
                lambda x: (x == "High").sum()
            ),
            medium_detections=(
                "severity",
                lambda x: (x == "Medium").sum()
            ),
            highest_severity_rank=(
                "severity_rank",
                "max"
            ),
            highest_confidence_rank=(
                "confidence_rank",
                "max"
            ),
        )
        .reset_index()
    )

    # Recover the display values for highest severity
    severity_lookup = {
        3: "Critical",
        2: "High",
        1: "Medium",
        0: "Low",
    }

    confidence_lookup = {
        3: "High",
        2: "Medium",
        1: "Low",
        0: "Low",
    }

    grouped["highest_severity"] = (
        grouped["highest_severity_rank"]
        .map(severity_lookup)
        .fillna("Low")
    )

    grouped["highest_confidence"] = (
        grouped["highest_confidence_rank"]
        .map(confidence_lookup)
        .fillna("Low")
    )

    return grouped


# ============================================================
# INVESTIGATION PRIORITY
# ============================================================

def calculate_priority(row):

    risk_score = row["risk_score"]
    threat_count = row["threat_detection_count"]
    distinct_types = row["distinct_threat_types"]
    critical = row["critical_detections"]
    high = row["high_detections"]

    # Risk score remains the primary prioritization signal.
    #
    # Corroboration acts as a bounded modifier:
    # - multiple threat types
    # - critical/high detections
    #
    # This does NOT replace the existing risk model.

    corroboration_bonus = 0

    if distinct_types >= 2:
        corroboration_bonus += 5

    if distinct_types >= 3:
        corroboration_bonus += 5

    if critical >= 1:
        corroboration_bonus += 5

    if critical >= 2:
        corroboration_bonus += 5

    if high >= 2:
        corroboration_bonus += 2

    priority_score = min(
        100,
        risk_score + corroboration_bonus
    )

    if priority_score >= 80:
        priority = "Critical"
    elif priority_score >= 60:
        priority = "High"
    elif priority_score >= 40:
        priority = "Medium"
    else:
        priority = "Low"

    return pd.Series(
        [
            priority_score,
            priority,
        ],
        index=[
            "investigation_priority_score",
            "investigation_priority",
        ],
    )


# ============================================================
# INVESTIGATION REASON
# ============================================================

def build_reason(row):

    reasons = []

    if row["risk_score"] >= 80:
        reasons.append(
            f"very high user risk score ({row['risk_score']:.1f})"
        )
    elif row["risk_score"] >= 60:
        reasons.append(
            f"high user risk score ({row['risk_score']:.1f})"
        )

    if row["distinct_threat_types"] >= 3:
        reasons.append(
            f"{row['distinct_threat_types']} distinct threat types"
        )
    elif row["distinct_threat_types"] >= 2:
        reasons.append(
            f"{row['distinct_threat_types']} distinct threat types"
        )

    if row["critical_detections"] > 0:
        reasons.append(
            f"{row['critical_detections']} critical detection(s)"
        )

    if row["high_detections"] > 0:
        reasons.append(
            f"{row['high_detections']} high-severity detection(s)"
        )

    if not reasons:
        reasons.append(
            f"{row['threat_detection_count']} threat detection(s)"
        )

    return "; ".join(reasons)


# ============================================================
# RECOMMENDED ACTION
# ============================================================

def recommended_action(row):

    if (
        row["critical_detections"] > 0
        and row["distinct_threat_types"] >= 2
    ):
        return (
            "Immediate investigation: correlate endpoint, "
            "IAM and identity evidence; validate affected "
            "account and assets."
        )

    if row["critical_detections"] > 0:
        return (
            "Prioritize investigation of critical telemetry "
            "and validate affected account and asset."
        )

    if row["high_detections"] > 0:
        return (
            "Review high-severity detections and correlate "
            "supporting IAM and endpoint evidence."
        )

    return (
        "Review detection evidence and validate identity "
        "and asset context."
    )


# ============================================================
# BUILD INVESTIGATION QUEUE
# ============================================================

def build_queue(threats, risk, identity):

    corroboration = build_corroboration(threats)

    queue = risk.merge(
        corroboration,
        on="user_id",
        how="inner",
    )

    queue = queue.merge(
        identity,
        on="user_id",
        how="left",
        suffixes=("", "_identity"),
    )

    priority = queue.apply(
        calculate_priority,
        axis=1
    )

    queue = pd.concat(
        [
            queue,
            priority,
        ],
        axis=1
    )

    queue["investigation_reason"] = queue.apply(
        build_reason,
        axis=1
    )

    queue["recommended_action"] = queue.apply(
        recommended_action,
        axis=1
    )

    queue = queue.sort_values(
        [
            "investigation_priority_score",
            "risk_score",
            "critical_detections",
            "high_detections",
        ],
        ascending=False,
    )

    queue.insert(
        0,
        "priority_rank",
        range(1, len(queue) + 1)
    )

    # --------------------------------------------------------
    # Select final analytical columns
    # --------------------------------------------------------

    preferred_columns = [
        "priority_rank",
        "user_id",
        "full_name",
        "department",
        "role",
        "status",
        "location",
        "hostname",
        "device_id",
        "risk_score",
        "risk_level",
        "investigation_priority_score",
        "investigation_priority",
        "threat_detection_count",
        "distinct_threat_types",
        "threat_types",
        "critical_detections",
        "high_detections",
        "medium_detections",
        "highest_severity",
        "highest_confidence",
        "device_id_conflict",
        "device_user_count",
        "investigation_reason",
        "recommended_action",
    ]

    final_columns = [
        col
        for col in preferred_columns
        if col in queue.columns
    ]

    return queue[final_columns]


# ============================================================
# SUMMARY
# ============================================================

def build_summary(queue):

    summary = (
        queue
        .groupby("investigation_priority")
        .size()
        .reset_index(
            name="user_count"
        )
    )

    priority_order = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
    }

    summary["sort_order"] = (
        summary["investigation_priority"]
        .map(priority_order)
    )

    summary = (
        summary
        .sort_values("sort_order")
        .drop(columns="sort_order")
    )

    return summary


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("CORROBORATION & INVESTIGATION QUEUE")
    print("=" * 60)

    threats, risk, identity = load_data()

    print("\nPreparing datasets...")

    threats = prepare_threats(threats)
    risk = prepare_risk(risk)
    identity = prepare_identity(identity)

    print("\nBuilding investigation queue...")

    queue = build_queue(
        threats,
        risk,
        identity,
    )

    summary = build_summary(queue)

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    queue.to_csv(
        OUTPUT_PATH,
        index=False,
    )

    summary.to_csv(
        REPORT_PATH,
        index=False,
    )

    print("\n" + "=" * 60)
    print("INVESTIGATION QUEUE SUMMARY")
    print("=" * 60)

    print(summary.to_string(index=False))

    print(
        f"\nTotal users in queue: {len(queue)}"
    )

    print("\nTop 10 investigation priorities:")

    display_columns = [
        "priority_rank",
        "user_id",
        "risk_score",
        "investigation_priority_score",
        "investigation_priority",
        "threat_detection_count",
        "distinct_threat_types",
        "critical_detections",
        "highest_confidence",
    ]

    print(
        queue[display_columns]
        .head(10)
        .to_string(index=False)
    )

    print("\n" + "=" * 60)
    print("FILES SAVED")
    print("=" * 60)

    print(f"✓ Investigation queue : {OUTPUT_PATH}")
    print(f"✓ Queue summary       : {REPORT_PATH}")

    print("\n" + "=" * 60)
    print("CORROBORATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()