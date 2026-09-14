from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = ROOT / "data" / "processed"
REPORT_DIR = ROOT / "reports" / "join_quality"


IDENTITY_PATH = DATA_DIR / "track2_identity_asset_master_clean.csv"
IAM_PATH = DATA_DIR / "track2_iam_audit_trail_clean.csv"
ENDPOINT_PATH = DATA_DIR / "track2_endpoint_alerts_clean.csv"
FIREWALL_PATH = DATA_DIR / "track2_firewall_logs_clean.csv"


def normalize_key(value):
    """Normalize identifiers while preserving missing values."""
    if pd.isna(value):
        return pd.NA

    value = str(value).strip().upper()

    return value if value else pd.NA


def normalize_hostname(value):
    """
    Normalize hostnames for cross-source joins.

    The .corp.local suffix is removed because the source systems
    represent the same host with and without the domain suffix.
    """
    if pd.isna(value):
        return pd.NA

    value = str(value).strip().lower()
    value = value.replace("_", "-")

    if value.endswith(".corp.local"):
        value = value[:-10]

    return value if value else pd.NA


def load_data():
    """Load all production-cleaned telemetry datasets."""
    identity = pd.read_csv(IDENTITY_PATH)
    iam = pd.read_csv(IAM_PATH)
    endpoint = pd.read_csv(ENDPOINT_PATH)
    firewall = pd.read_csv(FIREWALL_PATH)

    return identity, iam, endpoint, firewall


def prepare_identity(identity):
    """
    Prepare identity reference keys and identify genuinely ambiguous
    hostname/device mappings.

    Multiple records for the same user_id are not considered ambiguous
    by themselves because the identity master can legitimately contain
    multiple asset records for a user.
    """
    identity = identity.copy()

    identity["user_key"] = identity["user_id"].map(normalize_key)
    identity["hostname_join_key"] = identity["hostname"].map(
        normalize_hostname
    )
    identity["device_key"] = identity["device_id"].map(normalize_key)

    hostname_users = (
        identity.dropna(subset=["hostname_join_key", "user_key"])
        .groupby("hostname_join_key")["user_key"]
        .nunique()
    )

    device_users = (
        identity.dropna(subset=["device_key", "user_key"])
        .groupby("device_key")["user_key"]
        .nunique()
    )

    ambiguous_hostnames = (
        hostname_users[hostname_users > 1]
        .rename("distinct_user_count")
        .reset_index()
        .sort_values("distinct_user_count", ascending=False)
    )

    ambiguous_devices = (
        device_users[device_users > 1]
        .rename("distinct_user_count")
        .reset_index()
        .sort_values("distinct_user_count", ascending=False)
    )

    return identity, ambiguous_hostnames, ambiguous_devices


def validate_single_key(
    source_name,
    relationship,
    source,
    source_column,
    identity_keys,
    key_type,
):
    """Validate a single telemetry key against the identity master."""

    source_keys = source[source_column].map(
        normalize_hostname if key_type == "hostname" else normalize_key
    )

    missing = source_keys.isna()

    matched = source_keys.notna() & source_keys.isin(identity_keys)

    unmatched = source_keys.notna() & ~source_keys.isin(identity_keys)

    usable = source_keys.notna()

    match_rate = (
        matched.sum() / usable.sum() * 100
        if usable.sum()
        else 0
    )

    return {
        "source": source_name,
        "relationship": relationship,
        "relationship_status": (
            "Strong"
            if match_rate >= 90
            else "Moderate"
            if match_rate >= 75
            else "Weak"
        ),
        "rows": len(source),
        "matched": int(matched.sum()),
        "missing": int(missing.sum()),
        "unmatched": int(unmatched.sum()),
        "match_rate_pct": round(match_rate, 2),
        "usable_pairs": pd.NA,
        "consistent_pairs": pd.NA,
        "inconsistent_pairs": pd.NA,
        "consistency_rate_pct": pd.NA,
    }


def validate_user_hostname_relationship(
    source_name,
    source,
    identity,
):
    """
    Validate whether a telemetry user_id + hostname pair exists
    in the identity master.
    """

    source = source.copy()

    source["user_key"] = source["user_id"].map(normalize_key)
    source["hostname_join_key"] = source["hostname"].map(
        normalize_hostname
    )

    identity_pairs = set(
        zip(
            identity["user_key"].dropna(),
            identity.loc[
                identity["user_key"].notna(),
                "hostname_join_key",
            ],
        )
    )

    # Rebuild pairs safely so both values are present.
    identity_pair_df = identity[
        ["user_key", "hostname_join_key"]
    ].dropna()

    identity_pairs = set(
        zip(
            identity_pair_df["user_key"],
            identity_pair_df["hostname_join_key"],
        )
    )

    usable = source[
        source["user_key"].notna()
        & source["hostname_join_key"].notna()
    ]

    source_pairs = list(
        zip(
            usable["user_key"],
            usable["hostname_join_key"],
        )
    )

    consistent = sum(
        pair in identity_pairs
        for pair in source_pairs
    )

    inconsistent = len(source_pairs) - consistent

    consistency_rate = (
        consistent / len(source_pairs) * 100
        if source_pairs
        else 0
    )

    return {
        "source": source_name,
        "relationship": "user_id + hostname -> identity",
        "relationship_status": (
            "Strong"
            if consistency_rate >= 90
            else "Moderate"
            if consistency_rate >= 75
            else "Weak"
        ),
        "rows": len(source),
        "matched": pd.NA,
        "missing": pd.NA,
        "unmatched": pd.NA,
        "match_rate_pct": pd.NA,
        "usable_pairs": len(source_pairs),
        "consistent_pairs": consistent,
        "inconsistent_pairs": inconsistent,
        "consistency_rate_pct": round(consistency_rate, 2),
    }


def validate_device_relationship(
    source_name,
    source,
    identity_keys,
):
    """Validate device_id relationships where device_id exists."""

    if "device_id" not in source.columns:
        return None

    return validate_single_key(
        source_name,
        "device_id -> identity",
        source,
        "device_id",
        identity_keys,
        "device",
    )


def validate_sessions(iam, firewall):
    """
    Validate exact IAM <-> Firewall session_id overlap.

    Session IDs are deliberately treated as an observed relationship,
    not as a trusted analytical join key, because exact overlap is
    weak and the shared sessions fail hostname/timestamp reconciliation.
    """

    iam_sessions = set(
        iam["session_id"]
        .map(normalize_key)
        .dropna()
    )

    firewall_sessions = set(
        firewall["session_id"]
        .map(normalize_key)
        .dropna()
    )

    shared = iam_sessions & firewall_sessions

    iam_rate = (
        len(shared) / len(iam_sessions) * 100
        if iam_sessions
        else 0
    )

    firewall_rate = (
        len(shared) / len(firewall_sessions) * 100
        if firewall_sessions
        else 0
    )

    return {
        "relationship": "IAM session_id <-> Firewall session_id",
        "relationship_status": "Weak / Rejected",
        "iam_unique_sessions": len(iam_sessions),
        "firewall_unique_sessions": len(firewall_sessions),
        "shared_session_ids": len(shared),
        "iam_only_sessions": len(iam_sessions - firewall_sessions),
        "firewall_only_sessions": len(
            firewall_sessions - iam_sessions
        ),
        "session_match_rate_iam_pct": round(iam_rate, 2),
        "session_match_rate_firewall_pct": round(
            firewall_rate, 2
        ),
    }


def validate_shared_session_evidence(iam, firewall):
    """
    Reconcile shared session IDs using hostname and approximate
    timestamps.

    This does NOT create a join. It measures whether shared session IDs
    provide enough evidence to be considered trustworthy.
    """

    iam = iam.copy()
    firewall = firewall.copy()

    iam["session_key"] = iam["session_id"].map(normalize_key)
    firewall["session_key"] = firewall["session_id"].map(
        normalize_key
    )

    iam["hostname_key"] = iam["hostname"].map(
        normalize_hostname
    )
    firewall["hostname_key"] = firewall["hostname"].map(
        normalize_hostname
    )

    iam["timestamp"] = pd.to_datetime(
        iam["timestamp"],
        errors="coerce",
    )

    firewall["timestamp"] = pd.to_datetime(
        firewall["timestamp"],
        errors="coerce",
    )

    iam_sessions = set(iam["session_key"].dropna())
    firewall_sessions = set(firewall["session_key"].dropna())

    shared = iam_sessions & firewall_sessions

    rows = []

    for session in shared:
        iam_rows = iam[iam["session_key"] == session]
        firewall_rows = firewall[
            firewall["session_key"] == session
        ]

        iam_hosts = set(
            iam_rows["hostname_key"].dropna()
        )

        firewall_hosts = set(
            firewall_rows["hostname_key"].dropna()
        )

        common_hosts = iam_hosts & firewall_hosts

        iam_times = iam_rows["timestamp"].dropna()
        firewall_times = firewall_rows["timestamp"].dropna()

        differences = []

        for iam_time in iam_times:
            for firewall_time in firewall_times:
                differences.append(
                    abs(
                        (
                            iam_time - firewall_time
                        ).total_seconds()
                    )
                )

        min_difference = (
            min(differences)
            if differences
            else pd.NA
        )

        rows.append(
            {
                "session_id": session,
                "iam_rows": len(iam_rows),
                "firewall_rows": len(firewall_rows),
                "hostname_overlap": bool(common_hosts),
                "timestamp_evidence": bool(differences),
                "min_time_difference_seconds": min_difference,
                "within_60_minutes": (
                    bool(differences)
                    and min_difference <= 3600
                ),
            }
        )

    evidence = pd.DataFrame(rows)

    if evidence.empty:
        return {
            "shared_sessions_checked": 0,
            "hostname_consistent_sessions": 0,
            "hostname_inconsistent_sessions": 0,
            "sessions_without_hostname_evidence": 0,
            "timestamp_within_60_minutes": 0,
            "session_join_decision": "Rejected",
        }, evidence

    hostname_consistent = evidence[
        evidence["hostname_overlap"]
    ]

    hostname_inconsistent = evidence[
        ~evidence["hostname_overlap"]
        & evidence["timestamp_evidence"]
    ]

    no_hostname_evidence = evidence[
        ~evidence["hostname_overlap"]
        & ~evidence["timestamp_evidence"]
    ]

    timestamp_matches = evidence[
        evidence["within_60_minutes"]
    ]

    summary = {
        "shared_sessions_checked": len(evidence),
        "hostname_consistent_sessions": len(
            hostname_consistent
        ),
        "hostname_inconsistent_sessions": len(
            hostname_inconsistent
        ),
        "sessions_without_hostname_evidence": len(
            no_hostname_evidence
        ),
        "timestamp_within_60_minutes": len(
            timestamp_matches
        ),
        "session_join_decision": "Rejected",
    }

    return summary, evidence


def main():

    print("=" * 60)
    print("TELEMETRY RELATIONSHIP VALIDATION")
    print("=" * 60)

    identity, iam, endpoint, firewall = load_data()

    print("\nLoaded datasets:")
    print(f"Identity : {identity.shape}")
    print(f"IAM      : {iam.shape}")
    print(f"Endpoint : {endpoint.shape}")
    print(f"Firewall : {firewall.shape}")

    identity, ambiguous_hostnames, ambiguous_devices = (
        prepare_identity(identity)
    )

    identity_users = set(
        identity["user_key"].dropna()
    )

    identity_hosts = set(
        identity["hostname_join_key"].dropna()
    )

    identity_devices = set(
        identity["device_key"].dropna()
    )

    results = []

    # IAM relationships
    results.append(
        validate_single_key(
            "IAM",
            "user_id -> identity",
            iam,
            "user_id",
            identity_users,
            "user",
        )
    )

    results.append(
        validate_single_key(
            "IAM",
            "hostname -> identity",
            iam,
            "hostname",
            identity_hosts,
            "hostname",
        )
    )

    results.append(
        validate_single_key(
            "IAM",
            "device_id -> identity",
            iam,
            "device_id",
            identity_devices,
            "device",
        )
    )

    results.append(
        validate_user_hostname_relationship(
            "IAM",
            iam,
            identity,
        )
    )

    # Endpoint relationships
    results.append(
        validate_single_key(
            "Endpoint",
            "user_id -> identity",
            endpoint,
            "user_id",
            identity_users,
            "user",
        )
    )

    results.append(
        validate_single_key(
            "Endpoint",
            "hostname -> identity",
            endpoint,
            "hostname_join_key"
            if "hostname_join_key" in endpoint.columns
            else "hostname",
            identity_hosts,
            "hostname",
        )
    )

    results.append(
        validate_user_hostname_relationship(
            "Endpoint",
            endpoint,
            identity,
        )
    )

    # Endpoint does not currently contain device_id,
    # so no artificial zero-match relationship is reported.

    # Firewall relationships
    results.append(
        validate_single_key(
            "Firewall",
            "hostname -> identity",
            firewall,
            "hostname_join_key"
            if "hostname_join_key" in firewall.columns
            else "hostname",
            identity_hosts,
            "hostname",
        )
    )

    relationship_report = pd.DataFrame(results)

    print("\n" + "=" * 60)
    print("RELATIONSHIP RESULTS")
    print("=" * 60)

    print(
        relationship_report.to_string(index=False)
    )

    # Session relationship
    session_summary = validate_sessions(
        iam,
        firewall,
    )

    print("\n" + "=" * 60)
    print("IAM <-> FIREWALL SESSION RELATIONSHIP")
    print("=" * 60)

    for key, value in session_summary.items():
        print(f"{key}: {value}")

    # Shared session evidence
    session_evidence_summary, session_evidence = (
        validate_shared_session_evidence(
            iam,
            firewall,
        )
    )

    print("\n" + "=" * 60)
    print("SHARED-SESSION RECONCILIATION")
    print("=" * 60)

    for key, value in session_evidence_summary.items():
        print(f"{key}: {value}")

    # Reports
    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    relationship_report.to_csv(
        REPORT_DIR / "relationship_quality_report.csv",
        index=False,
    )

    pd.DataFrame(
        [session_summary]
    ).to_csv(
        REPORT_DIR / "session_relationship_report.csv",
        index=False,
    )

    pd.DataFrame(
        [session_evidence_summary]
    ).to_csv(
        REPORT_DIR / "session_hostname_consistency_report.csv",
        index=False,
    )

    session_evidence.to_csv(
        REPORT_DIR / "shared_session_evidence.csv",
        index=False,
    )

    ambiguous_hostnames.to_csv(
        REPORT_DIR / "ambiguous_hostnames.csv",
        index=False,
    )

    ambiguous_devices.to_csv(
        REPORT_DIR / "ambiguous_devices.csv",
        index=False,
    )

    print("\nReports saved:")
    print(
        f"✓ {REPORT_DIR / 'relationship_quality_report.csv'}"
    )
    print(
        f"✓ {REPORT_DIR / 'session_relationship_report.csv'}"
    )
    print(
        f"✓ {REPORT_DIR / 'session_hostname_consistency_report.csv'}"
    )
    print(
        f"✓ {REPORT_DIR / 'shared_session_evidence.csv'}"
    )
    print(
        f"✓ {REPORT_DIR / 'ambiguous_hostnames.csv'}"
    )
    print(
        f"✓ {REPORT_DIR / 'ambiguous_devices.csv'}"
    )

    print("\n" + "=" * 60)
    print("RELATIONSHIP VALIDATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()