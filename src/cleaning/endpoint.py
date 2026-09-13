import re
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

# Ensure standard UTF-8 console encoding on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_PATH = PROJECT_ROOT / "data" / "raw" / "track2_endpoint_alerts.xlsx"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
REPORT_DIR = PROJECT_ROOT / "reports" / "data_quality"

OUTPUT_PATH = PROCESSED_DIR / "track2_endpoint_alerts_clean.csv"
QUALITY_PATH = REPORT_DIR / "endpoint_alerts_quality_report.csv"
SUMMARY_PATH = REPORT_DIR / "endpoint_alerts_pipeline_summary.csv"


# ============================================================
# EXPECTED SCHEMA
# ============================================================

EXPECTED_COLUMNS = [
    "alert_id",
    "detected_timestamp",
    "resolved_timestamp",
    "hostname",
    "user_id",
    "endpoint_product",
    "alert_name",
    "severity",
    "status",
    "description",
    "file_path",
    "process_name",
    "sha256",
    "assigned_to",
    "device_criticality",
]

ALLOWED_SEVERITY = {"Critical", "High", "Medium", "Low"}

ALLOWED_STATUS = {
    "New",
    "Open",
    "In Progress",
    "Resolved",
    "Closed",
    "Unassigned",
}

ALLOWED_CRITICALITY = {"Critical", "High", "Medium", "Low"}

MISSING_TOKENS = {
    "",
    "NA",
    "N/A",
    "NONE",
    "NULL",
    "NAN",
    "NOT AVAILABLE",
    "UNKNOWN",
}


# ============================================================
# CLEANING HELPERS
# ============================================================

def clean_missing(value):
    """Convert recognized missing tokens to pandas NA."""
    if pd.isna(value):
        return pd.NA

    text = str(value).strip()

    if text.upper() in MISSING_TOKENS:
        return pd.NA

    return text


def clean_user_id(value):
    """
    Canonical user ID.

    Examples:
        EMP-12345 -> EMP12345
        12345     -> EMP12345
    """
    value = clean_missing(value)

    if pd.isna(value):
        return pd.NA

    compact = re.sub(r"[^A-Z0-9]", "", str(value).upper())

    if compact.isdigit():
        compact = "EMP" + compact

    return compact or pd.NA


def clean_hostname(value):
    """
    Canonical hostname used by the production datasets.

    Example:
        WS_10202.CORP.LOCAL
        -> ws-10202.corp.local

    The full hostname is preserved.

    A separate hostname_join_key removes the .corp.local
    suffix for cross-source joins.
    """
    value = clean_missing(value)

    if pd.isna(value):
        return pd.NA

    value = str(value).strip().lower()
    value = value.replace("_", "-")

    return value or pd.NA


def hostname_join_key(value):
    """Create the canonical cross-source hostname join key."""
    value = clean_hostname(value)

    if pd.isna(value):
        return pd.NA

    value = re.sub(r"\.corp\.local$", "", str(value))

    return value or pd.NA


def clean_label(value):
    """Normalize ordinary text labels without changing their meaning."""
    value = clean_missing(value)

    if pd.isna(value):
        return pd.NA

    return re.sub(r"\s+", " ", str(value)).strip()


def canonical_map(value, mapping):
    """Map a raw categorical value to its canonical value."""
    value = clean_missing(value)

    if pd.isna(value):
        return pd.NA

    key = str(value).strip().upper()

    return mapping.get(key, pd.NA)


# ============================================================
# CANONICAL MAPPINGS
# ============================================================

SEVERITY_MAP = {
    "P1": "Critical",
    "S1": "Critical",
    "CRIT": "Critical",
    "CRITICAL": "Critical",
    "SEVERE": "Critical",

    "P2": "High",
    "S2": "High",
    "H": "High",
    "HIGH": "High",
    "MAJOR": "High",

    "P3": "Medium",
    "S3": "Medium",
    "MEDIUM": "Medium",
    "MODERATE": "Medium",
    "M": "Medium",

    "P4": "Low",
    "S4": "Low",
    "LOW": "Low",
    "MINOR": "Low",
    "L": "Low",
}


STATUS_MAP = {
    "NEW": "New",
    "N": "New",

    "OPEN": "Open",
    "O": "Open",
    "ACTIVE": "Open",

    "IN_PROGRESS": "In Progress",
    "IN PROGRESS": "In Progress",
    "WIP": "In Progress",
    "INVESTIGATING": "In Progress",

    "RESOLVED": "Resolved",
    "R": "Resolved",

    "CLOSED": "Closed",
    "C": "Closed",
    "NOT MALICIOUS": "Closed",
    "FALSE_POSITIVE": "Closed",
    "FALSE POSITIVE": "Closed",
    "FP": "Closed",

    "UNASSIGNED": "Unassigned",
    "U": "Unassigned",
}


CRITICALITY_MAP = {
    "CRITICAL": "Critical",
    "C": "Critical",
    "P1": "Critical",

    "HIGH": "High",
    "H": "High",
    "P2": "High",

    "MEDIUM": "Medium",
    "M": "Medium",
    "P3": "Medium",

    "LOW": "Low",
    "L": "Low",
    "P4": "Low",
}


# ============================================================
# TIMESTAMP PARSER
# ============================================================

TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",

    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M",
    "%Y/%m/%d",

    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%d/%m/%Y",

    "%d-%b-%Y %H:%M:%S",
    "%d-%b-%Y %H:%M",
    "%d-%b-%Y",

    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
    "%m/%d/%Y",

    "%m-%d-%Y %I:%M:%S %p",
    "%m-%d-%Y %I:%M %p",
]


def parse_timestamp(value):
    """Parse the timestamp formats observed in the endpoint dataset."""
    value = clean_missing(value)

    if pd.isna(value):
        return pd.NaT

    text = str(value).strip()

    # Unix timestamp in seconds
    if re.fullmatch(r"\d{10}(?:\.0)?", text):
        try:
            return pd.to_datetime(
                int(float(text)),
                unit="s",
                errors="coerce",
            )
        except (TypeError, ValueError, OverflowError):
            return pd.NaT

    for fmt in TIMESTAMP_FORMATS:
        try:
            return pd.Timestamp(datetime.strptime(text, fmt))
        except ValueError:
            continue

    return pd.NaT


# ============================================================
# SHA-256 VALIDATION
# ============================================================

def valid_sha256(value):
    """Return True for a structurally valid 64-character SHA-256 hash."""
    value = clean_missing(value)

    if pd.isna(value):
        return pd.NA

    return bool(
        re.fullmatch(
            r"[0-9A-Fa-f]{64}",
            str(value).strip(),
        )
    )


# ============================================================
# MAIN PIPELINE
# ============================================================

def main():

    print("=" * 60)
    print("ENDPOINT ALERT CLEANING PIPELINE")
    print("=" * 60)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # --------------------------------------------------------
    # 1. Load
    # --------------------------------------------------------

    if not RAW_PATH.exists():
        raise FileNotFoundError(
            f"Endpoint source file not found: {RAW_PATH}"
        )

    raw = pd.read_excel(RAW_PATH)

    print(f"Raw shape: {raw.shape}")

    # --------------------------------------------------------
    # 2. Schema validation
    # --------------------------------------------------------

    missing_columns = set(EXPECTED_COLUMNS) - set(raw.columns)

    if missing_columns:
        raise ValueError(
            f"Missing required endpoint columns: "
            f"{sorted(missing_columns)}"
        )

    # Only work with the expected source columns.
    raw = raw[EXPECTED_COLUMNS].copy()

    # --------------------------------------------------------
    # 3. Duplicate profiling
    # --------------------------------------------------------

    exact_duplicate_rows = int(
        raw.duplicated(subset=EXPECTED_COLUMNS).sum()
    )

    duplicate_alert_rows = int(
        raw["alert_id"].duplicated(keep=False).sum()
    )

    unique_alert_ids_before = int(
        raw["alert_id"].nunique(dropna=True)
    )

    print(
        f"Exact duplicate rows identified: "
        f"{exact_duplicate_rows}"
    )

    print(
        f"Rows belonging to duplicate alert-ID groups: "
        f"{duplicate_alert_rows}"
    )

    print(
        f"Unique alert IDs before cleaning: "
        f"{unique_alert_ids_before}"
    )

    # --------------------------------------------------------
    # 4. Remove exact duplicates
    # --------------------------------------------------------

    df = raw.drop_duplicates(
        subset=EXPECTED_COLUMNS,
        keep="first",
    ).copy()

    exact_duplicates_removed = len(raw) - len(df)

    print(
        f"Exact duplicate rows removed: "
        f"{exact_duplicates_removed}"
    )

    print(
        f"Shape after deduplication: "
        f"{df.shape}"
    )

    # --------------------------------------------------------
    # 5. Preserve duplicate-ID evidence
    # --------------------------------------------------------

    # Audit conflicting alert IDs in raw before deduplication
    raw_exact_mask = raw.duplicated(subset=EXPECTED_COLUMNS, keep=False)
    raw_dup_id_mask = raw["alert_id"].duplicated(keep=False)
    conflicting_alert_ids = set(
        raw.loc[raw_dup_id_mask & ~raw_exact_mask, "alert_id"]
    )

    # In the deduplicated dataset, remaining duplicate alert IDs
    # indicate a content conflict.
    df["duplicate_alert_id_flag"] = (
        df["alert_id"].duplicated(keep=False)
    )

    df["duplicate_alert_id_different_content_flag"] = (
        df["alert_id"].isin(conflicting_alert_ids)
    )

    # --------------------------------------------------------
    # 6. Clean identifiers
    # --------------------------------------------------------

    df["user_id"] = df["user_id"].map(clean_user_id)

    df["hostname"] = df["hostname"].map(clean_hostname)

    df["hostname_join_key"] = (
        df["hostname"].map(hostname_join_key)
    )

    # --------------------------------------------------------
    # 7. Clean categorical fields
    # --------------------------------------------------------

    df["severity"] = df["severity"].map(
        lambda x: canonical_map(x, SEVERITY_MAP)
    )

    df["status"] = df["status"].map(
        lambda x: canonical_map(x, STATUS_MAP)
    )

    df["device_criticality"] = df[
        "device_criticality"
    ].map(
        lambda x: canonical_map(x, CRITICALITY_MAP)
    )

    # --------------------------------------------------------
    # 8. Clean ordinary labels
    # --------------------------------------------------------

    for column in [
        "endpoint_product",
        "alert_name",
        "description",
        "file_path",
        "process_name",
        "assigned_to",
        "sha256",
    ]:
        df[column] = df[column].map(clean_label)

    # --------------------------------------------------------
    # 9. Timestamp parsing
    # --------------------------------------------------------

    detected_raw_missing = (
        df["detected_timestamp"].map(clean_missing).isna()
    )

    resolved_raw_missing = (
        df["resolved_timestamp"].map(clean_missing).isna()
    )

    df["detected_timestamp"] = (
        df["detected_timestamp"].map(parse_timestamp)
    )

    df["resolved_timestamp"] = (
        df["resolved_timestamp"].map(parse_timestamp)
    )

    df["missing_detected_timestamp_flag"] = (
        detected_raw_missing
        & df["detected_timestamp"].isna()
    )

    df["invalid_detected_timestamp_flag"] = (
        ~detected_raw_missing
        & df["detected_timestamp"].isna()
    )

    df["missing_resolved_timestamp_flag"] = (
        resolved_raw_missing
        & df["resolved_timestamp"].isna()
    )

    df["invalid_resolved_timestamp_flag"] = (
        ~resolved_raw_missing
        & df["resolved_timestamp"].isna()
    )

    # --------------------------------------------------------
    # 10. Resolution consistency
    # --------------------------------------------------------

    df["impossible_resolution_flag"] = (
        df["detected_timestamp"].notna()
        & df["resolved_timestamp"].notna()
        & (
            df["resolved_timestamp"]
            < df["detected_timestamp"]
        )
    )

    unresolved_statuses = [
        "New",
        "Open",
        "In Progress",
        "Unassigned",
    ]

    df["unresolved_alert_flag"] = (
        df["status"].isin(unresolved_statuses)
    )

    df["resolved_without_timestamp_flag"] = (
        df["status"].isin(["Resolved", "Closed"])
        & df["resolved_timestamp"].isna()
    )

    df["unresolved_with_resolution_timestamp_flag"] = (
        df["unresolved_alert_flag"]
        & df["resolved_timestamp"].notna()
    )

    # --------------------------------------------------------
    # 11. Missing / mapping validation
    # --------------------------------------------------------

    df["missing_user_id_flag"] = df["user_id"].isna()

    df["missing_hostname_flag"] = df["hostname"].isna()

    df["unmapped_severity_flag"] = (
        df["severity"].isna()
        & ~raw.loc[df.index, "severity"]
        .map(clean_missing)
        .isna()
    )

    df["unmapped_status_flag"] = (
        df["status"].isna()
        & ~raw.loc[df.index, "status"]
        .map(clean_missing)
        .isna()
    )

    df["unmapped_criticality_flag"] = (
        df["device_criticality"].isna()
        & ~raw.loc[df.index, "device_criticality"]
        .map(clean_missing)
        .isna()
    )

    # --------------------------------------------------------
    # 12. SHA-256 validation
    # --------------------------------------------------------

    sha_missing = (
        raw.loc[df.index, "sha256"]
        .map(clean_missing)
        .isna()
    )

    sha_valid = (
        raw.loc[df.index, "sha256"]
        .map(valid_sha256)
        .astype("boolean")
        .fillna(False)
        .astype(bool)
    )

    df["sha256_valid_flag"] = sha_valid

    df["sha256_missing_flag"] = sha_missing

    df["invalid_sha256_flag"] = (
        ~sha_valid & ~sha_missing
    )

    df["sha256_validation_status"] = np.select(
        [
            sha_missing,
            sha_valid,
        ],
        [
            "missing_sha256",
            "valid_sha256",
        ],
        default="malformed_sha256",
    )

    # --------------------------------------------------------
    # 13. Data-quality issue count
    # --------------------------------------------------------

    quality_flags = [
        "duplicate_alert_id_flag",
        "missing_user_id_flag",
        "missing_hostname_flag",
        "invalid_detected_timestamp_flag",
        "invalid_resolved_timestamp_flag",
        "impossible_resolution_flag",
        "resolved_without_timestamp_flag",
        "unresolved_with_resolution_timestamp_flag",
        "unmapped_severity_flag",
        "unmapped_status_flag",
        "unmapped_criticality_flag",
        "invalid_sha256_flag",
    ]

    df["data_quality_issue_count"] = (
        df[quality_flags]
        .astype(int)
        .sum(axis=1)
    )

    df["data_quality_status"] = np.where(
        df["data_quality_issue_count"].eq(0),
        "Pass",
        "Review",
    )

    # --------------------------------------------------------
    # 14. Hard validation checks
    # --------------------------------------------------------

    assert set(
        df["severity"].dropna().unique()
    ).issubset(ALLOWED_SEVERITY)

    assert set(
        df["status"].dropna().unique()
    ).issubset(ALLOWED_STATUS)

    assert set(
        df["device_criticality"].dropna().unique()
    ).issubset(ALLOWED_CRITICALITY)

    assert not (
        df["impossible_resolution_flag"]
        & ~(
            df["detected_timestamp"].notna()
            & df["resolved_timestamp"].notna()
        )
    ).any()

    # --------------------------------------------------------
    # 15. Final production columns
    # --------------------------------------------------------

    output_columns = [
        "alert_id",
        "detected_timestamp",
        "resolved_timestamp",
        "hostname",
        "hostname_join_key",
        "user_id",
        "endpoint_product",
        "alert_name",
        "severity",
        "status",
        "description",
        "file_path",
        "process_name",
        "sha256",
        "assigned_to",
        "device_criticality",

        "duplicate_alert_id_flag",
        "duplicate_alert_id_different_content_flag",

        "missing_user_id_flag",
        "missing_hostname_flag",

        "missing_detected_timestamp_flag",
        "invalid_detected_timestamp_flag",

        "missing_resolved_timestamp_flag",
        "invalid_resolved_timestamp_flag",

        "impossible_resolution_flag",
        "unresolved_alert_flag",
        "resolved_without_timestamp_flag",
        "unresolved_with_resolution_timestamp_flag",

        "unmapped_severity_flag",
        "unmapped_status_flag",
        "unmapped_criticality_flag",

        "sha256_valid_flag",
        "sha256_missing_flag",
        "invalid_sha256_flag",
        "sha256_validation_status",

        "data_quality_issue_count",
        "data_quality_status",
    ]

    df = df[output_columns].copy()

    # --------------------------------------------------------
    # 16. Quality report
    # --------------------------------------------------------

    quality_rows = []

    for column in output_columns:
        quality_rows.append(
            {
                "column": column,
                "rows": len(df),
                "missing_count": int(df[column].isna().sum()),
                "missing_pct": round(
                    float(df[column].isna().mean() * 100),
                    2,
                ),
                "unique_values": int(
                    df[column].nunique(dropna=True)
                ),
            }
        )

    quality_report = pd.DataFrame(quality_rows)

    # --------------------------------------------------------
    # 17. Pipeline summary
    # --------------------------------------------------------

    summary_rows = [
        {
            "metric": "raw_rows",
            "value": len(raw),
        },
        {
            "metric": "raw_unique_alert_ids",
            "value": unique_alert_ids_before,
        },
        {
            "metric": "exact_duplicate_rows_removed",
            "value": exact_duplicates_removed,
        },
        {
            "metric": "final_rows",
            "value": len(df),
        },
        {
            "metric": "final_unique_alert_ids",
            "value": df["alert_id"].nunique(),
        },
        {
            "metric": "remaining_duplicate_alert_id_rows",
            "value": int(
                df["duplicate_alert_id_flag"].sum()
            ),
        },
        {
            "metric": "missing_user_id",
            "value": int(
                df["missing_user_id_flag"].sum()
            ),
        },
        {
            "metric": "missing_hostname",
            "value": int(
                df["missing_hostname_flag"].sum()
            ),
        },
        {
            "metric": "invalid_detected_timestamp",
            "value": int(
                df["invalid_detected_timestamp_flag"].sum()
            ),
        },
        {
            "metric": "invalid_resolved_timestamp",
            "value": int(
                df["invalid_resolved_timestamp_flag"].sum()
            ),
        },
        {
            "metric": "impossible_resolution",
            "value": int(
                df["impossible_resolution_flag"].sum()
            ),
        },
        {
            "metric": "resolved_without_timestamp",
            "value": int(
                df["resolved_without_timestamp_flag"].sum()
            ),
        },
        {
            "metric": "unresolved_with_resolution_timestamp",
            "value": int(
                df[
                    "unresolved_with_resolution_timestamp_flag"
                ].sum()
            ),
        },
        {
            "metric": "missing_sha256",
            "value": int(
                df["sha256_missing_flag"].sum()
            ),
        },
        {
            "metric": "invalid_sha256",
            "value": int(
                df["invalid_sha256_flag"].sum()
            ),
        },
        {
            "metric": "rows_requiring_review",
            "value": int(
                df["data_quality_status"]
                .eq("Review")
                .sum()
            ),
        },
    ]

    pipeline_summary = pd.DataFrame(summary_rows)

    # --------------------------------------------------------
    # 18. Save
    # --------------------------------------------------------

    df.to_csv(OUTPUT_PATH, index=False)

    quality_report.to_csv(
        QUALITY_PATH,
        index=False,
    )

    pipeline_summary.to_csv(
        SUMMARY_PATH,
        index=False,
    )

    # --------------------------------------------------------
    # 19. Final console output
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("FINAL VALIDATION")
    print("=" * 60)

    print(f"Final shape: {df.shape}")
    print(
        f"Duplicate rows: "
        f"{int(df.duplicated().sum())}"
    )
    print(
        f"Unique alert IDs: "
        f"{df['alert_id'].nunique()}"
    )
    print(
        f"Remaining duplicate alert-ID rows: "
        f"{int(df['duplicate_alert_id_flag'].sum())}"
    )
    print(
        f"Missing user IDs: "
        f"{int(df['missing_user_id_flag'].sum())}"
    )
    print(
        f"Missing hostnames: "
        f"{int(df['missing_hostname_flag'].sum())}"
    )
    print(
        f"Invalid detected timestamps: "
        f"{int(df['invalid_detected_timestamp_flag'].sum())}"
    )
    print(
        f"Invalid resolved timestamps: "
        f"{int(df['invalid_resolved_timestamp_flag'].sum())}"
    )
    print(
        f"Impossible resolutions: "
        f"{int(df['impossible_resolution_flag'].sum())}"
    )
    print(
        f"Missing SHA-256 (telemetry): "
        f"{int(df['sha256_missing_flag'].sum())}"
    )
    print(
        f"Invalid SHA-256 values: "
        f"{int(df['invalid_sha256_flag'].sum())}"
    )
    print(
        f"Rows requiring review: "
        f"{int(df['data_quality_status'].eq('Review').sum())}"
    )

    if df["detected_timestamp"].notna().any():
        print(
            "Detected timestamp range: "
            f"{df['detected_timestamp'].min()} "
            f"to "
            f"{df['detected_timestamp'].max()}"
        )

    print()
    print("=" * 60)
    print("FILES SAVED")
    print("=" * 60)

    print(f"✓ Cleaned dataset : {OUTPUT_PATH}")
    print(f"✓ Quality report  : {QUALITY_PATH}")
    print(f"✓ Pipeline summary: {SUMMARY_PATH}")


if __name__ == "__main__":
    main()