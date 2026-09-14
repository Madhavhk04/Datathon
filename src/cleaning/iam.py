from pathlib import Path
import re
import ipaddress

import pandas as pd


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_PATH = PROJECT_ROOT / "data" / "raw" / "track2_iam_audit_trail.json"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
REPORT_DIR = PROJECT_ROOT / "reports" / "data_quality"

OUTPUT_PATH = PROCESSED_DIR / "track2_iam_audit_trail_clean.csv"
QUALITY_REPORT_PATH = REPORT_DIR / "iam_audit_trail_quality_report.csv"
SUMMARY_PATH = REPORT_DIR / "iam_audit_trail_pipeline_summary.csv"


# ============================================================
# EXPECTED SCHEMA
# ============================================================

EXPECTED_COLUMNS = [
    "event_id",
    "timestamp",
    "user_id",
    "username",
    "department",
    "event_type",
    "auth_method",
    "source_ip",
    "hostname",
    "device_id",
    "session_id",
    "mfa_passed",
    "failure_reason",
    "risk_score",
    "geo_location",
]


# ============================================================
# GENERIC HELPERS
# ============================================================

MISSING_VALUES = {
    "",
    "NA",
    "N/A",
    "NONE",
    "NULL",
    "UNKNOWN",
}


def clean_text(value):
    if pd.isna(value):
        return pd.NA

    value = str(value).strip()

    if value.upper() in MISSING_VALUES:
        return pd.NA

    return value


# ============================================================
# USER ID
# ============================================================

def clean_user_id(value):
    if pd.isna(value):
        return pd.NA

    value = str(value).strip().upper()

    if value in MISSING_VALUES:
        return pd.NA

    # Remove spaces, hyphens, underscores and other separators.
    value = re.sub(r"[^A-Z0-9]", "", value)

    if value == "":
        return pd.NA

    # Numeric IDs are standardized to EMP + number.
    if value.isdigit():
        value = f"EMP{value}"

    return value


# ============================================================
# USERNAME
# ============================================================

def clean_username(value):
    value = clean_text(value)

    if pd.isna(value):
        return pd.NA

    return str(value).lower()


# ============================================================
# DEPARTMENT
# ============================================================

DEPARTMENT_MAP = {
    "IT": "IT",
    "INFORMATION TECHNOLOGY": "IT",
    "IT DEPT": "IT",

    "HR": "Human Resources",
    "HUMAN RESOURCES": "Human Resources",
    "HUMAN RESOURCE": "Human Resources",

    "FINANCE": "Finance",
    "FIN": "Finance",

    "OPERATIONS": "Operations",
    "OPS": "Operations",
    "OPS TEAM": "Operations",
    "OPERATIONS DEPT": "Operations",

    "SALES": "Sales",

    "MARKETING": "Marketing",
    "MKT": "Marketing",

    "LEGAL": "Legal",

    "PROCUREMENT": "Procurement",

    "CUSTOMER SUPPORT": "Customer Support",
    "CUSTOMER SERVICE": "Customer Support",

    "SUPPLY CHAIN": "Supply Chain",

    "R&D": "R&D",
    "RESEARCH AND DEVELOPMENT": "R&D",

    "COMPLIANCE": "Compliance",

    "PEOPLE": "People",

    "BRAND": "Brand",

    "INNOVATION": "Innovation",
}


def clean_department(value):
    value = clean_text(value)

    if pd.isna(value):
        return pd.NA

    normalized = str(value).upper()

    return DEPARTMENT_MAP.get(normalized, normalized)


# ============================================================
# EVENT TYPE
# ============================================================

EVENT_TYPE_MAP = {
    "LOGIN_SUCCESS": "LOGIN_SUCCESS",
    "AUTH_SUCCESS": "LOGIN_SUCCESS",
    "SSO_SUCCESS": "LOGIN_SUCCESS",
    "LOGIN": "LOGIN_SUCCESS",
    "LOGON_SUCCESS": "LOGIN_SUCCESS",

    "LOGIN_FAILURE": "LOGIN_FAILURE",
    "AUTH_FAILURE": "LOGIN_FAILURE",
    "SSO_FAILURE": "LOGIN_FAILURE",
    "LOGIN_FAILED": "LOGIN_FAILURE",
    "AUTH_FAILED": "LOGIN_FAILURE",

    "MFA_FAILURE": "MFA_FAILURE",
    "MFA_FAILED": "MFA_FAILURE",

    "ACCOUNT_LOCK": "ACCOUNT_LOCK",
    "ACCOUNT_LOCKED": "ACCOUNT_LOCK",

    "ACCOUNT_UNLOCK": "ACCOUNT_UNLOCK",
    "ACCOUNT_UNLOCKED": "ACCOUNT_UNLOCK",

    "DEVICE_REGISTERED": "DEVICE_REGISTERED",
    "DEVICE_REGISTRATION": "DEVICE_REGISTERED",

    "MFA_ENROLLMENT": "MFA_ENROLLMENT",
    "MFA_ENROLLED": "MFA_ENROLLMENT",

    "PASSWORD_RESET": "PASSWORD_RESET",
    "PASSWORD_CHANGED": "PASSWORD_RESET",

    "PRIVILEGE_ESCALATION_REQUEST": "PRIVILEGE_ESCALATION_REQUEST",
    "PRIVILEGE_ESCALATION": "PRIVILEGE_ESCALATION_REQUEST",

    "SESSION_TERMINATED": "SESSION_TERMINATED",
    "SESSION_END": "SESSION_TERMINATED",
}


def clean_event_type(value):
    value = clean_text(value)

    if pd.isna(value):
        return pd.NA

    normalized = str(value).strip().upper()

    return EVENT_TYPE_MAP.get(normalized, normalized)


# ============================================================
# AUTH METHOD
# ============================================================

AUTH_METHOD_MAP = {
    "BIOMETRIC": "BIOMETRIC",
    "CERTIFICATE": "CERTIFICATE",
    "MFA": "MFA",
    "OTP": "OTP",
    "PASSWORD": "PASSWORD",
    "SSO": "SSO",
}


def clean_auth_method(value):
    value = clean_text(value)

    if pd.isna(value):
        return pd.NA

    normalized = str(value).upper()

    return AUTH_METHOD_MAP.get(normalized, normalized)


# ============================================================
# TIMESTAMP
# ============================================================

def clean_timestamp(value):
    if pd.isna(value):
        return pd.NaT

    value = str(value).strip()

    if value == "":
        return pd.NaT

    # Unix timestamp in seconds.
    if re.fullmatch(r"\d{10}", value):
        try:
            return pd.to_datetime(int(value), unit="s")
        except (ValueError, OverflowError):
            return pd.NaT

    # ISO / YYYY-MM-DD
    if re.match(r"^\d{4}-\d{2}-\d{2}", value):
        try:
            return pd.to_datetime(value, dayfirst=False)
        except (ValueError, TypeError):
            return pd.NaT

    # YYYY/MM/DD
    if re.match(r"^\d{4}/\d{2}/\d{2}", value):
        try:
            return pd.to_datetime(value, dayfirst=False)
        except (ValueError, TypeError):
            return pd.NaT

    # DD/MM/YYYY
    if re.match(r"^\d{2}/\d{2}/\d{4}", value):
        try:
            return pd.to_datetime(value, dayfirst=True)
        except (ValueError, TypeError):
            return pd.NaT

    # DD-Mon-YYYY
    if re.match(r"^\d{1,2}-[A-Za-z]{3}-\d{4}", value):
        try:
            return pd.to_datetime(value, dayfirst=True)
        except (ValueError, TypeError):
            return pd.NaT

    # MM-DD-YYYY with AM/PM
    if re.match(
        r"^\d{2}-\d{2}-\d{4}.*(?:AM|PM)$",
        value,
        re.IGNORECASE,
    ):
        try:
            return pd.to_datetime(value, dayfirst=False)
        except (ValueError, TypeError):
            return pd.NaT

    # Final fallback.
    try:
        return pd.to_datetime(value, dayfirst=False)
    except (ValueError, TypeError):
        return pd.NaT


# ============================================================
# SOURCE IP
# ============================================================

def classify_ip(value):
    if pd.isna(value):
        return "MISSING"

    value = str(value).strip()

    if value == "":
        return "MISSING"

    if value.upper() in MISSING_VALUES:
        return "UNKNOWN"

    try:
        ip = ipaddress.ip_address(value)

        if ip.version == 4:
            if ip.is_private:
                return "VALID_PRIVATE"
            return "VALID_PUBLIC"

        return "VALID_OTHER"

    except ValueError:
        return "MALFORMED"


def clean_source_ip(value):
    if pd.isna(value):
        return pd.NA

    value = str(value).strip()

    if value == "":
        return pd.NA

    if value.upper() in MISSING_VALUES:
        return pd.NA

    return value


# ============================================================
# HOSTNAME
# ============================================================

def clean_hostname(value):
    value = clean_text(value)

    if pd.isna(value):
        return pd.NA

    value = str(value).upper()

    value = re.sub(r"\.CORP\.LOCAL$", "", value)

    value = value.replace("_", "-")

    return value


# ============================================================
# DEVICE ID
# ============================================================

def clean_device_id(value):
    value = clean_text(value)

    if pd.isna(value):
        return pd.NA

    value = str(value).upper()

    value = re.sub(r"[\s-]+", "", value)

    return value


# ============================================================
# SESSION ID
# ============================================================

def clean_session_id(value):
    value = clean_text(value)

    if pd.isna(value):
        return pd.NA

    return str(value).upper()


# ============================================================
# MFA
# ============================================================

def clean_mfa_passed(value):
    if pd.isna(value):
        return pd.NA

    value = str(value).strip().upper()

    if value in MISSING_VALUES:
        return pd.NA

    if value in {"TRUE", "YES", "Y", "1", "PASSED", "PASS"}:
        return True

    if value in {"FALSE", "NO", "N", "0", "FAILED", "FAIL"}:
        return False

    return pd.NA


# ============================================================
# FAILURE REASON
# ============================================================

FAILURE_REASON_MAP = {
    "INVALID CREDENTIALS": "INVALID_CREDENTIALS",
    "TIMEOUT": "TIMEOUT",
    "UNKNOWN USER": "UNKNOWN_USER",
    "BAD TOKEN": "BAD_TOKEN",
    "ACCOUNT LOCKED": "ACCOUNT_LOCKED",
    "WRONG_PASSWORD": "WRONG_PASSWORD",
    "WRONG PASSWORD": "WRONG_PASSWORD",
    "OTP EXPIRED": "OTP_EXPIRED",
    "MFA FAILED": "MFA_FAILED",
    "EXPIRED PASSWORD": "EXPIRED_PASSWORD",
}


def clean_failure_reason(value):
    value = clean_text(value)

    if pd.isna(value):
        return pd.NA

    normalized = str(value).upper()

    return FAILURE_REASON_MAP.get(normalized, normalized)


# ============================================================
# RISK SCORE
# ============================================================

def clean_risk_score(value):
    if pd.isna(value):
        return pd.NA

    value = str(value).strip().upper()

    if value in MISSING_VALUES:
        return pd.NA

    # Values such as 78/100.
    match = re.fullmatch(
        r"(\d+(?:\.\d+)?)\s*/\s*100",
        value,
    )

    if match:
        score = float(match.group(1))

        if 0 <= score <= 100:
            return score

        return pd.NA

    # Plain numeric score.
    try:
        score = float(value)

        if 0 <= score <= 100:
            return score

    except ValueError:
        pass

    # Preserve categorical risk labels separately.
    if value in {"LOW", "MEDIUM", "HIGH"}:
        return pd.NA

    return pd.NA


def clean_risk_level(value):
    if pd.isna(value):
        return pd.NA

    value = str(value).strip().upper()

    if value in {"LOW", "MEDIUM", "HIGH"}:
        return value

    return pd.NA


# ============================================================
# GEO LOCATION
# ============================================================

def clean_geo_location(value):
    if pd.isna(value):
        return pd.NA

    value = str(value).strip().upper()

    if value in {"", "NONE", "N/A", "NA"}:
        return pd.NA

    if value == "UNKNOWN":
        return "UNKNOWN"

    if value == "REMOTE":
        return "REMOTE"

    if value in {"IN", "INDIA", "IND"}:
        return "INDIA"

    if value in {"PB", "PUNJAB"}:
        return "PUNJAB"

    if value in {"DL", "DELHI"}:
        return "DELHI"

    if value == "MAHARASHTRA":
        return "MAHARASHTRA"

    return value


# ============================================================
# QUALITY REPORT
# ============================================================

def build_quality_report(df):
    records = []

    for column in df.columns:
        records.append(
            {
                "column": column,
                "rows": len(df),
                "missing_count": int(df[column].isna().sum()),
                "missing_pct": round(
                    df[column].isna().mean() * 100,
                    2,
                ),
                "unique_values": int(
                    df[column].nunique(dropna=True)
                ),
            }
        )

    return pd.DataFrame(records)


# ============================================================
# MAIN PIPELINE
# ============================================================

def main():

    print("=" * 60)
    print("IAM AUDIT CLEANING PIPELINE")
    print("=" * 60)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # --------------------------------------------------------
    # LOAD
    # --------------------------------------------------------

    raw_df = pd.read_json(RAW_PATH)

    print(f"Raw shape: {raw_df.shape}")

    missing_columns = [
        column
        for column in EXPECTED_COLUMNS
        if column not in raw_df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing expected columns: {missing_columns}"
        )

    df = raw_df[EXPECTED_COLUMNS].copy()

    # --------------------------------------------------------
    # EXACT DUPLICATE REMOVAL
    # --------------------------------------------------------

    duplicate_rows = int(df.duplicated().sum())

    df = df.drop_duplicates().copy()

    print(f"Exact duplicate rows removed: {duplicate_rows}")
    print(f"Shape after deduplication: {df.shape}")

    # --------------------------------------------------------
    # CLEAN FIELDS
    # --------------------------------------------------------

    df["event_id"] = df["event_id"].astype("string").str.strip()

    df["timestamp"] = df["timestamp"].apply(clean_timestamp)

    df["user_id"] = df["user_id"].apply(clean_user_id)

    df["username"] = df["username"].apply(clean_username)

    df["department"] = df["department"].apply(clean_department)

    df["event_type"] = df["event_type"].apply(clean_event_type)

    df["auth_method"] = df["auth_method"].apply(clean_auth_method)

    df["source_ip"] = df["source_ip"].apply(clean_source_ip)

    df["ip_status"] = raw_df.loc[
        df.index,
        "source_ip",
    ].apply(classify_ip)

    df["hostname"] = df["hostname"].apply(clean_hostname)

    df["device_id"] = df["device_id"].apply(clean_device_id)

    df["session_id"] = df["session_id"].apply(clean_session_id)

    df["mfa_passed"] = df["mfa_passed"].apply(clean_mfa_passed)

    df["failure_reason"] = df["failure_reason"].apply(
        clean_failure_reason
    )

    df["risk_level"] = df["risk_score"].apply(
        clean_risk_level
    )

    df["risk_score"] = df["risk_score"].apply(
        clean_risk_score
    )

    df["geo_location"] = df["geo_location"].apply(
        clean_geo_location
    )

    # --------------------------------------------------------
    # DEVICE RELATIONSHIP QUALITY
    # --------------------------------------------------------

    device_user_counts = (
        df[df["device_id"].notna()]
        .groupby("device_id")["user_id"]
        .nunique()
    )

    conflicting_devices = device_user_counts[
        device_user_counts > 1
    ]

    device_conflict_count = int(len(conflicting_devices))

    device_records_affected = int(
        df["device_id"].isin(
            conflicting_devices.index
        ).sum()
    )

    # --------------------------------------------------------
    # FINAL COLUMN ORDER
    # --------------------------------------------------------

    final_columns = [
        "event_id",
        "timestamp",
        "user_id",
        "username",
        "department",
        "event_type",
        "auth_method",
        "source_ip",
        "ip_status",
        "hostname",
        "device_id",
        "session_id",
        "mfa_passed",
        "failure_reason",
        "risk_score",
        "risk_level",
        "geo_location",
    ]

    df = df[final_columns].copy()

    # --------------------------------------------------------
    # FINAL VALIDATION
    # --------------------------------------------------------

    duplicate_event_ids = int(
        df["event_id"].duplicated().sum()
    )

    duplicate_rows_final = int(
        df.duplicated().sum()
    )

    risk_scores = df["risk_score"].dropna()

    timestamp_min = df["timestamp"].min()
    timestamp_max = df["timestamp"].max()

    print("\n" + "=" * 60)
    print("FINAL VALIDATION")
    print("=" * 60)

    print(f"Final shape: {df.shape}")
    print(f"Duplicate rows: {duplicate_rows_final}")
    print(f"Duplicate event IDs: {duplicate_event_ids}")
    print(f"Missing timestamps: {df['timestamp'].isna().sum()}")
    print(f"Missing user IDs: {df['user_id'].isna().sum()}")
    print(
        f"Missing session IDs: "
        f"{df['session_id'].isna().sum()}"
    )

    if not risk_scores.empty:
        print(
            f"Risk score range: "
            f"{risk_scores.min()} - {risk_scores.max()}"
        )

    print(f"Timestamp range: {timestamp_min} to {timestamp_max}")

    print(
        f"Device IDs linked to multiple users: "
        f"{device_conflict_count}"
    )

    print(
        f"IAM records affected by device conflicts: "
        f"{device_records_affected}"
    )

    # --------------------------------------------------------
    # SAVE PROCESSED DATA
    # --------------------------------------------------------

    df.to_csv(
        OUTPUT_PATH,
        index=False,
    )

    # --------------------------------------------------------
    # SAVE QUALITY REPORT
    # --------------------------------------------------------

    quality_report = build_quality_report(df)

    quality_report.to_csv(
        QUALITY_REPORT_PATH,
        index=False,
    )

    # --------------------------------------------------------
    # PIPELINE SUMMARY
    # --------------------------------------------------------

    summary = pd.DataFrame(
        [
            {
                "metric": "raw_rows",
                "value": len(raw_df),
            },
            {
                "metric": "raw_columns",
                "value": len(raw_df.columns),
            },
            {
                "metric": "exact_duplicates_removed",
                "value": duplicate_rows,
            },
            {
                "metric": "final_rows",
                "value": len(df),
            },
            {
                "metric": "final_columns",
                "value": len(df.columns),
            },
            {
                "metric": "duplicate_event_ids",
                "value": duplicate_event_ids,
            },
            {
                "metric": "missing_timestamps",
                "value": int(df["timestamp"].isna().sum()),
            },
            {
                "metric": "missing_user_ids",
                "value": int(df["user_id"].isna().sum()),
            },
            {
                "metric": "missing_session_ids",
                "value": int(df["session_id"].isna().sum()),
            },
            {
                "metric": "device_conflicting_ids",
                "value": device_conflict_count,
            },
            {
                "metric": "device_conflict_records",
                "value": device_records_affected,
            },
        ]
    )

    summary.to_csv(
        SUMMARY_PATH,
        index=False,
    )

    print("\n" + "=" * 60)
    print("FILES SAVED")
    print("=" * 60)

    print(OUTPUT_PATH)
    print(QUALITY_REPORT_PATH)
    print(SUMMARY_PATH)


if __name__ == "__main__":
    main()