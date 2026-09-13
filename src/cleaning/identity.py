"""
Identity & Asset Master cleaning pipeline.

Source:
    data/raw/track2_identity_asset_master.csv

Output:
    data/processed/track2_identity_asset_master_clean.csv
    reports/data_quality/identity_asset_master_quality_report.csv

Design principles:
- Preserve raw data untouched.
- Normalize identifiers and categorical values deterministically.
- Preserve missing values; never fabricate identifiers.
- Parse mixed date formats explicitly.
- Detect device/user conflicts and retain them as security-relevant quality signals.
"""

from __future__ import annotations

import re
from pathlib import Path

import pandas as pd


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_FILE = PROJECT_ROOT / "data" / "raw" / "track2_identity_asset_master.csv"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
REPORT_DIR = PROJECT_ROOT / "reports" / "data_quality"

OUTPUT_FILE = PROCESSED_DIR / "track2_identity_asset_master_clean.csv"
QUALITY_REPORT_FILE = REPORT_DIR / "identity_asset_master_quality_report.csv"


EXPECTED_COLUMNS = [
    "full_name",
    "role",
    "user_id",
    "department",
    "location",
    "status",
    "hire_date",
    "termination_date",
    "username",
    "hostname",
    "device_id",
    "manager_username",
]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_schema(df: pd.DataFrame) -> None:
    missing = [c for c in EXPECTED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")


# ---------------------------------------------------------------------------
# Identifier / text cleaning
# ---------------------------------------------------------------------------

def clean_user_id(value):
    """Normalize user IDs while preserving true missing values."""
    if pd.isna(value):
        return pd.NA

    value = str(value).strip().upper()
    value = re.sub(r"[^A-Z0-9]", "", value)

    if not value or value in {"NAN", "NONE", "NULL", "NA"}:
        return pd.NA

    if value.isdigit():
        return f"EMP{value}"

    return value


def clean_username(value):
    if pd.isna(value):
        return pd.NA

    value = str(value).strip().lower()

    if not value or value in {"nan", "none", "null", "na", "n/a"}:
        return pd.NA

    return value


def clean_hostname(value):
    if pd.isna(value):
        return pd.NA

    value = str(value).strip().upper()

    if not value or value in {"NAN", "NONE", "NULL", "NA"}:
        return pd.NA

    value = re.sub(r"\.CORP\.LOCAL$", "", value)
    value = value.replace("_", "-")

    return value


def clean_device_id(value):
    if pd.isna(value):
        return pd.NA

    value = str(value).strip().upper()

    if not value or value in {"NAN", "NONE", "NULL", "NA"}:
        return pd.NA

    # Preserve the notebook's normalization rule: remove spaces and hyphens.
    return re.sub(r"[\s-]+", "", value)


# ---------------------------------------------------------------------------
# Categorical normalization
# ---------------------------------------------------------------------------

DEPARTMENT_MAP = {
    "Accounts": "Finance",
    "FINANCE": "Finance",
    "Fin": "Finance",
    "Finance": "Finance",
    "finance dept": "Finance",
    "HR": "Human Resources",
    "Human Resource": "Human Resources",
    "Human Resources": "Human Resources",
    "hr dept": "Human Resources",
    "IT": "IT",
    "IT Dept": "IT",
    "IT Support": "IT",
    "Information Technology": "IT",
    "information tech": "IT",
    "LEGAL": "Legal",
    "Legal": "Legal",
    "Legal Dept": "Legal",
    "legal": "Legal",
    "MKT": "Marketing",
    "Marketing": "Marketing",
    "Mktg": "Marketing",
    "marketing dept": "Marketing",
    "OPERATIONS": "Operations",
    "Operations": "Operations",
    "Ops": "Operations",
    "Ops Team": "Operations",
    "operations dept": "Operations",
    "PURCH": "Procurement",
    "Procurement": "Procurement",
    "Purchase": "Procurement",
    "procurement team": "Procurement",
    "R&D": "R&D",
    "RD": "R&D",
    "Research and Development": "R&D",
    "RnD": "R&D",
    "SALES": "Sales",
    "Sales": "Sales",
    "Business Sales": "Sales",
    "sales dept": "Sales",
    "sales team": "Sales",
    "CS": "Customer Support",
    "Customer Support": "Customer Support",
    "Support": "Customer Support",
    "customer care": "Customer Support",
    "Call Center": "Customer Support",
    "Supply Chain": "Supply Chain",
    "People Team": "People",
    "Compliance": "Compliance",
    "Brand Team": "Brand",
    "Innovation": "Innovation",
}

LOCATION_MAP = {
    "BRANCH OFFICE": "Branch Office",
    "Branch Office": "Branch Office",
    "Branch_Office": "Branch Office",
    "branch office": "Branch Office",
    "DATA CENTER": "Data Center",
    "Data Center": "Data Center",
    "Data_Center": "Data Center",
    "data center": "Data Center",
    "HEAD OFFICE": "Head Office",
    "Head Office": "Head Office",
    "Head_Office": "Head Office",
    "head office": "Head Office",
    "REGIONAL OFFICE": "Regional Office",
    "Regional Office": "Regional Office",
    "Regional_Office": "Regional Office",
    "regional office": "Regional Office",
    "REMOTE": "Remote",
    "Remote": "Remote",
    "remote": "Remote",
    "WAREHOUSE": "Warehouse",
    "Warehouse": "Warehouse",
    "warehouse": "Warehouse",
    "WORK FROM HOME": "Work From Home",
    "Work From Home": "Work From Home",
    "Work_From_Home": "Work From Home",
    "work from home": "Work From Home",
}

STATUS_MAP = {
    "A": "Active",
    "ACTIVE": "Active",
    "Active": "Active",
    "Enabled": "Active",
    "Live": "Active",
    "Working": "Active",
    "Blocked": "Disabled",
    "D": "Disabled",
    "DISABLED": "Disabled",
    "Deactivated": "Disabled",
    "Disabled": "Disabled",
    "Exited": "Inactive",
    "L": "Inactive",
    "LEFT": "Inactive",
    "Left": "Inactive",
    "LWP": "Inactive",
    "Leave": "Inactive",
    "Resigned": "Inactive",
    "Terminated": "Inactive",
    "ON_LEAVE": "On Leave",
    "On Leave": "On Leave",
    "OOO": "On Leave",
}


def clean_mapped_value(value, mapping):
    if pd.isna(value):
        return pd.NA

    value = str(value).strip()

    if not value or value.lower() in {"nan", "none", "null", "na", "n/a"}:
        return pd.NA

    return mapping.get(value, pd.NA)


# ---------------------------------------------------------------------------
# Date parsing
# ---------------------------------------------------------------------------

MISSING_DATE_VALUES = {"not available", "na", "n/a", "none", "null", ""}


def clean_mixed_date(value):
    """Parse the date formats observed in the identity master."""
    if pd.isna(value):
        return pd.NaT

    value = str(value).strip()

    if value.lower() in MISSING_DATE_VALUES:
        return pd.NaT

    # 10-digit Unix timestamp, interpreted as seconds.
    if re.fullmatch(r"\d{10}", value):
        try:
            return pd.to_datetime(int(value), unit="s")
        except (ValueError, TypeError, OverflowError):
            return pd.NaT

    # Explicit formats used by the source.
    if re.match(r"^\d{4}-\d{2}-\d{2}", value):
        try:
            return pd.to_datetime(value, dayfirst=False)
        except (ValueError, TypeError):
            return pd.NaT

    if re.match(r"^\d{4}/\d{2}/\d{2}", value):
        try:
            return pd.to_datetime(value, dayfirst=False)
        except (ValueError, TypeError):
            return pd.NaT

    if re.match(r"^\d{2}/\d{2}/\d{4}", value):
        try:
            return pd.to_datetime(value, dayfirst=True)
        except (ValueError, TypeError):
            return pd.NaT

    if re.match(r"^\d{1,2}-[A-Za-z]{3}-\d{4}", value):
        try:
            return pd.to_datetime(value, dayfirst=True)
        except (ValueError, TypeError):
            return pd.NaT

    if re.match(r"^\d{2}-\d{2}-\d{4}.*(?:AM|PM)$", value, re.IGNORECASE):
        try:
            return pd.to_datetime(value, dayfirst=False)
        except (ValueError, TypeError):
            return pd.NaT

    try:
        return pd.to_datetime(value, dayfirst=False)
    except (ValueError, TypeError):
        return pd.NaT


# ---------------------------------------------------------------------------
# Main cleaning
# ---------------------------------------------------------------------------

def clean_identity_data(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    validate_schema(df)

    raw_rows = len(df)
    exact_duplicates = int(df.duplicated().sum())

    # Remove only exact duplicate rows.
    df = df.drop_duplicates().copy()

    # Normalize fields.
    df["user_id"] = df["user_id"].apply(clean_user_id)
    df["department"] = df["department"].apply(
        lambda x: clean_mapped_value(x, DEPARTMENT_MAP)
    )
    df["location"] = df["location"].apply(
        lambda x: clean_mapped_value(x, LOCATION_MAP)
    )
    df["status"] = df["status"].apply(
        lambda x: clean_mapped_value(x, STATUS_MAP)
    )

    df["hire_date"] = df["hire_date"].apply(clean_mixed_date)
    df["termination_date"] = df["termination_date"].apply(clean_mixed_date)

    df["username"] = df["username"].apply(clean_username)
    df["hostname"] = df["hostname"].apply(clean_hostname)
    df["device_id"] = df["device_id"].apply(clean_device_id)
    df["manager_username"] = df["manager_username"].apply(clean_username)

    # Device conflict analysis.
    device_user_counts = (
        df.groupby("device_id", dropna=True)["user_id"]
        .nunique()
    )

    df["device_user_count"] = (
        df["device_id"].map(device_user_counts)
        .fillna(0)
        .astype("Int64")
    )

    df["device_id_conflict"] = (
        df["device_id"].notna()
        & (df["device_user_count"] > 1)
    )

    # Keep canonical source columns first, followed by quality/provenance fields.
    output_columns = EXPECTED_COLUMNS + [
        "device_id_conflict",
        "device_user_count",
    ]
    df = df[output_columns].copy()

    # Quality metrics.
    invalid_date_order = (
        df["hire_date"].notna()
        & df["termination_date"].notna()
        & (df["termination_date"] < df["hire_date"])
    )

    # IDs should be unique at the employee-master level; flag rather than
    # silently delete conflicting records.
    duplicate_user_ids = int(df["user_id"].duplicated(keep=False).sum())

    summary = {
        "raw_rows": raw_rows,
        "exact_duplicate_rows": exact_duplicates,
        "clean_rows": len(df),
        "duplicate_user_id_rows": duplicate_user_ids,
        "missing_user_id": int(df["user_id"].isna().sum()),
        "missing_username": int(df["username"].isna().sum()),
        "missing_hostname": int(df["hostname"].isna().sum()),
        "missing_device_id": int(df["device_id"].isna().sum()),
        "device_conflict_records": int(df["device_id_conflict"].sum()),
        "conflicting_devices": int(
            df.loc[df["device_id_conflict"], "device_id"].nunique()
        ),
        "termination_before_hire": int(invalid_date_order.sum()),
    }

    return df, summary


# ---------------------------------------------------------------------------
# Quality report
# ---------------------------------------------------------------------------

def generate_quality_report(df: pd.DataFrame) -> pd.DataFrame:
    report = pd.DataFrame(
        {
            "column": df.columns,
            "rows": len(df),
            "missing_count": [int(df[c].isna().sum()) for c in df.columns],
            "missing_pct": [
                round(float(df[c].isna().mean() * 100), 2)
                for c in df.columns
            ],
            "unique_values": [
                int(df[c].nunique(dropna=True)) for c in df.columns
            ],
        }
    )
    return report


def save_outputs(df: pd.DataFrame, summary: dict) -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    df.to_csv(OUTPUT_FILE, index=False)

    report = generate_quality_report(df)
    report.to_csv(QUALITY_REPORT_FILE, index=False)

    summary_df = pd.DataFrame(
        [{"metric": key, "value": value} for key, value in summary.items()]
    )
    summary_file = REPORT_DIR / "identity_asset_master_pipeline_summary.csv"
    summary_df.to_csv(summary_file, index=False)

    print(f"✓ Cleaned dataset saved: {OUTPUT_FILE}")
    print(f"✓ Quality report saved: {QUALITY_REPORT_FILE}")
    print(f"✓ Pipeline summary saved: {summary_file}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    print("=" * 65)
    print("       IDENTITY & ASSET MASTER CLEANING PIPELINE")
    print("=" * 65)

    if not RAW_FILE.exists():
        raise FileNotFoundError(f"Raw identity dataset not found: {RAW_FILE}")

    raw_df = pd.read_csv(RAW_FILE)

    print(
        f"Raw records loaded     : {len(raw_df):,} rows | "
        f"{len(raw_df.columns)} columns"
    )
    print(f"Exact duplicate rows   : {raw_df.duplicated().sum():,}")

    cleaned_df, summary = clean_identity_data(raw_df)

    print("-" * 65)
    print(
        f"✓ Deduplication        : removed "
        f"{summary['exact_duplicate_rows']:,} exact duplicate rows"
    )
    print(
        f"✓ Clean records        : {summary['clean_rows']:,}"
    )
    print(
        f"✓ Missing user IDs     : {summary['missing_user_id']:,}"
    )
    print(
        f"✓ Missing hostnames    : {summary['missing_hostname']:,}"
    )
    print(
        f"✓ Device conflicts     : "
        f"{summary['conflicting_devices']:,} devices / "
        f"{summary['device_conflict_records']:,} records"
    )
    print(
        f"✓ Termination < hire   : "
        f"{summary['termination_before_hire']:,} records"
    )
    print("-" * 65)

    save_outputs(cleaned_df, summary)

    print("=" * 65)
    print(
        f"PIPELINE COMPLETE: {len(cleaned_df):,} rows | "
        f"{len(cleaned_df.columns)} columns"
    )
    print("=" * 65)


if __name__ == "__main__":
    main()
