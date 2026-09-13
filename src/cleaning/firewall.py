from pathlib import Path
import re
import ipaddress
import pandas as pd


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
REPORT_DIR = PROJECT_ROOT / "reports"

FIREWALL_FILE = RAW_DIR / "track2_firewall_logs.csv"
QUALITY_REPORT_DIR = REPORT_DIR / "data_quality"
OUTPUT_FILE = PROCESSED_DIR / "track2_firewall_logs_clean.csv"
QUALITY_REPORT_FILE = QUALITY_REPORT_DIR / "firewall_quality_report.csv"
PIPELINE_SUMMARY_FILE = QUALITY_REPORT_DIR / "firewall_pipeline_summary.csv"


# ============================================================
# SCHEMA
# ============================================================

EXPECTED_COLUMNS = [
    "log_id",
    "timestamp",
    "hostname",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "action",
    "bytes_sent",
    "bytes_received",
    "session_id",
    "threat_flag",
    "rule_name",
    "geo_country",
]


def validate_schema(df: pd.DataFrame) -> None:
    """Validate that the firewall dataset contains expected columns."""
    actual_columns = df.columns.tolist()

    missing_columns = [col for col in EXPECTED_COLUMNS if col not in actual_columns]
    unexpected_columns = [col for col in actual_columns if col not in EXPECTED_COLUMNS]

    if missing_columns:
        raise ValueError(f"Missing required columns: {missing_columns}")

    if unexpected_columns:
        print(f"  Warning: Unexpected columns found: {unexpected_columns}")

    print(f"✓ Schema validated ({len(EXPECTED_COLUMNS)} required columns present)")


# ============================================================
# DATA LOADING & PROFILING
# ============================================================

def load_firewall_data() -> pd.DataFrame:
    """Load the raw firewall telemetry."""
    if not FIREWALL_FILE.exists():
        raise FileNotFoundError(f"Firewall dataset not found: {FIREWALL_FILE}")

    df = pd.read_csv(FIREWALL_FILE)
    return df.copy()


def profile_raw_data(df: pd.DataFrame) -> None:
    """Print a concise summary profile of raw firewall data."""
    missing_total = df.isna().sum().sum()
    print(f"  Raw records loaded   : {len(df):,} rows | {len(df.columns)} columns")
    print(f"  Exact duplicate rows : {df.duplicated().sum():,}")
    print(f"  Total missing cells  : {missing_total:,}")


def analyze_duplicates(df: pd.DataFrame) -> None:
    """Check duplicate log IDs vs exact duplicate rows."""
    dup_ids = df["log_id"].duplicated(keep=False).sum()
    exact_dups = df.duplicated().sum()
    print(f"  Duplicate log_id rows: {dup_ids:,} (confirmed all {exact_dups:,} are exact identical rows)")


def remove_exact_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    """Remove exact duplicate rows across all columns."""
    before = len(df)
    df = df.drop_duplicates().copy()
    removed = before - len(df)
    print(f"✓ Deduplication: Removed {removed:,} exact duplicate rows ({len(df):,} remaining)")
    return df


# ============================================================
# FIELD-LEVEL CLEANING
# ============================================================

def clean_timestamps(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize multi-format timestamp strings into ISO datetime."""
    timestamp = df["timestamp"].astype("string").str.strip()
    cleaned = pd.Series(pd.NaT, index=df.index, dtype="datetime64[ns]")

    rules = [
        ("YYYY-MM-DD HH:MM:SS", r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$", "%Y-%m-%d %H:%M:%S"),
        ("DD/MM/YYYY HH:MM", r"^\d{2}/\d{2}/\d{4} \d{2}:\d{2}$", "%d/%m/%Y %H:%M"),
        ("YYYY-MM-DDTHH:MM:SS", r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$", "%Y-%m-%dT%H:%M:%S"),
        ("DD-Mon-YYYY HH:MM:SS", r"^\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2}$", "%d-%b-%Y %H:%M:%S"),
        ("MM-DD-YYYY HH:MM:SS AM/PM", r"^\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2} [AP]M$", "%m-%d-%Y %I:%M:%S %p"),
        ("Date only", r"^\d{2}/\d{2}/\d{4}$", "%d/%m/%Y"),
        ("YYYY/MM/DD", r"^\d{4}/\d{2}/\d{2}$", "%Y/%m/%d"),
    ]

    for _, pattern, fmt in rules:
        mask = timestamp.str.match(pattern, na=False)
        cleaned.loc[mask] = pd.to_datetime(timestamp[mask], format=fmt, errors="coerce")

    unix_mask = timestamp.str.match(r"^\d{10}$", na=False)
    if unix_mask.any():
        cleaned.loc[unix_mask] = pd.to_datetime(
            pd.to_numeric(timestamp[unix_mask]), unit="s", errors="coerce"
        )

    df["timestamp"] = cleaned
    valid_cnt = cleaned.notna().sum()
    miss_cnt = cleaned.isna().sum()
    print(f"✓ Timestamps: Standardized {valid_cnt:,} timestamps to ISO datetime ({miss_cnt:,} missing/NaT)")
    return df


def create_hostname_join_key(df: pd.DataFrame) -> pd.DataFrame:
    """Clean hostnames and create join key by stripping domain suffix."""
    hostname = (
        df["hostname"]
        .astype("string")
        .str.strip()
        .str.lower()
        .str.replace("_", "-", regex=False)
    )
    df["hostname"] = hostname
    df["hostname_join_key"] = hostname.str.replace(r"\.corp\.local$", "", regex=True)

    unique_keys = df["hostname_join_key"].nunique(dropna=True)
    miss_cnt = df["hostname"].isna().sum()
    print(f"✓ Hostnames: Created 'hostname_join_key' ({unique_keys:,} unique keys, {miss_cnt:,} missing)")
    return df


def validate_ip_addresses(df: pd.DataFrame) -> pd.DataFrame:
    """Validate IPv4/IPv6 addresses, preserve validity status, and nullify invalid values."""
    for column in ["src_ip", "dst_ip"]:
        values = df[column].astype("string").str.strip()

        def classify_ip(val):
            if pd.isna(val) or val == "":
                return pd.NA
            try:
                ipaddress.ip_address(val)
                return True
            except ValueError:
                return False

        valid = values.map(classify_ip).astype("boolean")
        df[f"{column}_valid"] = valid
        df[column] = values.where(valid == True, pd.NA)

    src_v = (df["src_ip_valid"] == True).sum()
    src_inv = (df["src_ip_valid"] == False).sum()
    src_orig_m = df["src_ip_valid"].isna().sum()
    src_final_m = df["src_ip"].isna().sum()

    dst_v = (df["dst_ip_valid"] == True).sum()
    dst_inv = (df["dst_ip_valid"] == False).sum()
    dst_orig_m = df["dst_ip_valid"].isna().sum()
    dst_final_m = df["dst_ip"].isna().sum()

    print(f"✓ IP Addresses:")
    print(f"    - src_ip : {src_v:,} valid | {src_inv:,} invalid | {src_orig_m:,} originally missing -> {src_final_m:,} final missing")
    print(f"    - dst_ip : {dst_v:,} valid | {dst_inv:,} invalid | {dst_orig_m:,} originally missing -> {dst_final_m:,} final missing")
    return df


def clean_ports(df: pd.DataFrame) -> pd.DataFrame:
    """Validate and clean ports (0-65535), setting invalid values to NA."""
    for column in ["src_port", "dst_port"]:
        numeric = pd.to_numeric(df[column], errors="coerce")
        original = df[column].astype("string").str.strip()

        valid = numeric.notna() & (numeric >= 0) & (numeric <= 65535) & (numeric % 1 == 0)
        missing = original.isna() | original.eq("")
        invalid = ~valid & ~missing

        status = pd.Series("valid", index=df.index, dtype="string")
        status.loc[missing] = "missing"
        status.loc[invalid] = "invalid"

        df[f"{column}_status"] = status
        df[column] = numeric.where(valid, pd.NA).astype("Int64")

    s_v = (df["src_port_status"] == "valid").sum()
    s_inv = (df["src_port_status"] == "invalid").sum()
    d_v = (df["dst_port_status"] == "valid").sum()
    d_inv = (df["dst_port_status"] == "invalid").sum()

    print(f"✓ Port Numbers (0-65535):")
    print(f"    - src_port : {s_v:,} valid | {s_inv:,} invalid | {df['src_port'].isna().sum():,} missing")
    print(f"    - dst_port : {d_v:,} valid | {d_inv:,} invalid | {df['dst_port'].isna().sum():,} missing")
    return df


def clean_protocol(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize protocols to standard uppercase canonical tokens."""
    original = df["protocol"].astype("string").str.strip().str.upper()

    protocol_map = {
        "TCP": "TCP",
        "TCP/6": "TCP",
        "6": "TCP",
        "UDP": "UDP",
        "UDP/17": "UDP",
        "17": "UDP",
        "ICMP": "ICMP",
        "1": "ICMP",
    }

    cleaned = original.map(protocol_map)
    missing = original.isna() | original.eq("")
    unknown = cleaned.isna() & ~missing

    cleaned.loc[unknown] = "OTHER"
    cleaned.loc[missing] = pd.NA
    df["protocol"] = cleaned.astype("string")

    counts = df["protocol"].value_counts().to_dict()
    summary = " | ".join(f"{k}: {v:,}" for k, v in counts.items())
    print(f"✓ Protocols normalized: {summary} ({missing.sum():,} missing)")
    return df


def clean_actions(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize firewall actions to ALLOW / DENY."""
    original = df["action"].astype("string").str.strip().str.upper()

    action_map = {
        "ALLOW": "ALLOW",
        "PERMIT": "ALLOW",
        "PASS": "ALLOW",
        "DENY": "DENY",
        "DROP": "DENY",
        "BLOCK": "DENY",
    }

    cleaned = original.map(action_map)
    missing = original.isna() | original.eq("")
    unknown = cleaned.isna() & ~missing

    cleaned.loc[unknown] = "OTHER"
    cleaned.loc[missing] = pd.NA
    df["action"] = cleaned.astype("string")

    counts = df["action"].value_counts().to_dict()
    summary = " | ".join(f"{k}: {v:,}" for k, v in counts.items())
    print(f"✓ Actions normalized: {summary} ({missing.sum():,} missing)")
    return df


def clean_byte_value(value):
    """Parse byte string with optional comma or unit (KB/MB/GB) into integer bytes."""
    if pd.isna(value):
        return pd.NA
    value = str(value).strip()
    if value == "":
        return pd.NA

    normalized = value.replace(",", "")
    match = re.fullmatch(r"([-+]?\d+(?:\.\d+)?)\s*(KB|MB|GB)?", normalized, flags=re.IGNORECASE)
    if not match:
        return pd.NA

    number = float(match.group(1))
    unit = match.group(2)
    if number < 0:
        return pd.NA

    multiplier = {None: 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}
    return int(round(number * multiplier[unit.upper() if unit else None]))


def clean_byte_fields(df: pd.DataFrame) -> pd.DataFrame:
    """Standardize bytes_sent and bytes_received into integer byte counts."""
    for column in ["bytes_sent", "bytes_received"]:
        original = df[column].astype("string").str.strip()
        missing = original.isna() | original.eq("")
        cleaned = original.map(clean_byte_value)
        invalid = cleaned.isna() & ~missing

        status = pd.Series("valid", index=df.index, dtype="string")
        status.loc[missing] = "missing"
        status.loc[invalid] = "invalid"

        df[f"{column}_status"] = status
        df[column] = cleaned.astype("Int64")

    s_v = (df["bytes_sent_status"] == "valid").sum()
    r_v = (df["bytes_received_status"] == "valid").sum()
    print(f"✓ Byte Counts: bytes_sent ({s_v:,} valid) | bytes_received ({r_v:,} valid)")
    return df


def clean_threat_flags(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize boolean threat flags."""
    original = df["threat_flag"].astype("string").str.strip().str.lower()

    true_values = {"true", "yes", "y", "1"}
    false_values = {"false", "no", "n", "0"}

    cleaned = pd.Series(pd.NA, index=df.index, dtype="boolean")
    cleaned.loc[original.isin(true_values)] = True
    cleaned.loc[original.isin(false_values)] = False

    df["threat_flag"] = cleaned
    t_cnt = (cleaned == True).sum()
    f_cnt = (cleaned == False).sum()
    m_cnt = cleaned.isna().sum()
    print(f"✓ Threat Flags: True: {t_cnt:,} | False: {f_cnt:,} | Missing: {m_cnt:,}")
    return df


def clean_session_ids(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize session IDs to canonical format (SID + 6 digits)."""
    original = df["session_id"].astype("string").str.strip().str.upper()
    missing = original.isna() | original.eq("")

    cleaned = original.str.replace(r"^SID-(\d{6})$", r"SID\1", regex=True)
    valid_format = cleaned.str.fullmatch(r"SID\d{6}", na=False)
    unexpected = ~missing & ~valid_format

    df["session_id"] = cleaned.astype("string")
    v_cnt = valid_format.sum()
    m_cnt = missing.sum()
    u_cnt = unexpected.sum()
    print(f"✓ Session IDs: {v_cnt:,} valid (canonical SID+6 digits) | {u_cnt:,} unexpected | {m_cnt:,} missing")
    return df


def clean_rule_names(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize rule names to uppercase canonical tokens."""
    original = df["rule_name"].astype("string").str.strip()
    missing = original.isna() | original.eq("")
    cleaned = original.str.upper()

    df["rule_name"] = cleaned
    non_m = (~missing).sum()
    u_cnt = cleaned.nunique(dropna=True)
    print(f"✓ Rule Names: {non_m:,} mapped to {u_cnt} canonical rules ({missing.sum():,} missing)")
    return df


def clean_geo_country(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize country names to standard ISO 2-letter codes."""
    original = df["geo_country"].astype("string").str.strip().str.upper()
    missing = original.isna() | original.eq("")

    country_map = {
        "US": "US",
        "UNITED STATES": "US",
        "IN": "IN",
        "IND": "IN",
        "INDIA": "IN",
        "RU": "RU",
        "RUSSIA": "RU",
        "CN": "CN",
        "CHINA": "CN",
        "UNKNOWN": "UNKNOWN",
    }

    cleaned = original.map(country_map)
    df["geo_country"] = cleaned.astype("string")

    counts = df["geo_country"].value_counts().to_dict()
    summary = " | ".join(f"{k}: {v:,}" for k, v in counts.items())
    print(f"✓ Geo Countries: {summary} ({missing.sum():,} missing)")
    return df


def validate_log_ids(df: pd.DataFrame) -> pd.DataFrame:
    """Ensure log_id primary key has zero duplicates and zero missing values."""
    missing = (df["log_id"].isna() | df["log_id"].astype("string").str.strip().eq("")).sum()
    duplicate = df["log_id"].duplicated().sum()

    if missing == 0 and duplicate == 0:
        print(f"✓ Log ID integrity: 100% unique & non-null ({len(df):,} records)")
    else:
        print(f"⚠ Log ID integrity warning: {missing:,} missing | {duplicate:,} duplicates")
    return df


def generate_quality_report(df):
    print("=" * 60)
    print("FINAL DATA QUALITY REPORT")
    print("=" * 60)

    report = []

    for column in EXPECTED_COLUMNS:
        missing = df[column].isna().sum()
        unique = df[column].nunique(dropna=True)

        report.append({
            "column": column,
            "rows": len(df),
            "missing_count": missing,
            "missing_pct": round(
                missing / len(df) * 100, 2
            ),
            "unique_values": unique,
        })

    report_df = pd.DataFrame(report)

    QUALITY_REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    report_df.to_csv(
        QUALITY_REPORT_FILE,
        index=False
    )

    print(
        f"✓ Quality report saved: "
        f"{QUALITY_REPORT_FILE}"
    )

    return report_df


def save_cleaned_data(df):
    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print(
        f"✓ Cleaned dataset saved: "
        f"{OUTPUT_FILE}"
    )


def generate_pipeline_summary(raw_df: pd.DataFrame, clean_df: pd.DataFrame) -> pd.DataFrame:
    raw_rows = len(raw_df)
    exact_duplicates = int(raw_df.duplicated().sum())

    summary = {
        "raw_rows": raw_rows,
        "exact_duplicate_rows": exact_duplicates,
        "clean_rows": len(clean_df),
        "clean_columns": len(clean_df.columns),
        "duplicate_log_ids": int(clean_df["log_id"].duplicated().sum()),
        "missing_log_ids": int(clean_df["log_id"].isna().sum()),
        "standardized_timestamps": int(clean_df["timestamp"].notna().sum()),
        "missing_timestamps": int(clean_df["timestamp"].isna().sum()),
        "unique_hostnames": int(clean_df["hostname"].nunique(dropna=True)),
        "missing_hostnames": int(clean_df["hostname"].isna().sum()),
        "unique_hostname_join_keys": int(clean_df["hostname_join_key"].nunique(dropna=True)),
        "valid_src_ip": int((clean_df["src_ip_valid"] == True).sum()),
        "invalid_src_ip": int((clean_df["src_ip_valid"] == False).sum()),
        "missing_src_ip": int(clean_df["src_ip"].isna().sum()),
        "valid_dst_ip": int((clean_df["dst_ip_valid"] == True).sum()),
        "invalid_dst_ip": int((clean_df["dst_ip_valid"] == False).sum()),
        "missing_dst_ip": int(clean_df["dst_ip"].isna().sum()),
        "valid_src_port": int((clean_df["src_port_status"] == "valid").sum()),
        "invalid_src_port": int((clean_df["src_port_status"] == "invalid").sum()),
        "missing_src_port": int(clean_df["src_port"].isna().sum()),
        "valid_dst_port": int((clean_df["dst_port_status"] == "valid").sum()),
        "invalid_dst_port": int((clean_df["dst_port_status"] == "invalid").sum()),
        "missing_dst_port": int(clean_df["dst_port"].isna().sum()),
        "threat_flag_true": int((clean_df["threat_flag"] == True).sum()),
        "threat_flag_false": int((clean_df["threat_flag"] == False).sum()),
        "valid_session_ids": int(clean_df["session_id"].notna().sum()),
        "missing_session_ids": int(clean_df["session_id"].isna().sum()),
        "missing_rule_names": int(clean_df["rule_name"].isna().sum()),
        "missing_geo_country": int(clean_df["geo_country"].isna().sum()),
    }

    summary_df = pd.DataFrame(
        [{"metric": k, "value": v} for k, v in summary.items()]
    )

    QUALITY_REPORT_DIR.mkdir(parents=True, exist_ok=True)
    summary_df.to_csv(PIPELINE_SUMMARY_FILE, index=False)

    print(f"✓ Pipeline summary saved: {PIPELINE_SUMMARY_FILE}")

    return summary_df


# ============================================================
# MAIN PIPELINE
# ============================================================

def main() -> pd.DataFrame:
    """Run full firewall telemetry cleaning pipeline."""
    print("\n" + "=" * 65)
    print("          FIREWALL DATA CLEANING PIPELINE")
    print("=" * 65)

    raw_df = load_firewall_data()
    df = raw_df.copy()

    # Raw validation
    validate_schema(df)
    profile_raw_data(df)
    analyze_duplicates(df)

    print("-" * 65)

    # Deduplication & cleaning
    df = remove_exact_duplicates(df)
    df = clean_timestamps(df)
    df = create_hostname_join_key(df)
    df = validate_ip_addresses(df)
    df = clean_ports(df)
    df = clean_protocol(df)
    df = clean_actions(df)
    df = clean_byte_fields(df)
    df = clean_threat_flags(df)
    df = clean_session_ids(df)
    df = clean_rule_names(df)
    df = clean_geo_country(df)

    print("-" * 65)

    # Final integrity validation
    df = validate_log_ids(df)

    # Generate evidence
    quality_report = generate_quality_report(df)
    pipeline_summary = generate_pipeline_summary(raw_df, df)

    # Save processed dataset
    save_cleaned_data(df)

    print("\n" + "=" * 65)
    print("PIPELINE COMPLETE")
    print("=" * 65)
    print(f"Final rows    : {len(df):,}")
    print(f"Final columns : {len(df.columns):,}")
    print("=" * 65)

    return df


if __name__ == "__main__":
    cleaned_df = main()