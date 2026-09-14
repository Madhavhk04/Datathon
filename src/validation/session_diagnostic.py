import pandas as pd
from pathlib import Path

# ============================================================
# CREDENTIAL COMPROMISE DIAGNOSTIC
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

IAM_PATH = ROOT / "data" / "processed" / "track2_iam_audit_trail_clean.csv"
ENDPOINT_PATH = ROOT / "data" / "processed" / "track2_endpoint_alerts_clean.csv"

print("=" * 60)
print("CREDENTIAL COMPROMISE DIAGNOSTIC")
print("=" * 60)

iam = pd.read_csv(IAM_PATH)
endpoint = pd.read_csv(ENDPOINT_PATH)

iam["timestamp"] = pd.to_datetime(iam["timestamp"], errors="coerce")
endpoint["detected_timestamp"] = pd.to_datetime(
    endpoint["detected_timestamp"],
    errors="coerce"
)

print(f"\nIAM      : {iam.shape}")
print(f"Endpoint : {endpoint.shape}")

# ------------------------------------------------------------
# Normalize event names
# ------------------------------------------------------------

iam["event_type_norm"] = (
    iam["event_type"]
    .astype("string")
    .str.strip()
    .str.lower()
)

endpoint["alert_name_norm"] = (
    endpoint["alert_name"]
    .astype("string")
    .str.strip()
    .str.lower()
)

# ------------------------------------------------------------
# Identify relevant signals
# ------------------------------------------------------------

failed_auth = iam[
    iam["event_type_norm"].str.contains(
        "fail", na=False
    )
].copy()

mfa_fail = iam[
    (
        iam["event_type_norm"].str.contains("mfa", na=False)
    )
    &
    (
        iam["event_type_norm"].str.contains(
            "fail|denied|reject", na=False
        )
    )
].copy()

credential_alerts = endpoint[
    endpoint["alert_name_norm"].str.contains(
        "credential|credential access|credential-access",
        na=False
    )
].copy()

print("\nSIGNAL COUNTS")
print("-" * 60)
print(f"Failed authentication events : {len(failed_auth)}")
print(f"MFA failure events            : {len(mfa_fail)}")
print(f"Credential-access alerts      : {len(credential_alerts)}")

# ------------------------------------------------------------
# User-level availability
# ------------------------------------------------------------

print("\nUSERS WITH EACH SIGNAL")
print("-" * 60)

failed_users = set(failed_auth["user_id"].dropna())
mfa_users = set(mfa_fail["user_id"].dropna())
credential_users = set(credential_alerts["user_id"].dropna())

print(f"Users with failed auth       : {len(failed_users)}")
print(f"Users with MFA failures      : {len(mfa_users)}")
print(f"Users with credential alerts : {len(credential_users)}")

all_three_users = (
    failed_users
    & mfa_users
    & credential_users
)

print(f"Users with ALL THREE signals : {len(all_three_users)}")

# ------------------------------------------------------------
# 24-hour temporal diagnostic
# ------------------------------------------------------------

def max_events_in_window(df, user_col, time_col, window_hours=24):
    results = []

    work = df[
        [user_col, time_col]
    ].dropna().sort_values([user_col, time_col])

    for user_id, group in work.groupby(user_col):
        times = group[time_col].sort_values().tolist()

        left = 0
        max_count = 0

        for right in range(len(times)):
            while (
                times[right] - times[left]
            ).total_seconds() > window_hours * 3600:
                left += 1

            max_count = max(max_count, right - left + 1)

        results.append((user_id, max_count))

    return pd.DataFrame(
        results,
        columns=["user_id", "max_events_24h"]
    )


failed_24h = max_events_in_window(
    failed_auth,
    "user_id",
    "timestamp"
)

mfa_24h = max_events_in_window(
    mfa_fail,
    "user_id",
    "timestamp"
)

credential_24h = max_events_in_window(
    credential_alerts,
    "user_id",
    "detected_timestamp"
)

# ------------------------------------------------------------
# Check qualifying users
# ------------------------------------------------------------

failed_qualifying = set(
    failed_24h.loc[
        failed_24h["max_events_24h"] >= 3,
        "user_id"
    ]
)

mfa_qualifying = set(
    mfa_24h.loc[
        mfa_24h["max_events_24h"] >= 2,
        "user_id"
    ]
)

credential_qualifying = set(
    credential_24h["user_id"]
)

print("\n24-HOUR WINDOW CHECK")
print("-" * 60)

print(
    f"Users with >=3 failed auth in 24h : "
    f"{len(failed_qualifying)}"
)

print(
    f"Users with >=2 MFA failures in 24h: "
    f"{len(mfa_qualifying)}"
)

print(
    f"Users with credential alert        : "
    f"{len(credential_qualifying)}"
)

qualifying_users = (
    failed_qualifying
    & mfa_qualifying
    & credential_qualifying
)

print(
    f"\nUSERS QUALIFYING FOR CREDENTIAL "
    f"COMPROMISE: {len(qualifying_users)}"
)

if qualifying_users:
    print("\nQualifying users:")
    for user_id in sorted(qualifying_users):
        print(f"  - {user_id}")

# ------------------------------------------------------------
# Important diagnostic:
# show near misses
# ------------------------------------------------------------

print("\nNEAR-MISS ANALYSIS")
print("-" * 60)

common_users = (
    failed_users
    & mfa_users
    & credential_users
)

near_misses = []

for user_id in common_users:

    f = failed_24h.loc[
        failed_24h["user_id"] == user_id,
        "max_events_24h"
    ]

    m = mfa_24h.loc[
        mfa_24h["user_id"] == user_id,
        "max_events_24h"
    ]

    failed_max = int(f.iloc[0]) if len(f) else 0
    mfa_max = int(m.iloc[0]) if len(m) else 0

    near_misses.append(
        (
            user_id,
            failed_max,
            mfa_max
        )
    )

near_misses = sorted(
    near_misses,
    key=lambda x: (x[1], x[2]),
    reverse=True
)

for user_id, failed_max, mfa_max in near_misses[:20]:
    print(
        f"{user_id}: "
        f"failed_auth_24h={failed_max}, "
        f"mfa_failures_24h={mfa_max}"
    )

print("\n" + "=" * 60)
print("DIAGNOSTIC COMPLETE")
print("=" * 60)