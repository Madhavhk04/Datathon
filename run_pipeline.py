"""Run the complete AgentIQ cybersecurity analytics pipeline.

Pipeline order:
1. Clean identity / asset master
2. Clean IAM audit trail
3. Clean endpoint alerts
4. Clean firewall logs
5. Validate cross-source relationships
6. Calculate user risk scores
7. Detect threats
8. Build corroborated investigation queue

All individual modules remain independently runnable. This orchestrator simply
runs them in dependency order and verifies that the expected outputs exist.
"""

from __future__ import annotations

import argparse
import runpy
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent

RAW_FILES = [
    ROOT / "data" / "raw" / "track2_identity_asset_master.csv",
    ROOT / "data" / "raw" / "track2_iam_audit_trail.json",
    ROOT / "data" / "raw" / "track2_endpoint_alerts.xlsx",
    ROOT / "data" / "raw" / "track2_firewall_logs.csv",
]

STEPS = [
    ("Identity / Asset Master", ROOT / "src" / "cleaning" / "identity.py"),
    ("IAM Audit Trail", ROOT / "src" / "cleaning" / "iam.py"),
    ("Endpoint Alerts", ROOT / "src" / "cleaning" / "endpoint.py"),
    ("Firewall Logs", ROOT / "src" / "cleaning" / "firewall.py"),
    ("Relationship Validation", ROOT / "src" / "validation" / "relationships.py"),
    ("Risk Scoring", ROOT / "src" / "analytics" / "risk.py"),
    ("Threat Detection", ROOT / "src" / "analytics" / "threat.py"),
    ("Investigation Corroboration", ROOT / "src" / "analytics" / "corroboration.py"),
]

EXPECTED_OUTPUTS = [
    ROOT / "data" / "processed" / "track2_identity_asset_master_clean.csv",
    ROOT / "data" / "processed" / "track2_iam_audit_trail_clean.csv",
    ROOT / "data" / "processed" / "track2_endpoint_alerts_clean.csv",
    ROOT / "data" / "processed" / "track2_firewall_logs_clean.csv",
    ROOT / "reports" / "join_quality" / "relationship_quality_report.csv",
    ROOT / "reports" / "join_quality" / "session_relationship_report.csv",
    ROOT / "reports" / "join_quality" / "session_hostname_consistency_report.csv",
    ROOT / "reports" / "join_quality" / "shared_session_evidence.csv",
    ROOT / "reports" / "join_quality" / "ambiguous_hostnames.csv",
    ROOT / "reports" / "join_quality" / "ambiguous_devices.csv",
    ROOT / "data" / "analytics" / "user_risk_scores.csv",
    ROOT / "reports" / "analytics" / "risk_band_distribution.csv",
    ROOT / "reports" / "analytics" / "top_100_risk_users.csv",
    ROOT / "data" / "analytics" / "threat_detections.csv",
    ROOT / "reports" / "analytics" / "threat_type_summary.csv",
    ROOT / "reports" / "analytics" / "threat_severity_summary.csv",
    ROOT / "data" / "analytics" / "investigation_queue.csv",
    ROOT / "reports" / "analytics" / "investigation_queue_summary.csv",
]


def print_header(text: str) -> None:
    print("\n" + "=" * 72)
    print(text)
    print("=" * 72)


def check_raw_inputs() -> None:
    missing = [path for path in RAW_FILES if not path.exists()]
    if missing:
        print("ERROR: Required raw dataset(s) are missing:")
        for path in missing:
            print(f"  - {path.relative_to(ROOT)}")
        raise SystemExit(1)


def run_step(name: str, script: Path) -> None:
    if not script.exists():
        raise FileNotFoundError(f"Pipeline step not found: {script}")

    print_header(f"STEP: {name}")
    print(f"Running: {script.relative_to(ROOT)}")

    old_argv = sys.argv
    try:
        sys.argv = [str(script)]
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        if code != 0:
            print(f"\nERROR: {name} failed with exit code {code}.")
            raise SystemExit(code) from exc
    except Exception as exc:
        print(f"\nERROR: {name} failed: {exc.__class__.__name__}: {exc}")
        raise
    finally:
        sys.argv = old_argv

    print(f"✓ {name} completed successfully.")


def verify_outputs() -> None:
    print_header("OUTPUT VALIDATION")
    missing = [path for path in EXPECTED_OUTPUTS if not path.exists()]

    if missing:
        print("ERROR: Pipeline completed, but expected outputs are missing:")
        for path in missing:
            print(f"  - {path.relative_to(ROOT)}")
        raise SystemExit(1)

    for path in EXPECTED_OUTPUTS:
        print(f"✓ {path.relative_to(ROOT)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the complete AgentIQ cybersecurity analytics pipeline."
    )
    parser.add_argument(
        "--skip-input-check",
        action="store_true",
        help="Skip the raw-data existence check before starting.",
    )
    args = parser.parse_args()

    if not args.skip_input_check:
        check_raw_inputs()

    print_header("AGENTIQ CYBERSECURITY PIPELINE")
    print(f"Project root: {ROOT}")
    print(f"Python: {sys.executable}")

    for name, script in STEPS:
        run_step(name, script)

    verify_outputs()

    print_header("PIPELINE COMPLETE")
    print("✓ All pipeline stages completed successfully.")
    print("✓ All expected production outputs are present.")
    print("\nThe project is ready for downstream dashboard / agent consumption.")


if __name__ == "__main__":
    main()
