# Issue #6: Endpoint Alert Cleaning and Risk Analysis

This branch implements GitHub Issue #6 for the TransOrg AgentIQ Datathon. It cleans and validates endpoint security alerts, enriches them with identity and asset information, and generates explainable risky-device and risky-user outputs.

## Scope

This implementation focuses only on endpoint alert processing. Dashboard development, IAM audit analysis, firewall analysis, and AI-agent integration are outside the scope of this issue.

## Input datasets

The notebook uses the following files from `data/raw/`:

- `track2_endpoint_alerts.xlsx` — primary endpoint-alert dataset
- `track2_identity_asset_master.csv` — identity and asset reference data used for enrichment


## Processing completed

The notebook:

- Profiles the raw endpoint-alert data and records baseline metrics.
- Normalizes user IDs, hostnames, severities, statuses, and device criticality.
- Parses mixed timestamp formats and flags missing, invalid, unresolved, and impossible timestamps.
- Validates SHA-256 hash values.
- Detects duplicate alert IDs and distinguishes exact duplicates from conflicting duplicate records.
- Categorizes alerts, including malware/ransomware, credential access, lateral movement, PowerShell, USB, security tampering, and phishing/browser threats.
- Flags critical, unresolved, malformed, and otherwise invalid alert records.
- Enriches endpoint alerts using the identity and asset master.
- Classifies identity joins as both-key, user-only, hostname-only, ambiguous, or unmatched.
- Calculates explainable device- and user-level risk scores.
- Preserves risk-score components and risk reasons for traceability.
- Exports processed datasets and quality reports.
- Runs final acceptance assertions to verify the expected output structure and data quality.
