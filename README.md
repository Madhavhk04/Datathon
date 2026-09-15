# AgentIQ Datathon — Zero-Trust Telemetry & Insider Threat Detection

This project brings together four different security telemetry sources and turns them into something an analyst can actually work with.

The main idea was simple: **clean the data without hiding its problems, understand which relationships are trustworthy, then use the reliable signals to find users and activity that deserve investigation.**

The pipeline works with:

- Identity & Asset Master
- IAM Audit Trail
- Endpoint Alerts
- Firewall Logs

It produces user-level risk scores, concrete threat detections, a prioritized investigation queue, and a local SOC-style dashboard with an analyst/agent layer.

---

## What we built

The project is split into a few clear stages:

```text
Raw Telemetry
     │
     ▼
Cleaning & Standardization
     │
     ▼
Data Quality + Relationship Validation
     │
     ├───────────────┐
     ▼               ▼
Risk Analytics   Threat Detection
     │               │
     └───────┬───────┘
             ▼
      Corroboration
             │
             ▼
    Investigation Queue
             │
       ┌─────┴─────┐
       ▼           ▼
   Dashboard    AI Analyst
```

A key design decision is that the **Identity & Asset Master is the canonical identity/asset anchor**. We measure relationships before using them instead of assuming that every shared identifier means two records belong together.

---

## Repository structure

```text
Datathon/
│
├── README.md
├── .gitignore
├── run_pipeline.py
│
├── data/
│   ├── raw/
│   │   ├── track2_identity_asset_master.csv
│   │   ├── track2_iam_audit_trail.json
│   │   ├── track2_endpoint_alerts.xlsx
│   │   └── track2_firewall_logs.csv
│   │
│   ├── processed/
│   │   ├── track2_identity_asset_master_clean.csv
│   │   ├── track2_iam_audit_trail_clean.csv
│   │   ├── track2_endpoint_alerts_clean.csv
│   │   └── track2_firewall_logs_clean.csv
│   │
│   └── analytics/
│       ├── user_risk_scores.csv
│       ├── threat_detections.csv
│       └── investigation_queue.csv
│
├── src/
│   ├── cleaning/
│   │   ├── identity.py
│   │   ├── iam.py
│   │   ├── endpoint.py
│   │   └── firewall.py
│   │
│   ├── validation/
│   │   └── relationships.py
│   │
│   └── analytics/
│       ├── risk.py
│       ├── threat.py
│       └── corroboration.py
│
├── reports/
│   ├── data_quality/
│   ├── join_quality/
│   └── analytics/
│
├── backend/
│   ├── main.py
│   └── requirements.txt
│
├── dashboard/
│   ├── package.json
│   └── src/
│
├── agent/
│   ├── agent.py
│   ├── chat_analyst.py
│   ├── investigator.py
│   └── tools.py
│
└── docs/
    └── data_dictionary.md
```

---

# 1. Data sources

| Dataset | What it represents | Main role in the project |
|---|---|---|
| Identity & Asset Master | Users, departments, hosts and devices | Canonical identity/asset reference |
| IAM Audit Trail | Authentication and identity events | Authentication and IAM risk signals |
| Endpoint Alerts | Endpoint security alerts | Malware, credential, lateral movement and endpoint signals |
| Firewall Logs | Network activity | Network/threat telemetry and hostname relationships |

The raw files are kept separate from the processed files. The cleaning scripts read the raw data and write cleaned analytical versions rather than overwriting the originals.

---

# 2. Data rescue and cleaning

We did not want cleaning to mean simply deleting every row containing a null value. Security telemetry is messy by nature, and a missing value can itself be useful information.

The general approach was:

1. Remove exact duplicate records where the duplicate is clearly the same record.
2. Normalize identifiers and categorical values.
3. Parse timestamps into a consistent datetime representation.
4. Validate IP addresses, ports, hashes and other structured fields.
5. Keep missing information as missing instead of inventing a value.
6. Add quality flags where a specific condition needs to be visible downstream.
7. Measure relationships between datasets before using them for analytics.

### Overall row counts

| Dataset | Raw rows | Exact duplicates removed | Clean rows |
|---|---:|---:|---:|
| Identity & Asset Master | 3,090 | 90 | 3,000 |
| IAM Audit Trail | 20,500 | 500 | 20,000 |
| Endpoint Alerts | 8,240 | 240 | 8,000 |
| Firewall Logs | 30,600 | 600 | 30,000 |
| **Total** | **62,430** | **1,430** | **61,000** |

The quality reports under `reports/data_quality/` provide the detailed cleaning evidence.

---

## Identity & Asset Master

The identity data is used as the reference point for user, host and device relationships.

Cleaning includes:

- Exact duplicate removal
- User ID normalization
- Username normalization
- Department, location and status normalization
- Hire/termination date parsing
- Hostname normalization
- Device ID normalization
- Detection of conflicting device ownership

Result:

```text
Raw records             : 3,090
Exact duplicates removed: 90
Clean records            : 3,000
```

Conflicting device assignments are not silently resolved. They are retained as a quality signal so that downstream analysis knows the relationship is ambiguous.

---

## IAM Audit Trail

The IAM pipeline standardizes the fields needed for authentication and identity analysis.

Cleaning includes:

- Exact duplicate removal
- Event ID validation
- User and username normalization
- Timestamp parsing
- Authentication method normalization
- IP validation
- Hostname and device ID normalization
- Session ID normalization
- MFA value normalization
- Risk score and risk-level handling
- Preservation of failure reasons

Result:

```text
Raw records             : 20,500
Exact duplicates removed: 500
Clean records            : 20,000
```

Duplicate event IDs are also checked after deduplication so duplicate security events do not quietly enter the analytics layer.

---

## Endpoint Alerts

Endpoint telemetry contains several different kinds of problems, so we kept a distinction between missing information and genuinely invalid information.

Cleaning includes:

- Exact duplicate removal
- Alert ID validation
- Detected/resolved timestamp parsing
- Hostname and user ID validation
- Severity and status normalization
- Device criticality normalization
- SHA-256 validation
- Resolution consistency checks
- Explicit data-quality flags

Result:

```text
Raw records             : 8,240
Exact duplicates removed: 240
Clean records            : 8,000
```

Current quality findings include:

```text
Missing hostnames       : 481
Impossible resolutions  : 263
Missing SHA-256         : 1,438
Invalid SHA-256         : 799
Rows requiring review   : 5,168
```

A missing SHA-256 is not automatically treated as an invalid hash. The absence of telemetry and malformed telemetry are two different conditions, so the pipeline keeps them separate.

---

## Firewall Logs

Firewall records contain mixed timestamp formats and inconsistent network fields.

Cleaning includes:

- Exact duplicate removal
- Timestamp parsing across supported formats
- Hostname normalization
- IP validation
- Port validation
- Protocol normalization
- Action normalization
- Byte-field validation
- Session ID normalization
- Threat flag normalization
- Preservation of geographic fields

Result:

```text
Raw records             : 30,600
Exact duplicates removed: 600
Clean records            : 30,000
```

A separate `hostname_join_key` is used when comparing hostnames with the identity data. This allows the `.corp.local` suffix to be handled consistently without changing the original analytical hostname.

The resulting firewall-to-identity hostname match rate is **94.41%**.

---

# 3. Missing values and quality flags

Missing values are generally retained in the cleaned data. We did not use blanket imputation just to make the tables look complete.

Where it helps explain a specific problem, the cleaned dataset contains an additional flag. Endpoint alerts are the clearest example, with fields such as:

- `missing_hostname_flag`
- `missing_user_id_flag`
- `invalid_detected_timestamp_flag`
- `impossible_resolution_flag`
- `invalid_sha256_flag`
- `sha256_missing_flag`

The distinction is important: a flag does not replace the original field. It records what happened to that field or record while the available value remains available for analysis.

For invalid structured values, the analytical field may be set to null while the corresponding validation flag records why it was rejected. This avoids passing malformed values into downstream joins or calculations.

---

# 4. Relationship validation

One of the more important parts of the project was deciding **which relationships we could actually trust**.

We use the Identity & Asset Master as the central anchor:

```text
                         Identity
                            │
             ┌──────────────┼──────────────┐
             │              │              │
             ▼              ▼              ▼
            IAM          Endpoint       Firewall
```

The current relationship-quality results are:

| Relationship | Result | Assessment |
|---|---:|---|
| IAM → Identity by `user_id` | 100.00% | Strong |
| IAM → Identity by hostname | 94.60% | Strong |
| IAM → Identity by `device_id` | 82.25% | Moderate |
| IAM user + hostname consistency | 94.60% | Strong |
| Endpoint → Identity by `user_id` | 100.00% | Strong |
| Endpoint → Identity by hostname | 93.59% | Strong |
| Endpoint user + hostname consistency | 85.68% | Moderate |
| Firewall → Identity by hostname | 94.41% | Strong |

The full relationship evidence is available under `reports/join_quality/`.

---

# 5. IAM ↔ Firewall session reconciliation

We specifically checked whether a shared `session_id` was reliable enough to join IAM and firewall activity directly.

It was not.

There were **303 shared sessions**. When we reconciled the available hostname and timestamp evidence:

```text
Hostname-consistent : 0
Hostname-inconsistent: 248
No hostname evidence : 55
Within ±60 minutes   : 0
```

The IAM ↔ Firewall session relationship was therefore **rejected for analytical joining**.

This is intentional. A shared identifier by itself is not enough evidence to claim that two security events describe the same activity. Using a weak join here would have created false correlations in the threat analytics.

Instead, the production model uses the stronger identity-centred relationships described above.

---

# 6. User risk scoring

The risk engine gives each user a score from **0 to 100**. It is meant for investigation prioritization, not as a probability that an account has been compromised.

The score combines several dimensions:

| Dimension | Maximum contribution |
|---|---:|
| Authentication | 20 |
| IAM risk | 20 |
| Endpoint severity | 20 |
| Threat behaviour | 30 |
| Context | 15 |
| Cross-signal bonus | 10 |

The final score is capped at 100.

### Risk bands

```text
0–39    Low
40–59   Medium
60–79   High
80–100  Critical
```

### Current production distribution

| Risk band | Users | Percentage |
|---|---:|---:|
| Low | 1,474 | 49.13% |
| Medium | 1,329 | 44.30% |
| High | 186 | 6.20% |
| Critical | 11 | 0.37% |
| **Total** | **3,000** | **100%** |

That gives us **197 High/Critical users** for closer attention.

The score is a triage mechanism. A high score should lead an analyst to the underlying evidence rather than being treated as proof of malicious behaviour.

---

# 7. Threat detection

Risk scoring tells us which users look concerning overall. Threat detection answers a different question: **what specific behaviour caused concern?**

The production detector uses temporal correlation for scenarios where unrelated events could otherwise be incorrectly combined.

### Post-Termination Activity

Flags IAM or endpoint activity associated with a user after the recorded termination date.

This is an investigation signal, not automatic proof of malicious activity. Possible explanations include delayed telemetry, stale mappings, service accounts, shared credentials or asset reassignment.

### Potential Credential Compromise

The production rule requires all of the following to occur within a common 24-hour window:

```text
≥ 3 failed authentications
        +
≥ 2 MFA failures
        +
≥ 1 credential-related endpoint alert
```

The current production dataset has **0 detections** for this scenario. That is expected from the conservative common-window rule.

### Malware + Lateral Movement

Looks for malware activity and lateral-movement activity within a 24-hour window. Same-host evidence receives stronger confidence than same-user evidence across different hosts.

### Suspicious Administrative Activity

Combines suspicious administrative IAM behaviour with relevant endpoint activity, again giving more weight to same-host activity within the 24-hour window.

### Identity / Hostname Mismatch

Flags repeated telemetry relationships where the observed hostname does not agree with the canonical identity/asset mapping.

---

# 8. Threat results

Current production output contains:

```text
Total detections : 742
Affected users   : 693
```

| Threat type | Detections |
|---|---:|
| Post-Termination Activity | 367 |
| Identity / Hostname Mismatch | 216 |
| Suspicious Administrative Activity | 119 |
| Malware + Lateral Movement | 40 |
| Potential Credential Compromise | 0 |
| **Total** | **742** |

### Severity

| Severity | Detections |
|---|---:|
| Critical | 399 |
| High | 127 |
| Medium | 216 |
| **Total** | **742** |

---

# 9. Corroboration and investigation queue

We did not want the risk score and threat detections to live as two unrelated outputs.

The corroboration layer combines:

- User risk score
- Threat detections
- Number of distinct threat types
- Critical/high/medium detection counts
- Detection confidence
- Identity context
- Device conflict information

This creates the final investigation queue.

Current queue:

```text
693 users
```

| Investigation priority | Users |
|---|---:|
| Critical | 7 |
| High | 52 |
| Medium | 204 |
| Low | 430 |
| **Total** | **693** |

The queue is intended to answer a practical SOC question: **who should an analyst look at first, and why?**

---

# 10. Reproducible pipeline

The full data pipeline is orchestrated by `run_pipeline.py` at the repository root.

It runs the stages in dependency order:

```text
Identity cleaning
      ↓
IAM cleaning
      ↓
Endpoint cleaning
      ↓
Firewall cleaning
      ↓
Relationship validation
      ↓
Risk analytics
      ↓
Threat detection
      ↓
Corroboration
```

The runner also checks that the expected production outputs were created.

## Run the pipeline

From the repository root, install the data-processing dependencies:

```bash
pip install pandas numpy openpyxl
```

Then run:

```bash
python run_pipeline.py
```

The raw input files expected by the pipeline are already under `data/raw/`.

The generated outputs are written to:

```text
data/processed/
data/analytics/
reports/data_quality/
reports/join_quality/
reports/analytics/
```

---

# 11. Dashboard

The project includes a local SOC Command Center built with React/Vite and a small FastAPI backend.

The dashboard is read-only with respect to the committed analytics data. It reads the investigation queue, threat detections and risk scores produced by the pipeline.

### Start the backend

From the repository root:

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\pip install -r backend\requirements.txt
.\.venv\Scripts\python -m uvicorn backend.main:app --reload --port 8000
```

### Start the frontend

In a second terminal:

```bash
cd dashboard
npm install
npm run dev
```

Then open the local Vite address shown in the terminal, normally:

```text
http://localhost:5173
```

The backend exposes:

```text
GET  /api/health
GET  /api/snapshot
POST /api/analyst/query
GET  /api/investigate/{user_id}
```

---

# 12. AI analyst layer

The AI layer sits on top of the deterministic pipeline rather than replacing it.

The agent can use the committed risk, threat, identity, IAM, endpoint and firewall evidence to investigate a user and explain the reason for the priority.

The intended flow is:

```text
Detect
  ↓
Corroborate
  ↓
Investigate
  ↓
Explain
```

The important guardrail is that the agent should not turn a risk score into a claim that a person is malicious. Its job is to bring the evidence together, build an understandable investigation view, and suggest reasonable next steps.

---

# 13. Why some relationships are rejected

A recurring theme in this project is **not forcing the data to say more than it actually says**.

For example, the IAM ↔ Firewall session analysis produced only 303 shared sessions and none had matching hostname evidence plus a timestamp within the chosen 60-minute window. Rather than inventing a fuzzy join, we rejected that relationship.

The same principle is used with missing fields, conflicting device ownership and post-termination activity.

This makes the final analytics a little more conservative, but it also makes the investigation results easier to defend.

---

# 14. Evidence and outputs

Useful evidence produced by the project includes:

```text
reports/data_quality/
    *_quality_report.csv
    *_pipeline_summary.csv

reports/join_quality/
    relationship_quality_report.csv
    session_relationship_report.csv
    session_hostname_consistency_report.csv
    shared_session_evidence.csv
    ambiguous_devices.csv
    ambiguous_hostnames.csv

reports/analytics/
    risk_band_distribution.csv
    top_100_risk_users.csv
    threat_type_summary.csv
    threat_severity_summary.csv
    investigation_queue_summary.csv
```

The cleaned datasets and analytics outputs are also committed under `data/processed/` and `data/analytics/` so the evaluator can inspect the results directly.

---

# 15. Data dictionary

The column-level definitions for the cleaned datasets are in:

```text
docs/data_dictionary.md
```

The dictionary describes the analytical meaning of the columns, including the validation and quality flags introduced during cleaning.

---

# Final note

The goal of the project was not to make the telemetry look perfect. The goal was to make it **usable without hiding uncertainty**.

Where a relationship was strong, we used it. Where a value was missing, we kept that information. Where a relationship was ambiguous or unsupported, we reported it instead of guessing.

That approach is what the downstream risk, threat and investigation layers are built on.
