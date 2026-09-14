# AgentIQ Datathon — Zero-Trust Telemetry & Insider Threat Detection

A cybersecurity analytics pipeline for detecting suspicious user activity and insider-threat signals across **IAM audit logs, endpoint alerts, firewall telemetry, and identity/asset records**.

The project follows a production-oriented approach: raw telemetry is preserved, datasets are cleaned and validated independently, relationships are measured before joining, and risk/threat analytics are generated from trusted signals.

---

## Problem Statement

Modern enterprise security environments generate telemetry across multiple systems. Individually, these sources provide only partial visibility into user and device activity.

This project builds a unified analytical layer across:

- Identity & Asset Master
- IAM Audit Trail
- Endpoint Alerts
- Firewall Logs

The objective is to identify users and activities that require security investigation while explicitly accounting for:

- Missing and malformed telemetry
- Duplicate records
- Inconsistent identifiers
- Ambiguous identity relationships
- Weak cross-source relationships
- Temporal relationships between security events

The resulting system produces:

- User-level risk scores
- Threat detections
- Cross-signal corroboration
- A prioritized investigation queue
- An executive/analyst security dashboard

---

# Architecture

```text
                         ┌─────────────────────┐
                         │     Raw Telemetry   │
                         └──────────┬──────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
       Identity Master         IAM Audit Trail      Endpoint Alerts
              │                     │                     │
              │                     │                     │
              └──────────────┬──────┴──────────────┬──────┘
                             │                     │
                             ▼                     ▼
                    Cleaning & Validation    Cleaning & Validation
                             │                     │
                             └──────────┬──────────┘
                                        │
                              ┌─────────▼─────────┐
                              │ Relationship      │
                              │ Validation        │
                              │                   │
                              │ Identity ↔ IAM    │
                              │ Identity ↔ E.P.   │
                              │ Identity ↔ FW     │
                              └─────────┬─────────┘
                                        │
                         ┌──────────────┴──────────────┐
                         │                             │
                         ▼                             ▼
                  Risk Analytics                Threat Detection
                         │                             │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                              Corroboration Layer
                                        │
                                        ▼
                              Investigation Queue
                                        │
                                        ▼
                                  Dashboard
```

---

# Repository Structure

```text
Datathon/
│
├── README.md
├── requirements.txt
├── .gitignore
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
│   │   ├── schema.py
│   │   ├── quality.py
│   │   └── relationships.py
│   │
│   ├── analytics/
│   │   ├── risk.py
│   │   ├── threat.py
│   │   └── corroboration.py
│   │
│   └── utils/
│       ├── ids.py
│       ├── timestamps.py
│       └── logging.py
│
├── pipeline/
│   └── run_pipeline.py
│
├── reports/
│   ├── data_quality/
│   ├── join_quality/
│   └── analytics/
│
├── dashboard/
│
├── agent/
│
└── docs/
    ├── data_dictionary.md
    ├── architecture.md
    └── metric_definitions.md
```

---

# 1. Data Sources

The project works with four telemetry sources.

| Dataset | Purpose |
|---|---|
| Identity & Asset Master | Canonical user, device and asset relationships |
| IAM Audit Trail | Authentication and identity activity |
| Endpoint Alerts | Endpoint security events and malware-related activity |
| Firewall Logs | Network activity and threat telemetry |

The **Identity & Asset Master** is treated as the canonical identity/asset anchor for downstream relationships.

---

# 2. Data Rescue & Cleaning

Raw datasets are preserved and are never overwritten.

Each source has an independent cleaning module under:

```text
src/cleaning/
```

The objective is to convert inconsistent raw telemetry into canonical analytical datasets while preserving uncertainty through explicit quality flags.

---

## Identity & Asset Master

The identity pipeline performs:

- Exact duplicate removal
- `user_id` normalization
- Username normalization
- Department normalization
- Location normalization
- Status normalization
- Date parsing
- Hostname normalization
- Device identifier normalization
- Device ownership conflict detection

### Dataset Size

```text
Raw records              : 3,090
Exact duplicate records  : 90
Clean records            : 3,000
```

The final dataset contains explicit indicators for conflicting device assignments.

The Identity & Asset Master is used as the canonical reference for connecting users, hosts and devices to telemetry.

---

## IAM Audit Trail

The IAM pipeline performs:

- Exact duplicate removal
- Event ID validation
- User ID normalization
- Username normalization
- Timestamp parsing
- Authentication method normalization
- IP validation
- Hostname normalization
- Device ID normalization
- Session ID normalization
- MFA value normalization
- Risk score normalization
- Risk-level standardization
- Failure reason preservation

### Dataset Size

```text
Raw records              : 20,500
Exact duplicate records  : 500
Clean records            : 20,000
```

Duplicate event IDs are checked after deduplication to prevent duplicate security events from propagating into downstream analytics.

---

## Endpoint Alerts

The endpoint pipeline performs:

- Exact duplicate removal
- Alert ID validation
- Timestamp parsing
- Hostname normalization
- User identifier validation
- Severity normalization
- Status normalization
- Device criticality normalization
- SHA-256 validation
- Resolution consistency checks
- Data-quality flag generation

### Dataset Size

```text
Raw records              : 8,240
Exact duplicate records  : 240
Clean records            : 8,000
```

The pipeline distinguishes between:

- Invalid telemetry
- Missing telemetry
- Operational state
- Actual data-quality defects

For example, a missing SHA-256 value is retained as a telemetry completeness issue rather than automatically being treated as an invalid record.

### Endpoint Quality Findings

```text
Missing hostnames       : 481
Impossible resolutions  : 263
Missing SHA-256         : 1,438
Invalid SHA-256         : 799
Rows requiring review   : 5,168
```

Missing SHA-256 values are reported separately from invalid hashes because missing telemetry and malformed telemetry represent different quality conditions.

---

## Firewall Logs

The firewall pipeline performs:

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
- Geographic field preservation

### Dataset Size

```text
Raw records              : 30,600
Exact duplicate records  : 600
Clean records            : 30,000
```

Hostname normalization includes case normalization and conversion of inconsistent underscore usage.

A separate `hostname_join_key` is used for identity relationships so that the `.corp.local` suffix does not prevent otherwise valid matches.

This increased the firewall-to-identity hostname match rate to:

```text
94.41%
```

No user identity is inferred from an unmatched hostname.

---

# 3. Data Quality

Data quality is treated as a first-class part of the pipeline.

The system explicitly tracks:

- Missing values
- Invalid identifiers
- Invalid IP addresses
- Invalid ports
- Invalid timestamps
- Invalid hashes
- Duplicate records
- Conflicting device ownership
- Impossible timestamp relationships
- Unresolved endpoint alerts
- Ambiguous relationships
- Join coverage
- Cross-source consistency

Missing values are **not blindly imputed**.

When information is unavailable, the pipeline preserves the missingness and records the appropriate quality flag.

This prevents artificial certainty from entering the security analytics layer.

---

# 4. Relationship Validation

Datasets are **not blindly joined**.

Before using a relationship for analytics, its coverage and consistency are measured.

The primary architecture is:

```text
                         Identity
                            │
             ┌──────────────┼──────────────┐
             │              │              │
             ▼              ▼              ▼
            IAM          Endpoint       Firewall
```

This makes the Identity & Asset Master the canonical identity/asset anchor.

---

## Relationship Quality

| Relationship | Coverage / Consistency | Assessment |
|---|---:|---|
| IAM → Identity by `user_id` | 92.49% | Strong |
| IAM → Identity by hostname | 94.60% | Strong |
| IAM → Identity by `device_id` | 82.25% | Moderate |
| IAM user + hostname consistency | 88.14% | Moderate |
| Endpoint → Identity by `user_id` | 92.16% | Strong |
| Endpoint → Identity by hostname | 93.59% | Strong |
| Endpoint user + hostname consistency | 79.37% | Moderate |
| Firewall → Identity by hostname | 94.41% | Strong |

These measurements are retained in relationship-quality reports rather than hidden during preprocessing.

---

# 5. IAM ↔ Firewall Session Reconciliation

The presence of a shared `session_id` does not automatically mean that IAM and firewall records describe the same activity.

A dedicated reconciliation analysis was therefore performed.

### Session Counts

```text
IAM unique sessions       : 11,452
Firewall unique sessions  : 25,133
Shared sessions           : 303
```

For the 303 shared sessions:

```text
Hostname-consistent       : 0
Hostname-inconsistent     : 248
No hostname evidence      : 55
Within ±60 minutes        : 0
```

The timestamp evidence also showed large temporal differences between shared-session records.

### Decision

```text
IAM ↔ Firewall session relationship
             ↓
          REJECTED
```

The session relationship is therefore **not used as an analytical join**.

This is an intentional data-quality decision.

Rather than forcing a weak relationship into the model, the system relies on the stronger:

```text
Identity ↔ IAM
Identity ↔ Endpoint
Identity ↔ Firewall
```

relationships.

This reduces the risk of false correlations contaminating downstream threat analytics.

---

# 6. Risk Analytics

The risk engine produces a user-level score from:

```text
0–100
```

The score is designed for **security triage and prioritization**, not as a probability of compromise.

The model uses multiple dimensions instead of allowing a single noisy signal to dominate the result.

---

## Risk Dimensions

| Dimension | Maximum Contribution |
|---|---:|
| Authentication | 20 |
| IAM Risk | 20 |
| Endpoint Severity | 20 |
| Threat Behaviour | 30 |
| Context | 15 |
| Cross-Signal Bonus | 10 |

The final score is capped at:

```text
100
```

---

## Risk Bands

```text
0–39      Low
40–59     Medium
60–79     High
80–100    Critical
```

---

## Current Risk Distribution

| Risk Band | Users | Percentage |
|---|---:|---:|
| Low | 1,591 | 53.03% |
| Medium | 1,224 | 40.80% |
| High | 174 | 5.80% |
| Critical | 11 | 0.37% |
| **Total** | **3,000** | **100%** |

Therefore:

```text
High + Critical users = 185
Percentage             = 6.17%
```

This narrows the population requiring immediate attention compared with investigating every user or every telemetry event equally.

---

# 7. Threat Detection

The threat detection layer identifies concrete security scenarios.

Unlike the risk model, threat detections are event-oriented and provide an explanation for why a user or activity was flagged.

The production detector uses temporal correlation where appropriate to reduce false positives from unrelated events occurring far apart in time.

---

## Threat Scenario 1 — Post-Termination Activity

Detects IAM or endpoint activity occurring after the recorded termination date of a user.

The detector uses the actual telemetry timestamps and the Identity & Asset Master termination date.

A post-termination event is treated as a security investigation signal.

It does **not** automatically imply malicious activity.

Possible explanations include:

- Stale identity mappings
- Service accounts
- Delayed telemetry
- Shared credentials
- Asset reassignment
- Logging inconsistencies

---

## Threat Scenario 2 — Potential Credential Compromise

The production rule requires multiple signals to occur within a common 24-hour window:

```text
≥ 3 failed authentications
        +
≥ 2 MFA failures
        +
≥ 1 credential-related endpoint alert
```

The common-window requirement prevents events that merely occur somewhere within the dataset lifetime from being incorrectly interpreted as one coordinated attack.

---

## Threat Scenario 3 — Malware + Lateral Movement

The detector looks for:

```text
Malware activity
        +
Lateral movement activity
```

within a 24-hour temporal window.

Same-host correlation receives stronger confidence than same-user correlation across different hosts.

This creates a hierarchy of evidence rather than treating all relationships equally.

---

## Threat Scenario 4 — Suspicious Administrative Activity

The detector combines suspicious administrative IAM behaviour with relevant endpoint activity.

The production rule prioritizes temporal correlation:

```text
Same host + within 24 hours
        ↓
Higher confidence

Same user + within 24 hours
        ↓
Moderate supporting evidence
```

Lifetime co-occurrence without temporal support is not treated as a confirmed scenario.

---

## Threat Scenario 5 — Identity / Hostname Mismatch

Detects telemetry where the observed user-host relationship conflicts with the canonical Identity & Asset Master relationship.

This is treated as an investigation signal rather than automatic proof of compromise.

---

# 8. Threat Detection Results

Current production output:

```text
Total detections : 742
Affected users   : 693
```

### Detection Breakdown

| Threat Type | Detections |
|---|---:|
| Post-Termination Activity | 367 |
| Identity / Hostname Mismatch | 216 |
| Suspicious Administrative Activity | 119 |
| Malware + Lateral Movement | 40 |
| Potential Credential Compromise | 0 |
| **Total** | **742** |

### Severity Distribution

| Severity | Detections |
|---|---:|
| Critical | 399 |
| High | 127 |
| Medium | 216 |
| **Total** | **742** |

The zero result for Potential Credential Compromise is intentional.

The detector is deliberately conservative and requires all required signals to occur within the same common temporal window rather than relying on lifetime event intersections.

---

# 9. Corroboration Layer

Risk scoring and threat detection answer different questions.

### Risk score

> How much overall security concern is associated with this user?

### Threat detection

> What specific suspicious behaviour was observed?

The corroboration layer combines both.

For each user, it considers:

- Risk score
- Threat detections
- Number of distinct threat types
- Critical detection count
- Detection confidence
- Identity context

This produces a prioritized **investigation queue**.

---

# 10. Investigation Queue

Current queue:

```text
693 users
```

### Priority Distribution

| Priority | Users |
|---|---:|
| Critical | 7 |
| High | 52 |
| Medium | 204 |
| Low | 430 |
| **Total** | **693** |

The queue allows analysts to move from a large telemetry population to a focused set of users requiring investigation.

The intended workflow is:

```text
Enterprise
    ↓
Risk Population
    ↓
Threat Category
    ↓
Priority Queue
    ↓
Individual User
    ↓
Supporting Evidence
```

---

# 11. Example High-Risk Users

The risk and corroboration layers surface users with combinations of multiple independent security signals.

For example, one high-priority user can simultaneously exhibit:

- Multiple failed authentications
- MFA failures
- High-risk IAM events
- Malware detections
- Credential-access activity
- Lateral-movement signals
- Critical endpoint alerts
- Post-termination activity

The system therefore does not depend on a single alert.

It prioritizes **corroborated evidence across telemetry sources**.

---

# 12. Analytical Caveats

## Post-Termination Activity

A post-termination event means:

> Telemetry contains activity associated with the user's identity after the recorded termination date.

It does not prove that:

- The employee personally performed the activity
- The credentials were used maliciously
- The identity mapping is still valid

The signal should therefore trigger investigation rather than automatic attribution.

---

## Risk Score

The risk score is a triage mechanism.

It is not:

- A probability of compromise
- A formal incident severity classification
- A replacement for analyst investigation

The score is intended to help security teams decide where to look first.

---

## Identity / Hostname Mismatch

A mismatch indicates an inconsistency between telemetry and the canonical identity/asset relationship.

Potential causes include:

- Device reassignment
- Shared devices
- Stale mappings
- Identity synchronization issues
- Data-quality problems
- Potential unauthorized activity

Therefore, the detector should be interpreted as an investigation signal.

---

## Rejected Session Relationship

The IAM ↔ Firewall session relationship was rejected because shared session IDs lacked supporting hostname and temporal evidence.

This decision is intentional.

A weak relationship is more dangerous than an explicitly unresolved relationship because an incorrect join can create false attack narratives.

---

# 13. Reproducibility

Install the project dependencies:

```bash
pip install -r requirements.txt
```

Run the complete pipeline:

```bash
python pipeline/run_pipeline.py
```

The pipeline is structured into separate stages for:

```text
Cleaning
    ↓
Validation
    ↓
Relationship Analysis
    ↓
Risk Analytics
    ↓
Threat Detection
    ↓
Corroboration
```

Individual modules can also be executed independently when debugging or developing a specific layer.

---

# 14. Output Files

## Processed Data

Located under:

```text
data/processed/
```

Contains canonical cleaned datasets.

---

## Analytics

Located under:

```text
data/analytics/
```

Contains:

```text
user_risk_scores.csv
threat_detections.csv
investigation_queue.csv
```

---

## Data Quality Reports

Located under:

```text
reports/data_quality/
```

These reports provide evidence for:

- Duplicate removal
- Missing values
- Invalid values
- Validation results
- Cleaning decisions

---

## Relationship Reports

Located under:

```text
reports/join_quality/
```

These include:

- Relationship quality
- Join coverage
- Ambiguous hostnames
- Ambiguous devices
- Session reconciliation
- Shared-session evidence

---

## Analytics Reports

Located under:

```text
reports/analytics/
```

These include:

- Risk band distribution
- Top risk users
- Investigation queue summary

---

# 15. Data Lineage

The project maintains a clear separation between raw, processed and analytical data.

```text
data/raw/
    │
    │  Source telemetry
    ▼
src/cleaning/
    │
    │  Canonicalization
    ▼
data/processed/
    │
    │
    ├───────────────► src/validation/
    │                       │
    │                       ▼
    │                reports/join_quality/
    │
    ▼
src/analytics/
    │
    ├──────────────► Risk Analytics
    │
    ├──────────────► Threat Detection
    │
    └──────────────► Corroboration
                            │
                            ▼
                     data/analytics/
```

This separation ensures that analytical transformations can be traced back to cleaned source data.

---

# 16. Key Design Principles

### 1. Preserve Raw Data

Raw telemetry is never overwritten.

### 2. Clean Before Joining

Every source is cleaned independently before relationship analysis.

### 3. Measure Before Joining

Relationships are quantified before being trusted.

### 4. Do Not Invent Identity

Unmatched telemetry is not assigned to users using unsupported assumptions.

### 5. Preserve Uncertainty

Missing and ambiguous information is explicitly represented rather than silently filled.

### 6. Prefer Temporal Evidence

Security events occurring close together in time provide stronger evidence than lifetime co-occurrence.

### 7. Separate Data Quality From Security Risk

A malformed or missing field is not automatically treated as malicious behaviour.

### 8. Use Corroboration

Independent security signals are combined to improve investigation prioritization.

### 9. Reject Weak Relationships

A relationship that cannot be supported by the available evidence should not be forced into the analytical model.

### 10. Optimize for Analyst Action

The final product is not simply a collection of alerts.

It is a prioritized investigation workflow.

---

# 17. Dashboard

The dashboard provides an executive and analyst-oriented view of the resulting security intelligence.

The dashboard is designed around the following flow:

```text
Security Overview
        ↓
Risk Distribution
        ↓
Threat Landscape
        ↓
Investigation Queue
        ↓
User Investigation
        ↓
Evidence
```

Key dashboard capabilities include:

- Overall security posture
- Risk-band distribution
- High/Critical user identification
- Threat category analysis
- Investigation priority
- Cross-signal corroboration
- User-level evidence
- Data-quality indicators

The goal is to allow an analyst to move from a high-level security overview to the evidence behind an individual investigation.

---

# 18. Future / Bonus Layer

The repository also provides a foundation for an agentic security investigation layer.

The potential agent workflow is:

```text
Analyst Question
       ↓
Investigation Agent
       ↓
Risk + Threat + Identity Context
       ↓
Relevant Evidence
       ↓
Investigation Summary
       ↓
Recommended Next Action
```

Potential use cases include:

- "Why is this user high risk?"
- "Show the evidence behind this alert."
- "What threat signals are associated with this user?"
- "Which users require immediate investigation?"
- "Are there other users showing similar behaviour?"

The agentic layer should remain grounded in the validated analytical outputs rather than generating unsupported conclusions.

---

# 19. Technology Stack

- Python
- Pandas
- NumPy
- Jupyter / Python analysis
- CSV
- JSON
- Excel
- Git
- GitHub
- Rule-based temporal correlation
- Data-quality validation
- Dashboard layer

---

# 20. Project Outcome

The project transforms heterogeneous cybersecurity telemetry into an evidence-backed security investigation workflow.

```text
┌──────────────────────┐
│     Raw Telemetry    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│    Data Rescue       │
│    & Cleaning        │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Canonical Clean Data │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Relationship         │
│ Validation            │
└──────────┬───────────┘
           │
           ├───────────────┐
           ▼               ▼
┌─────────────────┐ ┌─────────────────┐
│  Risk Analytics │ │ Threat Detection│
└────────┬────────┘ └────────┬────────┘
         │                   │
         └─────────┬─────────┘
                   ▼
        ┌─────────────────────┐
        │    Corroboration     │
        └──────────┬──────────┘
                   │
                   ▼
        ┌─────────────────────┐
        │ Investigation Queue │
        └──────────┬──────────┘
                   │
                   ▼
        ┌─────────────────────┐
        │      Dashboard      │
        └─────────────────────┘
```

The key objective is not to generate more alerts.

It is to:

**reduce noise, preserve uncertainty, validate relationships, correlate meaningful security signals, and prioritize the users and behaviours most deserving of analyst attention.**

---

# Team

Developed for the **TransOrg AgentIQ Datathon — Cybersecurity Track**.

### Team Members

- Adwaid Krishna K
- Madhav Hemakumar
- Ananjay Pampalli
- Aadhil Ajas Kareem

---

## Status

**Core data engineering, validation, risk analytics, threat detection, and corroboration layers completed.**

Dashboard and agentic investigation capabilities are being developed as the final presentation layer.
