# Data Dictionary

This dictionary describes the **cleaned analytical datasets** produced by the Track 2 pipeline. The raw files are preserved separately under `data/raw/`.

A few conventions are used throughout the cleaned data:

- IDs are normalized to a consistent representation where possible.
- Timestamps are parsed into a consistent datetime representation.
- Missing values are kept missing unless there is a safe, explicit transformation.
- Validation flags explain why a value or record may need attention.
- A quality flag does not mean the entire record is unusable; it identifies a condition an analyst should know about.

---

## 1. Identity & Asset Master

File: `data/processed/track2_identity_asset_master_clean.csv`

| Column | Meaning |
|---|---|
| `full_name` | Full name associated with the user record. |
| `role` | User's recorded job role. |
| `user_id` | Canonical employee/user identifier used to connect telemetry to a person/account. |
| `department` | Department associated with the user. |
| `location` | Recorded user/work location. |
| `status` | Current employment/account status from the identity source. |
| `hire_date` | Parsed date on which the user joined. |
| `termination_date` | Parsed termination date when one is available. |
| `username` | Normalized account username. |
| `hostname` | Normalized hostname assigned to the user/asset. |
| `device_id` | Normalized device identifier associated with the user. |
| `manager_username` | Username of the user's recorded manager. |
| `device_id_conflict` | Indicates that the device identifier is associated with conflicting user assignments. |
| `device_user_count` | Number of distinct users associated with the device identifier in the cleaned identity data. |

### Identity-specific cleaning notes

`user_id`, `username`, hostname and device identifiers are normalized before relationship checks. Hostnames are standardized so casing and underscore differences do not create artificial mismatches.

Device conflicts are retained rather than silently choosing one owner.

---

## 2. IAM Audit Trail

File: `data/processed/track2_iam_audit_trail_clean.csv`

| Column | Meaning |
|---|---|
| `event_id` | Unique identifier for the IAM event. |
| `timestamp` | Parsed timestamp at which the IAM event was recorded. |
| `user_id` | Canonical user identifier associated with the event. |
| `username` | Username recorded for the event, normalized for consistency. |
| `department` | Department value carried by the IAM record. |
| `event_type` | Type of IAM activity represented by the event. |
| `auth_method` | Authentication method used for the event. |
| `source_ip` | Source IP address associated with the IAM event. |
| `ip_status` | Validation status of the source IP address. |
| `hostname` | Hostname associated with the IAM event. |
| `device_id` | Device identifier associated with the IAM event. |
| `session_id` | Canonicalized session identifier from the IAM event. |
| `mfa_passed` | Normalized indication of whether MFA was passed. |
| `failure_reason` | Reason recorded when an authentication/action failed. |
| `risk_score` | Numeric risk value present in the IAM source after normalization. |
| `risk_level` | Normalized categorical risk level associated with the IAM record. |
| `geo_location` | Geographic location information recorded by the IAM source. |

### IAM-specific cleaning notes

User IDs, hostnames, device IDs and session IDs are normalized so that formatting differences do not prevent valid comparisons. Invalid IP addresses are not passed forward as if they were valid network identifiers.

The IAM-to-Identity relationship is evaluated separately in `reports/join_quality/` rather than enriching IAM records inside the cleaner.

---

## 3. Endpoint Alerts

File: `data/processed/track2_endpoint_alerts_clean.csv`

| Column | Meaning |
|---|---|
| `alert_id` | Identifier of the endpoint alert. |
| `detected_timestamp` | Parsed time at which the endpoint alert was detected. |
| `resolved_timestamp` | Parsed time at which the alert was resolved, when available. |
| `hostname` | Normalized hostname associated with the alert. |
| `hostname_join_key` | Normalized hostname key used for relationship matching. |
| `user_id` | Canonical user identifier associated with the alert. |
| `endpoint_product` | Endpoint security product/source that generated the alert. |
| `alert_name` | Name/type of the endpoint alert. |
| `severity` | Normalized alert severity. |
| `status` | Normalized operational status of the alert. |
| `description` | Human-readable description supplied by the endpoint source. |
| `file_path` | File path associated with the alert, when present. |
| `process_name` | Process associated with the alert, when present. |
| `sha256` | SHA-256 value associated with the alert, when present and accepted as a field value. |
| `assigned_to` | Analyst/person or queue assigned to the alert, when available. |
| `device_criticality` | Normalized criticality of the affected device. |
| `duplicate_alert_id_flag` | Indicates an alert ID duplication condition detected during validation. |
| `duplicate_alert_id_different_content_flag` | Indicates duplicate alert IDs were associated with different record content. |
| `missing_user_id_flag` | Indicates that the user ID was missing. |
| `missing_hostname_flag` | Indicates that the hostname was missing. |
| `missing_detected_timestamp_flag` | Indicates that the detected timestamp was missing. |
| `invalid_detected_timestamp_flag` | Indicates that the detected timestamp could not be interpreted as a valid timestamp. |
| `missing_resolved_timestamp_flag` | Indicates that the resolved timestamp was missing. |
| `invalid_resolved_timestamp_flag` | Indicates that the resolved timestamp was present but invalid/unparseable. |
| `impossible_resolution_flag` | Indicates that the resolution timing is logically inconsistent, such as a resolution preceding detection. |
| `unresolved_alert_flag` | Indicates that the alert remains unresolved according to the source state. |
| `resolved_without_timestamp_flag` | Indicates a resolved state without a usable resolution timestamp. |
| `unresolved_with_resolution_timestamp_flag` | Indicates an unresolved state that nevertheless contains a resolution timestamp. |
| `unmapped_severity_flag` | Indicates that the original severity could not be mapped to the canonical severity categories. |
| `unmapped_status_flag` | Indicates that the original status could not be mapped to the canonical status categories. |
| `unmapped_criticality_flag` | Indicates that the device criticality value could not be mapped to the canonical categories. |
| `sha256_valid_flag` | Indicates whether the supplied SHA-256 value passed validation. |
| `sha256_missing_flag` | Indicates that the SHA-256 value was not supplied. This is a completeness signal, not automatically an invalid-hash finding. |
| `invalid_sha256_flag` | Indicates that a supplied SHA-256 value failed validation. |
| `sha256_validation_status` | Human-readable classification of the SHA-256 validation result. |
| `data_quality_issue_count` | Number of quality conditions detected for the endpoint record. |
| `data_quality_status` | Overall data-quality status derived from the validation flags. |

### Endpoint-specific cleaning notes

The endpoint pipeline deliberately distinguishes **missing** telemetry from **invalid** telemetry. For example, a missing SHA-256 is different from a SHA-256 value that is present but malformed.

The quality flags are retained so an analyst can trace why a record was considered clean, reviewable or problematic.

---

## 4. Firewall Logs

File: `data/processed/track2_firewall_logs_clean.csv`

| Column | Meaning |
|---|---|
| `log_id` | Identifier for the firewall log record. |
| `timestamp` | Parsed timestamp of the firewall event. |
| `hostname` | Normalized hostname associated with the network event. |
| `src_ip` | Validated source IP address when available. |
| `dst_ip` | Validated destination IP address when available. |
| `src_port` | Validated source port when available. |
| `dst_port` | Validated destination port when available. |
| `protocol` | Canonicalized network protocol, such as TCP, UDP or ICMP. |
| `action` | Canonicalized firewall action, such as ALLOW or DENY. |
| `bytes_sent` | Validated bytes sent value. |
| `bytes_received` | Validated bytes received value. |
| `session_id` | Canonicalized firewall session identifier. |
| `threat_flag` | Normalized indication that the firewall source marked the event as threat-related. |
| `rule_name` | Firewall rule associated with the event. |
| `geo_country` | Geographic country information associated with the event. |
| `hostname_join_key` | Normalized hostname key used when comparing the firewall record with identity data. |
| `src_ip_valid` | Indicates whether the source IP passed validation. |
| `dst_ip_valid` | Indicates whether the destination IP passed validation. |
| `src_port_status` | Validation status of the source port. |
| `dst_port_status` | Validation status of the destination port. |
| `bytes_sent_status` | Validation status of the bytes-sent field. |
| `bytes_received_status` | Validation status of the bytes-received field. |

### Firewall-specific cleaning notes

Timestamp parsing supports the formats present in the source data. IPs and ports are validated instead of being treated as trustworthy strings simply because a value is present.

`hostname_join_key` is a relationship helper. It does not replace the analytical hostname field.

---

## 5. Analytics outputs

### User risk scores

File: `data/analytics/user_risk_scores.csv`

The risk output contains identity context, telemetry counts and the components used to construct the final user score.

| Column/group | Meaning |
|---|---|
| `user_id`, `username`, `department`, `role`, `status` | User identity context used in the investigation view. |
| `hostname_count`, `device_count` | Number of associated hosts/devices observed in the analytical context. |
| `iam_events` | Number of IAM events associated with the user. |
| `iam_failed_auth` | Failed authentication count. |
| `iam_mfa_failures` | MFA failure count. |
| `iam_high_risk_events` | Number of IAM events classified as high risk. |
| `iam_avg_risk_score` | Average IAM risk score for the user. |
| `iam_max_risk_score` | Maximum IAM risk score observed for the user. |
| `iam_hostname_count` | Number of hostnames observed in IAM telemetry for the user. |
| `iam_session_count` | Number of IAM sessions associated with the user. |
| `endpoint_alerts` | Endpoint alert count. |
| `endpoint_critical_alerts` | Critical endpoint alert count. |
| `endpoint_high_alerts` | High-severity endpoint alert count. |
| `endpoint_unresolved_critical` | Unresolved critical endpoint alert count. |
| `endpoint_malware_alerts` | Malware-related endpoint alert count. |
| `endpoint_credential_alerts` | Credential-related endpoint alert count. |
| `endpoint_lateral_movement` | Lateral-movement endpoint alert count. |
| `endpoint_powershell` | PowerShell-related endpoint alert count. |
| `endpoint_tampering` | Tampering-related endpoint alert count. |
| `endpoint_usb` | USB-related endpoint alert count. |
| `endpoint_impossible_resolution` | Count of endpoint alerts with impossible resolution timing. |
| `endpoint_hostname_count` | Number of hostnames observed in endpoint telemetry. |
| `termination_date` | Canonical termination date from the identity context. |
| `post_termination_iam_events` | IAM events observed after the recorded termination date. |
| `post_termination_endpoint_events` | Endpoint events observed after the recorded termination date. |
| `post_termination_activity` | Combined post-termination activity count. |
| `post_termination_activity_flag` | Indicates whether post-termination activity was observed. |
| `authentication_risk` | Risk contribution from authentication behaviour. |
| `iam_risk` | Risk contribution from IAM behaviour. |
| `endpoint_severity_risk` | Risk contribution from endpoint severity. |
| `threat_behavior_risk` | Risk contribution from threat-related behaviour. |
| `contextual_risk` | Context-related risk contribution. |
| `cross_signal_bonus` | Additional contribution when independent signals corroborate one another. |
| `risk_score` | Final user-level risk score, capped at 100. |
| `risk_level` | Categorical risk level corresponding to the final score. |
| `risk_band` | Dashboard/triage risk band: Low, Medium, High or Critical. |
| `risk_drivers` | Human-readable summary of the main factors contributing to the user's score. |

---

### Threat detections

File: `data/analytics/threat_detections.csv`

| Column | Meaning |
|---|---|
| `threat_id` | Identifier for the generated detection. |
| `user_id` | User associated with the detection. |
| `threat_type` | Security scenario detected by the rule engine. |
| `severity` | Severity assigned to the detection. |
| `confidence` | Confidence level based on the supporting evidence and correlation strength. |
| `evidence` | Human-readable evidence explaining the detection. |
| `first_observed` | Earliest event time supporting the detection. |
| `last_observed` | Latest event time supporting the detection. |
| `related_hostname` | Hostname relevant to the detection when available. |
| `related_alert_count` | Number of supporting endpoint/security alerts associated with the detection. |
| `recommended_action` | Suggested analyst follow-up for the detection. |

Current production threat types are:

- Post-Termination Activity
- Identity / Hostname Mismatch
- Suspicious Administrative Activity
- Malware + Lateral Movement

The potential credential-compromise rule exists in the detector but currently produces zero production detections because it requires all qualifying signals to fall inside the same common 24-hour window.

---

### Investigation queue

File: `data/analytics/investigation_queue.csv`

| Column | Meaning |
|---|---|
| `priority_rank` | Rank of the user in the investigation queue. |
| `user_id` | User being prioritized for investigation. |
| `full_name` | User's full name from identity context. |
| `department` | User department. |
| `role` | User role. |
| `status` | User/account status. |
| `location` | User location. |
| `hostname` | Canonical/primary hostname shown for investigation. |
| `device_id` | Canonical/primary device identifier shown for investigation. |
| `risk_score` | User-level risk score. |
| `risk_level` | Risk category associated with the score. |
| `investigation_priority_score` | Combined score used to prioritize the investigation queue. |
| `investigation_priority` | Final queue category: Critical, High, Medium or Low. |
| `threat_detection_count` | Number of detections associated with the user. |
| `distinct_threat_types` | Number of different threat scenarios associated with the user. |
| `threat_types` | Names of the threat scenarios associated with the user. |
| `critical_detections` | Number of critical detections for the user. |
| `high_detections` | Number of high detections for the user. |
| `medium_detections` | Number of medium detections for the user. |
| `highest_severity` | Highest detection severity associated with the user. |
| `highest_confidence` | Highest detection confidence associated with the user. |
| `device_id_conflict` | Whether the user's identity context contains a device ownership conflict. |
| `device_user_count` | Number of users associated with the relevant device ID. |
| `investigation_reason` | Short explanation for why the user was placed in the queue. |
| `recommended_action` | Suggested next step for an analyst. |

---

## 6. Supporting reports

The `reports/` directory contains supporting evidence rather than replacing the cleaned data.

### Data quality reports

`reports/data_quality/` contains per-source quality reports and pipeline summaries covering missing values, invalid values, duplicate removal and validation outcomes.

### Relationship reports

`reports/join_quality/` contains:

- `relationship_quality_report.csv` — relationship coverage and consistency results.
- `session_relationship_report.csv` — IAM ↔ Firewall session reconciliation.
- `session_hostname_consistency_report.csv` — hostname evidence for shared sessions.
- `shared_session_evidence.csv` — detailed evidence for shared sessions.
- `ambiguous_devices.csv` — device relationships that require caution.
- `ambiguous_hostnames.csv` — hostname relationships that require caution.

### Analytics summaries

`reports/analytics/` contains risk-band, threat-type, threat-severity and investigation-queue summaries used by the dashboard and for review.

---

## 7. Important interpretation notes

### Missing does not mean malicious

A missing field is a data-quality condition. It should not automatically become a security finding.

### Post-termination activity does not prove user intent

It means telemetry associated with the user ID was observed after the recorded termination date. Delayed logging, stale mappings, service accounts, shared credentials and asset reassignment are possible explanations.

### Risk score is not probability

The 0–100 score is a triage score designed to help analysts decide where to look first.

### Relationship strength matters

The project intentionally rejects weak cross-source relationships rather than filling gaps with fuzzy assumptions. In particular, the IAM ↔ Firewall session relationship is not used as an analytical join because its supporting hostname and timestamp evidence was insufficient.
