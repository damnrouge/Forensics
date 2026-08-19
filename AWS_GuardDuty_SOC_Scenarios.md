# AWS GuardDuty SOC Incident Simulations

## Index

| # | Scenario | GuardDuty Finding | Severity | Coverage |
|---|---|---|---|---|
| 1 | EC2 Command-and-Control Activity | `Backdoor:EC2/C&CActivity.B` | High | Detection → L1 triage → L2 investigation → containment → recovery → communications |

## Scenario 1 — EC2 Command-and-Control Activity

**Finding:** `Backdoor:EC2/C&CActivity.B`

**Scenario:** A production EC2 instance running a Payments API is detected communicating with a suspicious external command-and-control destination. Investigation identifies a malicious process, systemd persistence, abuse of the EC2 instance role, unauthorized S3 access to customer export data, and an attempted internal SSH connection.

**Simulation coverage:**

- GuardDuty finding ingestion and raw alert context
- L1 SOC acknowledgement and initial triage
- EC2 metadata and resource identification
- VPC Flow Log investigation
- CloudTrail investigation
- IAM role and `AssumeRole` analysis
- S3 data-event investigation
- DNS investigation
- Application-log correlation
- Endpoint/process investigation
- Persistence discovery
- Lateral-movement checks
- Data-access and potential exfiltration assessment
- Blast-radius assessment
- Evidence preservation
- EC2 network isolation
- Credential and IAM containment
- C2 infrastructure blocking
- Clean rebuild and recovery
- IOC sweep across the environment
- L1 → L2/IR escalation
- Security-team status update
- Executive summary
- Closure criteria and escalation thresholds

### Scenario Reference

The complete scenario is the production-style simulation covering the lifecycle from GuardDuty detection through incident response and recovery.

### Key Investigation Correlation

```text
GuardDuty
   ↓
VPC Flow Logs
   ↓
CloudTrail
   ↓
S3 Data Events
   ↓
DNS Logs
   ↓
Application Logs
   ↓
Endpoint Telemetry
   ↓
Persistence
   ↓
Credential Abuse
   ↓
Lateral Movement
   ↓
Potential Exfiltration
   ↓
Incident Response
```

## Planned Scenario Categories

This index is structured so additional GuardDuty simulations can be added without changing the document structure. Candidate future scenarios include:

1. EC2 command-and-control activity
2. IAM credentials used from an unusual location
3. S3 bucket access by a suspicious principal
4. EC2 instance communicating with a known malicious IP
5. EC2 instance cryptocurrency-mining activity
6. IAM privilege escalation / suspicious API activity
7. S3 credential exfiltration and anomalous data access
8. EKS/container workload compromise

> Current completed scenarios: **1**
