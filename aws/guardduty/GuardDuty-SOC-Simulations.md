# AWS GuardDuty — End-to-End SOC Incident Simulations

> **Purpose:** Production-style training material for L1/L2 SOC analysts and incident responders investigating Amazon GuardDuty findings across multiple AWS services.
>
> **Source of finding names and service coverage:** [AWS GuardDuty finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html). The AWS documentation identifies active findings by impacted resource and data source; this guide uses five representative active finding types spanning EC2, IAM, S3, Lambda, and RDS. All account IDs, resource IDs, IP addresses, usernames, timestamps, hashes, and metric values in the scenarios are **synthetic training data**.

---

## Index

1. [How to Use This Guide](#how-to-use-this-guide)
2. [SOC Severity and Decision Model](#soc-severity-and-decision-model)
3. [Scenario 1 — EC2 Malware: `Execution:EC2/MaliciousFile`](#scenario-1--ec2-malware-executionec2maliciousfile)
4. [Scenario 2 — IAM Credential Compromise: `CredentialAccess:IAMUser/CompromisedCredentials`](#scenario-2--iam-credential-compromise-credentialaccessiamusercompromisedcredentials)
5. [Scenario 3 — S3 Data Exfiltration: `Exfiltration:S3/AnomalousBehavior`](#scenario-3--s3-data-exfiltration-exfiltrations3anomalousbehavior)
6. [Scenario 4 — Lambda C2: `Backdoor:Lambda/C&CActivity.B`](#scenario-4--lambda-c2-backdoorlambacactivityb)
7. [Scenario 5 — RDS Account Compromise: `CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce`](#scenario-5--rds-account-compromise-credentialaccessrdsanomalousbehaviorsuccessfulbruteforce)
8. [Cross-Scenario Investigation Checklist](#cross-scenario-investigation-checklist)
9. [Containment Decision Matrix](#containment-decision-matrix)
10. [Evidence and Case-Closure Standard](#evidence-and-case-closure-standard)

---

## How to Use This Guide

Each scenario is intentionally self-contained. Treat the finding as the first signal, not the conclusion.

The simulated SOC operates with the following assumptions:

- GuardDuty findings are forwarded to the SIEM and/or case-management platform.
- CloudTrail management events are enabled in all accounts and regions under investigation.
- S3 data events are enabled for protected buckets.
- VPC Flow Logs and Route 53 Resolver query logging are available where applicable.
- Analysts have read-only investigation access and a controlled break-glass role for containment.
- Production containment changes require the normal change/incident approval path unless there is an active threat to confidentiality, integrity, or availability.
- The analyst records all timestamps in UTC and converts to local time only for stakeholder communication.

### Important distinction

A GuardDuty finding is an AWS detection result. The SOC must determine whether it represents:

1. expected administrative or application behavior;
2. suspicious behavior with insufficient evidence of compromise; or
3. confirmed compromise requiring containment and incident response.

Do not close a finding solely because the resource owner says the activity was expected. Validate the actor, source, timing, API actions, resource sensitivity, and surrounding telemetry.

---

## SOC Severity and Decision Model

### Escalate immediately when any of these are true

- Confirmed unauthorized access to a privileged IAM identity.
- Successful authentication from an untrusted or malicious source where the account owner cannot validate it.
- Evidence that credentials were used outside the expected workload, region, ASN, or device context.
- Evidence of data access or exfiltration involving sensitive data.
- Malware or command-and-control activity on a production workload.
- Evidence of persistence, privilege escalation, lateral movement, or defense evasion.
- Evidence that multiple AWS resources/accounts are involved.
- CloudTrail logging, security controls, or public-access controls were disabled by the suspicious actor.

### Contain before the investigation is complete when

- The attacker has an active session or active network connection.
- A credential is demonstrably compromised.
- A workload is making active C2 connections or executing confirmed malware.
- Sensitive data is actively leaving the environment.
- Continued activity can materially increase impact while analysts investigate.

### Prefer monitor/close when

- The activity is fully explained by an approved change, penetration test, vulnerability scanner, backup, deployment, or known workload.
- The identity, source, time, action, and destination all match the approved activity.
- No unauthorized follow-on activity exists.
- The owner and change record are independently verifiable.

---

# Scenario 1 — EC2 Malware: `Execution:EC2/MaliciousFile`

## 1. Scenario Overview

**Service:** Amazon EC2  
**Finding:** `Execution:EC2/MaliciousFile`  
**Severity:** Variable depending on detected threat  
**Threat pattern:** Malware execution on a production EC2 instance  
**Synthetic account:** `482731905614`  
**Region:** `us-east-1`  
**Instance:** `i-0f4a9c21b7d8e63a1`  
**Private IP:** `10.42.17.83`  
**Application:** `payments-api-prod-02`

The AWS finding type is associated with Malware Protection for EC2/EBS. The important SOC question is not simply “is there malware?” but “what executed, how did it arrive, what credentials could it access, and what else did the instance contact?”

## 2. L1 SOC Initial Response

### 2.1 Raw finding delivered to the SOC

```json
{
  "version": "0",
  "id": "f8d9a8e2-5f7b-4e5c-9a91-3b7f6e2d1184",
  "detail-type": "GuardDuty Finding",
  "source": "aws.guardduty",
  "account": "482731905614",
  "time": "2026-08-19T14:02:11Z",
  "region": "us-east-1",
  "detail": {
    "schemaVersion": "2.0",
    "id": "9b6c5d1a7f3e4c2b8d9a0f1e2c3b4a5d",
    "type": "Execution:EC2/MaliciousFile",
    "severity": 8,
    "createdAt": "2026-08-19T14:01:52.000Z",
    "updatedAt": "2026-08-19T14:02:07.000Z",
    "title": "A malicious file was detected on an EC2 instance",
    "description": "A malicious file was detected on EC2 instance i-0f4a9c21b7d8e63a1.",
    "resource": {
      "resourceType": "Instance",
      "instanceDetails": {
        "instanceId": "i-0f4a9c21b7d8e63a1",
        "instanceType": "m6i.large",
        "availabilityZone": "us-east-1b",
        "platform": "AMAZON_LINUX_2023",
        "privateIpAddress": "10.42.17.83",
        "iamInstanceProfile": {
          "arn": "arn:aws:iam::482731905614:instance-profile/payments-api-prod"
        },
        "tags": [
          {"key":"Name","value":"payments-api-prod-02"},
          {"key":"Environment","value":"prod"}
        ]
      }
    },
    "service": {
      "serviceName": "guardduty",
      "detectorId": "12abc3456789def0123456789abcdef0",
      "count": 1,
      "action": {
        "actionType": "AWS_API_CALL"
      }
    }
  }
}
```

### 2.2 Immediate triage questions

L1 answers these in order:

1. **Is the host production or non-production?**  
   The `Environment=prod` tag makes this an immediate high-priority case.
2. **What exactly was detected?**  
   Retrieve the full GuardDuty finding and malware details; identify file path, hash, process context, and detection timestamp.
3. **Is the instance still running?**  
   Active malware requires faster containment than a historical artifact.
4. **What IAM role is attached?**  
   `payments-api-prod` could expose application secrets or AWS permissions.
5. **What network activity occurred around the detection?**  
   Look for C2, download infrastructure, scanning, and unusual outbound volume.
6. **Did the host perform AWS API calls?**  
   A compromised instance role can turn an endpoint incident into an AWS control-plane incident.
7. **Is there evidence of persistence?**  
   Check user-data changes, systemd units, cron jobs, startup scripts, SSM associations, and recently modified binaries.

### 2.3 Retrieve the finding

```bash
aws guardduty get-findings \
  --detector-id 12abc3456789def0123456789abcdef0 \
  --finding-ids 9b6c5d1a7f3e4c2b8d9a0f1e2c3b4a5d \
  --region us-east-1
```

**Why:** The SIEM copy is often normalized. The GuardDuty response contains resource, service, action, and evidence fields needed to drive the next queries.

### 2.4 Check instance state and network identity

```bash
aws ec2 describe-instances \
  --instance-ids i-0f4a9c21b7d8e63a1 \
  --region us-east-1 \
  --query 'Reservations[0].Instances[0].{State:State.Name,PrivateIp:PrivateIpAddress,Subnet:SubnetId,Vpc:VpcId,Profile:IamInstanceProfile.Arn,Image:ImageId,Launch:LaunchTime,SG:SecurityGroups[*].GroupId}'
```

**Why:** This establishes whether the asset is live, where it sits, which security controls apply, and which IAM role must be investigated.

### 2.5 Pull recent CloudTrail activity for the instance role

First identify the role name:

```bash
aws iam get-instance-profile \
  --instance-profile-name payments-api-prod \
  --query 'InstanceProfile.Roles[*].RoleName'
```

Then search CloudTrail around the detection window:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=payments-api-prod \
  --start-time 2026-08-19T13:30:00Z \
  --end-time 2026-08-19T14:30:00Z \
  --region us-east-1 \
  --output json
```

**Why:** Malware on EC2 becomes materially worse if the instance role is used to enumerate, modify, or access AWS resources.

### 2.6 Query VPC Flow Logs in the SIEM

Example Splunk-style query:

```spl
index=aws_vpc sourcetype=aws:vpcflow
src_ip=10.42.17.83 earliest="08/19/2026:13:30:00" latest="08/19/2026:14:30:00"
| stats sum(bytes) as bytes sum(packets) as packets count by dest_ip dest_port action
| sort - bytes
```

Look for:

- repeated outbound connections to a previously unseen public IP;
- TCP/443 or TCP/80 connections inconsistent with the application;
- high byte counts;
- denied connections followed by successful connections;
- lateral connections to other private subnets;
- unusual SSH, RDP, SMB, database, or management-port traffic.

### 2.7 Severity decision

**Escalate to L2 immediately** because this is a production EC2 host with a confirmed malicious-file detection.

Escalation becomes **full IR** if any of the following are observed:

- malware executed rather than merely stored;
- C2 activity;
- credential theft or metadata-service access;
- suspicious AWS API calls from the instance role;
- lateral movement;
- persistence;
- sensitive application data access.

---

## 3. L2 SOC Deep Dive

### 3.1 Establish the execution timeline

Correlate:

```text
13:41:22Z  EC2 downloads archive from 203.0.113.77
13:42:03Z  /tmp/update.bin created
13:42:11Z  process execution observed
13:43:17Z  outbound TLS connection begins
13:56:49Z  GuardDuty malware finding generated
14:02:11Z  SOC receives finding
```

The synthetic IP `203.0.113.77` is documentation-only and intentionally reserved for examples.

The key question is whether the file was part of a legitimate deployment. Compare the hash with the approved release artifact and deployment pipeline.

### 3.2 Host-side evidence to collect

Before destructive containment, request volatile and persistent evidence through the organization's EDR/forensics workflow:

- running processes and parent/child relationships;
- network connections;
- process command lines;
- file hash and metadata;
- shell history where legally and operationally appropriate;
- cron/systemd persistence;
- recently created users and SSH keys;
- `/etc/ld.so.preload` and suspicious shared libraries;
- application deployment logs;
- package installation history;
- SSM command history;
- EC2 console output if needed.

Do not delete the malicious file before evidence collection unless active threat containment requires immediate destruction.

### 3.3 Check IMDS access and instance-role activity

Investigate CloudTrail for unusual role actions:

```spl
index=aws_cloudtrail
userIdentity.sessionContext.sessionIssuer.userName="payments-api-prod"
eventTime>= "2026-08-19T13:30:00Z"
eventTime<= "2026-08-19T14:30:00Z"
| stats count values(eventName) as actions values(sourceIPAddress) as src values(recipientAccountId) as accounts by userIdentity.arn
```

Look for:

- `ListBuckets`, `GetObject`, `GetSecretValue`;
- `DescribeInstances`, `DescribeSecurityGroups`, `DescribeIamRoles`;
- `CreateAccessKey`, `AssumeRole`;
- `PutObject`, `CopyObject`;
- changes to security groups, IAM, or SSM.

### 3.4 Blast-radius analysis

Pivot on:

- the EC2 instance role;
- source IPs observed from the host;
- destination IPs/domains;
- malicious file hash;
- S3 buckets accessed by the role;
- Secrets Manager and SSM Parameter Store access;
- other instances sharing the AMI or vulnerable package;
- CloudTrail activity from the same role session.

A single infected instance with no credential or lateral movement evidence is materially different from a host that accessed production secrets and assumed another role.

### 3.5 L2 recommendation

**Recommended disposition: Full incident response.**

Reason: production malware plus a live application role. Even if the initial malware appears contained, the credential and persistence questions remain unresolved.

---

## 4. Incident Response Actions

### 4.1 Preserve evidence

Record:

```text
Finding ID:       9b6c5d1a7f3e4c2b8d9a0f1e2c3b4a5d
Instance ID:      i-0f4a9c21b7d8e63a1
AMI ID:           ami-0a12bc34de56f7890
Instance profile: payments-api-prod
Detection:        2026-08-19T14:01:52Z
SOC receipt:      2026-08-19T14:02:11Z
```

Preserve the GuardDuty JSON, EDR telemetry, CloudTrail events, VPC Flow Logs, DNS logs, and approved forensic image/snapshot according to the incident evidence procedure.

### 4.2 Containment

For an active compromise, isolate the instance using the approved isolation security group or network-control mechanism. Avoid casually terminating the instance because termination destroys useful evidence and can remove the ability to reconstruct the attack.

Example controlled isolation operation:

```bash
aws ec2 modify-instance-attribute \
  --instance-id i-0f4a9c21b7d8e63a1 \
  --groups sg-0isolation123456789 \
  --region us-east-1
```

**Why:** Isolation prevents further network communication while preserving the running state for forensics. Use the organization's pre-created isolation SG; do not improvise a permissive security group during an incident.

If the role is compromised, apply the organization's credential-containment process: restrict the role, remove unnecessary permissions, and invalidate active sessions where supported by the identity architecture.

### 4.3 Recovery

1. Preserve evidence.
2. Rebuild from a known-good AMI or immutable deployment artifact rather than trusting a cleaned host.
3. Rotate secrets the instance could access.
4. Validate the replacement host before restoring production traffic.
5. Hunt for the malware hash and infrastructure across the account and organization.
6. Re-enable normal security-group membership only after IR approval.

---

## 5. Team Communication

### Initial alert to IR lead

```text
[SEV-1] GuardDuty EC2 Malware — payments-api-prod-02

14:02Z GuardDuty generated Execution:EC2/MaliciousFile for i-0f4a9c21b7d8e63a1 in us-east-1.

Asset: payments-api-prod-02 (10.42.17.83)
Account: 482731905614
Finding severity: 8/High
Environment: Production

Initial assessment: confirmed malicious-file detection on a production workload. L2 is validating execution context, outbound C2, instance-role activity, and persistence. No termination has been performed; evidence preservation is in progress.

Requested: IR lead acknowledgment and incident bridge if C2 or AWS credential use is confirmed.
```

### L2 status update

```text
[UPDATE 14:28Z] EC2 malware investigation

Confirmed execution of an unsigned binary created at 13:42Z. The binary does not match the approved payments-api release artifacts.

Observed 23 outbound connections to a previously unseen external endpoint between 13:43Z and 14:05Z. CloudTrail review is in progress for the attached instance role. No evidence of lateral movement has been confirmed yet.

Containment: instance placed in approved isolation SG at 14:25Z after forensic collection.

Current assessment: active compromise. Full IR recommended.
```

### Executive summary

```text
A production EC2 workload was compromised and executed a malicious binary. The host was isolated after evidence preservation. Investigation identified suspicious outbound communications and is validating whether the instance role was abused to access AWS resources. Production service was restored through a known-good replacement instance. Secret rotation and organization-wide IOC hunting are underway.
```

---

# Scenario 2 — IAM Credential Compromise: `CredentialAccess:IAMUser/CompromisedCredentials`

## 1. Scenario Overview

**Service:** IAM  
**Finding:** `CredentialAccess:IAMUser/CompromisedCredentials`  
**Severity:** High  
**Threat pattern:** Stolen IAM credentials used from an anomalous source  
**Synthetic account:** `615204837921`  
**Region:** `us-west-2`  
**Identity:** `svc-data-export`

AWS lists this finding as High severity and associates it with CloudTrail management events or S3 data events. This is a credential-compromise scenario, so the first priority is to determine whether the credential is actively being used.

## 2. L1 Initial Response

### Raw finding

```json
{
  "schemaVersion": "2.0",
  "id": "7d31c9e8a4f24b55b6a1f1d8e7c2aa90",
  "type": "CredentialAccess:IAMUser/CompromisedCredentials",
  "severity": 8,
  "createdAt": "2026-08-19T15:17:43.000Z",
  "updatedAt": "2026-08-19T15:18:01.000Z",
  "title": "IAM credentials have been compromised",
  "resource": {
    "resourceType": "AccessKey",
    "accessKeyDetails": {
      "accessKeyId": "AKIAEXAMPLE7N4Q",
      "principalId": "AIDAEXAMPLE9K3",
      "userName": "svc-data-export",
      "userType": "IAMUser"
    }
  },
  "service": {
    "serviceName": "guardduty",
    "action": {
      "actionType": "AWS_API_CALL",
      "awsApiCallAction": {
        "api": "ListBuckets",
        "serviceName": "s3.amazonaws.com",
        "callerType": "RemoteIP",
        "remoteIpDetails": {
          "ipAddressV4": "198.51.100.42",
          "organization": {"asnOrg":"Example Hosting"},
          "country": {"countryName":"Exampleland"}
        }
      }
    }
  }
}
```

### Immediate questions

- Is `svc-data-export` still expected to use long-lived access keys?
- Who owns the identity?
- What systems normally use the key?
- Was the source IP expected?
- What API calls occurred before and after the GuardDuty finding?
- Did the actor enumerate IAM, S3, EC2, Secrets Manager, KMS, or STS?
- Did the identity access sensitive objects?
- Did it create persistence such as another access key, user, role, or policy?

### Identify key status

```bash
aws iam list-access-keys \
  --user-name svc-data-export \
  --query 'AccessKeyMetadata[*].{Id:AccessKeyId,Status:Status,Created:CreateDate}'
```

Do not print secret access keys into the ticket or SIEM.

### CloudTrail lookup

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=svc-data-export \
  --start-time 2026-08-19T14:30:00Z \
  --end-time 2026-08-19T15:45:00Z \
  --region us-west-2 \
  --output json
```

### SIEM query

```spl
index=aws_cloudtrail userIdentity.accessKeyId="AKIAEXAMPLE7N4Q"
| stats earliest(_time) as first latest(_time) as last count values(eventName) as actions values(sourceIPAddress) as src by awsRegion
| convert ctime(first) ctime(last)
```

**Escalate immediately** if the source is not approved or if privileged/data-access APIs are present.

---

## 3. L2 Deep Dive

### 3.1 Build the credential timeline

Synthetic timeline:

```text
14:51:06Z  GetCallerIdentity from 198.51.100.42
14:51:18Z  ListBuckets from 198.51.100.42
14:52:03Z  ListRoles from 198.51.100.42
14:52:31Z  ListPolicies from 198.51.100.42
14:53:02Z  GetObject against finance-export bucket
15:17:43Z  GuardDuty finding generated
15:18:01Z  SOC receives alert
```

The progression from identity validation to enumeration to sensitive S3 access is strong evidence of active credential abuse.

### 3.2 Check privilege and sensitive access

```bash
aws iam list-attached-user-policies --user-name svc-data-export
aws iam list-user-policies --user-name svc-data-export
aws iam list-groups-for-user --user-name svc-data-export
```

For S3 data events, search for the access key and bucket/object names in CloudTrail.

Example Splunk:

```spl
index=aws_cloudtrail
userIdentity.accessKeyId="AKIAEXAMPLE7N4Q"
(eventName=GetObject OR eventName=PutObject OR eventName=CopyObject OR eventName=DeleteObject)
| stats count sum(bytesTransferred) as bytes values(requestParameters.bucketName) as buckets values(requestParameters.key) as objects by eventName sourceIPAddress
```

### 3.3 Persistence checks

Search for:

```text
CreateAccessKey
CreateUser
CreateRole
AttachUserPolicy
AttachRolePolicy
PutUserPolicy
PutRolePolicy
UpdateAssumeRolePolicy
CreateLoginProfile
AddUserToGroup
AssumeRole
```

A compromised low-privilege identity that creates or modifies another principal is an immediate privilege-escalation concern.

### 3.4 Blast radius

Pivot on the access key across all CloudTrail data available to the SOC. Do not restrict the hunt to the GuardDuty region because IAM credentials are account-wide and attackers frequently move across regions.

Look for:

- new regions accessed by the identity;
- new AWS services;
- sensitive S3 buckets;
- KMS decrypt activity;
- Secrets Manager reads;
- STS role assumption;
- security-group or network changes;
- CloudTrail configuration changes;
- GuardDuty/Security Hub changes.

### L2 disposition

**Full IR.** Confirmed suspicious source + enumeration + sensitive S3 access = credential compromise with probable data-access impact.

---

## 4. Incident Response Actions

### Evidence preservation

Capture:

- complete GuardDuty finding JSON;
- all CloudTrail events for the access key from at least 24 hours before detection through containment;
- IAM policy state and identity metadata;
- S3 data-event records;
- STS AssumeRole activity;
- relevant application/job logs identifying legitimate use of the key.

### Immediate credential containment

If unauthorized use is confirmed, disable the compromised access key:

```bash
aws iam update-access-key \
  --user-name svc-data-export \
  --access-key-id AKIAEXAMPLE7N4Q \
  --status Inactive
```

**Why:** Disabling the specific key stops continued use while preserving the IAM user and other key metadata for investigation. If a second legitimate key exists, do not disable it blindly.

Then rotate the credential through the organization's secret-management process and migrate the workload to short-lived credentials/roles where feasible.

### Persistence cleanup

If the attacker created additional users, keys, roles, or policy changes, preserve the unauthorized objects and configuration state before deleting or reverting them. Coordinate with IR/cloud engineering because deleting evidence can remove attribution data.

### Recovery

- Replace the credential in the owning application or pipeline.
- Rotate any downstream secrets exposed through the identity.
- Review KMS and S3 access logs for data exposure.
- Hunt the malicious source IP and access key across the organization.
- Verify no secondary persistence remains.

---

## 5. Team Communication

### Initial IR notification

```text
[SEV-1] GuardDuty IAM credential compromise — svc-data-export

15:18Z GuardDuty reported CredentialAccess:IAMUser/CompromisedCredentials for access key AKIAEXAMPLE7N4Q.

Observed source: 198.51.100.42
Account: 615204837921
Finding severity: High

L1 confirmed the key was used outside its expected execution context. CloudTrail shows S3 enumeration followed by GetObject activity against finance-export. L2 is validating object sensitivity, STS role assumption, and persistence.

Recommended immediate action: disable the affected access key and begin credential-rotation procedure.
```

### Security team update

```text
[UPDATE 15:42Z]

The compromised key was disabled at 15:35Z. Prior to containment, the actor performed IAM enumeration and accessed 17 objects in the finance-export bucket. No unauthorized IAM user creation was observed. One AssumeRole event is under review.

Current assessment: confirmed credential compromise; potential sensitive-data access. Full IR remains active.
```

### Executive summary

```text
A service-account access key was used from an unauthorized external source. The actor enumerated AWS resources and accessed objects in a finance export bucket. The key was disabled and replaced. Investigation found no confirmed privilege escalation, while S3 object access and downstream role activity remain under review. The organization is hunting for related use of the credential across all accounts and regions.
```

---

# Scenario 3 — S3 Data Exfiltration: `Exfiltration:S3/AnomalousBehavior`

## 1. Scenario Overview

**Service:** Amazon S3  
**Finding:** `Exfiltration:S3/AnomalousBehavior`  
**Severity:** High  
**Threat pattern:** Anomalous S3 object retrieval consistent with data exfiltration  
**Synthetic account:** `731846209553`  
**Region:** `us-east-1`  
**Bucket:** `customer-analytics-prod`

AWS classifies this as an S3 CloudTrail data-event finding with High severity. The core investigation is to establish **who accessed what, from where, how much, and whether the access was authorized**.

## 2. L1 Initial Response

### Raw finding

```json
{
  "schemaVersion": "2.0",
  "id": "4d1e8a7c0b1f4a9c9c1f1a2b3d4e5f60",
  "type": "Exfiltration:S3/AnomalousBehavior",
  "severity": 8,
  "createdAt": "2026-08-19T16:06:33.000Z",
  "resource": {
    "resourceType": "S3Bucket",
    "s3BucketDetails": [{
      "name": "customer-analytics-prod",
      "type": "TARGET"
    }]
  },
  "service": {
    "action": {
      "actionType": "AWS_API_CALL",
      "awsApiCallAction": {
        "api": "GetObject",
        "serviceName": "s3.amazonaws.com",
        "callerType": "RemoteIP",
        "remoteIpDetails": {
          "ipAddressV4": "198.51.100.91"
        }
      }
    }
  }
}
```

### First questions

- Is the bucket business-critical or regulated?
- Which principal accessed it?
- Is the source IP known?
- Was the access via an application role, IAM user, or assumed role?
- How many objects were read?
- What were their sizes and classifications?
- Was access normal for this identity?
- Were objects copied, downloaded, or accessed in a burst?
- Did the actor enumerate the bucket before reading objects?

### Check bucket configuration

```bash
aws s3api get-bucket-location --bucket customer-analytics-prod
aws s3api get-public-access-block --bucket customer-analytics-prod
aws s3api get-bucket-encryption --bucket customer-analytics-prod
```

**Why:** Establish the security baseline and whether the bucket is intended to contain protected data.

### CloudTrail data-event query

In Splunk:

```spl
index=aws_cloudtrail
s3.bucket.name="customer-analytics-prod"
(eventName=GetObject OR eventName=ListObjects OR eventName=ListObjectsV2)
eventTime>="2026-08-19T15:00:00Z"
eventTime<="2026-08-19T16:15:00Z"
| stats count values(userIdentity.arn) as principals values(sourceIPAddress) as src values(requestParameters.key) as objects by eventName
```

If S3 data events are delivered in raw CloudTrail format, normalize the exact field names used by the organization's parser.

### Escalation criteria

Escalate to L2 immediately when:

- the source is unauthorized;
- a sensitive bucket/object set was accessed;
- the identity is compromised;
- object reads are materially above baseline;
- the actor accessed many objects in a short interval;
- there is evidence of cross-account access or public exposure.

---

## 3. L2 Deep Dive

### 3.1 Quantify data access

Example query:

```spl
index=aws_cloudtrail
s3.bucket.name="customer-analytics-prod"
eventName=GetObject
sourceIPAddress="198.51.100.91"
| stats count as objects sum(responseElements.bytesTransferred) as bytes by userIdentity.arn
| eval GB=round(bytes/1024/1024/1024,2)
```

Synthetic result:

```text
principal: arn:aws:sts::731846209553:assumed-role/analytics-batch/etl-20260819
objects: 1842
bytes: 47,315,284,992
GB: 44.06
window: 15:34Z–15:58Z
```

This is far outside the role's historical baseline of approximately 2–4 GB per batch run.

### 3.2 Determine whether the role was itself compromised

Pivot on the assumed-role session name and source IP. Search CloudTrail for:

```text
AssumeRole
GetCallerIdentity
ListBuckets
ListObjectsV2
GetObject
GetObjectAttributes
GetBucketLocation
GetBucketPolicy
GetBucketAcl
```

The sequence matters. Enumeration followed by high-volume object access from an unfamiliar source is stronger evidence than a single anomalous `GetObject`.

### 3.3 Cross-account and public-access checks

```bash
aws s3api get-bucket-policy --bucket customer-analytics-prod
aws s3api get-bucket-acl --bucket customer-analytics-prod
```

Also inspect AWS Organizations/SCP context and the role's trust policy if the access originated from an assumed role.

### 3.4 Data classification and impact

Classify the affected objects using the organization's data inventory. For training, assume:

```text
customers/2026-08-19/customer_profile_*.parquet
customers/2026-08-19/customer_contact_*.parquet
```

contain customer identifiers and contact information.

Do not download production objects simply to prove exposure. Use metadata, object inventory, DLP/classification tags, and approved evidence-handling procedures.

### 3.5 Network and endpoint correlation

If the role is normally used by a batch job, identify the expected source workload and compare:

- EC2 private IP;
- NAT gateway;
- ECS/EKS workload;
- Lambda execution;
- CI/CD runner;
- VPN/Direct Connect path.

A role suddenly used directly from an external IP is a strong compromise signal.

### L2 recommendation

**Full IR.** The synthetic evidence shows unauthorized access to approximately 44 GB of customer-related objects from an anomalous source.

---

## 4. Incident Response Actions

### 4.1 Preserve evidence

Preserve:

- GuardDuty finding;
- complete S3 CloudTrail data events;
- bucket policy and ACL state;
- IAM role policy/trust policy;
- relevant access-point policy if present;
- object inventory metadata;
- source identity and network telemetry;
- SIEM searches used to calculate impact.

### 4.2 Contain the access path

If the IAM role is compromised, restrict or disable the credential path according to the organization's cloud IAM containment procedure.

If a bucket policy or access point is the exposure mechanism, apply a narrowly scoped deny/containment control rather than taking the entire bucket offline without business-impact assessment.

If a known malicious principal is still active, revoke its access before continuing the hunt.

### 4.3 Recovery and eradication

- Rotate the compromised credentials.
- Rebuild the originating workload if compromised.
- Remove unauthorized policy statements.
- Validate bucket Block Public Access settings.
- Review all objects accessed during the attack window.
- Determine whether notification/legal/privacy workflows are required based on data classification.
- Hunt for the same source and principal in every account.

---

## 5. Team Communication

### Initial notification

```text
[SEV-1] GuardDuty S3 exfiltration — customer-analytics-prod

16:07Z GuardDuty generated Exfiltration:S3/AnomalousBehavior for bucket customer-analytics-prod.

Source: 198.51.100.91
Account: 731846209553

L1 identified anomalous GetObject activity. L2 is quantifying the affected object set and validating the assumed-role session. Initial telemetry indicates a significant deviation from the role's normal transfer volume.

Potential impact: customer data exposure. IR and data-governance stakeholders should be prepared for escalation pending confirmation of authorization and data classification.
```

### Status update

```text
[UPDATE 16:41Z]

Confirmed 1,842 object reads totaling approximately 44.06 GB between 15:34Z and 15:58Z. The source IP is not associated with the expected analytics execution path. Affected objects include customer profile/contact datasets.

Access path has been contained. Evidence preservation is complete for the initial window. IR investigation is active to determine credential origin and whether the data was successfully transferred outside the organization.
```

### Executive summary

```text
GuardDuty detected anomalous S3 access against a production customer-data bucket. Investigation confirmed high-volume object retrieval from an unauthorized source, substantially exceeding the workload's historical baseline. Access was contained and the affected role is being rotated. The incident response team is determining the exact data set accessed and whether external transfer occurred.
```

---

# Scenario 4 — Lambda C2: `Backdoor:Lambda/C&CActivity.B`

## 1. Scenario Overview

**Service:** AWS Lambda  
**Finding:** `Backdoor:Lambda/C&CActivity.B`  
**Severity:** High  
**Threat pattern:** Lambda function establishes command-and-control network activity  
**Synthetic account:** `904172638511`  
**Region:** `eu-west-1`  
**Function:** `invoice-renderer-prod`

AWS lists this finding under Lambda Network Activity Monitoring with High severity. The key questions are whether the function package/configuration was modified, which invocation triggered the behavior, what IAM role it has, and whether the function can reach sensitive internal services.

## 2. L1 Initial Response

### Raw finding

```json
{
  "schemaVersion": "2.0",
  "id": "b9c8d7e6f5a41234a9b8c7d6e5f40123",
  "type": "Backdoor:Lambda/C&CActivity.B",
  "severity": 8,
  "createdAt": "2026-08-19T17:12:19.000Z",
  "resource": {
    "resourceType": "Lambda",
    "lambdaDetails": {
      "functionName": "invoice-renderer-prod",
      "functionArn": "arn:aws:lambda:eu-west-1:904172638511:function:invoice-renderer-prod",
      "version": "$LATEST",
      "revisionId": "c8e6a9f2-0d4a-4d4e-8f31-22a7d0b2e991"
    }
  },
  "service": {
    "serviceName": "guardduty",
    "action": {
      "actionType": "NETWORK_CONNECTION"
    }
  }
}
```

### L1 questions

- Was the function recently deployed?
- Did the function configuration or code hash change outside CI/CD?
- What destination did the function contact?
- Does the function normally make external network calls?
- Is the function attached to a VPC?
- What IAM execution role is attached?
- What secrets, S3 buckets, queues, databases, or APIs can the function access?
- Which event source invoked the function?

### Function metadata

```bash
aws lambda get-function-configuration \
  --function-name invoice-renderer-prod \
  --region eu-west-1
```

Then:

```bash
aws lambda get-function \
  --function-name invoice-renderer-prod \
  --region eu-west-1 \
  --query '{CodeSha256:Configuration.CodeSha256,Role:Configuration.Role,LastModified:Configuration.LastModified,Version:Configuration.Version,Runtime:Configuration.Runtime}'
```

**Why:** The deployment hash and timestamp establish whether the function changed shortly before the finding.

### CloudTrail deployment search

```spl
index=aws_cloudtrail
(eventName=UpdateFunctionCode OR eventName=UpdateFunctionConfiguration OR eventName=PublishVersion)
requestParameters.functionName="invoice-renderer-prod"
| table eventTime eventName userIdentity.arn sourceIPAddress userAgent requestParameters
| sort eventTime
```

### Lambda application logs

```spl
index=aws_lambda function_name="invoice-renderer-prod"
eventTime>="2026-08-19T16:30:00Z"
eventTime<="2026-08-19T17:30:00Z"
| search "timeout" OR "connection" OR "http" OR "dns" OR "exception"
```

**Escalate immediately** because C2 activity on a production Lambda function is a high-confidence compromise signal unless the destination is explicitly approved security-testing infrastructure.

---

## 3. L2 Deep Dive

### 3.1 Identify the deployment source

Search CloudTrail for function-code changes and compare the actor with the CI/CD service role.

Synthetic timeline:

```text
16:48Z  Approved deployment completed by codepipeline-prod
16:49Z  UpdateFunctionCode by codepipeline-prod
17:01Z  Unexpected UpdateFunctionConfiguration from assumed role arn:aws:sts::904172638511:assumed-role/deploy-helper/tmp-9481
17:03Z  New function configuration revision observed
17:11Z  Function invokes external destination
17:12Z  GuardDuty finding generated
```

The unexpected configuration update is a major escalation indicator.

### 3.2 Inspect environment-variable and layer configuration

Use:

```bash
aws lambda get-function-configuration \
  --function-name invoice-renderer-prod \
  --region eu-west-1 \
  --query '{Env:Environment.Variables,Vpc:VpcConfig,Layers:Layers,Role:Role,Handler:Handler}'
```

Handle secrets carefully. Do not copy secret values into tickets or chat. The goal is to identify references, not expose credentials.

### 3.3 Investigate invocation sources

Check CloudTrail, EventBridge, SQS, API Gateway, S3, or the application's event source logs depending on the function architecture.

Questions:

- Did a new event source trigger the function?
- Was an invocation volume spike observed?
- Did an attacker invoke the function directly?
- Did a compromised upstream application trigger it?

### 3.4 IAM blast radius

Retrieve the execution role:

```bash
aws iam list-attached-role-policies --role-name invoice-renderer-prod
aws iam list-role-policies --role-name invoice-renderer-prod
```

Look for access to:

```text
secretsmanager:GetSecretValue
kms:Decrypt
s3:GetObject
s3:PutObject
ssm:GetParameter
rds-db:connect
sts:AssumeRole
```

A Lambda C2 incident with a powerful execution role can become a credential/data-access incident.

### 3.5 Lateral movement and persistence

Search for:

- unexpected Lambda layers;
- new function versions;
- aliases moved to unauthorized versions;
- event-source mappings;
- modified resource policies;
- unusual cross-account invocation permissions;
- IAM policy changes;
- role assumption by the execution role.

### L2 recommendation

**Full IR.** The synthetic evidence shows unauthorized Lambda configuration modification followed by network C2 behavior.

---

## 4. Incident Response Actions

### Evidence preservation

Preserve:

- function configuration JSON;
- deployment metadata and CodeSha256;
- CloudTrail management events;
- Lambda logs;
- GuardDuty finding;
- function versions and layers;
- event-source configuration;
- IAM role policy state;
- destination IP/domain and DNS evidence.

### Containment

Contain the function using the organization's Lambda incident procedure. Typical controls include:

- disable the triggering event source;
- restrict unauthorized invocation permissions;
- move traffic away from the compromised version/alias;
- deploy a known-good version from the approved pipeline;
- restrict egress through the VPC/network architecture where applicable;
- disable or rotate credentials accessible to the function.

Do not delete the function or compromised version before evidence collection unless required to stop active destructive behavior.

### Recovery

1. Rebuild the function from a trusted source commit.
2. Verify dependency and layer integrity.
3. Rotate secrets available to the function.
4. Restore the approved alias/version.
5. Validate resource-based policies.
6. Re-enable event sources after IR approval.
7. Hunt for the same unauthorized deployment actor across Lambda functions.

---

## 5. Team Communication

### Initial alert

```text
[SEV-1] GuardDuty Lambda C2 — invoice-renderer-prod

17:12Z GuardDuty generated Backdoor:Lambda/C&CActivity.B for arn:aws:lambda:eu-west-1:904172638511:function:invoice-renderer-prod.

Initial assessment: high-confidence malicious network behavior from a production Lambda function. L1 is validating recent code/configuration changes, execution role permissions, invocation source, and destination infrastructure.

No function deletion performed. Evidence preservation is in progress.
```

### Security update

```text
[UPDATE 17:39Z]

L2 identified an unauthorized UpdateFunctionConfiguration event approximately 10 minutes before the C2 detection. The actor used assumed role deploy-helper/tmp-9481, which is not associated with the approved CI/CD pipeline.

Function event source has been disabled and the production alias moved to the last approved version. Credentials accessible to the function are being rotated.

Current assessment: confirmed Lambda compromise. Full IR active.
```

### Executive summary

```text
A production Lambda function was modified by an unauthorized assumed role and subsequently generated command-and-control network activity. The event source was disabled, the production alias was restored to a known-good version, and exposed secrets are being rotated. Investigation is determining the origin of the unauthorized deployment role and whether other Lambda functions were modified.
```

---

# Scenario 5 — RDS Account Compromise: `CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce`

## 1. Scenario Overview

**Service:** Amazon RDS/Aurora  
**Finding:** `CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce`  
**Severity:** High  
**Threat pattern:** Repeated login attempts followed by successful authentication to a production database  
**Synthetic account:** `328615704992`  
**Region:** `ap-south-1`  
**DB cluster:** `orders-prod-cluster`

AWS lists this finding as High severity and associates it with RDS Login Activity Monitoring. The SOC must determine whether the successful login represents a real credential compromise and whether database access occurred after authentication.

## 2. L1 Initial Response

### Raw finding

```json
{
  "schemaVersion": "2.0",
  "id": "e3f4a5b6c7d8491029384756a1b2c3d4",
  "type": "CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce",
  "severity": 8,
  "createdAt": "2026-08-19T18:22:17.000Z",
  "resource": {
    "resourceType": "RDSDBInstance",
    "rdsDbInstanceDetails": {
      "dbInstanceIdentifier": "orders-prod-instance-1",
      "engine": "aurora-postgresql",
      "dbClusterIdentifier": "orders-prod-cluster"
    }
  },
  "service": {
    "serviceName": "guardduty",
    "action": {
      "actionType": "DATABASE_LOGIN",
      "databaseLoginAction": {
        "remoteIpDetails": {
          "ipAddressV4": "198.51.100.117"
        },
        "userName": "reporting_admin"
      }
    }
  }
}
```

### Immediate questions

- Is `reporting_admin` a valid production identity?
- Is the source IP an approved application, analyst workstation, VPN, or jump host?
- How many failed attempts occurred?
- Was the successful login followed by SQL activity?
- Was the account expected to access production?
- Is the database publicly reachable?
- Did the actor query sensitive tables or create another database account?
- Were application credentials exposed?

### RDS network configuration

```bash
aws rds describe-db-instances \
  --db-instance-identifier orders-prod-instance-1 \
  --region ap-south-1 \
  --query 'DBInstances[0].{PubliclyAccessible:PubliclyAccessible,Endpoint:Endpoint.Address,Port:Endpoint.Port,Vpc:DBSubnetGroup.VpcId,SGs:VpcSecurityGroups[*].VpcSecurityGroupId,Engine:Engine}'
```

**Why:** Public exposure materially changes the threat model. A database reachable only through a private application network has a different likely attack path than one reachable from the Internet.

### RDS activity query

```spl
index=aws_rds
cluster="orders-prod-cluster"
source_ip="198.51.100.117"
eventTime>="2026-08-19T17:30:00Z"
eventTime<="2026-08-19T18:45:00Z"
| stats count by username action database
| sort -count
```

If PostgreSQL audit logging is enabled, correlate connection and statement logs. If database activity is not available, document that limitation explicitly and use application/database telemetry that is available.

### Severity decision

A successful brute-force finding against a production database is **L2 immediately** and normally **full IR** when the account is privileged or the source is unauthorized.

---

## 3. L2 Deep Dive

### 3.1 Reconstruct the authentication sequence

Synthetic evidence:

```text
18:04:11Z  failed login reporting_admin from 198.51.100.117
18:04:13Z  failed login reporting_admin from 198.51.100.117
18:04:16Z  failed login reporting_admin from 198.51.100.117
18:04:21Z  failed login reporting_admin from 198.51.100.117
18:04:28Z  successful login reporting_admin from 198.51.100.117
18:05:03Z  SELECT against customer_orders
18:05:19Z  SELECT against customer_contact
18:06:07Z  pg_catalog enumeration
18:06:31Z  connection terminated after containment
```

This is materially different from five failed logins with no success. The successful authentication followed by sensitive queries indicates likely account compromise.

### 3.2 Validate source identity

Check:

- corporate VPN ranges;
- approved database bastions;
- application NAT gateways;
- known database administration hosts;
- identity-provider/device logs if database authentication integrates with them;
- CMDB ownership of the source address.

### 3.3 Determine database impact

Identify whether the user can:

- read sensitive tables;
- write or delete records;
- create users/roles;
- alter permissions;
- access large datasets;
- invoke dangerous extensions or functions.

Do not run intrusive queries on production data during triage. Use audit metadata and existing telemetry first.

### 3.4 Check for credential reuse

The database password may have been exposed through:

- application configuration;
- CI/CD secrets;
- developer workstation compromise;
- secret-management access;
- leaked configuration files;
- phishing or credential theft.

Search the same username in application authentication logs and secret-access logs. If the database credential is stored in AWS Secrets Manager, inspect access to that secret around the incident window.

### 3.5 Network exposure and lateral movement

Check security-group rules:

```bash
aws ec2 describe-security-groups \
  --group-ids sg-0db123456789abcd1 \
  --region ap-south-1
```

The objective is to identify whether the database accepted traffic from a broad Internet CIDR, an unexpected network, or only the approved application tier.

### L2 recommendation

**Full IR.** Successful authentication after brute-force activity plus access to customer tables is confirmed unauthorized database access.

---

## 4. Incident Response Actions

### Evidence preservation

Preserve:

- GuardDuty finding;
- RDS login telemetry;
- database audit logs;
- CloudTrail RDS configuration events;
- security-group state;
- Secrets Manager access events;
- application logs;
- database account metadata;
- source network telemetry.

Record the exact incident window before rotating credentials so that historical searches remain consistent.

### Containment

Preferred sequence:

1. Confirm whether the account is actively connected.
2. Restrict the source network path if it is clearly unauthorized.
3. Disable/rotate the compromised database credential using the database credential-management process.
4. Restrict the affected database account to the minimum required permissions.
5. If the database is Internet-accessible contrary to architecture, immediately narrow the security-group ingress to approved sources after business-owner confirmation or emergency containment authority.
6. Preserve active-session evidence before terminating sessions where feasible.

### Recovery

- Rotate the compromised credential.
- Review and revert unauthorized database grants.
- Restore security-group baseline.
- Validate no new DB users/roles were created.
- Hunt for use of the same credential in non-production and other environments.
- Validate sensitive-table access and determine whether data was exported.
- Restore normal access only after IR approval.

---

## 5. Team Communication

### Initial notification

```text
[SEV-1] GuardDuty RDS successful brute force — orders-prod-cluster

18:22Z GuardDuty generated CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce.

Database: orders-prod-cluster / orders-prod-instance-1
User: reporting_admin
Source: 198.51.100.117

Telemetry shows four failed authentication attempts followed by a successful login and subsequent queries against customer_orders and customer_contact.

Assessment: probable unauthorized database access. L2 is preserving audit evidence and validating source authorization and credential exposure. IR escalation recommended.
```

### Status update

```text
[UPDATE 18:51Z]

Source 198.51.100.117 is not an approved corporate VPN, application NAT, or database administration address. Successful authentication was followed by reads against two customer datasets and database catalog enumeration.

The affected credential has been rotated and the unauthorized network path has been blocked. Database audit evidence is preserved. No evidence of destructive SQL activity has been identified in the reviewed window.

Current assessment: confirmed database account compromise with unauthorized data access. Full IR active.
```

### Executive summary

```text
An attacker successfully authenticated to a production Aurora PostgreSQL database after multiple failed login attempts. The source was not an approved corporate or application network. The account accessed customer-related tables before containment. The credential was rotated, the unauthorized network path was blocked, and database audit evidence is preserved. IR is assessing the complete data-access scope and source of the compromised credential.
```

---

# Cross-Scenario Investigation Checklist

## L1 — First 10 Minutes

- [ ] Record GuardDuty finding ID, type, severity, account, region, resource, and detection timestamp.
- [ ] Confirm whether the resource is production.
- [ ] Determine whether the finding indicates active behavior or historical evidence.
- [ ] Identify the principal/role/user associated with the activity.
- [ ] Identify source IP/domain and whether it is expected.
- [ ] Pull the complete GuardDuty finding.
- [ ] Establish a ±30–60 minute investigation window.
- [ ] Search CloudTrail for related API activity.
- [ ] Search service-specific telemetry.
- [ ] Check for data access, credential use, persistence, privilege escalation, or lateral movement.
- [ ] Escalate to L2 when compromise cannot be confidently excluded.

## L2 — Investigation Expansion

- [ ] Expand the time window to at least 24 hours when credential compromise is suspected.
- [ ] Hunt across all relevant AWS regions.
- [ ] Pivot on access key ID, principal ARN, role session name, source IP, instance ID, function name, bucket, or database account.
- [ ] Identify first-seen and last-seen activity.
- [ ] Compare behavior against a known-good baseline.
- [ ] Identify all resources accessed by the principal.
- [ ] Identify all principals accessing the affected resource.
- [ ] Check for persistence and privilege escalation.
- [ ] Check CloudTrail configuration and security-control changes.
- [ ] Check S3/KMS/Secrets Manager/SSM access when relevant.
- [ ] Quantify affected data and resources.
- [ ] Determine whether active attacker access remains.
- [ ] Make an explicit containment recommendation.

## Evidence Preservation

- [ ] Original GuardDuty finding JSON.
- [ ] CloudTrail management events.
- [ ] CloudTrail S3 data events where applicable.
- [ ] VPC Flow Logs.
- [ ] Route 53 Resolver logs where available.
- [ ] Service/application logs.
- [ ] IAM policy and trust-policy state.
- [ ] Security-group and network-control state.
- [ ] Relevant endpoint/EDR telemetry.
- [ ] Database audit logs.
- [ ] Deployment/change records.
- [ ] Hashes and file metadata for malware cases.

---

# Containment Decision Matrix

| Finding pattern | Evidence threshold | Immediate containment? | IR disposition |
|---|---|---:|---|
| EC2 malicious file + active C2 | Malware executed + outbound C2 | Yes | Full IR |
| EC2 malicious file only | Confirmed malware, no active C2 | Usually | Full IR for production |
| IAM compromised credentials | Unauthorized use confirmed | Yes | Full IR |
| IAM anomaly only | Fully explained approved activity | No | Close/monitor |
| S3 anomalous behavior | Unauthorized sensitive-data access | Yes | Full IR |
| S3 anomaly with approved batch | Baseline/change record matches | No | Close/monitor |
| Lambda C2 | Unauthorized network behavior | Yes | Full IR |
| Lambda network finding from approved scanner | Destination and test window verified | No | Close/monitor |
| RDS successful brute force | Successful unauthorized login | Yes | Full IR |
| RDS failed login only | No successful access, source blocked | Usually monitor | L2 review |

---

# Evidence and Case-Closure Standard

A production-quality closure should answer five questions:

1. **What happened?**  
   State the exact GuardDuty finding and observed behavior.
2. **Was it authorized?**  
   Identify the owner/change record or establish unauthorized activity.
3. **What was affected?**  
   List accounts, resources, identities, data, and time range.
4. **What did the attacker do after initial access?**  
   Address discovery, credential access, persistence, privilege escalation, lateral movement, collection, and exfiltration.
5. **What stopped the activity and prevented recurrence?**  
   Document containment, credential rotation, rebuilds, policy changes, monitoring, and follow-up detections.

### Strong closure example

```text
Disposition: Confirmed compromise — contained

GuardDuty finding: CredentialAccess:IAMUser/CompromisedCredentials
Finding ID: 7d31c9e8a4f24b55b6a1f1d8e7c2aa90

The svc-data-export access key was used from an unauthorized external source. CloudTrail confirmed IAM enumeration and S3 object access. The key was disabled at 15:35Z and replaced through the approved secret-management process. Investigation found no unauthorized IAM principal creation. S3 access was quantified and data-governance review was initiated.

Evidence retained: GuardDuty finding, CloudTrail events, IAM state, S3 data events, SIEM searches, and containment timestamps.

Follow-up: hunt for the source IP, review all uses of the credential, migrate the workload to short-lived role credentials, and tune detection for anomalous service-account geography and API sequences.
```

### Weak closure example

```text
Closed — GuardDuty alert handled.
```

The second example is insufficient because it does not establish authorization, scope, evidence, containment, or residual risk.

---

# Analyst Takeaways

## EC2

Think **host compromise → credentials → network → AWS control plane**.

## IAM

Think **credential → API sequence → privilege → persistence → data access**.

## S3

Think **principal → object set → volume → source → data sensitivity → exfiltration path**.

## Lambda

Think **deployment/configuration → invocation → execution role → network → secrets/data**.

## RDS

Think **authentication → source → session → SQL activity → data impact → credential origin**.

The strongest SOC investigations do not stop at the GuardDuty finding. They reconstruct the attack chain around it and prove both the absence or presence of impact. GuardDuty supplies the detection signal; CloudTrail, network telemetry, workload telemetry, IAM context, and application/service logs establish what actually happened.

---

## AWS Reference

- Amazon GuardDuty finding types: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html
- The finding names and severity classifications used in this guide were selected from AWS's active finding-type documentation.

> **Training note:** All identifiers and telemetry values in this document are synthetic. IP addresses use documentation ranges where possible. Do not execute containment commands against production resources without validating the resource, account, region, change authority, and incident procedure.
