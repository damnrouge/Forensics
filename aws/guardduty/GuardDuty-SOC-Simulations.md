# 🕵️‍♂️ AWS GuardDuty — SOC Case Files
### The Fun (But Deadly Serious) Training Guide

> **Welcome to the Cloud Crime Scene Unit.**  
> You’re not just reading findings. You’re hunting attackers in AWS.  
> Every scenario below is a complete, production-style investigation you can run in your lab or use to train your team.  
> All names, IPs, account IDs, and telemetry are **synthetic**. Treat them like real ones.

---

## How to Play This Guide

Each scenario is a **case file**.  
You start as L1 (the first responder), then level up to L2 (the detective), then call in IR (the cleanup crew).

**Your mission every time:**
1. Don’t trust the finding alone.
2. Reconstruct the attack chain.
3. Decide: Close, Monitor, or Full IR.

**House rules of this SOC:**
- GuardDuty findings land in the SIEM.
- CloudTrail, VPC Flow Logs, and S3 data events are available.
- You have read-only access + a break-glass role for containment.
- Production changes need approval… unless the house is already on fire.

---

## The Severity Compass (Memorize This)

**Escalate now if:**
- Privileged IAM identity is compromised
- Real credentials are being used from weird places
- Sensitive data is moving
- Malware or C2 is live
- Persistence or lateral movement appears
- Logging or security controls got turned off

**Contain immediately if:**
- Attacker still has an active session
- Credential is confirmed stolen
- Live C2 or malware is running
- Data is actively leaving

**Close / Monitor only if:**
- Everything matches an approved change, scanner, or deployment
- You can prove it independently (not just “the owner said so”)

---

# 📁 CASE 01 — The Malicious Binary on Payments
**Finding:** `Execution:EC2/MaliciousFile`  
**Severity:** High  
**Asset:** `payments-api-prod-02` (i-0f4a9c21b7d8e63a1)

### The Scene
It’s 14:02 UTC. Your coffee is cold. GuardDuty just screamed:

> “A malicious file was detected on EC2 instance i-0f4a9c21b7d8e63a1.”

This is a **production** payments API. The clock is now ticking.

### L1 — First 10 Minutes (Don’t Panic, Just Move)

1. **Is it production?** → Yes (`Environment=prod` tag). Instant high priority.
2. Pull the full finding (SIEM versions are often watered down):

```bash
aws guardduty get-findings \
  --detector-id 12abc3456789def0123456789abcdef0 \
  --finding-ids 9b6c5d1a7f3e4c2b8d9a0f1e2c3b4a5d \
  --region us-east-1
```

3. Is the instance still alive?

```bash
aws ec2 describe-instances \
  --instance-ids i-0f4a9c21b7d8e63a1 \
  --region us-east-1 \
  --query 'Reservations[0].Instances[0].{State:State.Name,PrivateIp:PrivateIpAddress,Profile:IamInstanceProfile.Arn}'
```

4. What power does this box have? Check the instance profile role, then look at CloudTrail for that role in the last hour.

5. VPC Flow Logs — is it talking to anything weird?

```spl
index=aws_vpc sourcetype=aws:vpcflow src_ip=10.42.17.83
earliest="08/19/2026:13:30:00" latest="08/19/2026:14:30:00"
| stats sum(bytes) as bytes count by dest_ip dest_port action
| sort -bytes
```

**L1 Decision:** Escalate to L2 immediately. Production + malware = no debate.

### L2 — The Real Investigation

Build the timeline. Here’s the synthetic one you should recreate in every lab:

```
13:41  Download from 203.0.113.77
13:42  /tmp/update.bin appears
13:42  Process executes
13:43  Outbound TLS starts
13:56  GuardDuty fires
14:02  You get the ticket
```

**Key questions only L2 asks:**
- Did the binary match any approved release artifact?
- Did the instance role start doing AWS API calls it shouldn’t?
- Is there persistence (cron, systemd, user-data, SSM)?
- Did it touch Secrets Manager, S3, or other instances?

**Pro move:** Always check IMDS / instance-role activity. A malware hit that never touches AWS APIs is bad. One that starts enumerating roles is a five-alarm fire.

**L2 Call:** Full Incident Response. Production malware + live role = game on.

### Containment & Cleanup

- Isolate first (don’t terminate — evidence dies with the instance):

```bash
aws ec2 modify-instance-attribute \
  --instance-id i-0f4a9c21b7d8e63a1 \
  --groups sg-0isolation123456789 \
  --region us-east-1
```

- Snapshot / forensic image
- Rebuild from known-good AMI
- Rotate every secret the role could reach
- Hunt the hash and C2 IP across the org

---

# 📁 CASE 02 — The Stolen Keys
**Finding:** `CredentialAccess:IAMUser/CompromisedCredentials`  
**Identity:** `svc-data-export`  
**Key:** `AKIAEXAMPLE7N4Q`

### The Scene
Someone is using a long-lived access key from a sketchy IP (`198.51.100.42`) and they just did `ListBuckets`.

This is the classic “keys fell out of the pocket” story.

### L1 Quick Hits

```bash
# Is the key even still active?
aws iam list-access-keys --user-name svc-data-export

# What has this key been doing?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=svc-data-export \
  --start-time 2026-08-19T14:30:00Z \
  --end-time 2026-08-19T15:45:00Z
```

SIEM version:

```spl
index=aws_cloudtrail userIdentity.accessKeyId="AKIAEXAMPLE7N4Q"
| stats earliest(_time) as first latest(_time) as last count values(eventName) as actions by sourceIPAddress
```

**Escalate if:** Source is unexpected **or** you see enumeration + data access.

### L2 — Reconstruct the Crime

Synthetic attack sequence (learn this pattern):

```
14:51  GetCallerIdentity
14:51  ListBuckets
14:52  ListRoles + ListPolicies
14:53  GetObject on finance-export
15:17  GuardDuty finally notices
```

This progression (identity check → enum → data) is textbook credential abuse.

**Blast radius hunt:** Search the key across **all regions**. IAM credentials don’t care about regions.

**L2 Call:** Full IR. Disable the key **now**.

```bash
aws iam update-access-key \
  --user-name svc-data-export \
  --access-key-id AKIAEXAMPLE7N4Q \
  --status Inactive
```

Then rotate properly and move the workload to short-lived credentials forever.

---

# 📁 CASE 03 — The 44 GB Heist
**Finding:** `Exfiltration:S3/AnomalousBehavior`  
**Bucket:** `customer-analytics-prod`

### The Scene
Someone just pulled **1,842 objects** (~44 GB) of customer data in 24 minutes from an IP that has never touched this bucket before.

This is the “data is leaving the building” case.

### L1 Focus
- Is the bucket sensitive? Yes.
- Who is the principal?
- How much data actually moved?

```spl
index=aws_cloudtrail s3.bucket.name="customer-analytics-prod" eventName=GetObject
sourceIPAddress="198.51.100.91"
| stats count as objects sum(responseElements.bytesTransferred) as bytes by userIdentity.arn
| eval GB=round(bytes/1024/1024/1024,2)
```

### L2 Reality Check
Normal batch jobs pull 2–4 GB. This one pulled 44 GB from an external IP using an assumed role.

That’s not a batch job. That’s a heist.

**Contain the access path**, rotate the role, quantify exactly what left, and involve data governance / legal if customer data is involved.

---

# 📁 CASE 04 — The Backdoored Lambda
**Finding:** `Backdoor:Lambda/C&CActivity.B`  
**Function:** `invoice-renderer-prod`

### The Scene
A production Lambda just started calling home to a C2 server… and ten minutes earlier someone modified its configuration using a role that is **not** the approved CI/CD pipeline.

This is the “serverless malware” case.

### L1 First Moves
Check when the function last changed:

```bash
aws lambda get-function \
  --function-name invoice-renderer-prod \
  --region eu-west-1 \
  --query '{CodeSha256:Configuration.CodeSha256,LastModified:Configuration.LastModified,Role:Configuration.Role}'
```

Then hunt for unauthorized `UpdateFunctionCode` / `UpdateFunctionConfiguration`.

### L2 Truth
Unauthorized configuration change → C2 traffic = confirmed compromise.

**Containment priority order:**
1. Disable the event source
2. Point the alias back to the last known-good version
3. Rotate every secret the function could reach
4. Hunt for the same unauthorized role across other functions

Never delete the function until you have the evidence.

---

# 📁 CASE 05 — The Database Break-In
**Finding:** `CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce`  
**Database:** `orders-prod-cluster`  
**User:** `reporting_admin`

### The Scene
Four failed logins… then success… then queries against `customer_orders` and `customer_contact`.

This is the “someone just walked into the vault” case.

### L1 Questions
- Is the source IP approved (VPN / bastion / app tier)?
- Did the successful login actually do anything after authenticating?

### L2 Timeline (Golden Pattern)

```
18:04  Failed login ×4
18:04  Successful login
18:05  SELECT customer_orders
18:05  SELECT customer_contact
18:06  Catalog enumeration
```

That’s not a fat-finger. That’s an attacker.

Rotate the credential, block the source network path, preserve the audit logs, and determine how the password was originally obtained.

---

## 🧰 Universal Investigation Checklist (Print This)

**L1 – First 10 minutes**
- [ ] Finding ID + resource + severity recorded
- [ ] Production? Yes/No
- [ ] Principal / role identified
- [ ] Source IP expected?
- [ ] ±60 min CloudTrail window pulled
- [ ] Escalated if compromise can’t be ruled out

**L2 – Expansion**
- [ ] Time window expanded to 24h when credentials involved
- [ ] All regions searched
- [ ] First-seen / last-seen established
- [ ] Persistence & privilege escalation checked
- [ ] Data impact quantified
- [ ] Explicit containment recommendation made

---

## Containment Decision Cheat Sheet

| Situation                        | Contain Now? | Disposition   |
|----------------------------------|--------------|---------------|
| Live C2 or malware on prod       | Yes          | Full IR       |
| Confirmed stolen credentials     | Yes          | Full IR       |
| 40+ GB sensitive data pulled     | Yes          | Full IR       |
| Successful DB brute force        | Yes          | Full IR       |
| Fully explained approved change  | No           | Close/Monitor |

---

## Final Boss Lesson

GuardDuty is just the **doorbell**.  
Your job is to walk through the whole house and see what the burglar actually did.

- EC2 → host → credentials → control plane  
- IAM → API sequence → privilege → data  
- S3 → principal → volume → sensitivity → path  
- Lambda → config change → role → network  
- RDS → auth → source → SQL → impact  

Master the chain and you stop being a ticket-closer and start being a real cloud detective.

---

**Now go break things in your lab (safely) and practice these five cases until they feel like second nature.**

You got this. 🛡️
