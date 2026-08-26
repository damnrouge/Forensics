# Cross-Session Activation — Playbook Notes

## Step 1: COM Objects Enumeration

**Goal:** Find COM classes that can be used for Cross-Session Activation.

**Must-have conditions:**
- `RunAs = Interactive User`
- Launch/Activation permissions allow the attacker (preferably Remote Activation)
- COM interface has useful methods for code execution

**Tool:**
```
PermissionHunter.exe -outfile result -outformat xlsx
```
(from COMThanasia)

**Required permission:** Run as **Administrator** (elevated).  
Why: Needs full read of `HKLM\SOFTWARE\Classes\AppID` / `CLSID` and Launch/Access permission ACLs. Standard user gets incomplete results.

**Filter results for:**
- RunAs = Interactive User
- LaunchAccess = Remote Activation
- LaunchPrincipal = Everyone / Administrators / Empty

**Common useful CLSIDs:**
- Speech Runtime → `{38FE8DFE-B129-452B-A215-119382B89E3D}`
- sppui → `{F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}`
- HelpPane / IHxHelpPaneServer
- Auth UI CredUI

**Note:** Not every Interactive User CLSID is usable — the interface must support useful methods.

### Filtered Candidates (from PermissionHunter)

| Priority | AppID | Name | Notes |
|----------|-------|------|-------|
| High | `{1725704B-A716-4E04-8EF6-87ED4F0A180A}` | Speech Runtime COM | Contains known CLSID `{38FE8DFE-B129-452B-A215-119382B89E3D}` |
| High | `{924DC564-16A6-42EB-929A-9A61FA7DA06F}` | Auth UI CredUI | Clean Admin launch + SYSTEM access |
| Medium | `{1111A26D-EF95-4A45-9F55-21E52ADF9887}` | MpUx Agent Host | Clean Admin permissions |
| Medium | `{1D278EEF-5C38-4F2A-8C7D-D5C13B662567}` | Security Health Agent Host | Clean Admin permissions |
| Medium | `{362cc086-4d81-4824-bbb5-666d34b3197d}` | Windows Push Notification | Clean Admin |
| Medium | `{4839DDB7-58C2-48F5-8283-E1D1807D0D7D}` | ShellServiceHost | Clean Admin |
| Medium | `{b21858c6-9711-4257-99c8-5c0084bebce1}` | DockInterface COM server | Clean Admin |
| Medium | `{f59bbec1-0907-4464-b04d-1da329585370}` | ActivatableApplicationRegistrar | Has CLSID |
| Medium | `{37399c92-dc3f-4b55-ae5b-811ee82398ad}` | AppServiceContainerBroker | Clean Admin |
| Low | `{B8C54A54-355E-11D3-83EB-00A0C92A2F2D}` | Windows Media Player | Launch=Everyone but AccessDenied |

**Recommended first targets:**
1. Speech Runtime — `{38FE8DFE-B129-452B-A215-119382B89E3D}`
2. Auth UI CredUI — `{924DC564-16A6-42EB-929A-9A61FA7DA06F}`

---

## Step 2: Session Enumeration

**Requirement:** Cross-Session Activation requires an active interactive user session on the target. In this test an RDP session was used so the victim account remained in an Active state, which was then enumerated on the victim machine before activation.

**Goal:** Identify active interactive sessions and their Session IDs on the target.

**Command (from attacker):**
```bash
quser /server:<TARGET-IP>
```

**Example:**
```bash
quser /server:10.110.0.101
```

**Sample output:**
```
USERNAME              SESSIONNAME        ID  STATE
victim                rdp-tcp#0          3  Active
```

**Notes:**
- Only sessions in **Active** state are reliable targets.
- Session IDs are local to each machine (not unique across the domain).
- Disconnected (Disc) sessions are less reliable for CSA.

---

## Step 3: Remote Registry

**Why it is critical:**  
Remote Registry is required for remote COM hijacking and for many remote CSA tooling paths. It allows the attacker to read/write registry keys on the target (for example to plant COM hijacks under the victim user’s HKCU or to inspect AppID/CLSID permissions). Without it, pure remote registry-based steps fail even if DCOM activation itself works.

**Check status (from attacker):**
```bash
sc \\10.110.0.101 query RemoteRegistry
```

**Start the service:**
```bash
sc \\10.110.0.101 start RemoteRegistry
```

**Enable automatic start (optional):**
```bash
sc \\10.110.0.101 config RemoteRegistry start= auto
sc \\10.110.0.101 start RemoteRegistry
```

**Note:** When using PsExec to run a local PoC already on the target, Remote Registry is less critical. It becomes essential for remote COM hijack + SpeechRuntimeMove-style attacks.
