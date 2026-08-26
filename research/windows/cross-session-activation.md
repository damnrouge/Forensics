With administrative privileges, an attacker can request activation of a COM class configured to run as the interactive user and specify a target user’s session ID, forcing the COM object to be created and executed inside that user’s interactive session.

# Cross-Session Activation (CSA)

**Research topic:** Windows Cross-Session Activation  
**Primary source:** https://ipurple.team/2026/05/04/cross-session-activation/  
**Focus:** Threat research, purple-team validation, detection engineering

## Short Note (Jira / Diagram-Aligned)

**Cross-Session Activation (CSA)** is a Windows COM/DCOM technique that allows a process running in one logon session to activate a COM object inside a **different user’s interactive session** and execute code under that user’s context.

**High-level flow (matches the article diagram):**

1. A COM class (CLSID) is configured with `RunAs = Interactive User`.
2. Attacker calls `CoCreateInstance` to create the COM object.
3. Attacker queries the `ISpecialSystemProperties` interface.
4. Attacker calls `SetSessionId` to target a specific user’s active session.
5. Attacker triggers object instantiation (via `StandardGetInstanceFromIStorage` or equivalent method), causing the COM server to run in the target user’s session.

**Key prerequisites:**
- Administrative privileges (registry modification + remote activation)
- Active interactive session on the target host
- COM class set to run as Interactive User
- Launch/Activation permissions allowing the attacker

**Result:** Code execution occurs in the security context of the logged-on user (instead of the attacker’s session), enabling stealthy lateral movement or session hijacking-style execution through legitimate COM hosts.

This is useful for purple team testing because it abuses native Windows behaviour and can bypass many traditional process-injection detections.

---

## Executive Summary

Cross-Session Activation (CSA) is a Windows COM/DCOM abuse technique that can allow an attacker with elevated privileges to activate a COM object in another user's interactive logon session.

The simplified chain is:

```text
Elevated attacker
      |
      v
Enumerate interactive sessions
      |
      v
Identify suitable COM class
      |
      v
COM/AppID configuration
      |
      v
Activate COM object
      |
      v
Target interactive session
      |
      v
Legitimate COM server
      |
      v
Attacker-controlled execution
```

The detection challenge is that individual components can be legitimate Windows activity. Detection becomes stronger when multiple signals are correlated.

## 1. Important Windows Concepts

### CLSID

A CLSID identifies a COM class. It answers: "Which COM component should be activated?"

### AppID

AppID provides COM/DCOM configuration. A relevant configuration is:

```text
RunAs = Interactive User
```

Relevant registry area:

```text
HKLM\SOFTWARE\Classes\AppID
```

### COM Activation

Applications can request COM objects through APIs such as `CoCreateInstance()`. CSA abuses normal COM activation behavior to influence which interactive session receives the activation.

### Session ID

Windows assigns a session ID to each logon session. For example:

```text
Session 1 -> Alice
Session 2 -> Administrator
```

Session enumeration can involve APIs such as `WTSEnumerateSessions`, `WTSEnumerateSessionsEx`, and `WTSQuerySessionInformation`.

## 2. Attack Flow

### Phase 1 — Elevated Context

CSA generally requires significant privileges. Treat it primarily as post-compromise execution/session abuse rather than a standalone privilege-escalation technique.

### Phase 2 — Enumerate Sessions

An attacker identifies logged-in users and their session IDs. A common administrative command is:

```text
quser
```

Example:

```text
SESSIONNAME    USERNAME        ID
console        alice           1
rdp-tcp#2      administrator   2
```

**Detection:** monitor unusual processes that enumerate session information, especially when followed by COM activity.

### Phase 3 — Identify Suitable COM Objects

The attacker looks for COM classes with useful properties, including:

```text
RunAs = Interactive User
Suitable activation permissions
Useful COM interface/server behavior
```

Not every Interactive User COM class is exploitable.

### Phase 4 — COM Hijacking

CSA can be combined with COM hijacking:

```text
CLSID
  |
  v
Modified COM registration
  |
  v
Attacker-controlled component
```

CSA and COM hijacking are related but should not automatically be treated as the same technique. If registry registration is changed to redirect a CLSID, T1546.015 is relevant.

### Phase 5 — Session-Targeted Activation

The research describes a COM activation sequence involving COM interfaces and session selection, conceptually:

```text
CoCreateInstance()
       |
       v
QueryInterface()
       |
       v
Session-related COM interface
       |
       v
SetSessionId()
       |
       v
Target interactive session
       |
       v
COM activation
```

### Phase 6 — Execution in the Target Session

The resulting process tree can resemble:

```text
Target session
  |
  +-- Legitimate COM server
          |
          +-- Attacker-controlled process
```

The attacker can therefore make legitimate Windows infrastructure participate in execution.

## 3. HelpPane Example

HelpPane is one of the COM server examples discussed in the research.

A normal relationship can include browser-related processes:

```text
HelpPane.exe
    +-- msedge.exe
```

Suspicious relationships include:

```text
HelpPane.exe
    +-- cmd.exe
    +-- powershell.exe
    +-- rundll32.exe
    +-- regsvr32.exe
    +-- wscript.exe
    +-- cscript.exe
    +-- unknown.exe
```

Do not alert on HelpPane alone. The child process and surrounding session/COM context provide the detection value.

## 4. Local vs Remote CSA

### Local

```text
Host
 |
 +-- Session 1 -> User A
 |
 +-- Session 2 -> User B
             ^
             |
       COM activation
```

### Remote

```text
Attacker
   |
   | Remote management / DCOM-related activity
   v
Target host
   |
   +-- Interactive session
          |
          v
      COM activation
```

Remote scenarios can add WMI, DCOM, Remote Registry, network authentication, and process-creation telemetry.

## 5. Detection Opportunities

### Session Enumeration

Look for suspicious use of:

```text
WTSEnumerateSessions
WTSEnumerateSessionsEx
WTSQuerySessionInformation
```

Treat this as a supporting signal rather than a standalone alert.

### COM Registry Access

Monitor relevant locations:

```text
HKLM\SOFTWARE\Classes\CLSID
HKLM\SOFTWARE\Classes\AppID
```

Useful operations include:

```text
CreateSubKey
SetValue
Delete
WriteDAC
```

### Interactive User Configuration

Unexpected changes involving:

```text
RunAs = Interactive User
```

should receive elevated attention when correlated with suspicious COM activity.

### Cross-Session Execution

Compare parent and child session IDs:

```text
Parent Session ID != Child Session ID
```

This is particularly valuable when combined with COM-related processes and an elevated caller.

### Suspicious COM Server Children

High-value patterns include:

```text
HelpPane.exe -> cmd.exe
HelpPane.exe -> powershell.exe
HelpPane.exe -> rundll32.exe
HelpPane.exe -> regsvr32.exe
HelpPane.exe -> wscript.exe
HelpPane.exe -> unknown executable
```

## 6. Telemetry

| Telemetry | Detection value |
|---|---|
| Windows 4688 | Process creation |
| Windows 4663 | Object/registry access where auditing is configured |
| EDR process telemetry | Process tree and command line |
| EDR session information | Source/target session |
| Registry telemetry | CLSID/AppID modifications |
| WMI telemetry | Remote execution context |
| Network telemetry | Remote activation context |
| Service telemetry | RemoteRegistry and related activity |

## 7. Splunk / RBA Detection Strategy

Use multiple detections rather than one broad rule.

### Rule 1 — Suspicious COM Registry Modification

```text
Target: CLSID/AppID registry locations
AND
Operation: SetValue / CreateSubKey / Delete / WriteDAC
AND
Actor: unusual process or account
```

Suggested risk: **+30**

### Rule 2 — Interactive User COM Configuration

```text
COM/AppID configuration changed
AND
RunAs = Interactive User
```

Suggested risk: **+40**

### Rule 3 — Suspicious COM Server Child

```text
Parent: HelpPane.exe
Child: cmd.exe / powershell.exe / rundll32.exe /
       regsvr32.exe / wscript.exe / cscript.exe / unknown
```

Suggested risk: **+60**

### Rule 4 — Cross-Session Execution

```text
Parent Session ID != Child Session ID
AND
COM-related process
```

Suggested risk: **+50**

### Rule 5 — Remote Activation Chain

Correlate:

```text
RemoteRegistry
    +
WMI/DCOM
    +
COM server execution
    +
Process creation
```

Suggested risk: **+70**

## 8. Recommended Correlation

```text
Session Enumeration
        |
        v
COM/CLSID Discovery
        |
        v
Registry Modification
        |
        v
COM Activation
        |
        v
Session Transition
        |
        v
COM Server Execution
        |
        v
Suspicious Child Process
        |
        v
     HIGH RISK
```

The strongest analytic is:

> Elevated context + session enumeration + COM configuration/activation + cross-session execution + abnormal child process.

## 9. MITRE ATT&CK Mapping

### T1021.003 — Distributed Component Object Model

Relevant when DCOM is used for remote execution/lateral movement.

### T1546.015 — Component Object Model Hijacking

Relevant when COM registration is modified to redirect execution to attacker-controlled code.

Do not automatically map every CSA event to COM Hijacking. The registry-hijacking behavior must actually occur.

## 10. Purple-Team Validation Plan

### Phase 1 — Baseline

Collect:

```text
4688
4663
EDR process events
EDR session IDs
Registry telemetry
WMI telemetry
RemoteRegistry telemetry
Network telemetry
```

Establish normal process trees for HelpPane and other candidate COM servers.

### Phase 2 — Controlled Simulation

Use an isolated lab and begin with benign execution such as `calc.exe`. Validate:

```text
Session enumeration
       |
       v
COM activation
       |
       v
Target session
       |
       v
Benign process
```

### Phase 3 — Detection Validation

The investigation should identify:

```text
WHO?             Account
WHERE?            Host
SOURCE SESSION?   Session ID
TARGET SESSION?   Session ID
WHAT COM OBJECT?  CLSID/AppID
WHAT SERVER?      Process
WHAT CHILD?       Process tree
REGISTRY CHANGED? Path + operation
REMOTE?           Source/context
WHEN?             Timestamp
```

## 11. Investigation Checklist

- [ ] Identify initiating user/account.
- [ ] Determine whether the process had elevated privileges.
- [ ] Determine source and target session IDs.
- [ ] Review session enumeration activity.
- [ ] Identify CLSID/AppID involved.
- [ ] Review recent COM registry modifications.
- [ ] Check for `RunAs=Interactive User`.
- [ ] Identify the COM server process.
- [ ] Inspect the complete process tree.
- [ ] Identify suspicious child processes.
- [ ] Check WMI/DCOM/RemoteRegistry activity.
- [ ] Check remote authentication.
- [ ] Check for COM hijacking persistence.
- [ ] Map the complete chain to ATT&CK.
- [ ] Correlate preceding credential-access or privilege-escalation activity.

## References

- iPurple — Cross-Session Activation: https://ipurple.team/2026/05/04/cross-session-activation/
- MITRE ATT&CK — T1021.003 Distributed Component Object Model
- MITRE ATT&CK — T1546.015 Component Object Model Hijacking
- Microsoft Windows Security Event ID 4688 and 4663 documentation
