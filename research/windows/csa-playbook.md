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
