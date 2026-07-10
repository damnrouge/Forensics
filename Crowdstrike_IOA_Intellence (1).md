# CrowdStrike Custom IOA: complete technical reference

**CrowdStrike Custom IOA rules provide four rule types (Process Creation, File Creation, Network Connection, Domain Name) across three platforms, using RE2-compatible regex matching against a fixed set of fields per rule type, with all populated fields evaluated as AND conditions.** This document serves as a machine-consumable reference for autonomous generation of valid, high-fidelity Custom IOA rules via the Falcon API. The architecture is simpler than many expect — there are no Registry or Service Creation rule types, no hash-based or username fields, and no traditional operators like CONTAINS or STARTS_WITH. Everything runs through regex include/exclude pairs on a defined field schema.

---

## Rule types, platforms, and the architecture that binds them

CrowdStrike Custom IOA supports exactly **4 rule types**, each identified by a platform-specific numeric `ruletype_id`:

| Rule Type | Windows | Linux | Mac | Description |
|---|---|---|---|---|
| Process Creation | `1` | `12` | `5` | Triggers on process execution matching field patterns |
| File Creation | `2` | `13` | `6` | Triggers on file write/creation events |
| Network Connection | `9` | `17` | `10` | Triggers on outbound network connections |
| Domain Name | `11` | `15` | `16` | Triggers on DNS resolution requests |

**Registry Operations, Service Creation, and DNS Request are not available as Custom IOA rule types.** These are handled by CrowdStrike's built-in prevention policy toggles (e.g., `suspicious_registry_operations`, `credential_dumping`, `javascript_via_rundll32`). This is the single most common misconception about Custom IOA capabilities.

### Rule group architecture

Each rule group targets exactly **one platform** (immutable after creation). The assignment chain is: **Rule Group → Prevention Policy → Host Group → Hosts**. A single rule group can be assigned to multiple prevention policies. Policy precedence (lowest number = highest priority) determines the effective policy for a host.

All matching rules fire — this is **not** a first-match system. Multiple rules across multiple groups can match the same event, each generating its own detection. Custom IOA rules **supplement** built-in Falcon detections; they never override them. Custom IOA detections cannot be excluded via the standard IOA Exclusion mechanism — to suppress a false positive, you must modify the rule itself.

### Actions (disposition IDs)

| `disposition_id` | UI Label | Behavior |
|---|---|---|
| `10` | Monitor | Event Search telemetry only (`CustomIOABasicProcessDetectionInfoEvent`); no detection in UI |
| `20` | Detect | Creates a detection in Falcon console; process continues running |
| `30` | Kill Process | Terminates the process and creates a detection |

CrowdStrike recommends a **crawl-walk-run methodology**: Monitor → Detect → Kill Process. Monitor-mode rules are verified via Event Search: `event_simpleName=CustomIOABasicProcessDetectionInfoEvent TemplateInstanceId_decimal=<RULE_ID>`.

### Severity levels

Valid `pattern_severity` values: `critical`, `high`, `medium`, `low`, `informational`. Confidence scores are **not user-assignable** — they are determined by CrowdStrike's backend based on detection context.

---

## Complete field reference with data types and regex applicability

Every rule type shares **6 common excludable fields**. Some types add type-specific fields. All excludable fields accept regex include/exclude pairs. There are no `UserName`, `MD5`, `SHA256`, `HostName`, `LocalAddress`, or `LocalPort` fields — these do not exist in Custom IOA.

### Common fields (all 4 rule types)

| API Field Name | UI Label | Type | Regex | Notes |
|---|---|---|---|---|
| `GrandparentImageFilename` | Grandparent Image Filename | `excludable` | Yes | Full path of grandparent process |
| `GrandparentCommandLine` | Grandparent Command Line | `excludable` | Yes | Command line of grandparent process |
| `ParentImageFilename` | Parent Image Filename | `excludable` | Yes | Full path of parent process |
| `ParentCommandLine` | Parent Command Line | `excludable` | Yes | Command line of parent process |
| `ImageFilename` | Image Filename | `excludable` | Yes | Full path of target process |
| `CommandLine` | Command Line | `excludable` | Yes | Command line of target process |

### File Creation additional fields

| API Field Name | UI Label | Type | Regex | Notes |
|---|---|---|---|---|
| `FilePath` | File Path | `excludable` | Yes | Full path of created file |
| `FileType` | File Type | `set` | No | Multi-select from 46 values |

**FileType valid values (46):** `7ZIP`, `ARC`, `ARJ`, `BMP`, `BZIP2`, `CAB`, `CRX`, `DEB`, `DMP`, `DOCX`, `DWG`, `DXF`, `EARC`, `EML`, `ESE`, `GIF`, `HIVE`, `IDW`, `JAR`, `JCLASS`, `JPG`, `LNK`, `MACHO`, `MSI`, `OLE`, `OOXML`, `PDF`, `PE`, `PNG`, `PPTX`, `PYTHON`, `RAR`, `RPM`, `RTF`, `SCRIPT`, `SLD`, `TAR`, `TIFF`, `VDI`, `VMDK`, `VSDX`, `XAR`, `XLSX`, `ZIP`, `OTHER`

### Network Connection additional fields

| API Field Name | UI Label | Type | Regex | Notes |
|---|---|---|---|---|
| `RemoteIPAddress` | Remote IP Address | `excludable` | Yes | Remote IP address pattern |
| `RemotePort` | Remote Port | `excludable` | Yes | Remote TCP/UDP port pattern |
| `ConnectionType` | Connection Type | `set` | No | Values: `ICMP`, `TCP`, `UDP` |

### Domain Name additional fields

| API Field Name | UI Label | Type | Regex | Notes |
|---|---|---|---|---|
| `DomainName` | Domain Name | `excludable` | Yes | Domain name pattern |

### Platform-specific path differences

Windows paths use backslashes (escaped as `\\` in regex): `.*\\\\powershell\\.exe`. Linux/Mac paths use forward slashes: `.*/bin/bash`. The field schema is **identical across platforms** — only `ruletype_id` values and path conventions differ.

---

## The regex engine: RE2-compatible with critical constraints

CrowdStrike has not officially disclosed the regex engine name, but **all evidence points to RE2 or an RE2-compatible implementation**. The API backend (gofalcon) is Go-based, which uses RE2 natively. The sensor-side matching (C/C++) uses a proprietary engine that accepts RE2-compatible syntax. This has a critical practical implication: **no catastrophic backtracking is possible**, since RE2 guarantees linear-time matching.

### Supported regex features

| Feature | Syntax | Status |
|---|---|---|
| Dot (any char) | `.` | ✅ Confirmed |
| Quantifiers | `*`, `+`, `?`, `{n,m}` | ✅ Confirmed |
| Lazy quantifiers | `*?`, `+?`, `??` | ✅ Supported |
| Character classes | `[a-z]`, `[0-9]`, `[^abc]` | ✅ Supported |
| Perl shorthand | `\d`, `\w`, `\s`, `\D`, `\W`, `\S` | ✅ Supported |
| Anchors | `^`, `$` | ✅ Supported |
| Word boundary | `\b`, `\B` | ✅ Supported |
| Alternation | `\|` | ✅ Confirmed |
| Capturing groups | `(...)` | ✅ Supported |
| Non-capturing groups | `(?:...)` | ✅ Supported |
| Escape sequences | `\\`, `\.` | ✅ Confirmed (heavy use for paths) |
| Inline flags | `(?i)`, `(?m)`, `(?s)` | ✅ Likely (RE2 standard) |
| Named groups | `(?P<name>...)` | ✅ Likely (RE2 standard) |

### Unsupported regex features (RE2 limitations)

| Feature | Syntax | Status |
|---|---|---|
| Lookaheads | `(?=...)`, `(?!...)` | ❌ Not supported |
| Lookbehinds | `(?<=...)`, `(?<!...)` | ❌ Not supported |
| Backreferences | `\1`, `\2` | ❌ Not supported |
| Atomic groups | `(?>...)` | ❌ Not supported |
| Possessive quantifiers | `*+`, `++`, `?+` | ❌ Not supported |
| Conditional patterns | `(?(cond)yes\|no)` | ❌ Not supported |
| Recursive patterns | `(?R)` | ❌ Not supported |

### Case sensitivity and matching behavior

**File path fields (`ImageFilename`, `ParentImageFilename`, etc.) are case-insensitive on Windows**, consistent with the NTFS filesystem. Command line fields may be case-sensitive. Best practice: use `(?i)` prefix or character classes like `[Pp]owershell` for critical case matching. When in doubt, account for both cases.

### Operator model — there are no traditional operators

Custom IOA uses **only regex-based matching** with include/exclude pairs. There is no `CONTAINS`, `STARTS_WITH`, `ENDS_WITH`, `MATCH`, or `IN` operator. To achieve equivalent behavior:

| Desired Operation | Regex Pattern |
|---|---|
| CONTAINS "pattern" | `.*pattern.*` |
| STARTS_WITH "pattern" | `pattern.*` |
| ENDS_WITH "pattern" | `.*pattern` |
| EXACT MATCH | `^pattern$` |
| IN (list of values) | `(value1\|value2\|value3)` |
| NOT (exclusion) | Use the `exclude` label |

### Pattern length and validation constraints

IOA exclusion regex fields are limited to **256 characters** (auto-truncated with `.*` appended). Custom IOA rule fields likely have a similar limit. RE2 rejects counted repetitions `{n,m}` with counts above 1000. The API provides a **validate endpoint** (`POST /ioarules/entities/rules/validate/v1`) to test patterns against test data before deployment. At least one non-exclude field per rule must have an include value that is **not** just `.*`.

---

## API schema and JSON templates for programmatic rule creation

### Authentication

OAuth2 client credentials grant. Token lifetime: **30 minutes**. Required scopes: `custom-ioa:read`, `custom-ioa:write`.

| Region | Base URL |
|---|---|
| US-1 | `https://api.crowdstrike.com` |
| US-2 | `https://api.us-2.crowdstrike.com` |
| EU-1 | `https://api.eu-1.crowdstrike.com` |
| US-GOV-1 | `https://api.laggar.gcw.crowdstrike.com` |

### Core API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/ioarules/entities/rule-groups/v1` | Create rule group |
| GET | `/ioarules/entities/rule-groups/v1` | Get rule groups by ID |
| PATCH | `/ioarules/entities/rule-groups/v1` | Update rule group |
| DELETE | `/ioarules/entities/rule-groups/v1` | Delete rule groups |
| POST | `/ioarules/entities/rules/v1` | Create rule |
| PATCH | `/ioarules/entities/rules/v2` | Update rules (v2, preferred — accepts subset) |
| DELETE | `/ioarules/entities/rules/v1` | Delete rules |
| POST | `/ioarules/entities/rules/validate/v1` | Validate field patterns |
| GET | `/ioarules/queries/rule-groups-full/v1` | Query rule groups with full detail |
| GET | `/ioarules/queries/rule-types/v1` | Get all rule type IDs |
| GET | `/ioarules/entities/rule-types/v1` | Get rule type details |
| GET | `/ioarules/entities/pattern-severities/v1` | Get severity definitions |

### JSON template: create rule group

```json
{
  "comment": "Initial creation",
  "description": "Custom IOA rules for suspicious process activity",
  "name": "Windows Process Monitoring",
  "platform": "windows"
}
```

### JSON template: create rule (Process Creation — full skeleton)

```json
{
  "comment": "Adding detection rule",
  "description": "Rule description here",
  "disposition_id": 20,
  "field_values": [
    {
      "name": "GrandparentImageFilename",
      "label": "Grandparent Image Filename",
      "type": "excludable",
      "values": [{"label": "include", "value": ".*"}]
    },
    {
      "name": "GrandparentCommandLine",
      "label": "Grandparent Command Line",
      "type": "excludable",
      "values": [{"label": "include", "value": ".*"}]
    },
    {
      "name": "ParentImageFilename",
      "label": "Parent Image Filename",
      "type": "excludable",
      "values": [{"label": "include", "value": ".*"}]
    },
    {
      "name": "ParentCommandLine",
      "label": "Parent Command Line",
      "type": "excludable",
      "values": [{"label": "include", "value": ".*"}]
    },
    {
      "name": "ImageFilename",
      "label": "Image Filename",
      "type": "excludable",
      "values": [
        {"label": "include", "value": ".*\\\\target\\.exe"}
      ]
    },
    {
      "name": "CommandLine",
      "label": "Command Line",
      "type": "excludable",
      "values": [
        {"label": "include", "value": ".*suspicious_argument.*"}
      ]
    }
  ],
  "name": "Rule Name Here",
  "pattern_severity": "high",
  "rulegroup_id": "<RULE_GROUP_ID>",
  "ruletype_id": "1"
}
```

### JSON template: Network Connection rule

```json
{
  "comment": "Network rule",
  "description": "Detect suspicious outbound connection",
  "disposition_id": 20,
  "field_values": [
    {"name": "GrandparentImageFilename", "label": "Grandparent Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "GrandparentCommandLine", "label": "Grandparent Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ParentImageFilename", "label": "Parent Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ParentCommandLine", "label": "Parent Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ImageFilename", "label": "Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*\\\\notepad\\.exe"}]},
    {"name": "CommandLine", "label": "Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "RemoteIPAddress", "label": "Remote IP Address", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "RemotePort", "label": "Remote Port", "type": "excludable", "values": [{"label": "include", "value": "^(80|443|4444)$"}]},
    {"name": "ConnectionType", "label": "Connection Type", "type": "set", "values": [{"label": "TCP", "value": "TCP"}]}
  ],
  "name": "Suspicious Outbound from Notepad",
  "pattern_severity": "high",
  "rulegroup_id": "<RULE_GROUP_ID>",
  "ruletype_id": "9"
}
```

### JSON template: File Creation rule

```json
{
  "comment": "File creation rule",
  "description": "Detect PE drop in startup folder",
  "disposition_id": 20,
  "field_values": [
    {"name": "GrandparentImageFilename", "label": "Grandparent Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "GrandparentCommandLine", "label": "Grandparent Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ParentImageFilename", "label": "Parent Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ParentCommandLine", "label": "Parent Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ImageFilename", "label": "Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "CommandLine", "label": "Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "FilePath", "label": "File Path", "type": "excludable", "values": [{"label": "include", "value": ".*(Start Menu|Startup)\\\\.*"}]},
    {"name": "FileType", "label": "File Type", "type": "set", "values": [{"label": "PE", "value": "PE"}, {"label": "SCRIPT", "value": "SCRIPT"}, {"label": "LNK", "value": "LNK"}]}
  ],
  "name": "PE/Script Drop in Startup Folder",
  "pattern_severity": "medium",
  "rulegroup_id": "<RULE_GROUP_ID>",
  "ruletype_id": "2"
}
```

### JSON template: Domain Name rule

```json
{
  "comment": "Domain rule",
  "description": "Detect DNS resolution to known C2 domain",
  "disposition_id": 20,
  "field_values": [
    {"name": "GrandparentImageFilename", "label": "Grandparent Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "GrandparentCommandLine", "label": "Grandparent Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ParentImageFilename", "label": "Parent Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ParentCommandLine", "label": "Parent Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ImageFilename", "label": "Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "CommandLine", "label": "Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "DomainName", "label": "Domain Name", "type": "excludable", "values": [{"label": "include", "value": ".*malicious-domain\\.com"}]}
  ],
  "name": "C2 Domain Resolution",
  "pattern_severity": "critical",
  "rulegroup_id": "<RULE_GROUP_ID>",
  "ruletype_id": "11"
}
```

### Export and import workflow

Export: `GET /ioarules/queries/rule-groups-full/v1` returns full rule group objects with nested rules. Strip computed metadata (`modified_on`, `created_on`, `instance_id`, `pattern_id`, `customer_id`, `version_ids`). Import: create the target rule group first via `POST /ioarules/entities/rule-groups/v1`, then create each rule via `POST /ioarules/entities/rules/v1`. The `rulegroup_version` field is critical for update operations (optimistic locking). Changes propagate to sensors in **up to 40 minutes**.

---

## Coverage matrix: technique to rule type to fields to regex

| MITRE ID | Technique | Rule Type | Key Fields | ImageFilename Include | CommandLine Include | Severity | Confidence |
|---|---|---|---|---|---|---|---|
| T1218.005 | Mshta abuse | Process Creation | ImageFilename + CommandLine | `.*\\mshta\.exe` | `.*(https?://\|vbscript:\|javascript:\|\.hta).*` | High | High |
| T1059.005 | VBScript/JScript | Process Creation | ImageFilename + CommandLine + Parent | `.*\\[wc]script\.exe` | `.*(https?://\|%temp%\|%appdata%\|\.vbs\b\|\.js\b).*` | High | Medium |
| T1218.010 | Regsvr32 Squiblydoo | Process Creation | ImageFilename + CommandLine | `.*\\regsvr32\.exe` | `.*(/s\|/i:).*scrobj\.dll.*` | Critical | Very High |
| T1140 | Certutil decode/download | Process Creation | ImageFilename + CommandLine | `.*\\certutil\.exe` | `.*(-urlcache\|-decode\|-encode\|-decodehex).*` | High | High |
| T1197 | BITS transfer abuse | Process Creation | ImageFilename + CommandLine | `.*\\bitsadmin\.exe` | `.*/transfer\s.*https?://.*` | Medium | Medium |
| T1218.011 | Rundll32 suspicious DLL | Process Creation | ImageFilename + CommandLine | `.*\\rundll32\.exe` | `.*(javascript:\|\\temp\\\|\\appdata\\).*\.dll.*` | High | Medium |
| T1127.001 | MSBuild inline task | Process Creation | ImageFilename + CommandLine + ParentExclude | `.*\\msbuild\.exe` | `.*(\\temp\\\|\\appdata\\).*\.(csproj\|xml).*` | High | High |
| T1218.004 | InstallUtil bypass | Process Creation | ImageFilename + CommandLine | `.*\\InstallUtil\.exe` | `.*/logfile=.*/LogToConsole=false.*` | High | Very High |
| T1053.005 | Scheduled task creation | Process Creation | ImageFilename + CommandLine | `.*\\schtasks\.exe` | `.*/create\s.*(\\temp\\\|\\appdata\\\|powershell\|\.ps1).*` | Medium | Medium |
| T1547.001 | Registry run key (via reg.exe) | Process Creation | ImageFilename + CommandLine | `.*\\reg\.exe` | `.*add\s.*\\CurrentVersion\\Run.*` | High | High |
| T1547.001 | Startup folder drop | File Creation | FilePath + FileType | (any) | (any) | `FilePath: .*(Start Menu\|Startup)\\.*` | Medium |
| T1543.003 | Service install via sc.exe | Process Creation | ImageFilename + CommandLine | `.*\\sc\.exe` | `.*create\s.*binPath=.*` | Medium | Medium |
| T1546.003 | WMI event subscription | Process Creation | ImageFilename + CommandLine | `.*\\(wmic\|powershell)\.exe` | `.*(EventFilter\|EventConsumer\|FilterToConsumerBinding).*` | High | High |
| T1569.002 | PsExec service | Process Creation | ImageFilename | `.*\\PSEXESVC\.exe` | `.*` | High | High |
| T1047 | WMI remote execution | Process Creation | ImageFilename + CommandLine | `.*\\wmic\.exe` | `.*/node:.*process\s+call\s+create.*` | High | High |
| T1003.001 | LSASS dump (procdump) | Process Creation | ImageFilename + CommandLine | `.*\\procdump(64)?\.exe` | `.*(-ma\|-r)\s.*lsass.*` | Critical | Very High |
| T1003.001 | LSASS dump (comsvcs) | Process Creation | ImageFilename + CommandLine | `.*\\rundll32\.exe` | `.*comsvcs\.dll.*MiniDump.*` | Critical | Very High |
| T1003.002 | SAM hive save | Process Creation | ImageFilename + CommandLine | `.*\\reg\.exe` | `.*save\s.*(hklm\\sam\|hklm\\security\|hklm\\system).*` | Critical | Very High |
| T1003.001 | Mimikatz commands | Process Creation | CommandLine | `.*` | `.*(sekurlsa::logonpasswords\|lsadump::dcsync\|kerberos::golden).*` | Critical | Very High |
| T1003.003 | NTDS.dit IFM | Process Creation | ImageFilename + CommandLine | `.*\\ntdsutil\.exe` | `.*(ifm\|create\s+full\|ac\s+i\s+ntds).*` | Critical | High |
| — | Unusual process outbound | Network Connection | ImageFilename + RemotePort | `.*\\(notepad\|calc\|mspaint\|certutil)\.exe` | `RemotePort: ^(80\|443\|4444\|8080)$` | High | High |
| — | DNS-over-HTTPS | Domain Name | DomainName + ImageFilename exclude | ImageFilename exclude: `.*\\(chrome\|firefox\|msedge)\.exe` | `DomainName: .*(dns\.google\|cloudflare-dns\.com).*` | Medium | Medium |
| — | Azure CLI abuse | Process Creation | ImageFilename + CommandLine | `.*(\\az\.cmd\|\\az\.exe)` | `.*az\s+(ad\|role\|keyvault\|vm\s+run-command).*` | Medium | Low |
| — | AWS CLI abuse | Process Creation | ImageFilename + CommandLine | `.*\\aws(\.exe)?` | `.*(sts\s+assume-role\|iam\s+create-user\|ssm\s+send-command).*` | Medium | Low |

---

## Regex pattern library organized by technique category

### LOLBin process matching patterns

```
# Windows executable matching (always anchor with path separator)
.*\\mshta\.exe
.*\\[wc]script\.exe
.*\\regsvr32\.exe
.*\\certutil\.exe
.*\\bitsadmin\.exe
.*\\rundll32\.exe
.*\\msbuild\.exe
.*\\InstallUtil\.exe
.*\\powershell\.exe
.*\\pwsh\.exe
.*\\cmd\.exe
.*\\wmic\.exe

# Linux equivalents
.*/bin/bash
.*/bin/sh
.*/usr/bin/python[23]?
.*/usr/bin/curl
.*/usr/bin/wget
```

### Command-line argument patterns

```
# Encoded PowerShell
.*-[Ee]nc(oded)?[Cc]ommand\s+.*

# PowerShell download cradles
.*(Invoke-WebRequest|Invoke-RestMethod|wget|curl|Net\.WebClient|DownloadString|DownloadFile).*

# Certutil abuse
.*(-urlcache|-decode|-encode|-decodehex|split\s+-f).*

# Regsvr32 Squiblydoo
.*(/s|/i:).*scrobj\.dll.*

# Scheduled task with suspicious path
.*/create\s.*(\\temp\\|\\appdata\\|\\public\\|powershell|\.ps1|\.bat).*

# Registry run key manipulation
.*add\s.*\\CurrentVersion\\Run.*

# Service creation
.*create\s.*binPath=.*

# WMI event subscription keywords
.*(EventFilter|EventConsumer|FilterToConsumerBinding).*

# Mimikatz module commands
.*(sekurlsa::|lsadump::|kerberos::golden|privilege::debug|token::elevate).*

# LSASS dump indicators
.*(-ma|-r)\s.*lsass.*
.*comsvcs\.dll.*MiniDump.*

# SAM/SECURITY/SYSTEM hive save
.*save\s.*(hklm\\sam|hklm\\security|hklm\\system).*

# WMI remote process creation
.*/node:.*process\s+call\s+create.*

# Cloud CLI suspicious operations
.*az\s+(ad|role|keyvault|vm\s+run-command|account\s+get-access-token).*
.*(sts\s+assume-role|iam\s+create-user|ssm\s+send-command).*
.*(auth\s+print-access-token|compute\s+ssh|iam\s+service-accounts\s+keys\s+create).*

# OAuth/OIDC token patterns
.*(grant_type=client_credentials|access_token=|refresh_token=|oauth2/token).*
```

### Network and domain patterns

```
# Suspicious ports for Network Connection rules
^(4444|5555|6666|1337|8888|9999|31337)$
^(80|443|8080|8443)$
^(445|139)$

# IP address generic pattern
\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}

# DNS-over-HTTPS providers for Domain Name rules
.*(dns\.google|cloudflare-dns\.com|doh\.opendns\.com|dns\.quad9\.net).*

# File paths for File Creation rules
.*(Start Menu|Startup)\\.*
.*\\temp\\.*\.(exe|dll|ps1|bat|vbs|js)
.*\\appdata\\.*\.(exe|dll|scr)
```

---

## FP-prone patterns to avoid and anchoring best practices

### Known false-positive generators

- **`.*\\rundll32\.exe` without CommandLine filtering** — fires thousands of times daily on any Windows system. Always combine with a CommandLine include pattern.
- **`.*\\cmd\.exe` with `.*(/c|/k).*`** — most administrative tools and scripts invoke `cmd /c`. Requires parent process context or specific argument matching.
- **`.*\\schtasks\.exe` with `.*(/create).*`** alone — IT automation, GPO, and SCCM create tasks constantly. Must include suspicious path or command arguments.
- **`.*\\powershell\.exe` with `.*-enc.*`** without parent context — management tools (SCCM, Intune, KACE) frequently use encoded commands.
- **`.*\\reg\.exe` with `.*add.*`** without specifying registry path — `reg add` is routine in installers and GPO.
- **`.*\\sc\.exe` without the `create` verb** — `sc query`, `sc start`, `sc stop` are routine operations.
- **Any rule with `ImageFilename include=.*` and `CommandLine include=.*`** — matches every process execution. The API validation rejects this, but combining overly broad patterns in multiple fields still generates excessive noise.

### Anchoring strategies

**Always anchor executable names with the path separator** to avoid substring matches: use `.*\\cmd\.exe` not `.*cmd.*`. For command-line flags, include whitespace context: `.*\s/create\s.*` not `.*/create.*`. Escape dots in filenames: `certutil\.exe` not `certutil.exe`. Use alternation with non-capturing groups for efficiency: `(?:powershell|pwsh)\.exe` rather than separate rules.

### Combining fields for precision (AND logic)

All populated fields within a single rule act as **AND conditions**. This is the primary mechanism for reducing false positives. A rule matching `ParentImageFilename=.*\\winword\.exe` AND `ImageFilename=.*\\cmd\.exe` AND `CommandLine=.*powershell.*` is far more precise than any single-field rule. Three-level process chain matching (grandparent + parent + child) provides the highest fidelity.

### Scoping without a UserName field

Since Custom IOA lacks a `UserName` field, scope rules through:

- **Host groups and sensor grouping tags**: Assign rule groups only to relevant host populations (servers vs. workstations, developers vs. finance)
- **Parent/grandparent process chains**: Use process ancestry to identify execution context
- **Exclude patterns**: Carve out known-good processes via the `exclude` label on any field

---

## Real-world rule examples in full API JSON format

### Example 1: Certutil download/decode abuse (T1140/T1105)

```json
{
  "comment": "Detect certutil misuse for downloading or decoding payloads",
  "description": "Triggers on certutil.exe with -urlcache, -decode, -encode, or -decodehex flags indicating potential payload staging or encoding abuse.",
  "disposition_id": 20,
  "field_values": [
    {"name": "GrandparentImageFilename", "label": "Grandparent Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "GrandparentCommandLine", "label": "Grandparent Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ParentImageFilename", "label": "Parent Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ParentCommandLine", "label": "Parent Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ImageFilename", "label": "Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*\\\\certutil\\.exe"}]},
    {"name": "CommandLine", "label": "Command Line", "type": "excludable", "values": [
      {"label": "include", "value": ".*(-urlcache|-decode|-encode|-decodehex|split\\s+-f).*"}
    ]}
  ],
  "name": "Certutil Download or Decode Abuse",
  "pattern_severity": "high",
  "rulegroup_id": "<RULE_GROUP_ID>",
  "ruletype_id": "1"
}
```

### Example 2: LSASS dump via comsvcs.dll (T1003.001)

```json
{
  "comment": "Critical credential theft detection - comsvcs MiniDump of LSASS",
  "description": "Detects rundll32.exe loading comsvcs.dll with MiniDump export, a known technique for dumping LSASS process memory for credential harvesting.",
  "disposition_id": 30,
  "field_values": [
    {"name": "GrandparentImageFilename", "label": "Grandparent Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "GrandparentCommandLine", "label": "Grandparent Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ParentImageFilename", "label": "Parent Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ParentCommandLine", "label": "Parent Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ImageFilename", "label": "Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*\\\\rundll32\\.exe"}]},
    {"name": "CommandLine", "label": "Command Line", "type": "excludable", "values": [
      {"label": "include", "value": ".*comsvcs\\.dll.*MiniDump.*"}
    ]}
  ],
  "name": "LSASS Dump via comsvcs.dll MiniDump",
  "pattern_severity": "critical",
  "rulegroup_id": "<RULE_GROUP_ID>",
  "ruletype_id": "1"
}
```

### Example 3: Unusual process making outbound connection (Network Connection)

```json
{
  "comment": "Detect LOLBins making outbound TCP connections - strong C2 indicator",
  "description": "Notepad, calc, mspaint, and similar non-network processes making outbound connections indicate process injection or C2 activity.",
  "disposition_id": 20,
  "field_values": [
    {"name": "GrandparentImageFilename", "label": "Grandparent Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "GrandparentCommandLine", "label": "Grandparent Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ParentImageFilename", "label": "Parent Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ParentCommandLine", "label": "Parent Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ImageFilename", "label": "Image Filename", "type": "excludable", "values": [
      {"label": "include", "value": ".*\\\\(notepad|calc|mspaint|write|charmap)\\.exe"}
    ]},
    {"name": "CommandLine", "label": "Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "RemoteIPAddress", "label": "Remote IP Address", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "RemotePort", "label": "Remote Port", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ConnectionType", "label": "Connection Type", "type": "set", "values": [{"label": "TCP", "value": "TCP"}]}
  ],
  "name": "Non-Network Process Outbound Connection",
  "pattern_severity": "high",
  "rulegroup_id": "<RULE_GROUP_ID>",
  "ruletype_id": "9"
}
```

### Example 4: Office spawning script host (macro execution chain)

```json
{
  "comment": "Detect Office application spawning script interpreters - classic macro attack chain",
  "description": "Detects winword.exe, excel.exe, or powerpnt.exe spawning cmd.exe or powershell.exe, indicating potential macro-based initial access.",
  "disposition_id": 20,
  "field_values": [
    {"name": "GrandparentImageFilename", "label": "Grandparent Image Filename", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "GrandparentCommandLine", "label": "Grandparent Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ParentImageFilename", "label": "Parent Image Filename", "type": "excludable", "values": [
      {"label": "include", "value": ".*\\\\(winword|excel|powerpnt|outlook)\\.exe"}
    ]},
    {"name": "ParentCommandLine", "label": "Parent Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]},
    {"name": "ImageFilename", "label": "Image Filename", "type": "excludable", "values": [
      {"label": "include", "value": ".*\\\\(cmd|powershell|pwsh|wscript|cscript|mshta)\\.exe"}
    ]},
    {"name": "CommandLine", "label": "Command Line", "type": "excludable", "values": [{"label": "include", "value": ".*"}]}
  ],
  "name": "Office Application Spawning Script Interpreter",
  "pattern_severity": "high",
  "rulegroup_id": "<RULE_GROUP_ID>",
  "ruletype_id": "1"
}
```

---

## SDK and community tooling reference

### FalconPy (Python)

The official CrowdStrike Python SDK provides complete Custom IOA management via the `CustomIOA` service class. Key methods: `create_rule_group()`, `create_rule()`, `update_rules_v2()`, `delete_rules()`, `validate()`, `query_rule_groups_full()`. Source: `github.com/CrowdStrike/falconpy`.

### PSFalcon (PowerShell)

Official PowerShell module with cmdlets: `New-FalconIoaGroup`, `New-FalconIoaRule`, `Edit-FalconIoaRule`, `Get-FalconIoaRule`, `Export-FalconConfig`, `Import-FalconConfig`. Recent updates added `DescendentProcess` field support. Source: `github.com/CrowdStrike/psfalcon`.

### Terraform Provider

The `crowdstrike_ioa_rule_group` resource manages Custom IOA as infrastructure-as-code. Supports all 4 rule types, all fields, and assignment to prevention policies via `ioa_rule_groups`. Source: `github.com/CrowdStrike/terraform-provider-crowdstrike`.

### Community tools

- **cs-shadowbq/blueteam-ioa-rules** — Export/import scripts (`falcon-export-ioarules.py`, `falcon-import-ioarules.py`) with FQL filtering and rate-limit handling. Best community resource for rule lifecycle management.
- **crazyman62/Crowdstrike_IOA_Clone** — MSSP-focused tool for replicating IOA rules across parent/child tenants with multi-threading support.
- **JohnRequejoLopez/IOACollector** — Template-based IOA rule creation using Jinja2 + YAML, with dry-run mode.
- **CrowdStrike/falcon-mcp** — MCP server connecting AI agents to Falcon, with full Custom IOA CRUD operations.

---

## Conclusion: architectural constraints that shape every rule

The most important insight for autonomous rule generation is that **Custom IOA operates within tight architectural boundaries**: 4 rule types, 6-9 fields per type, regex-only matching (RE2 subset, no lookaheads), and AND logic across fields. There is no registry rule type, no hash-based matching, no username field, and no correlation across events. These constraints mean that the highest-value Custom IOA rules are **process creation rules combining parent-child chains with command-line argument patterns** — this single approach covers the majority of the MITRE ATT&CK matrix detectable through behavioral signatures. Network Connection and Domain Name rules serve as a complementary layer for C2 detection, while File Creation rules cover persistence via startup folder drops and suspicious file staging.

The `disposition_id` progression (10 → 20 → 30) is not optional — deploying a Kill Process rule without soak testing in Monitor/Detect mode risks disrupting production workloads. The 40-minute propagation delay means rules cannot be used for real-time incident response; they are strategic detection instruments, not tactical ones. Every rule should be validated via the API's `validate` endpoint before deployment, and monitored through Event Search using `event_simpleName=CustomIOABasicProcessDetectionInfoEvent` before promotion to higher severity actions.