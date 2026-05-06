# DSCourier: Weaponizing DSC via WinGet COM API for EDR Evasive Execution

**Published**: April 16, 2026  
**Author**: Dylan Davis (dylansec.com)  
**Technique**: Arbitrary code execution using WinGet Configuration COM API  
**Tested Against**: CrowdStrike Falcon, Microsoft Defender for Endpoint, Elastic EDR (as of May 2026)

## 1. Windows Internals - The Basics You Must Understand

Before understanding DSCourier, you need to know these core Windows concepts:

- **WinGet**: Microsoft's official package manager for Windows (pre-installed on Windows 10/11 and Server 2025+).
- **Desired State Configuration (DSC)**: A declarative management platform that uses YAML files to define system state. It can execute PowerShell code through the `PSDscResources/Script` resource.
- **COM (Component Object Model) / WinRT**: Windows' mechanism for inter-process communication. Applications expose COM objects that can be called directly by other programs.
- **Microsoft.Management.Configuration**: The COM interface exposed by WinGet that allows direct interaction with the DSC engine without going through `winget.exe`.
- **WindowsPackageManagerServer.exe** and **ConfigurationRemotingServer.exe**: Legitimate, Microsoft-signed binaries responsible for processing WinGet configurations.

**Important**: Traditional execution (`winget configure`) creates this chain:
`cmd.exe → winget.exe → ConfigurationRemotingServer.exe`

DSCourier **completely bypasses** `winget.exe` and `cmd.exe` by calling the COM interface directly.

## 2. How DSCourier Works (Clean & Simple Explanation)

DSCourier is a C# tool that does the following:

1. Uses `CoCreateInstance` to activate the WinGet Configuration COM object (`Microsoft.Management.Configuration.ConfigurationStaticFunctions`).
2. Loads a specially crafted YAML DSC configuration file.
3. Instructs the COM engine to apply the configuration.
4. The engine spawns `WindowsPackageManagerServer.exe`.
5. Inside it, `ConfigurationRemotingServer.exe` runs.
6. Your malicious PowerShell code (placed in the `SetScript` block) executes **inside** the Microsoft-signed process.

**Key Advantage**: No `powershell.exe`, `pwsh.exe`, `winget.exe`, or `cmd.exe` appears in the process tree — making it very stealthy against EDRs.

## 3. Execution Flow Diagrams

### Diagram 1: Traditional vs DSCourier Process Tree

```mermaid
graph TD
    A[Traditional Method] --> B[cmd.exe / PowerShell.exe]
    B --> C[winget.exe]
    C --> D[ConfigurationRemotingServer.exe]
    D --> E[Malicious Code Runs]

    F[DSCourier (COM Direct Call)] --> G[svchost.exe (DCOM)]
    G --> H[WindowsPackageManagerServer.exe]
    H --> I[ConfigurationRemotingServer.exe]
    I --> J[Malicious Code Runs]

    style A fill:#ff6666
    style F fill:#66cc66
```

### Diagram 2: Detailed Internal Flow

```mermaid
graph TD
    DSC[DSCourier.exe] --> COM[CoCreateInstance → Microsoft.Management.Configuration]
    COM --> Server[WindowsPackageManagerServer.exe]
    Server --> Remoting[ConfigurationRemotingServer.exe]
    Remoting --> Exec[Execute SetScript (PowerShell code)]
```

## 4. Red Team Usage - Step by Step

(Full tactical steps, YAML example, build instructions, OPSEC, and handling PowerShell-blocked environments are included below.)

---

**Full detailed guide continues in the file...**

**GitHub PoC**: https://github.com/DylanDavis1/DSCourier
**Original Research**: https://dylansec.com/DSCourier/
