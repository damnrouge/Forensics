# 🔍 Windows Forensic Artifacts – Detailed Reference

This guide provides comprehensive details on **key Windows forensic artifacts**, including:

- 📄 What they are
- 🔍 Why they're important
- 🎯 When to use them during an investigation

---

## 📁 1. SYSTEM INFORMATION ARTIFACTS

### 🧠 Registry Hives  
- **Path:** `C:\Windows\System32\config\`  
- **Key Hives:** `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`
- **What:** Contains all critical system configurations and user data.
- **Use Case:**  
  - 🎯 When analyzing system persistence, startup programs, or security policies.
  - 🧑‍💻 Used to extract user accounts (SAM), installed software (SOFTWARE), and time zone settings (SYSTEM).

---

### 🖥️ SystemInfo Command  
- **Tool:** `systeminfo` (CMD)
- **What:** Provides OS details, uptime, installed hotfixes, domain info.
- **Use Case:**  
  - 🎯 Establishes host baseline during IR.
  - 🔥 Useful in malware IR to verify privilege escalation or recent patch application.

---

### ⚡ Prefetch Files  
- **Path:** `C:\Windows\Prefetch\`  
- **What:** Stores metadata about executed programs (executable name, run count, last run time).
- **Use Case:**  
  - 🎯 Critical in identifying programs executed before a system crash or breach.
  - 👣 Helps track lateral movement or execution of suspicious tools.

---

## 👤 2. USER ACTIVITY ARTIFACTS

### 👀 UserAssist  
- **Registry Key:** `NTUSER.DAT > Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
- **What:** Tracks GUI-based program execution, encoded in ROT13.
- **Use Case:**  
  - 🎯 Timeline of user interaction.
  - 🧩 Useful in insider threat investigations or to validate alibi claims.

---

### 📄 RecentDocs  
- **Registry Key:** `NTUSER.DAT > ...\Explorer\RecentDocs`
- **What:** Tracks recently opened documents per file extension.
- **Use Case:**  
  - 🎯 Verify if sensitive documents were accessed.
  - 📂 Prove data theft or access before deletion.

---

### 🧷 Jump Lists  
- **Path:** `AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`  
- **What:** Per-application recent file access history.
- **Use Case:**  
  - 🎯 Shows exact files used in Word, Excel, etc.
  - 🔍 Useful in data leak or intellectual property cases.

---

### 🧳 Shellbags  
- **Registry:** `NTUSER.DAT`, `USRCLASS.DAT`
- **What:** Records folder access and view settings.
- **Use Case:**  
  - 🎯 Reconstruct folder access even if directory is deleted.
  - 🛠️ Effective in tracking use of removable drives.

---

### 🔠 TypedPaths  
- **Registry Key:** `Explorer\TypedPaths`
- **What:** Stores Explorer address bar inputs.
- **Use Case:**  
  - 🎯 Confirms manual folder navigation.
  - 🧪 Can indicate reconnaissance behavior.

---

### ▶️ RunMRU  
- **Registry Key:** `Explorer\RunMRU`
- **What:** History of commands typed into the Run dialog.
- **Use Case:**  
  - 🎯 Evidence of manual tool or script execution.
  - 🛠️ Often used in privilege escalation scenarios.

---

### 🌐 Browser History  
- **Path:** Browser-specific (e.g., Chrome's SQLite files, IE index.dat)
- **What:** URLs visited, download history, cookies.
- **Use Case:**  
  - 🎯 Confirm access to C2 domains or file downloads.
  - 🌍 Useful in phishing or web shell cases.

---

## 🕓 3. TIMESTAMPS & METADATA

### 📁 $MFT (Master File Table)  
- **What:** Tracks all NTFS file metadata (create, modify, access).
- **Use Case:**  
  - 🎯 Timeline building.
  - 🛠️ Proving file creation prior to timestamp manipulation.

---

### 🔁 $LogFile  
- **What:** NTFS transactional journal of file system changes.
- **Use Case:**  
  - 🎯 Evidence of file movement/deletion even if MFT is cleared.
  - 🔍 Deep forensic timeline validation.

---

### 📈 $UsnJrnl  
- **Path:** `C:\$Extend\$UsnJrnl`
- **What:** Tracks file changes across the volume.
- **Use Case:**  
  - 🎯 Detect deleted malware or exfiltrated files.
  - 🧠 Ideal in ransomware response cases.

---

### 🔗 LNK Files  
- **Path:** `C:\Users\<User>\AppData\Roaming\Microsoft\Windows\Recent\`
- **What:** Shortcuts created when a file is opened. Stores path, timestamps, and volume serial.
- **Use Case:**  
  - 🎯 Tracks file access even after deletion.
  - 🧷 Common in attribution and lateral movement tracking.

---

## 🌐 4. NETWORK & REMOTE ACCESS

### 🧩 RDP Cache / Default.rdp  
- **Path:** `Documents\Default.rdp`
- **What:** Cached settings of previous RDP connections.
- **Use Case:**  
  - 🎯 Identify lateral movement via RDP.
  - 🔍 Validate remote access attempts.

---

### 🧪 Terminal Services Registry Keys  
- **Registry:** `HKCU\Software\Microsoft\Terminal Server Client\Servers`
- **What:** Stores manually entered RDP IPs/hosts.
- **Use Case:**  
  - 🎯 Reveal attacker-controlled or internal pivot points.

---

### 🔥 Firewall Logs  
- **Path:** `C:\Windows\System32\LogFiles\Firewall\pfirewall.log`
- **What:** Logs blocked/allowed inbound/outbound connections.
- **Use Case:**  
  - 🎯 Detect beaconing or exfiltration attempts.
  - 🧱 Identify attack vectors and blocked threats.

---

### 🌐 DNS Cache  
- **Tool:** `ipconfig /displaydns`
- **What:** Lists recently resolved domain names.
- **Use Case:**  
  - 🎯 Identify C2 or phishing domains contacted.
  - 📡 Validate timeline against proxy/DNS logs.

---

## 🧰 5. EXECUTION ARTIFACTS

### 🗃️ Amcache.hve  
- **Path:** `C:\Windows\AppCompat\Programs\Amcache.hve`
- **What:** Stores metadata of executed binaries.
- **Use Case:**  
  - 🎯 Detect deleted executables.
  - 🧩 Correlate hash with malware databases.

---

### 📚 Shimcache (AppCompatCache)  
- **Registry:** `SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache`
- **What:** Stores file execution metadata (but not time).
- **Use Case:**  
  - 🎯 Determine past binary execution.
  - ⚠️ Often used in APT attribution and long-term intrusion analysis.

---

### 📊 SRUM (System Resource Usage Monitor)  
- **Path:** `C:\Windows\System32\sru\SRUDB.dat`
- **What:** Tracks network usage, app runtime, energy use.
- **Use Case:**  
  - 🎯 Confirm timeframes of malware activity.
  - 🧭 Effective in covert tool detection (e.g., Cobalt Strike beacons).

---

### 🕓 Scheduled Tasks  
- **Path:** `C:\Windows\System32\Tasks\`
- **What:** Task definitions and timings.
- **Use Case:**  
  - 🎯 Spot persistence mechanisms.
  - ⏲️ Detect stealthy recon jobs or scheduled reverse shells.

---

## 🖥️ 6. SERVICES & PERSISTENCE

### 🧩 Services Registry  
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Services`
- **What:** Lists all services and startup drivers.
- **Use Case:**  
  - 🎯 Detect malicious or renamed services.
  - 🧱 Key to rootkit or kernel-mode analysis.

---

### 🧰 Autoruns Entries  
- **Tool:** Sysinternals Autoruns
- **What:** Collects all known auto-start locations.
- **Use Case:**  
  - 🎯 Catch hidden persistence.
  - 🔦 Spot suspicious DLLs or registry entries.

---

### 🚀 Startup Folder  
- **Path:** `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
- **What:** Programs launched at login.
- **Use Case:**  
  - 🎯 Spot quick and dirty persistence.
  - 🗂️ Malware dropped here often by phishing payloads.

---

## 📑 7. EVENT LOGS

### 📜 Windows Logs (.evtx)  
- **Location:** `C:\Windows\System32\winevt\Logs\`
- **Key Logs:**
  - `System.evtx`
  - `Security.evtx`
  - `Application.evtx`
  - `PowerShell/Operational.evtx`
  - `WMI-Activity.evtx`
- **Use Case:**
  - 🎯 Logon attempts, process creation (Event ID 4688), PowerShell usage (4104), WMI abuse.
  - 🛡️ Baseline system behavior and detect anomalies.

---

### 🛡️ Sysmon Logs (If installed)  
- **Tool:** Sysinternals Sysmon  
- **What:** Rich telemetry of process creation, network, file events.
- **Use Case:**  
  - 🎯 High-fidelity detection of attacker behavior.
  - ⚔️ Essential for threat hunting and purple teaming.

---

## 💽 8. MEMORY & VOLATILE ARTIFACTS

### 🧠 Memory Dump  
- **Tools:** FTK Imager, DumpIt, Belkasoft RAM Capturer  
- **What:** Live snapshot of memory (processes, DLLs, passwords).
- **Use Case:**  
  - 🎯 Investigate in-memory malware, credential dumping.
  - ⚠️ Crucial in ransomware, RAT investigations.

---

### 💾 Pagefile.sys  
- **Path:** `C:\pagefile.sys`  
- **What:** Stores swapped-out memory data.
- **Use Case:**  
  - 🎯 Recover memory-resident malware or commands post-reboot.

---

### 🔒 Hiberfil.sys  
- **Path:** `C:\hiberfil.sys`  
- **What:** RAM snapshot from system hibernation.
- **Use Case:**  
  - 🎯 Postmortem forensics.
  - ⏪ Roll back volatile memory state during IR.

---

## 🔐 9. CREDENTIALS & SECRETS

### 🧬 SAM Hive  
- **Path:** `C:\Windows\System32\config\SAM`
- **What:** Encrypted user account names and password hashes.
- **Use Case:**  
  - 🎯 Credential theft investigation.
  - ⚠️ Use with SYSTEM key for hash extraction.

---

### 🧬 LSASS Memory  
- **Tool:** DumpIt, ProcDump  
- **What:** Holds plaintext passwords, Kerberos tickets, tokens.
- **Use Case:**  
  - 🎯 Detect credential dumping (Mimikatz, etc.).
  - 🧪 Red vs Blue training (T1003.001 - MITRE).

---

### 🔑 Vault Credentials  
- **Path:** `AppData\Local\Microsoft\Vault\`  
- **What:** Windows Credential Manager storage.
- **Use Case:**  
  - 🎯 Extract web or RDP saved credentials.
  - 📂 Confirm attacker password reuse.

---

## 🧪 10. MISCELLANEOUS

### 📁 Temp Files  
- **Path:** `%TEMP%`, `C:\Temp`  
- **What:** Storage for installers, scripts, payloads.
- **Use Case:**  
  - 🎯 Recover initial dropper or artifacts missed by AV.
  - 🧹 Indicator of attacker sloppiness.

---

### ⬇️ Downloads Folder  
- **Path:** `C:\Users\<User>\Downloads`  
- **What:** Legit and malicious file staging area.
- **Use Case:**  
  - 🎯 Validate lure delivery in phishing.
  - 💡 Prove user interaction with attacker payload.

---

### 🗃️ 7zip/WinRAR History  
- **Registry Path:** App-specific  
- **What:** Recently archived/extracted files and paths.
- **Use Case:**  
  - 🎯 Trace data exfiltration via archives.
  - 🧩 Track attack staging before compression.

---

## ✅ Summary Matrix

| Category | Artifact | Use Case |
|----------|----------|----------|
| Execution | Prefetch, Shimcache, SRUM | Track what ran & when |
| Persistence | Services, Tasks, Autoruns | Identify long-term foothold |
| Network | DNS, RDP, Firewall | Trace C2 and lateral movement |
| Credentials | LSASS, SAM, Vault | Detect stolen access |
| User Activity | UserAssist, Shellbags | Profile attacker or insider |
| Volatile | Memory, Pagefile | Recover live/resident malware |
| Logs | Sysmon, Event Logs | Correlate full timeline |

---
**📌 Use this guide for:**
- Rapid triage during IR
- Timeline reconstruction
- Threat hunting
- Red team validation
- Memory forensics

