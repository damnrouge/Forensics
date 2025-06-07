# Windows Forensic Artifacts: The Definitive List

## User Activity & Behavior
| Artifact                | Description | Forensic Importance | Path/Registry Key |
|-------------------------|-------------|----------------------|-------------------|
| **Jump Lists**          | Tracks files opened via taskbar apps (Word, Excel, etc.) | Reconstruct document access timeline | `C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` |
| **Shellbags**           | Preserves folder views (size, position) even after deletion | Prove knowledge of folder existence | `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\` |
| **RecentDocs**          | Lists recently accessed documents by file extension | Show user file access patterns | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` |
| **TypedPaths**          | Manually typed Windows Explorer paths | Reveal hidden/network locations | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` |
| **UserAssist**          | ROT13-encoded GUI program execution history | Prove application usage | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` |
| **Notification DB**     | Toast notifications from apps (includes timestamps) | Corroborate activity times | `C:\Users\<USER>\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db` |
| **Clipboard Artifacts** | Windows 10+ clipboard history (text/images) | Recover copied sensitive data | `HKCU\Software\Microsoft\Clipboard` |

## Program Execution Evidence
| Artifact                | Description | Forensic Importance | Path/Registry Key |
|-------------------------|-------------|----------------------|-------------------|
| **Prefetch**            | Execution logs (Win7-10) with run count & timestamps | Prove program execution | `C:\Windows\Prefetch\*.pf` |
| **ShimCache**           | Tracks executable existence (even if deleted) | Identify deleted malware | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` |
| **AmCache**             | Enhanced execution tracking (Win8+) | Newer alternative to Prefetch | `C:\Windows\AppCompat\Programs\Amcache.hve` |
| **Background Activity Moderator (BAM)** | Tracks background app execution (Win10+) | Detect stealthy malware | `HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` |
| **Windows Timeline**    | Cross-device activity history (Win10+) | Full user activity reconstruction | `C:\Users\<USER>\AppData\Local\ConnectedDevicesPlatform\` |

## File System Artifacts
| Artifact                | Description | Forensic Importance | Path/Registry Key |
|-------------------------|-------------|----------------------|-------------------|
| **Thumbcache**          | Thumbnail images (even if originals deleted) | Visual evidence recovery | `C:\Users\<USER>\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db` |
| **Recycle Bin**         | Metadata for deleted files ($I prefix files) | Recover deletion evidence | `C:\$Recycle.Bin\<SID>\` |
| **Windows Search DB**   | Indexed file content (including text searches) | Find hidden data | `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\` |
| **Link Files (LNK)**    | Shortcut files with target MAC times | Prove file access | `C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Recent\` |
| **File History**        | Windows backup versions of files | Recover previous file versions | `C:\Users\<USER>\AppData\Local\Microsoft\Windows\FileHistory\` |

## Network & Internet Activity
| Artifact                | Description | Forensic Importance | Path/Registry Key |
|-------------------------|-------------|----------------------|-------------------|
| **WebCacheV01.dat**     | IE/Edge browsing history, cookies, downloads | Comprehensive internet activity | `C:\Users\<USER>\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat` |
| **Chrome History**      | Chrome browsing data (SQLite format) | Detailed URL tracking | `C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\History` |
| **Firefox Places**      | Firefox browsing history (SQLite) | Alternative browser evidence | `C:\Users\<USER>\AppData\Roaming\Mozilla\Firefox\Profiles\<PROFILE>\places.sqlite` |
| **RDP Cache**           | Bitmaps of remote desktop sessions | Visual proof of RDP activity | `C:\Users\<USER>\AppData\Local\Microsoft\Terminal Server Client\Cache\` |
| **Wi-Fi Profiles**      | Historical wireless network connections | Track physical movement | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\` |

## External Device Forensics
| Artifact                | Description | Forensic Importance | Path/Registry Key |
|-------------------------|-------------|----------------------|-------------------|
| **USBSTOR**             | All connected USB storage devices | Prove device usage | `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\` |
| **SetupAPI Logs**       | Device installation history | Timestamp device connections | `C:\Windows\inf\setupapi.dev.log` |
| **Volume Shadow Copies** | System restore points | Recover previous file states | `C:\System Volume Information\` |
| **Mounted Devices**     | Disk/volume mounting history | Identify external storage | `HKLM\SYSTEM\MountedDevices` |

## System & Logs
| Artifact                | Description | Forensic Importance | Path/Registry Key |
|-------------------------|-------------|----------------------|-------------------|
| **Event Logs**          | Security/System/Application logs | Central investigative timeline | `C:\Windows\System32\winevt\Logs\` |
| **Registry Hives**      | SYSTEM, SOFTWARE, SAM, NTUSER.dat | System configuration & user activity | `C:\Windows\System32\config\` & User profiles |
| **SRUM**                | Resource usage (network, apps, energy) | Correlate activity with data usage | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\` |
| **Pagefile.sys**        | Virtual memory dump | Recover process memory artifacts | `C:\pagefile.sys` |
| **Windows Error Reporting** | Crash reports with memory dumps | Analyze crashed malicious processes | `C:\ProgramData\Microsoft\Windows\WER\` |

## Anti-Forensics Detection
| Artifact                | Description | Forensic Importance | Path/Registry Key |
|-------------------------|-------------|----------------------|-------------------|
| **TimeStomp Indicators** | MFT entry vs $STANDARD_INFO timestamp discrepancies | Detect timestamp manipulation | MFT analysis required |
| **Evidence Eliminator Logs** | Traces of anti-forensic tool usage | Prove intentional destruction | `%Temp%` or AppData folders |
| **Volume Shadow Copy Deletion** | VSS admin logs showing deletion | Identify evidence tampering | Event ID 8222 in Windows Logs |

## Specialized Artifacts
| Artifact                | Description | Forensic Importance | Path/Registry Key |
|-------------------------|-------------|----------------------|-------------------|
| **BitLocker Recovery Keys** | Windows encryption recovery keys | Critical for data access | `AD DS` or `HKCU\Software\Microsoft\BitLocker` |
| **Windows Defender Scans** | Antivirus scan history | Detect known malware | `HKLM\SOFTWARE\Microsoft\Windows Defender\Scan\History\` |
| **Print Spooler Files** | Printed document contents (EMF) | Recover printed documents | `C:\Windows\System32\spool\PRINTERS\` |
| **Windows Update Logs** | Patch installation history | Identify vulnerability windows | `C:\Windows\WindowsUpdate.log` |

## Recommended Tools
- **Registry Analysis**: Registry Explorer, RegRipper
- **Browser Forensics**: Hindsight (Chrome), DB Browser for SQLite
- **Timeline Analysis**: Plaso (log2timeline), KAPE
- **Memory Analysis**: Volatility, Rekall
- **File Carving**: Autopsy, FTK

> **Investigator Notes**:  
> 1. Always check multiple artifacts to corroborate evidence  
> 2. Prioritize volatile data collection first (RAM, running processes)  
> 3. Document hashes of all collected artifacts  

**Last Updated**: 2024-06-15 | **Version**: 2.0  
