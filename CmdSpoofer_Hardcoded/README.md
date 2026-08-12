# CmdSpoofer – Hardcoded Version

This is a modified version of the original CmdSpoofer for testing against **CrowdStrike Custom IOA**.

### Purpose
The fake and real command lines are **hardcoded** inside `Main.c` so that the launcher process itself does not contain the suspicious string in its command line.

### Current Hardcoded Values

- **Fake (what CrowdStrike sees):**  
  `C:\Windows\System32\cmd.exe /c echo hello`

- **Real (what actually executes):**  
  `C:\Windows\System32\cmd.exe /c wwwww`

- **Sleep:** 4 seconds

### How to use

1. Replace the original `Main.c` with the one in this folder.
2. Rebuild the project in Visual Studio (x64 - Release).
3. Run simply:

```cmd
CmdSpoofer.exe
```

No arguments needed.

### Changing the commands

Edit these two lines in `Main.c`:

```c
PCWSTR pwszFakeCommandline = L"C:\\Windows\\System32\\cmd.exe /c echo hello";
PCWSTR pwszRealCommandline = L"C:\\Windows\\System32\\cmd.exe /c wwwww";
```
