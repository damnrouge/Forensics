# Command-Line Spoofing on Windows
### Purple Team Technical Manual
**Technique Reference:** [yo-yo-yo-jbo/commandline_spoofing](https://github.com/yo-yo-yo-jbo/commandline_spoofing)  
**Focus:** Evasion testing against CrowdStrike Falcon  
**Architecture:** Native x64 only  
**Last Updated:** 12 August 2026

---

## How the Tool Works – Clear Timeline

This is the most important section. Here is exactly what happens, step by step:

### Timeline (Visual)

**Figma Diagram:** [CmdSpoofer Timeline - How it Works vs CrowdStrike](https://www.figma.com/board/rnYGQfMZvqURwi6Q1EJQNo)

```
1. CmdSpoofer starts
         ↓
2. CreateProcessW(FAKE command line + DEBUG_ONLY_THIS_PROCESS)
         ↓
3. Process is created (still suspended / under debugger)
         ↓
4. ★ CrowdStrike captures ProcessCreate event
   → Records the FAKE command line
         ↓
5. Tool waits until kernel32.dll is loaded
   (RtlpInitParameterBlock has finished)
         ↓
6. ★ SWAP HAPPENS HERE
   - Read PEB
   - Allocate new memory
   - Write the REAL command line
   - Update Length / MaximumLength / Buffer
         ↓
7. Detach debugger + ResumeThread
         ↓
8. Process continues and executes the REAL command line
```

### Simple English Explanation

1. The tool starts a new process using the **fake** (clean) command line and attaches as a debugger.
2. Because the process is created with `DEBUG_ONLY_THIS_PROCESS`, CrowdStrike sees the creation event and records the **fake** command line.
3. The tool waits until `kernel32.dll` is loaded. This is the moment when Windows has finished moving the process parameters to the process heap.
4. **At this exact point** the tool rewrites the command line inside the process memory to the **real** one.
5. The tool detaches the debugger and resumes the process.
6. The process now runs using the **real** command line, but CrowdStrike already logged the fake one.

---

## Successful Lab Result (12 Aug 2026)

**Command used:**
```cmd
CmdSpoofer.exe "C:\Windows\System32\cmd.exe /c notepad.exe" "C:\Windows\System32\cmd.exe /c calc.exe" 3
```

| What CrowdStrike Saw                    | What Actually Happened     |
|-----------------------------------------|----------------------------|
| `cmd.exe /c notepad.exe`                | Calculator (`calc.exe`) opened |

This confirmed that:
- The fake command line was captured by Falcon
- The real command line was executed successfully

---

## Detailed Internal Working of CmdSpoofer

### Phase 1 – Create Debugged Process
- Calls `CreateProcessW` with the **fake** command line
- Flag used: `DEBUG_ONLY_THIS_PROCESS`
- Process starts suspended under the debugger

### Phase 2 – Wait for Safe Moment
- Loops on `WaitForDebugEvent`
- Waits until `kernel32.dll` is loaded (compared by base address)
- This guarantees `RtlpInitParameterBlock` has already run

### Phase 3 – The Swap (Core of the Technique)
1. `NtQueryInformationProcess` → get PEB address
2. Read the `RTL_USER_PROCESS_PARAMETERS`
3. Zero the old command-line buffer
4. `VirtualAllocEx` → allocate new memory for the real command line
5. Write the real command line into the new buffer
6. Update the three fields of the `UNICODE_STRING`:
   - `Length`
   - `MaximumLength`
   - `Buffer` (points to the new allocation)
7. Write the updated `UNICODE_STRING` back into the remote process

### Phase 4 – Clean Exit
- Suspend the main thread
- Drain remaining debug events
- `DebugActiveProcessStop`
- `ResumeThread`

After this point the process continues with the **real** command line.

---

## Why the Length Limitation Exists (and how we bypass it)

- Classic method only works if real command line ≤ fake command line (because it overwrites the existing buffer).
- If you try to allocate a new buffer too early, `RtlpInitParameterBlock` later “fixes” the pointers and the process crashes.
- By waiting until after `kernel32.dll` is loaded, the tool can safely allocate a completely new buffer of any size.

---

## Practical Usage

```cmd
CmdSpoofer.exe "<fake command line>" "<real command line>" <sleep_seconds>
```

**Rules:**
- Both command lines must start with the full path of the executable
- The process image is determined by the **fake** command line
- Sleep value of 2–5 seconds is usually enough for Falcon to capture the creation event

**Working examples:**

```cmd
:: Basic proof
CmdSpoofer.exe "C:\Windows\System32\cmd.exe /c echo FAKE" "C:\Windows\System32\cmd.exe /c echo REAL & pause" 3

:: Notepad (seen by CS) → Calculator (actually runs)
CmdSpoofer.exe "C:\Windows\System32\cmd.exe /c notepad.exe" "C:\Windows\System32\cmd.exe /c calc.exe" 3
```

---

## Detection Opportunities

Even though the creation event contains the fake command line, residual signals remain:

- Process was started under a debugger (`DEBUG_ONLY_THIS_PROCESS`)
- Short period of suspension / debug events
- New private memory allocation containing the real command line
- Mismatch between the command line recorded at creation time and the command line visible later in the PEB / Process Explorer

---

## References

- Original research: https://github.com/yo-yo-yo-jbo/commandline_spoofing
- Figma Timeline: https://www.figma.com/board/rnYGQfMZvqURwi6Q1EJQNo
- Related deep dive: https://l--k.uk/2022/03/05/command-line-tampering-in-windows-part-iii/

---

*Document maintained for purple team / detection engineering use only.*
