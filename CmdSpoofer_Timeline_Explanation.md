# CmdSpoofer Timeline – How it Works vs CrowdStrike

Clear explanation of each step in the process.

---

### 1. CmdSpoofer starts
The tool (`CmdSpoofer.exe`) is launched with three arguments:  
- Fake command line  
- Real command line  
- Sleep time (in seconds)

This is the starting point of the entire technique.

---

### 2. CreateProcessW with FAKE command line + DEBUG_ONLY_THIS_PROCESS
The tool calls `CreateProcessW` using the **fake** command line and the flag `DEBUG_ONLY_THIS_PROCESS`.  

This creates the target process in a special debugged state so that CmdSpoofer can control it and later modify its memory.

---

### 3. Process is created in suspended/debugged state
The new process is created but **not yet running normally**.  
It is paused (suspended) and attached to the debugger (CmdSpoofer).  

At this moment, only the fake command line exists.

---

### 4. CrowdStrike captures ProcessCreate event → Records the FAKE command line
This is the critical detection point.  

CrowdStrike’s sensor sees the process creation and records the **fake** command line in its telemetry (ProcessCreate / ProcessRollup event).  

After this point, CrowdStrike usually does **not** re-check the command line.

---

### 5. Sleep / Wait for kernel32.dll to load (RtlpInitParameterBlock finishes)
CmdSpoofer waits (or sleeps) until `kernel32.dll` is loaded into the process.  

This is important because Windows moves and finalizes the process parameters (`RTL_USER_PROCESS_PARAMETERS`) during this stage.  
Waiting ensures the spoof will not be overwritten or cause a crash.

---

### 6. Spoof happens here
This is the actual evasion step:

- Read the PEB of the target process  
- Allocate a new memory buffer  
- Write the **REAL** command line into that buffer  
- Update the `UNICODE_STRING` structure (Length, MaximumLength, and Buffer pointer)

Now the process memory contains the real command line instead of the fake one.

---

### 7. Detach debugger + ResumeThread
CmdSpoofer cleanly detaches from the process (stops debugging it) and calls `ResumeThread`.  

The process is now free to continue execution on its own.

---

### 8. Process continues and executes the REAL command line
The process resumes and runs using the **real** command line that was written in step 6.  

CrowdStrike still has the fake command line recorded from step 4, while the actual execution uses the real one.

---

**Summary**  
CrowdStrike sees the fake command line at creation time (step 4), but the process actually runs the real command line after the spoof (step 8).
