# CmdSpoofer (CREATE_NEW_CONSOLE lab variant)

Purple-team lab copy of [yo-yo-yo-jbo/commandline_spoofing](https://github.com/yo-yo-yo-jbo/commandline_spoofing) `CmdSpoofer`, with one change:

`spoofer_CreateDebuggedChild` now creates the child with:

- `DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE` when `bHideConsole == FALSE`
- `DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW` when `bHideConsole == TRUE`

`Main.c` already calls `SPOOFER_Spawn(..., FALSE, FALSE, NULL)`, so the default path uses `CREATE_NEW_CONSOLE` (`0x10`) plus `DEBUG_ONLY_THIS_PROCESS` (`0x2`).

Use this to test whether command-line spoofing still works when detections key on process-creation flags.

## Changed file

`Spoofer.c` only. Look at `spoofer_CreateDebuggedChild`.

## Isolated lab only

Compile and run only in an isolated test VM. Do not run against production systems.
