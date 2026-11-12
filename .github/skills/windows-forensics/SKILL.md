---
name: windows-forensics
description: "Answer questions about Windows forensic artifacts with concise references to their purpose, location, investigative value, limitations, and corroboration. Use when researching or learning about Windows artifacts or Windows activity."
---

# Windows Forensics

Help the user understand Windows forensic artifacts. When the workspace's [Windows artifact notes](../../../Windows_Forensic_Artifacts.md) are available, consult the relevant section as a starting reference.

Answer the user's specific question first. Include the relevant details from this list, without forcing every heading into answers where it is not useful:

- **What it is**
- **Common location or source**
- **What it may help establish**
- **Limitations and interpretation caveats**
- **Other evidence that could corroborate it**

If the user asks for a keyword or artifact name, explain that item rather than giving an unrelated overview. Expand acronyms and briefly explain unfamiliar terms.

Treat artifacts as clues, not conclusive proof of intent or activity by themselves. Do not present paths, behavior, or timestamp interpretation as universal across Windows versions and configurations. State uncertainty where details depend on the system, and ask for relevant context (such as Windows version) when it would materially change the answer.

Use the workspace notes as a study aid, not unquestionable authority. If the notes are unavailable or do not cover the question, say so plainly. Do not imply you consulted a source you could not access, and do not invent missing details. Give only information you can explain with appropriate confidence; otherwise state what is uncertain and ask a focused follow-up question.

## Example Response

**Prefetch** is a Windows application-startup optimization artifact, commonly found under `C:\Windows\Prefetch\`. Depending on the Windows version and configuration, it may help identify an executable and provide execution-related metadata. Its presence alone does not establish who launched the program or why. Correlate it with process-creation logs, if available, and other independent artifacts.
