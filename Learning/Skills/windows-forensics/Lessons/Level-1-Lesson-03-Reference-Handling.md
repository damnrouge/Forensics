# Level 1 — Lesson 3: Handle References Reliably

## Goal

Learn to link a skill to workspace notes correctly, decide what to do when those notes are missing or incomplete, and keep answers useful without pretending a source says more than it does.

## What changed since Lesson 2

The working skill now:

- Treats the workspace artifact notes as a starting reference, not unquestionable authority.
- Tells the agent to be clear when the notes are unavailable or do not cover the question.
- Avoids claiming it consulted a source it could not access or filling gaps with invented details.
- Uses only the answer details that fit the user's question, rather than forcing every heading into every response.
- Asks for context, such as Windows version, when that could change the answer.

## Relative links: a small path exercise

The active skill lives at:

`.github/skills/windows-forensics/SKILL.md`

The artifact notes live at:

`Windows_Forensic_Artifacts.md`

To write a relative path from the skill folder to the repository root, go up three directories:

1. `windows-forensics` → `skills` with `..`
2. `skills` → `.github` with `..`
3. `.github` → repository root with `..`

Then name the file. The resulting link is:

`../../../Windows_Forensic_Artifacts.md`

The link in the skill is relative to the skill file. If you move either file, recalculate and verify the link instead of assuming it still works.

## Source handling rules

When using a reference:

1. Check that the referenced file exists and open the relevant section.
2. Separate what the reference explicitly says from what you infer.
3. Look for caveats and avoid turning a study note into a universal claim.
4. If the file is missing or silent on the question, be transparent. Do not say “the notes state” unless they actually do.
5. If a reliable answer needs more context, ask a focused question or clearly state the uncertainty.

## Practice

Suppose a user asks about an artifact that is not covered in `Windows_Forensic_Artifacts.md`.

Which response follows the skill better?

**A.** “The notes confirm this artifact proves the user ran the program.”

**B.** “I don’t see this artifact covered in the workspace notes. I can explain what I know, but the interpretation depends on the Windows version; which version are you investigating?”

**Check:** B is better. It is honest about the source, avoids treating an artifact as proof, and asks for context that may matter. If the agent does not know enough to explain the artifact reliably, it should say so rather than guess.

## Test checklist

- [ ] Confirm the reference path resolves from the skill folder.
- [ ] Ask about an artifact that is covered by the notes; check that the answer is relevant and appropriately qualified.
- [ ] Ask about a topic absent from the notes; check that the answer does not falsely attribute information to the notes.
- [ ] Ask a narrow question; check that the response stays focused instead of mechanically repeating every heading.
- [ ] Ask about behavior that may vary by Windows version; check that the answer qualifies it or requests context.

## Your turn

In your own words, explain what the skill should do when its reference file is missing. Then pick one artifact topic from the notes and test the skill with a specific question. Check whether it distinguishes evidence from conclusions.

## Next lesson

Next, review whether the skill's description helps Copilot discover it for the right requests, then practice refining the description with clear trigger phrases—without making it so broad that unrelated questions invoke it.

## Final file — current skill

Standalone working copy: [SKILL.md](../../../../.github/skills/windows-forensics/SKILL.md).

```markdown
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
```
