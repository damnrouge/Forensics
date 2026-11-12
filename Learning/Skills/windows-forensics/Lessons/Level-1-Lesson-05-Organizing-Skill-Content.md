# Level 1 — Lesson 5: Organize Skill Content

## Goal

Learn what belongs in `SKILL.md`, when a supporting reference file is worthwhile, and how to avoid creating files that add maintenance without helping the user.

## The core principle

Keep the required workflow, important constraints, and common instructions in `SKILL.md`. Split material into a supporting file only when it is substantial and useful to load or consult separately, such as a long reference, a detailed optional procedure, or a reusable template.

Extra files are not automatically better. They add paths to maintain and make it easier for the skill and its references to become inconsistent. Prefer the simplest structure that is clear and easy to maintain.

## A practical decision test

Before creating a support file, ask:

1. Is this content long or specialized enough to distract from the main workflow?
2. Is it optional or useful only for some requests?
3. Will a separate file make the material easier to find or maintain?
4. Can `SKILL.md` link to it clearly, and can the link be verified?

If most answers are “no,” leave the content in `SKILL.md`. A short set of instructions does not need to be split across multiple files just to create a folder structure.

## Applying the test to this skill

The Windows Forensics skill currently has a concise answer procedure and one compact example. Those belong directly in `SKILL.md`; a separate example file would add needless navigation.

The workspace's full [Windows forensic artifacts notes](../../../../Windows_Forensic_Artifacts.md) are a substantial, optional reference, so linking to that existing file is more useful than copying its contents into the skill. The skill should be transparent if the notes are unavailable or do not answer the question.

## Practice

Imagine you are adding these items to a new skill:

- A four-line rule used for every request.
- A twenty-page optional catalog used only when a user asks about a specific subsystem.
- A short example showing the expected response.

**Suggested organization:**

- Keep the four-line core rule in `SKILL.md`.
- Put the long optional catalog in a supporting reference file and link it from `SKILL.md`.
- Keep the short example in `SKILL.md` unless it becomes large or has a separate maintenance purpose.

Explain why each choice reduces clutter without hiding instructions the agent needs on every invocation.

## Checklist

- [ ] Essential workflow and constraints are easy to find in `SKILL.md`.
- [ ] Supporting files contain substantial optional detail, not arbitrary fragments.
- [ ] Every support file is linked from the skill where it is relevant.
- [ ] Links resolve after files are moved.
- [ ] The structure remains easy to understand and maintain.

## Your turn

Look at the current Windows Forensics skill. Which content belongs in its main file, and which reference is worth linking rather than copying? Use the four questions above to explain your choices.

## Next lesson

Next, review the complete skill against the quick-reference checklist, identify one real request that should activate it and one unrelated request that should not, then make any final focused improvements.

## Keep the central reference updated

This lesson is summarized in [`Skill-Building-Quick-Reference.md`](../Skill-Building-Quick-Reference.md). Add the key takeaways from every new lesson there and update its lesson index.

## Final file — current skill

Standalone working copy: [SKILL.md](../../../../.github/skills/windows-forensics/SKILL.md).

```markdown
---
name: windows-forensics
description: "Explain, compare, and help interpret Windows forensic artifacts and activity evidence, including Prefetch, Registry artifacts, event logs, Amcache, Jump Lists, and file-system traces. Use when researching Windows forensics, artifact meaning, evidence limitations, or corroborating sources."
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

Keep the core workflow in this file. Link supporting files only when they contain substantial optional reference material or procedures; avoid splitting short instructions into extra files without a clear benefit.

## Example Response

**Prefetch** is a Windows application-startup optimization artifact, commonly found under `C:\Windows\Prefetch\`. Depending on the Windows version and configuration, it may help identify an executable and provide execution-related metadata. Its presence alone does not establish who launched the program or why. Correlate it with process-creation logs, if available, and other independent artifacts.
```
