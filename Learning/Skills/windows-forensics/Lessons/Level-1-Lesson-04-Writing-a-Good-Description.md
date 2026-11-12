# Level 1 — Lesson 4: Write a Good Skill Description

## Goal

Learn how the skill description helps Copilot decide when this skill is relevant, and refine it to include useful Windows-forensics terms without making it apply to unrelated requests.

## What changed since Lesson 3

The active skill's description now says:

- **What it can do:** explain, compare, and help interpret.
- **Its domain:** Windows forensic artifacts and activity evidence.
- **Examples of useful terms:** Prefetch, Registry artifacts, event logs, Amcache, Jump Lists, and file-system traces.
- **When it applies:** researching Windows forensics, artifact meaning, evidence limitations, or corroborating sources.

The description is not the whole skill. Keep procedures, response formatting, and caveats in the body. The description is a short discovery summary that helps the agent match relevant requests to this skill.

## A simple way to draft a description

Use this pattern:

> **Action** + **topic** + **recognizable examples or keywords** + **when to use it**

For example:

> Explain and compare Windows forensic artifacts such as Prefetch, Registry artifacts, and event logs. Use when researching Windows activity, evidence limitations, or corroborating sources.

Do not try to list every artifact. Choose representative terms that reflect the skill's actual scope.

## Avoid descriptions that are too broad or too vague

**Too broad:** “Help with computers and security.”  
This could match many unrelated tasks and does not identify the Windows-forensics domain.

**Too vague:** “A quick reference guide.”  
This does not say what the guide covers or when it should be used.

**More useful:** “Explain and compare Windows forensic artifacts, their limitations, and corroborating evidence. Use for questions about Windows artifact meaning or activity evidence.”

The improved version names the domain and the user's likely question types. The skill body can supply the details.

## Practice: predict when it should match

For each request, decide whether the Windows Forensics skill should be relevant:

1. “What can Prefetch tell me during an investigation?” — **Yes**; it names a Windows artifact.
2. “Compare Amcache and Prefetch, including limitations.” — **Yes**; it asks about artifacts and evidence limits.
3. “How do I center a heading in CSS?” — **No**; it is unrelated to Windows forensics.
4. “What does this Windows event log suggest about a logon?” — **Likely yes**; it asks to interpret Windows activity evidence.

The model's automatic selection is probabilistic. A good description improves discoverability but does not guarantee invocation. Use `/windows-forensics` when you need explicit invocation.

## Keep the central reference updated

The concise cumulative guide is [`Skill-Building-Quick-Reference.md`](../Skill-Building-Quick-Reference.md). Whenever you complete a new lesson or level, add its most reusable takeaways there and add the lesson to its index.

## Description review checklist

- [ ] Does it name the subject area clearly?
- [ ] Does it use words a user is likely to ask about?
- [ ] Does it say when the skill is relevant?
- [ ] Does it accurately describe the skill's capabilities?
- [ ] Would unrelated requests be less likely to match?
- [ ] Are detailed procedures kept in the body instead?

## Your turn

Write a one-sentence description for a skill that explains Linux command-line forensic tools. Check it against the six questions above. Keep it focused on that skill's real scope, rather than copying the Windows skill's keywords.

## Next lesson

Next, review whether the skill's instructions are organized for quick use and decide when additional reference files are worthwhile. Keep the main `SKILL.md` focused; split out supporting material only when it is useful and can be linked clearly.

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

## Example Response

**Prefetch** is a Windows application-startup optimization artifact, commonly found under `C:\Windows\Prefetch\`. Depending on the Windows version and configuration, it may help identify an executable and provide execution-related metadata. Its presence alone does not establish who launched the program or why. Correlate it with process-creation logs, if available, and other independent artifacts.
```
