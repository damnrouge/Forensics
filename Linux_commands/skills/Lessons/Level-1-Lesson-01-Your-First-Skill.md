# Level 1 — Lesson 1: Validate Your First Skill

## Goal

Learn the basic structure of a VS Code agent skill, identify what is missing from your first draft, and build a small working first version without losing the original.

## Your draft

Your first attempt is in [`myfirstskill.md`](windows-forensics/myfirstskill.md). It already communicates the intended topic: Windows forensic artifacts, with quick-reference answers based on workspace notes.

## Validation

| Draft element | What it does | What to improve |
|---|---|---|
| `name: windows-forensics` | Suggests the skill's topic. | A skill needs YAML frontmatter between `---` lines. The name must also match its skill folder. |
| `description: ...` | Explains the skill's purpose. | Make it specific enough to help the agent decide when to use the skill; mention Windows artifacts and the kind of help it provides. |
| `instructions:` | Signals that behavior guidance is coming. | `instructions` is not a required skill metadata field. Put the procedure in the Markdown body after the frontmatter. |
| `**utilize the knowledge...**` | Points to reference material. | Use the actual filename, `Windows_Forensic_Artifacts.md`, and a relative Markdown link. |
| `**Provide information about keyword quired by user**` | Requests answers to user topics. | Clarify what an answer should contain. For example: purpose, location, investigative value, limitations, and corroborating artifacts. Correct typos such as “quired” to “queried.” |
| Filename `myfirstskill.md` | Keeps your learning draft. | VS Code discovers skills using a file named `SKILL.md` inside a named skill folder. Keep the draft, and put the working version at the recognized path. |

## First concepts to remember

1. **A skill is a folder, not just a Markdown file.** The conventional workspace path is `.github/skills/<skill-name>/SKILL.md`.
2. **Frontmatter is metadata.** Put `name` and `description` between the opening and closing `---` lines. Put the actual instructions after the closing line.
3. **The name and folder must match.** Here, both are `windows-forensics`.
4. **The description is the discovery text.** Say what the skill does and when it should be used.
5. **Write actionable instructions.** Tell the agent how to answer, which references to consult, and how to explain uncertainty.
6. **Keep a useful draft.** Your original file is preserved; the new skill is a first version to learn from and revise.

## Your first working version

The initial skill is at [`SKILL.md`](../../../.github/skills/windows-forensics/SKILL.md). Compare it with your draft:

- The frontmatter is clearly separated from the instructions.
- The folder and `name` match.
- Its description says when the skill applies.
- The body gives a repeatable response structure.
- The reference points to the exact artifact-notes filename and reminds the agent to explain evidence limitations.

## Practice

Without looking at the new skill, write down the three required basics you have learned:

1. The conventional path and required filename.
2. Where `name` and `description` go.
3. What makes a description useful.

Then open both files and check your answers. If you can explain each difference between your draft and the working version, you are ready for Level 1, Lesson 2: improving instructions and testing a skill with example requests.

## Next lesson

Improve the first version by adding a short example response and checking how it handles an artifact with version-dependent behavior. Do this after reviewing this lesson, so the changes make sense rather than becoming unexplained boilerplate.

## Final file — current skill

This is the complete starter skill created in this lesson. The standalone working copy is [`SKILL.md`](../../../.github/skills/windows-forensics/SKILL.md).

```markdown
---
name: windows-forensics
description: "Answer questions about Windows forensic artifacts with concise references to their purpose, location, investigative value, limitations, and corroboration. Use when researching or learning about Windows artifacts or Windows activity."
---

# Windows Forensics

Help the user understand Windows forensic artifacts. Use the workspace's [Windows artifact notes](../../../Windows_Forensic_Artifacts.md) as a starting reference when relevant.

For each artifact or topic the user asks about, give a concise answer with:

- **What it is**
- **Common location or source**
- **What it may help establish**
- **Limitations and interpretation caveats**
- **Other evidence that could corroborate it**

Answer the user's specific question first. If they ask for a keyword or artifact name, explain that item rather than giving an unrelated overview. Expand acronyms and briefly explain unfamiliar terms.

Treat artifacts as clues, not conclusive proof of intent or activity by themselves. Do not present paths, behavior, or timestamp interpretation as universal across Windows versions and configurations. State uncertainty where details depend on the system, and recommend corroborating evidence. Treat the workspace notes as a study aid; qualify claims when needed rather than repeating them uncritically.
```
