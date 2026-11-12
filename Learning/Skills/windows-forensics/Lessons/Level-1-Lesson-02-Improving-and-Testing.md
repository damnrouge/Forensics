# Level 1 — Lesson 2: Improve and Test a Skill

## Goal

Improve the first Windows forensics skill with an example, learn the optional invocation settings, and test that the skill behaves as intended.

## What changed since Lesson 1

The working skill now has an **Example Response** section. Instructions tell the agent what to do; an example demonstrates the expected style and level of detail.

The example is intentionally short. It demonstrates a useful answer shape without repeating a full artifact manual. It also avoids treating a Prefetch file as conclusive proof. Keep examples accurate, representative, and small enough that they do not conflict with the general instructions.

## Optional invocation settings

These are YAML frontmatter options. They are separate from the body instructions:

```yaml
user-invocable: true
disable-model-invocation: true
```

- `user-invocable: true` allows a person to invoke the skill explicitly, such as with `/windows-forensics`.
- `disable-model-invocation: true` prevents Copilot from choosing the skill automatically. Explicit invocation remains available when the skill is user-invocable.
- If `disable-model-invocation` is omitted or `false`, the model may choose the skill automatically when it is relevant. This is the current behavior of the working skill.

Choose the setting to match how you want to use the skill. For a skill you want Copilot to apply naturally to matching questions, do not disable model invocation. For a skill you want to run only on demand, set `disable-model-invocation: true` and keep `user-invocable: true`.

## How to test a skill

Test behavior, not just whether the file looks correct:

1. Open the Forensics repository as the VS Code workspace.
2. Ask a matching question without a slash command, such as “What can Prefetch tell me during a Windows investigation?”
3. Check whether the answer addresses the question and includes useful limitations and corroboration. Automatic selection can vary, so this is not a guaranteed invocation test.
4. Invoke `/windows-forensics` and ask the same question. This checks explicit discovery and the skill's response guidance.
5. Ask an unrelated question. The skill should not force a Windows-artifact format onto unrelated topics.
6. If you change invocation metadata, test the corresponding behavior again. A disabled automatic invocation should still be explicitly callable if `user-invocable` is enabled.

## Review checklist

- [ ] Frontmatter is between opening and closing `---` lines.
- [ ] `name` matches the skill folder.
- [ ] `description` says what the skill does and when it applies.
- [ ] Body instructions are specific and not contradictory.
- [ ] Relative links point to real workspace files.
- [ ] Example output follows the instructions and avoids overclaiming.
- [ ] Invocation settings match the desired automatic/manual behavior.
- [ ] Test prompts produce relevant, appropriately cautious answers.

## Next improvement

The skill currently links to the repository's Windows artifact notes. In the next lesson, improve reference handling: verify a link's relative path, choose what to do when a reference is missing or incomplete, and keep the response useful without inventing facts.

## Final file — current skill

Standalone working copy: [SKILL.md](../../../../.github/skills/windows-forensics/SKILL.md).

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

## Example Response

**Prefetch** is a Windows application-startup optimization artifact, commonly found under `C:\Windows\Prefetch\`. Depending on the Windows version and configuration, it may help identify an executable and provide execution-related metadata. Its presence alone does not establish who launched the program or why. Correlate it with process-creation logs, if available, and other independent artifacts.
```
