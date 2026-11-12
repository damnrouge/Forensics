# Skill-Building Quick Reference

Short, cumulative reference for the Windows Forensics skill-building lessons. The individual lesson files provide explanations and exercises; use this page for the essentials.

> **Keep this document current:** whenever a new lesson or level is completed, add its key takeaways here and update the lesson index in [`Learning/README.md`](../../README.md).

## The Four Essentials

1. **Location:** A workspace skill is discovered from `.github/skills/<skill-name>/SKILL.md`.
2. **Frontmatter:** Put `name` and `description` between opening and closing `---` lines. The skill `name` must match its containing folder.
3. **Description:** Summarize the skill's action, topic, recognizable user keywords, and when to use it. It helps discovery; it does not guarantee automatic invocation.
4. **Instructions:** Put actionable behavior in the Markdown body. Use supporting references only when they add value, and link them with correct relative paths.
5. **Organization:** Keep core workflow instructions in `SKILL.md`. Add linked supporting files only for substantial optional detail; extra files create maintenance and navigation costs.

## Building and Improving a Skill

1. Define the skill's purpose and intended users.
2. Create the skill folder and `SKILL.md` in the discovery location.
3. Write concise, keyword-rich frontmatter.
4. Write specific instructions for how to answer, including appropriate limitations and uncertainty.
5. Add a short example when it clarifies the desired response.
6. Link relevant references, verify that each path exists, and be transparent if a source is missing or incomplete.
7. Test a relevant request, an unrelated request, and explicit slash invocation.
8. Review the result and update the skill and this quick reference when lessons produce new takeaways.

## Organizing Skill Content

- Keep the required workflow and essential constraints in `SKILL.md`.
- Put long, optional procedures or reference material in nearby files only when they meaningfully improve navigation or reduce unnecessary context.
- Link supporting material from `SKILL.md` and verify the link.
- Avoid creating files just to make the skill folder look organized; prefer the simplest structure that is easy to maintain.

## Invocation Settings

```yaml
user-invocable: true
disable-model-invocation: true
```

- `user-invocable: true` enables explicit invocation (for example, `/windows-forensics`).
- `disable-model-invocation: true` disables automatic model selection. Omit it or set it to `false` if automatic selection is desired.
- Automatic selection is probabilistic. Use the slash command when explicit invocation matters.

## Using References Reliably

- Resolve a relative link from the file containing the link.
- Check that the target exists after moving or renaming files.
- Distinguish what the source says from your interpretation.
- If a source is unavailable or silent, say so; do not claim to have consulted it or invent its contents.
- Ask for context when it could materially change the answer.

## Testing Checklist

- [ ] `SKILL.md` is under `.github/skills/<matching-name>/`.
- [ ] Frontmatter is valid and the name matches the directory.
- [ ] The description says what the skill does and when it applies.
- [ ] Instructions are clear, focused, and consistent with the example.
- [ ] Reference links resolve and missing-source behavior is clear.
- [ ] A relevant prompt gets a focused answer.
- [ ] An unrelated prompt does not get forced into this skill's format.
- [ ] Explicit invocation works when `user-invocable` is enabled.

## Lesson Index

| Lesson | Main takeaway |
|---|---|
| [Lesson 1 — Your First Skill](./Lessons/Level-1-Lesson-01-Your-First-Skill.md) | Skill folder and `SKILL.md` structure; frontmatter versus body. |
| [Lesson 2 — Improve and Test](./Lessons/Level-1-Lesson-02-Improving-and-Testing.md) | Examples, invocation settings, and behavior-based testing. |
| [Lesson 3 — Handle References](./Lessons/Level-1-Lesson-03-Reference-Handling.md) | Correct relative paths, source limitations, and honest fallback behavior. |
| [Lesson 4 — Write a Good Description](./Lessons/Level-1-Lesson-04-Writing-a-Good-Description.md) | Discovery descriptions should be specific, keyword-rich, and scoped. |
| [Lesson 5 — Organize Skill Content](./Lessons/Level-1-Lesson-05-Organizing-Skill-Content.md) | Keep core guidance in `SKILL.md`; split out supporting files only when useful. |

## Current Windows Forensics Skill

- Active skill: [`SKILL.md`](../../../.github/skills/windows-forensics/SKILL.md)
- Learning draft: [`myfirstskill.md`](./Drafts/myfirstskill.md)
- Workspace artifact notes: [`Windows_Forensic_Artifacts.md`](../../../Windows_Forensic_Artifacts.md)
