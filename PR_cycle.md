# DaC PR Cycle — Full Command Reference

> Detection-as-Code | Bitbucket workflow | Branch → Push → Merge

---

## Stage 1 — Sync `main`

```bash
git checkout main
git fetch origin
git pull origin main
```

**🔍 Debug**
```bash
git status                            # confirm clean working tree
git log origin/main --oneline -5      # verify latest commits pulled
git branch -vv                        # check tracking branch linkage
```

---

## Stage 2 — Create Branch

> Naming convention: `new-*` · `tune-*` · `rapid-*` · `feature-*`

```bash
git checkout -b new-endpoint-lsass-access main
```

**🔍 Debug**
```bash
git branch                            # confirm you're on the new branch
git log --oneline main..HEAD          # should be empty (no commits yet)
git rev-parse --abbrev-ref HEAD       # prints current branch name
```

---

## Stage 3 — Stage Changes

```bash
# Stage a specific file:
git add detections/endpoint/lsass-access.yaml

# Or stage everything:
git add .
```

**🔍 Debug**
```bash
git status                            # see staged vs unstaged files
git diff --cached                     # review exactly what's staged
git diff                              # any remaining unstaged changes
```

---

## Stage 4 — Pre-commit Hook (YAML Validator)

> The hook fires automatically on `git commit`. Run it manually first to catch errors early.

```bash
# Trigger hook manually:
.git/hooks/pre-commit

# Lint YAML directly:
python3 -c "import yaml, sys; yaml.safe_load(open('detections/endpoint/lsass-access.yaml'))" && echo "YAML OK"
```

**🔍 Debug**
```bash
# Inspect what the hook does:
cat .git/hooks/pre-commit

# Spot-check required fields:
grep -E "status:|domain:|entitytype:|riskscore:" detections/endpoint/lsass-access.yaml
```

**Common validator errors**

| Error | Fix |
|---|---|
| `metadata.status` invalid | Must be: `active`, `disabled`, `warn`, or `draft` |
| `metadata.domain` invalid | Must be: `application`, `access`, `endpoint`, `cloud`, `email`, `network` |
| `risk.entities[N].entitytype` missing | Required — add entity type |
| `risk.entities[N].riskscore` missing | Required — add risk score |
| `triageSteps` got list, expected string | Wrap array in block scalar string |
| `alertdetails.finding.drilldown-searches[N].latest_offset` missing | Required — add field |

---

## Stage 5 — Commit

```bash
git commit -m "DET-1234: detect LSASS access via OpenProcess with suspicious GrantedAccess"
```

**🔍 Debug**
```bash
git log --oneline -3                  # confirm commit landed
git show --stat HEAD                  # files changed in last commit
git diff main..HEAD                   # full diff of branch vs main
```

---

## Stage 6 — Push Branch

> Enter SSH passphrase when prompted.

```bash
git push origin new-endpoint-lsass-access
```

**🔍 Debug**
```bash
# Check remote URL:
git remote -v

# Test SSH auth:
ssh -T git@bitbucket.org
ssh -vT git@bitbucket.org             # verbose — shows key handshake

# Safe force-push (if branch already exists remotely):
git push origin new-endpoint-lsass-access --force-with-lease

# Confirm branch is visible on remote:
git ls-remote origin | grep new-endpoint-lsass-access
```

---

## Stage 7 — Raise PR in Bitbucket

**UI steps:**
- **Source:** `new-endpoint-lsass-access`
- **Destination:** `main`
- Fill PR template:
  - [ ] Title — include JIRA ticket or `NO_JIRA`
  - [ ] High-level description of change
  - [ ] Rapid Request? (Yes / No)
  - [ ] New detection or tuning?
  - [ ] Link to logic (Splunk search)
  - [ ] Link to drilldown logic
- Assign reviewer → **Create**

**🔍 Debug** *(branch not showing in Bitbucket?)*
```bash
git push origin new-endpoint-lsass-access        # re-push if it didn't register
git log origin/new-endpoint-lsass-access --oneline -3   # confirm remote has your commits
```

---

## Stage 8 — Post-Review Amendments

> Commits on the same branch appear in the PR automatically.

```bash
# Edit file, then:
git add detections/endpoint/lsass-access.yaml
git commit -m "DET-1234: address review — tighten GrantedAccess filter"
git push origin new-endpoint-lsass-access
```

**🔍 Debug**
```bash
git log origin/main..HEAD --oneline   # all commits in your PR
git diff origin/main..HEAD            # full diff reviewer sees
```

---

## Stage 9 — Post-Merge Cleanup

```bash
git checkout main
git pull origin main
git branch -d new-endpoint-lsass-access       # delete local branch
git remote prune origin                        # prune stale remote refs
```

**🔍 Debug**
```bash
git branch -a | grep new-endpoint             # confirm branch is gone
git log --oneline -5                          # confirm merge commit is present
```

---

## Quick Reference — Common Push Failures

| Error | Cause | Fix |
|---|---|---|
| `Permission denied (publickey)` | SSH key not loaded | `ssh-add ~/.ssh/id_rsa` |
| `rejected — non-fast-forward` | Remote has commits you don't | `git pull --rebase origin main` then re-push |
| `pre-commit hook failed` | YAML validation error | Fix YAML, re-stage, re-commit |
| `remote: Repository not found` | Wrong remote URL | `git remote set-url origin <correct-url>` |
| `src refspec not found` | Branch name typo | `git branch` to verify exact name |

---

## Full Flow at a Glance

```
main (sync)
    │
    ├─▶ checkout -b new-* main
    │
    ├─▶ git add / git diff --cached
    │
    ├─▶ pre-commit hook (YAML validate)
    │
    ├─▶ git commit -m "DET-XXXX: ..."
    │
    ├─▶ git push origin <branch>
    │
    ├─▶ Bitbucket PR → main
    │
    ├─▶ Review → amend → push (same branch)
    │
    └─▶ Merge → cleanup local branch
```

---

*TLP:GREEN — Internal use · Detection Engineering · Purple Team*
