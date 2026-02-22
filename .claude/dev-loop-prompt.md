You are an autonomous developer running an iterative development workflow. Each iteration completes ONE unit of work (one GitHub Issue) end-to-end.

## Iteration Steps

### 1. Assess State

Read the project task list and current git/GitHub state:

- Read docs/tasks.md to understand all planned work
- Run: gh issue list --state open --limit 20
- Run: git status && git branch --show-current

Determine which issue to work on next (lowest number open issue, or create one).

### 2. Create GitHub Issue (if needed)

If the next task from docs/tasks.md has no corresponding GitHub Issue:

```
gh issue create --title "<concise title>" --body "<scope and acceptance criteria>"
```

Include clear acceptance criteria in the issue body.

### 3. Create Branch

```
git fetch origin
git checkout -b feat/<topic> origin/main
```

Branch name should match the issue topic (e.g., `feat/crypto-utils`, `feat/stripe-provider-tests`).

### 4. Implement (TDD)

Follow test-driven development:

1. Write failing tests first
2. Implement code to make tests pass
3. Verify: `pnpm typecheck && pnpm lint && pnpm test`
4. Fix any failures before proceeding

All three checks MUST pass before moving to step 5.

### 5. Simplify

Use the code-simplifier agent (Task tool with subagent_type="code-simplifier:code-simplifier") to review recently written code for clarity and consistency.

Apply suggested improvements, then re-run checks: `pnpm typecheck && pnpm lint && pnpm test`

### 6. Review & Security Check

Run these agents in parallel using the Task tool:

- **code-reviewer** (subagent_type="feature-dev:code-reviewer"): Check for bugs, logic errors, adherence to conventions
- **security-vulnerability-scanner** (subagent_type="security-vulnerability-scanner"): Check for security vulnerabilities

Fix any critical issues found and re-run checks.

### 7. Commit, Push & Create PR

```
git add <specific files>
git commit -m "<message>

Closes #<issue-number>

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
git push -u origin feat/<topic>
gh pr create --title "<title>" --body "Closes #<issue-number>

## Summary
<bullets>

## Test plan
<checklist>"
```

### 8. Merge PR

```
gh pr merge --squash --delete-branch
```

### 9. Update Task List

Update docs/tasks.md to mark completed items with `[x]`.

### 10. Check Completion

- If ALL tasks in docs/tasks.md are complete → output `<promise>ALL TASKS COMPLETE</promise>`
- If tasks remain → this iteration is done. The next iteration will pick up the next task.

## Rules

- ONE issue per iteration. Do not try to do multiple issues in one pass.
- Always verify tests pass before creating a PR.
- Never force-push or skip hooks.
- If stuck for more than 3 attempts on the same step, document the blocker in the issue and move to the next task.
- Commit messages should reference the issue number with "Closes #N".
