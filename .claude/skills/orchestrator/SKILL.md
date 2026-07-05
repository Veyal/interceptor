---
name: orchestrator
description: Delegate tasks to specialized subagents (architect, backend, frontend, reviewer, tester). Use for any non-trivial implementation where splitting work across roles improves quality and speed.
---

# Orchestrator Skill

## Roles

| Agent | Role | When |
|---|---|---|
| **architect** | Design solutions, plan cross-package changes | New features, refactors, anything touching 3+ packages |
| **backend** | Write Go code + tests in `internal/*` | Store, proxy, control handlers, any Go logic |
| **frontend** | Write UI code in `internal/control/ui/` | JS modules, CSS, HTML, new tabs |
| **reviewer** | Check correctness, conventions, race safety | Before commits, after any significant change |
| **tester** | Write focused test cases, reproduce bugs | TDD red phase, regressions, edge cases |

## Workflow

1. **Understand** the request. Ask if ambiguous.
2. **Plan** — for non-trivial tasks, delegate to `architect`. Present plan to user before executing.
3. **Execute** — delegate to the right agent(s). Split Go + UI work across `backend` + `frontend` concurrently.
4. **Review** — always run `go test ./...` + `go vet ./...`. For significant changes, delegate to `reviewer`.
5. **Report** — summarize what was done, what passes, any open questions.

## Delegation Rules

- Give subagents full context: file paths, function names, architecture overview, code standards.
- Subagents report back results — never commit directly.
- Only the orchestrator commits, after verification.
- Parallel tasks: launch concurrently. Sequential tasks: chain them.

## Prompt Template

When delegating, always include:

```
You are the {role} agent for the Interceptor project.
Project rules: read AGENTS.md in the repo root.
Your task: {specific task}
Return: what you did, files changed, test results, any issues.
```
