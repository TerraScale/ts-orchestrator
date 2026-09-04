# Domain docs

Engineering skills should read this repository's domain documentation before exploring the codebase.

## What to read

- Read `CONTEXT.md` at the repository root when it exists.
- Read relevant decisions under `docs/adr/`.
- If either location does not exist, continue without calling attention to its absence. The domain-modeling workflow creates these files when the project resolves useful terms or decisions.

## File structure

This repository uses a single domain context:

```text
/
├── CONTEXT.md
├── docs/
│   └── adr/
└── src/
```

## Use the glossary's vocabulary

Use the terms defined in `CONTEXT.md` in specifications, proposals, tests, and code.

If a needed concept is missing, first check whether the repository already uses another term. Record a genuine vocabulary gap for the domain-modeling workflow.

## Flag ADR conflicts

Call out any proposal that contradicts an existing ADR. Name the ADR and explain why the decision may need reconsideration.
