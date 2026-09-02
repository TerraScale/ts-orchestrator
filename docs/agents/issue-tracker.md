# Issue tracker: Forgejo

Issues and specs for this repository live in Forgejo at `git.terrascale.tech`.
Use the `fj` CLI for all Forgejo issue operations from inside the repository.

## Conventions

- Create, read, search, comment, label, assign, and close issues with `fj`.
- Infer the Forgejo repository from the current repository's `origin` remote.
- Before any write, confirm that the selected Forgejo repository matches the current Git repository.
- Preserve existing issue content and labels unless the task calls for changing them.
- Use `fj -C <repo-path>` when the fallback command runs outside the repository.

## `fj` commands

- Create: `fj issue create "..." --body "..."`
- Read: `fj issue view <number>` and `fj issue view <number> comments`
- Search: `fj issue search [query] --state open`
- Comment: `fj issue comment <number> "..."`
- Add or remove labels: `fj issue edit <number> labels --add "..."` or `--rm "..."`
- Assign: `fj issue assign <number> <username>`
- Close with an explanation: `fj issue close <number> --with-msg "..."`

Use `--body-file` for long issue bodies or comments.

## Pull requests as a triage surface

PRs as a request surface: no.

## When a skill says "publish to the issue tracker"

Create a Forgejo issue in the repository inferred from `origin`.

## When a skill says "fetch the relevant ticket"

Read the issue body, comments, labels, state, and assignees with `fj issue
view`.

## Wayfinding operations

The map is one Forgejo issue. Its child tickets are separate issues.

- Label the map `wayfinder:map`.
- Put `Part of #<map>` at the top of each child issue.
- Label each child `wayfinder:<type>`, where the type is `research`, `prototype`, `grilling`, or `task`.
- Record dependencies as `Blocked by: #<number>, #<number>` at the top of the child body.
- A ticket is available when it is open, has no open blocker, and has no assignee.
- Claim a ticket by assigning the current Forgejo user before starting work.
- Resolve a ticket by posting the answer, closing it, and adding its result to the map's Decisions-so-far section.
