# Phase 1 NATS subject grammar

## Goal

Implement infrastructure-free NATS subject and permission-pattern grammar used by future generated account policies. This validates syntax and matching only; it does not select account topology, subjects, or permissions.

## Allowed paths

- `src/TerraScale.Orchestrator.Protocol/Subjects/**`
- `tests/TerraScale.Orchestrator.Protocol.Tests/Subject*.cs`
- `docs/work-packages/handoffs/phase1-subject-grammar.md`

## Required behavior

- Concrete subjects are nonempty bounded dot-separated tokens and reject whitespace, empty tokens, control characters, `*`, and `>`.
- Permission patterns are separately typed; `*` occupies exactly one token and `>` is permitted only as the final whole token. Reject embedded/trailing injection and ambiguous spellings.
- Matching is deterministic, allocation-bounded, culture-invariant, and case-sensitive. It must not use regex constructed from input.
- Provide a typed permission decision over explicit allow and deny pattern sets. Deny wins; no match denies; empty allow denies. Return a stable reason code without echoing untrusted subject text.
- Defensive copies, duplicate rejection, canonical ordering, maximum token/count/length limits supplied as explicit validated policy (no production default), and adversarial tests including fuzz-like malformed corpus and boundary cases.
- Do not add NATS packages, fixed subject roots, account names, stream names, or owner-decision defaults.

## Verification

`dotnet test tests/TerraScale.Orchestrator.Protocol.Tests/TerraScale.Orchestrator.Protocol.Tests.csproj`
