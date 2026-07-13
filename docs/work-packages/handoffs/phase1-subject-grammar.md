# Phase 1 subject grammar handoff

- Branch: `phase1/subject-grammar`
- Work package: `docs/work-packages/phase1-subject-grammar.md`
- Scope: infrastructure-free subject syntax, wildcard matching, permission decision, and focused TUnit tests
- NATS packages, accounts, roots, streams, actual permissions, package/build files, registry, and composition root: unchanged

## Implemented behavior

`ConcreteSubject` and `SubjectPermissionPattern` are deliberately separate immutable types:

- Concrete subjects require one or more nonempty dot-separated tokens and reject whitespace, control characters, unpaired UTF-16 surrogates, empty tokens, and either wildcard character anywhere.
- Permission patterns apply the same bounded token grammar, allow `*` only as an entire one-token wildcard, and allow `>` only as the final entire token.
- `SubjectPermissionPattern.Matches` performs ordinal, case-sensitive token walking. It uses no regular expression and allocates nothing per match. `*` consumes exactly one token; terminal `>` consumes one or more tokens, matching the [official NATS subject semantics](https://docs.nats.io/nats-concepts/subjects).
- `SubjectGrammarLimits` is mandatory caller input. Its validated positive fields cap total .NET string length, token count, token length, and combined permission-pattern count. There is no production default.
- Parsing checks total length before allocating token strings. Policy construction stops enumeration at the explicit count bound, rejects null/duplicate/cross-set patterns, copies the caller's collections, and sorts both sets using ordinal canonical order.
- `SubjectPermissionPolicy.Authorize` checks every deny before any allow. A deny match wins; an empty allow set, no allow match, or invalid subject denies. `SubjectPermissionDecision` returns a stable enum reason and never contains the untrusted subject text (`SEC-NO-SECRET-OUTPUT`).

The implementation does not claim the broader `INV-018` separation invariant: it provides only grammar and deny-first decision primitives for future generated policies.

## Determinism and allocation bounds

Parse failures use the closed `SubjectGrammarError` catalog. Limit validation occurs first, followed by empty input and total length. The bounded left-to-right scan then rejects empty/excess tokens, whitespace/control characters, malformed Unicode scalar sequences, and token length before the concrete/pattern-specific wildcard pass.

Matcher work is linear in the bounded number of tokens. A nonterminal pattern must have exactly the concrete token count. A terminal `>` pattern requires at least as many concrete tokens as pattern tokens because `>` consumes one or more. Literal comparison uses `StringComparer.Ordinal`; culture and current locale cannot affect matching, equality, duplicate detection, or ordering.

Policy construction uses one combined maximum count across allow and deny. Exact duplicates within either set and exact patterns appearing in both sets are rejected. Case-distinct patterns remain distinct because NATS subjects are case-sensitive.

## Tests

The 19 focused TUnit tests cover:

- invalid and exact-boundary limit policies;
- concrete subject total/token/count boundaries;
- null, empty, leading/trailing/consecutive-dot, whitespace, control, unpaired high/low surrogate, wildcard, and injection-like malformed corpora;
- valid `*`, terminal `>`, mixed wildcard patterns, and invalid embedded/nonterminal variants;
- literal, single-token, multi-token, case-sensitive, and regex-metacharacter-as-literal matching;
- deny precedence, empty-allow/no-match default deny, invalid subject, and stable credential-like-text non-echoing reasons;
- null, duplicate, cross-set, and excess permission patterns;
- caller collection mutation after construction; and
- ordinal canonical ordering and case-sensitive duplicate behavior.

Verification:

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx --no-restore
dotnet test tests/TerraScale.Orchestrator.Protocol.Tests/TerraScale.Orchestrator.Protocol.Tests.csproj --no-build --no-restore -- --treenode-filter '/*/*/Subject*/*'
dotnet test tests/TerraScale.Orchestrator.Protocol.Tests/TerraScale.Orchestrator.Protocol.Tests.csproj --no-build --no-restore
git diff --check
```

## Deliberate limitations

- No actual subject root, account, stream, import/export, allow, or deny is selected. Generated policy ownership remains a later steward/identity lane.
- Limits count .NET UTF-16 characters. A future serializer/transport adapter must add an explicit UTF-8 byte ceiling and real-server conformance fixtures without weakening this grammar.
- The grammar accepts non-control, non-whitespace Unicode literally and performs no normalization. A future generated naming policy may choose a narrower token alphabet; this layer never silently rewrites identity.
- No NATS client/server behavior, JWT configuration, L0C conformance, or verified registry evidence is claimed by these pure tests.
