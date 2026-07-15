# Mutation evidence foundation

This directory records a strict policy and an intentionally empty mutation
result. It does not install or run a mutation engine.

`mutation-policy.json` inventories every production project and makes the
current runtime project mandatory. There are no source exclusions: startup,
configuration, topology, and NATS runtime behavior are all operational code.
Any project inventory drift fails validation.

`mutation-evidence.json` cross-checks the Phase 0 supply-chain audit. That audit
lists dotnet-stryker 4.16.0 only as an unselected candidate, so every execution
value is `null` and every acceptance claim is `false`. The report has a bounded
30-day review window so a forgotten readiness record fails closed.

Run the standard-library-only checks with no restore, network, process under
test, or credentials:

```text
python3 tools/mutation/validate_mutation_evidence.py --as-of 2026-07-13
python3 -m unittest discover -s tools/mutation -p 'test_*.py' -v
```

An owner/toolchain decision must select a tool and version before any invocation
can be wired. Selection must then add a locked content hash, internal mirror,
.NET 10/TUnit compatibility evidence, stable mutant denominator, deterministic
normalized report, and safety-mutant classification. Updating this zero-claim
schema is reviewed work; changing `candidate-unselected` to an execution claim
is not an allowed shortcut.
