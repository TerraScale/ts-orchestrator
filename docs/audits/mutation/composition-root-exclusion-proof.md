# Composition-root mutation exclusion proof

The `TerraScale.Orchestrator` executable project currently contains only
`Program.cs`, which prints a Phase 0 disabled-state message. It contains no
state transition, validator, authority, fencing, deletion, retry,
compensation, adapter result classification, credential release, or
deployment behavior.

The checked-in mutation policy excludes exactly that file as trivial
composition-root wiring. The validator fails if another C# source file is
added to the project, if the exclusion expands, or if any correctness-critical
project is marked optional. This proof must be removed or narrowed before the
composition root gains behavior.

This is an exclusion-policy proof only. It is not mutation execution evidence.
