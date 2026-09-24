# Pre-migration documentation archive

These documents describe the former C#/.NET Orchestrator, earlier Go
experiments, or plans written against those implementations. They are kept
for historical context and are not current commands, wire contracts, or
operational procedures for the greenfield Go binary.

The new implementation does not promise compatibility with the archived
configuration, NATS subjects, stores, APIs, or rollout path. Use the active
documents under `docs/` and verify behavior against the current Go source.

The earlier model and replay fixtures from the former .NET test tree are kept
under [`testdata`](testdata/). The dated records under [`docs/evidence`](../../evidence/)
were deliberately left in place and unchanged. They preserve what earlier
source revisions and commands established; they do not qualify the Go
implementation or production OCI behavior.
