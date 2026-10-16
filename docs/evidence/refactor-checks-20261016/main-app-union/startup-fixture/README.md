# Bounded manager and Agent fixture

Exact APP source `582a3992` compiled and passed the selected startup fixture in
1.65 seconds, without skips. Signed external controller-c seed producers, SDK
Object/Compute/VNIC fixtures, ledger CAS and genuine Gate/current authority feed
signed foundation and create-once Vault SDK fixtures, an actual manager/Raft,
and one authenticated NATS Agent session. The fixture manually emits and
observes READY before it starts NATS and the Agent. Session cancellation joins
the Agent; the manager remains live and paused, with material and registry
providers closed. Network allocation is deliberately unavailable in this idle
manager fixture; the runtime log records that limitation.

The earlier `dbc43f0d` run failed before manager/NATS/Agent startup because its
marker directory was0700. Production requires0755 before journal inspection.
The three-line fixture correction sets that exact mode and retains all genuine
ownership, nofollow, initial journal absence and accepted-marker checks.

QA imported only the TestMain scaffold and two fixture files as
`a3caaffd`, `16dd8cec` and `4e5fcb5c`. Their blobs match the qualified APP source.
The whole union APP fixturetest test package compiled at `4e5fcb5c`.
The passing runtime case was not repeated. Other production differences between
APP and this union retain their existing exact-source evidence; there is no
whole-union runtime PASS claim.

This does not execute production RunManagedRuntime/readiness or session wrappers,
the independent binding observer, HomeIAM, positive material/registry binding,
native workloads, systemd, CLI, final-image or live OCI acceptance.

Raw logs retain their original bytes, including indented empty output lines.
Whitespace checks apply to source and prose; checksums attest the raw logs.
