using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.ControlPlane.Runtime;
using TerraScale.Orchestrator.Messaging;
using HostArchitecture = TerraScale.Orchestrator.Runtime.HostArchitecture;
using HostRuntimeDriver = TerraScale.Orchestrator.Runtime.RuntimeDriver;
using HostRuntimePlan = TerraScale.Orchestrator.Runtime.HostRuntimePlan;
using HostRole = TerraScale.Orchestrator.Runtime.AdmittedRole;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class NatsRuntimeLifecycleJournalProtocolTests
{
    [Test]
    public async Task CanonicalRedactedCheckpointRejectsTamperSchemaCellAndBrokenDigestChain()
    {
        var proposed = RuntimeLifecycleCheckpoint.Proposed(Request());
        var persisted = proposed with { JournalRevision = 1 };
        persisted = persisted with { EventDigest = RuntimeLifecycleFingerprint.Event(persisted) };
        var key = RuntimeLifecycleNatsProtocol.Key(persisted.OperationKey);
        var serialized = RuntimeLifecycleNatsProtocol.Serialize(persisted);

        await Assert.That(serialized).DoesNotContain("ImageReference");
        await Assert.That(serialized).DoesNotContain("ContainerId");
        await Assert.That(serialized).DoesNotContain("credentials");
        await Assert.That(RuntimeLifecycleNatsProtocol.TryDeserialize(serialized, out var parsed)).IsTrue();
        await Assert.That(RuntimeLifecycleNatsProtocol.IsCheckpoint(parsed, "gru", key, 1)).IsTrue();

        var tampered = parsed with { EventDigest = new RuntimeDigest(Digest("tampered")) };
        await Assert.That(RuntimeLifecycleNatsProtocol.IsCheckpoint(tampered, "gru", key, 1)).IsFalse();
        var foreign = parsed with { Cell = new RuntimeLifecycleCellId("sfo") };
        foreign = foreign with { EventDigest = RuntimeLifecycleFingerprint.Event(foreign) };
        await Assert.That(RuntimeLifecycleNatsProtocol.IsCheckpoint(foreign, "gru", key, 1)).IsFalse();
        var unknownSchema = parsed with { SchemaVersion = 99 };
        unknownSchema = unknownSchema with { EventDigest = RuntimeLifecycleFingerprint.Event(unknownSchema) };
        await Assert.That(RuntimeLifecycleNatsProtocol.IsCheckpoint(unknownSchema, "gru", key, 1)).IsFalse();

        var next = parsed with { JournalRevision = 2, PreviousEventDigest = parsed.EventDigest, Phase = RuntimeLifecyclePhase.Authorized };
        next = next with { EventDigest = RuntimeLifecycleFingerprint.Event(next) };
        await Assert.That(RuntimeLifecycleNatsProtocol.IsChained(parsed, next)).IsTrue();
        await Assert.That(RuntimeLifecycleNatsProtocol.IsChained(parsed, next with { PreviousEventDigest = new RuntimeDigest(Digest("foreign-chain")) })).IsFalse();
    }

    [Test]
    public async Task ProofBindingIncludesRequestIdentityRevisionAndWriterEpoch()
    {
        const string key = "runtime.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        var one = RuntimeLifecycleNatsProtocol.ProofBinding(RuntimeLifecycleNatsProtocol.UpdateAction, 1, "gru", key, 7, 9,
            "0123456789abcdef0123456789abcdef", "checkpoint");
        var differentEpoch = RuntimeLifecycleNatsProtocol.ProofBinding(RuntimeLifecycleNatsProtocol.UpdateAction, 1, "gru", key, 7, 10,
            "0123456789abcdef0123456789abcdef", "checkpoint");
        var differentRequest = RuntimeLifecycleNatsProtocol.ProofBinding(RuntimeLifecycleNatsProtocol.UpdateAction, 1, "gru", key, 7, 9,
            "fedcba9876543210fedcba9876543210", "checkpoint");

        await Assert.That(one).IsNotEqualTo(differentEpoch);
        await Assert.That(one).IsNotEqualTo(differentRequest);
        await Assert.That(typeof(NatsRuntimeLifecycleJournal).GetConstructors()
            .SelectMany(static constructor => constructor.GetParameters())
            .Any(static parameter => parameter.ParameterType == typeof(INatsKVStore))).IsFalse();
    }

    [Test]
    public async Task RegionalAuthorityMappingOnlyAdmitsFreshPositiveLeaderEpoch()
    {
        var now = DateTimeOffset.UtcNow;
        var leader = new RegionalAuthoritySnapshot("leader", true, 7, 1, now.AddSeconds(10), now, null);
        var follower = leader with { State = "follower", IsLeader = false };
        var stale = leader with { ObservedAt = now.AddMinutes(-1) };
        var unavailable = leader with { State = "fenced", IsLeader = false, Error = "fenced" };

        await Assert.That(NatsRuntimeLifecycleAuthorityGate.Map(leader).Status).IsEqualTo(RuntimeLifecycleAuthorityStatus.ReadyLeader);
        await Assert.That(NatsRuntimeLifecycleAuthorityGate.Map(leader).Epoch).IsEqualTo(new RuntimeEpoch(7));
        await Assert.That(NatsRuntimeLifecycleAuthorityGate.Map(follower).Status).IsEqualTo(RuntimeLifecycleAuthorityStatus.Follower);
        await Assert.That(NatsRuntimeLifecycleAuthorityGate.Map(stale).Status).IsEqualTo(RuntimeLifecycleAuthorityStatus.NotReady);
        await Assert.That(NatsRuntimeLifecycleAuthorityGate.Map(unavailable).Status).IsEqualTo(RuntimeLifecycleAuthorityStatus.Unavailable);
    }

    private static RuntimeLifecycleOperationRequest Request()
    {
        var plan = HostRuntimePlan.Create(HostRole.Platform, HostRuntimeDriver.OciContainer,
            new TerraScale.Orchestrator.Runtime.RuntimeAllocationId("platform-a"),
            new TerraScale.Orchestrator.Runtime.ArtifactDigest(Digest("artifact")), HostArchitecture.Arm64);
        return new(new("gru"), new("node-a"), new(7), new(Digest("convergence")), plan, LifecycleAction.Converge,
            new(7), new(Digest("authorization")), new(new(Digest("deadline")), 9));
    }

    private static string Digest(string value) => RuntimeLifecycleFingerprint.Hash(value);
}
