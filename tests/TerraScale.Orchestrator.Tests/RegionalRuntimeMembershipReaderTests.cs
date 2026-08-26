using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Reader-taxonomy coverage for regional membership records: every classification
/// is derived from the record's own evidence and the reader's prior observation,
/// on a virtual clock. No transport participates.
/// </summary>
public sealed class RegionalRuntimeMembershipReaderTests
{
    private static readonly IReadOnlySet<string> ThreeControllers =
        RegionalRuntimeMembershipReader.ExpectedInstances(3);

    [Test]
    public async Task SignedIdentityRoundTripsAndCoversEveryBoundField()
    {
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var observedAt = DateTimeOffset.UtcNow;
        var member = Member(identity, observedAt);

        await Assert.That(member.IsValidFor("gru", observedAt)).IsTrue();
        await Assert.That(member.VerifySignedIdentity()).IsTrue();
        await Assert.That(member.IdentityKeyId).Length().IsEqualTo(32);

        // Tampering with any bound field invalidates the signature.
        await Assert.That((member with { SessionId = Guid.NewGuid().ToString("N") }).VerifySignedIdentity()).IsFalse();
        await Assert.That((member with { AuthorityEpoch = member.AuthorityEpoch + 1 }).VerifySignedIdentity()).IsFalse();
        await Assert.That((member with { LeaseExpiresAt = member.LeaseExpiresAt.AddSeconds(5) }).VerifySignedIdentity())
            .IsFalse();
        await Assert.That((member with { Cell = "sfo" }).VerifySignedIdentity()).IsFalse();
        await Assert.That((member with { Build = "other-build" }).VerifySignedIdentity()).IsFalse();
    }

    [Test]
    public async Task ReaderDistinguishesEveryRequiredClassification()
    {
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var now = DateTimeOffset.UtcNow;
        var healthy = Member(identity, now);
        // A legitimately stale record: signed 25 seconds ago, so its 20-second
        // semantic lease has genuinely lapsed.
        var stale = Member(identity, now.AddSeconds(-25));

        // Healthy, stale, and missing slots.
        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "gru", "controller-1", ThreeControllers, previous: null, record: healthy, now))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.Healthy);
        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "gru", "controller-1", ThreeControllers, previous: null, record: stale, now))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.Stale);
        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "gru", "controller-2", ThreeControllers, previous: null, record: null, now))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.Missing);

        // Unexpected: a lease-live, correctly signed record for a slot the cell
        // does not expect.
        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "gru", "controller-9", ThreeControllers, previous: null,
            record: Member(identity, now, instance: "controller-9"), now))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.Unexpected);

        // Wrong cell.
        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "sfo", "controller-1", ThreeControllers, previous: null, record: healthy, now))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.WrongCell);

        // Conflicting session: a new session, correctly signed, under a still-live lease.
        var previousLive = healthy;
        var conflicting = Member(identity, now, sessionId: Guid.NewGuid().ToString("N"));        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "gru", "controller-1", ThreeControllers, previous: previousLive, record: conflicting, now))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.ConflictingSession);

        // Stale epoch: a re-delivered older epoch after a newer one was observed.
        var newerEpoch = healthy with { AuthorityEpoch = healthy.AuthorityEpoch + 1 };
        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "gru", "controller-1", ThreeControllers, previous: newerEpoch, record: healthy, now))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.StaleEpoch);

        // Invalid signature: a forged record and a broken key continuity.
        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "gru", "controller-1", ThreeControllers, previous: null,
            record: healthy with { IdentitySignature = new string('A', 96) }, now))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.InvalidSignature);
        using var otherIdentity = RegionalRuntimeMembershipIdentity.Create();
        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "gru", "controller-1", ThreeControllers, previous: healthy,
            record: Member(otherIdentity, now), now))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.InvalidSignature);

        // Malformed: structurally invalid (unsorted capabilities).
        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "gru", "controller-1", ThreeControllers, previous: null,
            record: healthy with { Capabilities = ["service-discovery", "authority"] }, now))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.Malformed);
    }

    [Test]
    public async Task UnsignedRecordsAreRejectedByTheStructuralContract()
    {
        var now = DateTimeOffset.UtcNow;
        var unsigned = Member(RegionalRuntimeMembershipIdentity.Create(), now) with { IdentitySignature = "" };

        await Assert.That(unsigned.IsValidFor("gru", now)).IsFalse();
        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "gru", "controller-1", ThreeControllers, previous: null, record: unsigned, now))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.Malformed);
    }

    [Test]
    public async Task LeaseBoundaryIsExactAndStaleSlotsStayStaleWithoutNewRecords()
    {
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var observedAt = DateTimeOffset.UtcNow;
        var member = Member(identity, observedAt);

        // The 20-second semantic lease: one tick before expiry the slot is healthy.
        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "gru", "controller-1", ThreeControllers, previous: null, record: member,
            observedAt + RegionalRuntimeMembership.LeaseDuration - TimeSpan.FromMilliseconds(1)))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.Healthy);
        // At and after expiry it is stale, and it stays stale with no further record.
        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "gru", "controller-1", ThreeControllers, previous: null, record: member,
            observedAt + RegionalRuntimeMembership.LeaseDuration))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.Stale);
        // An absent record is a departed slot — the watcher's delete path — never
        // a silently healthy or stale one, whether or not a predecessor is
        // remembered and whatever that predecessor's lease state was.
        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "gru", "controller-1", ThreeControllers, previous: member, record: null,
            observedAt + TimeSpan.FromSeconds(1)))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.Missing);
        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "gru", "controller-1", ThreeControllers, previous: member, record: null,
            observedAt + RegionalRuntimeMembership.LeaseDuration + TimeSpan.FromSeconds(1)))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.Missing);
        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "gru", "controller-2", ThreeControllers, previous: null, record: null, observedAt))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.Missing);
    }

    [Test]
    public async Task CanonicalMaterialCoversEverySignedFieldExactly()
    {
        // Exhaustiveness by construction: every property of the record must have
        // a mutation case here (a future field without one fails this test), each
        // non-identity mutation must change the canonical signed material, and
        // the three identity fields must not (they are carried, not signed).
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var observedAt = DateTimeOffset.UtcNow;
        var baseline = Member(identity, observedAt);
        var material = baseline.CanonicalMaterial();

        var constructor = typeof(RegionalRuntimeMember).GetConstructors().Single();
        var arguments = constructor.GetParameters();
        var baselineArguments = new object?[]
        {
            baseline.SchemaVersion, baseline.Cell, baseline.Cluster, baseline.Instance,
            baseline.SessionId, baseline.Build, baseline.Capabilities, baseline.StartedAt,
            baseline.ObservedAt, baseline.LeaseExpiresAt, baseline.AuthorityState,
            baseline.IsAuthorityLeader, baseline.AuthorityEpoch, baseline.AuthorityRevision,
            baseline.IdentityKeyId, baseline.IdentityPublicKey, baseline.IdentitySignature,
        };
        var argumentIndex = arguments
            .Select((parameter, index) => (parameter.Name!, index))
            .ToDictionary(static pair => pair.Item1, static pair => pair.Item2, StringComparer.Ordinal);

        object? Mutation(string name) => name switch
        {
            nameof(RegionalRuntimeMember.SchemaVersion) => baseline.SchemaVersion + 1,
            nameof(RegionalRuntimeMember.Cell) => "sfo",
            nameof(RegionalRuntimeMember.Cluster) => "orchestrator-control-sfo",
            nameof(RegionalRuntimeMember.Instance) => "controller-2",
            nameof(RegionalRuntimeMember.SessionId) => Guid.NewGuid().ToString("N"),
            nameof(RegionalRuntimeMember.Build) => "another-build",
            nameof(RegionalRuntimeMember.Capabilities) => baseline.Capabilities.Append("z-capability").ToArray(),
            nameof(RegionalRuntimeMember.StartedAt) => baseline.StartedAt.AddSeconds(1),
            nameof(RegionalRuntimeMember.ObservedAt) => baseline.ObservedAt.AddSeconds(1),
            nameof(RegionalRuntimeMember.LeaseExpiresAt) => baseline.LeaseExpiresAt.AddSeconds(1),
            nameof(RegionalRuntimeMember.AuthorityState) => "follower",
            nameof(RegionalRuntimeMember.IsAuthorityLeader) => !baseline.IsAuthorityLeader,
            nameof(RegionalRuntimeMember.AuthorityEpoch) => baseline.AuthorityEpoch + 1,
            nameof(RegionalRuntimeMember.AuthorityRevision) => baseline.AuthorityRevision + 1,
            nameof(RegionalRuntimeMember.IdentityKeyId) => new string('f', 32),
            nameof(RegionalRuntimeMember.IdentityPublicKey) => "QUNITFRIS0VZ", // valid base64, different key
            nameof(RegionalRuntimeMember.IdentitySignature) => new string('B', 96),
            _ => throw new InvalidOperationException(
                $"RegionalRuntimeMember gained the property '{name}' without a canonical-material mutation case."),
        };

        var properties = typeof(RegionalRuntimeMember).GetProperties()
            .Where(static property => property.CanRead)
            .Select(static property => property.Name)
            .ToArray();
        await Assert.That(properties.Length).IsEqualTo(arguments.Length);
        var unsigned = new HashSet<string>(StringComparer.Ordinal)
        {
            nameof(RegionalRuntimeMember.IdentityKeyId),
            nameof(RegionalRuntimeMember.IdentityPublicKey),
            nameof(RegionalRuntimeMember.IdentitySignature),
        };

        foreach (var name in properties)
        {
            var mutatedArguments = (object?[])baselineArguments.Clone();
            mutatedArguments[argumentIndex[name]] = Mutation(name);
            var mutated = (RegionalRuntimeMember)constructor.Invoke(mutatedArguments)!;
            if (unsigned.Contains(name))
                await Assert.That(mutated.CanonicalMaterial()).IsEqualTo(material).Because(name);
            else
                await Assert.That(mutated.CanonicalMaterial()).IsNotEqualTo(material).Because(name);
        }
    }

    [Test]
    public async Task DelayedDuplicatesAndReorderedReplaysDoNotResurrectAStaleSession()
    {
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var now = DateTimeOffset.UtcNow;
        var first = Member(identity, now, sessionId: Guid.NewGuid().ToString("N"), epoch: 5);

        // A delayed duplicate of the old session arrives after a newer session was
        // observed under the same live lease: the reader flags the conflict, and a
        // reordered older epoch is classified stale rather than authoritative.
        var second = Member(identity, now, sessionId: Guid.NewGuid().ToString("N"), epoch: 6);
        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "gru", "controller-1", ThreeControllers, previous: second, record: first, now))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.StaleEpoch);

        // The same session replayed after its lease expired is stale, not healthy.
        await Assert.That(RegionalRuntimeMembershipReader.Classify(
            "gru", "controller-1", ThreeControllers, previous: null, record: first,
            now + RegionalRuntimeMembership.LeaseDuration + TimeSpan.FromSeconds(1)))
            .IsEqualTo(RegionalRuntimeMembershipRecordClass.Stale);
    }

    private static RegionalRuntimeMember Member(
        RegionalRuntimeMembershipIdentity identity,
        DateTimeOffset observedAt,
        string? sessionId = null,
        long epoch = 7,
        string instance = "controller-1")
    {
        var member = new RegionalRuntimeMember(
            1,
            "gru",
            "orchestrator-control-gru",
            instance,
            sessionId ?? Guid.NewGuid().ToString("N"),
            "test-build",
            ["authority", "regional-membership", "service-discovery"],
            observedAt.AddMinutes(-1),
            observedAt,
            observedAt.Add(RegionalRuntimeMembership.LeaseDuration),
            "leader",
            true,
            epoch,
            11,
            identity.KeyId,
            identity.PublicKey,
            string.Empty);
        return member with { IdentitySignature = identity.Sign(member) };
    }
}
