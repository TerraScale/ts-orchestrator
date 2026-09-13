using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Compare-and-swap mutation policy for regional membership records: a publisher
/// mutates only its own bound instance record, healing reuses an expired slot, and
/// a live foreign lease is never overwritten or deleted. All on a virtual clock.
/// </summary>
public sealed class RegionalRuntimeMembershipMutationTests
{
    private const string Cell = "gru";
    private const string Instance = "controller-1";
    private const string OwnSession = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string ForeignSession = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    [Test]
    public async Task EmptySlotCreatesAndOwnSessionRenews()
    {
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var now = DateTimeOffset.UtcNow;
        var own = Member(identity, now, sessionId: OwnSession);

        await Assert.That(Decide(own, existing: null, now))
            .IsEqualTo(RegionalRuntimeMembershipMutationClass.CreateOwnRecord);
        await Assert.That(Decide(own, existing: own, now))
            .IsEqualTo(RegionalRuntimeMembershipMutationClass.RenewOwnRecord);

        // Renewal is also allowed once the own lease expired; the CAS revision still binds.
        await Assert.That(Decide(own, existing: own, now + RegionalRuntimeMembership.LeaseDuration))
            .IsEqualTo(RegionalRuntimeMembershipMutationClass.TakeOverExpiredLease);
    }

    [Test]
    public async Task LiveForeignSessionIsHeldAndNeverDeleted()
    {
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var now = DateTimeOffset.UtcNow;
        var foreign = Member(identity, now, sessionId: ForeignSession);
        var own = Member(identity, now, sessionId: OwnSession);

        await Assert.That(Decide(own, existing: foreign, now))
            .IsEqualTo(RegionalRuntimeMembershipMutationClass.HoldForLiveForeignLease);

        // Healing waits for the semantic lease to lapse; only then may the slot be taken over.
        var afterExpiry = now + RegionalRuntimeMembership.LeaseDuration + TimeSpan.FromSeconds(1);
        await Assert.That(Decide(own, existing: foreign, afterExpiry))
            .IsEqualTo(RegionalRuntimeMembershipMutationClass.TakeOverExpiredLease);

        // The deletion rule: only the owning session may delete, under its held revision.
        await Assert.That(RegionalRuntimeMembershipMutation.MayDeleteCurrentRecord(ForeignSession, foreign, heldRevision: 4))
            .IsTrue();
        await Assert.That(RegionalRuntimeMembershipMutation.MayDeleteCurrentRecord(OwnSession, foreign, heldRevision: 4))
            .IsFalse();
        await Assert.That(RegionalRuntimeMembershipMutation.MayDeleteCurrentRecord(ForeignSession, foreign, heldRevision: 0))
            .IsFalse();
        await Assert.That(RegionalRuntimeMembershipMutation.MayDeleteCurrentRecord(ForeignSession, current: null, heldRevision: 4))
            .IsFalse();
    }

    [Test]
    public async Task WrongBindingAndIdentityDiscontinuityAreRejected()
    {
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        using var otherIdentity = RegionalRuntimeMembershipIdentity.Create();
        var now = DateTimeOffset.UtcNow;
        var own = Member(identity, now, sessionId: OwnSession);
        var existing = Member(identity, now, sessionId: OwnSession);

        // A proposal for another instance or cell may never be written by this publisher.
        await Assert.That(RegionalRuntimeMembershipMutation.Decide(
                Cell, "controller-2", own with { Instance = "controller-2" }, existing, now))
            .IsEqualTo(RegionalRuntimeMembershipMutationClass.RejectWrongBinding);
        // A publisher bound to gru may not write a record claiming another cell.
        await Assert.That(RegionalRuntimeMembershipMutation.Decide(
                Cell, Instance, own with { Cell = "sfo", Cluster = "orchestrator-control-sfo" }, existing: null, now))
            .IsEqualTo(RegionalRuntimeMembershipMutationClass.RejectWrongBinding);

        // A record that already exists under the deterministic key but binds a
        // different instance is a wrong binding, not a takeover candidate.
        await Assert.That(RegionalRuntimeMembershipMutation.Decide(
                Cell, Instance, own, existing: existing with { Instance = "controller-2" }, now))
            .IsEqualTo(RegionalRuntimeMembershipMutationClass.RejectWrongBinding);

        // The same session may not silently change its signing key.
        await Assert.That(Decide(
                Member(otherIdentity, now, sessionId: OwnSession), existing, now))
            .IsEqualTo(RegionalRuntimeMembershipMutationClass.RejectWrongBinding);

        // A restarted process holds a fresh per-process key and a new session:
        // under a live lease it is held, and after the lease lapses it heals the
        // slot with a key rotation.
        var restartedKey = Member(
            otherIdentity, now, sessionId: Guid.NewGuid().ToString("N"));
        await Assert.That(Decide(restartedKey, existing, now))
            .IsEqualTo(RegionalRuntimeMembershipMutationClass.HoldForLiveForeignLease);
        await Assert.That(Decide(
                restartedKey,
                existing,
                now + RegionalRuntimeMembership.LeaseDuration + TimeSpan.FromSeconds(1)))
            .IsEqualTo(RegionalRuntimeMembershipMutationClass.TakeOverExpiredLease);

        // Unsigned proposals are refused outright.
        await Assert.That(Decide(own with { IdentitySignature = "" }, existing: null, now))
            .IsEqualTo(RegionalRuntimeMembershipMutationClass.RejectWrongBinding);
    }

    [Test]
    public async Task EpochAndRevisionRegressionIsRefused()
    {
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var now = DateTimeOffset.UtcNow;
        var current = Member(identity, now, sessionId: OwnSession, epoch: 9, revision: 40);

        await Assert.That(Decide(current with { AuthorityEpoch = 8 }, current, now))
            .IsEqualTo(RegionalRuntimeMembershipMutationClass.RejectStaleEpoch);
        await Assert.That(Decide(current with { AuthorityRevision = 39 }, current, now))
            .IsEqualTo(RegionalRuntimeMembershipMutationClass.RejectStaleEpoch);

        // Duplicate delivery of the identical proposal is an idempotent renewal.
        await Assert.That(Decide(current, current, now))
            .IsEqualTo(RegionalRuntimeMembershipMutationClass.RenewOwnRecord);
    }

    private static RegionalRuntimeMembershipMutationClass Decide(
        RegionalRuntimeMember proposed,
        RegionalRuntimeMember? existing,
        DateTimeOffset now) =>
        RegionalRuntimeMembershipMutation.Decide(Cell, Instance, proposed, existing, now);

    private static RegionalRuntimeMember Member(
        RegionalRuntimeMembershipIdentity identity,
        DateTimeOffset observedAt,
        string sessionId,
        long epoch = 9,
        long revision = 40)
    {
        var member = new RegionalRuntimeMember(
            1,
            Cell,
            $"orchestrator-control-{Cell}",
            Instance,
            sessionId,
            "test-build",
            ["authority", "regional-membership", "service-discovery"],
            observedAt.AddMinutes(-1),
            observedAt,
            observedAt.Add(RegionalRuntimeMembership.LeaseDuration),
            "leader",
            true,
            epoch,
            revision,
            identity.KeyId,
            identity.PublicKey,
            string.Empty);
        return member with { IdentitySignature = identity.Sign(member) };
    }
}

