using System.Diagnostics;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Real-R3 membership evidence in the one-region L0C component lane: two
/// credentialed controller instances discover each other through the bounded
/// ORCH_RUNTIME KV bucket under a real authority election, keep renewing their
/// leases through the loss of one of the three NATS members, and converge again
/// after the member returns. This is R3 component evidence for regional
/// membership, not gateway, systemd, host-failure, or production qualification.
/// </summary>
[NotInParallel(LocalNatsServerLease.SchedulingConstraint)]
public sealed class NatsControlR3MembershipTests
{
    private static readonly TimeSpan ConvergenceTimeout = TimeSpan.FromSeconds(20);

    [Test]
    public async Task TwoControllersDiscoverEachOtherAndSurviveOneMemberLossUnderFencing()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        await fixture.ProvisionAsync();
        var cell = fixture.Topology.Cell;

        // Two controller clients on two different members: the fault below kills
        // the third member, which neither client is connected to. Production-shaped
        // request timeouts: the R3 meta layer on a loaded host cannot always answer
        // a stream-info probe inside the fixture's tight 3s default (the same
        // precedent the lane's global-authority retention test sets).
        await using var controllerOne = await ConnectControllerAsync(fixture, fixture.Controller, 0);
        await using var controllerTwo = await ConnectControllerAsync(fixture, fixture.ControllerTwo, 1);
        var runtimeStore = await OpenStoreWithRetryAsync(controllerOne, fixture.Topology.Runtime.Bucket);
        var leadersStore = await OpenStoreWithRetryAsync(controllerTwo, fixture.Topology.Leaders.Bucket);

        using var identityOne = RegionalRuntimeMembershipIdentity.Create();
        using var identityTwo = RegionalRuntimeMembershipIdentity.Create();
        var authorityOne = await RegionalAuthorityCoordinator.StartAsync(
            leadersStore, cell, "controller-1", default);
        var authorityTwo = await RegionalAuthorityCoordinator.StartAsync(
            leadersStore, cell, "controller-2", default);
        RegionalRuntimeMembership? membershipOne = null;
        RegionalRuntimeMembership? membershipTwo = null;
        try
        {
            var startedAt = DateTimeOffset.UtcNow;
            membershipOne = await RegionalRuntimeMembership.StartAsync(
                runtimeStore,
                new NatsTopology(cell, 3, "controller-1"),
                "test-build",
                ["authority", "regional-membership", "service-discovery"],
                startedAt,
                () => authorityOne.Snapshot,
                default,
                identityOne);
            membershipTwo = await RegionalRuntimeMembership.StartAsync(
                runtimeStore,
                new NatsTopology(cell, 3, "controller-2"),
                "test-build",
                ["authority", "regional-membership", "service-discovery"],
                startedAt,
                () => authorityTwo.Snapshot,
                default,
                identityTwo);

            // -----------------------------------------------------------------
            // Discovery: both instances converge on the same two signed members
            // with exactly one leader under fencing.
            // -----------------------------------------------------------------
            var discovered = await WaitForAsync(
                () => membershipOne.Snapshot.Members.Count == 2 &&
                      membershipTwo.Snapshot.Members.Count == 2
                    ? membershipOne.Snapshot
                    : null,
                ConvergenceTimeout,
                "both controllers to observe each other");
            discovered.Validate(cell);
            foreach (var member in discovered.Members)
            {
                await Assert.That(member.VerifySignedIdentity()).IsTrue();
                await Assert.That(member.Cluster).IsEqualTo($"orchestrator-control-{cell}");
            }
            await Assert.That(discovered.Health.ActiveControllers).IsEqualTo(2);
            await Assert.That(discovered.Health.ConflictingControllers).IsEqualTo(0);
            await Assert.That(discovered.Health.AuthorityLeaders).IsEqualTo(1);
            await Assert.That(discovered.Health.QuorumAvailable).IsTrue();
            await Assert.That(discovered.Health.Condition)
                .IsEqualTo(RegionalRuntimeMembershipCondition.Degraded);

            // A live record in an unconfigured slot must not fill the missing
            // configured slot or satisfy the health projection. This uses the
            // real KV watch and production Snapshot path, rather than calling
            // the pure health evaluator directly.
            using var unexpectedIdentity = RegionalRuntimeMembershipIdentity.Create();
            var unexpectedRecord = MembershipRecord(
                cell,
                unexpectedIdentity,
                DateTimeOffset.UtcNow,
                "controller-9",
                leader: false);
            await runtimeStore.CreateAsync("controller.controller-9", SerializeRecord(unexpectedRecord));
            var withUnexpected = await WaitForAsync(
                () => membershipOne.Snapshot.Members.Count == 3
                    ? membershipOne.Snapshot
                    : null,
                ConvergenceTimeout,
                "the unexpected membership slot to reach the snapshot");
            withUnexpected.Validate(cell);
            await Assert.That(withUnexpected.Health.ActiveControllers).IsEqualTo(3);
            await Assert.That(withUnexpected.Health.MissingControllers).IsEqualTo(1);
            await Assert.That(withUnexpected.Health.UnexpectedControllers).IsEqualTo(1);
            await Assert.That(withUnexpected.Health.QuorumAvailable).IsTrue();
            await Assert.That(withUnexpected.Health.Condition)
                .IsEqualTo(RegionalRuntimeMembershipCondition.Degraded);
            await runtimeStore.DeleteAsync("controller.controller-9");
            await WaitForAsync(
                () => membershipOne.Snapshot.Members.Count == 2
                    ? membershipOne.Snapshot
                    : null,
                ConvergenceTimeout,
                "the unexpected membership slot to leave the snapshot");
            var sessionsBefore = discovered.Members
                .ToDictionary(static member => member.Instance, static member => member.SessionId, StringComparer.Ordinal);
            var identitiesBefore = discovered.Members
                .ToDictionary(static member => member.Instance, static member => member.IdentityKeyId, StringComparer.Ordinal);
            var epochBefore = discovered.Members
                .Select(static member => member.AuthorityEpoch)
                .Order()
                .ToArray();

            // -----------------------------------------------------------------
            // One-member loss: the third NATS server disappears. Quorum survives,
            // so both instances keep renewing their leases and the leader keeps
            // its fenced authority without a duplicate owner.
            // -----------------------------------------------------------------
            await fixture.KillMemberAsync(2);

            // Across the loss window, the same sessions keep renewing: identity and
            // session continuity with advancing leases. Renewal is read from the KV
            // source of truth (the watch consumer can migrate leaders when a member
            // dies, so the local view may lag), with a bounded poll.
            var firstLease = ReadLeases(runtimeStore);
            var renewalDeadline = Stopwatch.GetTimestamp();
            while (Stopwatch.GetElapsedTime(renewalDeadline) < TimeSpan.FromSeconds(30))
            {
                var current = ReadLeases(runtimeStore);
                if (current["controller-1"] > firstLease["controller-1"] &&
                    current["controller-2"] > firstLease["controller-2"])
                {
                    break;
                }
                await Task.Delay(TimeSpan.FromMilliseconds(500));
            }
            var renewed = ReadLeases(runtimeStore);
            await Assert.That(renewed["controller-1"]).IsGreaterThan(firstLease["controller-1"]);
            await Assert.That(renewed["controller-2"]).IsGreaterThan(firstLease["controller-2"]);

            var duringLoss = membershipOne.Snapshot;
            duringLoss.Validate(cell);
            await Assert.That(duringLoss.Health.ActiveControllers).IsEqualTo(2);
            await Assert.That(duringLoss.Health.AuthorityLeaders).IsEqualTo(1);
            await Assert.That(duringLoss.Health.QuorumAvailable).IsTrue();
            await Assert.That(duringLoss.Health.MaximumHeartbeatAgeMilliseconds)
                .IsLessThan((long)RegionalRuntimeMembership.LeaseDuration.TotalMilliseconds);
            foreach (var member in duringLoss.Members)
            {
                await Assert.That(sessionsBefore[member.Instance]).IsEqualTo(member.SessionId);
                await Assert.That(identitiesBefore[member.Instance]).IsEqualTo(member.IdentityKeyId);
            }
            // Zero duplicate ownership: at every observation exactly one leader held
            // the fenced authority, and the epoch never regressed.
            for (var probe = 0; probe < 5; probe++)
            {
                await Assert.That(membershipOne.Snapshot.Health.AuthorityLeaders).IsEqualTo(1);
                await Assert.That(membershipTwo.Snapshot.Health.AuthorityLeaders).IsEqualTo(1);
                await Task.Delay(TimeSpan.FromMilliseconds(300));
            }

            // -----------------------------------------------------------------
            // Recovery: the member returns and the R3 store stays intact.
            // -----------------------------------------------------------------
            await fixture.RestartMemberAsync(2);
            await using var infrastructure = await fixture.ConnectAsync(fixture.Infrastructure, member: 2);
            var stream = await infrastructure.CreateJetStreamContext()
                .GetStreamAsync($"KV_{fixture.Topology.Runtime.Bucket}");
            await Assert.That(stream.Info.Config.NumReplicas).IsEqualTo(3);

            var recovered = await WaitForAsync(
                () => membershipTwo.Snapshot.Members.Count == 2 &&
                      membershipTwo.Snapshot.Health.ActiveControllers == 2
                    ? membershipTwo.Snapshot
                    : null,
                ConvergenceTimeout,
                "membership to converge after the member returned");
            recovered.Validate(cell);
            await Assert.That(recovered.Health.AuthorityLeaders).IsEqualTo(1);
            foreach (var member in recovered.Members)
            {
                await Assert.That(sessionsBefore[member.Instance]).IsEqualTo(member.SessionId);
                await Assert.That(member.VerifySignedIdentity()).IsTrue();
            }
            var epochsAfter = recovered.Members
                .Select(static member => member.AuthorityEpoch)
                .Order()
                .ToArray();
            for (var index = 0; index < epochsAfter.Length; index++)
                await Assert.That(epochsAfter[index]).IsGreaterThanOrEqualTo(epochBefore[index]);
        }
        finally
        {
            if (membershipTwo is not null) await membershipTwo.DisposeAsync();
            if (membershipOne is not null) await membershipOne.DisposeAsync();
            await authorityTwo.DisposeAsync();
            await authorityOne.DisposeAsync();
        }
    }

    /// <summary>
    /// Real-bucket healing of a dead member's leftover record. The record is
    /// written by an external writer and never renewed or deleted — exactly what
    /// a crashed process leaves behind — so the live-lease claim is held, and
    /// after the semantic lease lapses the slot heals through the KV
    /// compare-and-swap update path. Two healers racing for the same observed
    /// revision produce exactly one winner; the loser is refused with the typed
    /// active-lease error, never the raw KV revision exception.
    /// </summary>
    [Test]
    public async Task ExpiredSlotHealsUnderCasAndAHealRaceRefusesTheLoserWithATypedError()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        await fixture.ProvisionAsync();
        var cell = fixture.Topology.Cell;
        var topology = new NatsTopology(cell, 3, "controller-1");

        // One shared authority so every membership candidate sees a ready snapshot.
        await using var authorityClient = await ConnectControllerAsync(fixture, fixture.Controller, 0);
        await using var authority = await RegionalAuthorityCoordinator.StartAsync(
            await OpenStoreWithRetryAsync(authorityClient, fixture.Topology.Leaders.Bucket),
            cell,
            "controller-1",
            default);

        // The dead member's leftover record: externally written, live lease.
        await using var writer = await ConnectControllerAsync(fixture, fixture.ControllerTwo, 1);
        var writerStore = await OpenStoreWithRetryAsync(writer, fixture.Topology.Runtime.Bucket);
        using var deadIdentity = RegionalRuntimeMembershipIdentity.Create();
        var deadRecord = MembershipRecord(cell, deadIdentity, DateTimeOffset.UtcNow);
        var deadRevision = await writerStore.CreateAsync(
            $"controller.{topology.Instance}",
            SerializeRecord(deadRecord));

        // While the leftover lease is live, a claim on the slot is held.
        using var healerAIdentity = RegionalRuntimeMembershipIdentity.Create();
        using var healerBIdentity = RegionalRuntimeMembershipIdentity.Create();
        await Assert.That(async () =>
        {
            await using var rejected = await RegionalRuntimeMembership.StartAsync(
                writerStore,
                topology,
                "test-build",
                ["authority", "regional-membership", "service-discovery"],
                DateTimeOffset.UtcNow,
                () => authority.Snapshot,
                default,
                healerAIdentity);
        }).Throws<InvalidOperationException>();

        // The lease lapses with nobody renewing it: the member is dead.
        await Task.Delay(RegionalRuntimeMembership.LeaseDuration + TimeSpan.FromSeconds(2));

        // Two healers race for the same lapsed slot over their own connections.
        await using var healerClientA = await ConnectControllerAsync(fixture, fixture.Controller, 0);
        await using var healerClientB = await ConnectControllerAsync(fixture, fixture.ControllerTwo, 1);
        var race = await Task.WhenAll(
            TryStartAsync(
                await OpenStoreWithRetryAsync(healerClientA, fixture.Topology.Runtime.Bucket),
                topology, healerAIdentity, () => authority.Snapshot),
            TryStartAsync(
                await OpenStoreWithRetryAsync(healerClientB, fixture.Topology.Runtime.Bucket),
                topology, healerBIdentity, () => authority.Snapshot));

        // Exactly one healer wins the compare-and-swap.
        await Assert.That(race.Count(static attempt => attempt.Membership is not null)).IsEqualTo(1);
        var winner = race.Single(static attempt => attempt.Membership is not null);
        var loser = race.Single(static attempt => attempt.Membership is null);

        // The loser is refused with the typed active-lease error: the raw KV
        // wrong-last-revision exception of the lost race never escapes.
        await Assert.That(loser.Failure).IsNotNull();
        await Assert.That(loser.Failure!).IsTypeOf<InvalidOperationException>();
        await Assert.That(loser.Failure!.Message).Contains("active membership lease");

        // The winner healed the slot through the update path: the key never
        // disappeared and its revision advanced beyond the dead record's.
        var healedEntry = await writerStore.GetEntryAsync<string>($"controller.{topology.Instance}");
        healedEntry.EnsureSuccess();
        await Assert.That(healedEntry.Revision).IsGreaterThan(deadRevision);
        var healedRecord = DeserializeRecord(healedEntry.Value!);
        await Assert.That(healedRecord.VerifySignedIdentity()).IsTrue();
        await Assert.That(new[] { healerAIdentity.KeyId, healerBIdentity.KeyId })
            .Contains(healedRecord.IdentityKeyId);

        var snapshot = await WaitForAsync(
            () => winner.Membership!.Snapshot.Members.Count == 1 ? winner.Membership.Snapshot : null,
            ConvergenceTimeout,
            "the winning healer to observe its own record");
        snapshot.Validate(cell);
        await Assert.That(snapshot.Health.ConflictingControllers).IsEqualTo(0);
        await Assert.That(snapshot.Members.Single().SessionId).IsEqualTo(healedRecord.SessionId);
        // The winner's own view of the slot is its own record, under its own key.
        await Assert.That(snapshot.Members.Single().IdentityKeyId).IsEqualTo(healedRecord.IdentityKeyId);

        await winner.Membership!.DisposeAsync();
    }

    private static async Task<(RegionalRuntimeMembership? Membership, Exception? Failure)> TryStartAsync(
        INatsKVStore store,
        NatsTopology topology,
        RegionalRuntimeMembershipIdentity identity,
        Func<RegionalAuthoritySnapshot> authority)
    {
        try
        {
            return (await RegionalRuntimeMembership.StartAsync(
                store,
                topology,
                "test-build",
                ["authority", "regional-membership", "service-discovery"],
                DateTimeOffset.UtcNow,
                authority,
                default,
                identity), null);
        }
        catch (Exception failure)
        {
            return (null, failure);
        }
    }

    private static RegionalRuntimeMember MembershipRecord(
        string cell,
        RegionalRuntimeMembershipIdentity identity,
        DateTimeOffset observedAt,
        string instance = "controller-1",
        bool leader = true)
    {
        var member = new RegionalRuntimeMember(
            1,
            cell,
            $"orchestrator-control-{cell}",
            instance,
            Guid.NewGuid().ToString("N"),
            "test-build",
            ["authority", "regional-membership", "service-discovery"],
            observedAt.AddMinutes(-1),
            observedAt,
            observedAt.Add(RegionalRuntimeMembership.LeaseDuration),
            leader ? "leader" : "follower",
            leader,
            7,
            11,
            identity.KeyId,
            identity.PublicKey,
            string.Empty);
        return member with { IdentitySignature = identity.Sign(member) };
    }

    private static string SerializeRecord(RegionalRuntimeMember member) => System.Text.Json.JsonSerializer.Serialize(
        member,
        RegionalRuntimeMembershipJsonContext.Default.RegionalRuntimeMember);

    private static RegionalRuntimeMember DeserializeRecord(string value) => System.Text.Json.JsonSerializer.Deserialize(
        value,
        RegionalRuntimeMembershipJsonContext.Default.RegionalRuntimeMember)
        ?? throw new InvalidOperationException("The membership record is empty.");

    private static IReadOnlyDictionary<string, DateTimeOffset> ReadLeases(
        NATS.Client.KeyValueStore.INatsKVStore store)
    {
        var leases = new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal);
        foreach (var instance in new[] { "controller-1", "controller-2" })
        {
            var entry = store.GetEntryAsync<string>($"controller.{instance}").GetAwaiter().GetResult();
            entry.EnsureSuccess();
            var member = System.Text.Json.JsonSerializer.Deserialize(
                entry.Value ?? throw new InvalidOperationException("The membership record is empty."),
                RegionalRuntimeMembershipJsonContext.Default.RegionalRuntimeMember)
                ?? throw new InvalidOperationException("The membership record is empty.");
            leases[instance] = member.LeaseExpiresAt;
        }
        return leases;
    }

    private static async Task<NatsClient> ConnectControllerAsync(
        NatsControlR3L0cFixture fixture,
        NatsControlR3L0cFixture.NatsControlR3L0cIdentity identity,
        int member)
    {
        var client = new NatsClient(fixture.ClientOptions(identity, member) with
        {
            RequestTimeout = TimeSpan.FromSeconds(15),
        });
        try
        {
            await client.ConnectAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
            return client;
        }
        catch
        {
            await client.DisposeAsync();
            throw;
        }
    }

    private static async Task<NATS.Client.KeyValueStore.INatsKVStore> OpenStoreWithRetryAsync(
        NatsClient client,
        string bucket)
    {
        // The same settling window the L0C lane uses: an R3 meta layer that has
        // just formed may answer the first stream-info requests with a timeout.
        for (var attempt = 0; attempt < 16; attempt++)
        {
            try
            {
                return await client.CreateJetStreamContext()
                    .CreateKeyValueStoreContext()
                    .GetStoreAsync(bucket);
            }
            catch (NATS.Client.Core.NatsException) when (attempt < 15)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(500));
            }
        }
        throw new TimeoutException("The R3 membership store did not become readable.");
    }

    private static async Task<RegionalRuntimeMembershipSnapshot> WaitForAsync(
        Func<RegionalRuntimeMembershipSnapshot?> condition,
        TimeSpan timeout,
        string description)
    {
        var started = Stopwatch.GetTimestamp();
        while (Stopwatch.GetElapsedTime(started) < timeout)
        {
            if (condition() is { } snapshot) return snapshot;
            await Task.Delay(TimeSpan.FromMilliseconds(200));
        }
        throw new TimeoutException($"Timed out waiting for {description} within {timeout.TotalSeconds} seconds.");
    }
}
