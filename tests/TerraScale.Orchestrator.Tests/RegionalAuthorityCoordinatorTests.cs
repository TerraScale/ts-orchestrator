using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.ControlPlane.Authority;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class RegionalAuthorityCoordinatorTests
{
    [Test]
    public async Task AnUnvalidatableLeaseDocumentFencesInsteadOfCrashLoopingEveryCandidate()
    {
        // A lease document written by a different build's schema must surface as a fenced,
        // explicitly leaderless cell — not as an exception that crash-loops every candidate.
        var store = new FakeAuthorityStore();
        store.SeedLease(
            """{"SchemaVersion":99,"AuthorityId":"gru-regional","Epoch":3,"CandidateId":"gru-controller-9","LeaseId":"lease-foreign","IssuedAt":"2026-09-18T00:00:00Z","DurationMilliseconds":15000}""",
            revision: 4);

        var coordinator = await RegionalAuthorityCoordinator.StartAsync(store, "gru", "1", CancellationToken.None);
        try
        {
            var snapshot = coordinator.Snapshot;
            await Assert.That(snapshot.Ready).IsFalse();
            await Assert.That(snapshot.IsLeader).IsFalse();
            await Assert.That(snapshot.State).IsEqualTo("follower");
            await Assert.That(snapshot.Error).IsEqualTo("authority-lease-invalid");
            await Assert.That(coordinator.Completion.IsFaulted).IsFalse();
        }
        finally
        {
            await coordinator.DisposeAsync();
        }
    }

    [Test]
    public async Task TransientNatsFailuresDemoteTheCandidateWithoutFaultingTheTickLoop()
    {
        var store = new FakeAuthorityStore();
        var coordinator = await RegionalAuthorityCoordinator.StartAsync(store, "gru", "1", CancellationToken.None);
        try
        {
            await Assert.That(coordinator.Snapshot.IsLeader).IsTrue();

            // A transient NATS failure (timeout, connection loss) on a later tick must demote
            // the candidate to an explicit unavailable snapshot and keep the loop alive; only
            // persistent failure may fault Completion and exit the process.
            store.Failure = new NatsException("simulated transient connection loss");
            var deadline = Task.Delay(TimeSpan.FromSeconds(10));
            while (coordinator.Snapshot.State != "unavailable" && !deadline.IsCompleted)
                await Task.Delay(TimeSpan.FromMilliseconds(100));

            await Assert.That(coordinator.Snapshot.State).IsEqualTo("unavailable");
            await Assert.That(coordinator.Snapshot.Error).IsEqualTo("gru-regional-nats-unavailable");
            await Assert.That(coordinator.Completion.IsFaulted).IsFalse();
        }
        finally
        {
            await coordinator.DisposeAsync();
        }
    }

    [Test]
    public async Task LeaseDocumentRoundTripsExactFencingIdentity()
    {
        var issuedAt = DateTimeOffset.UtcNow.AddSeconds(-1);
        var lease = new AuthorityLease(
            "gru-controller-2",
            "lease-123",
            issuedAt,
            TimeSpan.FromSeconds(15));

        var document = RegionalAuthorityLeaseDocument.From("gru-regional", 7, lease);
        document.Validate();

        await Assert.That(document.Epoch).IsEqualTo(7);
        await Assert.That(document.ToLease()).IsEqualTo(lease);
    }

    [Test]
    public async Task LeaseDocumentRejectsCrossBoundaryAndUnboundedValues()
    {
        var valid = RegionalAuthorityLeaseDocument.From(
            "gru-regional",
            1,
            new AuthorityLease(
                "gru-controller-1",
                "lease-1",
                DateTimeOffset.UtcNow,
                TimeSpan.FromSeconds(15)));

        await Assert.That(() => (valid with { Epoch = 0 }).Validate())
            .Throws<InvalidOperationException>();
        await Assert.That(() => (valid with { DurationMilliseconds = 60_001 }).Validate())
            .Throws<InvalidOperationException>();
        await Assert.That(() => (valid with { CandidateId = "" }).Validate())
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task AuthorityReadinessRequiresFreshNonFencedObservation()
    {
        var future = DateTimeOffset.UtcNow.AddSeconds(10);
        var leader = new RegionalAuthoritySnapshot(
            "leader", true, 2, 3, future, DateTimeOffset.UtcNow, null);

        await Assert.That(leader.Ready).IsTrue();
        await Assert.That((leader with { State = "follower", IsLeader = false }).Ready).IsTrue();
        await Assert.That((leader with { State = "fenced", IsLeader = false }).Ready).IsFalse();
        await Assert.That((leader with { State = "held", IsLeader = false }).Ready).IsFalse();
        await Assert.That((leader with { ObservedAt = DateTimeOffset.UtcNow.AddMinutes(-1) }).Ready).IsFalse();
        await Assert.That((leader with { Error = "uncertain" }).Ready).IsFalse();
        await Assert.That((leader with { LeaseExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) }).Ready)
            .IsFalse();
    }

    /// <summary>
    /// The minimal KV surface the authority coordinator touches: one lease key with
    /// create/update compare-and-set semantics. Every other bucket operation is unsupported.
    /// </summary>
    private sealed class FakeAuthorityStore : INatsKVStore
    {
        private (string Value, ulong Revision)? lease;

        internal Exception? Failure { get; set; }

        internal void SeedLease(string value, ulong revision) => lease = (value, revision);

        string INatsKVStore.Bucket => "ORCH_LEADERS";

        INatsJSContext INatsKVStore.JetStreamContext => throw new NotSupportedException();

        ValueTask<ulong> INatsKVStore.CreateAsync<T>(
            string key, T value, INatsSerialize<T>? serializer, CancellationToken cancellationToken)
        {
            if (Failure is { } failure) return ValueTask.FromException<ulong>(failure);
            if (lease is not null) return ValueTask.FromException<ulong>(new NatsKVCreateException());
            lease = (value!.ToString()!, 1);
            return ValueTask.FromResult(1UL);
        }

        ValueTask<ulong> INatsKVStore.UpdateAsync<T>(
            string key, T value, ulong revision, INatsSerialize<T>? serializer, CancellationToken cancellationToken)
        {
            if (Failure is { } failure) return ValueTask.FromException<ulong>(failure);
            if (lease is not { } current || current.Revision != revision)
                return ValueTask.FromException<ulong>(new NatsKVCreateException());
            lease = (value!.ToString()!, current.Revision + 1);
            return ValueTask.FromResult(current.Revision + 1);
        }

        ValueTask<NatsKVEntry<T>> INatsKVStore.GetEntryAsync<T>(
            string key, ulong revision, INatsDeserialize<T>? serializer, CancellationToken cancellationToken)
        {
            if (Failure is { } failure)
                return ValueTask.FromException<NatsKVEntry<T>>(failure);
            if (lease is not { } current)
                return ValueTask.FromException<NatsKVEntry<T>>(NatsKVKeyNotFoundException.Default);
            return ValueTask.FromResult(new NatsKVEntry<T>("ORCH_LEADERS", key)
            {
                Value = (T)(object)current.Value,
                Revision = current.Revision,
                Operation = NatsKVOperation.Put,
            });
        }

        ValueTask<ulong> INatsKVStore.PutAsync<T>(
            string key, T value, INatsSerialize<T>? serializer, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        ValueTask<NatsResult<ulong>> INatsKVStore.TryPutAsync<T>(
            string key, T value, INatsSerialize<T>? serializer, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        ValueTask<ulong> INatsKVStore.CreateAsync<T>(
            string key, T value, TimeSpan ttl, INatsSerialize<T>? serializer, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        ValueTask<NatsResult<ulong>> INatsKVStore.TryCreateAsync<T>(
            string key, T value, INatsSerialize<T>? serializer, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        ValueTask<NatsResult<ulong>> INatsKVStore.TryCreateAsync<T>(
            string key, T value, TimeSpan ttl, INatsSerialize<T>? serializer, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        ValueTask<NatsResult<ulong>> INatsKVStore.TryUpdateAsync<T>(
            string key, T value, ulong revision, INatsSerialize<T>? serializer, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        ValueTask INatsKVStore.DeleteAsync(
            string key, NatsKVDeleteOpts? opts, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        ValueTask<NatsResult> INatsKVStore.TryDeleteAsync(
            string key, NatsKVDeleteOpts? opts, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        ValueTask INatsKVStore.PurgeAsync(
            string key, NatsKVDeleteOpts? opts, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        ValueTask INatsKVStore.PurgeAsync(
            string key, TimeSpan ttl, NatsKVDeleteOpts? opts, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        ValueTask<NatsResult> INatsKVStore.TryPurgeAsync(
            string key, NatsKVDeleteOpts? opts, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        ValueTask<NatsResult> INatsKVStore.TryPurgeAsync(
            string key, TimeSpan ttl, NatsKVDeleteOpts? opts, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        ValueTask<NatsResult<NatsKVEntry<T>>> INatsKVStore.TryGetEntryAsync<T>(
            string key, ulong revision, INatsDeserialize<T>? serializer, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        IAsyncEnumerable<NatsKVEntry<T>> INatsKVStore.WatchAsync<T>(
            string key, INatsDeserialize<T>? serializer, NatsKVWatchOpts? opts, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        IAsyncEnumerable<NatsKVEntry<T>> INatsKVStore.WatchAsync<T>(
            IEnumerable<string> keys, INatsDeserialize<T>? serializer, NatsKVWatchOpts? opts, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        IAsyncEnumerable<NatsKVEntry<T>> INatsKVStore.WatchAsync<T>(
            INatsDeserialize<T>? serializer, NatsKVWatchOpts? opts, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        IAsyncEnumerable<NatsKVEntry<T>> INatsKVStore.HistoryAsync<T>(
            string key, INatsDeserialize<T>? serializer, NatsKVWatchOpts? opts, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        ValueTask<NatsKVStatus> INatsKVStore.GetStatusAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        ValueTask INatsKVStore.PurgeDeletesAsync(NatsKVPurgeOpts? opts, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        IAsyncEnumerable<string> INatsKVStore.GetKeysAsync(
            NatsKVWatchOpts? opts, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        IAsyncEnumerable<string> INatsKVStore.GetKeysAsync(
            IEnumerable<string> filters, NatsKVWatchOpts? opts, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}

