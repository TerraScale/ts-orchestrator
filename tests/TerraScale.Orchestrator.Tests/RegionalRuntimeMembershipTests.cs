using System.Runtime.CompilerServices;
using System.Threading.Channels;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;
using NATS.Client.JetStream.Models;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class RegionalRuntimeMembershipTests
{
    [Test]
    public async Task MembershipDocumentCarriesStableDiscoveryIdentityAndAuthority()
    {
        var observedAt = DateTimeOffset.UtcNow;
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var member = Member(identity, observedAt);

        await Assert.That(member.IsValidFor("gru", observedAt)).IsTrue();
        await Assert.That(member.Cluster).IsEqualTo("orchestrator-control-gru");
        await Assert.That(member.Instance).IsEqualTo("controller-1");
        await Assert.That(member.AuthorityEpoch).IsEqualTo(7);
        await Assert.That(member.IsAuthorityLeader).IsTrue();
        await Assert.That(member.VerifySignedIdentity()).IsTrue();
    }

    [Test]
    public async Task MembershipRejectsExpiredCrossCellAndUnsortedRecords()
    {
        var observedAt = DateTimeOffset.UtcNow;
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var member = Member(identity, observedAt);

        await Assert.That((member with { LeaseExpiresAt = observedAt }).IsValidFor("gru", observedAt)).IsFalse();
        await Assert.That((member with { Cell = "sfo" }).IsValidFor("gru", observedAt)).IsFalse();
        await Assert.That((member with { Cluster = "product-gru" }).IsValidFor("gru", observedAt)).IsFalse();
        await Assert.That((member with { Capabilities = ["service-discovery", "authority"] })
            .IsValidFor("gru", observedAt)).IsFalse();
        await Assert.That((member with { AuthorityState = "follower" })
            .IsValidFor("gru", observedAt)).IsFalse();
    }

    [Test]
    public async Task MembershipSnapshotRequiresUniqueSortedActiveInstances()
    {
        var observedAt = DateTimeOffset.UtcNow;
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var first = Member(identity, observedAt);
        var second = Member(identity, observedAt, instance: "controller-2", leader: false);
        var health = RegionalRuntimeMembershipHealth.Evaluate("gru", 3, [first, second], 0, observedAt);
        var valid = new RegionalRuntimeMembershipSnapshot(2, "gru", observedAt, health, [first, second]);
        valid.Validate("gru");

        await Assert.That(() => (valid with { Members = [second, first] }).Validate("gru"))
            .Throws<InvalidOperationException>();
        await Assert.That(() => (valid with { Members = [first, first] }).Validate("gru"))
            .Throws<InvalidOperationException>();
        await Assert.That(() => (valid with { Members = [] }).Validate("gru"))
            .Throws<InvalidOperationException>();

        // Shape-valid identity material is still rejected when its signature
        // does not authenticate the member fields.
        await Assert.That(() => (valid with
        {
            Members = [first with { IdentitySignature = new string('A', 96) }, second]
        }).Validate("gru")).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task MembershipHealthMeasuresStaleMissingQuorumAndRecoveryState()
    {
        var observedAt = DateTimeOffset.UtcNow;
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var leader = Member(identity, observedAt.AddMilliseconds(-250));
        var follower = Member(
            identity, observedAt.AddMilliseconds(-250), instance: "controller-2", leader: false);
        var stale = Member(
            identity,
            observedAt.AddSeconds(-2),
            instance: "controller-3",
            leader: false,
            lease: TimeSpan.FromSeconds(1));

        var degraded = RegionalRuntimeMembershipHealth.Evaluate(
            "gru", 3, [leader, follower, stale], 4, observedAt);
        degraded.Validate();
        await Assert.That(degraded.ActiveControllers).IsEqualTo(2);
        await Assert.That(degraded.StaleControllers).IsEqualTo(1);
        await Assert.That(degraded.MissingControllers).IsEqualTo(1);
        await Assert.That(degraded.QuorumAvailable).IsTrue();
        await Assert.That(degraded.RejectedRecords).IsEqualTo(4);
        await Assert.That(degraded.MaximumHeartbeatAgeMilliseconds).IsGreaterThanOrEqualTo(250);
        await Assert.That(degraded.Condition).IsEqualTo(RegionalRuntimeMembershipCondition.Degraded);

        var recovered = RegionalRuntimeMembershipHealth.Evaluate(
            "gru",
            3,
            [leader, follower, Member(identity, observedAt, instance: "controller-3", leader: false)],
            4,
            observedAt);
        recovered.Validate();
        await Assert.That(recovered.ActiveControllers).IsEqualTo(3);
        await Assert.That(recovered.StaleControllers).IsEqualTo(0);
        await Assert.That(recovered.MissingControllers).IsEqualTo(0);
        await Assert.That(recovered.Condition).IsEqualTo(RegionalRuntimeMembershipCondition.Healthy);

        var unavailable = RegionalRuntimeMembershipHealth.Evaluate(
            "gru", 3, [stale], 4, observedAt);
        unavailable.Validate();
        await Assert.That(unavailable.QuorumAvailable).IsFalse();
        await Assert.That(unavailable.Condition).IsEqualTo(RegionalRuntimeMembershipCondition.Unavailable);
    }

    [Test]
    public async Task ConflictingSessionsAreACurrentGaugeNotALifetimeCounter()
    {
        // A conflict storm far beyond the slot count must never overflow the
        // projection: the conflicting count is bounded by the slots currently
        // observed, because it is derived per slot from the live record
        // classified against its immediately preceding observation.
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var observedAt = DateTimeOffset.UtcNow;
        var first = Member(identity, observedAt);
        var second = Member(identity, observedAt, instance: "controller-2", leader: false);
        var third = Member(identity, observedAt, instance: "controller-3", leader: false);
        var records = new[] { first, second, third };

        // Simulate many successive session changes on every slot: whatever the
        // history, the current gauge counts at most one conflict per slot.
        for (var rotation = 0; rotation < 10; rotation++)
        {
            var currentConflict = rotation % 2 == 0 ? 1 : 0;
            var health = RegionalRuntimeMembershipHealth.Evaluate(
                "gru", 3, records, 0, observedAt, currentConflict);
            health.Validate();
            await Assert.That(health.ConflictingControllers).IsEqualTo(currentConflict);
            await Assert.That(health.ConflictingControllers)
                .IsLessThanOrEqualTo(health.ActiveControllers + health.StaleControllers);
        }

        // The maximum expressible current conflict is one per observed slot: the
        // projection stays valid even in the fully conflicted state.
        var allConflicted = RegionalRuntimeMembershipHealth.Evaluate(
            "gru", 3, records, 0, observedAt, 3);
        allConflicted.Validate();
        await Assert.That(allConflicted.ConflictingControllers).IsEqualTo(3);
    }

    private static RegionalRuntimeMember Member(
        RegionalRuntimeMembershipIdentity identity,
        DateTimeOffset observedAt,
        string instance = "controller-1",
        bool leader = true,
        TimeSpan? lease = null)
    {
        var member = new RegionalRuntimeMember(
            1,
            "gru",
            "orchestrator-control-gru",
            instance,
            Guid.NewGuid().ToString("N"),
            "test-build",
            ["authority", "regional-membership", "service-discovery"],
            observedAt.AddMinutes(-1),
            observedAt,
            observedAt + (lease ?? RegionalRuntimeMembership.LeaseDuration),
            leader ? "leader" : "follower",
            leader,
            7,
            11,
            identity.KeyId,
            identity.PublicKey,
            string.Empty);
        return member with { IdentitySignature = identity.Sign(member) };
    }

    [Test]
    public async Task TransientHeartbeatFailuresAreRetriedWithoutFaultingTheLoop()
    {
        var store = new FakeMembershipStore();
        var membership = await StartAsync(store);
        try
        {
            // One JetStream blip mid-heartbeat: the tick is skipped, the lease has
            // three heartbeat intervals of slack, and the loop must retry on the
            // next tick instead of faulting Completion and exiting the process.
            store.MutationFailure = new NatsException("simulated transient JetStream timeout");
            await WaitUntilAsync(() => store.UpdateFailures >= 1, TimeSpan.FromSeconds(9));
            await Task.Delay(TimeSpan.FromSeconds(2));
            await Assert.That(membership.Completion.IsFaulted).IsFalse();

            // The next tick after the blip passes renews the lease successfully.
            store.MutationFailure = null;
            await WaitUntilAsync(() => store.UpdateAttempts >= 2, TimeSpan.FromSeconds(9));
            await Assert.That(store.RevisionOf("controller.controller-1")).IsGreaterThanOrEqualTo(2UL);
            await Assert.That(membership.Completion.IsFaulted).IsFalse();
        }
        finally
        {
            await membership.DisposeAsync();
        }
    }

    [Test]
    public async Task PersistentNonTransientHeartbeatFailuresStillFaultTheLoop()
    {
        var store = new FakeMembershipStore();
        var membership = await StartAsync(store);
        try
        {
            store.MutationFailure = new InvalidOperationException("persistent journal corruption");
            await WaitUntilAsync(() => membership.Completion.IsFaulted, TimeSpan.FromSeconds(9));
            await Assert.That(membership.Completion.IsFaulted).IsTrue();
        }
        finally
        {
            // Disposal drains the faulted loop and rethrows its exception (only
            // cancellation is swallowed); it must surface exactly the injected
            // non-transient failure.
            try
            {
                await membership.DisposeAsync();
            }
            catch (InvalidOperationException exception) when (
                exception.Message == "persistent journal corruption")
            {
            }
        }
    }

    [Test]
    public async Task LostSlotCasFaultsStillFaultTheLoopDespiteBeingNatsExceptions()
    {
        var store = new FakeMembershipStore();
        var membership = await StartAsync(store);
        try
        {
            // A lost slot (foreign takeover, deleted key) surfaces as a KV CAS
            // fault. NatsKVWrongLastRevisionException IS a NatsException subtype,
            // yet it is a protocol outcome, not an infrastructure transient: the
            // heartbeat cannot self-correct it, so it must stay fail-stop.
            store.MutationFailure = new NatsKVWrongLastRevisionException(new ApiError());
            await WaitUntilAsync(() => membership.Completion.IsFaulted, TimeSpan.FromSeconds(9));
            await Assert.That(membership.Completion.IsFaulted).IsTrue();
        }
        finally
        {
            try
            {
                await membership.DisposeAsync();
            }
            catch (NatsKVWrongLastRevisionException)
            {
            }
        }
    }

    [Test]
    public async Task TransientWatchFailuresReEstablishTheWatcherWithoutFaultingTheLoop()
    {
        var store = new FakeMembershipStore();
        var membership = await StartAsync(store);
        try
        {
            await WaitUntilAsync(() => store.WatchEstablishments == 1, TimeSpan.FromSeconds(5));

            // The live watch dies on a transient connection drop AND the first
            // re-establishment attempt fails transiently: both must be absorbed
            // with a retry, leaving the watcher replaying current records.
            store.FailNextWatchEstablishment = new NatsException("simulated transient watch failure");
            store.DropWatchers(new NatsException("simulated transient connection loss"));
            await WaitUntilAsync(() => store.WatchEstablishments >= 3, TimeSpan.FromSeconds(9));
            await Task.Delay(TimeSpan.FromSeconds(2));
            await Assert.That(membership.Completion.IsFaulted).IsFalse();
            await Assert.That(membership.Snapshot.Members.Select(static member => member.Instance))
                .IsEquivalentTo(["controller-1"]);
        }
        finally
        {
            await membership.DisposeAsync();
        }
    }

    private static Task<RegionalRuntimeMembership> StartAsync(FakeMembershipStore store) =>
        RegionalRuntimeMembership.StartAsync(
            store,
            new NatsTopology("gru", 3, "controller-1"),
            "test-build",
            ["authority", "regional-membership", "service-discovery"],
            DateTimeOffset.UtcNow,
            () => new RegionalAuthoritySnapshot(
                "leader", true, 7, 11,
                DateTimeOffset.UtcNow.AddSeconds(30),
                DateTimeOffset.UtcNow,
                null),
            CancellationToken.None);

    private static async Task WaitUntilAsync(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (!condition())
        {
            if (DateTime.UtcNow >= deadline)
                throw new TimeoutException("The regional runtime membership loop did not reach the expected state.");
            await Task.Delay(TimeSpan.FromMilliseconds(100));
        }
    }

    /// <summary>
    /// The minimal KV surface the membership loops touch: one deterministic
    /// controller key with create/update/delete compare-and-set semantics plus a
    /// bucket watch that replays current records and then streams live updates.
    /// Every other bucket operation is unsupported.
    /// </summary>
    private sealed class FakeMembershipStore : INatsKVStore
    {
        private const string StoreBucket = "ORCH_RUNTIME";
        private readonly object gate = new();
        private readonly Dictionary<string, (string Value, ulong Revision)> records = new(StringComparer.Ordinal);
        private readonly List<Channel<NatsKVEntry<string>>> watchers = [];
        private ulong revisionCounter;

        internal Exception? MutationFailure { get; set; }
        internal Exception? FailNextWatchEstablishment { get; set; }
        internal int WatchEstablishments { get; private set; }
        internal int UpdateAttempts { get; private set; }
        internal int UpdateFailures { get; private set; }

        internal ulong RevisionOf(string key)
        {
            lock (gate) return records[key].Revision;
        }

        string INatsKVStore.Bucket => StoreBucket;

        INatsJSContext INatsKVStore.JetStreamContext => throw new NotSupportedException();

        ValueTask<ulong> INatsKVStore.CreateAsync<T>(
            string key, T value, INatsSerialize<T>? serializer, CancellationToken cancellationToken)
        {
            if (MutationFailure is { } failure) return ValueTask.FromException<ulong>(failure);
            lock (gate)
            {
                if (records.ContainsKey(key))
                    return ValueTask.FromException<ulong>(new NatsKVCreateException());
                var revision = Store(key, value!.ToString()!);
                return ValueTask.FromResult(revision);
            }
        }

        ValueTask<ulong> INatsKVStore.UpdateAsync<T>(
            string key, T value, ulong revision, INatsSerialize<T>? serializer, CancellationToken cancellationToken)
        {
            UpdateAttempts++;
            if (MutationFailure is { } failure)
            {
                UpdateFailures++;
                return ValueTask.FromException<ulong>(failure);
            }
            lock (gate)
            {
                if (records.TryGetValue(key, out var current) && current.Revision == revision)
                {
                    var next = Store(key, value!.ToString()!);
                    return ValueTask.FromResult(next);
                }
            }
            return ValueTask.FromException<ulong>(new NatsKVWrongLastRevisionException(new ApiError()));
        }

        ValueTask<NatsKVEntry<T>> INatsKVStore.GetEntryAsync<T>(
            string key, ulong revision, INatsDeserialize<T>? serializer, CancellationToken cancellationToken)
        {
            if (MutationFailure is { } failure)
                return ValueTask.FromException<NatsKVEntry<T>>(failure);
            lock (gate)
            {
                if (!records.TryGetValue(key, out var current))
                    return ValueTask.FromException<NatsKVEntry<T>>(NatsKVKeyNotFoundException.Default);
                return ValueTask.FromResult(new NatsKVEntry<T>(StoreBucket, key)
                {
                    Value = (T)(object)current.Value,
                    Revision = current.Revision,
                    Operation = NatsKVOperation.Put,
                });
            }
        }

        ValueTask INatsKVStore.DeleteAsync(string key, NatsKVDeleteOpts? opts, CancellationToken cancellationToken)
        {
            lock (gate)
            {
                if (records.TryGetValue(key, out var current) && current.Revision == opts?.Revision)
                {
                    records.Remove(key);
                    Publish(new NatsKVEntry<string>(StoreBucket, key)
                    {
                        Value = null,
                        Revision = current.Revision,
                        Operation = NatsKVOperation.Del,
                    });
                    return ValueTask.CompletedTask;
                }
            }
            throw new NatsKVWrongLastRevisionException(new ApiError());
        }

        IAsyncEnumerable<NatsKVEntry<T>> INatsKVStore.WatchAsync<T>(
            string key, INatsDeserialize<T>? serializer, NatsKVWatchOpts? opts, CancellationToken cancellationToken) =>
            WatchAsync<T>(key, cancellationToken);

        private async IAsyncEnumerable<NatsKVEntry<T>> WatchAsync<T>(
            string key, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var watchKey = key.EndsWith('>') ? key[..^1] : key;
            var channel = Channel.CreateUnbounded<NatsKVEntry<string>>();
            lock (gate)
            {
                WatchEstablishments++;
                if (FailNextWatchEstablishment is { } failure)
                {
                    FailNextWatchEstablishment = null;
                    throw failure;
                }
                watchers.Add(channel);
                foreach (var (recordKey, record) in records)
                    if (recordKey.StartsWith(watchKey, StringComparison.Ordinal))
                        channel.Writer.TryWrite(Entry(recordKey, record));
            }
            try
            {
                await foreach (var entry in channel.Reader.ReadAllAsync(cancellationToken))
                    yield return new NatsKVEntry<T>(StoreBucket, entry.Key)
                    {
                        Value = (T)(object)entry.Value!,
                        Revision = entry.Revision,
                        Operation = entry.Operation,
                    };
            }
            finally
            {
                lock (gate) watchers.Remove(channel);
            }
        }

        private ulong Store(string key, string value)
        {
            revisionCounter++;
            records[key] = (value, revisionCounter);
            Publish(Entry(key, records[key]));
            return revisionCounter;
        }

        private void Publish(NatsKVEntry<string> entry)
        {
            foreach (var watcher in watchers)
                watcher.Writer.TryWrite(entry);
        }

        private static NatsKVEntry<string> Entry(string key, (string Value, ulong Revision) record) => new(
            StoreBucket, key)
        {
            Value = record.Value,
            Revision = record.Revision,
            Operation = NatsKVOperation.Put,
        };

        internal void DropWatchers(Exception exception)
        {
            lock (gate)
            {
                foreach (var watcher in watchers) watcher.Writer.TryComplete(exception);
            }
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
