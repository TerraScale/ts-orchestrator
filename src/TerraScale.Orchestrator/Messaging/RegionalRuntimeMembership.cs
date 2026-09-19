using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;

namespace TerraScale.Orchestrator.Messaging;

internal sealed record RegionalRuntimeMember(
    int SchemaVersion,
    string Cell,
    string Cluster,
    string Instance,
    string SessionId,
    string Build,
    IReadOnlyList<string> Capabilities,
    DateTimeOffset StartedAt,
    DateTimeOffset ObservedAt,
    DateTimeOffset LeaseExpiresAt,
    string AuthorityState,
    bool IsAuthorityLeader,
    long AuthorityEpoch,
    long AuthorityRevision,
    string IdentityKeyId = "",
    string IdentityPublicKey = "",
    string IdentitySignature = "")
{
    internal bool IsValidFor(string expectedCell, DateTimeOffset now) =>
        SchemaVersion == 1 &&
        Cell == expectedCell &&
        Cluster == $"orchestrator-control-{expectedCell}" &&
        !string.IsNullOrWhiteSpace(Instance) &&
        Guid.TryParseExact(SessionId, "N", out _) &&
        !string.IsNullOrWhiteSpace(Build) &&
        Capabilities.Count > 0 &&
        Capabilities.All(static capability => !string.IsNullOrWhiteSpace(capability)) &&
        Capabilities.SequenceEqual(Capabilities.Order(StringComparer.Ordinal), StringComparer.Ordinal) &&
        Capabilities.Distinct(StringComparer.Ordinal).Count() == Capabilities.Count &&
        StartedAt <= ObservedAt &&
        ObservedAt <= now.AddMinutes(1) &&
        LeaseExpiresAt > ObservedAt &&
        LeaseExpiresAt <= ObservedAt.AddMinutes(1) &&
        AuthorityState is "leader" or "follower" &&
        IsAuthorityLeader == (AuthorityState == "leader") &&
        AuthorityEpoch > 0 && AuthorityRevision > 0 &&
        HasWellFormedIdentityMaterial();

    /// <summary>Shape check only: the cryptographic verification is <see cref="VerifySignedIdentity"/>.</summary>
    internal bool HasWellFormedIdentityMaterial() =>
        IdentityKeyId is { Length: 32 } &&
        IdentityKeyId.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        IdentityPublicKey is { Length: > 0 and <= 256 } &&
        IsBase64(IdentityPublicKey) &&
        IdentitySignature is { Length: > 0 and <= 256 } &&
        IsBase64(IdentitySignature);

    /// <summary>Full signed-identity verification against the record's embedded public key.</summary>
    internal bool VerifySignedIdentity() => RegionalRuntimeMembershipIdentity.Verify(this);

    /// <summary>
    /// The exact signed material: every record field in a fixed order with fixed
    /// separators, timestamps as invariant Unix milliseconds. Changing any bound value
    /// changes the material; the signature fields themselves are not signed.
    /// </summary>
    internal string CanonicalMaterial() => string.Join('\n',
        Invariant(SchemaVersion),
        Cell,
        Cluster,
        Instance,
        SessionId,
        Build,
        string.Join('\u001f', Capabilities),
        Invariant(StartedAt.ToUnixTimeMilliseconds()),
        Invariant(ObservedAt.ToUnixTimeMilliseconds()),
        Invariant(LeaseExpiresAt.ToUnixTimeMilliseconds()),
        AuthorityState,
        IsAuthorityLeader ? "1" : "0",
        Invariant(AuthorityEpoch),
        Invariant(AuthorityRevision));

    private static string Invariant<T>(T value) =>
        Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty;

    private static bool IsBase64(string value) =>
        value.Length % 4 == 0 &&
        value.All(static character =>
            character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '+' or '/' or '=');
}

[JsonConverter(typeof(JsonStringEnumConverter<RegionalRuntimeMembershipCondition>))]
internal enum RegionalRuntimeMembershipCondition
{
    Unavailable = 0,
    Degraded = 1,
    Healthy = 2
}

internal sealed record RegionalRuntimeMembershipHealth(
    int ExpectedControllers,
    int ActiveControllers,
    int StaleControllers,
    int MissingControllers,
    int UnexpectedControllers,
    int ConflictingControllers,
    long RejectedRecords,
    int AuthorityLeaders,
    bool QuorumAvailable,
    long MaximumHeartbeatAgeMilliseconds,
    RegionalRuntimeMembershipCondition Condition,
    DateTimeOffset ObservedAt)
{
    /// <param name="conflictingControllers">
    /// The CURRENT number of conflicting sessions: slots whose live record is
    /// classified conflicting against its immediately preceding observation. A
    /// conflict stays current exactly until the surviving session's next renewal.
    /// This is a gauge bounded by the observed slots, never a lifetime counter —
    /// a cumulative value would eventually exceed the slot count and invalidate
    /// every projection built from it.
    /// </param>
    internal static RegionalRuntimeMembershipHealth Evaluate(
        string cell,
        int expectedControllers,
        IEnumerable<RegionalRuntimeMember> records,
        long rejectedRecords,
        DateTimeOffset observedAt,
        int conflictingControllers = 0)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cell);
        ArgumentNullException.ThrowIfNull(records);
        if (expectedControllers is not (1 or 3 or 5))
            throw new ArgumentOutOfRangeException(nameof(expectedControllers));
        if (rejectedRecords < 0)
            throw new ArgumentOutOfRangeException(nameof(rejectedRecords));
        if (conflictingControllers < 0)
            throw new ArgumentOutOfRangeException(nameof(conflictingControllers));

        var expectedInstances = RegionalRuntimeMembershipReader.ExpectedInstances(expectedControllers);
        var valid = records
            .Where(member => member.IsValidFor(cell, observedAt))
            .ToArray();
        var active = valid
            .Where(member => member.LeaseExpiresAt > observedAt)
            .ToArray();
        var stale = valid.Length - active.Length;
        var activeExpected = active.Count(member => expectedInstances.Contains(member.Instance));
        var missing = expectedInstances.Count(instance =>
            !active.Any(member => member.Instance == instance));
        var unexpected = valid.Count(member => !expectedInstances.Contains(member.Instance));
        var leaders = active.Count(member =>
            expectedInstances.Contains(member.Instance) && member.IsAuthorityLeader);
        var quorum = activeExpected >= (expectedControllers / 2) + 1;
        var maximumAge = active.Length == 0
            ? 0
            : active.Max(member => Math.Max(
                0,
                checked((long)Math.Ceiling((observedAt - member.ObservedAt).TotalMilliseconds))));
        var condition = activeExpected == 0
            ? RegionalRuntimeMembershipCondition.Unavailable
            : activeExpected == expectedControllers && stale == 0 && unexpected == 0 && leaders == 1
                ? RegionalRuntimeMembershipCondition.Healthy
                : RegionalRuntimeMembershipCondition.Degraded;
        return new(
            expectedControllers,
            active.Length,
            stale,
            missing,
            unexpected,
            conflictingControllers,
            rejectedRecords,
            leaders,
            quorum,
            maximumAge,
            condition,
            observedAt);
    }

    internal void Validate()
    {
        var expectedActive = ExpectedControllers - MissingControllers;
        var expectedQuorum = expectedActive >= (ExpectedControllers / 2) + 1;
        var expectedCondition = expectedActive == 0
            ? RegionalRuntimeMembershipCondition.Unavailable
            : expectedActive == ExpectedControllers && StaleControllers == 0 &&
              UnexpectedControllers == 0 && AuthorityLeaders == 1
                ? RegionalRuntimeMembershipCondition.Healthy
                : RegionalRuntimeMembershipCondition.Degraded;
        if (ExpectedControllers is not (1 or 3 or 5) || ActiveControllers < 0 || StaleControllers < 0 ||
            MissingControllers < 0 || MissingControllers > ExpectedControllers ||
            expectedActive > ActiveControllers || UnexpectedControllers < 0 ||
            UnexpectedControllers > ActiveControllers + StaleControllers ||
            ConflictingControllers < 0 || ConflictingControllers > ActiveControllers + StaleControllers ||
            RejectedRecords < 0 || AuthorityLeaders < 0 || AuthorityLeaders > ActiveControllers ||
            QuorumAvailable != expectedQuorum || MaximumHeartbeatAgeMilliseconds < 0 ||
            Condition != expectedCondition || ObservedAt == default ||
            ObservedAt > DateTimeOffset.UtcNow.AddMinutes(1))
        {
            throw new InvalidOperationException("The regional runtime membership health projection is invalid.");
        }
    }
}

internal sealed record RegionalRuntimeMembershipSnapshot(
    int SchemaVersion,
    string Cell,
    DateTimeOffset ObservedAt,
    RegionalRuntimeMembershipHealth Health,
    IReadOnlyList<RegionalRuntimeMember> Members)
{
    internal void Validate(string expectedCell)
    {
        Health.Validate();
        if (SchemaVersion != 2 || Cell != expectedCell || ObservedAt > DateTimeOffset.UtcNow.AddMinutes(1) ||
            Health.ObservedAt != ObservedAt || Health.ActiveControllers != Members.Count ||
            Members.Count == 0 ||
            Members.Any(member => !member.IsValidFor(expectedCell, ObservedAt) ||
                                  member.LeaseExpiresAt <= ObservedAt ||
                                  !member.VerifySignedIdentity()) ||
            Members.Select(static member => member.Instance).Distinct(StringComparer.Ordinal).Count() != Members.Count ||
            !Members.SequenceEqual(Members.OrderBy(static member => member.Instance, StringComparer.Ordinal)))
        {
            throw new InvalidOperationException("The regional runtime membership response is invalid.");
        }
    }
}

/// <summary>
/// Owns one controller's renewable KV registration and the watched, active peer view.
/// The deterministic key prevents two live processes from claiming the same instance.
/// </summary>
internal sealed class RegionalRuntimeMembership : IAsyncDisposable
{
    internal static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(5);
    internal static readonly TimeSpan LeaseDuration = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan WatchRetryDelay = TimeSpan.FromSeconds(1);

    private readonly INatsKVStore store;
    private readonly NatsTopology topology;
    private readonly string key;
    private readonly string sessionId;
    private readonly string build;
    private readonly IReadOnlyList<string> capabilities;
    private readonly DateTimeOffset startedAt;
    private readonly Func<RegionalAuthoritySnapshot> authority;
    private readonly RegionalRuntimeMembershipIdentity identity;
    private readonly bool ownsIdentity;
    private readonly ConcurrentDictionary<string, RegionalRuntimeMember> members = new(StringComparer.Ordinal);
    // The immediately preceding record per slot: what the current record is
    // classified against to derive CURRENT conflicting sessions. A conflict is
    // current until the new session's next renewal proves it.
    private readonly ConcurrentDictionary<string, RegionalRuntimeMember> previousMembers = new(StringComparer.Ordinal);
    // Trust-on-first-use pins: the first correctly signed record for an instance slot
    // fixes that instance's public key; later records must keep key continuity.
    private readonly ConcurrentDictionary<string, string> identityPins = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource stopping = new();
    private readonly TaskCompletionSource selfObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Task watchLoop;
    private Task? heartbeatLoop;
    private ulong revision;
    private long rejectedRecords;
    private int disposed;

    private RegionalRuntimeMembership(
        INatsKVStore store,
        NatsTopology topology,
        string sessionId,
        string build,
        IReadOnlyList<string> capabilities,
        DateTimeOffset startedAt,
        Func<RegionalAuthoritySnapshot> authority,
        RegionalRuntimeMembershipIdentity identity,
        bool ownsIdentity)
    {
        this.store = store;
        this.topology = topology;
        this.sessionId = sessionId;
        this.build = build;
        this.capabilities = capabilities;
        this.startedAt = startedAt;
        this.authority = authority;
        this.identity = identity;
        this.ownsIdentity = ownsIdentity;
        key = $"controller.{topology.Instance}";
        watchLoop = WatchAsync(stopping.Token);
    }

    internal Task Completion => Task.WhenAny(
        watchLoop,
        heartbeatLoop ?? Task.Delay(Timeout.InfiniteTimeSpan)).Unwrap();

    internal RegionalRuntimeMembershipSnapshot Snapshot
    {
        get
        {
            var now = DateTimeOffset.UtcNow;
            var records = members.Values.ToArray();
            var expectedInstances = RegionalRuntimeMembershipReader.ExpectedInstances(topology.Replicas);
            var active = records
                .Where(member => member.IsValidFor(topology.Cell, now) && member.LeaseExpiresAt > now)
                .OrderBy(static member => member.Instance, StringComparer.Ordinal)
                .ToArray();
            // Conflicting sessions are a CURRENT gauge derived from the live
            // records: each slot's current record classified against its
            // immediately preceding observation. A lifetime counter here would
            // eventually exceed the slot count and invalidate the projection.
            var conflicting = 0;
            foreach (var member in records)
            {
                if (!previousMembers.TryGetValue($"controller.{member.Instance}", out var previous)) continue;
                if (RegionalRuntimeMembershipReader.Classify(
                        topology.Cell,
                        member.Instance,
                        expectedInstances,
                        previous: previous,
                        record: member,
                        now: now) == RegionalRuntimeMembershipRecordClass.ConflictingSession)
                    conflicting++;
            }
            var health = RegionalRuntimeMembershipHealth.Evaluate(
                topology.Cell,
                topology.Replicas,
                records,
                Interlocked.Read(ref rejectedRecords),
                now,
                conflicting);
            return new(2, topology.Cell, now, health, active);
        }
    }

    internal RegionalRuntimeMembershipHealth Health => Snapshot.Health;

    internal static async Task<RegionalRuntimeMembership> StartAsync(
        INatsKVStore store,
        NatsTopology topology,
        string build,
        IReadOnlyList<string> capabilities,
        DateTimeOffset startedAt,
        Func<RegionalAuthoritySnapshot> authority,
        CancellationToken cancellationToken,
        RegionalRuntimeMembershipIdentity? identity = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(topology);
        ArgumentException.ThrowIfNullOrWhiteSpace(build);
        ArgumentNullException.ThrowIfNull(capabilities);
        ArgumentNullException.ThrowIfNull(authority);
        if (capabilities.Count == 0 ||
            capabilities.Any(string.IsNullOrWhiteSpace) ||
            !capabilities.SequenceEqual(capabilities.Order(StringComparer.Ordinal), StringComparer.Ordinal) ||
            capabilities.Distinct(StringComparer.Ordinal).Count() != capabilities.Count)
        {
            throw new ArgumentException("Runtime capabilities must be non-empty, unique, and ordinally sorted.", nameof(capabilities));
        }

        var membership = new RegionalRuntimeMembership(
            store,
            topology,
            Guid.NewGuid().ToString("N"),
            build,
            capabilities.ToArray(),
            startedAt,
            authority,
            identity ?? RegionalRuntimeMembershipIdentity.Create(),
            ownsIdentity: identity is null);
        try
        {
            await membership.ClaimAsync(cancellationToken);
            await membership.selfObserved.Task.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);
            membership.heartbeatLoop = membership.HeartbeatAsync(membership.stopping.Token);
            return membership;
        }
        catch
        {
            await membership.DisposeAsync();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        await stopping.CancelAsync();
        await IgnoreCancellationAsync(watchLoop);
        if (heartbeatLoop is not null) await IgnoreCancellationAsync(heartbeatLoop);
        try
        {
            // The pure rule: only this session's own record, only under the
            // compare-and-swap revision this process still holds. A newer owner
            // must never lose its registration to a departing peer.
            if (revision != 0 &&
                RegionalRuntimeMembershipMutation.MayDeleteCurrentRecord(
                    sessionId,
                    members.GetValueOrDefault(key),
                    revision))
            {
                await store.DeleteAsync(key, new NatsKVDeleteOpts { Revision = revision });
            }
        }
        catch (NatsKVWrongLastRevisionException)
        {
            // A newer session owns the deterministic instance key. Never delete it.
        }
        finally
        {
            stopping.Dispose();
            if (ownsIdentity) identity.Dispose();
        }
    }

    private async Task ClaimAsync(CancellationToken cancellationToken)
    {
        var document = Document(DateTimeOffset.UtcNow);
        var value = Serialize(document);
        try
        {
            revision = await store.CreateAsync(key, value, cancellationToken: cancellationToken);
            return;
        }
        catch (Exception exception) when (exception is NatsKVCreateException or NatsKVWrongLastRevisionException)
        {
        }

        // The slot already exists. Re-read, decide, and execute under the observed
        // revision; a lost compare-and-swap race (a concurrent healer won the same
        // observed revision) re-reads the winner and re-decides rather than
        // surfacing the raw KV revision exception.
        for (var attempt = 0; ; attempt++)
        {
            var current = await store.GetEntryAsync<string>(key, cancellationToken: cancellationToken);
            current.EnsureSuccess();
            var existing = Deserialize(current.Value);
            var now = DateTimeOffset.UtcNow;
            if (!existing.IsValidFor(topology.Cell, now) ||
                !existing.VerifySignedIdentity() ||
                existing.Instance != topology.Instance)
                throw new InvalidOperationException(
                    $"The regional runtime membership key '{key}' contains a record that is invalid or bound to " +
                    "another instance. The record's own lease is the first recovery path; if the key stays wedged " +
                    $"past it, an operator must purge '{key}' from the {topology.Runtime.Bucket} bucket after the " +
                    "record's lease has lapsed, and this instance will then claim the empty slot.");
            var decision = RegionalRuntimeMembershipMutation.Decide(
                topology.Cell,
                topology.Instance,
                document,
                existing,
                now);
            switch (decision)
            {
                case RegionalRuntimeMembershipMutationClass.TakeOverExpiredLease:
                    // Healing: the previous semantic lease has fully lapsed, so the slot
                    // is safely reclaimable under the observed revision.
                    try
                    {
                        revision = await store.UpdateAsync(
                            key, value, current.Revision, cancellationToken: cancellationToken);
                        return;
                    }
                    catch (NatsKVWrongLastRevisionException) when (attempt < 2)
                    {
                        continue;
                    }
                case RegionalRuntimeMembershipMutationClass.HoldForLiveForeignLease:
                    throw new InvalidOperationException(
                        $"Controller instance '{topology.Instance}' already has an active membership lease.");
                default:
                    throw new InvalidOperationException(
                        $"The regional runtime membership claim was refused ({decision}).");
            }
        }
    }

    private async Task HeartbeatAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(HeartbeatInterval);
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            try
            {
                var value = Serialize(Document(DateTimeOffset.UtcNow));
                revision = await store.UpdateAsync(key, value, revision, cancellationToken: cancellationToken);
            }
            catch (Exception exception) when (IsTransient(exception))
            {
                // Transient NATS failures (timeout, lost connection) skip one renewal;
                // the lease carries three heartbeat intervals of slack, so the loop
                // retries on the next tick instead of faulting Completion and taking
                // the process down. Persistent, non-transient failures still escape
                // (fail-stop), and a genuinely lost slot still surfaces as the
                // non-transient CAS revision fault.
            }
        }
        throw new InvalidOperationException("The regional runtime membership heartbeat stopped unexpectedly.");
    }

    private async Task WatchAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            try
            {
                await foreach (var entry in store.WatchAsync<string>("controller.>", cancellationToken: cancellationToken))
                {
                    entry.EnsureSuccess();
                    if (entry.Value is null)
                    {
                        members.TryRemove(entry.Key, out _);
                        previousMembers.TryRemove(entry.Key, out _);
                        identityPins.TryRemove(entry.Key, out _);
                        continue;
                    }

                    RegionalRuntimeMember member;
                    try
                    {
                        member = Deserialize(entry.Value);
                    }
                    catch (JsonException)
                    {
                        Interlocked.Increment(ref rejectedRecords);
                        members.TryRemove(entry.Key, out _);
                        previousMembers.TryRemove(entry.Key, out _);
                        continue;
                    }
                    if (!member.IsValidFor(topology.Cell, DateTimeOffset.UtcNow) ||
                        entry.Key != $"controller.{member.Instance}")
                    {
                        Interlocked.Increment(ref rejectedRecords);
                        members.TryRemove(entry.Key, out _);
                        previousMembers.TryRemove(entry.Key, out _);
                        continue;
                    }
                    if (!member.VerifySignedIdentity())
                    {
                        Interlocked.Increment(ref rejectedRecords);
                        members.TryRemove(entry.Key, out _);
                        previousMembers.TryRemove(entry.Key, out _);
                        continue;
                    }
                    var pinnedKey = identityPins.GetOrAdd(entry.Key, member.IdentityPublicKey);
                    if (pinnedKey != member.IdentityPublicKey)
                    {
                        // Key continuity: a different key is only accepted as a healing
                        // takeover once the previously observed record's lease has fully
                        // lapsed. Under a live lease the slot's key may not change.
                        var pinnedPrevious = members.GetValueOrDefault(entry.Key);
                        if (pinnedPrevious is null || pinnedPrevious.LeaseExpiresAt > DateTimeOffset.UtcNow)
                        {
                            Interlocked.Increment(ref rejectedRecords);
                            members.TryRemove(entry.Key, out _);
                            previousMembers.TryRemove(entry.Key, out _);
                            continue;
                        }
                        identityPins[entry.Key] = member.IdentityPublicKey;
                    }

                    // Stash the outgoing record unconditionally: the snapshot's CURRENT
                    // conflicting-session gauge classifies the live record against the
                    // immediately preceding one. A session change under a still-live
                    // lease stays counted as a current conflict exactly until the new
                    // session's next renewal replaces the stashed predecessor.
                    if (members.TryGetValue(entry.Key, out var previous))
                        previousMembers[entry.Key] = previous;

                    members[entry.Key] = member;
                    if (entry.Key == key && member.SessionId == sessionId)
                        selfObserved.TrySetResult();
                }
                throw new InvalidOperationException("The regional runtime membership watcher stopped unexpectedly.");
            }
            catch (Exception exception) when (IsTransient(exception))
            {
                // Transient NATS failures tear the watch down; re-establish it after
                // a short delay instead of faulting Completion and taking the process
                // down. The re-watch replays every current record, so the observed
                // view converges rather than going silently stale. Persistent,
                // non-transient failures still escape (fail-stop).
                await Task.Delay(WatchRetryDelay, cancellationToken);
            }
        }
    }

    private static bool IsTransient(Exception exception) =>
        // Infrastructure transients only (connection loss, timeout): unlike the
        // authority tick loop, the heartbeat does not re-observe before renewing,
        // so a swallowed KV protocol outcome could never self-correct. CAS faults
        // and missing keys (NatsKVException) therefore stay fail-stop.
        exception is NatsException and not NatsKVException;

    private RegionalRuntimeMember Document(DateTimeOffset observedAt)
    {
        var authoritySnapshot = authority();
        if (!authoritySnapshot.Ready)
            throw new InvalidOperationException("A controller cannot advertise membership without current regional authority state.");
        var unsigned = new RegionalRuntimeMember(
            1,
            topology.Cell,
            $"orchestrator-control-{topology.Cell}",
            topology.Instance,
            sessionId,
            build,
            capabilities,
            startedAt,
            observedAt,
            observedAt + LeaseDuration,
            authoritySnapshot.State,
            authoritySnapshot.IsLeader,
            authoritySnapshot.Epoch,
            authoritySnapshot.KvRevision,
            identity.KeyId,
            identity.PublicKey,
            string.Empty);
        return unsigned with { IdentitySignature = identity.Sign(unsigned) };
    }

    private static string Serialize(RegionalRuntimeMember member) => JsonSerializer.Serialize(
        member,
        RegionalRuntimeMembershipJsonContext.Default.RegionalRuntimeMember);

    private static RegionalRuntimeMember Deserialize(string? value) => JsonSerializer.Deserialize(
        value ?? throw new JsonException("The regional runtime membership record is empty."),
        RegionalRuntimeMembershipJsonContext.Default.RegionalRuntimeMember)
        ?? throw new JsonException("The regional runtime membership record is empty.");

    private static async Task IgnoreCancellationAsync(Task task)
    {
        try
        {
            await task;
        }
        catch (OperationCanceledException)
        {
        }
    }
}

[JsonSerializable(typeof(RegionalRuntimeMember))]
[JsonSerializable(typeof(RegionalRuntimeMembershipSnapshot))]
internal sealed partial class RegionalRuntimeMembershipJsonContext : JsonSerializerContext;
