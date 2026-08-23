using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;
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
    long AuthorityRevision)
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
        AuthorityEpoch > 0 && AuthorityRevision > 0;
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
    long RejectedRecords,
    int AuthorityLeaders,
    bool QuorumAvailable,
    long MaximumHeartbeatAgeMilliseconds,
    RegionalRuntimeMembershipCondition Condition,
    DateTimeOffset ObservedAt)
{
    internal static RegionalRuntimeMembershipHealth Evaluate(
        string cell,
        int expectedControllers,
        IEnumerable<RegionalRuntimeMember> records,
        long rejectedRecords,
        DateTimeOffset observedAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cell);
        ArgumentNullException.ThrowIfNull(records);
        if (expectedControllers is not (1 or 3 or 5))
            throw new ArgumentOutOfRangeException(nameof(expectedControllers));
        if (rejectedRecords < 0)
            throw new ArgumentOutOfRangeException(nameof(rejectedRecords));

        var valid = records
            .Where(member => member.IsValidFor(cell, observedAt))
            .ToArray();
        var active = valid
            .Where(member => member.LeaseExpiresAt > observedAt)
            .ToArray();
        var stale = valid.Length - active.Length;
        var missing = Math.Max(0, expectedControllers - active.Length);
        var unexpected = Math.Max(0, active.Length - expectedControllers);
        var leaders = active.Count(static member => member.IsAuthorityLeader);
        var quorum = active.Length >= (expectedControllers / 2) + 1;
        var maximumAge = active.Length == 0
            ? 0
            : active.Max(member => Math.Max(
                0,
                checked((long)Math.Ceiling((observedAt - member.ObservedAt).TotalMilliseconds))));
        var condition = active.Length == 0
            ? RegionalRuntimeMembershipCondition.Unavailable
            : active.Length == expectedControllers && stale == 0 && unexpected == 0 && leaders == 1
                ? RegionalRuntimeMembershipCondition.Healthy
                : RegionalRuntimeMembershipCondition.Degraded;
        return new(
            expectedControllers,
            active.Length,
            stale,
            missing,
            unexpected,
            rejectedRecords,
            leaders,
            quorum,
            maximumAge,
            condition,
            observedAt);
    }

    internal void Validate()
    {
        var expectedMissing = Math.Max(0, ExpectedControllers - ActiveControllers);
        var expectedUnexpected = Math.Max(0, ActiveControllers - ExpectedControllers);
        var expectedQuorum = ActiveControllers >= (ExpectedControllers / 2) + 1;
        var expectedCondition = ActiveControllers == 0
            ? RegionalRuntimeMembershipCondition.Unavailable
            : ActiveControllers == ExpectedControllers && StaleControllers == 0 &&
              UnexpectedControllers == 0 && AuthorityLeaders == 1
                ? RegionalRuntimeMembershipCondition.Healthy
                : RegionalRuntimeMembershipCondition.Degraded;
        if (ExpectedControllers is not (1 or 3 or 5) || ActiveControllers < 0 || StaleControllers < 0 ||
            MissingControllers != expectedMissing || UnexpectedControllers != expectedUnexpected ||
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
                                  member.LeaseExpiresAt <= ObservedAt) ||
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

    private readonly INatsKVStore store;
    private readonly NatsTopology topology;
    private readonly string key;
    private readonly string sessionId;
    private readonly string build;
    private readonly IReadOnlyList<string> capabilities;
    private readonly DateTimeOffset startedAt;
    private readonly Func<RegionalAuthoritySnapshot> authority;
    private readonly ConcurrentDictionary<string, RegionalRuntimeMember> members = new(StringComparer.Ordinal);
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
        Func<RegionalAuthoritySnapshot> authority)
    {
        this.store = store;
        this.topology = topology;
        this.sessionId = sessionId;
        this.build = build;
        this.capabilities = capabilities;
        this.startedAt = startedAt;
        this.authority = authority;
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
            var active = records
                .Where(member => member.IsValidFor(topology.Cell, now) && member.LeaseExpiresAt > now)
                .OrderBy(static member => member.Instance, StringComparer.Ordinal)
                .ToArray();
            var health = RegionalRuntimeMembershipHealth.Evaluate(
                topology.Cell,
                topology.Replicas,
                records,
                Interlocked.Read(ref rejectedRecords),
                now);
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
        CancellationToken cancellationToken)
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
            authority);
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
            if (revision != 0)
                await store.DeleteAsync(key, new NatsKVDeleteOpts { Revision = revision });
        }
        catch (NatsKVWrongLastRevisionException)
        {
            // A newer session owns the deterministic instance key. Never delete it.
        }
        finally
        {
            stopping.Dispose();
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
            var current = await store.GetEntryAsync<string>(key, cancellationToken: cancellationToken);
            current.EnsureSuccess();
            var existing = Deserialize(current.Value);
            var now = DateTimeOffset.UtcNow;
            if (!existing.IsValidFor(topology.Cell, now) || existing.Instance != topology.Instance)
                throw new InvalidOperationException("The regional runtime membership key contains an invalid record.");
            if (existing.LeaseExpiresAt > now)
                throw new InvalidOperationException($"Controller instance '{topology.Instance}' already has an active membership lease.");
            revision = await store.UpdateAsync(key, value, current.Revision, cancellationToken: cancellationToken);
        }
    }

    private async Task HeartbeatAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(HeartbeatInterval);
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            var value = Serialize(Document(DateTimeOffset.UtcNow));
            revision = await store.UpdateAsync(key, value, revision, cancellationToken: cancellationToken);
        }
        throw new InvalidOperationException("The regional runtime membership heartbeat stopped unexpectedly.");
    }

    private async Task WatchAsync(CancellationToken cancellationToken)
    {
        await foreach (var entry in store.WatchAsync<string>("controller.>", cancellationToken: cancellationToken))
        {
            entry.EnsureSuccess();
            if (entry.Value is null)
            {
                members.TryRemove(entry.Key, out _);
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
                continue;
            }
            if (!member.IsValidFor(topology.Cell, DateTimeOffset.UtcNow) ||
                entry.Key != $"controller.{member.Instance}")
            {
                Interlocked.Increment(ref rejectedRecords);
                members.TryRemove(entry.Key, out _);
                continue;
            }

            members[entry.Key] = member;
            if (entry.Key == key && member.SessionId == sessionId)
                selfObserved.TrySetResult();
        }
        throw new InvalidOperationException("The regional runtime membership watcher stopped unexpectedly.");
    }

    private RegionalRuntimeMember Document(DateTimeOffset observedAt)
    {
        var authoritySnapshot = authority();
        if (!authoritySnapshot.Ready)
            throw new InvalidOperationException("A controller cannot advertise membership without current regional authority state.");
        return new(
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
            authoritySnapshot.KvRevision);
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
