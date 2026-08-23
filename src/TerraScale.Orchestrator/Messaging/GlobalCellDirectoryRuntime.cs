using System.Text.Json;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// Publishes the local regional leader's renewable advertisement and watches the
/// durable global KV projection. WAN failures are retried and never revoke local authority.
/// </summary>
internal sealed class GlobalCellDirectoryRuntime : IAsyncDisposable
{
    internal static readonly TimeSpan AdvertisementInterval = TimeSpan.FromSeconds(5);
    internal static readonly TimeSpan AdvertisementLease = GlobalCellAdvertisement.SemanticLease;

    private readonly INatsKVStore store;
    private readonly string cell;
    private readonly Func<RegionalRuntimeMembershipSnapshot> membership;
    private readonly Func<RegionalAuthoritySnapshot> authority;
    private readonly CancellationTokenSource stopping = new();
    private readonly GlobalCellDirectory directory = new();
    private readonly Task watchLoop;
    private readonly Task publishLoop;
    private int disposed;

    private GlobalCellDirectoryRuntime(
        INatsKVStore store,
        string cell,
        Func<RegionalRuntimeMembershipSnapshot> membership,
        Func<RegionalAuthoritySnapshot> authority,
        bool publishEnabled)
    {
        this.store = store;
        this.cell = cell;
        this.membership = membership;
        this.authority = authority;
        watchLoop = WatchAsync(stopping.Token);
        publishLoop = publishEnabled
            ? PublishAsync(stopping.Token)
            : Task.Delay(Timeout.InfiniteTimeSpan, stopping.Token);
    }

    internal Task Completion => Task.WhenAny(watchLoop, publishLoop).Unwrap();
    internal GlobalCellDirectorySnapshot Snapshot => directory.Snapshot();

    internal static GlobalCellDirectoryRuntime Start(
        INatsKVStore store,
        string cell,
        Func<RegionalRuntimeMembershipSnapshot> membership,
        Func<RegionalAuthoritySnapshot> authority,
        bool publishEnabled = true)
    {
        ArgumentNullException.ThrowIfNull(store);
        if (!GlobalNatsTopology.IsCellToken(cell))
            throw new ArgumentException("The global directory cell is invalid.", nameof(cell));
        ArgumentNullException.ThrowIfNull(membership);
        ArgumentNullException.ThrowIfNull(authority);
        return new(store, cell, membership, authority, publishEnabled);
    }

    internal static GlobalCellAdvertisement CreateAdvertisement(
        RegionalRuntimeMembershipSnapshot membership,
        RegionalAuthoritySnapshot authority,
        long sequence)
    {
        ArgumentNullException.ThrowIfNull(membership);
        ArgumentNullException.ThrowIfNull(authority);
        membership.Validate(membership.Cell);
        if (!authority.Ready || !authority.IsLeader || authority.Epoch <= 0 || authority.KvRevision <= 0)
            throw new InvalidOperationException("Only the current regional authority leader may advertise its cell.");
        if (sequence <= 0) throw new ArgumentOutOfRangeException(nameof(sequence));
        var capabilities = membership.Members
            .SelectMany(static member => member.Capabilities)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        return new(
            1,
            membership.Cell,
            $"orchestrator-control-{membership.Cell}",
            $"{membership.Cell}-regional",
            authority.Epoch,
            authority.KvRevision,
            sequence,
            capabilities,
            membership.Health,
            membership.ObservedAt,
            membership.ObservedAt + AdvertisementLease);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        await stopping.CancelAsync();
        await IgnoreCancellationAsync(watchLoop);
        await IgnoreCancellationAsync(publishLoop);
        stopping.Dispose();
    }

    private async Task PublishAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(AdvertisementInterval);
        do
        {
            var regionalAuthority = authority();
            if (regionalAuthority.Ready && regionalAuthority.IsLeader)
            {
                try
                {
                    await PublishOnceAsync(regionalAuthority, cancellationToken);
                }
                catch (InvalidOperationException)
                {
                    // A temporarily empty or not-yet-converged local membership view
                    // must not turn the global projection into a regional dependency.
                }
                catch (Exception exception) when (IsTransient(exception))
                {
                    // The regional control plane continues from its local R3 state.
                    // The next tick retries and remote readers observe lease staleness.
                }
            }
        }
        while (await timer.WaitForNextTickAsync(cancellationToken));
        throw new InvalidOperationException("The global cell advertisement publisher stopped unexpectedly.");
    }

    private async Task PublishOnceAsync(
        RegionalAuthoritySnapshot regionalAuthority,
        CancellationToken cancellationToken)
    {
        var key = GlobalNatsTopology.CellAdvertisementKey(cell);
        for (var attempt = 0; attempt < 5; attempt++)
        {
            NatsKVEntry<string>? current = null;
            try
            {
                var observed = await store.GetEntryAsync<string>(key, cancellationToken: cancellationToken);
                observed.EnsureSuccess();
                current = observed;
            }
            catch (NatsKVKeyNotFoundException)
            {
            }

            var sequence = 1L;
            if (current.HasValue && current.Value.Value is not null)
            {
                GlobalCellAdvertisement existing;
                try
                {
                    existing = Deserialize(current.Value.Value!);
                }
                catch (JsonException)
                {
                    return;
                }
                if (!existing.IsValid(DateTimeOffset.UtcNow) || existing.Cell != cell)
                    return;
                var authorityOrder = regionalAuthority.Epoch.CompareTo(existing.AuthorityEpoch);
                if (authorityOrder == 0)
                    authorityOrder = regionalAuthority.KvRevision.CompareTo(existing.AuthorityRevision);
                if (authorityOrder < 0) return;
                sequence = authorityOrder == 0 ? checked(existing.Sequence + 1) : 1;
            }

            var advertisement = CreateAdvertisement(membership(), regionalAuthority, sequence);
            if (advertisement.Cell != cell || !advertisement.IsValid(DateTimeOffset.UtcNow))
                throw new InvalidOperationException("The local global-cell advertisement is invalid.");
            var value = JsonSerializer.Serialize(
                advertisement,
                GlobalCellDirectoryJsonContext.Default.GlobalCellAdvertisement);
            try
            {
                if (current is null)
                    _ = await store.CreateAsync(key, value, cancellationToken: cancellationToken);
                else
                    _ = await store.UpdateAsync(
                        key, value, current.Value.Revision, cancellationToken: cancellationToken);
                return;
            }
            catch (Exception exception) when (
                exception is NatsKVCreateException or NatsKVWrongLastRevisionException)
            {
            }
        }
    }

    private async Task WatchAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            try
            {
                await foreach (var entry in store.WatchAsync<string>("cell.>", cancellationToken: cancellationToken))
                {
                    entry.EnsureSuccess();
                    var advertisedCell = entry.Key.StartsWith("cell.", StringComparison.Ordinal)
                        ? entry.Key[5..]
                        : string.Empty;
                    if (!GlobalNatsTopology.IsCellToken(advertisedCell))
                    {
                        directory.Reject();
                        continue;
                    }
                    if (entry.Value is null)
                    {
                        directory.Remove(advertisedCell);
                        continue;
                    }

                    GlobalCellAdvertisement advertisement;
                    try
                    {
                        advertisement = Deserialize(entry.Value);
                    }
                    catch (JsonException)
                    {
                        directory.Reject();
                        continue;
                    }
                    _ = directory.Apply(entry.Key, advertisement);
                }
            }
            catch (Exception exception) when (IsTransient(exception))
            {
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
                continue;
            }
            throw new InvalidOperationException("The global cell directory watcher stopped unexpectedly.");
        }
    }

    private static GlobalCellAdvertisement Deserialize(string value) =>
        JsonSerializer.Deserialize(
            value,
            GlobalCellDirectoryJsonContext.Default.GlobalCellAdvertisement)
        ?? throw new JsonException("The global cell advertisement is empty.");

    private static bool IsTransient(Exception exception) =>
        exception is NatsException or NatsJSApiNoResponseException or NatsJSTimeoutException or
            NatsJSConnectionException;

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
