using System.Text.Json;
using System.Runtime.ExceptionServices;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;
using NATS.Net;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// Publishes the local regional leader's renewable advertisement and watches the
/// durable global KV projection. WAN failures are retried and never revoke local authority.
/// </summary>
internal sealed class GlobalCellDirectoryRuntime : IGlobalCellDirectoryRuntimeInstance
{
    internal static readonly TimeSpan AdvertisementInterval = TimeSpan.FromSeconds(5);
    internal static readonly TimeSpan AdvertisementLease = GlobalCellAdvertisement.SemanticLease;

    private readonly INatsKVStore store;
    private readonly string cell;
    private readonly Func<RegionalRuntimeMembershipSnapshot> membership;
    private readonly Func<RegionalAuthoritySnapshot> authority;
    private readonly IReadOnlyList<string> endpoints;
    private readonly NatsClient? ownedClient;
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
        IReadOnlyList<string> endpoints,
        bool publishEnabled,
        NatsClient? ownedClient = null)
    {
        this.store = store;
        this.cell = cell;
        this.membership = membership;
        this.authority = authority;
        this.endpoints = endpoints;
        this.ownedClient = ownedClient;
        watchLoop = WatchAsync(stopping.Token);
        publishLoop = publishEnabled
            ? PublishAsync(stopping.Token)
            : Task.Delay(Timeout.InfiniteTimeSpan, stopping.Token);
    }

    internal Task Completion => Task.WhenAny(watchLoop, publishLoop).Unwrap();
    internal GlobalCellDirectorySnapshot Snapshot => directory.Snapshot();
    internal GlobalCellDirectoryCondition Health => Snapshot.Condition;

    Task IGlobalCellDirectoryRuntimeInstance.Completion => Completion;
    GlobalCellDirectorySnapshot IGlobalCellDirectoryRuntimeInstance.Snapshot => Snapshot;

    internal static GlobalCellDirectoryRuntime Start(
        INatsKVStore store,
        string cell,
        Func<RegionalRuntimeMembershipSnapshot> membership,
        Func<RegionalAuthoritySnapshot> authority,
        bool publishEnabled = true,
        IReadOnlyList<string>? endpoints = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        if (!GlobalNatsTopology.IsCellToken(cell))
            throw new ArgumentException("The global directory cell is invalid.", nameof(cell));
        ArgumentNullException.ThrowIfNull(membership);
        ArgumentNullException.ThrowIfNull(authority);
        if (publishEnabled && (endpoints is null || endpoints.Count == 0))
            throw new ArgumentException(
                "Publishing a cell advertisement requires the cell's advertised control endpoints.", nameof(endpoints));
        return new(
            store,
            cell,
            membership,
            authority,
            endpoints ?? Array.Empty<string>(),
            publishEnabled);
    }

    /// <summary>
    /// Starts a directory-only connection. The adapter reconciles only the
    /// GLOBAL_CELLS KV store and does not create global streams, authority KV,
    /// CI state, or Object Store buckets.
    /// </summary>
    internal static async Task<GlobalCellDirectoryRuntime> StartAsync(
        GlobalDirectoryNatsConfiguration configuration,
        Func<RegionalRuntimeMembershipSnapshot> membership,
        Func<RegionalAuthoritySnapshot> authority,
        bool publishEnabled = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(membership);
        ArgumentNullException.ThrowIfNull(authority);
        if (publishEnabled && configuration.Endpoints.Count == 0)
            throw new ArgumentException(
                "Publishing a cell advertisement requires the cell's advertised control endpoints.",
                nameof(configuration));
        var client = new NatsClient(new NatsOpts
        {
            Url = configuration.Url,
            RetryOnInitialConnect = false,
            RequestTimeout = TimeSpan.FromSeconds(15),
            AuthOpts = configuration.Authentication.Options,
            TlsOpts = new NatsTlsOpts
            {
                Mode = TlsMode.Require,
                CaFile = configuration.Tls.CaFile,
                CertFile = configuration.Tls.CertificateFile,
                KeyFile = configuration.Tls.KeyFile,
            },
        });
        try
        {
            await client.ConnectAsync();
            var store = await OpenExistingStoreAsync(
                client.CreateJetStreamContext().CreateKeyValueStoreContext(), cancellationToken);
            return new(
                store,
                configuration.Cell,
                membership,
                authority,
                configuration.Endpoints,
                publishEnabled,
                client);
        }
        catch
        {
            await client.DisposeAsync();
            throw;
        }
    }

    /// <summary>
    /// Opens the infrastructure-provisioned directory bucket without a
    /// configuration object. This keeps directory startup from creating or
    /// mutating the GLOBAL_CELLS stream.
    /// </summary>
    internal static Task<INatsKVStore> OpenExistingStoreAsync(
        INatsKVContext keyValue,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(keyValue);
        return keyValue.GetStoreAsync(GlobalNatsTopology.CellsBucket, cancellationToken).AsTask();
    }

    internal static GlobalCellAdvertisement CreateAdvertisement(
        RegionalRuntimeMembershipSnapshot membership,
        RegionalAuthoritySnapshot authority,
        long sequence,
        IReadOnlyList<string> endpoints)
    {
        ArgumentNullException.ThrowIfNull(membership);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(endpoints);
        membership.Validate(membership.Cell);
        if (!authority.Ready || !authority.IsLeader || authority.Epoch <= 0 || authority.KvRevision <= 0)
            throw new InvalidOperationException("Only the current regional authority leader may advertise its cell.");
        if (sequence <= 0) throw new ArgumentOutOfRangeException(nameof(sequence));
        if (endpoints.Count == 0 || endpoints.Any(endpoint => !IsControlEndpoint(endpoint)))
            throw new ArgumentException(
                "A cell advertisement requires at least one valid control endpoint.", nameof(endpoints));
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
            membership.ObservedAt + AdvertisementLease,
            endpoints.Order(StringComparer.Ordinal).ToArray());
    }

    private static bool IsControlEndpoint(string endpoint) =>
        GlobalCellAdvertisement.IsControlEndpoint(endpoint);

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        Exception? failure = null;
        try
        {
            await stopping.CancelAsync();
        }
        catch (Exception exception)
        {
            failure = exception;
        }

        try
        {
            failure ??= await ObserveCompletionAsync(watchLoop);
        }
        finally
        {
            try
            {
                failure ??= await ObserveCompletionAsync(publishLoop);
            }
            finally
            {
                stopping.Dispose();
                if (ownedClient is not null)
                {
                    try
                    {
                        await ownedClient.DisposeAsync();
                    }
                    catch (Exception exception)
                    {
                        failure ??= exception;
                    }
                }
            }
        }

        if (failure is not null)
            ExceptionDispatchInfo.Capture(failure).Throw();
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

            var advertisement = CreateAdvertisement(membership(), regionalAuthority, sequence, endpoints);
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

    private static async Task<Exception?> ObserveCompletionAsync(Task task)
    {
        try
        {
            await task;
            return null;
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }
}
