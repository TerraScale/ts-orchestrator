using System.Collections.Immutable;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace TerraScale.Orchestrator.ControlPlane.EdgeRouting;

/// <summary>
/// The seam from the publisher to control-plane placement state. Production implements this from
/// the database placement evaluator plus live member observations; this interface is a seam to
/// that state — never a source of truth itself — and must return the complete desired state of
/// every database on every call.
/// </summary>
public interface IEdgePlacementSource
{
    /// <summary>Returns the complete desired edge-routing state for one publish pass.</summary>
    Task<EdgePlacementSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default);
}

/// <summary>A fixed snapshot source for qualification and development runs.</summary>
public sealed class StaticEdgePlacementSource : IEdgePlacementSource
{
    private readonly EdgePlacementSnapshot snapshot;

    public StaticEdgePlacementSource(EdgePlacementSnapshot snapshot)
    {
        this.snapshot = snapshot ?? throw new ArgumentNullException(nameof(snapshot));
    }

    public Task<EdgePlacementSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(snapshot);
}

public sealed class EdgeRoutingPublisherOptions
{
    /// <summary>The pass fails loudly when more placement documents than this need writing.</summary>
    public int MaximumWritesPerPass { get; init; } = 20_000;

    /// <summary>Total attempts per KV operation before the pass fails; transient failures only.</summary>
    public int MaximumAttemptsPerOperation { get; init; } = 4;

    public TimeSpan InitialBackoff { get; init; } = TimeSpan.FromMilliseconds(500);

    public TimeSpan MaximumBackoff { get; init; } = TimeSpan.FromSeconds(30);
}

public enum EdgePublishStepCode
{
    HealthWrite = 1,
    PlacementWrite = 2,
    StaleDelete = 3,
}

public enum EdgePublishStepOutcome
{
    Succeeded = 1,
}

public sealed record EdgePublishStep(EdgePublishStepCode Code, EdgePublishStepOutcome Outcome, int Count);

/// <summary>
/// The observable outcome of one publish pass. A returned result means the pass succeeded;
/// every failure mode throws a typed exception instead.
/// </summary>
public sealed class EdgePublishResult
{
    internal EdgePublishResult(
        int placementWrites,
        int placementSkips,
        int deletedKeys,
        TimeSpan duration,
        ImmutableArray<EdgePublishStep> steps)
    {
        PlacementWrites = placementWrites;
        PlacementSkips = placementSkips;
        DeletedKeys = deletedKeys;
        Duration = duration;
        Steps = steps;
    }

    public int PlacementWrites { get; }
    public int PlacementSkips { get; }
    public int DeletedKeys { get; }
    public TimeSpan Duration { get; }
    public ImmutableArray<EdgePublishStep> Steps { get; }
}

/// <summary>The desired snapshot failed closed validation; nothing was written.</summary>
public sealed class EdgePlacementValidationException : Exception
{
    internal EdgePlacementValidationException(ImmutableArray<EdgePlacementValidationError> errors)
        : base($"The edge placement snapshot failed closed validation with {errors.Length} error(s).")
    {
        Errors = errors;
    }

    public ImmutableArray<EdgePlacementValidationError> Errors { get; }
}

/// <summary>The source revision does not advance the currently published revision of one database.</summary>
public sealed class EdgeRevisionRegressionException : Exception
{
    internal EdgeRevisionRegressionException(string database, int sourceRevision, int publishedRevision)
        : base($"Database '{database}' revision {sourceRevision} does not advance published revision {publishedRevision}.")
    {
        Database = database;
        SourceRevision = sourceRevision;
        PublishedRevision = publishedRevision;
    }

    public string Database { get; }
    public int SourceRevision { get; }
    public int PublishedRevision { get; }
}

/// <summary>The pass planned more placement writes than the budget allows; nothing was written.</summary>
public sealed class EdgePublishBudgetException : Exception
{
    internal EdgePublishBudgetException(int plannedWrites, int maximumWrites)
        : base($"The pass planned {plannedWrites} placement writes, exceeding the {maximumWrites}-write budget.")
    {
        PlannedWrites = plannedWrites;
        MaximumWrites = maximumWrites;
    }

    public int PlannedWrites { get; }
    public int MaximumWrites { get; }
}

/// <summary>One publish step exhausted its bounded retries; the pass changed nothing further.</summary>
public sealed class EdgePublishOperationException : Exception
{
    internal EdgePublishOperationException(EdgePublishStepCode step, Exception innerException)
        : base($"The edge routing publish step '{step}' exhausted its retries.", innerException)
    {
        Step = step;
    }

    public EdgePublishStepCode Step { get; }
}

/// <summary>
/// The single writer of edge-routing KV state (ADR 0050 §6). Every pass is ordered (the health
/// document is written before any placement document), idempotent (a database is written only
/// when its fingerprint — branch placements, eligibility, residency, and revision inputs —
/// changed since the last observed successful write), and retryable (bounded exponential backoff
/// with jitter on transient Cloudflare failures). Keys of databases absent from the snapshot are
/// bulk-deleted only after every write of the pass succeeded; a failed step leaves its
/// observation un-advanced so the next pass retries. A pass that fails changes nothing
/// downstream of the failure.
/// <para>
/// Single-writer contract (ADR 0050 §6): exactly one publisher instance may run; concurrent
/// instances are a contract violation — the revision guard reads eventually-consistent KV and
/// cannot fence another writer, and Cloudflare KV offers no compare-and-swap that could. Within
/// one process, overlapping <see cref="PublishAsync"/> calls are serialized by an internal gate
/// so a process can never overlap itself; across processes, running a single publisher instance
/// is the operator's contract, not something this class can enforce.
/// </para>
/// </summary>
public sealed class EdgeRoutingPublisher
{
    /// <summary>The single key of the <c>REGIONS</c> namespace.</summary>
    public const string HealthKey = "regions";

    private readonly CloudflareKvClient client;
    private readonly IEdgePlacementSource source;
    private readonly string regionsNamespaceTitle;
    private readonly string placementNamespaceTitle;
    private readonly EdgeRoutingPublisherOptions options;
    private readonly TimeProvider clock;
    // Serializes passes within this process: Cloudflare KV has no compare-and-swap, so this
    // gate is the only fencing available against one publisher overlapping itself.
    private readonly SemaphoreSlim publishGate = new(1, 1);

    // Observations advance only after the corresponding write or delete succeeded, so a failed
    // pass retries the same work on the next pass instead of silently skipping it. They are
    // in-memory on purpose: a restarted publisher rewrites everything, which is always safe.
    private readonly Dictionary<string, string> observedFingerprints = new(StringComparer.Ordinal);
    private readonly HashSet<string> publishedDatabases = new(StringComparer.Ordinal);
    private string? regionsNamespaceId;
    private string? placementNamespaceId;

    public EdgeRoutingPublisher(
        CloudflareKvClient client,
        IEdgePlacementSource source,
        string regionsNamespaceTitle,
        string placementNamespaceTitle,
        EdgeRoutingPublisherOptions? options = null,
        TimeProvider? clock = null)
    {
        this.client = client ?? throw new ArgumentNullException(nameof(client));
        this.source = source ?? throw new ArgumentNullException(nameof(source));
        if (string.IsNullOrWhiteSpace(regionsNamespaceTitle))
            throw new ArgumentException("The REGIONS namespace title is required.", nameof(regionsNamespaceTitle));
        if (string.IsNullOrWhiteSpace(placementNamespaceTitle))
            throw new ArgumentException("The PLACEMENT namespace title is required.", nameof(placementNamespaceTitle));
        this.regionsNamespaceTitle = regionsNamespaceTitle;
        this.placementNamespaceTitle = placementNamespaceTitle;
        this.options = options ?? new EdgeRoutingPublisherOptions();
        this.clock = clock ?? TimeProvider.System;
        if (this.options.MaximumWritesPerPass < 1)
            throw new ArgumentOutOfRangeException(nameof(options), "The write budget must be positive.");
        if (this.options.MaximumAttemptsPerOperation < 1)
            throw new ArgumentOutOfRangeException(nameof(options), "The attempt bound must be positive.");
        if (this.options.InitialBackoff <= TimeSpan.Zero || this.options.MaximumBackoff < this.options.InitialBackoff)
            throw new ArgumentOutOfRangeException(nameof(options), "The backoff window is invalid.");
    }

    public static string PlacementKey(string databaseName) => $"db:{databaseName}";

    public async Task<EdgePublishResult> PublishAsync(CancellationToken cancellationToken = default)
    {
        // One pass at a time per process: the revision guard in the pass reads
        // eventually-consistent KV and cannot fence a concurrent pass, so overlapping
        // PublishAsync calls on this instance are serialized by this gate (ADR 0050 §6).
        await publishGate.WaitAsync(cancellationToken);
        try
        {
            return await PublishPassAsync(cancellationToken);
        }
        finally
        {
            publishGate.Release();
        }
    }

    private async Task<EdgePublishResult> PublishPassAsync(CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        var snapshot = await source.GetSnapshotAsync(cancellationToken);
        var errors = EdgePlacementValidation.Validate(snapshot);
        if (!errors.IsEmpty)
            throw new EdgePlacementValidationException(errors);

        // The write plan is deterministic: databases in name order, written only when their
        // fingerprint changed since the last observed successful write.
        var pending = new List<PendingWrite>();
        var skips = 0;
        foreach (var placement in snapshot.Databases
                     .OrderBy(static pair => pair.Key, StringComparer.Ordinal)
                     .Select(static pair => pair.Value))
        {
            var fingerprint = PlacementFingerprint(placement);
            if (observedFingerprints.TryGetValue(placement.DatabaseName, out var observed) &&
                string.Equals(observed, fingerprint, StringComparison.Ordinal))
            {
                skips++;
                continue;
            }

            pending.Add(new PendingWrite(placement, fingerprint));
        }

        if (pending.Count > options.MaximumWritesPerPass)
            throw new EdgePublishBudgetException(pending.Count, options.MaximumWritesPerPass);

        var steps = ImmutableArray.CreateBuilder<EdgePublishStep>();
        await ResolveNamespaceIdsAsync(cancellationToken);

        // 1. Health first, unconditionally, every pass — a placement revision is never published
        //    before the eligibility it describes.
        await RetryAsync(
            EdgePublishStepCode.HealthWrite,
            async token => await client.PutKeyValueAsync(
                regionsNamespaceId!,
                HealthKey,
                EdgePlacementJson.WriteHealthDocument(snapshot.Health),
                token),
            cancellationToken);
        steps.Add(new(EdgePublishStepCode.HealthWrite, EdgePublishStepOutcome.Succeeded, 1));

        // 2. Revision monotonicity against the currently published document, then bulk writes of
        //    exactly the changed documents. Fingerprints advance per chunk only after the chunk
        //    succeeded, so a partial bulk failure retries the unwritten remainder next pass.
        //    The guard GET reads eventually-consistent KV: it can detect a regression already
        //    visible but can never fence a concurrent writer — there is no compare-and-swap in
        //    Cloudflare KV. Correctness therefore rests entirely on the single-writer contract
        //    (ADR 0050 §6: exactly one publisher instance may run; concurrent instances are a
        //    contract violation) plus the in-process gate serializing overlapping passes.
        var updatedUnixSeconds = clock.GetUtcNow().ToUnixTimeSeconds();
        foreach (var item in pending)
        {
            var current = await GetPublishedPlacementValueAsync(
                PlacementKey(item.Placement.DatabaseName),
                cancellationToken);
            if (EdgePlacementJson.TryReadPublishedRevision(current, out var publishedRevision) &&
                item.Placement.Revision <= publishedRevision)
                throw new EdgeRevisionRegressionException(
                    item.Placement.DatabaseName,
                    item.Placement.Revision,
                    publishedRevision);
        }

        var writes = 0;
        foreach (var chunk in pending.Chunk(CloudflareKvClient.MaximumBulkKeys))
        {
            var entries = chunk
                .Select(item => new KeyValuePair<string, string>(
                    PlacementKey(item.Placement.DatabaseName),
                    EdgePlacementJson.WritePlacementDocument(new EdgePlacementDocument(
                        item.Placement.Revision,
                        updatedUnixSeconds,
                        item.Placement.Residency,
                        item.Placement.Branches))))
                .ToArray();
            await RetryAsync(
                EdgePublishStepCode.PlacementWrite,
                async token => await client.PutKeysInBulkAsync(placementNamespaceId!, entries, token),
                cancellationToken);
            foreach (var item in chunk)
            {
                observedFingerprints[item.Placement.DatabaseName] = item.Fingerprint;
                publishedDatabases.Add(item.Placement.DatabaseName);
            }

            writes += chunk.Length;
        }

        if (writes > 0)
            steps.Add(new(EdgePublishStepCode.PlacementWrite, EdgePublishStepOutcome.Succeeded, writes));

        // 3. Stale keys leave only after every write of the pass succeeded; a failed delete keeps
        //    the observation so the next pass retries it.
        var staleDatabases = publishedDatabases
            .Where(database => !snapshot.Databases.ContainsKey(database))
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (staleDatabases.Length > 0)
        {
            var staleKeys = staleDatabases.Select(static database => PlacementKey(database)).ToArray();
            await RetryAsync(
                EdgePublishStepCode.StaleDelete,
                async token => await client.DeleteKeysInBulkAsync(placementNamespaceId!, staleKeys, token),
                cancellationToken);
            foreach (var database in staleDatabases)
            {
                publishedDatabases.Remove(database);
                observedFingerprints.Remove(database);
            }

            steps.Add(new(EdgePublishStepCode.StaleDelete, EdgePublishStepOutcome.Succeeded, staleDatabases.Length));
        }

        watch.Stop();
        return new EdgePublishResult(writes, skips, staleDatabases.Length, watch.Elapsed, steps.ToImmutable());
    }

    /// <summary>
    /// The change-detection input: the database name, revision, residency, and every branch's
    /// ordered region entries, canonicalized so equivalent snapshots always fingerprint equally.
    /// </summary>
    internal static string PlacementFingerprint(EdgeDatabasePlacement placement)
    {
        var builder = new StringBuilder();
        builder.Append(placement.DatabaseName).Append('\n');
        builder.Append("rev:").Append(placement.Revision).Append('\n');
        builder.Append("res:");
        if (placement.Residency is { } residency)
        {
            if (residency.IsRegionList)
                builder.Append(string.Join(",", residency.Regions.Select(static region => region.Value).Order(StringComparer.Ordinal)));
            else
                builder.Append("label:").Append(residency.Label);
        }
        else
        {
            builder.Append("null");
        }

        builder.Append('\n');
        foreach (var branch in placement.Branches.OrderBy(static pair => pair.Key, StringComparer.Ordinal))
        {
            builder.Append("br:").Append(branch.Key).Append('\n');
            foreach (var entry in branch.Value)
                builder.Append(entry.Region.Value)
                    .Append(entry.Read ? 'r' : '-')
                    .Append(entry.Write ? 'w' : '-')
                    .Append('\n');
        }

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())));
    }

    private async Task ResolveNamespaceIdsAsync(CancellationToken cancellationToken)
    {
        if (regionsNamespaceId is null)
            regionsNamespaceId = await RetryAsync(
                EdgePublishStepCode.HealthWrite,
                async token => await client.ResolveNamespaceIdAsync(regionsNamespaceTitle, token),
                cancellationToken)
                ?? throw new InvalidOperationException(
                    $"The Cloudflare KV namespace '{regionsNamespaceTitle}' does not exist.");
        if (placementNamespaceId is null)
            placementNamespaceId = await RetryAsync(
                EdgePublishStepCode.HealthWrite,
                async token => await client.ResolveNamespaceIdAsync(placementNamespaceTitle, token),
                cancellationToken)
                ?? throw new InvalidOperationException(
                    $"The Cloudflare KV namespace '{placementNamespaceTitle}' does not exist.");
    }

    /// <summary>
    /// The revision-guard read. A namespace-not-found class 404 means the cached namespace id
    /// is stale (the namespace was deleted and recreated) or misconfigured: it must surface as
    /// a typed misconfiguration failure, never as a silent null that would disable the revision
    /// guard and wedge the pass. Before giving up the placement namespace id is re-resolved
    /// exactly once; a different id invalidates the cache and the read is retried under it.
    /// </summary>
    private async Task<string?> GetPublishedPlacementValueAsync(string key, CancellationToken cancellationToken)
    {
        var attemptedNamespaceId = placementNamespaceId!;
        try
        {
            return await RetryAsync(
                EdgePublishStepCode.PlacementWrite,
                async token => await client.GetKeyValueAsync(attemptedNamespaceId, key, token),
                cancellationToken);
        }
        catch (CloudflareKvNamespaceNotFoundException)
        {
            var resolved = await RetryAsync(
                EdgePublishStepCode.PlacementWrite,
                async token => await client.ResolveNamespaceIdAsync(placementNamespaceTitle, token),
                cancellationToken);
            if (resolved is null || string.Equals(resolved, attemptedNamespaceId, StringComparison.Ordinal))
                throw;
            placementNamespaceId = resolved;
            return await RetryAsync(
                EdgePublishStepCode.PlacementWrite,
                async token => await client.GetKeyValueAsync(resolved, key, token),
                cancellationToken);
        }
    }

    private async Task RetryAsync(
        EdgePublishStepCode step,
        Func<CancellationToken, Task> operation,
        CancellationToken cancellationToken)
    {
        await RetryAsync<object?>(
            step,
            async token =>
            {
                await operation(token);
                return null;
            },
            cancellationToken);
    }

    private async Task<T> RetryAsync<T>(
        EdgePublishStepCode step,
        Func<CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await operation(cancellationToken);
            }
            catch (Exception exception) when (IsTransient(exception) && attempt < options.MaximumAttemptsPerOperation)
            {
                await Task.Delay(BackoffDelay(attempt), clock, cancellationToken);
            }
            catch (Exception exception) when (IsTransient(exception))
            {
                throw new EdgePublishOperationException(step, exception);
            }
        }
    }

    private static bool IsTransient(Exception exception) =>
        exception is HttpRequestException or TimeoutException ||
        exception is CloudflareKvException { Status: { } status } && CloudflareKvException.IsTransientStatus(status);

    /// <summary>Exponential backoff with equal-part jitter: half fixed, half random, capped.</summary>
    private TimeSpan BackoffDelay(int attempt)
    {
        var shift = Math.Min(attempt - 1, 30);
        var exponential = TimeSpan.FromTicks(Math.Min(
            options.MaximumBackoff.Ticks,
            options.InitialBackoff.Ticks << shift));
        var half = TimeSpan.FromTicks(exponential.Ticks / 2);
        var jitter = TimeSpan.FromTicks((long)(half.Ticks * Random.Shared.NextDouble()));
        return half + jitter;
    }

    private readonly record struct PendingWrite(EdgeDatabasePlacement Placement, string Fingerprint);
}
