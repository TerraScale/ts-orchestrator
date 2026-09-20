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
/// discovered by listing the PLACEMENT namespace — never by remembering past passes, so a fresh
/// publisher still reconciles keys left by any earlier process — and bulk-deleted only after
/// every write of the pass succeeded; a failed step leaves the keys in place so the next pass
/// retries. A pass that fails changes nothing downstream of the failure.
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

    // Observations advance only after the corresponding write succeeded, so a failed pass
    // retries the same work on the next pass instead of silently skipping it. They are in-memory
    // on purpose: a restarted publisher rewrites everything, which is always safe. They are
    // never allowed to outlive their key — every pass's namespace listing voids observations
    // whose key is gone, so the cache cannot claim the edge holds a document it lost.
    // Stale-key deletion keeps NO observation — it is reality-based, from a fresh namespace listing.
    private readonly Dictionary<string, string> observedFingerprints = new(StringComparer.Ordinal);
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

        // Namespace ids are re-verified before the write plan is computed: a recreated
        // PLACEMENT namespace invalidates every observed fingerprint, so the plan rewrites
        // unchanged databases into the new namespace instead of skipping them.
        var steps = ImmutableArray.CreateBuilder<EdgePublishStep>();
        await ResolveNamespaceIdsAsync(cancellationToken);

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

        // 1. Health first, unconditionally, every pass — a placement revision is never published
        //    before the eligibility it describes.
        await WriteHealthDocumentAsync(snapshot.Health, cancellationToken);
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
                item.Placement.Revision < publishedRevision)
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
            }

            writes += chunk.Length;
        }

        if (writes > 0)
            steps.Add(new(EdgePublishStepCode.PlacementWrite, EdgePublishStepOutcome.Succeeded, writes));

        // 3. Stale keys leave only after every write of the pass succeeded. Deletion is
        //    reality-based: the PLACEMENT namespace is listed every pass — never remembered —
        //    so the only executable path (a fresh publisher per CLI invocation) still removes
        //    keys written by any earlier process. Only `db:`-prefixed keys the snapshot does not
        //    claim are deleted; any other key in the namespace is not this publisher's to touch.
        //    A failed listing or delete leaves the keys in place; the next pass lists again.
        var presentKeys = (await ListPlacementKeysAsync(cancellationToken)).ToHashSet(StringComparer.Ordinal);
        // The same listing invalidates the fingerprint cache, so the cache can never keep
        // describing a key the edge no longer holds: an observation whose `db:` key is absent
        // from the namespace (out-of-band delete, KV data loss) is voided and the next pass
        // republishes that database instead of skipping it as unchanged forever. Existence
        // only — rewriting content an out-of-contract writer tampered with is the
        // single-writer contract's to prevent (ADR 0050 §6), not a listing's to detect.
        foreach (var name in observedFingerprints.Keys
                     .Where(name => !presentKeys.Contains(PlacementKey(name)))
                     .ToArray())
            observedFingerprints.Remove(name);
        var staleKeys = presentKeys
            .Where(key => key.StartsWith("db:", StringComparison.Ordinal) &&
                          !snapshot.Databases.ContainsKey(key["db:".Length..]))
            .Order(StringComparer.Ordinal)
            .ToArray();
        var deleted = 0;
        foreach (var chunk in staleKeys.Chunk(CloudflareKvClient.MaximumBulkKeys))
        {
            await RetryAsync(
                EdgePublishStepCode.StaleDelete,
                async token => await client.DeleteKeysInBulkAsync(placementNamespaceId!, chunk, token),
                cancellationToken);
            // The observation dies with the key: a database re-onboarded later with an unchanged
            // revision must be rewritten, not skipped against the fingerprint of a deleted key.
            foreach (var key in chunk)
                observedFingerprints.Remove(key["db:".Length..]);
            deleted += chunk.Length;
        }

        if (deleted > 0)
            steps.Add(new(EdgePublishStepCode.StaleDelete, EdgePublishStepOutcome.Succeeded, deleted));

        watch.Stop();
        return new EdgePublishResult(writes, skips, deleted, watch.Elapsed, steps.ToImmutable());
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
        var resolvedPlacement = await RetryAsync(
            EdgePublishStepCode.HealthWrite,
            async token => await client.ResolveNamespaceIdAsync(placementNamespaceTitle, token),
            cancellationToken);
        if (resolvedPlacement is null)
        {
            // The namespace existed for an earlier pass but is gone now: the same typed
            // misconfiguration failure the read path raises, never a silent skip.
            if (placementNamespaceId is not null)
                throw new CloudflareKvNamespaceNotFoundException(System.Net.HttpStatusCode.NotFound, []);
            throw new InvalidOperationException(
                $"The Cloudflare KV namespace '{placementNamespaceTitle}' does not exist.");
        }
        if (placementNamespaceId is not null &&
            !string.Equals(resolvedPlacement, placementNamespaceId, StringComparison.Ordinal))
        {
            // The namespace was deleted and recreated: fingerprints observed in the old
            // one describe keys that no longer exist, so every database is rewritten.
            observedFingerprints.Clear();
        }
        placementNamespaceId = resolvedPlacement;
    }

    /// <summary>
    /// The health write with the same recreation recovery the placement reads have: a
    /// namespace-not-found class 404 re-resolves the REGIONS namespace exactly once and
    /// retries under the new id; anything else is a permanent misconfiguration.
    /// </summary>
    private async Task WriteHealthDocumentAsync(EdgeHealthDocument health, CancellationToken cancellationToken)
    {
        var attempted = regionsNamespaceId!;
        try
        {
            await RetryAsync(
                EdgePublishStepCode.HealthWrite,
                async token => await client.PutKeyValueAsync(
                    attempted,
                    HealthKey,
                    EdgePlacementJson.WriteHealthDocument(health),
                    token),
                cancellationToken);
        }
        catch (CloudflareKvNamespaceNotFoundException)
        {
            var resolved = await RetryAsync(
                EdgePublishStepCode.HealthWrite,
                async token => await client.ResolveNamespaceIdAsync(regionsNamespaceTitle, token),
                cancellationToken);
            if (resolved is null || string.Equals(resolved, attempted, StringComparison.Ordinal))
                throw;
            regionsNamespaceId = resolved;
            await RetryAsync(
                EdgePublishStepCode.HealthWrite,
                async token => await client.PutKeyValueAsync(
                    resolved,
                    HealthKey,
                    EdgePlacementJson.WriteHealthDocument(health),
                    token),
                cancellationToken);
        }
    }

    /// <summary>
    /// The revision-guard read. A namespace-not-found class 404 means the cached namespace id
    /// is stale (the namespace was deleted and recreated) or misconfigured: it must surface as
    /// a typed misconfiguration failure, never as a silent null that would disable the revision
    /// guard and wedge the pass.
    /// </summary>
    private Task<string?> GetPublishedPlacementValueAsync(string key, CancellationToken cancellationToken) =>
        PlacementNamespaceReadAsync(
            EdgePublishStepCode.PlacementWrite,
            (namespaceId, token) => client.GetKeyValueAsync(namespaceId, key, token),
            cancellationToken);

    /// <summary>The stale-detection read: every key actually present in the PLACEMENT namespace.</summary>
    private Task<IReadOnlyList<string>> ListPlacementKeysAsync(CancellationToken cancellationToken) =>
        PlacementNamespaceReadAsync(
            EdgePublishStepCode.StaleDelete,
            (namespaceId, token) => client.ListKeysAsync(namespaceId, token),
            cancellationToken);

    /// <summary>
    /// One read against the placement namespace under the cached namespace id. A
    /// namespace-not-found class 404 re-resolves the placement namespace id exactly once; a
    /// different id invalidates the cache and the read is retried under it, anything else is a
    /// permanent misconfiguration that surfaces as the typed exception.
    /// </summary>
    private async Task<T> PlacementNamespaceReadAsync<T>(
        EdgePublishStepCode step,
        Func<string, CancellationToken, Task<T>> read,
        CancellationToken cancellationToken)
    {
        var attemptedNamespaceId = placementNamespaceId!;
        try
        {
            return await RetryAsync(
                step,
                token => read(attemptedNamespaceId, token),
                cancellationToken);
        }
        catch (CloudflareKvNamespaceNotFoundException)
        {
            var resolved = await RetryAsync(
                step,
                async token => await client.ResolveNamespaceIdAsync(placementNamespaceTitle, token),
                cancellationToken);
            if (resolved is null || string.Equals(resolved, attemptedNamespaceId, StringComparison.Ordinal))
                throw;
            placementNamespaceId = resolved;
            // The namespace was recreated empty: fingerprints observed in the old one
            // describe keys that no longer exist, so every database must be rewritten
            // instead of skipped as unchanged.
            observedFingerprints.Clear();
            return await RetryAsync(
                step,
                token => read(resolved, token),
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
        // The exponential term is computed in floating point: a tick shift of a large initial
        // backoff would wrap negative long before the cap, and a negative delay is not a delay.
        var shift = Math.Min(attempt - 1, 30);
        var exponential = TimeSpan.FromMilliseconds(Math.Min(
            options.MaximumBackoff.TotalMilliseconds,
            options.InitialBackoff.TotalMilliseconds * Math.Pow(2, shift)));
        var half = TimeSpan.FromTicks(exponential.Ticks / 2);
        var jitter = TimeSpan.FromTicks((long)(half.Ticks * Random.Shared.NextDouble()));
        return half + jitter;
    }

    private readonly record struct PendingWrite(EdgeDatabasePlacement Placement, string Fingerprint);
}
