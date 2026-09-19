using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.ControlPlane.EdgeRouting;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Nodes;

namespace TerraScale.Orchestrator.ControlPlane.TerraBase;

/// <summary>
/// The bounded reconciler configuration file (<c>TS_ORCH_TERRABASE_RECONCILER</c>):
/// a closed shape with no inline credentials — the edge API token is read at start
/// from its owner-private file, mode-checked like every sibling credential path.
/// </summary>
public sealed class TerraBaseReconcilerConfiguration
{
    private const int MaximumConfigurationBytes = 64 * 1024;
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private TerraBaseReconcilerConfiguration(TerraBaseEdgeConfiguration? edge) => Edge = edge;

    /// <summary>The optional edge-routing publication target; absent means no publication.</summary>
    public TerraBaseEdgeConfiguration? Edge { get; }

    public sealed record TerraBaseEdgeConfiguration(
        string AccountId,
        string RegionsNamespaceTitle,
        string PlacementNamespaceTitle,
        string ApiTokenFile);

    public static TerraBaseReconcilerConfiguration? Load(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;
        var fullPath = Path.GetFullPath(path);
        var file = new FileInfo(fullPath);
        if (!file.Exists || file.LinkTarget is not null || file.Length is < 1 or > MaximumConfigurationBytes)
            throw new ArgumentException("The TerraBase reconciler configuration must be a bounded regular file.", nameof(path));
        using var stream = File.OpenRead(fullPath);
        var document = JsonSerializer.Deserialize<ConfigurationDocument>(stream, SerializerOptions)
            ?? throw new InvalidDataException("The TerraBase reconciler configuration is empty.");
        if (document.SchemaVersion != 1)
            throw new InvalidDataException("The TerraBase reconciler configuration has an unsupported shape.");
        TerraBaseEdgeConfiguration? edge = null;
        if (document.Edge is { } candidate)
        {
            if (string.IsNullOrWhiteSpace(candidate.AccountId) ||
                string.IsNullOrWhiteSpace(candidate.RegionsNamespaceTitle) ||
                string.IsNullOrWhiteSpace(candidate.PlacementNamespaceTitle) ||
                string.IsNullOrWhiteSpace(candidate.ApiTokenFile))
                throw new InvalidDataException("The TerraBase edge configuration is incomplete.");
            edge = new(
                candidate.AccountId,
                candidate.RegionsNamespaceTitle,
                candidate.PlacementNamespaceTitle,
                Path.GetFullPath(candidate.ApiTokenFile, file.DirectoryName ?? Directory.GetCurrentDirectory()));
        }
        return new(edge);
    }

    private sealed record ConfigurationDocument(int? SchemaVersion, EdgeDocument? Edge);

    private sealed record EdgeDocument(
        string? AccountId,
        string? RegionsNamespaceTitle,
        string? PlacementNamespaceTitle,
        string? ApiTokenFile);
}

/// <summary>
/// The composition options: the loaded reconciler configuration plus the member-host
/// fleet the runtime host builds where the authority lease and the NATS stores live.
/// </summary>
internal sealed record TerraBasePlacementReconcilerOptions(
    TerraBaseReconcilerConfiguration Configuration,
    IMemberHostFleet Fleet);

/// <summary>
/// Hosting for the placement reconciler: one background loop ticking the leader-gated
/// reconciler every few seconds. Tick failures are logged and retried — the loop never
/// exits on its own; cancellation is the only graceful stop.
/// </summary>
internal sealed class TerraBasePlacementReconcilerRuntime : IAsyncDisposable
{
    private static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(3);

    private readonly TerraBasePlacementReconciler reconciler;
    private readonly CancellationTokenSource stopping = new();
    private readonly List<Task> loops = [];

    private TerraBasePlacementReconcilerRuntime(TerraBasePlacementReconciler reconciler) =>
        this.reconciler = reconciler;

    /// <summary>Composes the reconciler with its optional edge publisher and starts the tick loop.</summary>
    internal static async Task<TerraBasePlacementReconcilerRuntime> StartAsync(
        INatsKVStore delivery,
        INatsKVStore runtimeStore,
        Func<RegionalAuthoritySnapshot> authority,
        TerraBasePlacementReconcilerOptions options,
        string cell,
        CancellationToken cancellationToken)
    {
        EdgeRoutingPublisher? publisher = null;
        TerraBasePlacementEdgeSource? source = null;
        if (options.Configuration.Edge is { } edge)
        {
            var token = await EdgeRoutingPublishCli.ReadApiTokenAsync(edge.ApiTokenFile, cancellationToken)
                .ConfigureAwait(false);
            source = new(cancellationToken => PlacementWorld.ReadAsync(delivery, options.Fleet, cancellationToken));
            publisher = new(
                CloudflareKvClient.Create(token, edge.AccountId),
                source,
                edge.RegionsNamespaceTitle,
                edge.PlacementNamespaceTitle);
        }
        var runtime = new TerraBasePlacementReconcilerRuntime(
            TerraBasePlacementReconciler.Create(
                delivery,
                runtimeStore,
                authority,
                options.Fleet,
                cell,
                publisher,
                source));
        runtime.loops.Add(Task.Run(() => runtime.LoopAsync(runtime.stopping.Token), CancellationToken.None));
        return runtime;
    }

    private async Task LoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await reconciler.TickAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine(
                    $"TerraBase placement tick failed ({exception.GetType().Name}); retrying next tick.");
            }
            try
            {
                await Task.Delay(TickInterval, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        stopping.Cancel();
        try
        {
            await Task.WhenAll(loops.ToArray()).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        stopping.Dispose();
    }
}
