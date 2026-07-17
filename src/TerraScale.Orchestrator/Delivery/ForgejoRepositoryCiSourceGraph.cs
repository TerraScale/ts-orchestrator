using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Delivery;

public sealed class ForgejoRepositoryCiSourceGraphConfiguration
{
    private const int MaximumBytes = 64 * 1024;
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private ForgejoRepositoryCiSourceGraphConfiguration(string[] repositories) =>
        Repositories = Array.AsReadOnly(repositories);

    public IReadOnlyList<string> Repositories { get; }

    public static ForgejoRepositoryCiSourceGraphConfiguration? Load(
        string? path,
        ForgejoSourceConfiguration? source)
    {
        if (string.IsNullOrWhiteSpace(path))
            return source is null ? null : new([source.Repository]);
        ArgumentNullException.ThrowIfNull(source);
        var fullPath = Path.GetFullPath(path);
        var file = new FileInfo(fullPath);
        if (!file.Exists || file.LinkTarget is not null || file.Length is < 2 or > MaximumBytes)
            throw new ArgumentException("The Forgejo CI source graph must be a bounded regular file.", nameof(path));
        using var stream = File.OpenRead(fullPath);
        var document = JsonSerializer.Deserialize<SourceGraphDocument>(stream, SerializerOptions) ??
            throw new InvalidDataException("The Forgejo CI source graph is empty.");
        var repositories = document.Repositories?.Order(StringComparer.Ordinal).ToArray() ?? [];
        if (document.SchemaVersion != 1 || repositories.Length is < 1 or > 64 ||
            repositories.Any(static repository => !ForgejoWebhookVerifier.IsRepository(repository)) ||
            repositories.Distinct(StringComparer.Ordinal).Count() != repositories.Length ||
            !repositories.Contains(source.Repository, StringComparer.Ordinal))
            throw new InvalidDataException("The Forgejo CI source graph is invalid or omits the webhook repository.");
        return new(repositories);
    }

    private sealed record SourceGraphDocument(int SchemaVersion, string[]? Repositories);
}

/// <summary>Snapshots one explicit Forgejo repository catalog into exact affected CI inputs.</summary>
internal sealed class ForgejoRepositoryCiSourceGraph : IAsyncDisposable
{
    private readonly ForgejoSourceConfiguration rootConfiguration;
    private readonly IReadOnlyDictionary<string, IForgejoRepositorySourceClient> sources;

    private ForgejoRepositoryCiSourceGraph(
        ForgejoSourceConfiguration rootConfiguration,
        IReadOnlyDictionary<string, IForgejoRepositorySourceClient> sources,
        ForgejoSourceClient? rootClient)
    {
        this.rootConfiguration = rootConfiguration;
        this.sources = sources;
        RootClient = rootClient;
    }

    internal ForgejoSourceClient? RootClient { get; }

    internal static ForgejoRepositoryCiSourceGraph Create(
        ForgejoSourceConfiguration source,
        ForgejoRepositoryCiSourceGraphConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(configuration);
        var clients = new Dictionary<string, IForgejoRepositorySourceClient>(StringComparer.Ordinal);
        ForgejoSourceClient? root = null;
        try
        {
            foreach (var repository in configuration.Repositories)
            {
                var client = ForgejoSourceClient.Create(source.ForRepository(repository));
                clients.Add(repository, client);
                if (repository == source.Repository) root = client;
            }
            return new(source, clients, root ?? throw new InvalidDataException(
                "The Forgejo CI source graph omitted its root client."));
        }
        catch
        {
            foreach (var client in clients.Values) client.DisposeAsync().AsTask().GetAwaiter().GetResult();
            throw;
        }
    }

    internal static ForgejoRepositoryCiSourceGraph CreateForTests(
        ForgejoSourceConfiguration source,
        ForgejoRepositoryCiSourceGraphConfiguration configuration,
        Func<ForgejoSourceConfiguration, IForgejoRepositorySourceClient> create)
    {
        ArgumentNullException.ThrowIfNull(create);
        var clients = configuration.Repositories.ToDictionary(
            static repository => repository,
            repository => create(source.ForRepository(repository)),
            StringComparer.Ordinal);
        return new(source, clients, null);
    }

    internal async Task<RepositoryCiPipelineGraph> ResolvePipelineAsync(
        ForgejoCiTriggerPlan trigger,
        IReadOnlyList<string> changedPaths,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(trigger);
        ArgumentNullException.ThrowIfNull(changedPaths);
        var profile = trigger.JobKind switch
        {
            ControlPlane.Delivery.JobKind.ProductValidation => RepositoryCiProfile.Feature,
            ControlPlane.Delivery.JobKind.TrustedBuild => RepositoryCiProfile.Release,
            _ => throw new InvalidOperationException("The trigger cannot resolve a CI source graph."),
        };
        var snapshot = await SnapshotAsync(trigger, "develop", exactRootMain: false, cancellationToken);
        var affected = Affected(snapshot.Descriptors, trigger.Envelope.Repository, changedPaths, profile);
        return new(
            snapshot.Files,
            Array.AsReadOnly(snapshot.Sources.Where(source => affected.Contains(source.Repository)).ToArray()));
    }

    internal async Task<IReadOnlyList<ForgejoBranchObservation>> ReadCurrentMainSourcesAsync(
        ForgejoCiTriggerPlan trigger,
        IReadOnlyList<string> changedPaths,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(trigger);
        ArgumentNullException.ThrowIfNull(changedPaths);
        var snapshot = await SnapshotAsync(trigger, "main", exactRootMain: true, cancellationToken);
        var affected = Affected(
            snapshot.Descriptors,
            trigger.Envelope.Repository,
            changedPaths,
            RepositoryCiProfile.Release);
        return Array.AsReadOnly(snapshot.Observations
            .Where(observation => affected.Contains(observation.Revision.Repository))
            .ToArray());
    }

    internal Task<ForgejoSourceArchive> ReadArchiveAsync(
        ForgejoResolvedRevision revision,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(revision);
        return sources.TryGetValue(revision.Repository, out var source)
            ? source.ReadArchiveAsync(revision, cancellationToken)
            : throw new InvalidDataException("The CI source archive belongs to a repository outside the source graph.");
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var source in sources.Values) await source.DisposeAsync();
    }

    private async Task<SourceSnapshot> SnapshotAsync(
        ForgejoCiTriggerPlan trigger,
        string branch,
        bool exactRootMain,
        CancellationToken cancellationToken)
    {
        if (!sources.ContainsKey(trigger.Envelope.Repository) ||
            trigger.Envelope.Repository != rootConfiguration.Repository)
            throw new InvalidDataException("The CI trigger is outside the configured source graph root.");
        var files = new List<ForgejoSourceFile>(sources.Count);
        var revisions = new List<ForgejoResolvedRevision>(sources.Count);
        var observations = new List<ForgejoBranchObservation>(sources.Count);
        var descriptors = new List<RepositoryCiDescriptorV2>(sources.Count);
        foreach (var item in sources.OrderBy(static item => item.Key, StringComparer.Ordinal))
        {
            ForgejoResolvedRevision revision;
            if (item.Key == trigger.Envelope.Repository && !exactRootMain)
            {
                revision = await item.Value.ResolveAsync(trigger.Envelope.Revision, cancellationToken);
            }
            else
            {
                var observation = await item.Value.PollBranchAsync(branch, cancellationToken);
                if (!observation.Protected || observation.Revision.Repository != item.Key ||
                    exactRootMain && item.Key == trigger.Envelope.Repository &&
                        !StringComparer.OrdinalIgnoreCase.Equals(
                            observation.Revision.Commit,
                            trigger.Envelope.Revision))
                    throw new InvalidDataException("The CI source graph branch snapshot is unprotected or changed.");
                revision = observation.Revision;
                observations.Add(observation);
            }
            var file = await item.Value.ReadFileAsync(
                revision.Commit,
                RepositoryCiImpactPlanner.DescriptorPath,
                ForgejoSourceClient.MaximumFileBytes,
                cancellationToken);
            var descriptor = RepositoryCiDescriptor.Parse(file.Content);
            if (file.Repository != item.Key || descriptor.Repository != item.Key || file.Commit != revision.Commit)
                throw new InvalidDataException("A CI source graph descriptor changed repository identity.");
            files.Add(file);
            revisions.Add(revision);
            descriptors.Add(descriptor);
        }
        return new(files.AsReadOnly(), revisions.AsReadOnly(), observations.AsReadOnly(), descriptors.AsReadOnly());
    }

    private static HashSet<string> Affected(
        IReadOnlyList<RepositoryCiDescriptorV2> descriptors,
        string repository,
        IReadOnlyList<string> changedPaths,
        RepositoryCiProfile profile) => RepositoryCiImpactPlanner.Plan(
            descriptors,
            [new RepositoryCiChange(repository, changedPaths)],
            profile)
        .Jobs.Select(static job => job.Repository)
        .ToHashSet(StringComparer.Ordinal);

    private sealed record SourceSnapshot(
        IReadOnlyList<ForgejoSourceFile> Files,
        IReadOnlyList<ForgejoResolvedRevision> Sources,
        IReadOnlyList<ForgejoBranchObservation> Observations,
        IReadOnlyList<RepositoryCiDescriptorV2> Descriptors);
}
