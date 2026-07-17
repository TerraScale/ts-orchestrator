using System.Buffers;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text.Json;

namespace TerraScale.Orchestrator.Delivery;

public sealed class RepositoryCiChange
{
    public RepositoryCiChange(string repository, IEnumerable<string> paths)
    {
        if (!ForgejoWebhookVerifier.IsRepository(repository))
            throw new ArgumentException("The changed repository identity is invalid.", nameof(repository));
        ArgumentNullException.ThrowIfNull(paths);
        var values = paths.Take(4_097).ToArray();
        if (values.Length is < 1 or > 4_096 || values.Distinct(StringComparer.Ordinal).Count() != values.Length ||
            values.Any(static path => !IsChangedPath(path)))
            throw new ArgumentException("Changed paths must be unique, bounded, safe repository-relative paths.", nameof(paths));
        Repository = repository;
        Paths = new ReadOnlyCollection<string>(values.Order(StringComparer.Ordinal).ToArray());
    }

    public string Repository { get; }
    public IReadOnlyList<string> Paths { get; }

    private static bool IsChangedPath(string? path)
    {
        if (path is not { Length: >= 1 and <= 512 } || path[0] == '/' || path.Contains('\\') ||
            path.Contains("//", StringComparison.Ordinal) || path.Any(char.IsControl)) return false;
        return path.Split('/').All(static segment => segment is not ("" or "." or ".."));
    }
}

public sealed record RepositoryCiPlannedJob(
    string Id,
    string Repository,
    RepositoryCiNode Node,
    IReadOnlyList<string> DependsOn,
    IReadOnlyList<string> Reasons);

public sealed record RepositoryCiImpactPlan(
    RepositoryCiProfile Profile,
    string Digest,
    IReadOnlyList<RepositoryCiPlannedJob> Jobs);

/// <summary>Selects the bounded cross-repository CI DAG and explains every included job.</summary>
public static class RepositoryCiImpactPlanner
{
    public const string DescriptorPath = ".terrascale/ci-v2.json";
    private const int MaximumRepositories = 64;

    public static RepositoryCiImpactPlan Plan(
        IEnumerable<RepositoryCiDescriptorV2> descriptors,
        IEnumerable<RepositoryCiChange> changes,
        RepositoryCiProfile profile)
    {
        ArgumentNullException.ThrowIfNull(descriptors);
        ArgumentNullException.ThrowIfNull(changes);
        if (profile is not (RepositoryCiProfile.Feature or RepositoryCiProfile.Release))
            throw new ArgumentOutOfRangeException(nameof(profile));
        var descriptorArray = descriptors.Take(MaximumRepositories + 1).ToArray();
        var changeArray = changes.Take(MaximumRepositories + 1).ToArray();
        if (descriptorArray.Length is < 1 or > MaximumRepositories || changeArray.Length is < 1 or > MaximumRepositories ||
            descriptorArray.Any(static value => value is null) || changeArray.Any(static value => value is null))
            throw new ArgumentException("Repository CI graph inputs must be bounded and non-empty.");
        var byRepository = Unique(descriptorArray, static value => value.Repository, "descriptor");
        var changed = Unique(changeArray, static value => value.Repository, "change");
        if (changed.Keys.Except(byRepository.Keys, StringComparer.Ordinal).Any())
            throw new InvalidDataException("Every changed repository requires a v2 CI descriptor.");

        var repositoryOrder = OrderRepositories(byRepository);
        var repositoryDependents = Dependents(byRepository);
        var affectedRepositories = ExpandAffected(changed.Keys, repositoryDependents);
        var selected = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        var reasons = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);

        foreach (var repository in repositoryOrder.Where(affectedRepositories.Contains))
        {
            var descriptor = byRepository[repository];
            var applicable = descriptor.Nodes.Where(node => node.Profiles.Contains(profile)).ToArray();
            if (applicable.Length == 0)
                throw new InvalidDataException("An affected repository has no nodes for the requested CI profile.");
            selected[repository] = new(StringComparer.Ordinal);
            if (changed.TryGetValue(repository, out var change))
            {
                foreach (var path in change.Paths)
                {
                    var matches = path == DescriptorPath
                        ? applicable
                        : applicable.Where(node => node.Paths.Any(prefix => Matches(path, prefix))).ToArray();
                    if (matches.Length == 0)
                        throw new InvalidDataException("A changed path has no explainable CI graph selection.");
                    foreach (var node in matches)
                        Select(repository, node.Id, $"changed:{path}", selected, reasons);
                }
            }
            else
            {
                var incoming = descriptor.RepositoryDependencies
                    .Where(dependency => affectedRepositories.Contains(dependency.Repository))
                    .ToArray();
                if (incoming.Length == 0)
                    throw new InvalidDataException("An affected repository has no explainable upstream dependency.");
                foreach (var node in applicable)
                    foreach (var dependency in incoming)
                        Select(repository, node.Id, $"upstream:{dependency.Repository}:{dependency.Reason}", selected, reasons);
            }
            CloseLocalGraph(descriptor, profile, selected, reasons);
        }

        var jobs = BuildJobs(byRepository, repositoryOrder, affectedRepositories, selected, reasons, profile);
        return new(profile, Digest(profile, byRepository, changed, jobs), ReadOnly(jobs));
    }

    private static Dictionary<string, T> Unique<T>(
        IEnumerable<T> values,
        Func<T, string> identity,
        string inputName)
    {
        var result = new Dictionary<string, T>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            if (!result.TryAdd(identity(value), value))
                throw new InvalidDataException($"The repository CI {inputName} input contains duplicate repositories.");
        }
        return result;
    }

    private static IReadOnlyList<string> OrderRepositories(
        IReadOnlyDictionary<string, RepositoryCiDescriptorV2> descriptors)
    {
        var remaining = descriptors.ToDictionary(
            static item => item.Key,
            item => item.Value.RepositoryDependencies.Count,
            StringComparer.Ordinal);
        var dependents = Dependents(descriptors);
        foreach (var descriptor in descriptors.Values)
            if (descriptor.RepositoryDependencies.Any(dependency => !descriptors.ContainsKey(dependency.Repository)))
                throw new InvalidDataException("A repository CI dependency is missing its descriptor.");
        var ready = new SortedSet<string>(
            remaining.Where(static item => item.Value == 0).Select(static item => item.Key),
            StringComparer.Ordinal);
        var ordered = new List<string>(descriptors.Count);
        while (ready.Count > 0)
        {
            var repository = ready.Min!;
            ready.Remove(repository);
            ordered.Add(repository);
            foreach (var dependent in dependents.GetValueOrDefault(repository) ?? [])
                if (--remaining[dependent] == 0) ready.Add(dependent);
        }
        if (ordered.Count != descriptors.Count)
            throw new InvalidDataException("The repository CI dependency graph contains a cycle.");
        return ordered;
    }

    private static Dictionary<string, List<string>> Dependents(
        IReadOnlyDictionary<string, RepositoryCiDescriptorV2> descriptors)
    {
        var result = descriptors.Keys.ToDictionary(
            static repository => repository,
            _ => new List<string>(),
            StringComparer.Ordinal);
        foreach (var descriptor in descriptors.Values)
            foreach (var dependency in descriptor.RepositoryDependencies)
                if (result.TryGetValue(dependency.Repository, out var values)) values.Add(descriptor.Repository);
        foreach (var values in result.Values) values.Sort(StringComparer.Ordinal);
        return result;
    }

    private static HashSet<string> ExpandAffected(
        IEnumerable<string> changed,
        IReadOnlyDictionary<string, List<string>> dependents)
    {
        var affected = new HashSet<string>(changed, StringComparer.Ordinal);
        var pending = new Queue<string>(affected.Order(StringComparer.Ordinal));
        while (pending.TryDequeue(out var repository))
            foreach (var dependent in dependents.GetValueOrDefault(repository) ?? [])
                if (affected.Add(dependent)) pending.Enqueue(dependent);
        return affected;
    }

    private static void CloseLocalGraph(
        RepositoryCiDescriptorV2 descriptor,
        RepositoryCiProfile profile,
        IReadOnlyDictionary<string, HashSet<string>> selected,
        IDictionary<string, HashSet<string>> reasons)
    {
        var byId = descriptor.Nodes.ToDictionary(static node => node.Id, StringComparer.Ordinal);
        var applicable = descriptor.Nodes.Where(node => node.Profiles.Contains(profile)).ToArray();
        var dependents = applicable.ToDictionary(static node => node.Id, _ => new List<string>(), StringComparer.Ordinal);
        foreach (var node in applicable)
            foreach (var dependency in node.DependsOn) dependents[dependency].Add(node.Id);

        var values = selected[descriptor.Repository];
        var changed = true;
        while (changed)
        {
            changed = false;
            foreach (var id in values.ToArray())
            {
                foreach (var dependency in byId[id].DependsOn)
                    changed |= Select(descriptor.Repository, dependency, $"required-by:{id}", selected, reasons);
                foreach (var dependent in dependents[id])
                    changed |= Select(descriptor.Repository, dependent, $"depends-on:{id}", selected, reasons);
            }
        }
    }

    private static bool Select(
        string repository,
        string node,
        string reason,
        IReadOnlyDictionary<string, HashSet<string>> selected,
        IDictionary<string, HashSet<string>> reasons)
    {
        var added = selected[repository].Add(node);
        var id = JobId(repository, node);
        if (!reasons.TryGetValue(id, out var values)) reasons[id] = values = new(StringComparer.Ordinal);
        values.Add(reason);
        return added;
    }

    private static List<RepositoryCiPlannedJob> BuildJobs(
        IReadOnlyDictionary<string, RepositoryCiDescriptorV2> descriptors,
        IReadOnlyList<string> repositoryOrder,
        IReadOnlySet<string> affectedRepositories,
        IReadOnlyDictionary<string, HashSet<string>> selected,
        IReadOnlyDictionary<string, HashSet<string>> reasons,
        RepositoryCiProfile profile)
    {
        var jobs = new List<RepositoryCiPlannedJob>();
        foreach (var repository in repositoryOrder.Where(affectedRepositories.Contains))
        {
            var descriptor = descriptors[repository];
            var selectedIds = selected[repository];
            var upstreamTerminals = descriptor.RepositoryDependencies
                .Where(dependency => affectedRepositories.Contains(dependency.Repository))
                .SelectMany(dependency => descriptors[dependency.Repository].Nodes
                    .Where(node => selected[dependency.Repository].Contains(node.Id) &&
                        localTerminal(node.Id, descriptors[dependency.Repository], selected[dependency.Repository], profile))
                    .Select(node => JobId(dependency.Repository, node.Id)))
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray();

            foreach (var node in descriptor.Nodes.Where(node => selectedIds.Contains(node.Id)))
            {
                var dependencies = node.DependsOn.Where(selectedIds.Contains)
                    .Select(dependency => JobId(repository, dependency))
                    .ToHashSet(StringComparer.Ordinal);
                var firstConsumer = node.Kind != RepositoryCiNodeKind.Static &&
                    node.DependsOn.Where(selectedIds.Contains).All(dependency =>
                        descriptor.Nodes.Single(candidate => candidate.Id == dependency).Kind == RepositoryCiNodeKind.Static);
                if (firstConsumer) dependencies.UnionWith(upstreamTerminals);
                var id = JobId(repository, node.Id);
                jobs.Add(new(
                    id,
                    repository,
                    node,
                    ReadOnly(dependencies.Order(StringComparer.Ordinal).ToArray()),
                    ReadOnly(reasons[id].Order(StringComparer.Ordinal).ToArray())));
            }
        }
        return jobs;

        static bool localTerminal(
            string id,
            RepositoryCiDescriptorV2 descriptor,
            IReadOnlySet<string> selectedIds,
            RepositoryCiProfile profile) => !descriptor.Nodes.Any(node =>
                node.Profiles.Contains(profile) && selectedIds.Contains(node.Id) && node.DependsOn.Contains(id));
    }

    private static bool Matches(string path, string prefix) => prefix.EndsWith('/')
        ? path.StartsWith(prefix, StringComparison.Ordinal)
        : path == prefix;

    private static string JobId(string repository, string node) => $"{repository}:{node}";

    private static string Digest(
        RepositoryCiProfile profile,
        IReadOnlyDictionary<string, RepositoryCiDescriptorV2> descriptors,
        IReadOnlyDictionary<string, RepositoryCiChange> changes,
        IReadOnlyList<RepositoryCiPlannedJob> jobs)
    {
        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            writer.WriteString("profile", profile.ToString());
            writer.WriteStartArray("descriptors");
            foreach (var descriptor in descriptors.Values.OrderBy(static value => value.Repository, StringComparer.Ordinal))
            {
                writer.WriteStartObject();
                writer.WriteString("repository", descriptor.Repository);
                writer.WriteString("digest", descriptor.Digest);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteStartArray("changes");
            foreach (var change in changes.Values.OrderBy(static value => value.Repository, StringComparer.Ordinal))
            {
                writer.WriteStartObject();
                writer.WriteString("repository", change.Repository);
                writer.WriteStartArray("paths");
                foreach (var path in change.Paths) writer.WriteStringValue(path);
                writer.WriteEndArray();
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteStartArray("jobs");
            foreach (var job in jobs)
            {
                writer.WriteStartObject();
                writer.WriteString("id", job.Id);
                writer.WriteStartArray("dependsOn");
                foreach (var dependency in job.DependsOn) writer.WriteStringValue(dependency);
                writer.WriteEndArray();
                writer.WriteStartArray("reasons");
                foreach (var reason in job.Reasons) writer.WriteStringValue(reason);
                writer.WriteEndArray();
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return Convert.ToHexStringLower(SHA256.HashData(bytes.WrittenSpan));
    }

    private static IReadOnlyList<T> ReadOnly<T>(T[] values) => new ReadOnlyCollection<T>(values);
    private static IReadOnlyList<T> ReadOnly<T>(List<T> values) => new ReadOnlyCollection<T>(values.ToArray());
}
