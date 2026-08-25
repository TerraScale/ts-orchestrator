using System.Buffers;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Delivery;

public enum RepositoryCiNodeKind
{
    Unspecified,
    Static,
    Build,
    Test,
    Artifact,
}

public enum RepositoryCiProfile
{
    Unspecified,
    Feature,
    Build,
}

public enum RepositoryCiResourceWeight
{
    Unspecified,
    Light,
    Medium,
    Heavy,
}

public enum RepositoryCiArchitecture
{
    Unspecified,
    Any,
    LinuxX64,
    LinuxArm64,
}

public sealed record RepositoryCiDependency
{
    internal RepositoryCiDependency(string repository, string reason)
    {
        Repository = repository;
        Reason = reason;
    }

    public string Repository { get; }
    public string Reason { get; }
}

public sealed record RepositoryCiNode
{
    internal RepositoryCiNode(
        string id,
        RepositoryCiNodeKind kind,
        RepositoryCiResourceWeight resourceWeight,
        IReadOnlyList<RepositoryCiProfile> profiles,
        IReadOnlyList<RepositoryCiArchitecture> architectures,
        IReadOnlyList<string> paths,
        IReadOnlyList<string> dependsOn)
    {
        Id = id;
        Kind = kind;
        ResourceWeight = resourceWeight;
        Profiles = profiles;
        Architectures = architectures;
        Paths = paths;
        DependsOn = dependsOn;
    }

    public string Id { get; }
    public RepositoryCiNodeKind Kind { get; }
    public RepositoryCiResourceWeight ResourceWeight { get; }
    public IReadOnlyList<RepositoryCiProfile> Profiles { get; }
    public IReadOnlyList<RepositoryCiArchitecture> Architectures { get; }
    public IReadOnlyList<string> Paths { get; }
    public IReadOnlyList<string> DependsOn { get; }
}

public sealed class RepositoryCiDescriptorV2
{
    internal RepositoryCiDescriptorV2(
        string apiVersion,
        string repository,
        string digest,
        IReadOnlyList<RepositoryCiDependency> repositoryDependencies,
        IReadOnlyList<RepositoryCiNode> nodes)
    {
        ApiVersion = apiVersion;
        Repository = repository;
        Digest = digest;
        RepositoryDependencies = repositoryDependencies;
        Nodes = nodes;
    }

    public string ApiVersion { get; }
    public string Repository { get; }
    public string Digest { get; }
    public IReadOnlyList<RepositoryCiDependency> RepositoryDependencies { get; }
    public IReadOnlyList<RepositoryCiNode> Nodes { get; }
}

/// <summary>Compiles the command-free repository CI policy used by the native affected graph.</summary>
public static class RepositoryCiDescriptor
{
    public const string ApiVersion = "terrascale.ci/v3";
    private const string RetiredApiVersion = "terrascale.ci/v2";
    public const int MaximumBytes = 256 * 1024;
    public const int MaximumNodes = 256;
    public const int MaximumItemsPerNode = 64;
    public const int MaximumRepositoryDependencies = 64;
    private const int MaximumDepth = 12;

    public static RepositoryCiDescriptorV2 Parse(ReadOnlyMemory<byte> descriptor)
    {
        if (descriptor.IsEmpty || descriptor.Length > MaximumBytes)
            throw new InvalidDataException("The repository CI descriptor is empty or exceeds its technical bound.");

        try
        {
            RejectDuplicateProperties(descriptor.Span);
            using (JsonDocument.Parse(descriptor, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = MaximumDepth,
            }))
            {
            }
            var document = JsonSerializer.Deserialize(
                descriptor.Span,
                RepositoryCiDescriptorJsonContext.Default.RepositoryCiDescriptorDocument)
                ?? throw new JsonException();
            // Retired-schema detection precedes unknown-field rejection so callers receive one
            // actionable migration error instead of per-field "unknown field" noise.
            if (document.ApiVersion == RetiredApiVersion)
                throw new InvalidDataException(RetiredSchemaMessage(document));
            if (document.ApiVersion is not { } apiVersion || apiVersion != ApiVersion)
                throw new InvalidDataException(
                    $"The repository CI descriptor apiVersion '{document.ApiVersion}' is not supported; this control plane requires '{ApiVersion}'.");
            RejectUnknown(document.Extra);
            if (document.Repository is not { } repository ||
                !ForgejoWebhookVerifier.IsRepository(repository))
                throw new InvalidDataException("The repository CI descriptor identity is invalid or unsupported.");
            var dependencies = ParseRepositoryDependencies(document);
            var nodes = OrderAndValidate(ParseNodes(document));
            return new(
                ApiVersion,
                repository,
                ComputeDigest(repository, dependencies, nodes),
                ReadOnly(dependencies),
                ReadOnly(nodes));
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The repository CI descriptor is invalid JSON.", exception);
        }
    }

    private static List<RepositoryCiDependency> ParseRepositoryDependencies(
        RepositoryCiDescriptorDocument document)
    {
        var values = document.RepositoryDependencies ?? [];
        if (values.Length > MaximumRepositoryDependencies)
            throw new InvalidDataException("The repository CI dependency list exceeds its technical bound.");
        var unique = new HashSet<string>(StringComparer.Ordinal);
        var dependencies = new List<RepositoryCiDependency>(values.Length);
        foreach (var value in values)
        {
            if (value is null) throw new InvalidDataException("A repository CI dependency is missing.");
            RejectUnknown(value.Extra);
            if (value.Repository is not { } repository || value.Reason is not { } reason ||
                !ForgejoWebhookVerifier.IsRepository(repository) || repository == document.Repository ||
                !unique.Add(repository) || !IsReason(reason))
                throw new InvalidDataException("A repository CI dependency is invalid.");
            dependencies.Add(new(repository, reason));
        }
        dependencies.Sort(static (left, right) => StringComparer.Ordinal.Compare(left.Repository, right.Repository));
        return dependencies;
    }

    private static List<RepositoryCiNode> ParseNodes(RepositoryCiDescriptorDocument document)
    {
        if (document.Nodes is not { Length: > 0 and <= MaximumNodes })
            throw new InvalidDataException("The repository CI node list must be bounded and non-empty.");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var nodes = new List<RepositoryCiNode>(document.Nodes.Length);
        foreach (var value in document.Nodes)
        {
            if (value is null) throw new InvalidDataException("A repository CI node is missing.");
            RejectUnknown(value.Extra);
            if (value.Id is not { } id || !IsToken(id) || !ids.Add(id) ||
                !ParseEnum(value.Kind, out RepositoryCiNodeKind kind) ||
                !ParseEnum(value.ResourceWeight, out RepositoryCiResourceWeight weight))
                throw new InvalidDataException("A repository CI node identity or policy is invalid.");
            var profiles = ParseProfiles(value.Profiles, kind);
            var architectures = ParseArchitectures(value.Architectures, kind);
            var paths = ParseStrings(value.Paths, IsSafePath, required: false);
            var dependencies = ParseStrings(value.DependsOn, IsToken, required: false);
            if (paths.Count == 0 && dependencies.Count == 0)
                throw new InvalidDataException("Every repository CI node must have a direct path or dependency.");
            nodes.Add(new(id, kind, weight, profiles, architectures, paths, dependencies));
        }
        return nodes;
    }

    private static IReadOnlyList<RepositoryCiProfile> ParseProfiles(string[]? values, RepositoryCiNodeKind kind)
    {
        if (values is not { Length: > 0 and <= 2 })
            throw new InvalidDataException("Every repository CI node requires a bounded profile list.");
        var profiles = new List<RepositoryCiProfile>(values.Length);
        foreach (var value in values)
        {
            if (!ParseEnum(value, out RepositoryCiProfile profile) || profiles.Contains(profile) ||
                kind == RepositoryCiNodeKind.Artifact && profile == RepositoryCiProfile.Feature)
                throw new InvalidDataException("A repository CI node profile is invalid.");
            profiles.Add(profile);
        }
        profiles.Sort();
        return ReadOnly(profiles);
    }

    private static IReadOnlyList<RepositoryCiArchitecture> ParseArchitectures(
        string[]? values,
        RepositoryCiNodeKind kind)
    {
        values ??= [nameof(RepositoryCiArchitecture.Any)];
        if (values.Length is < 1 or > 2)
            throw new InvalidDataException("A repository CI architecture list violates its technical bound.");
        var architectures = new HashSet<RepositoryCiArchitecture>();
        foreach (var value in values)
            if (!ParseEnum(value, out RepositoryCiArchitecture architecture) || !architectures.Add(architecture))
                throw new InvalidDataException("A repository CI architecture is invalid.");
        var expected = kind != RepositoryCiNodeKind.Artifact
            ? [RepositoryCiArchitecture.Any]
            : architectures.ToArray();
        if (!architectures.SetEquals(expected))
            throw new InvalidDataException("A repository CI architecture list does not satisfy the artifact policy.");
        return ReadOnly(architectures.Order().ToArray());
    }

    private static IReadOnlyList<string> ParseStrings(
        string[]? values,
        Func<string?, bool> validate,
        bool required)
    {
        values ??= [];
        if (values.Length > MaximumItemsPerNode || required && values.Length == 0)
            throw new InvalidDataException("A repository CI node list violates its technical bound.");
        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            if (value is not { } text || !validate(text) || !unique.Add(text))
                throw new InvalidDataException("A repository CI node list contains an invalid item.");
        }
        return ReadOnly(unique.Order(StringComparer.Ordinal).ToArray());
    }

    private static List<RepositoryCiNode> OrderAndValidate(IReadOnlyList<RepositoryCiNode> nodes)
    {
        var byId = nodes.ToDictionary(static node => node.Id, StringComparer.Ordinal);
        var dependents = nodes.ToDictionary(static node => node.Id, _ => new List<string>(), StringComparer.Ordinal);
        var remaining = nodes.ToDictionary(static node => node.Id, static node => node.DependsOn.Count, StringComparer.Ordinal);
        foreach (var node in nodes)
        {
            foreach (var dependency in node.DependsOn)
            {
                if (dependency == node.Id || !byId.TryGetValue(dependency, out var dependencyNode))
                    throw new InvalidDataException("Every repository CI node dependency must name another node.");
                if (node.Profiles.Except(dependencyNode.Profiles).Any() ||
                    Rank(dependencyNode.Kind) > Rank(node.Kind))
                    throw new InvalidDataException("A repository CI dependency cannot narrow its consumer profile or run later.");
                dependents[dependency].Add(node.Id);
            }
        }

        var ready = new SortedSet<string>(
            remaining.Where(static item => item.Value == 0).Select(static item => item.Key),
            StringComparer.Ordinal);
        var ordered = new List<RepositoryCiNode>(nodes.Count);
        while (ready.Count > 0)
        {
            if (ready.Min is not { } id)
                throw new InvalidDataException("The repository CI node graph lost a ready node.");
            ready.Remove(id);
            ordered.Add(byId[id]);
            foreach (var dependent in dependents[id].Order(StringComparer.Ordinal))
            {
                if (--remaining[dependent] == 0) ready.Add(dependent);
            }
        }
        if (ordered.Count != nodes.Count)
            throw new InvalidDataException("The repository CI node graph contains a cycle.");
        return ordered;
    }

    private static int Rank(RepositoryCiNodeKind kind) => kind switch
    {
        RepositoryCiNodeKind.Static => 0,
        RepositoryCiNodeKind.Build => 1,
        RepositoryCiNodeKind.Test => 2,
        RepositoryCiNodeKind.Artifact => 3,
        _ => throw new InvalidDataException("The repository CI node kind is invalid."),
    };

    private static string ComputeDigest(
        string repository,
        IReadOnlyList<RepositoryCiDependency> dependencies,
        IReadOnlyList<RepositoryCiNode> nodes)
    {
        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            writer.WriteString("apiVersion", ApiVersion);
            writer.WriteString("repository", repository);
            writer.WriteStartArray("repositoryDependencies");
            foreach (var dependency in dependencies)
            {
                writer.WriteStartObject();
                writer.WriteString("repository", dependency.Repository);
                writer.WriteString("reason", dependency.Reason);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteStartArray("nodes");
            foreach (var node in nodes)
            {
                writer.WriteStartObject();
                writer.WriteString("id", node.Id);
                writer.WriteString("kind", node.Kind.ToString());
                writer.WriteString("resourceWeight", node.ResourceWeight.ToString());
                WriteArray(writer, "profiles", node.Profiles.Select(static value => value.ToString()));
                WriteArray(writer, "architectures", node.Architectures.Select(static value => value.ToString()));
                WriteArray(writer, "paths", node.Paths);
                WriteArray(writer, "dependsOn", node.DependsOn);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return Convert.ToHexStringLower(SHA256.HashData(bytes.WrittenSpan));
    }

    private static void WriteArray(Utf8JsonWriter writer, string name, IEnumerable<string> values)
    {
        writer.WriteStartArray(name);
        foreach (var value in values) writer.WriteStringValue(value);
        writer.WriteEndArray();
    }

    private static void RejectDuplicateProperties(ReadOnlySpan<byte> value)
    {
        var reader = new Utf8JsonReader(value, new JsonReaderOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = MaximumDepth,
        });
        var objects = new Stack<HashSet<string>>();
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.StartObject) objects.Push(new(StringComparer.Ordinal));
            else if (reader.TokenType == JsonTokenType.EndObject)
            {
                if (objects.Count == 0)
                    throw new InvalidDataException("The repository CI descriptor contains an unmatched object end.");
                objects.Pop();
            }
            else if (reader.TokenType == JsonTokenType.PropertyName)
            {
                if (!objects.TryPeek(out var properties) || reader.GetString() is not { } property ||
                    !properties.Add(property))
                    throw new InvalidDataException("The repository CI descriptor contains duplicate fields.");
            }
        }
    }

    private static void RejectUnknown(Dictionary<string, JsonElement>? values)
    {
        if (values is { Count: > 0 })
            throw new InvalidDataException(
                $"The repository CI descriptor contains unknown fields ({string.Join(", ", values.Keys.Order(StringComparer.Ordinal))}); " +
                $"remove them or move to a newer descriptor schema. Supported fields are defined by '{ApiVersion}'.");
    }

    /// <summary>
    /// One bounded, actionable migration error for the retired candidate-era schema. Sibling
    /// repositories still carry v2 descriptors; their CI fails closed with these exact steps.
    /// </summary>
    private static string RetiredSchemaMessage(RepositoryCiDescriptorDocument document)
    {
        var retired = new List<string>();
        if (document.Extra is { } extra)
        {
            foreach (var field in extra.Keys.Order(StringComparer.Ordinal))
                retired.Add(field);
        }
        var profiles = (document.Nodes ?? [])
            .SelectMany(static node => node?.Profiles ?? [])
            .Where(static profile => profile == "Release")
            .ToList();
        if (profiles.Count > 0)
            retired.Add("profiles \"Release\"");
        var present = retired.Count > 0 ? $" (retired content found: {string.Join(", ", retired)})" : "";
        return
            $"The repository CI descriptor uses retired schema '{RetiredApiVersion}'{present}. " +
            $"Migrate the descriptor: delete 'candidateRetentionDays' and 'promotion', rename every 'Release' profile to 'Build', " +
            $"and set apiVersion to '{ApiVersion}'. Descriptor owners migrate their own repository; CI for unmigrated repositories stays closed.";
    }

    private static bool ParseEnum<T>(string? value, out T parsed) where T : struct, Enum =>
        Enum.TryParse(value, ignoreCase: false, out parsed) && Enum.IsDefined(parsed) &&
        Convert.ToInt32(parsed) != 0;

    private static bool IsToken(string? value) => value is { Length: >= 1 and <= 64 } &&
        value[0] is >= 'a' and <= 'z' &&
        value.All(static character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');

    private static bool IsSafePath(string? value)
    {
        if (value is not { Length: >= 1 and <= 256 } || value[0] == '/' || value.Contains('\\') ||
            value.Contains("//", StringComparison.Ordinal) ||
            value.Any(static character => character is not (
                >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '_' or '-' or '/')))
            return false;
        return value.TrimEnd('/').Split('/').All(static segment => segment is not ("" or "." or ".."));
    }

    private static bool IsReason(string? value) => value is { Length: >= 1 and <= 256 } &&
        value == value.Trim() && !value.Any(char.IsControl);

    private static IReadOnlyList<T> ReadOnly<T>(T[] values) => new ReadOnlyCollection<T>(values);
    private static IReadOnlyList<T> ReadOnly<T>(List<T> values) => new ReadOnlyCollection<T>(values.ToArray());
}

internal sealed class RepositoryCiDescriptorDocument
{
    public string? ApiVersion { get; set; }
    public string? Repository { get; set; }
    public RepositoryCiDependencyDocument?[]? RepositoryDependencies { get; set; }
    public RepositoryCiNodeDocument?[]? Nodes { get; set; }
    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; set; }
}

internal sealed class RepositoryCiDependencyDocument
{
    public string? Repository { get; set; }
    public string? Reason { get; set; }
    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; set; }
}

internal sealed class RepositoryCiNodeDocument
{
    public string? Id { get; set; }
    public string? Kind { get; set; }
    public string? ResourceWeight { get; set; }
    public string[]? Profiles { get; set; }
    public string[]? Architectures { get; set; }
    public string[]? Paths { get; set; }
    public string[]? DependsOn { get; set; }
    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; set; }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(RepositoryCiDescriptorDocument))]
internal sealed partial class RepositoryCiDescriptorJsonContext : JsonSerializerContext;
