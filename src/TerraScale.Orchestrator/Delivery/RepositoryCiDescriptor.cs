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
    Release,
}

public enum RepositoryCiResourceWeight
{
    Unspecified,
    Light,
    Medium,
    Heavy,
}

public enum RepositoryCiPromotionStrategy
{
    Unspecified,
    None,
    Package,
    Pages,
    NativeRolling,
    NativeBlueGreen,
    NativeOrdered,
}

public sealed record RepositoryCiDependency(string Repository, string Reason);

public sealed record RepositoryCiNode(
    string Id,
    RepositoryCiNodeKind Kind,
    RepositoryCiResourceWeight ResourceWeight,
    IReadOnlyList<RepositoryCiProfile> Profiles,
    IReadOnlyList<string> Paths,
    IReadOnlyList<string> DependsOn);

public sealed record RepositoryCiDescriptorV2(
    string ApiVersion,
    string Repository,
    string Digest,
    int CandidateRetentionDays,
    RepositoryCiPromotionStrategy Promotion,
    IReadOnlyList<RepositoryCiDependency> RepositoryDependencies,
    IReadOnlyList<RepositoryCiNode> Nodes);

/// <summary>Compiles the command-free repository CI policy used by the native affected graph.</summary>
public static class RepositoryCiDescriptor
{
    public const string ApiVersion = "terrascale.ci/v2";
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
            RejectUnknown(document.Extra);
            if (document.ApiVersion != ApiVersion || !ForgejoWebhookVerifier.IsRepository(document.Repository))
                throw new InvalidDataException("The repository CI descriptor identity is invalid or unsupported.");
            if (document.CandidateRetentionDays is < 1 or > 30 ||
                !ParseEnum(document.Promotion, out RepositoryCiPromotionStrategy promotion))
                throw new InvalidDataException("The repository CI candidate policy is invalid.");

            var dependencies = ParseRepositoryDependencies(document);
            var nodes = OrderAndValidate(ParseNodes(document));
            return new(
                ApiVersion,
                document.Repository!,
                ComputeDigest(document.Repository!, document.CandidateRetentionDays, promotion, dependencies, nodes),
                document.CandidateRetentionDays,
                promotion,
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
            if (!ForgejoWebhookVerifier.IsRepository(value.Repository) ||
                value.Repository == document.Repository || !unique.Add(value.Repository!) ||
                !IsReason(value.Reason))
                throw new InvalidDataException("A repository CI dependency is invalid.");
            dependencies.Add(new(value.Repository!, value.Reason!));
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
            if (!IsToken(value.Id) || !ids.Add(value.Id!) ||
                !ParseEnum(value.Kind, out RepositoryCiNodeKind kind) ||
                !ParseEnum(value.ResourceWeight, out RepositoryCiResourceWeight weight))
                throw new InvalidDataException("A repository CI node identity or policy is invalid.");
            var profiles = ParseProfiles(value.Profiles, kind);
            var paths = ParseStrings(value.Paths, IsSafePath, required: false);
            var dependencies = ParseStrings(value.DependsOn, IsToken, required: false);
            if (paths.Count == 0 && dependencies.Count == 0)
                throw new InvalidDataException("Every repository CI node must have a direct path or dependency.");
            nodes.Add(new(value.Id!, kind, weight, profiles, paths, dependencies));
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
            if (!validate(value) || !unique.Add(value!))
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
                if (dependency == node.Id || !byId.ContainsKey(dependency))
                    throw new InvalidDataException("Every repository CI node dependency must name another node.");
                dependents[dependency].Add(node.Id);
            }
        }

        var ready = new SortedSet<string>(
            remaining.Where(static item => item.Value == 0).Select(static item => item.Key),
            StringComparer.Ordinal);
        var ordered = new List<RepositoryCiNode>(nodes.Count);
        while (ready.Count > 0)
        {
            var id = ready.Min!;
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

    private static string ComputeDigest(
        string repository,
        int retentionDays,
        RepositoryCiPromotionStrategy promotion,
        IReadOnlyList<RepositoryCiDependency> dependencies,
        IReadOnlyList<RepositoryCiNode> nodes)
    {
        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            writer.WriteString("apiVersion", ApiVersion);
            writer.WriteString("repository", repository);
            writer.WriteNumber("candidateRetentionDays", retentionDays);
            writer.WriteString("promotion", promotion.ToString());
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
            else if (reader.TokenType == JsonTokenType.EndObject) objects.Pop();
            else if (reader.TokenType == JsonTokenType.PropertyName && !objects.Peek().Add(reader.GetString()!))
                throw new InvalidDataException("The repository CI descriptor contains duplicate fields.");
        }
    }

    private static void RejectUnknown(Dictionary<string, JsonElement>? values)
    {
        if (values is { Count: > 0 })
            throw new InvalidDataException("The repository CI descriptor contains an unknown field.");
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
    public int CandidateRetentionDays { get; set; }
    public string? Promotion { get; set; }
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
    public string[]? Paths { get; set; }
    public string[]? DependsOn { get; set; }
    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; set; }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(RepositoryCiDescriptorDocument))]
internal sealed partial class RepositoryCiDescriptorJsonContext : JsonSerializerContext;
