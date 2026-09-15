using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Protocol;

/// <summary>Whether one subject family lives under the global scope or under one Region scope.</summary>
public enum ProtocolSubjectFamilyScope
{
    Unspecified = 0,
    Global,
    Regional,
}

/// <summary>
/// One closed subject family of the checked-in protocol manifest. The pattern is the
/// manifest-facing template: regional families carry the <c>&lt;region&gt;</c> placeholder and the
/// agent family additionally carries the <c>&lt;agent-hash&gt;</c> placeholder.
/// </summary>
public sealed record ProtocolSubjectFamily(
    ProtocolSubjectFamilyScope Scope,
    string Family,
    string Pattern,
    bool AgentHashToken)
{
    internal bool IsWellFormed =>
        Scope is ProtocolSubjectFamilyScope.Global or ProtocolSubjectFamilyScope.Regional &&
        Family is { Length: >= 1 and <= 32 } &&
        Family.All(static character => character is >= 'a' and <= 'z' or '-') &&
        Pattern is { Length: >= 1 and <= 128 } &&
        !Pattern.Any(char.IsWhiteSpace) &&
        (!AgentHashToken || Scope == ProtocolSubjectFamilyScope.Regional);
}

/// <summary>
/// The standing permission grants of one account kind, as declared by the protocol manifest.
/// Templates substitute <c>&lt;region&gt;</c> and <c>&lt;agent-hash&gt;</c> when a scope is
/// instantiated. <see cref="BreakGlass"/> kinds hold no standing grants at all.
/// </summary>
public sealed record ProtocolAccountKindGrants(
    string Kind,
    bool RegionScoped,
    bool AgentHashScoped,
    bool PlatformOnly,
    bool ReadOnly,
    bool BreakGlass,
    IReadOnlyList<string> Publish,
    IReadOnlyList<string> Subscribe)
{
    internal bool IsWellFormed =>
        Kind is { Length: >= 1 and <= 64 } &&
        Kind.All(static character => character is >= 'a' and <= 'z' or '-') &&
        Publish is { Count: <= 64 } &&
        Subscribe is { Count: <= 64 } &&
        Publish.All(IsBoundedPattern) &&
        Subscribe.All(IsBoundedPattern) &&
        (!BreakGlass || (Publish.Count == 0 && Subscribe.Count == 0)) &&
        (!ReadOnly || Publish.Count == 0) &&
        (!AgentHashScoped || RegionScoped);

    private static bool IsBoundedPattern(string? pattern) =>
        pattern is { Length: >= 1 and <= 256 } && !pattern.Any(char.IsWhiteSpace);
}

/// <summary>
/// The checked-in protocol manifest: the single source of truth for the closed subject-family
/// set and the account-kind grant templates. The manifest is embedded into the assembly and
/// loaded fail-closed: a missing, oversized, malformed, or shape-invalid manifest is an
/// <see cref="InvalidOperationException"/>, never a silent fallback to compiled defaults.
/// </summary>
public sealed class ProtocolManifest
{
    /// <summary>The manifest resource embedded into the production assembly.</summary>
    public const string ManifestResourceName = "TerraScale.Orchestrator.Protocol.protocol-manifest.json";

    private const int MaximumManifestBytes = 1024 * 1024;
    private const int MaximumSubjectFamilies = 64;
    private const int MaximumAccountKinds = 32;

    private static readonly Lazy<ProtocolManifest> Embedded = new(LoadEmbedded);

    private ProtocolManifest(
        string name,
        string version,
        string root,
        IReadOnlyList<string> reservedRegionTokens,
        IReadOnlyList<ProtocolSubjectFamily> subjectFamilies,
        IReadOnlyList<ProtocolAccountKindGrants> accountKinds)
    {
        Name = name;
        Version = version;
        Root = root;
        ReservedRegionTokens = reservedRegionTokens;
        SubjectFamilies = subjectFamilies;
        AccountKinds = accountKinds;
    }

    /// <summary>The loaded embedded manifest. Loading validates the manifest shape once.</summary>
    public static ProtocolManifest Loaded => Embedded.Value;

    public string Name { get; }

    public string Version { get; }

    public string Root { get; }

    /// <summary>Region tokens that are reserved for scope names and can never name a Region.</summary>
    public IReadOnlyList<string> ReservedRegionTokens { get; }

    public IReadOnlyList<ProtocolSubjectFamily> SubjectFamilies { get; }

    public IReadOnlyList<ProtocolAccountKindGrants> AccountKinds { get; }

    private static ProtocolManifest LoadEmbedded()
    {
        var assembly = typeof(ProtocolManifest).Assembly;
        using var stream = assembly.GetManifestResourceStream(ManifestResourceName) ??
            throw new InvalidOperationException(
                $"The protocol manifest resource '{ManifestResourceName}' is missing from the assembly.");
        if (stream.Length > MaximumManifestBytes)
        {
            throw new InvalidOperationException("The protocol manifest exceeds the bounded manifest size.");
        }

        using var buffer = new MemoryStream((int)stream.Length);
        stream.CopyTo(buffer);
        ProtocolManifestDto? dto;
        try
        {
            dto = JsonSerializer.Deserialize(buffer.ToArray(), ProtocolManifestJsonContext.Default.ProtocolManifestDto);
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException("The protocol manifest is not valid JSON.", exception);
        }

        return FromDto(dto);
    }

    private static ProtocolManifest FromDto(ProtocolManifestDto? dto)
    {
        if (dto is null)
        {
            throw new InvalidOperationException("The protocol manifest is empty.");
        }

        if (string.IsNullOrWhiteSpace(dto.Name) || dto.Name.Length > 128 ||
            string.IsNullOrWhiteSpace(dto.Version) || dto.Version.Length > 32 ||
            string.IsNullOrWhiteSpace(dto.Root) || dto.Root.Length > 128 ||
            dto.Root.Any(char.IsWhiteSpace))
        {
            throw new InvalidOperationException("The protocol manifest header is malformed.");
        }

        var reserved = (IReadOnlyList<string>)(dto.RegionToken?.ReservedTokens ?? [])
            .Where(static token => !string.IsNullOrWhiteSpace(token) && token.Length <= 63)
            .ToArray();
        if (reserved.Count == 0 || reserved.Distinct(StringComparer.Ordinal).Count() != reserved.Count)
        {
            throw new InvalidOperationException("The protocol manifest region-token reservations are malformed.");
        }

        if (dto.SubjectFamilies is not { Count: >= 1 and <= MaximumSubjectFamilies } ||
            dto.AccountKinds is not { Count: >= 1 and <= MaximumAccountKinds })
        {
            throw new InvalidOperationException("The protocol manifest family or account tables are out of bounds.");
        }

        var families = new ProtocolSubjectFamily[dto.SubjectFamilies.Count];
        var familyKeys = new HashSet<(ProtocolSubjectFamilyScope, string)>();
        var familyPatterns = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < dto.SubjectFamilies.Count; index++)
        {
            var entry = dto.SubjectFamilies[index];
            var scope = entry.Scope switch
            {
                "global" => ProtocolSubjectFamilyScope.Global,
                "regional" => ProtocolSubjectFamilyScope.Regional,
                _ => ProtocolSubjectFamilyScope.Unspecified,
            };
            var family = new ProtocolSubjectFamily(scope, entry.Family ?? "", entry.Pattern ?? "", entry.AgentHashToken);
            if (!family.IsWellFormed ||
                !familyKeys.Add((family.Scope, family.Family)) ||
                !familyPatterns.Add(family.Pattern))
            {
                throw new InvalidOperationException(
                    $"The protocol manifest subject family '{family.Family}' is malformed or duplicated.");
            }

            families[index] = family;
        }

        var kinds = new ProtocolAccountKindGrants[dto.AccountKinds.Count];
        var kindNames = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < dto.AccountKinds.Count; index++)
        {
            var entry = dto.AccountKinds[index];
            var grants = new ProtocolAccountKindGrants(
                entry.Kind ?? "",
                entry.RegionScoped,
                entry.AgentHashScoped,
                entry.PlatformOnly,
                entry.ReadOnly,
                entry.BreakGlass,
                entry.Publish ?? [],
                entry.Subscribe ?? []);
            if (!grants.IsWellFormed || !kindNames.Add(grants.Kind))
            {
                throw new InvalidOperationException(
                    $"The protocol manifest account kind '{grants.Kind}' is malformed or duplicated.");
            }

            kinds[index] = grants;
        }

        return new ProtocolManifest(
            dto.Name!,
            dto.Version!,
            dto.Root!,
            reserved,
            families,
            kinds);
    }
}

[JsonSerializable(typeof(ProtocolManifestDto))]
[JsonSerializable(typeof(ProtocolSubjectFamilyDto))]
[JsonSerializable(typeof(ProtocolAccountKindDto))]
[JsonSerializable(typeof(ProtocolRegionTokenDto))]
internal sealed partial class ProtocolManifestJsonContext : JsonSerializerContext;

internal sealed class ProtocolManifestDto
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("version")]
    public string? Version { get; set; }

    [JsonPropertyName("root")]
    public string? Root { get; set; }

    [JsonPropertyName("regionToken")]
    public ProtocolRegionTokenDto? RegionToken { get; set; }

    [JsonPropertyName("subjectFamilies")]
    public List<ProtocolSubjectFamilyDto>? SubjectFamilies { get; set; }

    [JsonPropertyName("accountKinds")]
    public List<ProtocolAccountKindDto>? AccountKinds { get; set; }
}

internal sealed class ProtocolRegionTokenDto
{
    [JsonPropertyName("reservedTokens")]
    public List<string>? ReservedTokens { get; set; }
}

internal sealed class ProtocolSubjectFamilyDto
{
    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    [JsonPropertyName("family")]
    public string? Family { get; set; }

    [JsonPropertyName("pattern")]
    public string? Pattern { get; set; }

    [JsonPropertyName("agentHashToken")]
    public bool AgentHashToken { get; set; }
}

internal sealed class ProtocolAccountKindDto
{
    [JsonPropertyName("kind")]
    public string? Kind { get; set; }

    [JsonPropertyName("regionScoped")]
    public bool RegionScoped { get; set; }

    [JsonPropertyName("agentHashScoped")]
    public bool AgentHashScoped { get; set; }

    [JsonPropertyName("platformOnly")]
    public bool PlatformOnly { get; set; }

    [JsonPropertyName("readOnly")]
    public bool ReadOnly { get; set; }

    [JsonPropertyName("breakGlass")]
    public bool BreakGlass { get; set; }

    [JsonPropertyName("publish")]
    public List<string>? Publish { get; set; }

    [JsonPropertyName("subscribe")]
    public List<string>? Subscribe { get; set; }
}

