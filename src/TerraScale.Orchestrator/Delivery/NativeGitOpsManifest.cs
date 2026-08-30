using System.Collections.Frozen;
using System.Buffers;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Delivery;

public enum GitOpsChildOwnership
{
    Unspecified,
    RegionalJournal,
}

public enum GitOpsRemovalPolicy
{
    Unspecified,
    GuardedRetirement,
}

public sealed record NativeGitOpsWorkloadPlan(
    string Id,
    AdmittedRole Role,
    ArtifactDigest ArtifactDigest,
    RuntimeDriver Runtime,
    int Replicas,
    IReadOnlyList<string> Cells,
    IReadOnlyList<string> DependsOn,
    bool Suspended,
    GitOpsChildOwnership ChildOwnership,
    GitOpsRemovalPolicy RemovalPolicy);

public sealed record NativeGitOpsCellPlan(
    string Cell,
    long Generation,
    IReadOnlyList<NativeGitOpsWorkloadPlan> Workloads);

public sealed record NativeGitOpsPlan(
    string ApiVersion,
    string Kind,
    long Generation,
    string Digest,
    IReadOnlyList<NativeGitOpsWorkloadPlan> Workloads,
    IReadOnlyList<NativeGitOpsCellPlan> Cells);

/// <summary>
/// Parses fresh TerraScale desired state into a deterministic closed-role plan for REQ-O014 and INV-017.
/// It does not accept executable paths, image names, host paths, capabilities, unit text, or concrete
/// autoscaled children.
/// </summary>
public static class NativeGitOpsManifest
{
    public const string ApiVersion = "terrascale.io/v1";
    public const string Kind = "TerraScaleDesiredState";
    public const int MaximumBytes = 1024 * 1024;
    public const int MaximumWorkloads = 256;
    public const int MaximumCellsPerWorkload = 64;
    public const int MaximumDependenciesPerWorkload = 64;
    public const int MaximumReplicas = 1024;
    private const int MaximumDepth = 16;

    private static readonly FrozenSet<string> RootProperties =
        new[] { "apiVersion", "kind", "generation", "workloads" }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> WorkloadProperties =
        new[] { "id", "role", "artifactDigest", "runtime", "replicas", "cells", "dependsOn", "suspended" }
            .ToFrozenSet(StringComparer.Ordinal);

    public static NativeGitOpsPlan Parse(ReadOnlyMemory<byte> manifest)
    {
        if (manifest.IsEmpty || manifest.Length > MaximumBytes)
            throw new InvalidDataException("The native GitOps manifest is empty or exceeds its technical bound.");

        try
        {
            RejectDuplicateProperties(manifest.Span);
            using var document = JsonDocument.Parse(manifest, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = MaximumDepth,
            });
            var root = document.RootElement;
            RequireObject(root, "The native GitOps manifest root must be an object.");
            RejectUnknownProperties(root, RootProperties, "manifest");
            RequireExactString(root, "apiVersion", ApiVersion);
            RequireExactString(root, "kind", Kind);
            var generation = RequirePositiveInt64(root, "generation");
            var workloads = ParseWorkloads(root);
            var ordered = OrderAndValidate(workloads);
            var cells = CompileCells(generation, ordered);
            return new(
                ApiVersion,
                Kind,
                generation,
                ComputeDigest(generation, ordered),
                ReadOnly(ordered),
                ReadOnly(cells));
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The native GitOps manifest is invalid JSON.", exception);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            throw new InvalidDataException("The native GitOps manifest violates the closed TerraScale contract.", exception);
        }
    }

    private static List<NativeGitOpsWorkloadPlan> ParseWorkloads(JsonElement root)
    {
        if (!root.TryGetProperty("workloads", out var value) || value.ValueKind != JsonValueKind.Array ||
            value.GetArrayLength() > MaximumWorkloads)
            throw new InvalidDataException("The manifest must contain a bounded workload array.");

        var workloads = new List<NativeGitOpsWorkloadPlan>(value.GetArrayLength());
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in value.EnumerateArray())
        {
            RequireObject(item, "Every native GitOps workload must be an object.");
            RejectUnknownProperties(item, WorkloadProperties, "workload");
            var id = RequireToken(item, "id");
            if (!ids.Add(id)) throw new InvalidDataException("Workload identities must be unique.");
            var role = RequireEnum<AdmittedRole>(item, "role");
            var descriptor = AdmittedRoleCatalog.Get(role);
            // The GitOps lane admits roles by catalog membership and a well-formed digest only.
            var runtime = OptionalEnum(item, "runtime", descriptor.DefaultDriver);
            AdmittedRoleCatalog.Admit(role, runtime);
            var replicas = OptionalInt32(item, "replicas", descriptor.MinimumReplicas);
            if (replicas < descriptor.MinimumReplicas || replicas > MaximumReplicas)
                throw new InvalidDataException("Workload replicas violate the closed role policy.");
            var cells = StringArray(item, "cells", MaximumCellsPerWorkload, required: true);
            var dependencies = StringArray(item, "dependsOn", MaximumDependenciesPerWorkload, required: false);
            var suspended = OptionalBoolean(item, "suspended", false);
            workloads.Add(new(
                id,
                role,
                new ArtifactDigest(RequireString(item, "artifactDigest")),
                runtime,
                replicas,
                ReadOnly(cells.Order(StringComparer.Ordinal).ToArray()),
                ReadOnly(dependencies.Order(StringComparer.Ordinal).ToArray()),
                suspended,
                GitOpsChildOwnership.RegionalJournal,
                GitOpsRemovalPolicy.GuardedRetirement));
        }
        return workloads;
    }

    private static List<NativeGitOpsWorkloadPlan> OrderAndValidate(
        IReadOnlyList<NativeGitOpsWorkloadPlan> workloads)
    {
        var byId = workloads.ToDictionary(workload => workload.Id, StringComparer.Ordinal);
        var dependents = workloads.ToDictionary(
            workload => workload.Id,
            _ => new List<string>(),
            StringComparer.Ordinal);
        var remaining = workloads.ToDictionary(
            workload => workload.Id,
            workload => workload.DependsOn.Count,
            StringComparer.Ordinal);

        foreach (var workload in workloads)
        {
            foreach (var dependencyId in workload.DependsOn)
            {
                if (!byId.TryGetValue(dependencyId, out var dependency) || dependencyId == workload.Id)
                    throw new InvalidDataException("Every workload dependency must identify another declared workload.");
                if (workload.Cells.Except(dependency.Cells, StringComparer.Ordinal).Any())
                    throw new InvalidDataException("A workload dependency must be present in every consuming cell.");
                if (!workload.Suspended && dependency.Suspended)
                    throw new InvalidDataException("An active workload cannot depend on a suspended workload.");
                dependents[dependencyId].Add(workload.Id);
            }
        }

        var ready = new SortedSet<string>(
            remaining.Where(static item => item.Value == 0).Select(static item => item.Key),
            StringComparer.Ordinal);
        var ordered = new List<NativeGitOpsWorkloadPlan>(workloads.Count);
        while (ready.Count > 0)
        {
            if (ready.Min is not { } id)
                throw new InvalidDataException("The native GitOps dependency graph lost its next workload.");
            ready.Remove(id);
            ordered.Add(byId[id]);
            foreach (var dependent in dependents[id].Order(StringComparer.Ordinal))
            {
                remaining[dependent]--;
                if (remaining[dependent] == 0) ready.Add(dependent);
            }
        }
        if (ordered.Count != workloads.Count)
            throw new InvalidDataException("The native GitOps dependency graph contains a cycle.");
        return ordered;
    }

    private static NativeGitOpsCellPlan[] CompileCells(
        long generation,
        IReadOnlyList<NativeGitOpsWorkloadPlan> workloads) => workloads
        .SelectMany(static workload => workload.Cells)
        .Distinct(StringComparer.Ordinal)
        .Order(StringComparer.Ordinal)
        .Select(cell => new NativeGitOpsCellPlan(
            cell,
            generation,
            ReadOnly(workloads.Where(workload => workload.Cells.Contains(cell, StringComparer.Ordinal)).ToArray())))
        .ToArray();

    private static string ComputeDigest(long generation, IReadOnlyList<NativeGitOpsWorkloadPlan> workloads)
    {
        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            writer.WriteString("apiVersion", ApiVersion);
            writer.WriteString("kind", Kind);
            writer.WriteNumber("generation", generation);
            writer.WriteStartArray("workloads");
            foreach (var workload in workloads)
            {
                writer.WriteStartObject();
                writer.WriteString("id", workload.Id);
                writer.WriteString("role", workload.Role.ToString());
                writer.WriteString("artifactDigest", workload.ArtifactDigest.Value);
                writer.WriteString("runtime", workload.Runtime.ToString());
                writer.WriteNumber("replicas", workload.Replicas);
                writer.WriteStartArray("cells");
                foreach (var cell in workload.Cells) writer.WriteStringValue(cell);
                writer.WriteEndArray();
                writer.WriteStartArray("dependsOn");
                foreach (var dependency in workload.DependsOn) writer.WriteStringValue(dependency);
                writer.WriteEndArray();
                writer.WriteBoolean("suspended", workload.Suspended);
                writer.WriteString("childOwnership", workload.ChildOwnership.ToString());
                writer.WriteString("removalPolicy", workload.RemovalPolicy.ToString());
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return Convert.ToHexStringLower(SHA256.HashData(bytes.WrittenSpan));
    }

    private static void RejectDuplicateProperties(ReadOnlySpan<byte> manifest)
    {
        var reader = new Utf8JsonReader(manifest, new JsonReaderOptions
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
            else if (reader.TokenType == JsonTokenType.PropertyName)
            {
                if (objects.Count == 0 || reader.GetString() is not { } propertyName ||
                    !objects.Peek().Add(propertyName))
                    throw new InvalidDataException("The native GitOps manifest contains duplicate or malformed fields.");
            }
        }
    }

    private static void RejectUnknownProperties(JsonElement value, IReadOnlySet<string> allowed, string context)
    {
        foreach (var property in value.EnumerateObject())
        {
            if (!allowed.Contains(property.Name))
                throw new InvalidDataException($"The native GitOps {context} contains an unknown field.");
        }
    }

    private static void RequireObject(JsonElement value, string message)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException(message);
    }

    private static void RequireExactString(JsonElement owner, string name, string expected)
    {
        if (RequireString(owner, name) != expected)
            throw new InvalidDataException($"The native GitOps {name} is unsupported.");
    }

    private static string RequireString(JsonElement owner, string name)
    {
        if (!owner.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String ||
            property.GetString() is not { Length: > 0 } value)
            throw new InvalidDataException($"The native GitOps {name} must be a non-empty string.");
        return value;
    }

    private static string RequireToken(JsonElement owner, string name)
    {
        var value = RequireString(owner, name);
        _ = new RuntimeAllocationId(value);
        return value;
    }

    private static long RequirePositiveInt64(JsonElement owner, string name)
    {
        if (!owner.TryGetProperty(name, out var property) || !property.TryGetInt64(out var value) || value <= 0)
            throw new InvalidDataException($"The native GitOps {name} must be a positive integer.");
        return value;
    }

    private static int OptionalInt32(JsonElement owner, string name, int defaultValue)
    {
        if (!owner.TryGetProperty(name, out var property)) return defaultValue;
        if (!property.TryGetInt32(out var value))
            throw new InvalidDataException($"The native GitOps {name} must be an integer.");
        return value;
    }

    private static bool OptionalBoolean(JsonElement owner, string name, bool defaultValue)
    {
        if (!owner.TryGetProperty(name, out var property)) return defaultValue;
        if (property.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw new InvalidDataException($"The native GitOps {name} must be a boolean.");
        return property.GetBoolean();
    }

    private static T RequireEnum<T>(JsonElement owner, string name) where T : struct, Enum
    {
        var value = RequireString(owner, name);
        if (!Enum.TryParse<T>(value, ignoreCase: false, out var parsed) || !Enum.IsDefined(parsed))
            throw new InvalidDataException($"The native GitOps {name} is not admitted.");
        return parsed;
    }

    private static T OptionalEnum<T>(JsonElement owner, string name, T defaultValue) where T : struct, Enum =>
        owner.TryGetProperty(name, out _) ? RequireEnum<T>(owner, name) : defaultValue;

    private static string[] StringArray(JsonElement owner, string name, int maximum, bool required)
    {
        if (!owner.TryGetProperty(name, out var property))
        {
            if (required) throw new InvalidDataException($"The native GitOps {name} array is required.");
            return [];
        }
        if (property.ValueKind != JsonValueKind.Array || property.GetArrayLength() > maximum ||
            required && property.GetArrayLength() == 0)
            throw new InvalidDataException($"The native GitOps {name} array violates its technical bound.");
        var values = new List<string>(property.GetArrayLength());
        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in property.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || item.GetString() is not { } value)
                throw new InvalidDataException($"Every native GitOps {name} item must be a string.");
            _ = new RuntimeAllocationId(value);
            if (!unique.Add(value)) throw new InvalidDataException($"Native GitOps {name} items must be unique.");
            values.Add(value);
        }
        return values.ToArray();
    }

    private static IReadOnlyList<T> ReadOnly<T>(T[] values) =>
        new ReadOnlyCollection<T>(values);

    private static IReadOnlyList<T> ReadOnly<T>(List<T> values) =>
        new ReadOnlyCollection<T>(values.ToArray());
}
