using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Delivery;

internal sealed record NativeGitOpsParsedCellChange(
    NativeGitOpsChangeKind Kind,
    string WorkloadId,
    string? AcceptedWorkloadSha256,
    string? ProposedWorkloadSha256,
    NativeGitOpsWorkloadPlan? RetiredWorkload);

internal sealed record NativeGitOpsParsedCellSpec(
    long? AcceptedGeneration,
    string? AcceptedGlobalPlanDigest,
    long Generation,
    string GlobalPlanDigest,
    string Cell,
    string PayloadSha256,
    IReadOnlyList<NativeGitOpsWorkloadPlan> DesiredWorkloads,
    IReadOnlyList<NativeGitOpsParsedCellChange> Changes);

/// <summary>Rehydrates one immutable, signed CellSpec without trusting lossy runtime labels.</summary>
internal static class NativeGitOpsCellPayload
{
    private static readonly HashSet<string> RootProperties =
    [
        "schemaVersion", "repository", "commit", "tree", "filePath", "blob", "contentSha256",
        "acceptedGeneration", "acceptedGlobalPlanDigest", "generation", "globalPlanDigest", "cell",
        "desiredWorkloads", "changes",
    ];
    private static readonly HashSet<string> WorkloadProperties =
    [
        "id", "role", "artifactDigest", "runtime", "replicas", "cells", "dependsOn", "suspended",
        "childOwnership", "removalPolicy",
    ];
    private static readonly HashSet<string> ChangeProperties =
    [
        "kind", "workloadId", "childOwnership", "removalPolicy", "acceptedWorkloadSha256",
        "proposedWorkloadSha256",
    ];

    internal static NativeGitOpsParsedCellSpec Parse(NativeGitOpsAcceptedCellSpec accepted)
    {
        ArgumentNullException.ThrowIfNull(accepted);
        if (accepted.Payload.Length is < 1 or > NativeGitOpsCellSpecCompiler.MaximumCellSpecBytes ||
            Convert.ToHexStringLower(SHA256.HashData(accepted.Payload.Span)) != accepted.PayloadSha256)
            throw Invalid();
        try
        {
            RejectDuplicateProperties(accepted.Payload.Span);
            using var parsed = JsonDocument.Parse(accepted.Payload, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16,
            });
            ValidateShape(parsed.RootElement);
            var document = JsonSerializer.Deserialize(
                accepted.Payload.Span,
                NativeGitOpsCellPayloadJsonContext.Default.NativeGitOpsCellPayloadDocument) ?? throw Invalid();
            return Compile(document, accepted);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The accepted native GitOps CellSpec payload is invalid.", exception);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            throw new InvalidDataException("The accepted native GitOps CellSpec violates its closed contract.", exception);
        }
    }

    private static NativeGitOpsParsedCellSpec Compile(
        NativeGitOpsCellPayloadDocument document,
        NativeGitOpsAcceptedCellSpec accepted)
    {
        if (document.SchemaVersion != 1 || !ForgejoWebhookVerifier.IsRepository(document.Repository) ||
            !GitObject(document.Commit) || !GitObject(document.Tree) || !GitObject(document.Blob) ||
            document.FilePath != NativeGitOpsSourceLoader.ManifestPath || !Digest(document.ContentSha256) ||
            document.Generation != accepted.Generation || document.GlobalPlanDigest != accepted.GlobalPlanDigest ||
            document.Cell != accepted.Cell || document.DesiredWorkloads is null || document.Changes is null ||
            document.DesiredWorkloads.Length > NativeGitOpsManifest.MaximumWorkloads ||
            document.Changes.Length > NativeGitOpsManifest.MaximumWorkloads)
            throw Invalid();
        if ((document.AcceptedGeneration is null) != (document.AcceptedGlobalPlanDigest is null) ||
            document.AcceptedGeneration is <= 0 ||
            document.AcceptedGeneration > document.Generation ||
            document.AcceptedGlobalPlanDigest is not null && !Digest(document.AcceptedGlobalPlanDigest) ||
            document.AcceptedGeneration == document.Generation &&
            document.AcceptedGlobalPlanDigest != document.GlobalPlanDigest)
            throw Invalid();

        var desired = document.DesiredWorkloads.Select(Workload).ToArray();
        var desiredById = new Dictionary<string, NativeGitOpsWorkloadPlan>(StringComparer.Ordinal);
        foreach (var workload in desired)
        {
            if (!workload.Cells.Contains(document.Cell, StringComparer.Ordinal) ||
                !desiredById.TryAdd(workload.Id, workload) ||
                workload.DependsOn.Any(dependency => !desiredById.ContainsKey(dependency)))
                throw Invalid();
        }

        var changes = new List<NativeGitOpsParsedCellChange>(document.Changes.Length);
        var changed = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in document.Changes)
        {
            if (!changed.Add(value.WorkloadId) ||
                !Exact(value.ChildOwnership, GitOpsChildOwnership.RegionalJournal) ||
                !Exact(value.RemovalPolicy, GitOpsRemovalPolicy.GuardedRetirement) ||
                !Exact(value.Kind, out NativeGitOpsChangeKind kind) || kind == NativeGitOpsChangeKind.Unspecified)
                throw Invalid();
            var acceptedDigest = OptionalDigest(value.AcceptedWorkloadSha256);
            var proposedDigest = OptionalDigest(value.ProposedWorkloadSha256);
            var proposedMatches = desiredById.TryGetValue(value.WorkloadId, out var proposed) &&
                proposedDigest == NativeGitOpsCellSpecCompiler.WorkloadDigest(proposed);
            NativeGitOpsWorkloadPlan? retired = value.RetiredWorkload is null
                ? null
                : Workload(value.RetiredWorkload);
            var valid = kind switch
            {
                NativeGitOpsChangeKind.Create => acceptedDigest is null && retired is null && proposedMatches,
                NativeGitOpsChangeKind.Update or NativeGitOpsChangeKind.Suspend or NativeGitOpsChangeKind.Resume =>
                    acceptedDigest is not null && retired is null && proposedMatches,
                NativeGitOpsChangeKind.GuardedRetirement =>
                    acceptedDigest is not null && proposedDigest is null && proposed is null &&
                    retired is not null && retired.Id == value.WorkloadId &&
                    retired.Cells.Contains(document.Cell, StringComparer.Ordinal) &&
                    acceptedDigest == NativeGitOpsCellSpecCompiler.WorkloadDigest(retired),
                _ => false,
            };
            if (!valid || document.AcceptedGeneration is null && kind != NativeGitOpsChangeKind.Create)
                throw Invalid();
            changes.Add(new(kind, value.WorkloadId, acceptedDigest, proposedDigest, retired));
        }
        if (document.AcceptedGeneration == document.Generation && changes.Count != 0)
            throw Invalid();
        return new(
            document.AcceptedGeneration,
            document.AcceptedGlobalPlanDigest,
            document.Generation,
            document.GlobalPlanDigest,
            document.Cell,
            accepted.PayloadSha256,
            ReadOnly(desired),
            new ReadOnlyCollection<NativeGitOpsParsedCellChange>(changes));
    }

    private static NativeGitOpsWorkloadPlan Workload(NativeGitOpsCellWorkloadDocument value)
    {
        if (!Token(value.Id) || !Exact(value.Role, out AdmittedRole role) ||
            !Exact(value.Runtime, out RuntimeDriver runtime) ||
            !Exact(value.ChildOwnership, GitOpsChildOwnership.RegionalJournal) ||
            !Exact(value.RemovalPolicy, GitOpsRemovalPolicy.GuardedRetirement) ||
            value.Cells is null || value.DependsOn is null ||
            !Tokens(value.Cells, NativeGitOpsManifest.MaximumCellsPerWorkload) ||
            !Tokens(value.DependsOn, NativeGitOpsManifest.MaximumDependenciesPerWorkload))
            throw Invalid();
        var descriptor = AdmittedRoleCatalog.Admit(role, runtime);
        if (value.Replicas < descriptor.MinimumReplicas || value.Replicas > NativeGitOpsManifest.MaximumReplicas)
            throw Invalid();
        return new(
            value.Id,
            role,
            new ArtifactDigest(value.ArtifactDigest),
            runtime,
            value.Replicas,
            ReadOnly(value.Cells.ToArray()),
            ReadOnly(value.DependsOn.ToArray()),
            value.Suspended,
            GitOpsChildOwnership.RegionalJournal,
            GitOpsRemovalPolicy.GuardedRetirement);
    }

    private static void ValidateShape(JsonElement root)
    {
        ExactProperties(root, RootProperties);
        var workloads = root.GetProperty("desiredWorkloads");
        var changes = root.GetProperty("changes");
        if (workloads.ValueKind != JsonValueKind.Array || changes.ValueKind != JsonValueKind.Array)
            throw Invalid();
        foreach (var workload in workloads.EnumerateArray()) ExactProperties(workload, WorkloadProperties);
        foreach (var change in changes.EnumerateArray())
        {
            var expected = new HashSet<string>(ChangeProperties, StringComparer.Ordinal);
            if (change.TryGetProperty("retiredWorkload", out var retired))
            {
                expected.Add("retiredWorkload");
                ExactProperties(retired, WorkloadProperties);
            }
            ExactProperties(change, expected);
        }
    }

    private static void ExactProperties(JsonElement value, IReadOnlySet<string> expected)
    {
        if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Count() != expected.Count ||
            value.EnumerateObject().Any(property => !expected.Contains(property.Name)))
            throw Invalid();
    }

    private static void RejectDuplicateProperties(ReadOnlySpan<byte> payload)
    {
        var reader = new Utf8JsonReader(payload, new JsonReaderOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 16,
        });
        var objects = new Stack<HashSet<string>>();
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.StartObject) objects.Push(new(StringComparer.Ordinal));
            else if (reader.TokenType == JsonTokenType.EndObject) objects.Pop();
            else if (reader.TokenType == JsonTokenType.PropertyName && !objects.Peek().Add(reader.GetString()!))
                throw Invalid();
        }
    }

    private static bool Tokens(string[] values, int maximum) => values.Length <= maximum &&
        values.SequenceEqual(values.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)) &&
        values.All(Token);

    private static bool Token(string value)
    {
        try { _ = new RuntimeAllocationId(value); return true; }
        catch (Exception exception) when (exception is ArgumentException or ArgumentNullException) { return false; }
    }

    private static bool Exact<T>(string value, T expected) where T : struct, Enum =>
        Exact(value, out T actual) && EqualityComparer<T>.Default.Equals(actual, expected);

    private static bool Exact<T>(string value, out T parsed) where T : struct, Enum =>
        Enum.TryParse(value, ignoreCase: false, out parsed) && Enum.IsDefined(parsed) && parsed.ToString() == value;

    private static string? OptionalDigest(string? value)
    {
        if (value is null || Digest(value)) return value;
        throw Invalid();
    }

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool GitObject(string? value) => value is { Length: 40 or 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static InvalidDataException Invalid() =>
        new("The accepted native GitOps CellSpec payload is invalid.");

    private static IReadOnlyList<T> ReadOnly<T>(T[] values) => new ReadOnlyCollection<T>(values);
}

internal sealed record NativeGitOpsCellPayloadDocument(
    int SchemaVersion,
    string Repository,
    string Commit,
    string Tree,
    string FilePath,
    string Blob,
    string ContentSha256,
    long? AcceptedGeneration,
    string? AcceptedGlobalPlanDigest,
    long Generation,
    string GlobalPlanDigest,
    string Cell,
    NativeGitOpsCellWorkloadDocument[] DesiredWorkloads,
    NativeGitOpsCellChangeDocument[] Changes);

internal sealed record NativeGitOpsCellWorkloadDocument(
    string Id,
    string Role,
    string ArtifactDigest,
    string Runtime,
    int Replicas,
    string[] Cells,
    string[] DependsOn,
    bool Suspended,
    string ChildOwnership,
    string RemovalPolicy);

internal sealed record NativeGitOpsCellChangeDocument(
    string Kind,
    string WorkloadId,
    string ChildOwnership,
    string RemovalPolicy,
    string? AcceptedWorkloadSha256,
    string? ProposedWorkloadSha256,
    NativeGitOpsCellWorkloadDocument? RetiredWorkload);

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(NativeGitOpsCellPayloadDocument))]
internal sealed partial class NativeGitOpsCellPayloadJsonContext : JsonSerializerContext;
