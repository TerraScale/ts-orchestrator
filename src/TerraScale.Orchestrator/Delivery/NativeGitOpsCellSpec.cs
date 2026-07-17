using System.Buffers;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text.Json;

namespace TerraScale.Orchestrator.Delivery;

public sealed record NativeGitOpsCellChange(
    NativeGitOpsChangeKind Kind,
    string WorkloadId,
    NativeGitOpsWorkloadPlan? Accepted,
    NativeGitOpsWorkloadPlan? Proposed,
    GitOpsChildOwnership ChildOwnership,
    GitOpsRemovalPolicy RemovalPolicy);

public sealed class NativeGitOpsCellSpec
{
    internal NativeGitOpsCellSpec(
        string cell,
        long generation,
        string globalPlanDigest,
        string payloadSha256,
        ReadOnlyMemory<byte> payload,
        IReadOnlyList<NativeGitOpsWorkloadPlan> desiredWorkloads,
        IReadOnlyList<NativeGitOpsCellChange> changes)
    {
        Cell = cell;
        Generation = generation;
        GlobalPlanDigest = globalPlanDigest;
        PayloadSha256 = payloadSha256;
        Payload = payload;
        DesiredWorkloads = desiredWorkloads;
        Changes = changes;
    }

    public string Cell { get; }
    public long Generation { get; }
    public string GlobalPlanDigest { get; }
    public string PayloadSha256 { get; }
    public ReadOnlyMemory<byte> Payload { get; }
    public IReadOnlyList<NativeGitOpsWorkloadPlan> DesiredWorkloads { get; }
    public IReadOnlyList<NativeGitOpsCellChange> Changes { get; }
}

public sealed class NativeGitOpsCellHandoff
{
    internal NativeGitOpsCellHandoff(
        long generation,
        string globalPlanDigest,
        string handoffDigest,
        IReadOnlyList<string> requiredCells,
        IReadOnlyList<NativeGitOpsCellSpec> cells)
    {
        Generation = generation;
        GlobalPlanDigest = globalPlanDigest;
        HandoffDigest = handoffDigest;
        RequiredCells = requiredCells;
        Cells = cells;
    }

    public long Generation { get; }
    public string GlobalPlanDigest { get; }
    public string HandoffDigest { get; }
    public IReadOnlyList<string> RequiredCells { get; }
    public IReadOnlyList<NativeGitOpsCellSpec> Cells { get; }
}

/// <summary>
/// Compiles a verified global source plan into bounded deterministic per-cell payloads. Payload
/// digests are ready for a later KMS-backed signer; this compiler grants no unsigned apply authority.
/// </summary>
public static class NativeGitOpsCellSpecCompiler
{
    public const int MaximumCellSpecBytes = 1024 * 1024;
    public const int MaximumCellsPerHandoff = 64;

    public static NativeGitOpsCellHandoff Compile(NativeGitOpsSourcePlan source)
    {
        ArgumentNullException.ThrowIfNull(source);
        Validate(source);
        var cells = source.Proposed.Cells.Select(static value => value.Cell)
            .Concat(source.Diff.Changes.SelectMany(ChangeCells))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (cells.Length > MaximumCellsPerHandoff)
            throw new InvalidDataException("A native GitOps handoff exceeded its regional fan-out bound.");
        var specs = cells.Select(cell => CompileCell(source, cell)).ToArray();
        return new(
            source.Proposed.Generation,
            source.Proposed.Digest,
            ComputeHandoffDigest(source.Proposed.Generation, source.Proposed.Digest, specs),
            ReadOnly(cells),
            ReadOnly(specs));
    }

    private static NativeGitOpsCellSpec CompileCell(NativeGitOpsSourcePlan source, string cell)
    {
        var desired = source.Proposed.Workloads
            .Where(workload => workload.Cells.Contains(cell, StringComparer.Ordinal))
            .ToArray();
        var actions = source.Diff.Changes
            .Select(change => CellChange(change, cell))
            .Where(static change => change is not null)
            .Cast<NativeGitOpsCellChange>()
            .ToArray();
        var active = actions.Where(static change => change.Kind is not (
                NativeGitOpsChangeKind.Suspend or NativeGitOpsChangeKind.GuardedRetirement))
            .OrderBy(change => ProposedIndex(source.Proposed, change.WorkloadId))
            .ThenBy(static change => change.WorkloadId, StringComparer.Ordinal);
        var stopping = OrderStopping(actions.Where(static change => change.Kind is
            NativeGitOpsChangeKind.Suspend or NativeGitOpsChangeKind.GuardedRetirement));
        var ordered = active.Concat(stopping).ToArray();
        var payload = Payload(source, cell, desired, ordered);
        return new(
            cell,
            source.Proposed.Generation,
            source.Proposed.Digest,
            Convert.ToHexStringLower(SHA256.HashData(payload)),
            payload,
            ReadOnly(desired),
            ReadOnly(ordered));
    }

    private static NativeGitOpsCellChange? CellChange(NativeGitOpsChange change, string cell)
    {
        var accepted = change.Accepted?.Cells.Contains(cell, StringComparer.Ordinal) == true;
        var proposed = change.Proposed?.Cells.Contains(cell, StringComparer.Ordinal) == true;
        if (!accepted && !proposed) return null;
        var kind = (accepted, proposed) switch
        {
            (false, true) => NativeGitOpsChangeKind.Create,
            (true, false) => NativeGitOpsChangeKind.GuardedRetirement,
            _ when change.Accepted!.Suspended != change.Proposed!.Suspended =>
                change.Proposed.Suspended ? NativeGitOpsChangeKind.Suspend : NativeGitOpsChangeKind.Resume,
            _ => change.Kind,
        };
        return new(
            kind,
            change.WorkloadId,
            accepted ? change.Accepted : null,
            proposed ? change.Proposed : null,
            GitOpsChildOwnership.RegionalJournal,
            GitOpsRemovalPolicy.GuardedRetirement);
    }

    private static IEnumerable<NativeGitOpsCellChange> OrderStopping(
        IEnumerable<NativeGitOpsCellChange> values)
    {
        var actions = values.ToDictionary(static change => change.WorkloadId, StringComparer.Ordinal);
        var dependents = actions.Keys.ToDictionary(static id => id, _ => 0, StringComparer.Ordinal);
        foreach (var action in actions.Values)
        {
            foreach (var dependency in action.Accepted?.DependsOn ?? [])
            {
                if (dependents.ContainsKey(dependency)) dependents[dependency]++;
            }
        }
        var ready = new SortedSet<string>(
            dependents.Where(static item => item.Value == 0).Select(static item => item.Key),
            StringComparer.Ordinal);
        var ordered = new List<NativeGitOpsCellChange>(actions.Count);
        while (ready.Count > 0)
        {
            var id = ready.Min!;
            ready.Remove(id);
            var action = actions[id];
            ordered.Add(action);
            foreach (var dependency in action.Accepted?.DependsOn ?? [])
            {
                if (!dependents.TryGetValue(dependency, out var count)) continue;
                dependents[dependency] = --count;
                if (count == 0) ready.Add(dependency);
            }
        }
        if (ordered.Count != actions.Count)
            throw new InvalidDataException("The native GitOps cell retirement graph contains a cycle.");
        return ordered;
    }

    private static byte[] Payload(
        NativeGitOpsSourcePlan source,
        string cell,
        IReadOnlyList<NativeGitOpsWorkloadPlan> desired,
        IReadOnlyList<NativeGitOpsCellChange> changes)
    {
        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteString("repository", source.Revision.Repository);
            writer.WriteString("commit", source.Revision.Commit);
            writer.WriteString("tree", source.Revision.Tree);
            writer.WriteString("filePath", source.SourceFile.Path);
            writer.WriteString("blob", source.SourceFile.Blob);
            writer.WriteString("contentSha256", source.SourceFile.ContentSha256);
            writer.WriteNumber("generation", source.Proposed.Generation);
            writer.WriteString("globalPlanDigest", source.Proposed.Digest);
            writer.WriteString("cell", cell);
            writer.WriteStartArray("desiredWorkloads");
            foreach (var workload in desired) WriteWorkload(writer, workload);
            writer.WriteEndArray();
            writer.WriteStartArray("changes");
            foreach (var change in changes)
            {
                writer.WriteStartObject();
                writer.WriteString("kind", change.Kind.ToString());
                writer.WriteString("workloadId", change.WorkloadId);
                writer.WriteString("childOwnership", change.ChildOwnership.ToString());
                writer.WriteString("removalPolicy", change.RemovalPolicy.ToString());
                if (change.Kind == NativeGitOpsChangeKind.GuardedRetirement)
                {
                    writer.WritePropertyName("retiredWorkload");
                    WriteWorkload(writer, change.Accepted!);
                }
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        if (bytes.WrittenCount > MaximumCellSpecBytes)
            throw new InvalidDataException("A native GitOps cell specification exceeded its technical bound.");
        return bytes.WrittenMemory.ToArray();
    }

    private static void WriteWorkload(Utf8JsonWriter writer, NativeGitOpsWorkloadPlan workload)
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

    private static int ProposedIndex(NativeGitOpsPlan plan, string workloadId)
    {
        for (var index = 0; index < plan.Workloads.Count; index++)
        {
            if (plan.Workloads[index].Id == workloadId) return index;
        }
        return int.MaxValue;
    }

    private static IEnumerable<string> ChangeCells(NativeGitOpsChange change) =>
        (change.Accepted?.Cells ?? []).Concat(change.Proposed?.Cells ?? []);

    internal static string ComputeHandoffDigest(
        long generation,
        string globalPlanDigest,
        IReadOnlyList<NativeGitOpsCellSpec> cells)
    {
        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            writer.WriteNumber("generation", generation);
            writer.WriteString("globalPlanDigest", globalPlanDigest);
            writer.WriteStartArray("cells");
            foreach (var cell in cells)
            {
                writer.WriteStartObject();
                writer.WriteString("cell", cell.Cell);
                writer.WriteString("payloadSha256", cell.PayloadSha256);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return Convert.ToHexStringLower(SHA256.HashData(bytes.WrittenSpan));
    }

    private static void Validate(NativeGitOpsSourcePlan source)
    {
        var compiled = NativeGitOpsManifest.Parse(source.SourceFile.Content);
        var contentSha256 = Convert.ToHexStringLower(SHA256.HashData(source.SourceFile.Content.Span));
        if (!source.Revision.SignatureVerified || source.Revision.Repository != source.SourceFile.Repository ||
            source.Revision.Commit != source.SourceFile.Commit ||
            source.SourceFile.Path != NativeGitOpsSourceLoader.ManifestPath ||
            source.SourceFile.ContentSha256 != contentSha256 ||
            compiled.Generation != source.Proposed.Generation || compiled.Digest != source.Proposed.Digest ||
            source.Diff.ProposedGeneration != source.Proposed.Generation ||
            source.Diff.ProposedDigest != source.Proposed.Digest)
            throw new InvalidDataException("The native GitOps cell handoff source is inconsistent.");
    }

    private static IReadOnlyList<T> ReadOnly<T>(T[] values) =>
        new ReadOnlyCollection<T>(values);
}
