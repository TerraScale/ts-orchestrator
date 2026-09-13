using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsCellSpecTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string Commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
    private const string Tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
    private const string Blob = "217eb74224043ba2feb48d137756c8a9331c44ee";
    private const string PlatformV1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string PlatformV2 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string Auth = "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string Control = "3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    public async Task ExactSourceCompilesDeterministicSameDigestCellPayloads()
    {
        var source = SourcePlan(null, Plan(1,
            Workload("platform", "CustomerDashboard", PlatformV1, ["gru", "sfo"], ["auth"]),
            Workload("auth", "CustomerDashboard", Auth, ["gru", "sfo"])));

        var first = NativeGitOpsCellSpecCompiler.Compile(source);
        var second = NativeGitOpsCellSpecCompiler.Compile(source);

        await Assert.That(string.Join(',', first.RequiredCells)).IsEqualTo("gru,sfo");
        await Assert.That(first.HandoffDigest).IsEqualTo(second.HandoffDigest);
        await Assert.That(first.GlobalPlanDigest).IsEqualTo(source.Proposed.Digest);
        foreach (var cell in first.Cells)
        {
            await Assert.That(cell.GlobalPlanDigest).IsEqualTo(first.GlobalPlanDigest);
            await Assert.That(Convert.ToHexStringLower(SHA256.HashData(cell.Payload.Span)))
                .IsEqualTo(cell.PayloadSha256);
            await Assert.That(string.Join(',', cell.DesiredWorkloads.Select(workload => workload.Id)))
                .IsEqualTo("auth,platform");
            await Assert.That(string.Join(',', cell.Changes.Select(change => change.WorkloadId)))
                .IsEqualTo("auth,platform");
            await Assert.That(cell.Changes.All(change => change.Kind == NativeGitOpsChangeKind.Create)).IsTrue();
            await Assert.That(cell.Payload.Span.SequenceEqual(
                second.Cells.Single(other => other.Cell == cell.Cell).Payload.Span)).IsTrue();
        }
    }

    [Test]
    public async Task CellRemovalRetiresDependentsWhileOtherCellsCreateOrUpdate()
    {
        var accepted = NativeGitOpsManifest.Parse(Plan(1,
            Workload("platform", "CustomerDashboard", PlatformV1, ["gru", "sfo"], ["auth"]),
            Workload("auth", "CustomerDashboard", Auth, ["gru", "sfo"])));
        var source = SourcePlan(accepted, Plan(2,
            Workload("platform", "CustomerDashboard", PlatformV1, ["gru"], ["auth"]),
            Workload("auth", "CustomerDashboard", Auth, ["gru"]),
            Workload("control", "Orchestrator", Control, ["fra"], replicas: 3)));

        var handoff = NativeGitOpsCellSpecCompiler.Compile(source);
        var fra = handoff.Cells.Single(cell => cell.Cell == "fra");
        var gru = handoff.Cells.Single(cell => cell.Cell == "gru");
        var sfo = handoff.Cells.Single(cell => cell.Cell == "sfo");

        await Assert.That(string.Join(',', handoff.RequiredCells)).IsEqualTo("fra,gru,sfo");
        await Assert.That(string.Join(',', fra.Changes.Select(change => $"{change.Kind}:{change.WorkloadId}")))
            .IsEqualTo("Create:control");
        await Assert.That(string.Join(',', gru.Changes.Select(change => $"{change.Kind}:{change.WorkloadId}")))
            .IsEqualTo("Update:auth,Update:platform");
        await Assert.That(sfo.DesiredWorkloads).IsEmpty();
        await Assert.That(string.Join(',', sfo.Changes.Select(change => $"{change.Kind}:{change.WorkloadId}")))
            .IsEqualTo("GuardedRetirement:platform,GuardedRetirement:auth");
        await Assert.That(sfo.Changes.All(change =>
            change.Proposed is null && change.Accepted is not null &&
            change.ChildOwnership == GitOpsChildOwnership.RegionalJournal &&
            change.RemovalPolicy == GitOpsRemovalPolicy.GuardedRetirement)).IsTrue();
    }

    [Test]
    public async Task PayloadBindsAcceptedPlanAndBeforeAfterWorkloadIdentities()
    {
        var accepted = NativeGitOpsManifest.Parse(Plan(1,
            Workload("platform", "CustomerDashboard", PlatformV1, ["gru", "sfo"], ["auth"]),
            Workload("auth", "CustomerDashboard", Auth, ["gru", "sfo"])));
        var source = SourcePlan(accepted, Plan(2,
            Workload("platform", "CustomerDashboard", PlatformV2, ["gru"], ["auth"]),
            Workload("auth", "CustomerDashboard", Auth, ["gru"])));
        var handoff = NativeGitOpsCellSpecCompiler.Compile(source);

        foreach (var cell in handoff.Cells)
        {
            using var document = JsonDocument.Parse(cell.Payload);
            var root = document.RootElement;
            await Assert.That(root.GetProperty("acceptedGeneration").GetInt64()).IsEqualTo(1);
            await Assert.That(root.GetProperty("acceptedGlobalPlanDigest").GetString())
                .IsEqualTo(accepted.Digest);
            var encoded = root.GetProperty("changes").EnumerateArray().ToArray();
            await Assert.That(encoded.Length).IsEqualTo(cell.Changes.Count);
            for (var index = 0; index < encoded.Length; index++)
            {
                var change = cell.Changes[index];
                await Assert.That(encoded[index].GetProperty("workloadId").GetString())
                    .IsEqualTo(change.WorkloadId);
                await AssertDigest(encoded[index], "acceptedWorkloadSha256", change.Accepted);
                await AssertDigest(encoded[index], "proposedWorkloadSha256", change.Proposed);
            }
        }

        var first = NativeGitOpsCellSpecCompiler.Compile(SourcePlan(null, Plan(1,
            Workload("platform", "CustomerDashboard", PlatformV1, ["gru"])))).Cells.Single();
        using var initial = JsonDocument.Parse(first.Payload);
        await Assert.That(initial.RootElement.GetProperty("acceptedGeneration").ValueKind)
            .IsEqualTo(JsonValueKind.Null);
        await Assert.That(initial.RootElement.GetProperty("acceptedGlobalPlanDigest").ValueKind)
            .IsEqualTo(JsonValueKind.Null);
    }

    [Test]
    public async Task CombinedContentAndSuspensionChangeStopsDependentsFirst()
    {
        var accepted = NativeGitOpsManifest.Parse(Plan(1,
            Workload("platform", "CustomerDashboard", PlatformV1, ["gru"], ["auth"]),
            Workload("auth", "CustomerDashboard", Auth, ["gru"])));
        var source = SourcePlan(accepted, Plan(2,
            Workload("platform", "CustomerDashboard", PlatformV2, ["gru"], ["auth"], suspended: true),
            Workload("auth", "CustomerDashboard", Auth, ["gru"], suspended: true)));

        var cell = NativeGitOpsCellSpecCompiler.Compile(source).Cells.Single();

        await Assert.That(string.Join(',', cell.Changes.Select(change => $"{change.Kind}:{change.WorkloadId}")))
            .IsEqualTo("Suspend:platform,Suspend:auth");
    }

    [Test]
    public async Task EmptyProposedSetStillHandsRetirementToEveryAcceptedCell()
    {
        var accepted = NativeGitOpsManifest.Parse(Plan(1,
            Workload("platform", "CustomerDashboard", PlatformV1, ["gru", "sfo"], ["auth"]),
            Workload("auth", "CustomerDashboard", Auth, ["gru", "sfo"])));
        var source = SourcePlan(accepted, Plan(2));

        var handoff = NativeGitOpsCellSpecCompiler.Compile(source);

        await Assert.That(string.Join(',', handoff.RequiredCells)).IsEqualTo("gru,sfo");
        foreach (var cell in handoff.Cells)
        {
            await Assert.That(cell.DesiredWorkloads).IsEmpty();
            await Assert.That(string.Join(',', cell.Changes.Select(change =>
                $"{change.Kind}:{change.WorkloadId}")))
                .IsEqualTo("GuardedRetirement:platform,GuardedRetirement:auth");
        }
    }

    [Test]
    public async Task TotalCellFanOutIsBoundedIndependentlyOfEachWorkload()
    {
        var workloads = Enumerable.Range(0, NativeGitOpsCellSpecCompiler.MaximumCellsPerHandoff + 1)
            .Select(index => Workload(
                $"platform-{index}",
                "Orchestrator",
                PlatformV1,
                [$"cell-{index}"]))
            .ToArray();
        var source = SourcePlan(null, Plan(1, workloads));

        await Assert.That(() => NativeGitOpsCellSpecCompiler.Compile(source))
            .Throws<InvalidDataException>();
    }

    private static NativeGitOpsSourcePlan SourcePlan(NativeGitOpsPlan? accepted, byte[] content)
    {
        var proposed = NativeGitOpsManifest.Parse(content);
        var revision = new ForgejoResolvedRevision(Repository, Commit, Tree, signatureVerified: true);
        var file = new ForgejoSourceFile(
            Repository,
            Commit,
            NativeGitOpsSourceLoader.ManifestPath,
            Blob,
            Convert.ToHexStringLower(SHA256.HashData(content)),
            content);
        return new(revision, file, proposed, NativeGitOpsDiff.Compare(accepted, proposed));
    }

    private static byte[] Plan(long generation, params string[] workloads) => Encoding.UTF8.GetBytes($$"""
        {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":{{generation}},"workloads":[{{string.Join(',', workloads)}}]}
        """);

    private static string Workload(
        string id,
        string role,
        string digest,
        string[] cells,
        string[]? dependsOn = null,
        int? replicas = null,
        bool suspended = false) => $$"""
        {"id":"{{id}}","role":"{{role}}","artifactDigest":"{{digest}}","cells":[{{string.Join(',', cells.Select(cell => $"\"{cell}\""))}}],"dependsOn":[{{string.Join(',', (dependsOn ?? []).Select(dependency => $"\"{dependency}\""))}}]{{(replicas is null ? "" : $",\"replicas\":{replicas}")}},"suspended":{{suspended.ToString().ToLowerInvariant()}}}
        """;

    private static async Task AssertDigest(
        JsonElement change,
        string property,
        NativeGitOpsWorkloadPlan? workload)
    {
        var value = change.GetProperty(property);
        if (workload is null)
            await Assert.That(value.ValueKind).IsEqualTo(JsonValueKind.Null);
        else
            await Assert.That(value.GetString()).IsEqualTo(NativeGitOpsCellSpecCompiler.WorkloadDigest(workload));
    }
}

