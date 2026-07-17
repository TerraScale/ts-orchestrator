using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsCellPayloadTests
{
    private const string ApiV1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ApiV2 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string Auth = "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    public async Task DurablePayloadRehydratesExactBaseDesiredAndRetirementIdentities()
    {
        var accepted = Plan(1,
            Workload("api", "Api", ApiV1, ["gru", "sfo"], ["auth"]),
            Workload("auth", "Authentication", Auth, ["gru", "sfo"]));
        var handoff = Handoff(accepted, Plan(2,
            Workload("api", "Api", ApiV2, ["gru"], ["auth"]),
            Workload("auth", "Authentication", Auth, ["gru"])));

        var gru = handoff.Cells.Single(static cell => cell.Cell == "gru");
        var parsedGru = NativeGitOpsCellPayload.Parse(Accepted(handoff, gru));
        await Assert.That(parsedGru.AcceptedGeneration).IsEqualTo(1);
        await Assert.That(parsedGru.AcceptedGlobalPlanDigest)
            .IsEqualTo(NativeGitOpsManifest.Parse(accepted).Digest);
        await Assert.That(string.Join(',', parsedGru.DesiredWorkloads.Select(static value => value.Id)))
            .IsEqualTo("auth,api");
        await Assert.That(parsedGru.Changes.All(static value =>
            value.AcceptedWorkloadSha256 is not null && value.ProposedWorkloadSha256 is not null))
            .IsTrue();

        var sfo = handoff.Cells.Single(static cell => cell.Cell == "sfo");
        var parsedSfo = NativeGitOpsCellPayload.Parse(Accepted(handoff, sfo));
        await Assert.That(parsedSfo.DesiredWorkloads).IsEmpty();
        await Assert.That(string.Join(',', parsedSfo.Changes.Select(static value => value.WorkloadId)))
            .IsEqualTo("api,auth");
        await Assert.That(parsedSfo.Changes.All(change =>
            change.Kind == NativeGitOpsChangeKind.GuardedRetirement &&
            change.RetiredWorkload is not null &&
            change.AcceptedWorkloadSha256 ==
                NativeGitOpsCellSpecCompiler.WorkloadDigest(change.RetiredWorkload)))
            .IsTrue();
    }

    [Test]
    public async Task UnknownDuplicateAndContradictoryChangeFieldsFailClosed()
    {
        var handoff = Handoff(null, Plan(1, Workload("api", "Api", ApiV1, ["gru"])));
        var cell = handoff.Cells.Single();
        var json = Encoding.UTF8.GetString(cell.Payload.Span);
        var unknown = json.Replace("\"changes\":", "\"unknown\":true,\"changes\":", StringComparison.Ordinal);
        var duplicate = json.Replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1", StringComparison.Ordinal);
        var contradictory = json.Replace(
            "\"acceptedWorkloadSha256\":null",
            $"\"acceptedWorkloadSha256\":\"{ApiV2}\"",
            StringComparison.Ordinal);

        foreach (var invalid in new[] { unknown, duplicate, contradictory })
            await Assert.That(() => NativeGitOpsCellPayload.Parse(Accepted(
                    handoff,
                    cell,
                    Encoding.UTF8.GetBytes(invalid))))
                .Throws<InvalidDataException>();
    }

    [Test]
    public async Task PayloadMustRetainItsDurableCellGenerationPlanAndDigestIdentity()
    {
        var handoff = Handoff(null, Plan(1, Workload("api", "Api", ApiV1, ["gru"])));
        var cell = handoff.Cells.Single();
        var accepted = Accepted(handoff, cell);

        foreach (var mismatch in new[]
        {
            accepted with { Cell = "sfo" },
            accepted with { Generation = 2 },
            accepted with { GlobalPlanDigest = ApiV2 },
            accepted with { PayloadSha256 = ApiV2 },
        })
            await Assert.That(() => NativeGitOpsCellPayload.Parse(mismatch)).Throws<InvalidDataException>();
    }

    private static NativeGitOpsAcceptedCellSpec Accepted(
        NativeGitOpsCellHandoff handoff,
        NativeGitOpsCellSpec cell,
        byte[]? payload = null)
    {
        var bytes = payload ?? cell.Payload.ToArray();
        return new(
            cell.Cell,
            cell.Generation,
            cell.GlobalPlanDigest,
            handoff.HandoffDigest,
            Convert.ToHexStringLower(SHA256.HashData(bytes)),
            bytes,
            7,
            1,
            $"gitops/{handoff.HandoffDigest}/{cell.Cell}",
            $"gitops/{Convert.ToHexStringLower(SHA256.HashData(bytes))}",
            1,
            new(2026, 7, 17, 11, 59, 0, TimeSpan.Zero),
            new(2026, 7, 17, 12, 1, 0, TimeSpan.Zero),
            new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero),
            1,
            "a123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            1);
    }

    private static NativeGitOpsCellHandoff Handoff(byte[]? acceptedContent, byte[] proposedContent)
    {
        const string repository = "TerraScale/TerraScale.Orchestrator";
        const string commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
        const string tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
        const string blob = "217eb74224043ba2feb48d137756c8a9331c44ee";
        var accepted = acceptedContent is null ? null : NativeGitOpsManifest.Parse(acceptedContent);
        var proposed = NativeGitOpsManifest.Parse(proposedContent);
        return NativeGitOpsCellSpecCompiler.Compile(new(
            new(repository, commit, tree, signatureVerified: true),
            new(
                repository,
                commit,
                NativeGitOpsSourceLoader.ManifestPath,
                blob,
                Convert.ToHexStringLower(SHA256.HashData(proposedContent)),
                proposedContent),
            proposed,
            NativeGitOpsDiff.Compare(accepted, proposed)));
    }

    private static byte[] Plan(long generation, params string[] workloads) => Encoding.UTF8.GetBytes($$"""
        {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":{{generation}},"workloads":[{{string.Join(',', workloads)}}]}
        """);

    private static string Workload(
        string id,
        string role,
        string digest,
        string[] cells,
        string[]? dependsOn = null) => $$"""
        {"id":"{{id}}","role":"{{role}}","artifactDigest":"{{digest}}","cells":[{{string.Join(',', cells.Select(static cell => $"\"{cell}\""))}}],"dependsOn":[{{string.Join(',', (dependsOn ?? []).Select(static dependency => $"\"{dependency}\""))}}]}
        """;
}
