using System.Text;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsManifestTests
{
    private const string ApiDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string AuthDigest = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ControlDigest = "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    public async Task ClosedManifestCompilesVisibleDefaultsInDependencyOrderPerCell()
    {
        var plan = Parse($$"""
            {
              "apiVersion":"terrascale.io/v1",
              "kind":"TerraScaleDesiredState",
              "generation":7,
              "workloads":[
                {"id":"api","role":"Api","artifactDigest":"{{ApiDigest}}","cells":["sfo","gru"],"dependsOn":["auth"]},
                {"id":"control","role":"Orchestrator","artifactDigest":"{{ControlDigest}}","cells":["gru"]},
                {"id":"auth","role":"Authentication","artifactDigest":"{{AuthDigest}}","cells":["gru","sfo"]}
              ]
            }
            """);

        await Assert.That(plan.ApiVersion).IsEqualTo(NativeGitOpsManifest.ApiVersion);
        await Assert.That(plan.Kind).IsEqualTo(NativeGitOpsManifest.Kind);
        await Assert.That(plan.Generation).IsEqualTo(7);
        await Assert.That(plan.Digest.Length).IsEqualTo(64);
        await Assert.That(string.Join(',', plan.Workloads.Select(static value => value.Id)))
            .IsEqualTo("auth,api,control");
        var api = plan.Workloads.Single(static value => value.Id == "api");
        await Assert.That(api.Runtime).IsEqualTo(RuntimeDriver.OciContainer);
        await Assert.That(api.Replicas).IsEqualTo(1);
        await Assert.That(api.Cells).IsEquivalentTo(["gru", "sfo"]);
        await Assert.That(api.ChildOwnership).IsEqualTo(GitOpsChildOwnership.RegionalJournal);
        await Assert.That(api.RemovalPolicy).IsEqualTo(GitOpsRemovalPolicy.GuardedRetirement);
        var control = plan.Workloads.Single(static value => value.Id == "control");
        await Assert.That(control.Runtime).IsEqualTo(RuntimeDriver.NativeSystemd);
        await Assert.That(control.Replicas).IsEqualTo(3);
        await Assert.That(string.Join(',', plan.Cells.Select(static value => value.Cell))).IsEqualTo("gru,sfo");
        await Assert.That(string.Join(',', plan.Cells.Single(static value => value.Cell == "gru").Workloads
            .Select(static value => value.Id))).IsEqualTo("auth,api,control");
        await Assert.That(string.Join(',', plan.Cells.Single(static value => value.Cell == "sfo").Workloads
            .Select(static value => value.Id))).IsEqualTo("auth,api");
    }

    [Test]
    public async Task CanonicalPlanIsIndependentOfJsonAndSetOrdering()
    {
        var first = Parse($$"""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":1,"workloads":[
              {"id":"api","role":"Api","artifactDigest":"{{ApiDigest}}","cells":["sfo","gru"],"dependsOn":["auth"]},
              {"id":"auth","role":"Authentication","artifactDigest":"{{AuthDigest}}","cells":["sfo","gru"]}
            ]}
            """);
        var second = Parse($$"""
            {"workloads":[
              {"cells":["gru","sfo"],"artifactDigest":"{{AuthDigest}}","role":"Authentication","id":"auth","suspended":false,"replicas":1,"runtime":"OciContainer"},
              {"dependsOn":["auth"],"cells":["gru","sfo"],"artifactDigest":"{{ApiDigest}}","role":"Api","id":"api"}
            ],"generation":1,"kind":"TerraScaleDesiredState","apiVersion":"terrascale.io/v1"}
            """);

        await Assert.That(first.Digest).IsEqualTo(second.Digest);
        await Assert.That(first.Workloads).IsEquivalentTo(second.Workloads);
    }

    [Test]
    public async Task ArbitraryExecutionAndUnknownRolesFailClosed()
    {
        var cases = new[]
        {
            Workload($"\"id\":\"api\",\"role\":\"ArbitraryContainer\",\"artifactDigest\":\"{ApiDigest}\",\"cells\":[\"gru\"]"),
            Workload($"\"id\":\"api\",\"role\":\"Api\",\"artifactDigest\":\"{ApiDigest}\",\"cells\":[\"gru\"],\"runtime\":\"NativeSystemd\""),
            Workload($"\"id\":\"api\",\"role\":\"Api\",\"artifactDigest\":\"{ApiDigest}\",\"cells\":[\"gru\"],\"command\":\"/bin/sh\""),
            Workload($"\"id\":\"../../api\",\"role\":\"Api\",\"artifactDigest\":\"{ApiDigest}\",\"cells\":[\"gru\"]"),
            Workload("\"id\":\"api\",\"role\":\"Api\",\"artifactDigest\":\"latest\",\"cells\":[\"gru\"]"),
        };

        foreach (var value in cases)
            await Assert.That(() => Parse(value)).Throws<InvalidDataException>();
    }

    [Test]
    public async Task ReplicationFloorsAndSchemaAreStrict()
    {
        var cases = new[]
        {
            Workload($"\"id\":\"control\",\"role\":\"Orchestrator\",\"artifactDigest\":\"{ControlDigest}\",\"cells\":[\"gru\"],\"replicas\":1"),
            Workload($"\"id\":\"api\",\"id\":\"other\",\"role\":\"Api\",\"artifactDigest\":\"{ApiDigest}\",\"cells\":[\"gru\"]"),
            Workload($"\"id\":\"api\",\"role\":\"Api\",\"artifactDigest\":\"{ApiDigest}\",\"cells\":[\"gru\",\"gru\"]"),
            "{\"apiVersion\":\"terrascale.io/v2\",\"kind\":\"TerraScaleDesiredState\",\"generation\":1,\"workloads\":[]}",
            "{\"apiVersion\":\"terrascale.io/v1\",\"kind\":\"TerraScaleDesiredState\",\"generation\":0,\"workloads\":[]}",
        };

        foreach (var value in cases)
            await Assert.That(() => Parse(value)).Throws<InvalidDataException>();
    }

    [Test]
    public async Task DependencyGraphRejectsMissingCrossCellSelfAndCycles()
    {
        var missing = Manifest([
            $"{{\"id\":\"api\",\"role\":\"Api\",\"artifactDigest\":\"{ApiDigest}\",\"cells\":[\"gru\"],\"dependsOn\":[\"auth\"]}}"
        ]);
        var crossCell = Manifest([
            $"{{\"id\":\"api\",\"role\":\"Api\",\"artifactDigest\":\"{ApiDigest}\",\"cells\":[\"gru\",\"sfo\"],\"dependsOn\":[\"auth\"]}}",
            $"{{\"id\":\"auth\",\"role\":\"Authentication\",\"artifactDigest\":\"{AuthDigest}\",\"cells\":[\"gru\"]}}"
        ]);
        var self = Manifest([
            $"{{\"id\":\"api\",\"role\":\"Api\",\"artifactDigest\":\"{ApiDigest}\",\"cells\":[\"gru\"],\"dependsOn\":[\"api\"]}}"
        ]);
        var cycle = Manifest([
            $"{{\"id\":\"api\",\"role\":\"Api\",\"artifactDigest\":\"{ApiDigest}\",\"cells\":[\"gru\"],\"dependsOn\":[\"auth\"]}}",
            $"{{\"id\":\"auth\",\"role\":\"Authentication\",\"artifactDigest\":\"{AuthDigest}\",\"cells\":[\"gru\"],\"dependsOn\":[\"api\"]}}"
        ]);

        var suspendedDependency = Manifest([
            $"{{\"id\":\"api\",\"role\":\"Api\",\"artifactDigest\":\"{ApiDigest}\",\"cells\":[\"gru\"],\"dependsOn\":[\"auth\"]}}",
            $"{{\"id\":\"auth\",\"role\":\"Authentication\",\"artifactDigest\":\"{AuthDigest}\",\"cells\":[\"gru\"],\"suspended\":true}}"
        ]);

        foreach (var value in new[] { missing, crossCell, self, cycle, suspendedDependency })
            await Assert.That(() => Parse(value)).Throws<InvalidDataException>();
    }

    private static NativeGitOpsPlan Parse(string value) =>
        NativeGitOpsManifest.Parse(Encoding.UTF8.GetBytes(value));

    private static string Workload(string fields) => Manifest([$"{{{fields}}}"]);

    private static string Manifest(IEnumerable<string> workloads) =>
        $$"""{"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":1,"workloads":[{{string.Join(',', workloads)}}]}""";
}
