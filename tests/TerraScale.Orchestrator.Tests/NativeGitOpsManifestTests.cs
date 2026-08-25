using System.Text;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsManifestTests
{
    private const string PlatformDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
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
                {"id":"platform","role":"Platform","artifactDigest":"{{PlatformDigest}}","cells":["sfo","gru"],"dependsOn":["auth"]},
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
            .IsEqualTo("auth,control,platform");
        var platform = plan.Workloads.Single(static value => value.Id == "platform");
        await Assert.That(platform.Runtime).IsEqualTo(RuntimeDriver.OciContainer);
        await Assert.That(platform.Replicas).IsEqualTo(1);
        await Assert.That(platform.Cells).IsEquivalentTo(["gru", "sfo"]);
        await Assert.That(platform.ChildOwnership).IsEqualTo(GitOpsChildOwnership.RegionalJournal);
        await Assert.That(platform.RemovalPolicy).IsEqualTo(GitOpsRemovalPolicy.GuardedRetirement);
        var control = plan.Workloads.Single(static value => value.Id == "control");
        await Assert.That(control.Runtime).IsEqualTo(RuntimeDriver.NativeSystemd);
        await Assert.That(control.Replicas).IsEqualTo(3);
        await Assert.That(string.Join(',', plan.Cells.Select(static value => value.Cell))).IsEqualTo("gru,sfo");
        await Assert.That(string.Join(',', plan.Cells.Single(static value => value.Cell == "gru").Workloads
            .Select(static value => value.Id))).IsEqualTo("auth,control,platform");
        await Assert.That(string.Join(',', plan.Cells.Single(static value => value.Cell == "sfo").Workloads
            .Select(static value => value.Id))).IsEqualTo("auth,platform");
    }

    [Test]
    public async Task CanonicalPlanIsIndependentOfJsonAndSetOrdering()
    {
        var first = Parse($$"""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":1,"workloads":[
              {"id":"platform","role":"Platform","artifactDigest":"{{PlatformDigest}}","cells":["sfo","gru"],"dependsOn":["auth"]},
              {"id":"auth","role":"Authentication","artifactDigest":"{{AuthDigest}}","cells":["sfo","gru"]}
            ]}
            """);
        var second = Parse($$"""
            {"workloads":[
              {"cells":["gru","sfo"],"artifactDigest":"{{AuthDigest}}","role":"Authentication","id":"auth","suspended":false,"replicas":1,"runtime":"OciContainer"},
              {"dependsOn":["auth"],"cells":["gru","sfo"],"artifactDigest":"{{PlatformDigest}}","role":"Platform","id":"platform"}
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
            Workload($"\"id\":\"platform\",\"role\":\"ArbitraryContainer\",\"artifactDigest\":\"{PlatformDigest}\",\"cells\":[\"gru\"]"),
            Workload($"\"id\":\"platform\",\"role\":\"Platform\",\"artifactDigest\":\"{PlatformDigest}\",\"cells\":[\"gru\"],\"runtime\":\"NativeSystemd\""),
            Workload($"\"id\":\"platform\",\"role\":\"Platform\",\"artifactDigest\":\"{PlatformDigest}\",\"cells\":[\"gru\"],\"command\":\"/bin/sh\""),
            Workload($"\"id\":\"../../platform\",\"role\":\"Platform\",\"artifactDigest\":\"{PlatformDigest}\",\"cells\":[\"gru\"]"),
            Workload("\"id\":\"platform\",\"role\":\"Platform\",\"artifactDigest\":\"latest\",\"cells\":[\"gru\"]"),
        };

        foreach (var value in cases)
            await Assert.That(() => Parse(value)).Throws<InvalidDataException>();
    }

    [Test]
    public async Task TheMcpRoleIsRejectedUntilTheGitOpsLaneCarriesTheQualifiedArtifactBinding()
    {
        // ADR 0032: the GitOps lane admits roles by catalog membership plus a well-formed
        // digest, which is NOT sufficient for the MCP workload — it additionally requires the
        // qualified HTTP artifact binding this lane does not carry. Fail closed with the
        // actionable route (direct delivery) instead of admitting any well-formed digest.
        var cases = new[]
        {
            Workload($"\"id\":\"mcp\",\"role\":\"McpServer\",\"artifactDigest\":\"{PlatformDigest}\",\"cells\":[\"gru\"]"),
            Workload($"\"id\":\"mcp\",\"role\":\"McpServer\",\"artifactDigest\":\"{PlatformDigest}\",\"cells\":[\"gru\"],\"replicas\":2"),
        };

        foreach (var value in cases)
        {
            var reason = string.Empty;
            try
            {
                Parse(value);
            }
            catch (InvalidDataException exception)
            {
                reason = exception.Message;
            }
            await Assert.That(reason).Contains("qualified HTTP artifact binding");
            await Assert.That(reason).Contains("direct delivery");
        }
    }

    [Test]
    public async Task ReplicationFloorsAndSchemaAreStrict()
    {
        var cases = new[]
        {
            Workload($"\"id\":\"control\",\"role\":\"Orchestrator\",\"artifactDigest\":\"{ControlDigest}\",\"cells\":[\"gru\"],\"replicas\":1"),
            Workload($"\"id\":\"platform\",\"id\":\"other\",\"role\":\"Platform\",\"artifactDigest\":\"{PlatformDigest}\",\"cells\":[\"gru\"]"),
            Workload($"\"id\":\"platform\",\"role\":\"Platform\",\"artifactDigest\":\"{PlatformDigest}\",\"cells\":[\"gru\",\"gru\"]"),
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
            $"{{\"id\":\"platform\",\"role\":\"Platform\",\"artifactDigest\":\"{PlatformDigest}\",\"cells\":[\"gru\"],\"dependsOn\":[\"auth\"]}}"
        ]);
        var crossCell = Manifest([
            $"{{\"id\":\"platform\",\"role\":\"Platform\",\"artifactDigest\":\"{PlatformDigest}\",\"cells\":[\"gru\",\"sfo\"],\"dependsOn\":[\"auth\"]}}",
            $"{{\"id\":\"auth\",\"role\":\"Authentication\",\"artifactDigest\":\"{AuthDigest}\",\"cells\":[\"gru\"]}}"
        ]);
        var self = Manifest([
            $"{{\"id\":\"platform\",\"role\":\"Platform\",\"artifactDigest\":\"{PlatformDigest}\",\"cells\":[\"gru\"],\"dependsOn\":[\"platform\"]}}"
        ]);
        var cycle = Manifest([
            $"{{\"id\":\"platform\",\"role\":\"Platform\",\"artifactDigest\":\"{PlatformDigest}\",\"cells\":[\"gru\"],\"dependsOn\":[\"auth\"]}}",
            $"{{\"id\":\"auth\",\"role\":\"Authentication\",\"artifactDigest\":\"{AuthDigest}\",\"cells\":[\"gru\"],\"dependsOn\":[\"platform\"]}}"
        ]);

        var suspendedDependency = Manifest([
            $"{{\"id\":\"platform\",\"role\":\"Platform\",\"artifactDigest\":\"{PlatformDigest}\",\"cells\":[\"gru\"],\"dependsOn\":[\"auth\"]}}",
            $"{{\"id\":\"auth\",\"role\":\"Authentication\",\"artifactDigest\":\"{AuthDigest}\",\"cells\":[\"gru\"],\"suspended\":true}}"
        ]);

        foreach (var value in new[] { missing, crossCell, self, cycle, suspendedDependency })
            await Assert.That(() => Parse(value)).Throws<InvalidDataException>();
    }

    [Test]
    public async Task EmptyDesiredSetCompilesAsAnExplicitBoundedGeneration()
    {
        var plan = Parse("""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":9,"workloads":[]}
            """);

        await Assert.That(plan.Generation).IsEqualTo(9);
        await Assert.That(plan.Digest.Length).IsEqualTo(64);
        await Assert.That(plan.Workloads).IsEmpty();
        await Assert.That(plan.Cells).IsEmpty();
    }

    private static NativeGitOpsPlan Parse(string value) =>
        NativeGitOpsManifest.Parse(Encoding.UTF8.GetBytes(value));

    private static string Workload(string fields) => Manifest([$"{{{fields}}}"]);

    private static string Manifest(IEnumerable<string> workloads) =>
        $$"""{"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":1,"workloads":[{{string.Join(',', workloads)}}]}""";
}
