using System.Text;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsDiffTests
{
    private const string PlatformV1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string PlatformV2 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string Auth = "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string Control = "3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    public async Task InitialPlanCreatesInDependencyOrderWithGuardedChildOwnership()
    {
        var proposed = Plan(1,
            Workload("platform", "CustomerDashboard", PlatformV1, dependsOn: ["auth"]),
            Workload("auth", "CustomerDashboard", Auth));

        var diff = NativeGitOpsDiff.Compare(null, proposed);

        await Assert.That(string.Join(',', diff.Changes.Select(change => change.WorkloadId)))
            .IsEqualTo("auth,platform");
        await Assert.That(diff.Changes.All(change => change.Kind == NativeGitOpsChangeKind.Create)).IsTrue();
        await Assert.That(diff.Changes.All(change =>
            change.ChildOwnership == GitOpsChildOwnership.RegionalJournal &&
            change.RemovalPolicy == GitOpsRemovalPolicy.GuardedRetirement)).IsTrue();
    }

    [Test]
    public async Task UpdatesPrecedeDependentFirstGuardedRetirement()
    {
        var accepted = Plan(1,
            Workload("platform", "CustomerDashboard", PlatformV1, dependsOn: ["auth"]),
            Workload("auth", "CustomerDashboard", Auth));
        var proposed = Plan(2, Workload("control", "Orchestrator", Control));

        var diff = NativeGitOpsDiff.Compare(accepted, proposed);

        await Assert.That(string.Join(',', diff.Changes.Select(change => $"{change.Kind}:{change.WorkloadId}")))
            .IsEqualTo("Create:control,GuardedRetirement:platform,GuardedRetirement:auth");
        await Assert.That(diff.Changes.Where(change => change.Kind == NativeGitOpsChangeKind.GuardedRetirement)
            .All(change => change.Proposed is null && change.Accepted is not null)).IsTrue();
        await Assert.That(Enum.GetNames<NativeGitOpsChangeKind>()).DoesNotContain("Delete");
    }

    [Test]
    public async Task ContentAndSuspensionChangesHaveDistinctTypedActions()
    {
        var accepted = Plan(1,
            Workload("platform", "CustomerDashboard", PlatformV1),
            Workload("auth", "CustomerDashboard", Auth, suspended: true),
            Workload("control", "Orchestrator", Control));
        var proposed = Plan(2,
            Workload("platform", "CustomerDashboard", PlatformV2),
            Workload("auth", "CustomerDashboard", Auth),
            Workload("control", "Orchestrator", Control, suspended: true));

        var diff = NativeGitOpsDiff.Compare(accepted, proposed);

        await Assert.That(string.Join(',', diff.Changes.Select(change => $"{change.Kind}:{change.WorkloadId}")))
            .IsEqualTo("Resume:auth,Update:platform,Suspend:control");
        await Assert.That(diff.IsNoOp).IsFalse();
    }

    [Test]
    public async Task SuspensionIsDependentFirstAndResumeIsDependencyFirst()
    {
        var active = Plan(1,
            Workload("platform", "CustomerDashboard", PlatformV1, dependsOn: ["auth"]),
            Workload("auth", "CustomerDashboard", Auth));
        var suspended = Plan(2,
            Workload("platform", "CustomerDashboard", PlatformV1, dependsOn: ["auth"], suspended: true),
            Workload("auth", "CustomerDashboard", Auth, suspended: true));

        var stop = NativeGitOpsDiff.Compare(active, suspended);
        var start = NativeGitOpsDiff.Compare(
            suspended,
            Plan(3,
                Workload("platform", "CustomerDashboard", PlatformV1, dependsOn: ["auth"]),
                Workload("auth", "CustomerDashboard", Auth)));

        await Assert.That(string.Join(',', stop.Changes.Select(change => change.WorkloadId)))
            .IsEqualTo("platform,auth");
        await Assert.That(stop.Changes.All(change => change.Kind == NativeGitOpsChangeKind.Suspend)).IsTrue();
        await Assert.That(string.Join(',', start.Changes.Select(change => change.WorkloadId)))
            .IsEqualTo("auth,platform");
        await Assert.That(start.Changes.All(change => change.Kind == NativeGitOpsChangeKind.Resume)).IsTrue();
    }

    [Test]
    public async Task GenerationsAreMonotonicIdempotentAndConflictFree()
    {
        var accepted = Plan(4, Workload("platform", "CustomerDashboard", PlatformV1));
        var exactRetry = NativeGitOpsDiff.Compare(accepted, accepted);
        var noContentChange = NativeGitOpsDiff.Compare(
            accepted,
            Plan(5, Workload("platform", "CustomerDashboard", PlatformV1)));
        var stale = Capture(() => NativeGitOpsDiff.Compare(
            accepted,
            Plan(3, Workload("platform", "CustomerDashboard", PlatformV1))));
        var conflict = Capture(() => NativeGitOpsDiff.Compare(
            accepted,
            Plan(4, Workload("platform", "CustomerDashboard", PlatformV2))));

        await Assert.That(exactRetry.IsNoOp).IsTrue();
        await Assert.That(noContentChange.IsNoOp).IsTrue();
        await Assert.That(stale.Code).IsEqualTo(NativeGitOpsDiffError.StaleGeneration);
        await Assert.That(conflict.Code).IsEqualTo(NativeGitOpsDiffError.ConflictingGeneration);
    }

    [Test]
    public async Task StableWorkloadIdentityCannotChangeItsRole()
    {
        var accepted = Plan(1, Workload("service", "Orchestrator", PlatformV1));
        var changed = Plan(2, Workload("service", "CustomerDashboard", Auth));

        var error = Capture(() => NativeGitOpsDiff.Compare(accepted, changed));

        await Assert.That(error.Code).IsEqualTo(NativeGitOpsDiffError.ImmutableIdentityChanged);
    }

    [Test]
    public async Task EmptyDesiredSetRetiresEveryWorkloadDependentFirst()
    {
        var accepted = Plan(1,
            Workload("platform", "CustomerDashboard", PlatformV1, dependsOn: ["auth"]),
            Workload("auth", "CustomerDashboard", Auth));
        var proposed = Plan(2);

        var diff = NativeGitOpsDiff.Compare(accepted, proposed);
        var initial = NativeGitOpsDiff.Compare(null, Plan(1));

        await Assert.That(string.Join(',', diff.Changes.Select(change =>
            $"{change.Kind}:{change.WorkloadId}")))
            .IsEqualTo("GuardedRetirement:platform,GuardedRetirement:auth");
        await Assert.That(initial.IsNoOp).IsTrue();
    }

    private static NativeGitOpsPlan Plan(long generation, params string[] workloads) =>
        NativeGitOpsManifest.Parse(Encoding.UTF8.GetBytes($$"""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":{{generation}},"workloads":[{{string.Join(',', workloads)}}]}
            """));

    private static string Workload(
        string id,
        string role,
        string digest,
        string[]? dependsOn = null,
        bool suspended = false) => $$"""
        {"id":"{{id}}","role":"{{role}}","artifactDigest":"{{digest}}","cells":["gru"],"dependsOn":[{{string.Join(',', (dependsOn ?? []).Select(value => $"\"{value}\""))}}],"suspended":{{suspended.ToString().ToLowerInvariant()}}}
        """;

    private static NativeGitOpsDiffException Capture(Action action)
    {
        try
        {
            action();
        }
        catch (NativeGitOpsDiffException exception)
        {
            return exception;
        }
        throw new InvalidOperationException("The expected native GitOps diff error was not produced.");
    }
}

