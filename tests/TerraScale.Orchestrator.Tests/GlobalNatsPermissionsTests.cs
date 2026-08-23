using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Tests;

public sealed class GlobalNatsPermissionsTests
{
    [Test]
    public async Task CellDirectoryPublisherCanOnlyMutateItsOwnAdvertisement()
    {
        var plan = GlobalNatsPermissions.Create("sfo", GlobalNatsRole.CellDirectoryPublisher);

        await Assert.That(Allows(plan.Publish, "$KV.GLOBAL_CELLS.cell.sfo")).IsTrue();
        await Assert.That(Allows(plan.Publish, "$KV.GLOBAL_CELLS.cell.gru")).IsFalse();
        await Assert.That(Allows(plan.Publish, "$KV.ORCH_LEADERS.global")).IsFalse();
        await Assert.That(Allows(plan.Publish, "$KV.GLOBAL_RELEASES.release.42")).IsFalse();
        await Assert.That(Allows(plan.Publish, "$KV.CI_RUNNER_JOBS.ci.runner.bad.job.42")).IsFalse();
        await Assert.That(Allows(plan.Publish, "$O.GLOBAL_BUNDLES.C.digest")).IsFalse();
        await Assert.That(Allows(plan.Publish, "ts.orch.v1.global.desired.gitops.sfo")).IsFalse();
        await Assert.That(Allows(plan.Publish, "ts.orch.v1.global.ci.forgejo")).IsFalse();
    }

    [Test]
    public async Task CellDirectoryPublisherCanReadTheDirectoryAndCallItsReadOnlyService()
    {
        var plan = GlobalNatsPermissions.Create("sfo", GlobalNatsRole.CellDirectoryPublisher);

        var requiredPublish = new[]
        {
            "$JS.API.STREAM.INFO.KV_GLOBAL_CELLS",
            "$JS.API.DIRECT.GET.KV_GLOBAL_CELLS",
            "$JS.API.DIRECT.GET.KV_GLOBAL_CELLS.$KV.GLOBAL_CELLS.cell.gru",
            "$JS.API.CONSUMER.CREATE.KV_GLOBAL_CELLS.ordered.$KV.GLOBAL_CELLS.cell.gru",
            "$JS.FC.KV_GLOBAL_CELLS.ordered",
            GlobalNatsTopology.CellDirectorySubject,
        };
        foreach (var subject in requiredPublish)
            await Assert.That(Allows(plan.Publish, subject)).IsTrue();

        await Assert.That(Allows(plan.Subscribe, "_INBOX.directory.reply")).IsTrue();
        await Assert.That(Allows(plan.Subscribe, "$KV.GLOBAL_CELLS.cell.gru")).IsTrue();
    }

    [Test]
    public async Task CellDirectoryReaderCanOnlyRequestTheReadOnlyProjection()
    {
        var plan = GlobalNatsPermissions.Create("fra", GlobalNatsRole.CellDirectoryReader);

        await Assert.That(Allows(plan.Publish, GlobalNatsTopology.CellDirectorySubject)).IsTrue();
        await Assert.That(Allows(plan.Subscribe, "_INBOX.directory.reply")).IsTrue();
        await Assert.That(Allows(plan.Publish, "$KV.GLOBAL_CELLS.cell.fra")).IsFalse();
        await Assert.That(Allows(plan.Publish, "$KV.GLOBAL_CELLS.cell.gru")).IsFalse();
        await Assert.That(Allows(plan.Subscribe, "$KV.GLOBAL_CELLS.cell.fra")).IsFalse();
    }

    [Test]
    public async Task CellDirectoryServiceCanOnlyReceiveQueriesAndSendReplies()
    {
        var plan = GlobalNatsPermissions.Create("gru", GlobalNatsRole.CellDirectoryService);

        await Assert.That(Allows(plan.Subscribe, GlobalNatsTopology.CellDirectorySubject)).IsTrue();
        await Assert.That(Allows(plan.Subscribe, "$SRV.PING")).IsTrue();
        await Assert.That(Allows(plan.Subscribe, "$SRV.INFO.terrascale-global-cell-directory-gru")).IsTrue();
        await Assert.That(Allows(plan.Subscribe, "$SRV.STATS.terrascale-global-cell-directory-gru.instance")).IsTrue();
        await Assert.That(Allows(plan.Publish, "_INBOX.directory.reply")).IsTrue();
        await Assert.That(Allows(plan.Publish, GlobalNatsTopology.CellDirectorySubject)).IsFalse();
        await Assert.That(Allows(plan.Publish, "$KV.GLOBAL_CELLS.cell.gru")).IsFalse();
        await Assert.That(Allows(plan.Subscribe, "$KV.GLOBAL_CELLS.cell.gru")).IsFalse();
    }

    [Test]
    [Arguments("")]
    [Arguments("SFO")]
    [Arguments("-sfo")]
    [Arguments("sfo-")]
    [Arguments("sfo.us")]
    public async Task InvalidCellIsRejectedBeforePermissionsAreGenerated(string cell)
    {
        await Assert.That(() => GlobalNatsPermissions.Create(
                cell,
                GlobalNatsRole.CellDirectoryPublisher))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task GeneratedPatternsDoNotGrantAnotherCellThroughAWildcard()
    {
        var plan = GlobalNatsPermissions.Create("sfo", GlobalNatsRole.CellDirectoryPublisher);

        await Assert.That(plan.Publish).DoesNotContain("$KV.GLOBAL_CELLS.>");
        await Assert.That(plan.Publish).DoesNotContain("$KV.>");
        await Assert.That(plan.Publish).DoesNotContain("$JS.API.CONSUMER.DELETE.KV_GLOBAL_CELLS.>");
        await Assert.That(plan.Publish).DoesNotContain(">");
        foreach (var pattern in plan.Publish.Concat(plan.Subscribe))
            await Assert.That(SubjectPermissionPattern.TryParse(
                    pattern,
                    Limits(),
                    out _,
                    out _))
                .IsTrue();
    }

    private static bool Allows(IEnumerable<string> patterns, string subject)
    {
        if (!ConcreteSubject.TryParse(subject, Limits(), out var concrete, out _)) return false;
        return patterns.Any(pattern =>
            SubjectPermissionPattern.TryParse(pattern, Limits(), out var parsed, out _) &&
            parsed!.Matches(concrete));
    }

    private static SubjectGrammarLimits Limits()
    {
        SubjectGrammarLimits.TryCreate(2048, 64, 512, 32, out var limits);
        return limits!;
    }
}
