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
        };
        foreach (var subject in requiredPublish)
            await Assert.That(Allows(plan.Publish, subject)).IsTrue();

        await Assert.That(Allows(plan.Subscribe, "_INBOX.directory.reply")).IsTrue();
        await Assert.That(Allows(plan.Subscribe, "$KV.GLOBAL_CELLS.cell.gru")).IsTrue();
    }

    [Test]
    public async Task CellDirectoryPublisherNeverPublishesTheReadOnlyQuerySubject()
    {
        var plan = GlobalNatsPermissions.Create("sfo", GlobalNatsRole.CellDirectoryPublisher);

        // Only the GRU directory service answers the query subject (the reader requests,
        // the service replies); the publisher's advertisement path never publishes it.
        await Assert.That(Allows(plan.Publish, GlobalNatsTopology.CellDirectorySubject)).IsFalse();
        var service = GlobalNatsPermissions.Create("gru", GlobalNatsRole.CellDirectoryService);
        await Assert.That(Allows(service.Publish, GlobalNatsTopology.CellDirectorySubject)).IsFalse();
        var reader = GlobalNatsPermissions.Create("gru", GlobalNatsRole.CellDirectoryReader);
        await Assert.That(Allows(reader.Publish, GlobalNatsTopology.CellDirectorySubject)).IsTrue();
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
        await Assert.That(Allows(plan.Publish, "_R_.directory.reply")).IsTrue();
        await Assert.That(Allows(plan.Publish, GlobalNatsTopology.CellDirectorySubject)).IsFalse();
        await Assert.That(Allows(plan.Publish, "$KV.GLOBAL_CELLS.cell.gru")).IsFalse();
        await Assert.That(Allows(plan.Subscribe, "$KV.GLOBAL_CELLS.cell.gru")).IsFalse();

        var reader = GlobalNatsPermissions.Create("gru", GlobalNatsRole.CellDirectoryReader);
        var publisher = GlobalNatsPermissions.Create("gru", GlobalNatsRole.CellDirectoryPublisher);
        await Assert.That(Allows(reader.Publish, "_R_.directory.reply")).IsFalse();
        await Assert.That(Allows(publisher.Publish, "_R_.directory.reply")).IsFalse();
    }

    [Test]
    public async Task GlobalAuthorityCanReconcileOnlyTheGlobalTopologyAndDeliverySubjects()
    {
        var topology = new GlobalNatsTopology(3);
        var plan = GlobalNatsPermissions.Create("gru", GlobalNatsRole.GlobalAuthority);
        var streams = topology.Streams
            .SelectMany(stream => new[]
            {
                $"$JS.API.STREAM.CREATE.{stream.Name}",
                $"$JS.API.STREAM.UPDATE.{stream.Name}",
                $"$JS.API.STREAM.INFO.{stream.Name}",
            });
        var keyValueStores = new[]
        {
            topology.Leaders.Bucket,
            topology.Releases.Bucket,
            topology.RunnerJobs.Bucket,
        }.SelectMany(bucket => new[]
        {
            $"$JS.API.STREAM.CREATE.KV_{bucket}",
            $"$JS.API.STREAM.UPDATE.KV_{bucket}",
            $"$JS.API.STREAM.INFO.KV_{bucket}",
            $"$JS.API.DIRECT.GET.KV_{bucket}",
        });
        var objectStores = new[] { topology.Bundles, topology.RunnerBundles }
            .SelectMany(store => new[]
            {
                $"$JS.API.STREAM.CREATE.OBJ_{store.Bucket}",
                $"$JS.API.STREAM.UPDATE.OBJ_{store.Bucket}",
                $"$JS.API.STREAM.INFO.OBJ_{store.Bucket}",
                $"$JS.API.STREAM.PURGE.OBJ_{store.Bucket}",
                $"$JS.API.STREAM.MSG.GET.OBJ_{store.Bucket}",
                $"$JS.API.DIRECT.GET.OBJ_{store.Bucket}",
                $"$JS.FC.OBJ_{store.Bucket}.flow",
                $"$O.{store.Bucket}.C.digest",
                $"$O.{store.Bucket}.M.digest",
            });
        var consumers = new[]
        {
            (GlobalNatsTopology.CiStream, topology.CiConsumer),
            (GlobalNatsTopology.CiStream, topology.CiRuntimeProofConsumer),
            (GlobalNatsTopology.CellSpecStream, topology.CellSpecConsumer("gru")),
        }.SelectMany(item => new[]
        {
            $"$JS.API.CONSUMER.CREATE.{item.Item1}.{item.Item2.Name}",
            $"$JS.API.CONSUMER.CREATE.{item.Item1}.{item.Item2.Name}.{item.Item2.FilterSubject}",
            $"$JS.API.CONSUMER.DURABLE.CREATE.{item.Item1}.{item.Item2.Name}",
            $"$JS.API.CONSUMER.DURABLE.CREATE.{item.Item1}.{item.Item2.Name}.{item.Item2.FilterSubject}",
            $"$JS.API.CONSUMER.INFO.{item.Item1}.{item.Item2.Name}",
            $"$JS.API.CONSUMER.MSG.NEXT.{item.Item1}.{item.Item2.Name}",
            $"$JS.ACK.{item.Item1}.{item.Item2.Name}.sequence",
            $"$JS.FC.{item.Item1}.{item.Item2.Name}.flow",
        });
        var requiredPublish = streams
            .Concat(keyValueStores)
            .Concat(objectStores)
            .Concat(consumers)
            .Concat(new[]
            {
                "$KV.ORCH_LEADERS.authority.global",
                "$KV.GLOBAL_RELEASES.release.42",
                "$KV.CI_RUNNER_JOBS.ci.runner.42.job.17",
                GlobalNatsTopology.CiSubject,
                GlobalNatsTopology.CellSpecSubject("sfo"),
                GlobalNatsTopology.CiJobSubject("untrusted-product", "runner-static"),
                GlobalNatsTopology.CiJobSubject("trusted-build", "runner-static"),
                // Key enumeration (NatsForgejoDeliveryLedger.ListKeysAsync -> GetKeysAsync)
                // creates an ephemeral ordered consumer and receives on an inbox: exactly
                // these consumer-create publish forms are required, and nothing else in
                // the watch shape (durable/pull/ack/flow-control) is ever exercised. The
                // literal trailing filter token carries the caller's wildcard (e.g.
                // "...ephemeral.$KV.GLOBAL_RELEASES.release.>"), which the wildcard-free
                // suffix below represents within the concrete subject grammar.
                "$JS.API.CONSUMER.CREATE.KV_GLOBAL_RELEASES",
                "$JS.API.CONSUMER.CREATE.KV_GLOBAL_RELEASES.ephemeral-enumeration.$KV.GLOBAL_RELEASES.release.alpha.1",
                $"$JS.API.CONSUMER.CREATE.GLOBAL_CI.ci_runner_untrusted_product_abc123.{GlobalNatsTopology.CiJobSubjectPrefix}.untrusted-product.abc123",
                "$JS.API.CONSUMER.INFO.GLOBAL_CI.ci_runner_untrusted_product_abc123",
                "$JS.API.CONSUMER.MSG.NEXT.GLOBAL_CI.ci_runner_untrusted_product_abc123",
                "$JS.ACK.GLOBAL_CI.ci_runner_untrusted_product_abc123.sequence",
                "$JS.FC.GLOBAL_CI.ci_runner_untrusted_product_abc123.flow",
            });
        foreach (var subject in requiredPublish)
            await Assert.That(Allows(plan.Publish, subject)).IsTrue();

        // Enumeration is inbox-delivered: the authority's only subscription is its inbox,
        // with no $KV.* subscription on its own buckets.
        await Assert.That(plan.Subscribe).IsEquivalentTo(["_INBOX.>"]);
        await Assert.That(Allows(plan.Subscribe, "_INBOX.global.reply")).IsTrue();
        foreach (var subject in new[]
                 {
                     "$KV.GLOBAL_RELEASES.release.42",
                     "$KV.CI_RUNNER_JOBS.ci.runner.hash.job.17",
                     "$KV.GLOBAL_CELLS.cell.gru",
                 })
            await Assert.That(Allows(plan.Subscribe, subject)).IsFalse();
        foreach (var subject in new[]
                 {
                     "$KV.GLOBAL_CELLS.cell.gru",
                     "$KV.ORCH_RUNTIME.runtime.protected",
                     "$KV.ORCH_OPERATIONS.operation.protected",
                     "$KV.ORCH_OPERATION_PROOFS.proof.protected",
                     "$JS.API.STREAM.INFO.CELL_SPEC",
                     "$JS.API.STREAM.PURGE.OBJ_GLOBAL_SPEC",
                     "$JS.API.OTHER.GLOBAL_CI",
                     "$JS.API.STREAM.CREATE.UNRELATED",
                     "ts.orch.v1.sfo.desired.gitops.sfo",
                     "ts.orch.v1.global.ci.job.production-release.hash",
                     "ts.orch.v1.global.ci.job.untrusted-product.hash.extra",
                     "$KV.CI_RUNNER_JOBS.ci.other.hash.job.17",
                     "$KV.CI_RUNNER_JOBS.ci.runner.hash.other.17",
                     "$KV.CI_RUNNER_JOBS.other.runner.hash.job.17",
                     // Unused watch shapes stay ungranted: enumeration never creates
                     // durable consumers, never pulls, never acks, and never answers
                     // flow control on the releases bucket.
                     "$JS.API.CONSUMER.DURABLE.CREATE.KV_GLOBAL_RELEASES.retention-watch",
                     "$JS.API.CONSUMER.INFO.KV_GLOBAL_RELEASES.retention-watch",
                     "$JS.API.CONSUMER.MSG.NEXT.KV_GLOBAL_RELEASES.retention-watch",
                     "$JS.ACK.KV_GLOBAL_RELEASES.retention-watch.sequence",
                     "$JS.FC.KV_GLOBAL_RELEASES.retention-watch.flow",
                     "$JS.API.CONSUMER.CREATE.KV_GLOBAL_CELLS.retention-watch",
                     "$JS.FC.KV_GLOBAL_CELLS.retention-watch.flow",
                     "$JS.API.CONSUMER.CREATE.GLOBAL_CI.ci_runner_untrusted_product_abc123.ts.orch.v1.global.ci.forgejo",
                     "$JS.API.CONSUMER.CREATE.GLOBAL_SPEC.ci_runner_untrusted_product_abc123.ts.orch.v1.global.ci.job.untrusted-product.abc123",
                 })
            await Assert.That(Allows(plan.Publish, subject)).IsFalse();

        await Assert.That(plan.Publish).DoesNotContain("$JS.API.>");
        await Assert.That(plan.Publish).DoesNotContain("$KV.CI_RUNNER_JOBS.>");
        await Assert.That(plan.Publish)
            .DoesNotContain($"{GlobalNatsTopology.CiJobSubjectPrefix}.*.*");
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
