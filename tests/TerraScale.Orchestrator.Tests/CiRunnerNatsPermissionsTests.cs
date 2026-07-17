using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Tests;

public sealed class CiRunnerNatsPermissionsTests
{
    [Test]
    public async Task RunnerIdentityCanOnlyPullItsConsumerAndJournalInTheRunnerBuckets()
    {
        var topology = new GlobalNatsTopology(3);
        var plan = CiRunnerNatsPermissions.Create(topology, "untrusted-product", "runner-static");
        var other = CiRunnerNatsPermissions.Create(topology, "untrusted-product", "runner-other");
        var prefix = GlobalNatsTopology.CiRunnerJournalPrefix("runner-static");

        var allowedPublish = new[]
        {
            $"$JS.API.CONSUMER.INFO.GLOBAL_CI.{plan.Consumer}",
            $"$JS.API.CONSUMER.MSG.NEXT.GLOBAL_CI.{plan.Consumer}",
            $"$JS.ACK.GLOBAL_CI.{plan.Consumer}.1.2.3.4.5",
            $"$KV.CI_RUNNER_JOBS.{prefix}.0123456789abcdef",
            $"$JS.API.DIRECT.GET.KV_CI_RUNNER_JOBS.$KV.CI_RUNNER_JOBS.{prefix}.0123456789abcdef",
            "$JS.API.STREAM.INFO.KV_CI_RUNNER_JOBS",
            "$JS.API.STREAM.INFO.OBJ_CI_RUNNER_BUNDLES",
            "$JS.API.DIRECT.GET.OBJ_CI_RUNNER_BUNDLES",
            "$JS.API.CONSUMER.CREATE.OBJ_CI_RUNNER_BUNDLES.2w4hQG7S3B9dP1fK6mNxZa.$O.CI_RUNNER_BUNDLES.C.7xN3kLmP9qRsT2vW4yZaBc",
            "$JS.API.CONSUMER.DELETE.OBJ_CI_RUNNER_BUNDLES.2w4hQG7S3B9dP1fK6mNxZa",
            "$JS.FC.OBJ_CI_RUNNER_BUNDLES.7xN3kLmP9qRsT2vW4yZaBc",
            "$O.CI_RUNNER_BUNDLES.C.2w4hQG7S3B9dP1fK6mNxZa",
            "$O.CI_RUNNER_BUNDLES.M.Y2ktam9iLWNvbW1hbmQ",
        };
        foreach (var subject in allowedPublish)
            await Assert.That(Allows(plan.Publish, subject)).IsTrue();
        await Assert.That(Allows(plan.Subscribe, "_INBOX.runner.reply")).IsTrue();

        var deniedPublish = new[]
        {
            plan.FilterSubject,
            $"$JS.API.CONSUMER.MSG.NEXT.GLOBAL_CI.{other.Consumer}",
            $"$KV.CI_RUNNER_JOBS.{GlobalNatsTopology.CiRunnerJournalPrefix("runner-other")}.0123456789abcdef",
            "$O.GLOBAL_BUNDLES.M.Z2xvYmFsLXBsYW4",
            "$JS.API.STREAM.PURGE.OBJ_CI_RUNNER_BUNDLES",
            "$JS.API.CONSUMER.CREATE.GLOBAL_CI.injected.ts.orch.v1.global.ci.job.untrusted-product.bad",
        };
        foreach (var subject in deniedPublish)
            await Assert.That(Allows(plan.Publish, subject)).IsFalse();
        await Assert.That(Allows(plan.Subscribe, plan.FilterSubject)).IsFalse();
    }

    [Test]
    public async Task EveryGeneratedPermissionIsAValidBoundedNatsPattern()
    {
        var plan = CiRunnerNatsPermissions.Create(
            new GlobalNatsTopology(3),
            "trusted-build",
            "runner-build-7");

        foreach (var pattern in plan.Publish.Concat(plan.Subscribe))
            await Assert.That(SubjectPermissionPattern.TryParse(
                pattern,
                Limits(),
                out _,
                out _)).IsTrue();
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
