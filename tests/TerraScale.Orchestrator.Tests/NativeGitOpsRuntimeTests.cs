using TerraScale.Orchestrator.Messaging;
using System.Reflection;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsRuntimeTests
{
    [Test]
    public async Task SameEpochLeaseRenewalRemainsValidButRegressionAndLeadershipLossFailClosed()
    {
        var capturedGlobal = Snapshot("leader", true, epoch: 9, revision: 14);
        var capturedRegional = Snapshot("leader", true, epoch: 7, revision: 21);

        await Assert.That(NativeGitOpsRuntime.SameGlobalAuthority(
            capturedGlobal, capturedGlobal with { KvRevision = 15 })).IsTrue();
        await Assert.That(NativeGitOpsRuntime.SameRegionalLeaderAuthority(
            capturedRegional, capturedRegional with { KvRevision = 22 })).IsTrue();
        await Assert.That(NativeGitOpsRuntime.SameGlobalAuthority(
            capturedGlobal, capturedGlobal with { KvRevision = 13 })).IsFalse();
        await Assert.That(NativeGitOpsRuntime.SameGlobalAuthority(
            capturedGlobal, capturedGlobal with { IsLeader = false, KvRevision = 15 })).IsFalse();
        await Assert.That(NativeGitOpsRuntime.SameRegionalLeaderAuthority(
            capturedRegional, capturedRegional with { IsLeader = false, KvRevision = 22 })).IsFalse();
        await Assert.That(NativeGitOpsRuntime.SameGlobalAuthority(
            capturedGlobal, capturedGlobal with { Epoch = 10, KvRevision = 15 })).IsFalse();
    }

    [Test]
    public async Task WorkerFailureCancelsSiblingAndFaultsComposition()
    {
        var siblingCancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        await Assert.That(async () => await NativeGitOpsRuntime.RunWorkersAsync(
                _ => throw new InvalidDataException("relay failed"),
                async token =>
                {
                    try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
                    catch (OperationCanceledException) when (token.IsCancellationRequested)
                    {
                        siblingCancelled.SetResult(true);
                        throw;
                    }
                },
                CancellationToken.None))
            .Throws<InvalidDataException>();
        await siblingCancelled.Task.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Test]
    public async Task UnexpectedSuccessfulWorkerExitCancelsSiblingAndFaultsComposition()
    {
        var siblingCancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        var failure = await Assert.That(async () => await NativeGitOpsRuntime.RunWorkersAsync(
                _ => Task.CompletedTask,
                async token =>
                {
                    try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
                    catch (OperationCanceledException) when (token.IsCancellationRequested)
                    {
                        siblingCancelled.SetResult(true);
                        throw;
                    }
                },
                CancellationToken.None))
            .Throws<InvalidOperationException>();
        await Assert.That(failure!.Message).Contains("terminated");
        await siblingCancelled.Task.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Test]
    public async Task CompositionHasNoProjectorAssignmentOrExecutorDependency()
    {
        var runtime = typeof(NativeGitOpsRuntime);
        var dependencyNames = runtime.GetFields(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
            .Select(static field => field.FieldType.FullName)
            .Concat(runtime.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
                .SelectMany(static method => method.GetParameters().Select(parameter => parameter.ParameterType.FullName)
                    .Append(method.ReturnType.FullName)))
            .Where(static name => name is not null)
            .ToArray();

        await Assert.That(dependencyNames.Any(static name =>
            name!.Contains("RuntimeHostAssignment", StringComparison.Ordinal) ||
            name.Contains("NativeGitOpsCellRuntimeProjector", StringComparison.Ordinal) ||
            name.Contains("RuntimeLifecycleCoordinator", StringComparison.Ordinal) ||
            name.Contains("Executor", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task NativeCompositionIsDisabledWithoutGlobalOrVerifierAndRejectsUnsignedPublication()
    {
        await Assert.That(NativeGitOpsRuntime.IsEnabled(false, false)).IsFalse();
        await Assert.That(NativeGitOpsRuntime.IsEnabled(true, false)).IsFalse();
        await Assert.That(NativeGitOpsRuntime.IsEnabled(false, true)).IsFalse();
        // A verifier-only regional controller can consume an externally signed global handoff.
        await Assert.That(NativeGitOpsRuntime.IsEnabled(true, true)).IsTrue();
        await Assert.That(() => NativeGitOpsRuntime.ValidateConfiguration(true, true, false))
            .Throws<InvalidOperationException>();
        await Assert.That(() => NativeGitOpsRuntime.ValidateConfiguration(true, false, false))
            .ThrowsNothing();
    }

    private static RegionalAuthoritySnapshot Snapshot(
        string state,
        bool leader,
        long epoch,
        long revision) => new(
        state,
        leader,
        epoch,
        revision,
        DateTimeOffset.UtcNow.AddMinutes(1),
        DateTimeOffset.UtcNow,
        null);
}

