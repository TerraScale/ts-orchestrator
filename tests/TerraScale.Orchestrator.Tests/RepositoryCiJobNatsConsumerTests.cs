using Microsoft.Extensions.Primitives;
using NATS.Client.Core;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiJobNatsConsumerTests
{
    [Test]
    public async Task RunnerMetadataRequiresTheExactConsumerStreamSubjectAndBounds()
    {
        var configuration = new GlobalNatsTopology(3)
            .CiJobConsumer("untrusted-product", "runner-static");
        var valid = new RepositoryCiJobMessageMetadata(
            configuration.FilterSubject!,
            GlobalNatsTopology.CiStream,
            configuration.Name!,
            41,
            1,
            1,
            RepositoryCiJobWireCodec.MaximumWireBytes);

        await Assert.That(RepositoryCiJobNatsConsumer.ValidMetadata(valid, configuration)).IsTrue();
        await Assert.That(RepositoryCiJobNatsConsumer.ValidMetadata(
            valid with { Subject = GlobalNatsTopology.CiJobSubject("untrusted-product", "runner-other") },
            configuration)).IsFalse();
        await Assert.That(RepositoryCiJobNatsConsumer.ValidMetadata(
            valid with { Stream = "GLOBAL_SPEC" }, configuration)).IsFalse();
        await Assert.That(RepositoryCiJobNatsConsumer.ValidMetadata(
            valid with { Consumer = "ci_runner_other" }, configuration)).IsFalse();
        await Assert.That(RepositoryCiJobNatsConsumer.ValidMetadata(
            valid with { StreamSequence = 0 }, configuration)).IsFalse();
        await Assert.That(RepositoryCiJobNatsConsumer.ValidMetadata(
            valid with { ConsumerSequence = 0 }, configuration)).IsFalse();
        await Assert.That(RepositoryCiJobNatsConsumer.ValidMetadata(
            valid with { DeliveryCount = 6 }, configuration)).IsFalse();
        await Assert.That(RepositoryCiJobNatsConsumer.ValidMetadata(
            valid with { MessageSize = RepositoryCiJobWireCodec.MaximumWireBytes + 1 },
            configuration)).IsFalse();
    }

    [Test]
    public async Task RepeatedHeadersRemainVisibleAndFlatteningStopsAtOneBeyondTheContract()
    {
        var repeated = new NatsHeaders
        {
            { "TS-Runner-Id", new StringValues(["runner-static", "runner-other"]) },
            { "TS-Protocol-Version", "1" },
        };
        var flattened = RepositoryCiJobNatsConsumer.Flatten(repeated);
        var excessive = new NatsHeaders();
        for (var index = 0; index < 32; index++) excessive.Add($"X-{index}", index.ToString());
        var bounded = RepositoryCiJobNatsConsumer.Flatten(excessive);

        await Assert.That(flattened.Count).IsEqualTo(3);
        await Assert.That(flattened.Count(item => item.Key == "TS-Runner-Id")).IsEqualTo(2);
        await Assert.That(bounded.Count).IsEqualTo(RepositoryCiJobWireCodec.ExpectedHeaderCount + 1);
    }

    [Test]
    public async Task LongExecutionRenewsItsDeliveryUntilTheCoordinatorReturns()
    {
        var completed = new TaskCompletionSource<CiRunnerExecutionCoordinatorReceipt>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var progress = 0;

        var receipt = await RepositoryCiJobNatsConsumer.ExecuteWithProgressAsync(
            _ => completed.Task,
            _ =>
            {
                progress++;
                completed.TrySetResult(Completed());
                return Task.CompletedTask;
            },
            TimeSpan.FromMilliseconds(1),
            default);

        await Assert.That(progress).IsGreaterThanOrEqualTo(1);
        await Assert.That(receipt.Disposition).IsEqualTo(CiRunnerExecutionCoordinatorDisposition.Completed);
    }

    [Test]
    public async Task ProgressFailureCancelsExecutionAndCannotReturnAResult()
    {
        var canceled = false;

        await Assert.That(async () => await RepositoryCiJobNatsConsumer.ExecuteWithProgressAsync(
                async token =>
                {
                    try
                    {
                        await Task.Delay(Timeout.InfiniteTimeSpan, token);
                    }
                    catch (OperationCanceledException)
                    {
                        canceled = true;
                        throw;
                    }
                    throw new InvalidOperationException();
                },
                _ => throw new IOException("simulated progress failure"),
                TimeSpan.FromMilliseconds(1),
                default))
            .Throws<InvalidDataException>();
        await Assert.That(canceled).IsTrue();
    }

    [Test]
    public async Task LeaseRecoveryWaitsUntilTheExistingExecutionSettles()
    {
        var receipts = new Queue<CiRunnerExecutionCoordinatorReceipt>(
        [
            Pending(RepositoryCiJobExecutionDisposition.LeaseHeld),
            Pending(RepositoryCiJobExecutionDisposition.Contention),
            Completed(),
        ]);
        var waits = 0;

        var result = await RepositoryCiJobNatsConsumer.ExecuteUntilSettledAsync(
            _ => Task.FromResult(receipts.Dequeue()),
            _ =>
            {
                waits++;
                return Task.CompletedTask;
            },
            maximumWaits: 10);

        await Assert.That(result.Disposition).IsEqualTo(CiRunnerExecutionCoordinatorDisposition.Completed);
        await Assert.That(waits).IsEqualTo(2);
        await Assert.That(receipts).IsEmpty();
    }

    [Test]
    public async Task RecoveryWatchYieldsTheDeliveryAfterItsBound()
    {
        var executions = 0;
        var waits = 0;

        var result = await RepositoryCiJobNatsConsumer.ExecuteUntilSettledAsync(
            _ =>
            {
                executions++;
                return Task.FromResult(Pending(RepositoryCiJobExecutionDisposition.LeaseHeld));
            },
            _ =>
            {
                waits++;
                return Task.CompletedTask;
            },
            maximumWaits: 2);

        await Assert.That(result.ExecutionDisposition)
            .IsEqualTo(RepositoryCiJobExecutionDisposition.LeaseHeld);
        await Assert.That(executions).IsEqualTo(3);
        await Assert.That(waits).IsEqualTo(2);
    }

    [Test]
    public async Task UnsafeAcquisitionFailureIsNotRetriedBlindly()
    {
        var waits = 0;

        var result = await RepositoryCiJobNatsConsumer.ExecuteUntilSettledAsync(
            _ => Task.FromResult(Pending(RepositoryCiJobExecutionDisposition.IdentityConflict)),
            _ =>
            {
                waits++;
                return Task.CompletedTask;
            },
            maximumWaits: 10);

        await Assert.That(result.ExecutionDisposition)
            .IsEqualTo(RepositoryCiJobExecutionDisposition.IdentityConflict);
        await Assert.That(waits).IsEqualTo(0);
    }

    private static CiRunnerExecutionCoordinatorReceipt Completed() => new(
        CiRunnerExecutionCoordinatorDisposition.Completed,
        RepositoryCiJobExecutionDisposition.Completed,
        null,
        new string('a', 64));

    private static CiRunnerExecutionCoordinatorReceipt Pending(
        RepositoryCiJobExecutionDisposition disposition) => new(
        CiRunnerExecutionCoordinatorDisposition.NotAcquired,
        disposition,
        null,
        string.Empty);
}

