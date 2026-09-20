using TerraScale.Orchestrator.Scheduler.Autoscaling;

namespace TerraScale.Orchestrator.Scheduler.Tests;

public sealed class IndependentWorkloadAutoscalerTests
{
    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task Provider_failure_in_one_workload_does_not_stop_the_other(bool failObservation)
    {
        var driver = new FailingWorkloadDriver(failObservation);
        var runtime = new IndependentWorkloadAutoscalerRuntime(new([
            new("terrabase", "terrabase-member", 3, 9, scaleUpConfirmTicks: 1),
            new("ts-auth", "authentication", 1, 8, scaleUpConfirmTicks: 1)
        ]), driver);

        var decisions = await runtime.StepAsync();

        await Assert.That(decisions.Single(value => value.WorkloadId == "terrabase").Action)
            .IsEqualTo(WorkloadScaleAction.Blocked);
        await Assert.That(decisions.Single(value => value.WorkloadId == "terrabase").Reason)
            .IsEqualTo(failObservation ? "observation-missing" : "provider-apply-failed");
        await Assert.That(decisions.Single(value => value.WorkloadId == "ts-auth").Action)
            .IsEqualTo(WorkloadScaleAction.ScaleOut);
        await Assert.That(driver.Applied.Contains("ts-auth")).IsTrue();
    }

    [Test]
    public async Task Missing_observation_resets_only_its_workload_confirmation_window()
    {
        var scaler = new IndependentWorkloadAutoscaler([
            new("ts-auth", "authentication", 1, 8, scaleUpConfirmTicks: 2)
        ]);
        scaler.Tick([new("ts-auth", 2, 1, 1, 0, true)]);
        scaler.Tick([]);
        var resumed = scaler.Tick([new("ts-auth", 2, 1, 1, 0, true)]).Single();
        await Assert.That(resumed.Action).IsEqualTo(WorkloadScaleAction.Hold);
        await Assert.That(resumed.Reason).IsEqualTo("scale-up-confirming");
    }

    [Test]
    public async Task Cancellation_stops_the_runtime_without_provider_mutations()
    {
        var driver = new FailingWorkloadDriver(false);
        var runtime = new IndependentWorkloadAutoscalerRuntime(new([
            new("ts-auth", "authentication", 1, 8, scaleUpConfirmTicks: 1)
        ]), driver);
        using var stopping = new CancellationTokenSource();
        stopping.Cancel();
        await Assert.That(async () => { _ = await runtime.StepAsync(stopping.Token); })
            .Throws<OperationCanceledException>();
        await Assert.That(driver.Applied.Count).IsEqualTo(0);
    }

    [Test]
    public async Task TsAuth_and_terrabase_keep_separate_confirmation_state_and_targets()
    {
        var scaler = new IndependentWorkloadAutoscaler([
            new WorkloadScalePolicy("ts-auth", "authentication", 2, 8, scaleUpConfirmTicks: 2, scaleDownConfirmTicks: 2),
            new WorkloadScalePolicy("terrabase", "terrabase-member", 3, 9, scaleUpConfirmTicks: 3, scaleDownConfirmTicks: 2)
        ]);

        var first = scaler.Tick([
            new("ts-auth", 4, 1, 1, 0, false),
            new("terrabase", 3, 3, 3, 0, true)
        ]);
        var second = scaler.Tick([
            new("ts-auth", 4, 1, 1, 0, false),
            new("terrabase", 3, 3, 3, 0, true)
        ]);
        var third = scaler.Tick([
            new("ts-auth", 4, 1, 1, 0, false),
            new("terrabase", 5, 3, 3, 0, true)
        ]);

        await Assert.That(first.Single(value => value.WorkloadId == "ts-auth").Action)
            .IsEqualTo(WorkloadScaleAction.Hold);
        await Assert.That(second.Single(value => value.WorkloadId == "ts-auth").Action)
            .IsEqualTo(WorkloadScaleAction.ScaleOut);
        await Assert.That(second.Single(value => value.WorkloadId == "terrabase").Action)
            .IsEqualTo(WorkloadScaleAction.Hold);
        await Assert.That(third.Single(value => value.WorkloadId == "terrabase").Action)
            .IsEqualTo(WorkloadScaleAction.Hold);
        await Assert.That(second.Single(value => value.WorkloadId == "ts-auth").TargetReplicas)
            .IsEqualTo(2);
    }

    [Test]
    public async Task Pending_provider_operation_blocks_scale_in_and_policy_bounds_fail_closed()
    {
        var scaler = new IndependentWorkloadAutoscaler([
            new WorkloadScalePolicy("ts-auth", "authentication", 2, 4, scaleUpConfirmTicks: 1, scaleDownConfirmTicks: 1)
        ]);

        var pending = scaler.Tick([new("ts-auth", 2, 4, 4, 1, true)]).Single();
        var outOfBounds = scaler.Tick([new("ts-auth", 8, 4, 4, 0, true)]).Single();

        await Assert.That(pending.Action).IsEqualTo(WorkloadScaleAction.Hold);
        await Assert.That(pending.Reason).IsEqualTo("provider-operation-pending");
        await Assert.That(outOfBounds.Action).IsEqualTo(WorkloadScaleAction.Blocked);
        await Assert.That(outOfBounds.Reason).IsEqualTo("desired-replicas-out-of-policy");
        await Assert.That(outOfBounds.TargetReplicas).IsEqualTo(4);
    }

    private sealed class FailingWorkloadDriver(bool failObservation) : IWorkloadReplicaDriver
    {
        internal List<string> Applied { get; } = [];

        public Task<WorkloadScaleObservation> ObserveAsync(WorkloadScalePolicy policy, CancellationToken cancellationToken)
        {
            if (policy.WorkloadId == "terrabase" && failObservation)
                throw new IOException("provider observation unavailable");
            return Task.FromResult(new WorkloadScaleObservation(policy.WorkloadId, policy.MinReplicas + 1,
                policy.MinReplicas, policy.MinReplicas, 0, true));
        }

        public Task ApplyAsync(WorkloadScaleDecision decision, CancellationToken cancellationToken)
        {
            if (decision.WorkloadId == "terrabase") throw new IOException("provider mutation unavailable");
            Applied.Add(decision.WorkloadId);
            return Task.CompletedTask;
        }
    }
}
