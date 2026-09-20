using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.Scheduler.Autoscaling;

/// <summary>
/// Scaling policy for one admitted workload. A policy is deliberately scoped to
/// one workload id: ts-auth and TerraBase therefore carry separate bounds and
/// hysteresis state and can never scale each other as a side effect.
/// </summary>
public sealed record WorkloadScalePolicy
{
    public WorkloadScalePolicy(
        string workloadId,
        string roleKind,
        int minReplicas,
        int maxReplicas,
        int scaleUpConfirmTicks = 2,
        int scaleDownConfirmTicks = 4)
    {
        WorkloadId = AutoscalingTokens.Require(workloadId, nameof(workloadId));
        RoleKind = AutoscalingTokens.Require(roleKind, nameof(roleKind));
        if (minReplicas < 1 || minReplicas > AutoscalingTokens.MaximumReplicaCount)
            throw new ArgumentOutOfRangeException(nameof(minReplicas));
        if (maxReplicas < minReplicas || maxReplicas > AutoscalingTokens.MaximumReplicaCount)
            throw new ArgumentOutOfRangeException(nameof(maxReplicas));
        if (scaleUpConfirmTicks < 1 || scaleDownConfirmTicks < 1)
            throw new ArgumentOutOfRangeException(nameof(scaleUpConfirmTicks));

        MinReplicas = minReplicas;
        MaxReplicas = maxReplicas;
        ScaleUpConfirmTicks = scaleUpConfirmTicks;
        ScaleDownConfirmTicks = scaleDownConfirmTicks;
    }

    public string WorkloadId { get; }
    public string RoleKind { get; }
    public int MinReplicas { get; }
    public int MaxReplicas { get; }
    public int ScaleUpConfirmTicks { get; }
    public int ScaleDownConfirmTicks { get; }
}

/// <summary>One bounded observation supplied by a workload-specific provider.</summary>
public sealed record WorkloadScaleObservation
{
    public WorkloadScaleObservation(
        string workloadId,
        int desiredReplicas,
        int observedReplicas,
        int readyReplicas,
        int pendingReplicas,
        bool healthy)
    {
        WorkloadId = AutoscalingTokens.Require(workloadId, nameof(workloadId));
        if (desiredReplicas < 0 || observedReplicas < 0 || readyReplicas < 0 || pendingReplicas < 0 ||
            readyReplicas > observedReplicas)
            throw new ArgumentOutOfRangeException(nameof(desiredReplicas));

        DesiredReplicas = desiredReplicas;
        ObservedReplicas = observedReplicas;
        ReadyReplicas = readyReplicas;
        PendingReplicas = pendingReplicas;
        Healthy = healthy;
    }

    public string WorkloadId { get; }
    public int DesiredReplicas { get; }
    public int ObservedReplicas { get; }
    public int ReadyReplicas { get; }
    public int PendingReplicas { get; }
    public bool Healthy { get; }
}

public enum WorkloadScaleAction
{
    Hold = 1,
    ScaleOut = 2,
    ScaleIn = 3,
    Blocked = 4,
}

/// <summary>The independent decision for one workload, suitable for status and metrics.</summary>
public sealed record WorkloadScaleDecision(
    string WorkloadId,
    string RoleKind,
    int DesiredReplicas,
    int ObservedReplicas,
    int ReadyReplicas,
    int PendingReplicas,
    int TargetReplicas,
    WorkloadScaleAction Action,
    int ProgressPercent,
    string Reason)
{
    public void Validate()
    {
        AutoscalingTokens.Require(WorkloadId, nameof(WorkloadId));
        AutoscalingTokens.Require(RoleKind, nameof(RoleKind));
        if (!Enum.IsDefined(Action) || DesiredReplicas < 0 || ObservedReplicas < 0 || ReadyReplicas < 0 ||
            PendingReplicas < 0 || TargetReplicas < 0 || ReadyReplicas > ObservedReplicas ||
            ProgressPercent is < 0 or > 100 || string.IsNullOrWhiteSpace(Reason) || Reason.Length > 256)
            throw new InvalidOperationException("The workload scale decision is invalid.");
    }
}

/// <summary>
/// Deterministic per-workload scaler. Counters are keyed by workload id, so a
/// TerraBase placement change cannot satisfy, reset, or trigger ts-auth's
/// confirmation window. The desired replica count remains the source of truth;
/// the scaler only decides when its provider should apply that target.
/// </summary>
public sealed class IndependentWorkloadAutoscaler
{
    private readonly IReadOnlyDictionary<string, WorkloadScalePolicy> policies;
    private readonly Dictionary<string, int> scaleUpTicks = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> scaleDownTicks = new(StringComparer.Ordinal);

    public IndependentWorkloadAutoscaler(IEnumerable<WorkloadScalePolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);
        var values = policies.ToArray();
        if (values.Length is < 1 or > 64 || values.Any(static value => value is null) ||
            values.Select(static value => value.WorkloadId).Distinct(StringComparer.Ordinal).Count() != values.Length)
            throw new ArgumentException("Workload policies must be non-empty, bounded, and unique.", nameof(policies));
        this.policies = new ReadOnlyDictionary<string, WorkloadScalePolicy>(
            values.ToDictionary(static value => value.WorkloadId, StringComparer.Ordinal));
    }

    public IReadOnlyList<WorkloadScalePolicy> Policies => policies.Values
        .OrderBy(static value => value.WorkloadId, StringComparer.Ordinal)
        .ToArray();

    public IReadOnlyList<WorkloadScaleDecision> Tick(IEnumerable<WorkloadScaleObservation> observations)
    {
        ArgumentNullException.ThrowIfNull(observations);
        var values = observations.ToArray();
        var byWorkload = values.ToDictionary(static value => value.WorkloadId, StringComparer.Ordinal);
        if (byWorkload.Count != values.Length)
            throw new ArgumentException("Workload observations must be unique.", nameof(observations));

        var decisions = new List<WorkloadScaleDecision>(policies.Count);
        foreach (var policy in Policies)
        {
            if (!byWorkload.TryGetValue(policy.WorkloadId, out var observation))
            {
                Reset(policy.WorkloadId);
                decisions.Add(new(
                    policy.WorkloadId,
                    policy.RoleKind,
                    policy.MinReplicas,
                    0,
                    0,
                    0,
                    policy.MinReplicas,
                    WorkloadScaleAction.Blocked,
                    0,
                    "observation-missing"));
                continue;
            }

            var desired = Math.Clamp(observation.DesiredReplicas, policy.MinReplicas, policy.MaxReplicas);
            var readyAndPending = checked(observation.ReadyReplicas + observation.PendingReplicas);
            var progress = desired == 0
                ? 0
                : Math.Min(100, checked(observation.ReadyReplicas * 100 / desired));
            var desiredOutOfBounds = desired != observation.DesiredReplicas;
            if (desiredOutOfBounds)
            {
                Reset(policy.WorkloadId);
                decisions.Add(new(
                    policy.WorkloadId,
                    policy.RoleKind,
                    observation.DesiredReplicas,
                    observation.ObservedReplicas,
                    observation.ReadyReplicas,
                    observation.PendingReplicas,
                    desired,
                    WorkloadScaleAction.Blocked,
                    progress,
                    "desired-replicas-out-of-policy"));
                continue;
            }

            if (readyAndPending < desired)
            {
                var up = scaleUpTicks.GetValueOrDefault(policy.WorkloadId) + 1;
                scaleUpTicks[policy.WorkloadId] = up;
                scaleDownTicks.Remove(policy.WorkloadId);
                if (up >= policy.ScaleUpConfirmTicks)
                {
                    scaleUpTicks[policy.WorkloadId] = 0;
                    var target = Math.Min(desired, Math.Max(policy.MinReplicas, readyAndPending + 1));
                    var decision = new WorkloadScaleDecision(
                        policy.WorkloadId,
                        policy.RoleKind,
                        desired,
                        observation.ObservedReplicas,
                        observation.ReadyReplicas,
                        observation.PendingReplicas,
                        target,
                        WorkloadScaleAction.ScaleOut,
                        progress,
                        observation.Healthy ? "ready-replicas-below-desired" : "unhealthy-replicas-below-desired");
                    decision.Validate();
                    decisions.Add(decision);
                    continue;
                }

                decisions.Add(Hold(policy, observation, desired, progress, "scale-up-confirming"));
                continue;
            }

            scaleUpTicks.Remove(policy.WorkloadId);
            if (readyAndPending > desired && observation.PendingReplicas == 0)
            {
                var down = scaleDownTicks.GetValueOrDefault(policy.WorkloadId) + 1;
                scaleDownTicks[policy.WorkloadId] = down;
                if (down >= policy.ScaleDownConfirmTicks)
                {
                    scaleDownTicks[policy.WorkloadId] = 0;
                    var target = Math.Max(desired, policy.MinReplicas);
                    var decision = new WorkloadScaleDecision(
                        policy.WorkloadId,
                        policy.RoleKind,
                        desired,
                        observation.ObservedReplicas,
                        observation.ReadyReplicas,
                        observation.PendingReplicas,
                        target,
                        WorkloadScaleAction.ScaleIn,
                        progress,
                        "ready-replicas-above-desired");
                    decision.Validate();
                    decisions.Add(decision);
                    continue;
                }

                decisions.Add(Hold(policy, observation, desired, progress, "scale-down-confirming"));
                continue;
            }

            scaleDownTicks.Remove(policy.WorkloadId);
            decisions.Add(Hold(policy, observation, desired, progress,
                observation.PendingReplicas > 0 ? "provider-operation-pending" : "at-target"));
        }

        return decisions;
    }

    private static WorkloadScaleDecision Hold(
        WorkloadScalePolicy policy,
        WorkloadScaleObservation observation,
        int desired,
        int progress,
        string reason) => new(
            policy.WorkloadId,
            policy.RoleKind,
            desired,
            observation.ObservedReplicas,
            observation.ReadyReplicas,
            observation.PendingReplicas,
            desired,
            WorkloadScaleAction.Hold,
            progress,
            reason);

    private void Reset(string workloadId)
    {
        scaleUpTicks.Remove(workloadId);
        scaleDownTicks.Remove(workloadId);
    }
}

/// <summary>Provider seam used by the production OCI coordinator and local tests.</summary>
public interface IWorkloadReplicaDriver
{
    Task<WorkloadScaleObservation> ObserveAsync(WorkloadScalePolicy policy, CancellationToken cancellationToken);
    Task ApplyAsync(WorkloadScaleDecision decision, CancellationToken cancellationToken);
}

/// <summary>Runs independent workload decisions against one provider driver.</summary>
public sealed class IndependentWorkloadAutoscalerRuntime
{
    private readonly IndependentWorkloadAutoscaler scaler;
    private readonly IWorkloadReplicaDriver driver;

    public IndependentWorkloadAutoscalerRuntime(
        IndependentWorkloadAutoscaler scaler,
        IWorkloadReplicaDriver driver)
    {
        this.scaler = scaler ?? throw new ArgumentNullException(nameof(scaler));
        this.driver = driver ?? throw new ArgumentNullException(nameof(driver));
    }

    public async Task<IReadOnlyList<WorkloadScaleDecision>> StepAsync(CancellationToken cancellationToken = default)
    {
        var observations = new List<WorkloadScaleObservation>(scaler.Policies.Count);
        foreach (var policy in scaler.Policies)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                observations.Add(await driver.ObserveAsync(policy, cancellationToken).ConfigureAwait(false));
            }
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
            {
                // A provider failure in one workload must not stop the other
                // workload's reconciliation. Missing observations fail closed
                // and reset only that workload's confirmation window.
            }
        }

        var decisions = scaler.Tick(observations).ToArray();
        for (var index = 0; index < decisions.Length; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var decision = decisions[index];
            if (decision.Action is not (WorkloadScaleAction.ScaleOut or WorkloadScaleAction.ScaleIn)) continue;
            try
            {
                await driver.ApplyAsync(decision, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
            {
                decisions[index] = decision with
                {
                    Action = WorkloadScaleAction.Blocked,
                    Reason = "provider-apply-failed"
                };
            }
        }
        return decisions;
    }
}
