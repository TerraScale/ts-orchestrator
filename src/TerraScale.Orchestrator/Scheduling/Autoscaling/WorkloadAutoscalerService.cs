namespace TerraScale.Orchestrator.Scheduler.Autoscaling;

/// <summary>
/// Supervises the independent workload scaler in a regional controller.  The
/// scaler is deliberately one service with separate policy state per workload;
/// an OCI or NATS failure holds the current decision and retries on the next
/// bounded tick rather than issuing an unbounded mutation loop.
/// </summary>
public sealed class WorkloadAutoscalerService : IAsyncDisposable
{
    private readonly IndependentWorkloadAutoscalerRuntime runtime;
    private readonly TimeSpan interval;
    private readonly CancellationTokenSource stopping = new();
    private readonly Task loop;
    private IReadOnlyList<WorkloadScaleDecision> latest = Array.Empty<WorkloadScaleDecision>();
    private Exception? lastError;

    private WorkloadAutoscalerService(
        IndependentWorkloadAutoscalerRuntime runtime,
        TimeSpan interval)
    {
        this.runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        if (interval < TimeSpan.FromSeconds(1) || interval > TimeSpan.FromMinutes(5))
            throw new ArgumentOutOfRangeException(nameof(interval));
        this.interval = interval;
        loop = Task.Run(() => LoopAsync(stopping.Token), CancellationToken.None);
    }

    public IReadOnlyList<WorkloadScaleDecision> Latest => Volatile.Read(ref latest);
    public Exception? LastError => Volatile.Read(ref lastError);
    public Action<IReadOnlyList<WorkloadScaleDecision>>? DecisionUpdated { get; set; }

    public static WorkloadAutoscalerService Start(
        IndependentWorkloadAutoscalerRuntime runtime,
        TimeSpan? interval = null) =>
        new(runtime, interval ?? TimeSpan.FromSeconds(15));

    internal async Task StepAsync(CancellationToken cancellationToken = default)
    {
        var decisions = await runtime.StepAsync(cancellationToken).ConfigureAwait(false);
        Volatile.Write(ref latest, decisions);
        Volatile.Write(ref lastError, null);
        DecisionUpdated?.Invoke(decisions);
    }

    private async Task LoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await StepAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                Volatile.Write(ref lastError, exception);
            }

            try
            {
                await Task.Delay(interval, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        stopping.Cancel();
        try
        {
            await loop.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        stopping.Dispose();
    }
}
