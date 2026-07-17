using System.Runtime.Versioning;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery;

internal enum CiRunnerWorkloadFailureCode
{
    Unspecified,
    PolicyRejected,
    SourceRejected,
    OutputRejected,
    ProcessFailed,
    TimedOut,
    LogLimitExceeded,
}

internal enum CiRunnerExecutionCoordinatorDisposition
{
    Unspecified,
    NotAcquired,
    Completed,
    LeaseLost,
}

internal sealed record CiRunnerWorkloadEvidence(
    int SchemaVersion,
    string Runner,
    string PipelineDigest,
    string Job,
    string JobDigest,
    string ExecutionIdentityDigest,
    string PayloadDigest,
    string SignatureDigest,
    ulong StreamSequence,
    ulong AcceptanceRevision,
    int Attempt,
    long LeaseSequence,
    string PlanDigest,
    string SourceBundleSha256,
    string DescriptorSha256,
    string RecipeSha256,
    CiRunnerBuildKitExecutionDisposition BuildDisposition,
    int ExitCode,
    string LogSha256,
    long LogBytes,
    string MetadataSha256,
    string OutputSha256,
    int OutputFiles,
    long OutputBytes,
    bool Succeeded,
    RepositoryCiJobFailureKind FailureKind,
    CiRunnerWorkloadFailureCode FailureCode);

internal sealed record CiRunnerDurableWorkloadResult(
    string EvidenceDigest,
    int RequiredTestSkips);

internal interface ICiRunnerWorkloadResultSink
{
    /// <summary>
    /// Makes the exact evidence and, on success, the validated export tree durable before the
    /// execution lease can become terminal. The implementation must be idempotent by evidence.
    /// </summary>
    Task<CiRunnerDurableWorkloadResult> PersistAsync(
        CiRunnerWorkloadEvidence evidence,
        string? exportDirectory,
        CancellationToken cancellationToken);
}

internal sealed record CiRunnerExecutionCoordinatorReceipt(
    CiRunnerExecutionCoordinatorDisposition Disposition,
    RepositoryCiJobExecutionDisposition ExecutionDisposition,
    RepositoryCiJobExecutionSnapshot? Execution,
    string EvidenceDigest);

/// <summary>
/// Runs one durably accepted CI command under a renewable fence. A terminal journal state is
/// written only after a result sink has durably accepted the exact workload evidence and output.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class CiRunnerExecutionCoordinator
{
    private static readonly TimeSpan LeaseDuration = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RenewalInterval = TimeSpan.FromMinutes(2);
    private static readonly UnixFileMode PrivateDirectoryMode = UnixFileMode.UserRead |
        UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private readonly RepositoryCiJobExecutionJournal journal;
    private readonly CiRunnerSourceMaterializer materializer;
    private readonly CiRunnerBuildKitExecutor executor;
    private readonly ICiRunnerWorkloadResultSink results;
    private readonly TimeProvider timeProvider;

    internal CiRunnerExecutionCoordinator(
        RepositoryCiJobExecutionJournal journal,
        CiRunnerSourceMaterializer materializer,
        CiRunnerBuildKitExecutor executor,
        ICiRunnerWorkloadResultSink results,
        TimeProvider? timeProvider = null)
    {
        this.journal = journal ?? throw new ArgumentNullException(nameof(journal));
        this.materializer = materializer ?? throw new ArgumentNullException(nameof(materializer));
        this.executor = executor ?? throw new ArgumentNullException(nameof(executor));
        this.results = results ?? throw new ArgumentNullException(nameof(results));
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    internal async Task<CiRunnerExecutionCoordinatorReceipt> ExecuteAsync(
        RepositoryCiAcceptedJob accepted,
        RunnerEvidence runner,
        CiRunnerIsolationEvidence isolation,
        CiRunnerBuildKitRuntime runtime,
        string workspaceRoot,
        string operationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accepted);
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentNullException.ThrowIfNull(isolation);
        ArgumentNullException.ThrowIfNull(runtime);
        var workspace = RequirePrivateDirectory(workspaceRoot);
        var acquired = await journal.AcquireAsync(
            accepted,
            operationId,
            timeProvider.GetUtcNow(),
            LeaseDuration,
            cancellationToken);
        if (acquired.Disposition is not (RepositoryCiJobExecutionDisposition.Acquired or
                RepositoryCiJobExecutionDisposition.TakenOver) || acquired.Execution is null)
            return new(
                CiRunnerExecutionCoordinatorDisposition.NotAcquired,
                acquired.Disposition,
                acquired.Execution,
                acquired.Execution?.EvidenceDigest ?? string.Empty);

        var lease = new RenewableLease(acquired.Execution);
        using var leaseLost = new CancellationTokenSource();
        using var work = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, leaseLost.Token);
        using var stopRenewal = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var renewal = RenewAsync(lease, leaseLost, stopRenewal.Token);
        var sourcePath = Path.Combine(
            workspace,
            $"ci-{accepted.ExecutionIdentityDigest}-{acquired.Execution.LeaseSequence}");
        string? outputPath = null;
        CiRunnerDurableWorkloadResult durable;
        try
        {
            var execution = await ExecuteWorkloadAsync(
                accepted,
                runner,
                isolation,
                runtime,
                sourcePath,
                work.Token);
            outputPath = execution.ExportDirectory;
            durable = await results.PersistAsync(execution.Evidence, outputPath, work.Token);
            ValidateDurableResult(durable);
        }
        catch (OperationCanceledException) when (leaseLost.IsCancellationRequested &&
            !cancellationToken.IsCancellationRequested)
        {
            return new(
                CiRunnerExecutionCoordinatorDisposition.LeaseLost,
                lease.LostDisposition,
                lease.Snapshot,
                string.Empty);
        }
        finally
        {
            stopRenewal.Cancel();
            try
            {
                await renewal;
            }
            catch (OperationCanceledException) when (stopRenewal.IsCancellationRequested)
            {
            }
            Delete(sourcePath);
            if (outputPath is not null)
                Delete(Directory.GetParent(outputPath)?.FullName ?? outputPath);
        }

        if (lease.IsLost)
            return new(
                CiRunnerExecutionCoordinatorDisposition.LeaseLost,
                lease.LostDisposition,
                lease.Snapshot,
                string.Empty);
        var evidence = durable.EvidenceDigest;
        var workload = lease.Evidence!;
        var completed = await journal.CompleteAsync(
            lease.Snapshot,
            workload.Succeeded,
            evidence,
            durable.RequiredTestSkips,
            workload.FailureKind,
            timeProvider.GetUtcNow(),
            cancellationToken);
        return completed.Disposition is RepositoryCiJobExecutionDisposition.Completed or
                RepositoryCiJobExecutionDisposition.Duplicate
            ? new(
                CiRunnerExecutionCoordinatorDisposition.Completed,
                completed.Disposition,
                completed.Execution,
                evidence)
            : new(
                CiRunnerExecutionCoordinatorDisposition.LeaseLost,
                completed.Disposition,
                completed.Execution,
                evidence);

        async Task<ExecutedWorkload> ExecuteWorkloadAsync(
            RepositoryCiAcceptedJob command,
            RunnerEvidence runnerEvidence,
            CiRunnerIsolationEvidence isolationEvidence,
            CiRunnerBuildKitRuntime buildKitRuntime,
            string destination,
            CancellationToken token)
        {
            CiRunnerExecutionPlan plan;
            try
            {
                plan = CiRunnerExecutionPlanner.Create(command, runnerEvidence, isolationEvidence);
            }
            catch (InvalidDataException)
            {
                var rejected = Evidence(
                    command,
                    lease.Snapshot,
                    null,
                    null,
                    null,
                    RepositoryCiJobFailureKind.PolicyDenied,
                    CiRunnerWorkloadFailureCode.PolicyRejected);
                lease.Evidence = rejected;
                return new(rejected, null);
            }

            CiRunnerMaterializedSource source;
            try
            {
                source = await materializer.MaterializeAsync(plan, destination, token);
            }
            catch (InvalidDataException)
            {
                var rejected = Evidence(
                    command,
                    lease.Snapshot,
                    plan,
                    null,
                    null,
                    RepositoryCiJobFailureKind.PolicyDenied,
                    CiRunnerWorkloadFailureCode.SourceRejected);
                lease.Evidence = rejected;
                return new(rejected, null);
            }

            CiRunnerBuildKitExecutionResult build;
            try
            {
                build = await executor.ExecuteAsync(plan, source, buildKitRuntime, token);
            }
            catch (InvalidDataException)
            {
                var rejected = Evidence(
                    command,
                    lease.Snapshot,
                    plan,
                    source,
                    null,
                    RepositoryCiJobFailureKind.WorkloadFailed,
                    CiRunnerWorkloadFailureCode.OutputRejected);
                lease.Evidence = rejected;
                return new(rejected, null);
            }

            var succeeded = build.Disposition == CiRunnerBuildKitExecutionDisposition.Succeeded;
            var failureCode = build.Disposition switch
            {
                CiRunnerBuildKitExecutionDisposition.Succeeded => CiRunnerWorkloadFailureCode.Unspecified,
                CiRunnerBuildKitExecutionDisposition.ProcessFailed => CiRunnerWorkloadFailureCode.ProcessFailed,
                CiRunnerBuildKitExecutionDisposition.TimedOut => CiRunnerWorkloadFailureCode.TimedOut,
                CiRunnerBuildKitExecutionDisposition.LogLimitExceeded =>
                    CiRunnerWorkloadFailureCode.LogLimitExceeded,
                _ => throw new InvalidDataException("The CI workload returned an invalid build disposition."),
            };
            var evidence = Evidence(
                command,
                lease.Snapshot,
                plan,
                source,
                build,
                succeeded ? RepositoryCiJobFailureKind.Unspecified : RepositoryCiJobFailureKind.WorkloadFailed,
                failureCode);
            lease.Evidence = evidence;
            var export = succeeded
                ? CiRunnerBuildKitInvocationCompiler.Create(plan, source, buildKitRuntime).ExportDirectory
                : null;
            return new(evidence, export);
        }
    }

    private async Task RenewAsync(
        RenewableLease lease,
        CancellationTokenSource leaseLost,
        CancellationToken cancellationToken)
    {
        try
        {
            while (true)
            {
                await Task.Delay(RenewalInterval, timeProvider, cancellationToken);
                var renewed = await journal.RenewAsync(
                    lease.Snapshot,
                    timeProvider.GetUtcNow(),
                    LeaseDuration,
                    cancellationToken);
                if (renewed.Disposition is not (RepositoryCiJobExecutionDisposition.Renewed or
                        RepositoryCiJobExecutionDisposition.Duplicate) || renewed.Execution is null)
                {
                    lease.Lose(renewed.Disposition, renewed.Execution);
                    leaseLost.Cancel();
                    return;
                }
                lease.Snapshot = renewed.Execution;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch
        {
            lease.Lose(RepositoryCiJobExecutionDisposition.Contention, lease.Snapshot);
            leaseLost.Cancel();
        }
    }

    private static CiRunnerWorkloadEvidence Evidence(
        RepositoryCiAcceptedJob accepted,
        RepositoryCiJobExecutionSnapshot lease,
        CiRunnerExecutionPlan? plan,
        CiRunnerMaterializedSource? source,
        CiRunnerBuildKitExecutionResult? build,
        RepositoryCiJobFailureKind failureKind,
        CiRunnerWorkloadFailureCode failureCode)
    {
        var succeeded = failureKind == RepositoryCiJobFailureKind.Unspecified;
        return new(
            1,
            accepted.Command.Runner,
            accepted.Command.PipelineDigest,
            accepted.Command.Job,
            accepted.Command.JobDigest,
            accepted.ExecutionIdentityDigest,
            accepted.PayloadDigest,
            accepted.SignatureDigest,
            accepted.StreamSequence,
            accepted.JournalRevision,
            accepted.Command.Attempt,
            lease.LeaseSequence,
            plan?.Digest ?? string.Empty,
            accepted.Command.SourceBundleSha256,
            source?.DescriptorSha256 ?? string.Empty,
            source?.RecipeSha256 ?? string.Empty,
            build?.Disposition ?? CiRunnerBuildKitExecutionDisposition.Unspecified,
            build?.ExitCode ?? -1,
            build?.LogSha256 ?? string.Empty,
            build?.LogBytes ?? 0,
            build?.MetadataSha256 ?? string.Empty,
            build?.OutputSha256 ?? string.Empty,
            build?.OutputFiles ?? 0,
            build?.OutputBytes ?? 0,
            succeeded,
            failureKind,
            failureCode);
    }

    private static string RequirePrivateDirectory(string value)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("CI execution coordination requires Linux isolation.");
        if (!Path.IsPathFullyQualified(value))
            throw new ArgumentException("The CI workspace root must be absolute.", nameof(value));
        var path = Path.GetFullPath(value);
        var directory = new DirectoryInfo(path);
        if (!directory.Exists || directory.LinkTarget is not null ||
            (File.GetUnixFileMode(path) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite |
                UnixFileMode.OtherExecute)) != 0)
            throw new InvalidDataException("The CI workspace root must be a real owner-private directory.");
        File.SetUnixFileMode(path, PrivateDirectoryMode);
        return path;
    }

    private static void ValidateDurableResult(CiRunnerDurableWorkloadResult value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!RepositoryCiJobExecutionDocument.IsDigest(value.EvidenceDigest) ||
            value.RequiredTestSkips is < 0 or > 1_000_000)
            throw new InvalidDataException("The durable CI workload result is invalid.");
    }

    private static void Delete(string path)
    {
        try
        {
            if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
        }
        catch
        {
        }
    }

    private sealed record ExecutedWorkload(CiRunnerWorkloadEvidence Evidence, string? ExportDirectory);

    private sealed class RenewableLease(RepositoryCiJobExecutionSnapshot snapshot)
    {
        private readonly object gate = new();
        private RepositoryCiJobExecutionSnapshot snapshot = snapshot;
        private RepositoryCiJobExecutionDisposition lostDisposition;
        private bool lost;

        internal RepositoryCiJobExecutionSnapshot Snapshot
        {
            get
            {
                lock (gate) return snapshot;
            }
            set
            {
                lock (gate) snapshot = value;
            }
        }

        internal CiRunnerWorkloadEvidence? Evidence { get; set; }

        internal bool IsLost
        {
            get
            {
                lock (gate) return lost;
            }
        }

        internal RepositoryCiJobExecutionDisposition LostDisposition
        {
            get
            {
                lock (gate) return lostDisposition;
            }
        }

        internal void Lose(
            RepositoryCiJobExecutionDisposition disposition,
            RepositoryCiJobExecutionSnapshot? observed)
        {
            lock (gate)
            {
                lost = true;
                lostDisposition = disposition;
                if (observed is not null) snapshot = observed;
            }
        }
    }
}
