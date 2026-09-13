using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;
using System.Runtime.ExceptionServices;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// Bounded native-GitOps transport composition. It durably relays and records convergence
/// evidence; it does not create runtime assignments or dispatch any workload operation.
/// </summary>
internal sealed class NativeGitOpsRuntime : IAsyncDisposable
{
    private static readonly TimeSpan PullWait = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan AuthorityPause = TimeSpan.FromMilliseconds(250);

    private readonly CancellationTokenSource stopping = new();
    private readonly Task completion;

    private NativeGitOpsRuntime(
        NatsRuntime regional,
        GlobalNatsRuntime global,
        ICommandSignatureVerifier verifier)
    {
        var publisher = regional.CreateNativeGitOpsPublisher();
        var globalConsumer = global.CreateNativeGitOpsConsumer(publisher, regional.Cell);
        var regionalConsumer = regional.CreateNativeGitOpsConsumer();
        var convergence = regional.CreateNativeGitOpsConvergenceJournal();
        completion = RunAsync(regional, global, verifier, globalConsumer, regionalConsumer, convergence, stopping.Token);
    }

    internal Task Completion => completion;

    internal static bool IsEnabled(bool globalNatsConfigured, bool trustedVerifierConfigured) =>
        globalNatsConfigured && trustedVerifierConfigured;

    internal static void ValidateConfiguration(
        bool globalNatsConfigured,
        bool nativeGitOpsPublicationConfigured,
        bool trustedVerifierConfigured)
    {
        if (globalNatsConfigured && nativeGitOpsPublicationConfigured && !trustedVerifierConfigured)
            throw new InvalidOperationException(
                "Native GitOps global publication requires TS_ORCH_COMMAND_TRUST_KEY_FILES; unsigned CellSpec ingestion is disabled.");
    }

    internal static NativeGitOpsRuntime Start(
        NatsRuntime regional,
        GlobalNatsRuntime global,
        ICommandSignatureVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(regional);
        ArgumentNullException.ThrowIfNull(global);
        ArgumentNullException.ThrowIfNull(verifier);
        return new NativeGitOpsRuntime(regional, global, verifier);
    }

    private static async Task RunAsync(
        NatsRuntime regional,
        GlobalNatsRuntime global,
        ICommandSignatureVerifier verifier,
        NativeGitOpsGlobalCellNatsConsumer globalConsumer,
        NativeGitOpsCellNatsConsumer regionalConsumer,
        NativeGitOpsCellConvergenceJournal convergence,
        CancellationToken cancellationToken)
    {
        await RunWorkersAsync(
            token => RelayAsync(regional, global, verifier, globalConsumer, token),
            token => AcceptAsync(regional, global, verifier, regionalConsumer, convergence, token),
            cancellationToken);
    }

    internal static async Task RunWorkersAsync(
        Func<CancellationToken, Task> relay,
        Func<CancellationToken, Task> accept,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(relay);
        ArgumentNullException.ThrowIfNull(accept);
        using var workers = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var relayTask = InvokeAsync(relay, workers.Token);
        var acceptTask = InvokeAsync(accept, workers.Token);
        var all = Task.WhenAll(relayTask, acceptTask);
        var first = await Task.WhenAny(relayTask, acceptTask);
        if (cancellationToken.IsCancellationRequested)
        {
            await all;
            return;
        }

        workers.Cancel();
        try
        {
            await first;
        }
        catch (Exception failure)
        {
            try { await all; }
            catch { }
            ExceptionDispatchInfo.Capture(failure).Throw();
            throw;
        }

        try { await all; }
        catch (OperationCanceledException) when (workers.IsCancellationRequested) { }
        catch { }
        throw new InvalidOperationException("A native GitOps worker terminated without cancellation.");
    }

    private static async Task InvokeAsync(Func<CancellationToken, Task> worker, CancellationToken cancellationToken) =>
        await worker(cancellationToken);

    private static async Task RelayAsync(
        NatsRuntime regional,
        GlobalNatsRuntime global,
        ICommandSignatureVerifier verifier,
        NativeGitOpsGlobalCellNatsConsumer consumer,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var globalLease = global.AuthoritySnapshot;
            var regionalLease = regional.AuthoritySnapshot;
            if (!ReadyGlobal(globalLease) || !ReadyRegionalLeader(regionalLease))
            {
                await Task.Delay(AuthorityPause, cancellationToken);
                continue;
            }

            _ = await consumer.NextAsync(
                globalLease.Epoch,
                DateTimeOffset.UtcNow,
                TimeSpan.FromMinutes(1),
                PullWait,
                verifier,
                () => SameGlobalAuthority(globalLease, global.AuthoritySnapshot) &&
                      SameRegionalLeaderAuthority(regionalLease, regional.AuthoritySnapshot),
                cancellationToken);
        }
    }

    private static async Task AcceptAsync(
        NatsRuntime regional,
        GlobalNatsRuntime global,
        ICommandSignatureVerifier verifier,
        NativeGitOpsCellNatsConsumer consumer,
        NativeGitOpsCellConvergenceJournal convergence,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var globalLease = global.AuthoritySnapshot;
            var regionalLease = regional.AuthoritySnapshot;
            if (!ReadyGlobal(globalLease) || !ReadyRegionalLeader(regionalLease))
            {
                await Task.Delay(AuthorityPause, cancellationToken);
                continue;
            }

            _ = await consumer.NextWithConvergenceAsync(
                globalLease.Epoch,
                DateTimeOffset.UtcNow,
                TimeSpan.FromMinutes(1),
                PullWait,
                verifier,
                () => SameGlobalAuthority(globalLease, global.AuthoritySnapshot) &&
                      SameRegionalLeaderAuthority(regionalLease, regional.AuthoritySnapshot),
                async (accepted, token) =>
                {
                    var receipt = await convergence.AdvanceAsync(
                        accepted,
                        [],
                        [],
                        null,
                        Watermark(accepted.StreamSequence),
                        () => SameGlobalAuthority(globalLease, global.AuthoritySnapshot) &&
                              SameRegionalLeaderAuthority(regionalLease, regional.AuthoritySnapshot),
                        token);
                    // Pending Observe/Apply/Hold is evidence only. Do not use CanDispatch:
                    // this runtime contains no projector, assignment, executor, or adapter.
                    return receipt.Disposition is NativeGitOpsCellConvergenceJournalDisposition.Recorded or
                        NativeGitOpsCellConvergenceJournalDisposition.Duplicate;
                },
                cancellationToken);
        }
    }

    private static long Watermark(ulong streamSequence) => streamSequence > long.MaxValue
        ? long.MaxValue
        : Math.Max(1, (long)streamSequence);

    private static bool ReadyGlobal(RegionalAuthoritySnapshot snapshot) =>
        snapshot.Ready && snapshot.IsLeader && snapshot.Epoch > 0 && snapshot.KvRevision > 0;

    private static bool ReadyRegionalLeader(RegionalAuthoritySnapshot snapshot) =>
        snapshot.Ready && snapshot.IsLeader && snapshot.Epoch > 0 && snapshot.KvRevision > 0;

    internal static bool SameGlobalAuthority(RegionalAuthoritySnapshot expected, RegionalAuthoritySnapshot actual) =>
        ReadyGlobal(actual) && expected.Epoch == actual.Epoch && actual.KvRevision >= expected.KvRevision;

    internal static bool SameRegionalLeaderAuthority(RegionalAuthoritySnapshot expected, RegionalAuthoritySnapshot actual) =>
        ReadyRegionalLeader(actual) && expected.Epoch == actual.Epoch && actual.KvRevision >= expected.KvRevision;

    public async ValueTask DisposeAsync()
    {
        await stopping.CancelAsync();
        try
        {
            await completion;
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested)
        {
        }
        finally
        {
            stopping.Dispose();
        }
    }
}

