namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiPromotionOperation
{
    Unspecified,
    Publish,
    DeploySfo,
    DeployFra,
    DeployGru,
    RollbackPublication,
    RollbackGru,
    RollbackFra,
    RollbackSfo,
}

internal sealed record RepositoryCiPromotionOperationReceipt(
    bool Succeeded,
    string EvidenceDigest);

internal interface IRepositoryCiPromotionActuator
{
    Task<RepositoryCiPromotionOperationReceipt> ExecuteAsync(
        RepositoryCiPromotionOperation operation,
        RepositoryCiPromotionAuthorization authorization,
        RepositoryCiPromotionLease lease,
        string operationId,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken);
}

internal enum RepositoryCiPromotionCoordinationDisposition
{
    Unspecified,
    Completed,
    AlreadyCompleted,
    RolledBack,
    AlreadyRolledBack,
    AuthorityLost,
    LeaseRejected,
    RollbackFailed,
}

internal sealed record RepositoryCiPromotionCoordinationReceipt(
    RepositoryCiPromotionCoordinationDisposition Disposition,
    RepositoryCiPromotionJournalDisposition JournalDisposition,
    RepositoryCiPromotionLease? Lease,
    RepositoryCiPromotionOperation FailedOperation)
{
    internal bool IsTerminal => Disposition is
        RepositoryCiPromotionCoordinationDisposition.Completed or
        RepositoryCiPromotionCoordinationDisposition.AlreadyCompleted or
        RepositoryCiPromotionCoordinationDisposition.RolledBack or
        RepositoryCiPromotionCoordinationDisposition.AlreadyRolledBack;
}

/// <summary>
/// Drives the durable publish, SFO, FRA, GRU, and reverse rollback phases. Every external action
/// starts in the journal first and receives a stable operation ID plus the current fencing token.
/// </summary>
internal sealed class RepositoryCiPromotionCoordinator(
    RepositoryCiPromotionJournal journal,
    IRepositoryCiPromotionActuator actuator)
{
    internal async Task<RepositoryCiPromotionCoordinationReceipt> CoordinateAsync(
        RepositoryCiPromotionAuthorization authorization,
        string controllerId,
        long authorityEpoch,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(actuator);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (!authorityStillValid()) return AuthorityLost();

        var acquired = await journal.AcquireAsync(
            authorization,
            controllerId,
            authorityEpoch,
            cancellationToken);
        if (!acquired.CanContinue)
            return Rejected(acquired);
        var lease = acquired.Lease;
        if (lease.Phase == RepositoryCiPromotionPhase.Completed)
            return Result(
                RepositoryCiPromotionCoordinationDisposition.AlreadyCompleted,
                acquired.Disposition,
                lease);
        if (lease.Phase == RepositoryCiPromotionPhase.RolledBack)
            return Result(
                RepositoryCiPromotionCoordinationDisposition.AlreadyRolledBack,
                acquired.Disposition,
                lease);
        if (IsRollback(lease.Phase))
            return await RollbackAsync(
                authorization,
                lease,
                authorityStillValid,
                RepositoryCiPromotionOperation.Unspecified,
                cancellationToken);

        while (true)
        {
            if (!authorityStillValid()) return AuthorityLost(lease);
            switch (lease.Phase)
            {
                case RepositoryCiPromotionPhase.Authorized:
                    {
                        var started = await AdvanceAsync(
                            authorization,
                            lease,
                            RepositoryCiPromotionPhase.PublishStarted,
                            RepositoryCiPromotionOperation.Publish,
                            lease.EvidenceDigest,
                            cancellationToken);
                        if (!started.CanContinue) return Rejected(started);
                        lease = started.Lease;
                        break;
                    }
                case RepositoryCiPromotionPhase.PublishStarted:
                    {
                        var outcome = await ExecuteForwardAsync(
                            authorization,
                            lease,
                            RepositoryCiPromotionOperation.Publish,
                            RepositoryCiPromotionPhase.Published,
                            authorityStillValid,
                            cancellationToken);
                        if (outcome.Receipt is not null) return outcome.Receipt;
                        lease = outcome.Lease!;
                        break;
                    }
                case RepositoryCiPromotionPhase.Published:
                    {
                        var started = await AdvanceAsync(
                            authorization,
                            lease,
                            RepositoryCiPromotionPhase.SfoDeploymentStarted,
                            RepositoryCiPromotionOperation.DeploySfo,
                            lease.EvidenceDigest,
                            cancellationToken);
                        if (!started.CanContinue) return Rejected(started);
                        lease = started.Lease;
                        break;
                    }
                case RepositoryCiPromotionPhase.SfoDeploymentStarted:
                    {
                        var outcome = await ExecuteForwardAsync(
                            authorization,
                            lease,
                            RepositoryCiPromotionOperation.DeploySfo,
                            RepositoryCiPromotionPhase.SfoVerified,
                            authorityStillValid,
                            cancellationToken);
                        if (outcome.Receipt is not null) return outcome.Receipt;
                        lease = outcome.Lease!;
                        break;
                    }
                case RepositoryCiPromotionPhase.SfoVerified:
                    {
                        var started = await AdvanceAsync(
                            authorization,
                            lease,
                            RepositoryCiPromotionPhase.FraDeploymentStarted,
                            RepositoryCiPromotionOperation.DeployFra,
                            lease.EvidenceDigest,
                            cancellationToken);
                        if (!started.CanContinue) return Rejected(started);
                        lease = started.Lease;
                        break;
                    }
                case RepositoryCiPromotionPhase.FraDeploymentStarted:
                    {
                        var outcome = await ExecuteForwardAsync(
                            authorization,
                            lease,
                            RepositoryCiPromotionOperation.DeployFra,
                            RepositoryCiPromotionPhase.FraVerified,
                            authorityStillValid,
                            cancellationToken);
                        if (outcome.Receipt is not null) return outcome.Receipt;
                        lease = outcome.Lease!;
                        break;
                    }
                case RepositoryCiPromotionPhase.FraVerified:
                    {
                        var started = await AdvanceAsync(
                            authorization,
                            lease,
                            RepositoryCiPromotionPhase.GruDeploymentStarted,
                            RepositoryCiPromotionOperation.DeployGru,
                            lease.EvidenceDigest,
                            cancellationToken);
                        if (!started.CanContinue) return Rejected(started);
                        lease = started.Lease;
                        break;
                    }
                case RepositoryCiPromotionPhase.GruDeploymentStarted:
                    {
                        var outcome = await ExecuteForwardAsync(
                            authorization,
                            lease,
                            RepositoryCiPromotionOperation.DeployGru,
                            RepositoryCiPromotionPhase.GruVerified,
                            authorityStillValid,
                            cancellationToken);
                        if (outcome.Receipt is not null) return outcome.Receipt;
                        lease = outcome.Lease!;
                        break;
                    }
                case RepositoryCiPromotionPhase.GruVerified:
                    {
                        var completed = await journal.AdvanceAsync(
                            lease,
                            RepositoryCiPromotionPhase.Completed,
                            OperationId(authorization, "complete"),
                            lease.EvidenceDigest,
                            cancellationToken);
                        if (!completed.CanContinue) return Rejected(completed);
                        return Result(
                            RepositoryCiPromotionCoordinationDisposition.Completed,
                            completed.Disposition,
                            completed.Lease);
                    }
                default:
                    throw new InvalidDataException("The promotion journal is in an unsupported forward phase.");
            }
        }
    }

    private async Task<ForwardOutcome> ExecuteForwardAsync(
        RepositoryCiPromotionAuthorization authorization,
        RepositoryCiPromotionLease lease,
        RepositoryCiPromotionOperation operation,
        RepositoryCiPromotionPhase completedPhase,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken)
    {
        var operationId = OperationId(authorization, operation);
        if (lease.OperationId != operationId)
            throw new InvalidDataException("A started promotion phase changed operation identity.");
        var executed = await actuator.ExecuteAsync(
            operation,
            authorization,
            lease,
            operationId,
            authorityStillValid,
            cancellationToken) ?? throw new InvalidDataException("The promotion actuator returned no result.");
        if (!authorityStillValid()) return new(null, AuthorityLost(lease));
        if (!executed.Succeeded)
        {
            var rollbackOperation = RollbackOperation(lease.Phase);
            var rollback = await AdvanceAsync(
                authorization,
                lease,
                RollbackStart(lease.Phase),
                rollbackOperation,
                executed.EvidenceDigest,
                cancellationToken);
            if (!rollback.CanContinue) return new(null, Rejected(rollback));
            return new(null, await RollbackAsync(
                authorization,
                rollback.Lease,
                authorityStillValid,
                operation,
                cancellationToken));
        }

        var advanced = await journal.AdvanceAsync(
            lease,
            completedPhase,
            operationId,
            executed.EvidenceDigest,
            cancellationToken);
        return advanced.CanContinue
            ? new(advanced.Lease, null)
            : new(null, Rejected(advanced));
    }

    private async Task<RepositoryCiPromotionCoordinationReceipt> RollbackAsync(
        RepositoryCiPromotionAuthorization authorization,
        RepositoryCiPromotionLease lease,
        Func<bool> authorityStillValid,
        RepositoryCiPromotionOperation failedOperation,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            if (!authorityStillValid()) return AuthorityLost(lease, failedOperation);
            switch (lease.Phase)
            {
                case RepositoryCiPromotionPhase.RollbackStarted:
                    {
                        var outcome = await ExecuteRollbackAsync(
                            authorization,
                            lease,
                            RepositoryCiPromotionOperation.RollbackPublication,
                            RepositoryCiPromotionPhase.RolledBack,
                            authorityStillValid,
                            failedOperation,
                            cancellationToken);
                        if (outcome.Receipt is not null) return outcome.Receipt;
                        lease = outcome.Lease!;
                        break;
                    }
                case RepositoryCiPromotionPhase.RollbackGruStarted:
                    {
                        var outcome = await ExecuteRollbackAsync(
                            authorization,
                            lease,
                            RepositoryCiPromotionOperation.RollbackGru,
                            RepositoryCiPromotionPhase.GruRolledBack,
                            authorityStillValid,
                            failedOperation,
                            cancellationToken);
                        if (outcome.Receipt is not null) return outcome.Receipt;
                        lease = outcome.Lease!;
                        break;
                    }
                case RepositoryCiPromotionPhase.GruRolledBack:
                    {
                        var started = await AdvanceAsync(
                            authorization,
                            lease,
                            RepositoryCiPromotionPhase.RollbackFraStarted,
                            RepositoryCiPromotionOperation.RollbackFra,
                            lease.EvidenceDigest,
                            cancellationToken);
                        if (!started.CanContinue) return Rejected(started, failedOperation);
                        lease = started.Lease;
                        break;
                    }
                case RepositoryCiPromotionPhase.RollbackFraStarted:
                    {
                        var outcome = await ExecuteRollbackAsync(
                            authorization,
                            lease,
                            RepositoryCiPromotionOperation.RollbackFra,
                            RepositoryCiPromotionPhase.FraRolledBack,
                            authorityStillValid,
                            failedOperation,
                            cancellationToken);
                        if (outcome.Receipt is not null) return outcome.Receipt;
                        lease = outcome.Lease!;
                        break;
                    }
                case RepositoryCiPromotionPhase.FraRolledBack:
                    {
                        var started = await AdvanceAsync(
                            authorization,
                            lease,
                            RepositoryCiPromotionPhase.RollbackSfoStarted,
                            RepositoryCiPromotionOperation.RollbackSfo,
                            lease.EvidenceDigest,
                            cancellationToken);
                        if (!started.CanContinue) return Rejected(started, failedOperation);
                        lease = started.Lease;
                        break;
                    }
                case RepositoryCiPromotionPhase.RollbackSfoStarted:
                    {
                        var outcome = await ExecuteRollbackAsync(
                            authorization,
                            lease,
                            RepositoryCiPromotionOperation.RollbackSfo,
                            RepositoryCiPromotionPhase.SfoRolledBack,
                            authorityStillValid,
                            failedOperation,
                            cancellationToken);
                        if (outcome.Receipt is not null) return outcome.Receipt;
                        lease = outcome.Lease!;
                        break;
                    }
                case RepositoryCiPromotionPhase.SfoRolledBack:
                    {
                        var completed = await journal.AdvanceAsync(
                            lease,
                            RepositoryCiPromotionPhase.RolledBack,
                            OperationId(authorization, "rollback-complete"),
                            lease.EvidenceDigest,
                            cancellationToken);
                        if (!completed.CanContinue) return Rejected(completed, failedOperation);
                        return Result(
                            RepositoryCiPromotionCoordinationDisposition.RolledBack,
                            completed.Disposition,
                            completed.Lease,
                            failedOperation);
                    }
                case RepositoryCiPromotionPhase.RolledBack:
                    return Result(
                        RepositoryCiPromotionCoordinationDisposition.RolledBack,
                        RepositoryCiPromotionJournalDisposition.Resumed,
                        lease,
                        failedOperation);
                default:
                    throw new InvalidDataException("The promotion journal is in an unsupported rollback phase.");
            }
        }
    }

    private async Task<ForwardOutcome> ExecuteRollbackAsync(
        RepositoryCiPromotionAuthorization authorization,
        RepositoryCiPromotionLease lease,
        RepositoryCiPromotionOperation operation,
        RepositoryCiPromotionPhase completedPhase,
        Func<bool> authorityStillValid,
        RepositoryCiPromotionOperation failedOperation,
        CancellationToken cancellationToken)
    {
        var operationId = OperationId(authorization, operation);
        if (lease.OperationId != operationId)
            throw new InvalidDataException("A started promotion rollback changed operation identity.");
        var executed = await actuator.ExecuteAsync(
            operation,
            authorization,
            lease,
            operationId,
            authorityStillValid,
            cancellationToken) ?? throw new InvalidDataException("The promotion actuator returned no result.");
        if (!authorityStillValid()) return new(null, AuthorityLost(lease, failedOperation));
        if (!executed.Succeeded)
            return new(null, Result(
                RepositoryCiPromotionCoordinationDisposition.RollbackFailed,
                RepositoryCiPromotionJournalDisposition.Resumed,
                lease,
                operation));
        var advanced = await journal.AdvanceAsync(
            lease,
            completedPhase,
            operationId,
            executed.EvidenceDigest,
            cancellationToken);
        return advanced.CanContinue
            ? new(advanced.Lease, null)
            : new(null, Rejected(advanced, failedOperation));
    }

    private Task<RepositoryCiPromotionJournalReceipt> AdvanceAsync(
        RepositoryCiPromotionAuthorization authorization,
        RepositoryCiPromotionLease lease,
        RepositoryCiPromotionPhase phase,
        RepositoryCiPromotionOperation operation,
        string evidenceDigest,
        CancellationToken cancellationToken) => journal.AdvanceAsync(
        lease,
        phase,
        OperationId(authorization, operation),
        evidenceDigest,
        cancellationToken);

    private static RepositoryCiPromotionPhase RollbackStart(RepositoryCiPromotionPhase phase) => phase switch
    {
        RepositoryCiPromotionPhase.PublishStarted or RepositoryCiPromotionPhase.Published =>
            RepositoryCiPromotionPhase.RollbackStarted,
        RepositoryCiPromotionPhase.SfoDeploymentStarted or RepositoryCiPromotionPhase.SfoVerified =>
            RepositoryCiPromotionPhase.RollbackSfoStarted,
        RepositoryCiPromotionPhase.FraDeploymentStarted or RepositoryCiPromotionPhase.FraVerified =>
            RepositoryCiPromotionPhase.RollbackFraStarted,
        RepositoryCiPromotionPhase.GruDeploymentStarted or RepositoryCiPromotionPhase.GruVerified =>
            RepositoryCiPromotionPhase.RollbackGruStarted,
        _ => throw new InvalidDataException("The failed promotion phase has no rollback path."),
    };

    private static RepositoryCiPromotionOperation RollbackOperation(RepositoryCiPromotionPhase phase) => phase switch
    {
        RepositoryCiPromotionPhase.PublishStarted or RepositoryCiPromotionPhase.Published =>
            RepositoryCiPromotionOperation.RollbackPublication,
        RepositoryCiPromotionPhase.SfoDeploymentStarted or RepositoryCiPromotionPhase.SfoVerified =>
            RepositoryCiPromotionOperation.RollbackSfo,
        RepositoryCiPromotionPhase.FraDeploymentStarted or RepositoryCiPromotionPhase.FraVerified =>
            RepositoryCiPromotionOperation.RollbackFra,
        RepositoryCiPromotionPhase.GruDeploymentStarted or RepositoryCiPromotionPhase.GruVerified =>
            RepositoryCiPromotionOperation.RollbackGru,
        _ => throw new InvalidDataException("The failed promotion phase has no rollback operation."),
    };

    private static bool IsRollback(RepositoryCiPromotionPhase phase) => phase is
        RepositoryCiPromotionPhase.RollbackStarted or
        RepositoryCiPromotionPhase.RollbackGruStarted or
        RepositoryCiPromotionPhase.GruRolledBack or
        RepositoryCiPromotionPhase.RollbackFraStarted or
        RepositoryCiPromotionPhase.FraRolledBack or
        RepositoryCiPromotionPhase.RollbackSfoStarted or
        RepositoryCiPromotionPhase.SfoRolledBack;

    private static string OperationId(
        RepositoryCiPromotionAuthorization authorization,
        RepositoryCiPromotionOperation operation) => OperationId(authorization, operation switch
        {
            RepositoryCiPromotionOperation.Publish => "publish",
            RepositoryCiPromotionOperation.DeploySfo => "deploy-sfo",
            RepositoryCiPromotionOperation.DeployFra => "deploy-fra",
            RepositoryCiPromotionOperation.DeployGru => "deploy-gru",
            RepositoryCiPromotionOperation.RollbackPublication => "rollback-publication",
            RepositoryCiPromotionOperation.RollbackGru => "rollback-gru",
            RepositoryCiPromotionOperation.RollbackFra => "rollback-fra",
            RepositoryCiPromotionOperation.RollbackSfo => "rollback-sfo",
            _ => throw new ArgumentOutOfRangeException(nameof(operation)),
        });

    private static string OperationId(
        RepositoryCiPromotionAuthorization authorization,
        string operation) => $"promotion-{authorization.Digest}-{operation}";

    private static RepositoryCiPromotionCoordinationReceipt Rejected(
        RepositoryCiPromotionJournalReceipt receipt,
        RepositoryCiPromotionOperation failedOperation = RepositoryCiPromotionOperation.Unspecified) => Result(
        RepositoryCiPromotionCoordinationDisposition.LeaseRejected,
        receipt.Disposition,
        receipt.Lease,
        failedOperation);

    private static RepositoryCiPromotionCoordinationReceipt AuthorityLost(
        RepositoryCiPromotionLease? lease = null,
        RepositoryCiPromotionOperation failedOperation = RepositoryCiPromotionOperation.Unspecified) => Result(
        RepositoryCiPromotionCoordinationDisposition.AuthorityLost,
        RepositoryCiPromotionJournalDisposition.StaleAuthority,
        lease,
        failedOperation);

    private static RepositoryCiPromotionCoordinationReceipt Result(
        RepositoryCiPromotionCoordinationDisposition disposition,
        RepositoryCiPromotionJournalDisposition journalDisposition,
        RepositoryCiPromotionLease? lease,
        RepositoryCiPromotionOperation failedOperation = RepositoryCiPromotionOperation.Unspecified) => new(
        disposition,
        journalDisposition,
        lease,
        failedOperation);

    private sealed record ForwardOutcome(
        RepositoryCiPromotionLease? Lease,
        RepositoryCiPromotionCoordinationReceipt? Receipt);
}
