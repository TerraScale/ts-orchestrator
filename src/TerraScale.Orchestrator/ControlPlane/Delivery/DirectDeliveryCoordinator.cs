using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>
/// The ordinary product delivery path. The coordinator owns the receipt and
/// safety ordering; infrastructure adapters own the actual mutation.
/// </summary>
public class DirectDeliveryCoordinator
{
    public const int MaximumOperationIdLength = 128;
    public const int MaximumTextLength = 512;
    public const int MaximumIdentityLength = 256;
    public const int MaximumRegionCount = 64;

    private readonly IDeliveryAuthorizer _authorizer;
    private readonly IDeliveryProvenanceVerifier _provenanceVerifier;
    private readonly IDeliveryTargetResolver _targetResolver;
    private readonly IDeliveryJournal _journal;
    private readonly IDeliveryArtifactBuilder? _artifactBuilder;
    private readonly Func<string> _auditIdFactory;
    private readonly Func<DeliveryRequest, bool> _authorityIsCurrent;

    public DirectDeliveryCoordinator(
        IDeliveryAuthorizer authorizer,
        IDeliveryProvenanceVerifier provenanceVerifier,
        IDeliveryTargetResolver targetResolver,
        IDeliveryJournal journal,
        IDeliveryArtifactBuilder? artifactBuilder = null,
        Func<string>? auditIdFactory = null,
        Func<DeliveryRequest, bool>? authorityIsCurrent = null)
    {
        _authorizer = authorizer ?? throw new ArgumentNullException(nameof(authorizer));
        _provenanceVerifier = provenanceVerifier ?? throw new ArgumentNullException(nameof(provenanceVerifier));
        _targetResolver = targetResolver ?? throw new ArgumentNullException(nameof(targetResolver));
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _artifactBuilder = artifactBuilder;
        _auditIdFactory = auditIdFactory ?? (() => $"audit-{Guid.NewGuid():N}");
        _authorityIsCurrent = authorityIsCurrent ?? (_ => true);
    }

    private bool AuthorityIsCurrent(DeliveryRequest request)
    {
        try
        {
            return _authorityIsCurrent(request);
        }
        catch (Exception exception) when (IsAdapterFailure(exception))
        {
            return false;
        }
    }

    /// <summary>Accepts the wire document and always returns a redacted receipt.</summary>
    public async ValueTask<DeliveryReceipt> DeliverJsonAsync(string? json, CancellationToken cancellationToken = default)
    {
        DeliveryRequest request;
        try
        {
            request = DeliveryWireCodec.DeserializeRequest(json ?? string.Empty);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException)
        {
            return FailureReceipt(null, DirectDeliveryErrorCode.InvalidInput);
        }

        return await DeliverAsync(request, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask<DeliveryReceipt> ExecuteJsonAsync(string? json, CancellationToken cancellationToken = default) =>
        DeliverJsonAsync(json, cancellationToken);

    /// <summary>Executes one idempotent, directly authorized delivery request.</summary>
    public async ValueTask<DeliveryReceipt> DeliverAsync(DeliveryRequest? request, CancellationToken cancellationToken = default)
    {
        var validationError = ValidateRequest(request);
        if (validationError is not null)
            return FailureReceipt(request, validationError);

        // Admittance is the explicit fail-closed contract replacing nullable assertions: a request
        // that passed validation but does not carry its validated shape is rejected, never coerced.
        if (Admit(request) is not { } admitted)
            return FailureReceipt(request, DirectDeliveryErrorCode.InvalidInput);
        var wire = admitted.Wire;

        try
        {
            var authorization = await _authorizer.AuthorizeAsync(wire, cancellationToken).ConfigureAwait(false);
            if (authorization is null || !authorization.Authorized)
                return FailureReceipt(wire, DirectDeliveryErrorCode.UnauthorizedActor);
        }
        catch (OperationCanceledException)
        {
            return FailureReceipt(wire, DirectDeliveryErrorCode.Cancelled);
        }
        catch (Exception exception) when (IsAdapterFailure(exception))
        {
            // A denial and an unreachable boundary are different operator actions; only
            // infrastructure-class failures report as transient.
            return FailureReceipt(wire, IsTransientInfrastructure(exception)
                ? DirectDeliveryErrorCode.AuthorizationUnavailable
                : DirectDeliveryErrorCode.UnauthorizedActor);
        }

        DeliveryArtifact? artifact = wire.Artifact;
        if (artifact is null)
        {
            if (admitted.Source is not { } source)
                return FailureReceipt(wire, DirectDeliveryErrorCode.InvalidInput);
            try
            {
                artifact = await (_artifactBuilder?.BuildAsync(wire, source, cancellationToken)
                    ?? ValueTask.FromResult<DeliveryArtifact?>(null)).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return FailureReceipt(wire, DirectDeliveryErrorCode.Cancelled);
            }
            catch (Exception exception) when (IsAdapterFailure(exception))
            {
                return FailureReceipt(wire, DirectDeliveryErrorCode.InvalidInput);
            }

            if (artifact is null)
                return FailureReceipt(wire, DirectDeliveryErrorCode.InvalidInput);
        }

        var artifactError = ValidateArtifact(artifact);
        if (artifactError is not null)
            return FailureReceipt(wire, artifactError, artifact.Digest);

        // The constructed artifact is part of the canonical operation identity. A source-only
        // request can never silently reuse an operation for a different build output.
        if (Admit(wire with { Artifact = artifact }) is not { } built)
            return FailureReceipt(wire, DirectDeliveryErrorCode.InvalidInput, artifact.Digest,
                artifactManifestDigest: artifact.ManifestDigest);
        admitted = built;
        wire = built.Wire;
        var operationId = admitted.OperationId;
        var regions = admitted.Regions;
        var fingerprint = RequestFingerprint(wire);
        DeliveryJournalRecord? existing;
        try
        {
            existing = await _journal.ReadAsync(operationId, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return FailureReceipt(wire, DirectDeliveryErrorCode.Cancelled, artifact.Digest, artifactManifestDigest: artifact.ManifestDigest);
        }
        catch (Exception exception) when (IsAdapterFailure(exception))
        {
            // Routed through the failure-detail mapping: an unreadable durable record (a
            // pre-codec shape or corruption) must NOT get the "restore journal health and
            // retry" remediation — no amount of health restoration makes those bytes
            // replayable by this build.
            return WithJournalFailureDetail(
                FailureReceipt(wire, DirectDeliveryErrorCode.JournalUnavailable, artifact.Digest,
                    artifactManifestDigest: artifact.ManifestDigest),
                exception);
        }

        if (existing is not null)
        {
            // The request fingerprint is exact identity (hash of the canonical request); the
            // artifact digest is content-addressed hex and compares case-insensitively,
            // consistent with digest semantics everywhere else in this seam.
            if (!string.Equals(existing.RequestFingerprint, fingerprint, StringComparison.Ordinal) ||
                existing.ArtifactDigest is not null && !string.Equals(existing.ArtifactDigest, artifact.Digest, StringComparison.OrdinalIgnoreCase))
                return FailureReceipt(wire, DirectDeliveryErrorCode.OperationConflict, artifact.Digest,
                    artifactManifestDigest: artifact.ManifestDigest);
            if (existing.Receipt is not null && !NeedsRollbackRecovery(existing) && !IsReplayableFailure(existing))
                return existing.Receipt;
        }

        // Resolution is a dispatch boundary. A leader/takeover transition between envelope
        // validation and adapter selection must fence the operation before it can reach a target.
        if (!AuthorityIsCurrent(wire))
            return FailureReceipt(wire, DirectDeliveryErrorCode.AuthorityFenced, artifact.Digest,
                provenance: null, artifactManifestDigest: artifact.ManifestDigest);

        IDeliveryTarget? target;
        try
        {
            target = await _targetResolver.ResolveAsync(admitted.Target, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return FailureReceipt(wire, DirectDeliveryErrorCode.Cancelled, artifact.Digest, artifactManifestDigest: artifact.ManifestDigest);
        }
        catch (Exception exception) when (IsAdapterFailure(exception))
        {
            return FailureReceipt(wire, DirectDeliveryErrorCode.UnknownTarget, artifact.Digest,
                artifactManifestDigest: artifact.ManifestDigest);
        }

        if (target is null)
            return FailureReceipt(wire, DirectDeliveryErrorCode.UnknownTarget, artifact.Digest,
                artifactManifestDigest: artifact.ManifestDigest);

        DeliveryProvenanceResult provenance;
        try
        {
            provenance = await _provenanceVerifier.VerifyAsync(wire, artifact, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return FailureReceipt(wire, DirectDeliveryErrorCode.Cancelled, artifact.Digest, artifactManifestDigest: artifact.ManifestDigest);
        }
        catch (Exception exception) when (IsAdapterFailure(exception))
        {
            return FailureReceipt(wire, IsTransientInfrastructure(exception)
                ? DirectDeliveryErrorCode.ProvenanceUnavailable
                : DirectDeliveryErrorCode.ProvenanceFailed, artifact.Digest,
                artifactManifestDigest: artifact.ManifestDigest);
        }

        if (provenance is null || provenance.Stale)
            return FailureReceipt(wire, DirectDeliveryErrorCode.StaleDigest, artifact.Digest, provenance, artifact.ManifestDigest);
        if (!provenance.Verified)
            return FailureReceipt(wire, DirectDeliveryErrorCode.ProvenanceFailed, artifact.Digest, provenance, artifact.ManifestDigest);

        var progress = ProgressSnapshot(regions, existing?.Regions);
        if (existing is null)
        {
            try
            {
                await PersistAsync(operationId, fingerprint, DeliveryJournalState.Accepted, null,
                    artifact.Digest, progress, cancellationToken, wire).ConfigureAwait(false);
            }
            catch (DirectDeliveryJournalConflictException)
            {
                // Admission fencing: a concurrent delivery won the operationId with a different
                // request fingerprint; only the winner may mutate.
                return FailureReceipt(wire, DirectDeliveryErrorCode.OperationConflict, artifact.Digest,
                    artifactManifestDigest: artifact.ManifestDigest);
            }
            catch (OperationCanceledException)
            {
                return FailureReceipt(wire, DirectDeliveryErrorCode.Cancelled, artifact.Digest, provenance, artifact.ManifestDigest);
            }
            catch (Exception exception) when (IsAdapterFailure(exception))
            {
                return FailureReceipt(wire, DirectDeliveryErrorCode.JournalUnavailable, artifact.Digest, provenance, artifact.ManifestDigest);
            }
        }

        if (NeedsRollbackRecovery(existing))
        {
            var recoveryChecks = new List<DeliveryHealthCheck>();
            var recovery = await RollbackAsync(
                wire,
                operationId,
                artifact,
                target,
                progress,
                fingerprint,
                recoveryChecks,
                cancellationToken).ConfigureAwait(false);
            return await CompleteRollbackAsync(
                wire,
                operationId,
                fingerprint,
                artifact,
                provenance,
                recoveryChecks,
                progress,
                recovery,
                cancellationToken).ConfigureAwait(false);
        }

        var checks = new List<DeliveryHealthCheck>();
        var mutated = ProgressMutations(progress);
        string? failure;
        try
        {
            failure = await ApplyInOrderAsync(wire, operationId, regions, artifact, target, fingerprint, checks, progress, mutated, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (DeliveryJournalUnavailableException exception)
        {
            // The durable journal went down mid-apply. The target is not at fault, so no
            // rollback is attempted: the last durable per-region progress is the resume point
            // and the same operationId replays it (replayable failure, J2 semantics).
            return WithJournalFailureDetail(
                FailureReceipt(
                    wire,
                    DirectDeliveryErrorCode.JournalUnavailable,
                    artifact.Digest,
                    provenance,
                    artifact.ManifestDigest),
                exception);
        }
        catch (DirectDeliveryJournalConflictException exception)
        {
            // A same-request CAS loss on a later progress persist ('applied', 'healthy', or the
            // failure record): the concurrent winner owns the durable progress and retrying the
            // same operationId self-heals from it. Same J2 mapping as the applying-persist
            // conflict inside ApplyInOrderAsync — never a target rollback, and never an
            // uncaught exception escaping the receipt contract.
            return WithJournalFailureDetail(
                FailureReceipt(
                    wire,
                    DirectDeliveryErrorCode.JournalUnavailable,
                    artifact.Digest,
                    provenance,
                    artifact.ManifestDigest),
                exception);
        }
        catch (OperationCanceledException)
        {
            // Cancellation escaping a post-mutation progress persist ('applied' or 'healthy'):
            // the in-memory progress already carries the region's state, the failure path
            // records any write-ahead debt best-effort with a live token, and the caller still
            // receives a receipt — cancellation must never leave the operation without one.
            return await CompleteFailureAsync(wire, operationId, fingerprint, artifact, provenance, target, checks, progress, mutated,
                DirectDeliveryErrorCode.Cancelled, cancellationToken).ConfigureAwait(false);
        }
        if (failure is not null)
            return await CompleteFailureAsync(wire, operationId, fingerprint, artifact, provenance, target, checks, progress, mutated, failure,
                cancellationToken).ConfigureAwait(false);

        DeliveryConvergenceResult convergence;
        try
        {
            convergence = await target.CheckConvergenceAsync(wire, artifact, regions, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return await CompleteFailureAsync(wire, operationId, fingerprint, artifact, provenance, target, checks, progress, mutated,
                DirectDeliveryErrorCode.Cancelled, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (IsAdapterFailure(exception))
        {
            return await CompleteFailureAsync(wire, operationId, fingerprint, artifact, provenance, target, checks, progress, mutated,
                DirectDeliveryErrorCode.ConvergenceFailed, cancellationToken).ConfigureAwait(false);
        }

        if (convergence is null || !convergence.Converged)
            return await CompleteFailureAsync(wire, operationId, fingerprint, artifact, provenance, target, checks, progress, mutated,
                DirectDeliveryErrorCode.ConvergenceFailed, cancellationToken).ConfigureAwait(false);

        var receipt = SuccessReceipt(wire, artifact, provenance, checks, convergence.Converged);
        try
        {
            await _journal.AppendAsync(new DeliveryJournalRecord(operationId, fingerprint, DeliveryJournalState.Succeeded, receipt,
                    artifact.Digest, progress.ToArray(),
                    wire.AuthorityGeneration,
                    wire.WriterEpoch,
                    wire.Attempt), cancellationToken).ConfigureAwait(false);
            return receipt;
        }
        catch (OperationCanceledException exception)
        {
            return JournalFailedAfterSuccess(exception);
        }
        catch (Exception exception) when (IsAdapterFailure(exception))
        {
            return JournalFailedAfterSuccess(exception);
        }

        // The deployment is fully applied, healthy, and converged; only the final journal append
        // failed. Rolling a healthy deployment back because OUR journal is down would destroy
        // good state: report the replayable journal-unavailable receipt instead. Durable
        // per-region progress is already 'healthy', so a retry replays to convergence and
        // appends the terminal record then.
        DeliveryReceipt JournalFailedAfterSuccess(Exception exception) =>
            WithJournalFailureDetail(
                FailureReceipt(
                    wire,
                    DirectDeliveryErrorCode.JournalUnavailable,
                    artifact.Digest,
                    provenance,
                    artifact.ManifestDigest),
                exception);
    }

    public ValueTask<DeliveryReceipt> ExecuteAsync(DeliveryRequest? request, CancellationToken cancellationToken = default) =>
        DeliverAsync(request, cancellationToken);

    private async ValueTask<string?> ApplyInOrderAsync(
        DeliveryRequest request,
        string operationId,
        IReadOnlyList<string> regions,
        DeliveryArtifact artifact,
        IDeliveryTarget target,
        string fingerprint,
        List<DeliveryHealthCheck> checks,
        List<DeliveryRegionProgress> progress,
        List<MutationSnapshot> mutated,
        CancellationToken cancellationToken)
    {
        foreach (var region in regions)
        {
            var current = progress.Single(value => value.Region == region);
            if (current.State == "healthy")
            {
                AddMutation(current, mutated);
                continue;
            }

            DeliveryMutationResult mutation;
            if (current.State == "applied")
            {
                mutation = new DeliveryMutationResult(
                    true,
                    true,
                    current.PreviousArtifactDigest,
                    PreviousManifestDigest: current.PreviousManifestDigest);
            }
            else
            {
                try
                {
                    // Write-ahead rollback target: persist the region's current digest in the
                    // 'applying' record BEFORE mutating, so a crash between ApplyAsync and the
                    // 'applied' persist keeps the exact previous digest durably recoverable.
                    var writeAhead = await target.ObserveCurrentArtifactAsync(request, region, cancellationToken)
                        .ConfigureAwait(false);
                    if (writeAhead is not null &&
                        (!IsDigest(writeAhead.Digest) || !IsDigest(writeAhead.ManifestDigest)))
                        return DirectDeliveryErrorCode.MutationFailed;
                    // A region already running the requested digest has no rollback target: the
                    // write-ahead records no previous digest for it (mutating nothing).
                    var writeAheadPrevious =
                        writeAhead is not null &&
                        !string.Equals(writeAhead.Digest, artifact.Digest, StringComparison.OrdinalIgnoreCase)
                            ? writeAhead.Digest
                            : current.PreviousArtifactDigest;
                    var writeAheadPreviousManifest =
                        writeAhead is not null &&
                        !string.Equals(writeAhead.Digest, artifact.Digest, StringComparison.OrdinalIgnoreCase)
                            ? writeAhead.ManifestDigest
                            : current.PreviousManifestDigest;
                    var currentIndex = progress.IndexOf(current);
                    current = current with
                    {
                        State = DeliveryJournalState.Applying,
                        PreviousArtifactDigest = writeAheadPrevious,
                        PreviousManifestDigest = writeAheadPreviousManifest,
                    };
                    progress[currentIndex] = current;
                    await PersistAsync(operationId, fingerprint, DeliveryJournalState.Applying, null,
                        artifact.Digest, progress, cancellationToken, request).ConfigureAwait(false);
                    if (!AuthorityIsCurrent(request))
                        return DirectDeliveryErrorCode.AuthorityFenced;
                    // Per-mutation fence at the target seam (E11): the adapter applies only when
                    // the region STILL holds the digest this delivery durably recorded as the
                    // rollback target. A concurrent mutation inside the observe→apply window
                    // reports the typed mutation-race outcome instead of leaving a stale
                    // rollback target behind. Digest-only adapters cannot fence and keep the
                    // write-ahead record as their only rollback material.
                    var expectedPrevious = writeAhead?.Digest ?? current.PreviousArtifactDigest;
                    mutation = await target.ApplyFencedAsync(request, artifact, region, expectedPrevious, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Cancellation with a durably recorded write-ahead must not silently drop
                    // the region's recovery target: the region is marked as rollback debt so
                    // the failure path below collects it (idempotently — the rollback's
                    // already-restored observation converges for a mutation that never
                    // landed), and the best-effort persist uses a live token because the
                    // caller's is dead. A region with no write-ahead debt (pristine, or
                    // already running the requested digest) mutated nothing worth debt.
                    if (current.State == DeliveryJournalState.Applying &&
                        IsDigest(current.PreviousArtifactDigest) && IsDigest(current.PreviousManifestDigest))
                    {
                        progress[progress.IndexOf(current)] = current with
                        {
                            State = "rollback_pending",
                            ErrorCode = DirectDeliveryErrorCode.Cancelled,
                        };
                        await TryPersistProgressAsync(operationId, fingerprint, request, artifact, progress, CancellationToken.None)
                            .ConfigureAwait(false);
                    }
                    return DirectDeliveryErrorCode.Cancelled;
                }
                catch (DeliveryJournalUnavailableException)
                {
                    throw;
                }
                catch (DirectDeliveryJournalConflictException exception)
                {
                    // Deliberate mapping: a same-request CAS loss mid-apply reports the
                    // replayable journal-unavailable failure rather than a target failure — the
                    // concurrent winner owns the durable progress, and retrying the same
                    // operationId self-heals from it (no rollback of target state is attempted).
                    throw new DeliveryJournalUnavailableException(exception);
                }
                catch (Exception exception) when (IsAdapterFailure(exception))
                {
                    // The mutation was in flight when the adapter failed, so whether it landed
                    // is unknown. A region whose write-ahead was durably recorded carries its
                    // previous digests as rollback debt: the rollback's already-restored
                    // observation makes collection idempotent (an unmutated region converges
                    // without a second mutation). A failure before the write-ahead (observation)
                    // mutated nothing and records a plain failure.
                    progress[progress.IndexOf(progress.Single(value => value.Region == region))] = current with
                    {
                        State = current.State == DeliveryJournalState.Applying
                            ? "rollback_pending"
                            : DeliveryJournalState.Failed,
                        ErrorCode = DirectDeliveryErrorCode.MutationFailed,
                    };
                    await PersistAsync(operationId, fingerprint, DeliveryJournalState.Failed, null,
                        artifact.Digest, progress, cancellationToken, request).ConfigureAwait(false);
                    return DirectDeliveryErrorCode.MutationFailed;
                }
            }

            if (mutation is null)
                return DirectDeliveryErrorCode.MutationFailed;

            // Rollback-material contract: a region that already ran a DIFFERENT artifact must
            // report its exact previous digest, or the mutation is unsafe to leave unrecoverable.
            // A PRISTINE region (no prior artifact — first-ever deployment) has nothing to roll
            // back to by definition: it proceeds with no previous digest, and a later failure
            // leaves it deployed (bootstrap expectation, surfaced in the failure receipt).
            if (mutation.Mutated && current.PreviousArtifactDigest is not null &&
                (!IsDigest(mutation.PreviousArtifactDigest) ||
                 !IsDigest(mutation.PreviousManifestDigest) &&
                 !IsDigest(current.PreviousManifestDigest)))
                return DirectDeliveryErrorCode.RollbackFailed;

            if (!mutation.Succeeded)
            {
                // Typed-outcome preservation: only the whitelisted adapter failure codes are
                // durable/receipt material — an adapter's free-text code must never reach the
                // journal or a receipt. mutation_race keeps its distinct, bounded remediation;
                // everything else collapses to mutation_failed.
                var failureCode = mutation.FailureCode == DirectDeliveryErrorCode.MutationRace
                    ? DirectDeliveryErrorCode.MutationRace
                    : DirectDeliveryErrorCode.MutationFailed;
                progress[progress.IndexOf(progress.Single(value => value.Region == region))] = current with
                {
                    State = DeliveryJournalState.Failed,
                    ErrorCode = failureCode,
                };
                await PersistAsync(operationId, fingerprint, DeliveryJournalState.Failed, null,
                    artifact.Digest, progress, cancellationToken, request).ConfigureAwait(false);
                return failureCode;
            }

            if (mutation.Mutated)
            {
                // The adapter's mutation-time previous digest is authoritative only when it is
                // the FIRST durable rollback material (digest-only adapters, whose observation
                // cannot run) or when it agrees with the already-durable write-ahead (the fenced
                // path guarantees agreement). When it disagrees with a durable value, a
                // concurrent writer raced an unfenced adapter: the durable observation stays the
                // rollback target, because rewriting recorded rollback material is forbidden —
                // the journal would reject it and the older digest is the one this delivery
                // durably committed to restore.
                if (IsDigest(mutation.PreviousArtifactDigest) && IsDigest(mutation.PreviousManifestDigest) &&
                    (current.PreviousArtifactDigest is null ||
                     (string.Equals(current.PreviousArtifactDigest, mutation.PreviousArtifactDigest, StringComparison.OrdinalIgnoreCase) &&
                      string.Equals(current.PreviousManifestDigest, mutation.PreviousManifestDigest, StringComparison.OrdinalIgnoreCase))))
                    current = current with
                    {
                        PreviousArtifactDigest = mutation.PreviousArtifactDigest,
                        PreviousManifestDigest = mutation.PreviousManifestDigest,
                    };
            }

            if (current.State != "applied")
            {
                current = current with { State = "applied", ErrorCode = null };
                progress[progress.IndexOf(progress.Single(value => value.Region == region))] = current;
            }
            await PersistAsync(operationId, fingerprint, "applied", null,
                artifact.Digest, progress, cancellationToken, request).ConfigureAwait(false);

            DeliveryHealthResult health;
            try
            {
                health = await target.CheckHealthAsync(request, artifact, region, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return DirectDeliveryErrorCode.Cancelled;
            }
            catch (Exception exception) when (IsAdapterFailure(exception))
            {
                return DirectDeliveryErrorCode.HealthFailed;
            }

            if (health?.Checks is not null)
                checks.AddRange(health.Checks.Where(static check => check is not null));
            if (health is null || health.Checks is null || health.Checks.Count == 0 || !health.Passed ||
                health.Checks.Any(static check => check is null ||
                    !IsBoundedText(check.Name, MaximumTextLength) || check.Status != DeliveryHealthStatus.Passed))
            {
                progress[progress.IndexOf(progress.Single(value => value.Region == region))] = current with
                {
                    State = "health_failed",
                    ErrorCode = DirectDeliveryErrorCode.HealthFailed,
                };
                await PersistAsync(operationId, fingerprint, DeliveryJournalState.Failed, null,
                    artifact.Digest, progress, cancellationToken, request).ConfigureAwait(false);
                return DirectDeliveryErrorCode.HealthFailed;
            }

            progress[progress.IndexOf(progress.Single(value => value.Region == region))] = current with
            {
                State = "healthy",
                ErrorCode = null,
            };
            await PersistAsync(operationId, fingerprint, "healthy", null,
                artifact.Digest, progress, cancellationToken, request).ConfigureAwait(false);
        }

        return null;
    }

    private async ValueTask<DeliveryReceipt> CompleteFailureAsync(
        DeliveryRequest request,
        string operationId,
        string fingerprint,
        DeliveryArtifact artifact,
        DeliveryProvenanceResult provenance,
        IDeliveryTarget target,
        List<DeliveryHealthCheck> checks,
        List<DeliveryRegionProgress> progress,
        IReadOnlyList<MutationSnapshot> mutated,
        string errorCode,
        CancellationToken cancellationToken)
    {
        // Recompute from durable progress: regions may have become mutated after the caller
        // captured its list, and a mutation we fail to roll back is silent data loss.
        mutated = ProgressMutations(progress);
        if (mutated.Count == 0)
        {
            var failureReceipt = CreateReceipt(request, DeliveryReceiptStatus.Failed, artifact.Digest, provenance, checks, false,
                new DeliveryRollback(false, null, DeliveryRollbackStatus.NotRequired), errorCode, artifact.ManifestDigest);
            // First-deployment contract: a region deployed for the first time has no prior
            // artifact to roll back to, so it stays deployed after this failure. The receipt
            // says so explicitly instead of implying a rollback happened or was possible. An
            // 'applying' region (cancelled or crashed between the write-ahead and the
            // 'applied' persist) has no debt by construction here and is named too: it was
            // left unhealth-checked, never silently.
            if (progress.Any(static region =>
                    region.State is "applied" or "healthy" or "health_failed" or DeliveryJournalState.Applying))
            {
                failureReceipt = failureReceipt with
                {
                    Error = failureReceipt.Error with
                    {
                        Remediation = (string.IsNullOrWhiteSpace(failureReceipt.Error.Remediation)
                                ? string.Empty
                                : failureReceipt.Error.Remediation + " ") +
                            "Region(s) deployed for the first time have no prior artifact to roll back to and remain deployed; " +
                            "remediate them or redeploy a fixed artifact (bootstrap expectation).",
                    },
                };
            }
            return await PersistedOrSurfacedAsync(
                failureReceipt, operationId, fingerprint, DeliveryJournalState.Failed, artifact.Digest, progress, cancellationToken, request)
                .ConfigureAwait(false);
        }

        var rollbackChecks = new List<DeliveryHealthCheck>();
        var rollback = await RollbackAsync(request, operationId, artifact, target, progress, fingerprint, rollbackChecks, cancellationToken)
            .ConfigureAwait(false);
        checks.AddRange(rollbackChecks);
        // A rollback that failed because the OPERATION was cancelled keeps the replayable
        // 'cancelled' code (the retry guidance and IsReplayableFailure depend on it): the
        // regions' durable rollback_failed progress still records the recovery debt. Only a
        // rollback that failed on its own merits reports rollback_failed.
        var finalError = rollback.Status == DeliveryRollbackStatus.Succeeded
            ? (string?)null
            : errorCode == DirectDeliveryErrorCode.Cancelled
                ? DirectDeliveryErrorCode.Cancelled
                : DirectDeliveryErrorCode.RollbackFailed;
        var status = rollback.Status == DeliveryRollbackStatus.Succeeded
            ? DeliveryReceiptStatus.RolledBack
            : DeliveryReceiptStatus.Failed;
        var receipt = CreateReceipt(request, status, artifact.Digest, provenance, checks,
            status == DeliveryReceiptStatus.RolledBack, rollback, finalError ?? errorCode, artifact.ManifestDigest);
        // First-deployment contract: pristine regions that were deployed and NOT rolled back
        // (no prior artifact exists) stay deployed; the receipt says so instead of implying the
        // whole target was restored.
        if (progress.Any(static region =>
                region.State is "applied" or "healthy" or "health_failed" or DeliveryJournalState.Applying))
        {
            receipt = receipt with
            {
                Error = receipt.Error with
                {
                    Remediation = (string.IsNullOrWhiteSpace(receipt.Error.Remediation)
                            ? string.Empty
                            : receipt.Error.Remediation + " ") +
                        "Region(s) deployed for the first time have no prior artifact to roll back to and remain deployed; " +
                        "remediate them or redeploy a fixed artifact (bootstrap expectation).",
                },
            };
        }
        return await PersistedOrSurfacedAsync(
            receipt,
            operationId,
            fingerprint,
            status == DeliveryReceiptStatus.RolledBack ? DeliveryJournalState.RolledBack : DeliveryJournalState.Failed,
            artifact.Digest,
            progress,
            // The terminal receipt persist is not cancellable work: its content is already
            // decided, so a dead caller token (e.g. cancellation between the rollback and this
            // persist) must not cost durability of the outcome.
            CancellationToken.None,
            request).ConfigureAwait(false);
    }

    private async ValueTask<DeliveryRollback> RollbackAsync(
        DeliveryRequest request,
        string operationId,
        DeliveryArtifact artifact,
        IDeliveryTarget target,
        List<DeliveryRegionProgress> progress,
        string fingerprint,
        List<DeliveryHealthCheck> checks,
        CancellationToken cancellationToken)
    {
        var mutated = ProgressMutations(progress);
        if (mutated.Count == 0)
            return new DeliveryRollback(false, null, DeliveryRollbackStatus.NotRequired);

        var succeeded = true;
        string? targetDigest = null;
        string? targetManifestDigest = null;
        foreach (var mutation in mutated.AsEnumerable().Reverse())
        {
            var current = progress.Single(value => value.Region == mutation.Region);
            // The recovery target is named from the first reverse-order region's durable
            // write-ahead digests whether or not its rollback completes: a rollback mutation or
            // health failure must still report the exact digest the operator has to restore
            // (AC4), not a digestless failure.
            targetDigest ??= mutation.PreviousArtifactDigest;
            targetManifestDigest ??= mutation.PreviousManifestDigest;
            if (current.State == "rollback_succeeded")
                continue;
            progress[progress.IndexOf(current)] = current with { State = DeliveryJournalState.RollingBack, ErrorCode = null };
            await TryPersistProgressAsync(operationId, fingerprint, request, artifact, progress, cancellationToken).ConfigureAwait(false);
            try
            {
                if (!AuthorityIsCurrent(request))
                {
                    succeeded = false;
                    progress[progress.IndexOf(progress.Single(value => value.Region == mutation.Region))] = current with
                    {
                        State = "rollback_failed",
                        ErrorCode = DirectDeliveryErrorCode.AuthorityFenced,
                    };
                    await TryPersistProgressAsync(operationId, fingerprint, request, artifact, progress, cancellationToken).ConfigureAwait(false);
                    continue;
                }
                var observed = await target.ObserveCurrentArtifactAsync(
                    request, mutation.Region, cancellationToken).ConfigureAwait(false);
                var requestedArtifact = observed is not null &&
                    SameArtifact(observed, artifact);
                var alreadyRestored = observed is not null &&
                    SameArtifact(observed, new DeliveryArtifact(
                        mutation.PreviousArtifactDigest,
                        mutation.PreviousManifestDigest,
                        artifact.Kind));
                if (!requestedArtifact && !alreadyRestored)
                {
                    succeeded = false;
                    progress[progress.IndexOf(progress.Single(value => value.Region == mutation.Region))] = current with
                    {
                        State = "rollback_failed",
                        ErrorCode = DirectDeliveryErrorCode.RollbackFailed,
                    };
                    await TryPersistProgressAsync(operationId, fingerprint, request, artifact, progress, cancellationToken).ConfigureAwait(false);
                    continue;
                }
                var result = alreadyRestored
                    ? new DeliveryRollbackResult(
                        true,
                        mutation.PreviousArtifactDigest,
                        new DeliveryArtifact(mutation.PreviousArtifactDigest, mutation.PreviousManifestDigest, artifact.Kind))
                    : await target.RollbackAsync(
                        request,
                        mutation.Region,
                        mutation.PreviousArtifactDigest,
                        mutation.PreviousManifestDigest,
                        cancellationToken).ConfigureAwait(false);
                if (!alreadyRestored && (result is null || !result.Succeeded || result.Artifact is not { } exactArtifact ||
                    !SameArtifact(exactArtifact, new DeliveryArtifact(
                        mutation.PreviousArtifactDigest, mutation.PreviousManifestDigest, artifact.Kind))))
                {
                    succeeded = false;
                    progress[progress.IndexOf(progress.Single(value => value.Region == mutation.Region))] = current with
                    {
                        State = "rollback_failed",
                        ErrorCode = DirectDeliveryErrorCode.RollbackFailed,
                    };
                    await TryPersistProgressAsync(operationId, fingerprint, request, artifact, progress, cancellationToken).ConfigureAwait(false);
                    continue;
                }
                var rollbackArtifact = result.Artifact;
                if (rollbackArtifact is null)
                    throw new InvalidDataException("The rollback adapter omitted exact artifact provenance.");
                var health = await target.CheckHealthAsync(request, rollbackArtifact, mutation.Region, cancellationToken)
                    .ConfigureAwait(false);
                if (health?.Checks is not null)
                    checks.AddRange(health.Checks.Where(static check => check is not null));
                if (health is null || !health.Passed || health.Checks is null || health.Checks.Count == 0 ||
                    health.Checks.Any(static check => check is null || check.Status != DeliveryHealthStatus.Passed))
                {
                    succeeded = false;
                    progress[progress.IndexOf(progress.Single(value => value.Region == mutation.Region))] = current with
                    {
                        State = "rollback_failed",
                        ErrorCode = DirectDeliveryErrorCode.RollbackFailed,
                    };
                    await TryPersistProgressAsync(operationId, fingerprint, request, artifact, progress, cancellationToken).ConfigureAwait(false);
                    continue;
                }
                progress[progress.IndexOf(progress.Single(value => value.Region == mutation.Region))] = current with
                {
                    State = "rollback_succeeded",
                    ErrorCode = null,
                };
                await TryPersistProgressAsync(operationId, fingerprint, request, artifact, progress, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                succeeded = false;
                progress[progress.IndexOf(progress.Single(value => value.Region == mutation.Region))] = current with
                {
                    State = "rollback_failed",
                    ErrorCode = DirectDeliveryErrorCode.Cancelled,
                };
                await TryPersistProgressAsync(operationId, fingerprint, request, artifact, progress, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception exception) when (IsAdapterFailure(exception))
            {
                succeeded = false;
                progress[progress.IndexOf(progress.Single(value => value.Region == mutation.Region))] = current with
                {
                    State = "rollback_failed",
                    ErrorCode = DirectDeliveryErrorCode.RollbackFailed,
                };
                await TryPersistProgressAsync(operationId, fingerprint, request, artifact, progress, CancellationToken.None).ConfigureAwait(false);
            }
        }

        if (succeeded && targetDigest is not null)
        {
            try
            {
                if (!IsDigest(targetDigest) || !IsDigest(targetManifestDigest))
                    return new DeliveryRollback(true, null, DeliveryRollbackStatus.Failed);
                // M5: rollback convergence is PER-REGION. Regions can legitimately hold distinct
                // previous digests, so each mutated region is verified against ITS recorded
                // write-ahead previous digest; the shared single-call fast path is kept only
                // when every mutated region shares one previous artifact. Unmutated regions
                // (pristine, or already running the requested digest) are not part of the
                // rollback and must not be converged against a previous digest they never held.
                succeeded = await VerifyRollbackConvergenceAsync(
                    request, artifact, target, mutated, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                succeeded = false;
            }
            catch (Exception exception) when (IsAdapterFailure(exception))
            {
                succeeded = false;
            }
            if (!succeeded)
            {
                for (var index = 0; index < progress.Count; index++)
                {
                    if (progress[index].State == "rollback_succeeded")
                        progress[index] = progress[index] with
                        {
                            State = "rollback_failed",
                            ErrorCode = DirectDeliveryErrorCode.RollbackFailed,
                        };
                }
                await TryPersistProgressAsync(operationId, fingerprint, request, artifact, progress, CancellationToken.None).ConfigureAwait(false);
            }
        }

        return new DeliveryRollback(
            true,
            targetDigest,
            succeeded ? DeliveryRollbackStatus.Succeeded : DeliveryRollbackStatus.Failed,
            // Both identities travel together (the journal validates digest/manifest presence as
            // a pair), and a failed rollback still names the exact digest to restore.
            targetManifestDigest);
    }

    /// <summary>
    /// Verifies rollback convergence per mutated region against that region's own recorded
    /// write-ahead previous digest, preserving the one-call fast path when all mutated regions
    /// share the same previous artifact.
    /// </summary>
    private static async ValueTask<bool> VerifyRollbackConvergenceAsync(
        DeliveryRequest request,
        DeliveryArtifact artifact,
        IDeliveryTarget target,
        IReadOnlyList<MutationSnapshot> mutated,
        CancellationToken cancellationToken)
    {
        var shared = new DeliveryArtifact(
            mutated[0].PreviousArtifactDigest,
            mutated[0].PreviousManifestDigest,
            artifact.Kind);
        var mutatedRegions = mutated.Select(static mutation => mutation.Region).ToArray();
        if (mutated.All(mutation => SameArtifact(
                new DeliveryArtifact(mutation.PreviousArtifactDigest, mutation.PreviousManifestDigest, artifact.Kind),
                shared)))
        {
            var convergence = await target.CheckConvergenceAsync(request, shared, mutatedRegions, cancellationToken)
                .ConfigureAwait(false);
            return convergence is not null && convergence.Converged;
        }

        foreach (var mutation in mutated)
        {
            var expected = new DeliveryArtifact(
                mutation.PreviousArtifactDigest,
                mutation.PreviousManifestDigest,
                artifact.Kind);
            var convergence = await target.CheckConvergenceAsync(request, expected, [mutation.Region], cancellationToken)
                .ConfigureAwait(false);
            if (convergence is null || !convergence.Converged)
                return false;
        }
        return true;
    }

    private async ValueTask<DeliveryReceipt> CompleteRollbackAsync(
        DeliveryRequest request,
        string operationId,
        string fingerprint,
        DeliveryArtifact artifact,
        DeliveryProvenanceResult provenance,
        IReadOnlyList<DeliveryHealthCheck> checks,
        IReadOnlyList<DeliveryRegionProgress> progress,
        DeliveryRollback rollback,
        CancellationToken cancellationToken)
    {
        var succeeded = rollback.Status == DeliveryRollbackStatus.Succeeded;
        var receipt = CreateReceipt(
            request,
            succeeded ? DeliveryReceiptStatus.RolledBack : DeliveryReceiptStatus.Failed,
            artifact.Digest,
            provenance,
            checks,
            succeeded,
            rollback,
            succeeded ? null : DirectDeliveryErrorCode.RollbackFailed,
            artifact.ManifestDigest);
        return await PersistedOrSurfacedAsync(
            receipt,
            operationId,
            fingerprint,
            succeeded ? DeliveryJournalState.RolledBack : DeliveryJournalState.Failed,
            artifact.Digest,
            progress,
            cancellationToken,
            request).ConfigureAwait(false);
    }

    /// <summary>
    /// The durable journal failed while recording progress. Distinct from adapter (target)
    /// failures: the deployment may be fine, so callers report a replayable journal-unavailable
    /// outcome and never roll back healthy work because of it.
    /// </summary>
    private sealed class DeliveryJournalUnavailableException : Exception
    {
        public DeliveryJournalUnavailableException(Exception innerException)
            : base("The durable delivery journal is unavailable.", innerException) { }
    }

    /// <summary>
    /// A journal-unavailable receipt whose cause is a retention-cap overflow says so: the
    /// operator action is raising the cap (or letting the bounded horizon pass), not "restore
    /// journal health".
    /// </summary>
    private static DeliveryReceipt WithJournalFailureDetail(DeliveryReceipt receipt, Exception exception)
    {
        for (var cause = exception; cause is not null; cause = cause.InnerException)
        {
            if (cause is DirectDeliveryJournalConflictException)
            {
                // A continuity/write-ahead conflict is not journal ill-health: the durable
                // journal is fine and refused a progress append that contradicts the record
                // it owns. "Restore journal health" would send the operator to fix the wrong
                // thing entirely.
                return receipt with
                {
                    Error = receipt.Error with
                    {
                        Message = "The durable delivery journal rejected a conflicting progress append for this operation.",
                        Remediation =
                            "Another writer advanced this operation's durable progress (continuity or write-ahead rollback-material conflict); no update was lost. Reconcile the region state, then submit a new delivery request.",
                    },
                };
            }
            if (cause is TerraScale.Orchestrator.Delivery.JournalRetentionOverflowException)
            {
                return receipt with
                {
                    Error = receipt.Error with
                    {
                        Message = "The durable delivery journal is over its retention cap with unprunable records.",
                        Remediation =
                            "Raise the retention cap or let the bounded-age horizon pass, then retry the same operationId; the operation replays its durable progress.",
                    },
                };
            }
            if (cause is InvalidDataException)
            {
                // The durable record exists but this build's codec cannot round-trip it: it was
                // written before the current record shape (or the bytes are corrupt). This is
                // NOT a journal-health problem — no restoration makes those bytes readable,
                // and replaying the same operationId can never succeed against them.
                return receipt with
                {
                    Error = receipt.Error with
                    {
                        Message = "A durable delivery journal record for this operation cannot be read by the current record codec.",
                        Remediation =
                            "The journal record predates the current record codec and cannot be replayed; clear or drain the affected operation before continuing.",
                    },
                };
            }
        }
        return receipt;
    }

    private async ValueTask PersistAsync(
        string operationId,
        string fingerprint,
        string state,
        DeliveryReceipt? receipt,
        string? artifactDigest,
        IReadOnlyList<DeliveryRegionProgress> progress,
        CancellationToken cancellationToken,
        DeliveryRequest? request = null)
    {
        try
        {
            await _journal.AppendAsync(
                new DeliveryJournalRecord(
                    operationId,
                    fingerprint,
                    state,
                    receipt,
                    artifactDigest,
                    progress.ToArray(),
                    request?.AuthorityGeneration ?? 1,
                    request?.WriterEpoch ?? 1,
                    request?.Attempt ?? 1),
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        // The typed admission conflict must escape unwrapped so the admission catch in
        // DeliverAsync maps it to operation_conflict; wrapping it here made that catch dead and
        // reported admission-race losers as journal_unavailable.
        catch (DirectDeliveryJournalConflictException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not DeliveryJournalUnavailableException && IsAdapterFailure(exception))
        {
            throw new DeliveryJournalUnavailableException(exception);
        }
    }

    /// <summary>
    /// Best-effort bookkeeping persist for rollback progress: the rollback mutation itself must
    /// proceed even when the journal is degraded OR the operation's cancellation fired — the
    /// alternative (aborting mid-rollback because OUR bookkeeping failed) destroys the recovery
    /// path. This helper therefore never throws: the durable record may lag the actual
    /// rollback, the final receipt path surfaces the degraded state, and a retry replays the
    /// durable progress to convergence.
    /// </summary>
    private async ValueTask TryPersistProgressAsync(
        string operationId,
        string fingerprint,
        DeliveryRequest request,
        DeliveryArtifact artifact,
        IReadOnlyList<DeliveryRegionProgress> progress,
        CancellationToken cancellationToken)
    {
        try
        {
            await PersistAsync(operationId, fingerprint, DeliveryJournalState.Failed, null,
                artifact.Digest, progress, cancellationToken, request).ConfigureAwait(false);
        }
        catch (Exception exception) when (IsAdapterFailure(exception))
        {
            // Journal degraded (or cancelled) during rollback bookkeeping: the durable record
            // lags the actual rollback, and the receipt path below reports the journal-down
            // state. The in-progress rollback is never aborted mid-region.
        }
    }

    /// <summary>
    /// Persists the terminal receipt and returns it; when the journal is down the SAME receipt
    /// is returned with its remediation rewritten so the operator sees the record is not yet
    /// durable (never a silent swallow, and never a receipt that lies about durability).
    /// </summary>
    private async ValueTask<DeliveryReceipt> PersistedOrSurfacedAsync(
        DeliveryReceipt receipt,
        string operationId,
        string fingerprint,
        string state,
        string? artifactDigest,
        IReadOnlyList<DeliveryRegionProgress> progress,
        CancellationToken cancellationToken,
        DeliveryRequest request)
    {
        var persisted = await TryPersistReceiptAsync(
            operationId, fingerprint, state, receipt, artifactDigest, progress, cancellationToken, request).ConfigureAwait(false);
        if (persisted) return receipt;
        var remediation = string.IsNullOrWhiteSpace(receipt.Error.Remediation)
            ? string.Empty
            : receipt.Error.Remediation + " ";
        return receipt with
        {
            Error = receipt.Error with
            {
                Remediation = remediation +
                    "[journal currently unavailable: this receipt is not durable yet; retry the same operationId to replay durable progress]",
            },
        };
    }

    private async ValueTask<bool> TryPersistReceiptAsync(
        string operationId,
        string fingerprint,
        string state,
        DeliveryReceipt receipt,
        string? artifactDigest,
        IReadOnlyList<DeliveryRegionProgress> progress,
        CancellationToken cancellationToken,
        DeliveryRequest request)
    {
        try
        {
            await PersistAsync(operationId, fingerprint, state, receipt, artifactDigest, progress, cancellationToken, request)
                .ConfigureAwait(false);
            return true;
        }
        catch (Exception exception) when (IsAdapterFailure(exception))
        {
            // Not silent — including cancellation: the receipt is still returned with its
            // remediation rewritten so the operator sees it is not durable yet, and a retry of
            // the same operationId replays the durable progress. Throwing here would lose the
            // only in-memory copy of a completed rollback's outcome.
            return false;
        }
    }

    /// <summary>
    /// A journaled record whose rollback is still pending — including a region interrupted
    /// mid-rollback (<c>rolling_back</c>, the crash shape between the durable state change and
    /// the region's KV rollback): recovery must resume or complete the
    /// rollback instead of replaying a terminal receipt. A FAILURE whose terminal receipt never
    /// became durable (crash or journal outage between the failure-progress persist and the
    /// receipt persist) also owes recovery when its regions still carry forward write-ahead
    /// debt: the delivery already failed, so replay must resume the failure path (rollback),
    /// never re-apply a failed delivery. A receipt-less record in an in-flight state
    /// (accepted/applying/applied/healthy) is NOT a failure: it resumes the apply path — rolling
    /// back a healthy converged deployment because its receipt lagged would destroy good work.
    /// THREE sites must stay in agreement: this predicate and
    /// <c>NatsDirectDeliveryJournal.EnsureContinuity</c> (every durable shape classified here as
    /// recovery is re-enterable there — a receipt-less Failed record accepts lower-rank progress
    /// appends) and <c>NatsDirectDeliveryJournal.IsPrunable</c> (every recovery-owing shape is
    /// retained under retention-cap pressure). No shape may be unresumable in one place,
    /// unprunable-but-reshapable in another, or deletable in a third.
    /// </summary>
    private static bool NeedsRollbackRecovery(DeliveryJournalRecord? record) =>
        record is not null &&
        (record.State == DeliveryJournalState.RollingBack ||
            record.Regions?.Any(static region =>
                region.State is "rollback_failed" or "rollback_pending" or "rolling_back") == true ||
            record.Receipt?.Error.Code == DirectDeliveryErrorCode.RollbackFailed ||
            (record.State == DeliveryJournalState.Failed && record.Receipt is null && HasWriteAheadDebt(record)));

    /// <summary>
    /// True when any region holds durable write-ahead rollback material in a phase that has not
    /// been restored yet (forward delivery phases, or rollback phases that replay finishes —
    /// including a region interrupted mid-rollback, whose rollback replay must CONTINUE, never
    /// be skipped as already restored). A receipt-less record with such debt owes its rollback.
    /// </summary>
    private static bool HasWriteAheadDebt(DeliveryJournalRecord record) =>
        record.Regions?.Any(static region =>
            region.State is "applied" or "healthy" or "health_failed" or "rollback_pending" or
                "rolling_back" or "rollback_failed" or "rollback_succeeded" &&
            IsDigest(region.PreviousArtifactDigest) && IsDigest(region.PreviousManifestDigest)) == true;

    /// <summary>
    /// A journaled failure that is recoverable in place: the same operationId replays its durable
    /// per-region progress instead of poisoning the operation with a terminal receipt.
    /// </summary>
    private static bool IsReplayableFailure(DeliveryJournalRecord? record) =>
        record is not null &&
            record.Receipt?.Error.Code is DirectDeliveryErrorCode.JournalUnavailable or
                DirectDeliveryErrorCode.Cancelled or
                DirectDeliveryErrorCode.AuthorizationUnavailable or
                DirectDeliveryErrorCode.ProvenanceUnavailable;

    private static List<DeliveryRegionProgress> ProgressSnapshot(
        IReadOnlyList<string> regions,
        IReadOnlyList<DeliveryRegionProgress>? existing)
    {
        var byRegion = (existing ?? []).ToDictionary(static value => value.Region, StringComparer.Ordinal);
        return regions.Select(region => byRegion.TryGetValue(region, out var value)
                ? value
                : new DeliveryRegionProgress(region, "pending"))
            .ToList();
    }

    /// <summary>
    /// Regions owing rollback work, including one interrupted mid-rollback (<c>rolling_back</c>):
    /// a crash between the durable 'rolling_back' persist and the region's KV rollback must replay
    /// as rollback CONTINUATION — excluding it here would let recovery skip the region and emit a
    /// rolled_back receipt while the failed artifact stays deployed.
    /// </summary>
    private static List<MutationSnapshot> ProgressMutations(IEnumerable<DeliveryRegionProgress> progress) =>
        progress.Where(static value => value.State is "applied" or "healthy" or "health_failed" or
                "rollback_pending" or "rolling_back" or "rollback_failed" or "rollback_succeeded")
            .Where(static value => IsDigest(value.PreviousArtifactDigest) && IsDigest(value.PreviousManifestDigest))
            .Select(static value => new MutationSnapshot(
                value.Region,
                value.PreviousArtifactDigest ?? string.Empty,
                value.PreviousManifestDigest ?? string.Empty))
            .ToList();

    private static void AddMutation(DeliveryRegionProgress progress, List<MutationSnapshot> mutations)
    {
        if (progress.PreviousArtifactDigest is not { } previous || !IsDigest(previous) ||
            progress.PreviousManifestDigest is not { } manifest || !IsDigest(manifest) ||
            mutations.Any(value => value.Region == progress.Region))
            return;
        mutations.Add(new(
            progress.Region,
            previous,
            manifest));
    }

    private DeliveryReceipt SuccessReceipt(
        DeliveryRequest request,
        DeliveryArtifact artifact,
        DeliveryProvenanceResult provenance,
        IReadOnlyList<DeliveryHealthCheck> checks,
        bool converged) => CreateReceipt(request, DeliveryReceiptStatus.Succeeded, artifact.Digest, provenance,
            checks, converged, new DeliveryRollback(false, null, DeliveryRollbackStatus.NotRequired), null,
            artifact.ManifestDigest);

    private DeliveryReceipt FailureReceipt(
        DeliveryRequest? request,
        string errorCode,
        string? artifactDigest = null,
        DeliveryProvenanceResult? provenance = null,
        string? artifactManifestDigest = null) => CreateReceipt(request, DeliveryReceiptStatus.Failed, artifactDigest,
            provenance ?? new DeliveryProvenanceResult(false, false, request?.ConfigurationRevision, request?.MigrationRevision),
            Array.Empty<DeliveryHealthCheck>(), false,
            new DeliveryRollback(false, null, DeliveryRollbackStatus.NotRequired), errorCode, artifactManifestDigest);

    private DeliveryReceipt CreateReceipt(
        DeliveryRequest? request,
        string status,
        string? artifactDigest,
        DeliveryProvenanceResult provenance,
        IReadOnlyList<DeliveryHealthCheck> checks,
        bool converged,
        DeliveryRollback rollback,
        string? errorCode,
        string? artifactManifestDigest = null)
    {
        var safeOperationId = request is { OperationId: { } boundedOperationId } &&
                IsBoundedText(boundedOperationId, MaximumOperationIdLength)
            ? boundedOperationId
            : "invalid";
        var safeChecks = checks.Where(static check => check is not null &&
                IsBoundedText(check.Name, MaximumTextLength) &&
                (check.Status == DeliveryHealthStatus.Passed || check.Status == DeliveryHealthStatus.Failed))
            .ToArray();
        var error = errorCode is null ? new DeliveryErrorInfo(null, null, null) : Error(errorCode);
        // The two artifact identities are recorded as an atomic pair: a receipt that names one
        // without the other cannot prove which exact artifact it is about, so a request whose
        // artifact half-failed validation records neither (the journal enforces the same rule).
        var artifactIdentity = SafeArtifactIdentity(
            artifactDigest,
            artifactManifestDigest ?? request?.Artifact?.ManifestDigest);
        return new DeliveryReceipt(
            DeliveryRequest.CurrentSchemaVersion,
            safeOperationId,
            status,
            SafeSource(request?.Source),
            artifactIdentity.Digest,
            SafeTarget(request?.Target),
            new DeliveryProvenance(provenance.Verified, SafeDigest(provenance.ConfigurationRevision ?? request?.ConfigurationRevision),
                SafeDigest(provenance.MigrationRevision ?? request?.MigrationRevision)),
            new DeliveryHealth(safeChecks, converged),
            rollback,
            SafeAuditId(),
            error,
            artifactIdentity.ManifestDigest);
    }

    private string SafeAuditId()
    {
        try
        {
            var value = _auditIdFactory();
            return IsBoundedText(value, MaximumOperationIdLength) ? value : "audit-invalid";
        }
        catch (Exception exception) when (IsAdapterFailure(exception))
        {
            return "audit-unavailable";
        }
    }

    private static string? ValidateRequest(DeliveryRequest? request)
    {
        if (request is null)
            return DirectDeliveryErrorCode.InvalidInput;
        if (request.SchemaVersion != DeliveryRequest.CurrentSchemaVersion)
            return DirectDeliveryErrorCode.UnsupportedSchema;
        if (request.AuthorityGeneration <= 0 || request.WriterEpoch <= 0 || request.Attempt <= 0)
            return DirectDeliveryErrorCode.InvalidInput;
        if (!IsBoundedText(request.OperationId, MaximumOperationIdLength))
            return request.OperationId is not null && request.OperationId.Length > MaximumOperationIdLength
                ? DirectDeliveryErrorCode.UnboundedText : DirectDeliveryErrorCode.InvalidInput;
        if (request.Source is null && request.Artifact is null)
            return DirectDeliveryErrorCode.MissingSourceAndArtifact;
        if (request.Source is not null)
        {
            var sourceError = ValidateSource(request.Source);
            if (sourceError is not null)
                return sourceError;
        }
        if (request.Artifact is not null)
        {
            var artifactError = ValidateArtifact(request.Artifact);
            if (artifactError is not null)
                return artifactError;
        }
        if (request.Target is null)
            return DirectDeliveryErrorCode.InvalidInput;
        var targetError = ValidateTarget(request.Target);
        if (targetError is not null)
            return targetError;
        if (!IsBoundedText(request.ConfigurationRevision, MaximumTextLength) ||
            !IsDigest(request.ConfigurationRevision))
            return request.ConfigurationRevision is not null && request.ConfigurationRevision.Length > MaximumTextLength
                ? DirectDeliveryErrorCode.UnboundedText : DirectDeliveryErrorCode.InvalidDigest;
        if (request.MigrationRevision is not null &&
            (!IsBoundedText(request.MigrationRevision, MaximumTextLength) || !IsDigest(request.MigrationRevision)))
            return request.MigrationRevision.Length > MaximumTextLength ? DirectDeliveryErrorCode.UnboundedText : DirectDeliveryErrorCode.InvalidDigest;
        if (!IsBoundedText(request.RequestedBy, MaximumIdentityLength) || string.IsNullOrWhiteSpace(request.RequestedBy))
            return request.RequestedBy is not null && request.RequestedBy.Length > MaximumIdentityLength
                ? DirectDeliveryErrorCode.UnboundedText : DirectDeliveryErrorCode.InvalidInput;
        if (!IsBoundedText(request.Reason, MaximumTextLength) || string.IsNullOrWhiteSpace(request.Reason))
            return request.Reason is not null && request.Reason.Length > MaximumTextLength
                ? DirectDeliveryErrorCode.UnboundedText : DirectDeliveryErrorCode.InvalidInput;
        return null;
    }

    private static string? ValidateSource(DeliverySource source)
    {
        if (!IsBoundedText(source.Repository, MaximumTextLength) || !IsBoundedText(source.Commit, MaximumTextLength) ||
            !IsBoundedText(source.TreeDigest, MaximumTextLength))
            return DirectDeliveryErrorCode.UnboundedText;
        return string.IsNullOrWhiteSpace(source.Repository) || !IsCommit(source.Commit) || !IsDigest(source.TreeDigest)
            ? DirectDeliveryErrorCode.InvalidInput
            : null;
    }

    private static string? ValidateArtifact(DeliveryArtifact? artifact)
    {
        if (artifact is null)
            return DirectDeliveryErrorCode.InvalidInput;
        if (!IsBoundedText(artifact.Digest, MaximumTextLength) ||
            !IsBoundedText(artifact.ManifestDigest, MaximumTextLength) ||
            !IsBoundedText(artifact.Kind, MaximumTextLength))
            return DirectDeliveryErrorCode.UnboundedText;
        if (!IsDigest(artifact.Digest) || !IsDigest(artifact.ManifestDigest))
            return DirectDeliveryErrorCode.InvalidDigest;
        return artifact.Kind is "service" or "package" or "site" ? null : DirectDeliveryErrorCode.InvalidInput;
    }

    private static string? ValidateTarget(DeliveryTarget target)
    {
        if (!IsBoundedText(target.Service, MaximumTextLength) || !IsBoundedText(target.Environment, MaximumTextLength) ||
            target.Regions is null || target.Regions.Count is 0 or > MaximumRegionCount)
            return target.Regions is not null && target.Regions.Count > MaximumRegionCount
                ? DirectDeliveryErrorCode.UnboundedText : DirectDeliveryErrorCode.InvalidInput;
        if (string.IsNullOrWhiteSpace(target.Service) || target.Environment is not ("local" or "development" or "production"))
            return DirectDeliveryErrorCode.InvalidInput;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var region in target.Regions)
        {
            if (!IsBoundedText(region, MaximumTextLength))
                return DirectDeliveryErrorCode.UnboundedText;
            if (string.IsNullOrWhiteSpace(region) || !seen.Add(region))
                return DirectDeliveryErrorCode.InvalidInput;
        }
        return null;
    }

    /// <summary>The canonical sha256 fingerprint of the admitted request, including its built artifact.</summary>
    internal static string RequestFingerprint(DeliveryRequest request)
    {
        var bytes = Encoding.UTF8.GetBytes(DeliveryWireCodec.SerializeRequest(request));
        return $"sha256:{Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()}";
    }

    /// <summary>
    /// Binds the validated shape into a non-null snapshot. Returns null (fail closed) when a
    /// request that passed validation still lacks its operation identity, target, or regions —
    /// the contract that replaces nullable assertions at this boundary.
    /// </summary>
    private static AdmittedDeliveryRequest? Admit(DeliveryRequest? request)
    {
        if (request is not { OperationId: { Length: > 0 } operationId, Target: { } target } ||
            target.Regions is not { Count: > 0 } regions)
            return null;
        var regionList = regions.ToArray();
        var wire = request with
        {
            Source = request.Source is null
                ? null
                : new DeliverySource(request.Source.Repository, request.Source.Commit, request.Source.TreeDigest),
            Artifact = request.Artifact is null
                ? null
                : new DeliveryArtifact(request.Artifact.Digest, request.Artifact.ManifestDigest, request.Artifact.Kind),
            Target = new DeliveryTarget(target.Service, target.Environment, regionList),
        };
        return new AdmittedDeliveryRequest(wire, operationId, wire.Source, wire.Target, regionList);
    }

    private sealed record AdmittedDeliveryRequest(
        DeliveryRequest Wire,
        string OperationId,
        DeliverySource? Source,
        DeliveryTarget Target,
        IReadOnlyList<string> Regions);

    private static bool IsBoundedText(string? value, int maximum) => value is not null && value.Length > 0 && value.Length <= maximum &&
        value.All(static character => !char.IsControl(character));

    private static bool IsCommit(string? value) => value is not null && value.Length == 40 && value.All(IsHex);

    private static bool IsDigest(string? value) => value is not null && value.Length == 71 &&
        value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) && value[7..].All(IsHex);

    private static bool SameArtifact(DeliveryArtifact left, DeliveryArtifact right) =>
        IsDigest(left.Digest) && IsDigest(left.ManifestDigest) && IsDigest(right.Digest) &&
        IsDigest(right.ManifestDigest) &&
        string.Equals(left.Digest, right.Digest, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.ManifestDigest, right.ManifestDigest, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.Kind, right.Kind, StringComparison.Ordinal);

    private static bool IsHex(char value) => value is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';

    private static string? SafeDigest(string? value) => IsDigest(value) ? value : null;

    /// <summary>
    /// The receipt's artifact digest and manifest digest as a both-or-neither pair: only an
    /// artifact whose BOTH identities parse as digests is recorded, so a receipt can never claim
    /// one identity of an artifact it could not fully identify.
    /// </summary>
    private static (string? Digest, string? ManifestDigest) SafeArtifactIdentity(
        string? digest,
        string? manifestDigest)
    {
        var safeDigest = SafeDigest(digest);
        var safeManifest = SafeDigest(manifestDigest);
        return safeDigest is null || safeManifest is null
            ? (null, null)
            : (safeDigest, safeManifest);
    }

    private static DeliverySource? SafeSource(DeliverySource? source) =>
        source is not null && ValidateSource(source) is null
            ? new DeliverySource(source.Repository, source.Commit, source.TreeDigest)
            : null;

    private static DeliveryTarget? SafeTarget(DeliveryTarget? target) =>
        target is not null && target.Regions is { } regions && ValidateTarget(target) is null
            ? new DeliveryTarget(target.Service, target.Environment, regions.ToArray())
            : null;

    private static DeliveryErrorInfo Error(string code) => code switch
    {
        DirectDeliveryErrorCode.UnsupportedSchema => new(code, "The delivery request schema is not supported.", "Use schemaVersion 1."),
        DirectDeliveryErrorCode.MissingSourceAndArtifact => new(code, "A source or exact artifact is required.", "Provide source or artifact."),
        DirectDeliveryErrorCode.InvalidDigest => new(code, "A digest has an invalid format.", "Use a sha256 digest with 64 hexadecimal characters."),
        DirectDeliveryErrorCode.StaleDigest => new(code, "The artifact digest is stale.", "Publish or select the exact current artifact digest."),
        DirectDeliveryErrorCode.UnknownTarget => new(code, "The requested target is not admitted.", "Choose a known service, environment, and region."),
        DirectDeliveryErrorCode.UnauthorizedActor => new(code, "The actor is not authorized for this target.", "Use an authenticated actor with deployment permission."),
        DirectDeliveryErrorCode.UnboundedText => new(code, "A request field exceeds the supported text bound.", "Shorten the field and retry."),
        DirectDeliveryErrorCode.ProvenanceFailed => new(code, "Source and artifact provenance could not be verified.", "Provide matching immutable source, configuration, and artifact evidence."),
        DirectDeliveryErrorCode.HealthFailed => new(code, "A required health check failed.", "Inspect the service health details and retry after remediation."),
        DirectDeliveryErrorCode.ConvergenceFailed => new(code, "The target did not converge.", "Inspect the target and retry once it reports convergence."),
        DirectDeliveryErrorCode.RollbackFailed => new(code, "Automatic rollback did not complete.", "Restore the recorded target artifact digest and inspect the target before retrying."),
        DirectDeliveryErrorCode.JournalUnavailable => new(code, "The durable delivery journal is unavailable.", "Restore journal health and retry the same operationId; the operation replays its durable progress."),
        DirectDeliveryErrorCode.OperationConflict => new(code, "The operationId is already bound to a different request.", "Generate a new operationId for a different request."),
        DirectDeliveryErrorCode.Cancelled => new(code, "The delivery operation was cancelled.", "Retry the same operationId once the target is available; the operation replays its durable progress."),
        DirectDeliveryErrorCode.AuthorizationUnavailable => new(code, "The authorization boundary is temporarily unreachable.", "Retry the same operationId after the control plane is reachable."),
        DirectDeliveryErrorCode.ProvenanceUnavailable => new(code, "The provenance evidence source is temporarily unreachable.", "Retry the same operationId after the evidence source is reachable."),
        DirectDeliveryErrorCode.AuthorityFenced => new(code, "The delivery authority changed before the mutation completed.", "Sign and submit a new delivery request under the current authority: the fenced request's authority generation and writer epoch are bound into the operation fingerprint, so retrying the same operationId can never be admitted."),
        DirectDeliveryErrorCode.MutationFailed => new(code, "The target mutation failed.", "Inspect the target and retry after remediation."),
        DirectDeliveryErrorCode.MutationRace => new(code, "A concurrent mutation changed the region between admission and mutation.", "The region was left untouched by this delivery. Inspect the concurrent writer, then submit a new delivery request for the digest you actually want deployed; the recorded rollback target of this operationId is spent."),
        _ => new(DirectDeliveryErrorCode.InvalidInput, "The delivery request is invalid.", "Correct the request and retry."),
    };

    private static bool IsAdapterFailure(Exception exception) => exception is not OutOfMemoryException and
        not StackOverflowException and not AccessViolationException;

    /// <summary>Infrastructure-class failures are retryable in place; anything else is a denial.</summary>
    private static bool IsTransientInfrastructure(Exception exception) =>
        exception is IOException or TimeoutException or NATS.Client.Core.NatsException;

    private sealed record MutationSnapshot(
        string Region,
        string PreviousArtifactDigest,
        string PreviousManifestDigest);
}

/// <summary>Named service alias for composition roots that prefer service terminology.</summary>
public sealed class DirectDeliveryService : DirectDeliveryCoordinator
{
    public DirectDeliveryService(
        IDeliveryAuthorizer authorizer,
        IDeliveryProvenanceVerifier provenanceVerifier,
        IDeliveryTargetResolver targetResolver,
        IDeliveryJournal journal,
        IDeliveryArtifactBuilder? artifactBuilder = null,
        Func<string>? auditIdFactory = null,
        Func<DeliveryRequest, bool>? authorityIsCurrent = null)
        : base(authorizer, provenanceVerifier, targetResolver, journal, artifactBuilder, auditIdFactory, authorityIsCurrent)
    {
    }
}

/// <summary>A small durable implementation useful for local adapters and contract tests.</summary>
public sealed class InMemoryDeliveryJournal : IDeliveryJournal
{
    // One lock object guards the dictionary AND every per-operation list: readers must never
    // observe a list mid-append while enumerating the dictionary snapshot (and vice versa).
    private readonly object _lock = new();
    private readonly Dictionary<string, List<DeliveryJournalRecord>> _records = new(StringComparer.Ordinal);

    public IReadOnlyList<DeliveryJournalRecord> Records
    {
        get
        {
            lock (_lock)
            {
                return _records.Values
                    .SelectMany(static value => value.ToList())
                    .ToArray();
            }
        }
    }

    public ValueTask<DeliveryJournalRecord?> ReadAsync(string operationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_lock)
        {
            return ValueTask.FromResult(
                _records.TryGetValue(operationId, out var records) && records.Count > 0
                    ? records[^1]
                    : null);
        }
    }

    public ValueTask AppendAsync(DeliveryJournalRecord record, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_lock)
        {
            if (!_records.TryGetValue(record.OperationId, out var records))
            {
                records = [];
                _records.Add(record.OperationId, records);
            }
            records.Add(record);
        }
        return ValueTask.CompletedTask;
    }
}

