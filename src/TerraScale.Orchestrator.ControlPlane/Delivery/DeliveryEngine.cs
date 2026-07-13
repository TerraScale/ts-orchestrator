using System.Collections.ObjectModel;
using System.Globalization;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

public static class DeliveryEngine
{
    private const DeliveryRequirementCode Requirement = DeliveryRequirementCode.Inv005;
    private static readonly StringComparer Ordinal = StringComparer.Ordinal;

    public static DeliveryDecision DecideSource(SourceDecisionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!ValidSource(request.Proposed, request.MaximumIdentityLength)) return Held(DeliveryErrorCode.InvalidInput);
        if (request.Accepted is not null)
        {
            if (!ValidSource(request.Accepted, request.MaximumIdentityLength)) return Held(DeliveryErrorCode.InvalidInput);
            if (request.Proposed.Generation < request.Accepted.Generation) return Held(DeliveryErrorCode.StaleGeneration);
            if (request.Proposed.Generation == request.Accepted.Generation)
            {
                if (!EquivalentSource(request.Proposed, request.Accepted)) return Held(DeliveryErrorCode.ConflictingGeneration);
                return Decision([], [], [new(1, DeliveryTraceCode.Idempotent, DeliveryAction.Plan)]);
            }
        }
        if (request.Evidence is null)
        {
            var fetch = new FetchSourceIntent(request.Proposed.Source, request.Proposed.Commit, request.Proposed.Tree);
            return One(fetch, DeliveryTraceCode.FetchRequired);
        }
        if (!ValidEvidence(request.Evidence, request.MaximumIdentityLength) || request.Evidence.Source != request.Proposed.Source ||
            request.Evidence.Reference != request.Proposed.Reference || request.Evidence.Generation != request.Proposed.Generation ||
            request.Evidence.Commit != request.Proposed.Commit ||
            request.Evidence.Tree != request.Proposed.Tree || request.Evidence.Manifest != request.Proposed.Manifest ||
            request.Evidence.DesiredDigest != request.Proposed.DesiredDigest || request.Evidence.Signature != request.Proposed.Signature ||
            !EquivalentDependencies(request.Evidence.Dependencies, request.Proposed.Dependencies))
            return Held(DeliveryErrorCode.EvidenceInvalidated);
        if (request.Evidence.State < SourceState.Verified || !request.Evidence.SchemaValid || !request.Evidence.DependenciesValid)
        {
            var verify = new VerifySourceIntent(request.Proposed.Source, request.Proposed.Commit, request.Proposed.Tree,
                request.Proposed.Manifest, request.Proposed.DesiredDigest, request.Proposed.Signature);
            return One(verify, DeliveryTraceCode.VerificationRequired);
        }
        var plan = new PlanApplyIntent(request.Proposed.Source, request.Proposed.Commit, request.Proposed.Tree,
            request.Proposed.Manifest, request.Proposed.Generation, request.Proposed.DesiredDigest,
            new ReadOnlyCollection<DependencyProof>(request.Proposed.Dependencies.OrderBy(static value => value.Manifest.Value, Ordinal).ToArray()));
        return One(plan, DeliveryTraceCode.PlanReady);
    }

    public static DeliveryDecision DecideJob(JobRequest job, IReadOnlyList<RunnerEvidence> runners, int maximumIdentityLength)
    {
        ArgumentNullException.ThrowIfNull(job); ArgumentNullException.ThrowIfNull(runners);
        if (!ValidJob(job, maximumIdentityLength) || runners.Any(static value => value is null)) return Held(DeliveryErrorCode.InvalidInput, job.Job);
        if (job.Attempt > 1 && !job.RetryAuthorized) return Held(DeliveryErrorCode.RetryDenied, job.Job);
        if (job.Attempt > job.MaximumAttempts) return Held(DeliveryErrorCode.AttemptsExhausted, job.Job);
        if (!TrustPolicyAllows(job))
            return Held(DeliveryErrorCode.TrustZoneDenied, job.Job);

        var validRunners = runners.Where(runner => ValidRunner(runner, maximumIdentityLength)).ToArray();
        if (validRunners.Length != runners.Count) return Held(DeliveryErrorCode.InvalidInput, job.Job);
        if (validRunners.Select(static runner => runner.Runner).Distinct().Count() != validRunners.Length)
            return Held(DeliveryErrorCode.DuplicateEvidence, job.Job);
        var fresh = validRunners.Where(runner => runner.Sequence >= job.MinimumRunnerSequence &&
            runner.Sequence <= job.MaximumRunnerSequence && runner.Available).ToArray();
        if (fresh.Length == 0) return Held(DeliveryErrorCode.RunnerStale, job.Job);
        var zoned = fresh.Where(runner => job.AllowedZones.Contains(runner.Zone)).ToArray();
        if (zoned.Length == 0) return Held(DeliveryErrorCode.TrustZoneDenied, job.Job);
        var compatible = zoned.Where(runner => job.RequiredCapabilities.All(runner.Capabilities.Contains))
            .OrderBy(static runner => runner.Runner.Value, Ordinal).ToArray();
        if (compatible.Length == 0) return Held(DeliveryErrorCode.CapabilityMissing, job.Job);
        var selected = compatible[0];
        var dispatch = new DispatchJobIntent(job.Pipeline, job.Job, selected.Runner, job.Tree,
            job.Generation, job.Attempt, job.Idempotency);
        return One(dispatch, DeliveryTraceCode.RunnerSelected);
    }

    public static DeliveryDecision DecidePromotion(PromotionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Generation <= 0 || request.MaximumIdentityLength <= 0 || !Valid(request.Release?.Value, request.MaximumIdentityLength) ||
            !ValidSubject(request.Current, request.MaximumIdentityLength) || request.Qualification is null ||
            !Valid(request.Qualification.Release?.Value, request.MaximumIdentityLength) || request.Qualification.Generation <= 0 ||
            !ValidSubject(request.Qualification.Subject, request.MaximumIdentityLength))
            return Held(DeliveryErrorCode.InvalidInput, release: request.Release);
        if (request.Qualification.Release != request.Release || request.Qualification.Generation != request.Generation ||
            request.Current != request.Qualification.Subject)
            return Held(DeliveryErrorCode.EvidenceInvalidated, release: request.Release);
        var evidence = request.Qualification;
        if (!Valid(evidence.Tests?.Value, request.MaximumIdentityLength) || !Valid(evidence.Evidence?.Value, request.MaximumIdentityLength) ||
            !Valid(evidence.SigningIdentity?.Value, request.MaximumIdentityLength) || !Valid(evidence.Signature?.Value, request.MaximumIdentityLength) ||
            !Valid(evidence.Approval?.Value, request.MaximumIdentityLength) || evidence.Compatibility is null ||
            !Valid(evidence.Compatibility.CurrentToCurrent?.Value, request.MaximumIdentityLength) ||
            !Valid(evidence.Compatibility.CurrentToPrevious?.Value, request.MaximumIdentityLength) ||
            !Valid(evidence.Compatibility.PreviousToCurrent?.Value, request.MaximumIdentityLength))
            return Held(DeliveryErrorCode.MissingEvidence, release: request.Release);
        if (!evidence.TestsPassed || !evidence.EvidenceValid) return Held(DeliveryErrorCode.EvidenceInvalidated, release: request.Release);
        if (!evidence.SignatureValid) return Held(DeliveryErrorCode.ArtifactMismatch, release: request.Release);
        if (!evidence.ApprovalValid) return Held(DeliveryErrorCode.ApprovalDenied, release: request.Release);
        if (!evidence.Compatibility.CurrentToCurrentCompatible || !evidence.Compatibility.CurrentToPreviousCompatible ||
            !evidence.Compatibility.PreviousToCurrentCompatible)
            return Held(DeliveryErrorCode.CompatibilityDenied, release: request.Release);
        var intent = new PromoteArtifactIntent(request.Release!, request.Generation, request.Current,
            evidence.SigningIdentity!, evidence.Signature!, evidence.Approval!, evidence.Evidence!, evidence.Compatibility!);
        return One(intent, DeliveryTraceCode.PromotionReady);
    }

    public static DeliveryDecision DecideRollout(RolloutRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!ValidRelease(request.Release, request.MaximumIdentityLength) || request.CompletedCells is null || request.Availability is null ||
            request.CompletedCells.Any(static value => value is null) || request.Availability.Any(static value => value is null) ||
            request.CompletedCells.Select(static value => value.Cell).Distinct().Count() != request.CompletedCells.Count ||
            request.Availability.Select(static value => value.Cell).Distinct().Count() != request.Availability.Count)
            return Held(DeliveryErrorCode.InvalidInput, release: request.Release?.Release);
        var release = request.Release;
        if (!request.Availability.Select(static value => value.Cell).ToHashSet().SetEquals(release.OrderedCells))
            return Held(DeliveryErrorCode.MissingEvidence, release: release.Release);
        if (request.Availability.Any(value => !ValidAvailability(value, release, request.MaximumIdentityLength)))
            return Held(DeliveryErrorCode.EvidenceInvalidated, release: release.Release);
        if (!request.CompletedCells.Select(static value => value.Cell)
                .SequenceEqual(release.OrderedCells.Take(request.CompletedCells.Count)) ||
            request.CompletedCells.Any(value => !ValidCompletion(value, release, request.MaximumIdentityLength)))
            return Held(DeliveryErrorCode.StageOutOfOrder, release: release.Release);
        if (request.CompletedCells.Count == release.OrderedCells.Count)
            return Decision([], [], [new(1, DeliveryTraceCode.Idempotent, DeliveryAction.Advance)]);
        var expected = release.OrderedCells[request.CompletedCells.Count];
        var availability = request.Availability.SingleOrDefault(value => value.Cell == expected);
        if (availability is null || !availability.ForwardAvailable) return Held(DeliveryErrorCode.ArtifactMismatch, release: release.Release, cell: expected);
        if (!availability.RollbackAvailable) return Held(DeliveryErrorCode.RollbackUnavailable, release: release.Release, cell: expected);

        if (request.CurrentStage is null)
        {
            var stage = new StageReleaseIntent(release.Release, release.Operation, expected, release.Generation,
                release.Artifact, release.Digest, release.Signature, release.RollbackArtifact, release.RollbackDigest,
                release.RollbackSignature);
            return One(stage, DeliveryTraceCode.StageReady);
        }
        var current = request.CurrentStage;
        if (!ValidStage(current, request.MaximumIdentityLength) || current.Operation != release.Operation ||
            current.Cell != expected || current.Release != release.Release ||
            current.Generation != release.Generation || current.Artifact != release.Artifact || current.Digest != release.Digest)
            return Held(DeliveryErrorCode.ArtifactMismatch, release: release.Release, cell: expected);
        if (current.Signature != release.Signature)
            return Held(DeliveryErrorCode.ArtifactMismatch, release: release.Release, cell: expected);
        if (!current.DisruptionAuthorized || !current.AvailabilityAuthorized)
            return Held(DeliveryErrorCode.AvailabilityDenied, release: release.Release, cell: expected);
        if (current.Health == StageHealth.Failed)
        {
            if (release.RollbackPolicy != RollbackPolicy.AutomaticOnFailedHealth)
                return Held(DeliveryErrorCode.HealthDenied, release: release.Release, cell: expected);
            var rollback = new RollbackReleaseIntent(release.Release, release.Operation, expected, release.Generation,
                release.Artifact, release.Digest, release.Signature, release.RollbackArtifact, release.RollbackDigest,
                release.RollbackSignature, current.HealthProof);
            return One(rollback, DeliveryTraceCode.RollbackRequired);
        }
        if (current.Health != StageHealth.Healthy)
            return Held(DeliveryErrorCode.HealthDenied, release: release.Release, cell: expected);
        var next = request.CompletedCells.Count + 1 < release.OrderedCells.Count
            ? release.OrderedCells[request.CompletedCells.Count + 1] : null;
        var advance = new AdvanceReleaseIntent(release.Release, release.Operation, expected, next, release.Generation,
            release.Artifact, release.Digest, release.Signature, current.HealthProof);
        return One(advance, DeliveryTraceCode.AdvanceReady);
    }

    private static bool ValidSource(SourceRevision source, int max) => source is not null && max > 0 &&
        Valid(source.Source?.Value, max) && Valid(source.Reference?.Value, max) && Valid(source.Commit?.Value, max) &&
        Valid(source.Tree?.Value, max) && Valid(source.Manifest?.Value, max) && source.Generation > 0 &&
        Valid(source.DesiredDigest?.Value, max) && Valid(source.Signature?.Value, max) &&
        source.Dependencies.Count == source.Dependencies.Select(static value => value.Manifest).Distinct().Count() &&
        source.Dependencies.All(value => value.Generation > 0 && Valid(value.Manifest?.Value, max) && Valid(value.Digest?.Value, max));
    private static bool ValidEvidence(SourceEvidence evidence, int max) => evidence is not null &&
        Valid(evidence.Observation?.Value, max) && Defined(evidence.State) && Valid(evidence.Source?.Value, max) &&
        Valid(evidence.Reference?.Value, max) && evidence.Generation > 0 && Valid(evidence.Commit?.Value, max) &&
        Valid(evidence.Tree?.Value, max) && Valid(evidence.Manifest?.Value, max) && Valid(evidence.DesiredDigest?.Value, max) &&
        Valid(evidence.Signature?.Value, max) && Valid(evidence.SchemaAttestation?.Value, max) &&
        Valid(evidence.DependencyAttestation?.Value, max) &&
        evidence.Dependencies.Select(static value => value.Manifest).Distinct().Count() == evidence.Dependencies.Count &&
        evidence.Dependencies.All(value => value.Generation > 0 && Valid(value.Manifest?.Value, max) && Valid(value.Digest?.Value, max));
    private static bool ValidJob(JobRequest job, int max) => max > 0 && Valid(job.Pipeline?.Value, max) && Valid(job.Job?.Value, max) &&
        Defined(job.Kind) && Valid(job.Tree?.Value, max) && job.Generation > 0 && job.Attempt > 0 && job.MaximumAttempts > 0 &&
        Valid(job.Idempotency?.Value, max) && job.MinimumRunnerSequence > 0 && job.MaximumRunnerSequence >= job.MinimumRunnerSequence &&
        job.AllowedZones.Count > 0 && job.AllowedZones.All(Defined) && job.AllowedZones.Distinct().Count() == job.AllowedZones.Count &&
        job.RequiredCapabilities.Count > 0 && job.RequiredCapabilities.All(Defined) && job.RequiredCapabilities.Distinct().Count() == job.RequiredCapabilities.Count;
    private static bool ValidRunner(RunnerEvidence runner, int max) => runner is not null && Valid(runner.Runner?.Value, max) &&
        Defined(runner.Zone) && runner.Sequence > 0 && runner.Capabilities.Count > 0 && runner.Capabilities.All(Defined) &&
        runner.Capabilities.Distinct().Count() == runner.Capabilities.Count;
    private static bool TrustPolicyAllows(JobRequest job) => job.Kind switch
    {
        JobKind.ProductValidation => job.AllowedZones.All(static zone => zone == TrustZone.UntrustedProduct) &&
            job.RequiredCapabilities.All(static capability => capability is RunnerCapability.Compile or RunnerCapability.Test),
        JobKind.TrustedBuild => job.AllowedZones.All(static zone => zone == TrustZone.TrustedBuild) &&
            job.RequiredCapabilities.All(static capability => capability is RunnerCapability.Compile or RunnerCapability.Test or RunnerCapability.Sign),
        JobKind.Promotion => job.AllowedZones.All(static zone => zone == TrustZone.ProductionRelease) &&
            job.RequiredCapabilities.All(static capability => capability is RunnerCapability.Promote or RunnerCapability.ProductionDeploy),
        JobKind.ControlRecovery => job.AllowedZones.All(static zone => zone == TrustZone.ControlRecovery) &&
            job.RequiredCapabilities.All(static capability => capability == RunnerCapability.ControlRecover),
        _ => false,
    };
    private static bool ValidSubject(EvidenceSubject subject, int max) => subject is not null && Valid(subject.Tree?.Value, max) &&
        Valid(subject.DependencyLock?.Value, max) && Valid(subject.GeneratedSchemas?.Value, max) && Valid(subject.Artifact?.Value, max) && Valid(subject.ArtifactDigest?.Value, max);
    private static bool ValidRelease(ReleaseSpec release, int max) => release is not null && max > 0 &&
        Valid(release.Release?.Value, max) && Valid(release.Operation?.Value, max) && release.Generation > 0 &&
        Valid(release.Artifact?.Value, max) && Valid(release.Digest?.Value, max) && Valid(release.Signature?.Value, max) &&
        Valid(release.RollbackArtifact?.Value, max) && Valid(release.RollbackDigest?.Value, max) &&
        Valid(release.RollbackSignature?.Value, max) && Defined(release.Strategy) &&
        Defined(release.RollbackPolicy) && release.OrderedCells.Count > 0 && release.OrderedCells.All(value => Valid(value?.Value, max)) &&
        release.OrderedCells.Distinct().Count() == release.OrderedCells.Count && release.Artifact != release.RollbackArtifact &&
        release.Digest != release.RollbackDigest;
    private static bool ValidStage(StageEvidence stage, int max) => stage is not null && Valid(stage.Observation?.Value, max) &&
        Valid(stage.Operation?.Value, max) &&
        Valid(stage.Cell?.Value, max) && Valid(stage.Release?.Value, max) && stage.Generation > 0 &&
        Valid(stage.Artifact?.Value, max) && Valid(stage.Digest?.Value, max) && Valid(stage.Signature?.Value, max) &&
        Defined(stage.Health) && Valid(stage.HealthProof?.Value, max);

    private static bool EquivalentSource(SourceRevision left, SourceRevision right) =>
        left.Source == right.Source && left.Reference == right.Reference && left.Commit == right.Commit && left.Tree == right.Tree && left.Manifest == right.Manifest &&
        left.Generation == right.Generation && left.DesiredDigest == right.DesiredDigest && left.Signature == right.Signature &&
        EquivalentDependencies(left.Dependencies, right.Dependencies);
    private static bool EquivalentDependencies(IReadOnlyList<DependencyProof> left, IReadOnlyList<DependencyProof> right) =>
        left.OrderBy(static value => value.Manifest.Value, Ordinal)
            .SequenceEqual(right.OrderBy(static value => value.Manifest.Value, Ordinal));
    private static bool ValidCompletion(CellCompletionEvidence value, ReleaseSpec release, int max) =>
        value is not null && Valid(value.Operation?.Value, max) && Valid(value.Cell?.Value, max) &&
        Valid(value.Release?.Value, max) && value.Generation > 0 && Valid(value.Artifact?.Value, max) &&
        Valid(value.Digest?.Value, max) && Valid(value.Signature?.Value, max) && Valid(value.HealthProof?.Value, max) &&
        value.Operation == release.Operation && value.Release == release.Release && value.Generation == release.Generation &&
        value.Artifact == release.Artifact && value.Digest == release.Digest && value.Signature == release.Signature &&
        value.Health == StageHealth.Healthy;
    private static bool ValidAvailability(CellArtifactAvailability value, ReleaseSpec release, int max) =>
        value is not null && Valid(value.Release?.Value, max) && Valid(value.Operation?.Value, max) &&
        value.Generation > 0 && Valid(value.Cell?.Value, max) && Valid(value.ForwardArtifact?.Value, max) &&
        Valid(value.ForwardDigest?.Value, max) && Valid(value.ForwardSignature?.Value, max) &&
        Valid(value.RollbackArtifact?.Value, max) && Valid(value.RollbackDigest?.Value, max) &&
        Valid(value.RollbackSignature?.Value, max) &&
        value.Release == release.Release && value.Operation == release.Operation && value.Generation == release.Generation &&
        value.ForwardArtifact == release.Artifact && value.ForwardDigest == release.Digest &&
        value.ForwardSignature == release.Signature && value.RollbackArtifact == release.RollbackArtifact &&
        value.RollbackDigest == release.RollbackDigest && value.RollbackSignature == release.RollbackSignature;

    private static bool Valid(string? value, int maximumLength)
    {
        if (string.IsNullOrEmpty(value) || value.Length > maximumLength) return false;
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (char.IsWhiteSpace(character) || char.IsControl(character)) return false;
            if (!char.IsSurrogate(character)) continue;
            if (!char.IsHighSurrogate(character) || index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1])) return false;
            index++;
        }
        return true;
    }
    private static bool Defined<T>(T value) where T : struct, Enum => Enum.IsDefined(value) && Convert.ToInt64(value, CultureInfo.InvariantCulture) != 0;
    private static DeliveryDecision One(DeliveryIntent intent, DeliveryTraceCode code) => Decision([intent], [], [new(1, code, intent.Action)]);
    private static DeliveryDecision Held(DeliveryErrorCode code, JobId? job = null, ReleaseId? release = null, DeliveryCellId? cell = null)
    {
        var error = new DeliveryError(code, Requirement, job, release, cell);
        var hold = new HoldDeliveryIntent(code, job, release, cell);
        return Decision([hold], [error], [new(1, DeliveryTraceCode.Held, hold.Action)]);
    }
    private static DeliveryDecision Decision(IEnumerable<DeliveryIntent> intents, IEnumerable<DeliveryError> errors, IEnumerable<DeliveryTrace> trace) => new(
        new ReadOnlyCollection<DeliveryIntent>(intents.ToArray()), new ReadOnlyCollection<DeliveryError>(errors.ToArray()),
        new ReadOnlyCollection<DeliveryTrace>(trace.ToArray()));
}
