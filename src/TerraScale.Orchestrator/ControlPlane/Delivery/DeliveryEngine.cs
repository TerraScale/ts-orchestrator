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
        if (request.Evidence.State < SourceState.Verified || !request.Evidence.SignatureValid ||
            !request.Evidence.SchemaValid || !request.Evidence.DependenciesValid)
        {
            var verify = new VerifySourceIntent(request.Proposed.Source, request.Proposed.Commit, request.Proposed.Tree,
                request.Proposed.Manifest, request.Proposed.DesiredDigest, request.Proposed.Signature);
            return One(verify, DeliveryTraceCode.VerificationRequired);
        }
        var plan = new PlanApplyIntent(request.Proposed.Source, request.Proposed.Commit, request.Proposed.Tree,
            request.Proposed.Manifest, request.Proposed.Generation, request.Proposed.DesiredDigest,
            request.Proposed.Signature, request.Evidence.SchemaAttestation, request.Evidence.DependencyAttestation,
            request.Evidence.SignatureAttestation,
            new ReadOnlyCollection<DependencyProof>(request.Proposed.Dependencies.OrderBy(static value => value.Manifest.Value, Ordinal).ToArray()));
        return One(plan, DeliveryTraceCode.PlanReady);
    }

    public static DeliveryDecision DecideJob(JobRequest job, IReadOnlyList<RunnerEvidence> runners, int maximumIdentityLength)
    {
        ArgumentNullException.ThrowIfNull(job); ArgumentNullException.ThrowIfNull(runners);
        IReadOnlyList<RunnerEvidence> runnerSnapshot;
        try
        {
            if (runners.Count > DeliveryTechnicalInputLimits.MaximumRunnerEvidenceCount)
                return Held(DeliveryErrorCode.InvalidInput, job.Job);
            runnerSnapshot = DeliveryInputSnapshot.Copy(runners, DeliveryTechnicalInputLimits.MaximumRunnerEvidenceCount,
                nameof(runners), "Runner evidence input");
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException)
        {
            return Held(DeliveryErrorCode.InvalidInput, job.Job);
        }
        if (!ValidJob(job, maximumIdentityLength)) return Held(DeliveryErrorCode.InvalidInput, job.Job);
        if (job.Attempt > 1 && !job.RetryAuthorized) return Held(DeliveryErrorCode.RetryDenied, job.Job);
        if (job.Attempt > job.MaximumAttempts) return Held(DeliveryErrorCode.AttemptsExhausted, job.Job);
        if (!TrustPolicyAllows(job))
            return Held(DeliveryErrorCode.TrustZoneDenied, job.Job);

        if (runnerSnapshot.Any(runner => !ValidRunner(runner, maximumIdentityLength)))
            return Held(DeliveryErrorCode.InvalidInput, job.Job);
        if (runnerSnapshot.Select(static runner => runner.Runner).Distinct().Count() != runnerSnapshot.Count)
            return Held(DeliveryErrorCode.DuplicateEvidence, job.Job);

        var hasFreshRunner = false;
        var hasZonedRunner = false;
        var hasTrustedRunner = false;
        RunnerEvidence? selected = null;
        foreach (var runner in runnerSnapshot)
        {
            if (runner.Sequence < job.MinimumRunnerSequence ||
                runner.Sequence > job.MaximumRunnerSequence ||
                !runner.Available)
            {
                continue;
            }

            hasFreshRunner = true;
            if (!job.AllowedZones.Contains(runner.Zone))
            {
                continue;
            }

            hasZonedRunner = true;
            if (!RunnerTrustPolicyAllows(runner))
            {
                continue;
            }

            hasTrustedRunner = true;
            if (!job.RequiredCapabilities.All(runner.Capabilities.Contains))
            {
                continue;
            }

            if (selected is null || Ordinal.Compare(runner.Runner.Value, selected.Runner.Value) < 0)
            {
                selected = runner;
            }
        }

        if (!hasFreshRunner) return Held(DeliveryErrorCode.RunnerStale, job.Job);
        if (!hasZonedRunner || !hasTrustedRunner) return Held(DeliveryErrorCode.TrustZoneDenied, job.Job);
        if (selected is null) return Held(DeliveryErrorCode.CapabilityMissing, job.Job);
        var dispatch = new DispatchJobIntent(job, selected, maximumIdentityLength);
        return One(dispatch, DeliveryTraceCode.RunnerSelected);
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
        Valid(evidence.DependencyAttestation?.Value, max) && Valid(evidence.SignatureAttestation?.Value, max) &&
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
    private static bool RunnerTrustPolicyAllows(RunnerEvidence runner) => runner.Zone switch
    {
        TrustZone.UntrustedProduct => runner.Capabilities.All(static capability =>
            capability is RunnerCapability.Compile or RunnerCapability.Test),
        TrustZone.TrustedBuild => runner.Capabilities.All(static capability =>
            capability is RunnerCapability.Compile or RunnerCapability.Test or RunnerCapability.Sign),
        TrustZone.ProductionRelease => runner.Capabilities.All(static capability =>
            capability is RunnerCapability.Promote or RunnerCapability.ProductionDeploy),
        TrustZone.ControlRecovery => runner.Capabilities.All(static capability =>
            capability == RunnerCapability.ControlRecover),
        _ => false,
    };
    private static bool EquivalentSource(SourceRevision left, SourceRevision right) =>
        left.Source == right.Source && left.Reference == right.Reference && left.Commit == right.Commit && left.Tree == right.Tree && left.Manifest == right.Manifest &&
        left.Generation == right.Generation && left.DesiredDigest == right.DesiredDigest && left.Signature == right.Signature &&
        EquivalentDependencies(left.Dependencies, right.Dependencies);
    private static bool EquivalentDependencies(IReadOnlyList<DependencyProof> left, IReadOnlyList<DependencyProof> right) =>
        left.OrderBy(static value => value.Manifest.Value, Ordinal)
            .SequenceEqual(right.OrderBy(static value => value.Manifest.Value, Ordinal));
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
    private static DeliveryDecision Held(DeliveryErrorCode code, JobId? job = null)
    {
        var error = new DeliveryError(code, Requirement, job);
        var hold = new HoldDeliveryIntent(code, job);
        return Decision([hold], [error], [new(1, DeliveryTraceCode.Held, hold.Action)]);
    }
    private static DeliveryDecision Decision(IEnumerable<DeliveryIntent> intents, IEnumerable<DeliveryError> errors, IEnumerable<DeliveryTrace> trace) => new(
        new ReadOnlyCollection<DeliveryIntent>(intents.ToArray()), new ReadOnlyCollection<DeliveryError>(errors.ToArray()),
        new ReadOnlyCollection<DeliveryTrace>(trace.ToArray()));
}

