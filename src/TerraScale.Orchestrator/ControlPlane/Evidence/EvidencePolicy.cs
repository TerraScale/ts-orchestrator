using System.Collections.Immutable;

namespace TerraScale.Orchestrator.ControlPlane.Evidence;

public sealed class EvidencePolicy
{
    private readonly ImmutableHashSet<EvidenceDomain> _domains;
    private readonly ImmutableHashSet<EvidenceArchitecture> _architectures;
    private readonly ImmutableHashSet<EvidenceExclusionId> _permittedExclusions;
    public EvidencePolicy(EvidenceLane lane, IEnumerable<EvidenceDomain>? requiredDomains, bool coldRunRequired,
        EvidenceCount minimumTests, EvidencePercentage minimumBranchCoverage, EvidencePercentage minimumMutationScore,
        EvidenceCount minimumPropertyCases, EvidenceCount minimumModelSchedules, EvidenceDurationSeconds minimumFuzzDuration,
        EvidenceCount minimumFuzzCases, EvidenceCount minimumFlakeCleanRuns, IEnumerable<EvidenceExclusionId?>? permittedExclusions,
        IEnumerable<EvidenceArchitecture>? requiredArchitectures, bool reuseAllowed, int maximumEntries)
    {
        Lane = lane; ColdRunRequired = coldRunRequired; MinimumTests = minimumTests; MinimumBranchCoverage = minimumBranchCoverage;
        MinimumMutationScore = minimumMutationScore; MinimumPropertyCases = minimumPropertyCases; MinimumModelSchedules = minimumModelSchedules;
        MinimumFuzzDuration = minimumFuzzDuration; MinimumFuzzCases = minimumFuzzCases; MinimumFlakeCleanRuns = minimumFlakeCleanRuns; ReuseAllowed = reuseAllowed;
        var domains = EvidenceCollections.Snapshot(requiredDomains, maximumEntries, true, out var domainsValid); domainsValid = domainsValid && domains.All(x => Enum.IsDefined(x) && x != EvidenceDomain.Unknown);
        var architectures = EvidenceCollections.Snapshot(requiredArchitectures, maximumEntries, true, out var architecturesValid); architecturesValid = architecturesValid && architectures.All(x => Enum.IsDefined(x) && x != EvidenceArchitecture.Unknown);
        var exclusions = EvidenceCollections.Snapshot(permittedExclusions, maximumEntries, false, out var exclusionsValid); exclusionsValid = exclusionsValid && exclusions.All(x => x is not null);
        _domains = domains.ToImmutableHashSet(); _architectures = architectures.ToImmutableHashSet();
        _permittedExclusions = exclusions.Where(x => x is not null).Cast<EvidenceExclusionId>().ToImmutableHashSet();
        IsWellFormed = Enum.IsDefined(lane) && lane != EvidenceLane.Unknown && maximumEntries > 0 && domainsValid && domains.Distinct().Count() == domains.Length
            && architecturesValid && architectures.Distinct().Count() == architectures.Length && exclusionsValid && _permittedExclusions.Count == exclusions.Length
            && minimumTests.IsValid && minimumBranchCoverage.IsValid && minimumMutationScore.IsValid && minimumPropertyCases.IsValid
            && minimumModelSchedules.IsValid && minimumFuzzDuration.IsValid && minimumFuzzCases.IsValid && minimumFlakeCleanRuns.IsValid;
    }
    public EvidenceLane Lane { get; }
    public bool ColdRunRequired { get; }
    public EvidenceCount MinimumTests { get; }
    public EvidencePercentage MinimumBranchCoverage { get; }
    public EvidencePercentage MinimumMutationScore { get; }
    public EvidenceCount MinimumPropertyCases { get; }
    public EvidenceCount MinimumModelSchedules { get; }
    public EvidenceDurationSeconds MinimumFuzzDuration { get; }
    public EvidenceCount MinimumFuzzCases { get; }
    public EvidenceCount MinimumFlakeCleanRuns { get; }
    public bool ReuseAllowed { get; }
    public bool IsWellFormed { get; }
    public IReadOnlySet<EvidenceDomain> RequiredDomains => _domains; public IReadOnlySet<EvidenceArchitecture> RequiredArchitectures => _architectures;
    internal bool Permits(EvidenceExclusionId id) => _permittedExclusions.Contains(id);
}

public readonly record struct EvidencePolicyResult
{
    private EvidencePolicyResult(EvidenceCode code) => Code = code;
    public EvidenceCode Code { get; }
    public bool IsAccepted => Code == EvidenceCode.Allowed;
    internal static EvidencePolicyResult Accept() => new(EvidenceCode.Allowed);
    internal static EvidencePolicyResult Reject(EvidenceCode code) => new(code);
}

public static class EvidencePolicyEvaluator
{
    public static EvidencePolicyResult Evaluate(EvidenceManifest? manifest, EvidencePolicy? policy)
    {
        if (manifest is not { IsWellFormed: true } || policy is not { IsWellFormed: true } || manifest.Lane != policy.Lane) return EvidencePolicyResult.Reject(EvidenceCode.InvalidInput);
        var subject = manifest.Subject;
        try
        {
            _ = subject.Suites.Aggregate(0UL, (total, suite) => checked(total + suite.Tests.Value + suite.PropertyCases.Value + suite.ModelSchedules.Value + suite.ModelSeeds.Value));
            _ = subject.Fuzz.Aggregate(0UL, (total, fuzz) => checked(total + fuzz.Cases.Value + fuzz.Duration.Value));
        }
        catch (OverflowException) { return EvidencePolicyResult.Reject(EvidenceCode.ArithmeticOverflow); }
        if (policy.ColdRunRequired && subject.Execution != EvidenceExecutionKind.Cold) return EvidencePolicyResult.Reject(EvidenceCode.FullExecutionRequired);
        if (subject.Execution == EvidenceExecutionKind.ContentAddressedReuse && !policy.ReuseAllowed) return EvidencePolicyResult.Reject(EvidenceCode.ReuseDenied);
        if (subject.Execution == EvidenceExecutionKind.ContentAddressedReuse)
        {
            if (subject.ReuseProof is not { } proof) return EvidencePolicyResult.Reject(EvidenceCode.InvalidInput);
            var reuse = EvidenceReuseEvaluator.Evaluate(proof.Expected, proof.Candidate, policy, proof.Change);
            if (!reuse.IsReusable) return EvidencePolicyResult.Reject(reuse.Code);
        }
        if (subject.Suites.GroupBy(x => x.Domain).Any(x => x.Count() > 1) || subject.ModelCorpora.GroupBy(x => x.Domain).Any(x => x.Count() > 1)) return EvidencePolicyResult.Reject(EvidenceCode.DuplicateDomain);
        var suiteDomains = subject.Suites.Select(x => x.Domain).ToHashSet();
        var corpusDomains = subject.ModelCorpora.Select(x => x.Domain).ToHashSet();
        if (!suiteDomains.SetEquals(corpusDomains)) return EvidencePolicyResult.Reject(EvidenceCode.MissingDomain);
        if (subject.TestBinaries.Select(x => x.Identity).Distinct().Count() != subject.TestBinaries.Count
            || subject.Fuzz.Select(x => x.Target).Distinct().Count() != subject.Fuzz.Count) return EvidencePolicyResult.Reject(EvidenceCode.InvalidInput);
        if (subject.Artifacts.GroupBy(x => x.Architecture).Any(x => x.Count() != 1) || subject.Artifacts.Select(x => x.Identity).Distinct().Count() != subject.Artifacts.Count)
            return EvidencePolicyResult.Reject(EvidenceCode.InvalidArchitecture);
        var actualArchitectures = subject.Artifacts.Select(x => x.Architecture).ToHashSet();
        if (!policy.RequiredArchitectures.SetEquals(actualArchitectures)) return EvidencePolicyResult.Reject(EvidenceCode.InvalidArchitecture);
        if (subject.Suites.Any(x => x.Result != EvidenceResult.Passed)) return EvidencePolicyResult.Reject(EvidenceCode.ResultFailed);
        if (subject.Suites.Any(x => x.SurvivingSafetyMutants.Value != 0)) return EvidencePolicyResult.Reject(EvidenceCode.SafetyMutantSurvived);
        if (policy.RequiredDomains.Any(domain => !suiteDomains.Contains(domain))) return EvidencePolicyResult.Reject(EvidenceCode.MissingDomain);
        foreach (var suite in subject.Suites)
        {
            if (suite.Tests.Value < policy.MinimumTests.Value || suite.PropertyCases.Value < policy.MinimumPropertyCases.Value
                || suite.BranchCoverage.Value < policy.MinimumBranchCoverage.Value || suite.MutationScore.Value < policy.MinimumMutationScore.Value
                || suite.ModelSchedules.Value < policy.MinimumModelSchedules.Value || suite.FlakeCleanRuns.Value < policy.MinimumFlakeCleanRuns.Value)
                return EvidencePolicyResult.Reject(EvidenceCode.ThresholdNotMet);
        }
        if (subject.Fuzz.Any(x => x.Result != EvidenceResult.Passed)) return EvidencePolicyResult.Reject(EvidenceCode.ResultFailed);
        if (subject.Fuzz.Any(x => x.Duration.Value < policy.MinimumFuzzDuration.Value || x.Cases.Value < policy.MinimumFuzzCases.Value)) return EvidencePolicyResult.Reject(EvidenceCode.ThresholdNotMet);
        if (subject.Exclusions.Any(x => x.Kind is EvidenceExclusionKind.Safety or EvidenceExclusionKind.Authorization or EvidenceExclusionKind.Durability or EvidenceExclusionKind.Deletion
            or EvidenceExclusionKind.StateTransition or EvidenceExclusionKind.Validation or EvidenceExclusionKind.Ownership or EvidenceExclusionKind.Fencing
            or EvidenceExclusionKind.Retry or EvidenceExclusionKind.Compensation or EvidenceExclusionKind.AdapterClassification)) return EvidencePolicyResult.Reject(EvidenceCode.ForbiddenExclusion);
        if (subject.Exclusions.Any(x => x.Kind is not (EvidenceExclusionKind.GeneratedCode or EvidenceExclusionKind.TrivialWiring) || !policy.Permits(x.Identity))) return EvidencePolicyResult.Reject(EvidenceCode.ForbiddenExclusion);
        if (subject.L0C.Result != EvidenceResult.Passed || subject.Checks.Analyzer != EvidenceResult.Passed || subject.Checks.Dependency != EvidenceResult.Passed
            || subject.Checks.Vulnerability != EvidenceResult.Passed || subject.Checks.License != EvidenceResult.Passed || subject.Checks.SecretScan != EvidenceResult.Passed)
            return EvidencePolicyResult.Reject(EvidenceCode.ResultFailed);
        return EvidencePolicyResult.Accept();
    }
}

public sealed record EvidenceReuseFingerprint(EvidenceSha256 Source, EvidenceSha256 TransitiveContracts, EvidenceSha256 Tests, EvidenceSha256 Corpus,
    EvidenceSha256 Dependencies, EvidenceSha256 Generators, EvidenceSha256 Schemas, EvidenceSha256 Toolchain);
public sealed record EvidenceReuseProof(EvidenceReuseFingerprint Expected, EvidenceReuseFingerprint Candidate, EvidenceChangeKind Change);
public readonly record struct EvidenceReuseResult
{
    private EvidenceReuseResult(EvidenceCode code) => Code = code;
    public EvidenceCode Code { get; }
    public bool IsReusable => Code == EvidenceCode.Allowed;
    internal static EvidenceReuseResult Of(EvidenceCode code) => new(code);
}
public static class EvidenceReuseEvaluator
{
    public static EvidenceReuseResult Evaluate(EvidenceReuseFingerprint? expected, EvidenceReuseFingerprint? candidate, EvidencePolicy? policy, EvidenceChangeKind change)
    {
        if (!Valid(expected) || !Valid(candidate) || policy is not { IsWellFormed: true } || !Enum.IsDefined(change) || change == EvidenceChangeKind.Unknown)
            return EvidenceReuseResult.Of(EvidenceCode.InvalidInput);
        if (!policy.ReuseAllowed) return EvidenceReuseResult.Of(EvidenceCode.ReuseDenied);
        if (change is EvidenceChangeKind.SharedContract or EvidenceChangeKind.Security or EvidenceChangeKind.Toolchain or EvidenceChangeKind.ColdFirstCandidate)
            return EvidenceReuseResult.Of(EvidenceCode.FullExecutionRequired);
        return expected == candidate ? EvidenceReuseResult.Of(EvidenceCode.Allowed) : EvidenceReuseResult.Of(EvidenceCode.ReuseDenied);
    }
    private static bool Valid(EvidenceReuseFingerprint? fingerprint) => fingerprint is not null && fingerprint.Source is not null && fingerprint.TransitiveContracts is not null
        && fingerprint.Tests is not null && fingerprint.Corpus is not null && fingerprint.Dependencies is not null && fingerprint.Generators is not null
        && fingerprint.Schemas is not null && fingerprint.Toolchain is not null;
}
