using System.Collections.Immutable;

namespace TerraScale.Orchestrator.ControlPlane.Evidence;

public sealed record EvidenceTestBinary(EvidenceTestBinaryId Identity, EvidenceSha256 Digest);
public sealed record EvidenceArchitectureArtifact(EvidenceArtifactId Identity, EvidenceArchitecture Architecture, EvidenceSha256 Digest);
public sealed record EvidenceSuiteResult(EvidenceSuiteId Suite, EvidenceDomain Domain, EvidenceCount Tests, EvidenceCount PropertyCases,
    EvidencePercentage BranchCoverage, EvidencePercentage MutationScore, EvidenceNonNegativeCount SurvivingSafetyMutants, EvidenceCount ModelSchedules,
    EvidenceCount ModelSeeds, EvidenceCount FlakeCleanRuns, EvidenceResult Result);
public sealed record EvidenceFuzzResult(EvidenceFuzzTargetId Target, EvidenceCorpusId Corpus, EvidenceSha256 CorpusDigest,
    EvidenceDurationSeconds Duration, EvidenceCount Cases, EvidenceResult Result);
public sealed record EvidenceModelCorpus(EvidenceDomain Domain, EvidenceCorpusId Corpus, EvidenceSha256 Digest);
public sealed record EvidenceExclusion(EvidenceExclusionId Identity, EvidenceExclusionKind Kind);
public sealed record EvidenceCheckResults(EvidenceResult Analyzer, EvidenceResult Dependency, EvidenceResult Vulnerability,
    EvidenceResult License, EvidenceResult SecretScan);
public sealed record EvidenceRequirementTrace(EvidenceTraceId Identity, EvidenceSha256 Digest, EvidenceCount Requirements,
    EvidenceCount Invariants, EvidenceCount Errors, EvidenceCount Transitions);
public sealed record EvidenceL0CResult(EvidenceL0CId Identity, EvidenceSha256 Digest, EvidenceResult Result);

public sealed class EvidenceSubject
{
    private readonly ImmutableArray<EvidenceTestBinary> _testBinaries;
    private readonly ImmutableArray<EvidenceArchitectureArtifact> _artifacts;
    private readonly ImmutableArray<EvidenceSuiteResult> _suites;
    private readonly ImmutableArray<EvidenceFuzzResult> _fuzz;
    private readonly ImmutableArray<EvidenceModelCorpus> _modelCorpora;
    private readonly ImmutableArray<EvidenceExclusion> _exclusions;
    public EvidenceSubject(EvidenceTreeId tree, EvidenceSha256 treeDigest, EvidenceDependencyLockId dependencyLock, EvidenceSha256 dependencyDigest,
        EvidenceSchemaId schema, EvidenceSha256 schemaDigest, IEnumerable<EvidenceTestBinary?>? testBinaries, IEnumerable<EvidenceArchitectureArtifact?>? artifacts,
        IEnumerable<EvidenceSuiteResult?>? suites, EvidenceRequirementTrace trace, IEnumerable<EvidenceFuzzResult?>? fuzz,
        IEnumerable<EvidenceModelCorpus?>? modelCorpora, EvidenceL0CResult l0C, EvidenceCheckResults checks, EvidenceSha256 toolchainDigest,
        EvidenceApproverId approver, EvidenceExecutionKind execution, EvidenceReuseProof? reuseProof, IEnumerable<EvidenceExclusion?>? exclusions, int maximumEntries)
    {
        Tree = tree; TreeDigest = treeDigest; DependencyLock = dependencyLock; DependencyDigest = dependencyDigest; Schema = schema; SchemaDigest = schemaDigest;
        _testBinaries = EvidenceCollections.CopyBounded(testBinaries, maximumEntries, out var binariesValid);
        _artifacts = EvidenceCollections.CopyBounded(artifacts, maximumEntries, out var artifactsValid);
        _suites = EvidenceCollections.CopyBounded(suites, maximumEntries, out var suitesValid);
        _fuzz = EvidenceCollections.CopyBounded(fuzz, maximumEntries, out var fuzzValid);
        _modelCorpora = EvidenceCollections.CopyBounded(modelCorpora, maximumEntries, out var modelValid);
        var exclusionArray = EvidenceCollections.Snapshot(exclusions, maximumEntries, false, out var exclusionsValid); exclusionsValid = exclusionsValid && exclusionArray.All(x => x is not null);
        _exclusions = exclusionArray.Where(x => x is not null).Cast<EvidenceExclusion>().ToImmutableArray();
        _testBinaries = _testBinaries.OrderBy(x => x.Identity.Value, StringComparer.Ordinal).ToImmutableArray();
        _artifacts = _artifacts.OrderBy(x => x.Architecture).ThenBy(x => x.Identity.Value, StringComparer.Ordinal).ToImmutableArray();
        _suites = _suites.OrderBy(x => x.Domain).ThenBy(x => x.Suite.Value, StringComparer.Ordinal).ToImmutableArray();
        _fuzz = _fuzz.OrderBy(x => x.Target.Value, StringComparer.Ordinal).ToImmutableArray();
        _modelCorpora = _modelCorpora.OrderBy(x => x.Domain).ThenBy(x => x.Corpus.Value, StringComparer.Ordinal).ToImmutableArray();
        _exclusions = _exclusions.OrderBy(x => x.Identity.Value, StringComparer.Ordinal).ToImmutableArray();
        Trace = trace; L0C = l0C; Checks = checks; ToolchainDigest = toolchainDigest; Approver = approver; Execution = execution; ReuseProof = reuseProof;
        IsWellFormed = tree is not null && treeDigest is not null && dependencyLock is not null && dependencyDigest is not null && schema is not null && schemaDigest is not null
            && binariesValid && artifactsValid && suitesValid && fuzzValid && modelValid && exclusionsValid && trace is not null && l0C is not null && checks is not null
            && toolchainDigest is not null && approver is not null && Enum.IsDefined(execution) && execution != EvidenceExecutionKind.Unknown
            && (execution == EvidenceExecutionKind.Cold ? reuseProof is null : reuseProof is not null) && ValidEntries();
    }
    public EvidenceTreeId Tree { get; }
    public EvidenceSha256 TreeDigest { get; }
    public EvidenceDependencyLockId DependencyLock { get; }
    public EvidenceSha256 DependencyDigest { get; }
    public EvidenceSchemaId Schema { get; }
    public EvidenceSha256 SchemaDigest { get; }
    public EvidenceRequirementTrace Trace { get; }
    public EvidenceL0CResult L0C { get; }
    public EvidenceCheckResults Checks { get; }
    public EvidenceSha256 ToolchainDigest { get; }
    public EvidenceApproverId Approver { get; }
    public EvidenceExecutionKind Execution { get; }
    public EvidenceReuseProof? ReuseProof { get; }
    public bool IsWellFormed { get; }
    public IReadOnlyList<EvidenceTestBinary> TestBinaries => _testBinaries; public IReadOnlyList<EvidenceArchitectureArtifact> Artifacts => _artifacts;
    public IReadOnlyList<EvidenceSuiteResult> Suites => _suites; public IReadOnlyList<EvidenceFuzzResult> Fuzz => _fuzz; public IReadOnlyList<EvidenceModelCorpus> ModelCorpora => _modelCorpora;
    public IReadOnlyList<EvidenceExclusion> Exclusions => _exclusions;
    public override string ToString() => "<evidence-subject>";

    internal bool ExactEquals(EvidenceSubject? other) => other is not null && Tree == other.Tree && TreeDigest.Equals(other.TreeDigest)
        && DependencyLock == other.DependencyLock && DependencyDigest.Equals(other.DependencyDigest) && Schema == other.Schema && SchemaDigest.Equals(other.SchemaDigest)
        && SequenceEqual(_testBinaries, other._testBinaries) && SequenceEqual(_artifacts, other._artifacts) && SequenceEqual(_suites, other._suites)
        && Trace == other.Trace && SequenceEqual(_fuzz, other._fuzz) && SequenceEqual(_modelCorpora, other._modelCorpora) && L0C == other.L0C && Checks == other.Checks
        && ToolchainDigest.Equals(other.ToolchainDigest) && Approver == other.Approver && Execution == other.Execution && ReuseProof == other.ReuseProof && SequenceEqual(_exclusions, other._exclusions);

    private bool ValidEntries() => _testBinaries.All(x => x.Identity is not null && x.Digest is not null)
        && _artifacts.All(x => x.Identity is not null && x.Digest is not null && Enum.IsDefined(x.Architecture) && x.Architecture != EvidenceArchitecture.Unknown)
        && _suites.All(x => x.Suite is not null && Enum.IsDefined(x.Domain) && x.Domain != EvidenceDomain.Unknown && x.Tests.IsValid && x.PropertyCases.IsValid
            && x.BranchCoverage.IsValid && x.MutationScore.IsValid && x.SurvivingSafetyMutants.IsValid && x.ModelSchedules.IsValid && x.ModelSeeds.IsValid && x.FlakeCleanRuns.IsValid
            && Enum.IsDefined(x.Result) && x.Result != EvidenceResult.Unknown)
        && Trace.Identity is not null && Trace.Digest is not null && Trace.Requirements.IsValid && Trace.Invariants.IsValid && Trace.Errors.IsValid && Trace.Transitions.IsValid
        && _fuzz.All(x => x.Target is not null && x.Corpus is not null && x.CorpusDigest is not null && x.Duration.IsValid && x.Cases.IsValid && Enum.IsDefined(x.Result) && x.Result != EvidenceResult.Unknown)
        && _modelCorpora.All(x => Enum.IsDefined(x.Domain) && x.Domain != EvidenceDomain.Unknown && x.Corpus is not null && x.Digest is not null)
        && L0C.Identity is not null && L0C.Digest is not null && Enum.IsDefined(L0C.Result) && L0C.Result != EvidenceResult.Unknown
        && Enum.IsDefined(Checks.Analyzer) && Checks.Analyzer != EvidenceResult.Unknown && Enum.IsDefined(Checks.Dependency) && Checks.Dependency != EvidenceResult.Unknown
        && Enum.IsDefined(Checks.Vulnerability) && Checks.Vulnerability != EvidenceResult.Unknown && Enum.IsDefined(Checks.License) && Checks.License != EvidenceResult.Unknown
        && Enum.IsDefined(Checks.SecretScan) && Checks.SecretScan != EvidenceResult.Unknown
        && _suites.Select(x => x.Suite).Distinct().Count() == _suites.Length && _modelCorpora.Select(x => x.Corpus).Distinct().Count() == _modelCorpora.Length
        && _exclusions.All(x => x.Identity is not null && Enum.IsDefined(x.Kind) && x.Kind != EvidenceExclusionKind.Unknown)
        && _exclusions.Select(x => x.Identity).Distinct().Count() == _exclusions.Length;
    private static bool SequenceEqual<T>(ImmutableArray<T> left, ImmutableArray<T> right) => left.Length == right.Length && left.Zip(right).All(pair => EqualityComparer<T>.Default.Equals(pair.First, pair.Second));
}

public sealed class EvidenceManifest
{
    public EvidenceManifest(EvidenceManifestId identity, EvidenceLane lane, EvidenceSubject subject, EvidenceSha256 canonicalPayloadDigest)
    { Identity = identity; Lane = lane; Subject = subject; CanonicalPayloadDigest = canonicalPayloadDigest; IsWellFormed = identity is not null && Enum.IsDefined(lane) && lane != EvidenceLane.Unknown && subject is { IsWellFormed: true } && canonicalPayloadDigest is not null; }
    public EvidenceManifestId Identity { get; }
    public EvidenceLane Lane { get; }
    public EvidenceSubject Subject { get; }
    public EvidenceSha256 CanonicalPayloadDigest { get; }
    public bool IsWellFormed { get; }
    public override string ToString() => "<evidence-manifest>";
}
