using TerraScale.Orchestrator.ControlPlane.Evidence;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

internal static class EvidenceTestData
{
    private const int M = 80;
    private static T Require<T>(bool created, T? value) where T : class =>
        created && value is not null ? value : throw new InvalidOperationException("Evidence test data factory returned an invalid value.");
    public static EvidenceSha256 D(byte value) => Require(EvidenceSha256.TryCreate(Enumerable.Repeat(value, 32).ToArray(), out var x), x);
    public static EvidenceCount C(ulong value) { EvidenceCount.TryCreate(value, out var x); return x; }
    public static EvidenceNonNegativeCount Z(ulong value = 0) { EvidenceNonNegativeCount.TryCreate(value, out var x); return x; }
    public static EvidencePercentage P(ushort value) { EvidencePercentage.TryCreate(value, out var x); return x; }
    public static EvidenceDurationSeconds T(ulong value) { EvidenceDurationSeconds.TryCreate(value, out var x); return x; }
    public static EvidenceGeneration G(ulong value) { EvidenceGeneration.TryCreate(value, out var x); return x; }
    public static EvidenceSequence Q(ulong value) { EvidenceSequence.TryCreate(value, out var x); return x; }
    public static EvidenceTreeId Tree(string v = "tree") => Require(EvidenceTreeId.TryCreate(v, M, out var x), x); public static EvidenceDependencyLockId Lock(string v = "lock") => Require(EvidenceDependencyLockId.TryCreate(v, M, out var x), x);
    public static EvidenceSchemaId Schema(string v = "schema") => Require(EvidenceSchemaId.TryCreate(v, M, out var x), x); public static EvidenceTestBinaryId Binary(string v = "tests") => Require(EvidenceTestBinaryId.TryCreate(v, M, out var x), x);
    public static EvidenceArtifactId Artifact(string v) => Require(EvidenceArtifactId.TryCreate(v, M, out var x), x); public static EvidenceSuiteId Suite(string v = "control") => Require(EvidenceSuiteId.TryCreate(v, M, out var x), x);
    public static EvidenceTraceId Trace(string v = "trace") => Require(EvidenceTraceId.TryCreate(v, M, out var x), x); public static EvidenceFuzzTargetId FuzzTarget(string v = "manifest") => Require(EvidenceFuzzTargetId.TryCreate(v, M, out var x), x);
    public static EvidenceCorpusId Corpus(string v = "corpus") => Require(EvidenceCorpusId.TryCreate(v, M, out var x), x); public static EvidenceL0CId L0C(string v = "nats") => Require(EvidenceL0CId.TryCreate(v, M, out var x), x);
    public static EvidenceApproverId Approver(string v = "owner") => Require(EvidenceApproverId.TryCreate(v, M, out var x), x); public static EvidenceSigningProfileId Profile(string v = "profile") => Require(EvidenceSigningProfileId.TryCreate(v, M, out var x), x);
    public static EvidenceSigningIdentityId Signer(string v = "signer") => Require(EvidenceSigningIdentityId.TryCreate(v, M, out var x), x); public static EvidenceSignatureId SignatureId(string v = "signature") => Require(EvidenceSignatureId.TryCreate(v, M, out var x), x);
    public static EvidenceManifestId ManifestId(string v = "manifest") => Require(EvidenceManifestId.TryCreate(v, M, out var x), x); public static EvidenceExclusionId Exclusion(string v = "generated") => Require(EvidenceExclusionId.TryCreate(v, M, out var x), x);

    public static EvidenceSuiteResult SuiteResult(EvidenceDomain domain = EvidenceDomain.Control, EvidenceSuiteId? suite = null, EvidenceCount? tests = null, EvidenceCount? properties = null,
        EvidencePercentage? branch = null, EvidencePercentage? mutation = null, EvidenceNonNegativeCount? survivors = null, EvidenceCount? schedules = null,
        EvidenceCount? seeds = null, EvidenceCount? flakes = null, EvidenceResult result = EvidenceResult.Passed) =>
        new(suite ?? Suite(domain.ToString()), domain, tests ?? C(100), properties ?? C(1000), branch ?? P(90), mutation ?? P(85), survivors ?? Z(), schedules ?? C(10_000), seeds ?? C(100), flakes ?? C(10), result);

    public static EvidenceSubject Subject(EvidenceTreeId? tree = null, EvidenceSha256? treeDigest = null, EvidenceDependencyLockId? dependencyLock = null, EvidenceSha256? dependencyDigest = null,
        EvidenceSchemaId? schema = null, EvidenceSha256? schemaDigest = null, IEnumerable<EvidenceTestBinary?>? binaries = null, IEnumerable<EvidenceArchitectureArtifact?>? artifacts = null,
        IEnumerable<EvidenceSuiteResult?>? suites = null, EvidenceRequirementTrace? trace = null, IEnumerable<EvidenceFuzzResult?>? fuzz = null,
        IEnumerable<EvidenceModelCorpus?>? models = null, EvidenceL0CResult? l0c = null, EvidenceCheckResults? checks = null, EvidenceSha256? toolchain = null,
        EvidenceApproverId? approver = null, EvidenceExecutionKind execution = EvidenceExecutionKind.Cold, EvidenceReuseProof? reuseProof = null, IEnumerable<EvidenceExclusion?>? exclusions = null, int maximum = 64, bool defaultReuseProof = true) => new(
        tree ?? Tree(), treeDigest ?? D(1), dependencyLock ?? Lock(), dependencyDigest ?? D(2), schema ?? Schema(), schemaDigest ?? D(3),
        binaries ?? [new(Binary(), D(4))], artifacts ?? [new(Artifact("orchestrator-x64"), EvidenceArchitecture.LinuxX64, D(5)), new(Artifact("orchestrator-arm64"), EvidenceArchitecture.LinuxArm64, D(6))],
        suites ?? [SuiteResult()], trace ?? new(Trace(), D(7), C(20), C(10), C(5), C(8)),
        fuzz ?? [new(FuzzTarget(), Corpus(), D(8), T(60), C(10_000), EvidenceResult.Passed)], models ?? [new(EvidenceDomain.Control, Corpus("model"), D(9))],
        l0c ?? new(L0C(), D(10), EvidenceResult.Passed), checks ?? new(EvidenceResult.Passed, EvidenceResult.Passed, EvidenceResult.Passed, EvidenceResult.Passed, EvidenceResult.Passed),
        toolchain ?? D(11), approver ?? Approver(), execution, execution == EvidenceExecutionKind.ContentAddressedReuse && defaultReuseProof ? reuseProof ?? new(ReuseFingerprint(), ReuseFingerprint(), EvidenceChangeKind.ShardOnly) : reuseProof, exclusions ?? [], maximum);
    public static EvidenceReuseFingerprint ReuseFingerprint(byte offset = 0) => new(D((byte)(1 + offset)), D((byte)(2 + offset)), D((byte)(3 + offset)), D((byte)(4 + offset)),
        D((byte)(5 + offset)), D((byte)(6 + offset)), D((byte)(7 + offset)), D((byte)(8 + offset)));

    public static EvidencePolicy Policy(EvidenceLane lane = EvidenceLane.Full, IEnumerable<EvidenceDomain>? domains = null, bool cold = true,
        EvidenceCount? tests = null, EvidencePercentage? branch = null, EvidencePercentage? mutation = null, EvidenceCount? properties = null,
        EvidenceCount? schedules = null, EvidenceDurationSeconds? fuzzDuration = null, EvidenceCount? fuzzCases = null, EvidenceCount? flakes = null,
        IEnumerable<EvidenceExclusionId?>? exclusions = null, IEnumerable<EvidenceArchitecture>? architectures = null, bool reuse = true) => new(lane, domains ?? [EvidenceDomain.Control], cold,
        tests ?? C(100), branch ?? P(90), mutation ?? P(85), properties ?? C(1000), schedules ?? C(10_000), fuzzDuration ?? T(60), fuzzCases ?? C(10_000), flakes ?? C(10),
        exclusions ?? [], architectures ?? [EvidenceArchitecture.LinuxX64, EvidenceArchitecture.LinuxArm64], reuse, 64);
    public static EvidenceManifest Manifest(EvidenceSubject? subject = null, EvidenceLane lane = EvidenceLane.Full, EvidenceSha256? payload = null) => new(ManifestId(), lane, subject ?? Subject(), payload ?? D(20));
    public static EvidenceSignedEnvelope Envelope(EvidenceSha256? payload = null, EvidenceSigningProfileId? profile = null, EvidenceSigningIdentityId? signer = null,
        EvidenceSignatureId? signatureId = null, EvidenceGeneration? generation = null, EvidenceSequence? expiry = null) => new(
        new(payload ?? D(20), profile ?? Profile(), signer ?? Signer(), signatureId ?? SignatureId(), generation ?? G(3), expiry ?? Q(20)), new EvidenceOpaqueSignature([1, 2, 3], 64));
    public static EvidenceGateContext Context(EvidenceManifestId? manifest = null, EvidenceSubject? subject = null, EvidenceSha256? payload = null, EvidenceSigningProfileId? profile = null,
        EvidenceSigningIdentityId? signer = null, EvidenceSignatureId? signatureId = null, EvidenceGeneration? generation = null, EvidenceSequence? current = null,
        EvidenceSequence? expectedExpiry = null, EvidenceGateTarget target = EvidenceGateTarget.L1SCredentialRelease, IEvidenceSignatureVerifier? verifier = null) => new(manifest ?? ManifestId(), subject ?? Subject(), payload ?? D(20), profile ?? Profile(), signer ?? Signer(),
        signatureId ?? SignatureId(), generation ?? G(3), expectedExpiry ?? Q(20), current ?? Q(10), target, verifier ?? new TestEvidenceVerifier());
    public static EvidenceDecision Gate(EvidenceManifest? manifest = null, EvidencePolicy? policy = null, EvidenceSignedEnvelope? envelope = null, EvidenceGateContext? context = null) =>
        PreDeploymentEvidenceGate.Verify(manifest ?? Manifest(), policy ?? Policy(), envelope ?? Envelope(), context ?? Context());
}

internal sealed class TestEvidenceVerifier(EvidenceSignatureVerificationOutcome outcome = EvidenceSignatureVerificationOutcome.Valid, bool throws = false) : IEvidenceSignatureVerifier
{
    public int Calls { get; private set; }
    public EvidenceSignatureVerificationOutcome Verify(EvidenceSignedMaterial material, EvidenceOpaqueSignature signature) { Calls++; if (throws) throw new InvalidOperationException("secret verifier detail"); return outcome; }
}

