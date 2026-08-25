using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Evidence;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class EvidenceCoreTests
{
    private static T Require<T>(T? value) where T : class =>
        value ?? throw new InvalidOperationException("Evidence test assertion unexpectedly received null.");

    [Test]
    public async Task Accepted_decision_binds_every_manifest_and_signing_scope_field()
    {
        var subject=EvidenceTestData.Subject();var payload=EvidenceTestData.D(20);
        EvidenceDecision Gate(EvidenceManifestId? manifestId=null,EvidenceLane lane=EvidenceLane.Full,EvidenceGateTarget target=EvidenceGateTarget.DependencyConformance,
            EvidenceSigningProfileId? profile=null,EvidenceSigningIdentityId? signer=null,EvidenceSignatureId? signature=null,
            EvidenceGeneration? generation=null,EvidenceSequence? expiry=null)
        {
            manifestId??=EvidenceTestData.ManifestId();profile??=EvidenceTestData.Profile();signer??=EvidenceTestData.Signer();signature??=EvidenceTestData.SignatureId();
            generation??=EvidenceTestData.G(3);expiry??=EvidenceTestData.Q(20);
            return EvidenceTestData.Gate(manifest:new(manifestId,lane,subject,payload),policy:EvidenceTestData.Policy(lane:lane),
                envelope:EvidenceTestData.Envelope(profile:profile,signer:signer,signatureId:signature,generation:generation,expiry:expiry),
                context:EvidenceTestData.Context(manifest:manifestId,subject:subject,profile:profile,signer:signer,signatureId:signature,
                    generation:generation,expectedExpiry:expiry,target:target));
        }
        var exactManifest=EvidenceTestData.ManifestId();var exactProfile=EvidenceTestData.Profile();var exactSigner=EvidenceTestData.Signer();var exactSignature=EvidenceTestData.SignatureId();
        var exact=Gate(manifestId:exactManifest,profile:exactProfile,signer:exactSigner,signature:exactSignature);
        var replay=Gate(manifestId:exactManifest,profile:exactProfile,signer:exactSigner,signature:exactSignature);
        var variants=new[]{
            Gate(manifestId:EvidenceTestData.ManifestId("manifest-b")),
            Gate(lane:EvidenceLane.Feature),
            Gate(target:EvidenceGateTarget.L1SCredentialRelease),
            Gate(profile:EvidenceTestData.Profile("profile-b")),
            Gate(signer:EvidenceTestData.Signer("signer-b")),
            Gate(signature:EvidenceTestData.SignatureId("signature-b")),
            Gate(generation:EvidenceTestData.G(4)),
            Gate(expiry:EvidenceTestData.Q(21)),
        };
        await Assert.That(exact.IsAuthorized&&variants.All(x=>x.IsAuthorized)).IsTrue();
        await Assert.That(exact).IsEqualTo(replay);
        foreach(var variant in variants)await Assert.That(variant).IsNotEqualTo(exact);
        var scope=Require(exact.AuthorizationScope);
        await Assert.That(ReferenceEquals(scope.Manifest,exactManifest)).IsTrue();
        await Assert.That(ReferenceEquals(scope.SigningProfile,exactProfile)).IsTrue();
        await Assert.That(ReferenceEquals(scope.SigningIdentity,exactSigner)).IsTrue();
        await Assert.That(ReferenceEquals(scope.SignatureIdentity,exactSignature)).IsTrue();
        await Assert.That(scope.Manifest).IsEqualTo(EvidenceTestData.ManifestId());
        await Assert.That(scope.Lane).IsEqualTo(EvidenceLane.Full);
        await Assert.That(scope.Target).IsEqualTo(EvidenceGateTarget.DependencyConformance);
        await Assert.That(scope.SigningProfile).IsEqualTo(EvidenceTestData.Profile());
        await Assert.That(scope.SigningIdentity).IsEqualTo(EvidenceTestData.Signer());
        await Assert.That(scope.SignatureIdentity).IsEqualTo(EvidenceTestData.SignatureId());
        await Assert.That(scope.Generation).IsEqualTo(EvidenceTestData.G(3));
        await Assert.That(scope.ExpirySequence).IsEqualTo(EvidenceTestData.Q(20));
        var sourceGeneration=EvidenceTestData.G(17);var sourceExpiry=EvidenceTestData.Q(71);
        var sourceEnvelope=EvidenceTestData.Envelope(generation:sourceGeneration,expiry:sourceExpiry);
        var sourceDecision=EvidenceTestData.Gate(envelope:sourceEnvelope,
            context:EvidenceTestData.Context(generation:sourceGeneration,expectedExpiry:sourceExpiry));
        var sourceScope=Require(sourceDecision.AuthorizationScope);
        await Assert.That(sourceScope.Generation).IsEqualTo(sourceEnvelope.Material.Generation);
        await Assert.That(sourceScope.ExpirySequence).IsEqualTo(sourceEnvelope.Material.ExpirySequence);
    }

    [Test]
    public async Task Primitives_are_bounded_defensive_canonical_and_construction_closed()
    {
        var bytes=Enumerable.Repeat((byte)7,32).ToArray();EvidenceSha256.TryCreate(bytes,out var digest);bytes[0]=9;
        var copy=Require(digest).CopyBytes();copy[1]=8;
        await Assert.That(Require(digest).Equals(EvidenceTestData.D(7))).IsTrue();
        await Assert.That(EvidenceSha256.TryCreate(new byte[31],out _)).IsFalse();
        await Assert.That(EvidenceTreeId.TryCreate("two words",32,out _)).IsFalse();
        await Assert.That(typeof(EvidenceDecision).GetConstructors(BindingFlags.Public|BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(EvidenceDecisionSubject).GetConstructors(BindingFlags.Public|BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(EvidenceAuthorizationScope).GetConstructors(BindingFlags.Public|BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(EvidenceAuthorizationScope).GetMethods(BindingFlags.Public|BindingFlags.Instance|BindingFlags.Static)
            .Where(method=>method.Name=="Deconstruct")).IsEmpty();
        var publicScopeFactories=typeof(EvidenceAuthorizationScope).Assembly.GetExportedTypes()
            .SelectMany(type=>type.GetMethods(BindingFlags.Public|BindingFlags.Instance|BindingFlags.Static|BindingFlags.DeclaredOnly))
            .Where(method=>method.ReturnType==typeof(EvidenceAuthorizationScope)).ToArray();
        await Assert.That(publicScopeFactories.Select(method=>$"{Require(method.DeclaringType).Name}.{method.Name}").Order())
            .IsEquivalentTo(new[]{"EvidenceAuthorizationScope.<Clone>$","EvidenceDecision.get_AuthorizationScope"});
        await Assert.That(publicScopeFactories.Where(method=>method.Name!="<Clone>$"&&!method.IsSpecialName)).IsEmpty();
        var scopeClone=typeof(EvidenceAuthorizationScope).GetMethods(BindingFlags.Public|BindingFlags.Instance)
            .SingleOrDefault(method=>method.Name=="<Clone>$");
        await Assert.That(scopeClone).IsNotNull();
        var clone=Require(scopeClone);
        await Assert.That(clone.IsPublic).IsTrue();
        await Assert.That(clone.ReturnType).IsEqualTo(typeof(EvidenceAuthorizationScope));
        await Assert.That(clone.GetParameters()).IsEmpty();
        await Assert.That(typeof(EvidencePolicyResult).GetConstructors(BindingFlags.Public|BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(EvidenceReuseResult).GetConstructors(BindingFlags.Public|BindingFlags.Instance)).IsEmpty();
        await Assert.That(default(EvidencePolicyResult).Code).IsEqualTo(EvidenceCode.Unknown);
        await Assert.That(default(EvidencePolicyResult).IsAccepted).IsFalse();
        await Assert.That(default(EvidenceReuseResult).Code).IsEqualTo(EvidenceCode.Unknown);
        await Assert.That(default(EvidenceReuseResult).IsReusable).IsFalse();
        var closed=EvidenceTestData.Gate();await Assert.That(Enum.IsDefined(closed.Action)).IsTrue();await Assert.That(Enum.IsDefined(closed.Code)).IsTrue();
        await Assert.That(typeof(EvidenceDecision).GetProperties().All(property=>property.SetMethod is null)).IsTrue();
        await Assert.That(typeof(EvidenceAuthorizationScope).GetProperties().All(property=>property.SetMethod is null)).IsTrue();
        var identityValueProperty=Require(typeof(EvidenceIdentity).GetProperty(nameof(EvidenceIdentity.Value)));
        await Assert.That(identityValueProperty.SetMethod is null).IsTrue();
        var binaries=new[]{new EvidenceTestBinary(EvidenceTestData.Binary(),EvidenceTestData.D(4))};var subject=EvidenceTestData.Subject(binaries:binaries);binaries[0]=new(EvidenceTestData.Binary("forged"),EvidenceTestData.D(31));
        await Assert.That(subject.TestBinaries[0].Identity).IsEqualTo(EvidenceTestData.Binary());
        var signatureBytes=new byte[]{1,2,3};var signature=new EvidenceOpaqueSignature(signatureBytes,8);signatureBytes[0]=9;await Assert.That(signature.CopyBytes()[0]).IsEqualTo((byte)1);
        var original=CultureInfo.CurrentCulture;try{CultureInfo.CurrentCulture=new CultureInfo("ar-SA");await Assert.That(EvidenceTestData.C(123).ToString()).IsEqualTo("123");}finally{CultureInfo.CurrentCulture=original;}
        await Assert.That(EvidenceTestData.Gate().ToString()).DoesNotContain("signer");
        await Assert.That(Require(EvidenceTestData.Gate().AuthorizationScope).ToString()).IsEqualTo("<evidence-authorization-scope>");
        await Assert.That(EvidenceTestData.Envelope().ToString()).DoesNotContain("signature");
    }

    [Test]
    public async Task Policy_enforces_domains_architectures_thresholds_results_and_exclusions()
    {
        await Assert.That(EvidencePolicyEvaluator.Evaluate(EvidenceTestData.Manifest(),EvidenceTestData.Policy()).IsAccepted).IsTrue();
        var below=EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(branch:EvidenceTestData.P(89))]);
        await Assert.That(EvidencePolicyEvaluator.Evaluate(EvidenceTestData.Manifest(below),EvidenceTestData.Policy()).Code).IsEqualTo(EvidenceCode.ThresholdNotMet);
        var survivor=EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(survivors:EvidenceTestData.Z(1))]);
        await Assert.That(EvidencePolicyEvaluator.Evaluate(EvidenceTestData.Manifest(survivor),EvidenceTestData.Policy(mutation:EvidenceTestData.P(0))).Code).IsEqualTo(EvidenceCode.SafetyMutantSurvived);
        var forbidden=EvidenceTestData.Subject(exclusions:[new(EvidenceTestData.Exclusion(),EvidenceExclusionKind.Authorization)]);
        await Assert.That(EvidencePolicyEvaluator.Evaluate(EvidenceTestData.Manifest(forbidden),EvidenceTestData.Policy(exclusions:[EvidenceTestData.Exclusion()])).Code).IsEqualTo(EvidenceCode.ForbiddenExclusion);
        var permitted=EvidenceTestData.Subject(exclusions:[new(EvidenceTestData.Exclusion(),EvidenceExclusionKind.GeneratedCode)]);
        await Assert.That(EvidencePolicyEvaluator.Evaluate(EvidenceTestData.Manifest(permitted),EvidenceTestData.Policy(exclusions:[EvidenceTestData.Exclusion()])).IsAccepted).IsTrue();
        var oneArchitecture=EvidenceTestData.Subject(artifacts:[new(EvidenceTestData.Artifact("orchestrator-x64"),EvidenceArchitecture.LinuxX64,EvidenceTestData.D(5))]);
        await Assert.That(EvidencePolicyEvaluator.Evaluate(EvidenceTestData.Manifest(oneArchitecture),EvidenceTestData.Policy()).Code).IsEqualTo(EvidenceCode.InvalidArchitecture);
        var duplicated=EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(),EvidenceTestData.SuiteResult(suite:EvidenceTestData.Suite("other"))]);
        await Assert.That(EvidencePolicyEvaluator.Evaluate(EvidenceTestData.Manifest(duplicated),EvidenceTestData.Policy()).Code).IsEqualTo(EvidenceCode.DuplicateDomain);
        await Assert.That(EvidencePolicyEvaluator.Evaluate(EvidenceTestData.Manifest(),EvidenceTestData.Policy(domains:[EvidenceDomain.Control,EvidenceDomain.Storage])).Code).IsEqualTo(EvidenceCode.MissingDomain);
        var reused=EvidenceTestData.Subject(execution:EvidenceExecutionKind.ContentAddressedReuse);
        await Assert.That(EvidencePolicyEvaluator.Evaluate(EvidenceTestData.Manifest(reused),EvidenceTestData.Policy()).Code).IsEqualTo(EvidenceCode.FullExecutionRequired);
        var missingReuseProof=EvidenceTestData.Subject(execution:EvidenceExecutionKind.ContentAddressedReuse,defaultReuseProof:false);
        await Assert.That(EvidencePolicyEvaluator.Evaluate(EvidenceTestData.Manifest(missingReuseProof),EvidenceTestData.Policy(cold:false)).Code).IsEqualTo(EvidenceCode.InvalidInput);
        var failedScan=EvidenceTestData.Subject(checks:new(EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Failed));
        await Assert.That(EvidencePolicyEvaluator.Evaluate(EvidenceTestData.Manifest(failedScan),EvidenceTestData.Policy()).Code).IsEqualTo(EvidenceCode.ResultFailed);
        var excessive=EvidenceTestData.Subject(binaries:Enumerable.Range(0,65).Select(i=>(EvidenceTestBinary?)new(EvidenceTestData.Binary($"b{i}"),EvidenceTestData.D(4))));
        await Assert.That(EvidencePolicyEvaluator.Evaluate(EvidenceTestData.Manifest(excessive),EvidenceTestData.Policy()).Code).IsEqualTo(EvidenceCode.InvalidInput);
        var excessivePolicies=new[]{EvidenceTestData.Policy(tests:EvidenceTestData.C(101)),EvidenceTestData.Policy(branch:EvidenceTestData.P(91)),
            EvidenceTestData.Policy(mutation:EvidenceTestData.P(86)),EvidenceTestData.Policy(properties:EvidenceTestData.C(1001)),
            EvidenceTestData.Policy(schedules:EvidenceTestData.C(10_001)),EvidenceTestData.Policy(fuzzDuration:EvidenceTestData.T(61)),
            EvidenceTestData.Policy(fuzzCases:EvidenceTestData.C(10_001)),EvidenceTestData.Policy(flakes:EvidenceTestData.C(11))};
        foreach(var excessivePolicy in excessivePolicies)
            await Assert.That(EvidencePolicyEvaluator.Evaluate(EvidenceTestData.Manifest(),excessivePolicy).Code).IsEqualTo(EvidenceCode.ThresholdNotMet);
    }

    [Test]
    public async Task Caller_enumerables_are_bounded_and_iterator_failures_are_typed_invalid_input()
    {
        static IEnumerable<EvidenceTestBinary?> ThrowingBinaries(){yield return new(EvidenceTestData.Binary(),EvidenceTestData.D(4));throw new InvalidOperationException("iterator secret");}
        static IEnumerable<EvidenceDomain> ThrowingDomains(){yield return EvidenceDomain.Control;throw new InvalidOperationException("iterator secret");}
        var throwingSubject=EvidenceTestData.Subject(binaries:ThrowingBinaries());
        await Assert.That(throwingSubject.IsWellFormed).IsFalse();
        await Assert.That(EvidencePolicyEvaluator.Evaluate(EvidenceTestData.Manifest(throwingSubject),EvidenceTestData.Policy()).Code).IsEqualTo(EvidenceCode.InvalidInput);
        var throwingPolicy=EvidenceTestData.Policy(domains:ThrowingDomains());
        await Assert.That(throwingPolicy.IsWellFormed).IsFalse();
        var oversizedPolicy=EvidenceTestData.Policy(domains:Enumerable.Repeat(EvidenceDomain.Control,65));
        await Assert.That(oversizedPolicy.IsWellFormed).IsFalse();
    }

    [Test]
    public async Task Duplicate_identities_are_rejected_across_canonical_collections()
    {
        var suiteId=EvidenceTestData.Suite();
        var duplicateSuiteId=EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(suite:suiteId),EvidenceTestData.SuiteResult(EvidenceDomain.Storage,suite:suiteId)],
            models:[new(EvidenceDomain.Control,EvidenceTestData.Corpus("control"),EvidenceTestData.D(9)),new(EvidenceDomain.Storage,EvidenceTestData.Corpus("storage"),EvidenceTestData.D(12))]);
        var duplicateCorpusId=EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(),EvidenceTestData.SuiteResult(EvidenceDomain.Storage)],
            models:[new(EvidenceDomain.Control,EvidenceTestData.Corpus(),EvidenceTestData.D(9)),new(EvidenceDomain.Storage,EvidenceTestData.Corpus(),EvidenceTestData.D(12))]);
        var duplicateExclusion=EvidenceTestData.Subject(exclusions:[new(EvidenceTestData.Exclusion(),EvidenceExclusionKind.GeneratedCode),new(EvidenceTestData.Exclusion(),EvidenceExclusionKind.TrivialWiring)]);
        foreach(var subject in new[]{duplicateSuiteId,duplicateCorpusId,duplicateExclusion})
            await Assert.That(EvidencePolicyEvaluator.Evaluate(EvidenceTestData.Manifest(subject),EvidenceTestData.Policy()).Code).IsEqualTo(EvidenceCode.InvalidInput);
    }

    [Test]
    public async Task Malformed_and_unknown_enum_values_never_form_accepted_aggregates()
    {
        var malformedSubjects=new[]{
            EvidenceTestData.Subject(artifacts:[new(EvidenceTestData.Artifact("x64"),(EvidenceArchitecture)99,EvidenceTestData.D(5))]),
            EvidenceTestData.Subject(artifacts:[new(EvidenceTestData.Artifact("x64"),EvidenceArchitecture.Unknown,EvidenceTestData.D(5))]),
            EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult((EvidenceDomain)99)]),
            EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(EvidenceDomain.Unknown)]),
            EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(result:(EvidenceResult)99)]),
            EvidenceTestData.Subject(fuzz:[new(EvidenceTestData.FuzzTarget(),EvidenceTestData.Corpus(),EvidenceTestData.D(8),EvidenceTestData.T(60),EvidenceTestData.C(10_000),(EvidenceResult)99)]),
            EvidenceTestData.Subject(models:[new((EvidenceDomain)99,EvidenceTestData.Corpus(),EvidenceTestData.D(9))]),
            EvidenceTestData.Subject(l0c:new(EvidenceTestData.L0C(),EvidenceTestData.D(10),(EvidenceResult)99)),
            EvidenceTestData.Subject(checks:new(EvidenceResult.Unknown,EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Passed)),
            EvidenceTestData.Subject(checks:new(EvidenceResult.Passed,EvidenceResult.Unknown,EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Passed)),
            EvidenceTestData.Subject(checks:new(EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Unknown,EvidenceResult.Passed,EvidenceResult.Passed)),
            EvidenceTestData.Subject(checks:new(EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Unknown,EvidenceResult.Passed)),
            EvidenceTestData.Subject(checks:new(EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Unknown)),
            EvidenceTestData.Subject(execution:(EvidenceExecutionKind)99),
            EvidenceTestData.Subject(execution:EvidenceExecutionKind.Unknown),
            EvidenceTestData.Subject(exclusions:[new(EvidenceTestData.Exclusion(),(EvidenceExclusionKind)99)])};
        foreach(var subject in malformedSubjects)await Assert.That(subject.IsWellFormed).IsFalse();
        await Assert.That(EvidenceTestData.Manifest(lane:(EvidenceLane)99).IsWellFormed).IsFalse();
        await Assert.That(EvidenceTestData.Policy(lane:(EvidenceLane)99).IsWellFormed).IsFalse();
        await Assert.That(EvidenceTestData.Policy(lane:EvidenceLane.Unknown).IsWellFormed).IsFalse();
        await Assert.That(EvidenceTestData.Policy(domains:[(EvidenceDomain)99]).IsWellFormed).IsFalse();
        await Assert.That(EvidenceTestData.Policy(architectures:[(EvidenceArchitecture)99]).IsWellFormed).IsFalse();
        await Assert.That(EvidenceReuseEvaluator.Evaluate(EvidenceTestData.ReuseFingerprint(),EvidenceTestData.ReuseFingerprint(),EvidenceTestData.Policy(cold:false),(EvidenceChangeKind)99).Code).IsEqualTo(EvidenceCode.InvalidInput);
        await Assert.That(EvidenceTestData.Gate(context:EvidenceTestData.Context(target:(EvidenceGateTarget)99)).IsAuthorized).IsFalse();
    }

    [Test]
    public async Task Policy_detects_checked_arithmetic_overflow()
    {
        var huge=EvidenceTestData.C(ulong.MaxValue);var suites=new[]{EvidenceTestData.SuiteResult(tests:huge),EvidenceTestData.SuiteResult(EvidenceDomain.Storage)};
        var subject=EvidenceTestData.Subject(suites:suites,models:[new(EvidenceDomain.Control,EvidenceTestData.Corpus("control"),EvidenceTestData.D(9)),new(EvidenceDomain.Storage,EvidenceTestData.Corpus("storage"),EvidenceTestData.D(12))]);
        var result=EvidencePolicyEvaluator.Evaluate(EvidenceTestData.Manifest(subject),EvidenceTestData.Policy(domains:[EvidenceDomain.Control,EvidenceDomain.Storage]));
        await Assert.That(result.Code).IsEqualTo(EvidenceCode.ArithmeticOverflow);
    }

    [Test]
    public async Task Reuse_requires_every_content_address_and_forces_cold_execution_for_sensitive_changes()
    {
        EvidenceReuseFingerprint Finger(byte changed=0,int field=-1)=>new(
            EvidenceTestData.D(field==0?changed:(byte)1),EvidenceTestData.D(field==1?changed:(byte)2),EvidenceTestData.D(field==2?changed:(byte)3),EvidenceTestData.D(field==3?changed:(byte)4),
            EvidenceTestData.D(field==4?changed:(byte)5),EvidenceTestData.D(field==5?changed:(byte)6),EvidenceTestData.D(field==6?changed:(byte)7),EvidenceTestData.D(field==7?changed:(byte)8));
        var expected=Finger();await Assert.That(EvidenceReuseEvaluator.Evaluate(expected,Finger(),EvidenceTestData.Policy(cold:false),EvidenceChangeKind.ShardOnly).IsReusable).IsTrue();
        for(var field=0;field<8;field++)await Assert.That(EvidenceReuseEvaluator.Evaluate(expected,Finger(99,field),EvidenceTestData.Policy(cold:false),EvidenceChangeKind.ShardOnly).Code).IsEqualTo(EvidenceCode.ReuseDenied);
        foreach(var change in new[]{EvidenceChangeKind.SharedContract,EvidenceChangeKind.Security,EvidenceChangeKind.Toolchain,EvidenceChangeKind.ColdFirstCandidate})
            await Assert.That(EvidenceReuseEvaluator.Evaluate(expected,expected,EvidenceTestData.Policy(cold:false),change).Code).IsEqualTo(EvidenceCode.FullExecutionRequired);
        await Assert.That(EvidenceReuseEvaluator.Evaluate(expected,expected,EvidenceTestData.Policy(cold:false,reuse:false),EvidenceChangeKind.ShardOnly).Code).IsEqualTo(EvidenceCode.ReuseDenied);
    }

    [Test]
    public async Task Gate_allows_only_verified_exact_full_subject_for_credential_release()
    {
        var l1=EvidenceTestData.Gate();
        var dependency=EvidenceTestData.Gate(context:EvidenceTestData.Context(target:EvidenceGateTarget.DependencyConformance));
        await Assert.That(l1.Action).IsEqualTo(EvidenceAction.AllowL1SCredentialRelease);
        await Assert.That(dependency.Action).IsEqualTo(EvidenceAction.AllowDependencyConformance);
        var featureManifest=EvidenceTestData.Manifest(lane:EvidenceLane.Feature);
        await Assert.That(EvidenceTestData.Gate(manifest:featureManifest,policy:EvidenceTestData.Policy(lane:EvidenceLane.Feature)).Code).IsEqualTo(EvidenceCode.FeatureLaneCannotRelease);
        await Assert.That(EvidenceTestData.Gate(manifest:featureManifest,policy:EvidenceTestData.Policy(lane:EvidenceLane.Feature),
            context:EvidenceTestData.Context(target:EvidenceGateTarget.DependencyConformance)).Action).IsEqualTo(EvidenceAction.AllowDependencyConformance);
        var replay=EvidenceTestData.Gate();await Assert.That(replay).IsEqualTo(l1);
        await Assert.That(replay.AuthorizationScope).IsEqualTo(l1.AuthorizationScope);
        var permuted=EvidenceTestData.Subject(binaries:[new(EvidenceTestData.Binary("z"),EvidenceTestData.D(12)),new(EvidenceTestData.Binary("a"),EvidenceTestData.D(13))]);
        var permutedAgain=EvidenceTestData.Subject(binaries:permuted.TestBinaries.Reverse());
        await Assert.That(EvidenceTestData.Gate(manifest:EvidenceTestData.Manifest(permutedAgain),context:EvidenceTestData.Context(subject:permuted)).IsAuthorized).IsTrue();
    }

    [Test]
    public async Task Every_manifest_subject_field_is_exactly_bound()
    {
        var expected=EvidenceTestData.Subject();
        var substitutions=new EvidenceSubject[]{
            EvidenceTestData.Subject(tree:EvidenceTestData.Tree("other")),EvidenceTestData.Subject(treeDigest:EvidenceTestData.D(31)),
            EvidenceTestData.Subject(dependencyLock:EvidenceTestData.Lock("other")),EvidenceTestData.Subject(dependencyDigest:EvidenceTestData.D(32)),
            EvidenceTestData.Subject(schema:EvidenceTestData.Schema("other")),EvidenceTestData.Subject(schemaDigest:EvidenceTestData.D(33)),
            EvidenceTestData.Subject(binaries:[new(EvidenceTestData.Binary("other"),EvidenceTestData.D(4))]),
            EvidenceTestData.Subject(binaries:[new(EvidenceTestData.Binary(),EvidenceTestData.D(34))]),
            EvidenceTestData.Subject(artifacts:[new(EvidenceTestData.Artifact("other"),EvidenceArchitecture.LinuxX64,EvidenceTestData.D(5)),new(EvidenceTestData.Artifact("orchestrator-arm64"),EvidenceArchitecture.LinuxArm64,EvidenceTestData.D(6))]),
            EvidenceTestData.Subject(artifacts:[new(EvidenceTestData.Artifact("orchestrator-x64"),EvidenceArchitecture.LinuxArm64,EvidenceTestData.D(5)),new(EvidenceTestData.Artifact("orchestrator-arm64"),EvidenceArchitecture.LinuxX64,EvidenceTestData.D(6))]),
            EvidenceTestData.Subject(artifacts:[new(EvidenceTestData.Artifact("orchestrator-x64"),EvidenceArchitecture.LinuxX64,EvidenceTestData.D(35)),new(EvidenceTestData.Artifact("orchestrator-arm64"),EvidenceArchitecture.LinuxArm64,EvidenceTestData.D(6))]),
            EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(suite:EvidenceTestData.Suite("other"))]),
            EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(EvidenceDomain.Storage)]),
            EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(tests:EvidenceTestData.C(101))]),
            EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(properties:EvidenceTestData.C(1001))]),
            EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(branch:EvidenceTestData.P(91))]),
            EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(mutation:EvidenceTestData.P(86))]),
            EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(survivors:EvidenceTestData.Z(1))]),
            EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(schedules:EvidenceTestData.C(10_001))]),
            EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(seeds:EvidenceTestData.C(101))]),
            EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(flakes:EvidenceTestData.C(11))]),
            EvidenceTestData.Subject(suites:[EvidenceTestData.SuiteResult(result:EvidenceResult.Failed)]),
            EvidenceTestData.Subject(trace:new(EvidenceTestData.Trace("other"),EvidenceTestData.D(7),EvidenceTestData.C(20),EvidenceTestData.C(10),EvidenceTestData.C(5),EvidenceTestData.C(8))),
            EvidenceTestData.Subject(trace:new(EvidenceTestData.Trace(),EvidenceTestData.D(36),EvidenceTestData.C(20),EvidenceTestData.C(10),EvidenceTestData.C(5),EvidenceTestData.C(8))),
            EvidenceTestData.Subject(trace:new(EvidenceTestData.Trace(),EvidenceTestData.D(7),EvidenceTestData.C(21),EvidenceTestData.C(10),EvidenceTestData.C(5),EvidenceTestData.C(8))),
            EvidenceTestData.Subject(trace:new(EvidenceTestData.Trace(),EvidenceTestData.D(7),EvidenceTestData.C(20),EvidenceTestData.C(11),EvidenceTestData.C(5),EvidenceTestData.C(8))),
            EvidenceTestData.Subject(trace:new(EvidenceTestData.Trace(),EvidenceTestData.D(7),EvidenceTestData.C(20),EvidenceTestData.C(10),EvidenceTestData.C(6),EvidenceTestData.C(8))),
            EvidenceTestData.Subject(trace:new(EvidenceTestData.Trace(),EvidenceTestData.D(7),EvidenceTestData.C(20),EvidenceTestData.C(10),EvidenceTestData.C(5),EvidenceTestData.C(9))),
            EvidenceTestData.Subject(fuzz:[new(EvidenceTestData.FuzzTarget("other"),EvidenceTestData.Corpus(),EvidenceTestData.D(8),EvidenceTestData.T(60),EvidenceTestData.C(10_000),EvidenceResult.Passed)]),
            EvidenceTestData.Subject(fuzz:[new(EvidenceTestData.FuzzTarget(),EvidenceTestData.Corpus("other"),EvidenceTestData.D(8),EvidenceTestData.T(60),EvidenceTestData.C(10_000),EvidenceResult.Passed)]),
            EvidenceTestData.Subject(fuzz:[new(EvidenceTestData.FuzzTarget(),EvidenceTestData.Corpus(),EvidenceTestData.D(37),EvidenceTestData.T(60),EvidenceTestData.C(10_000),EvidenceResult.Passed)]),
            EvidenceTestData.Subject(fuzz:[new(EvidenceTestData.FuzzTarget(),EvidenceTestData.Corpus(),EvidenceTestData.D(8),EvidenceTestData.T(61),EvidenceTestData.C(10_000),EvidenceResult.Passed)]),
            EvidenceTestData.Subject(fuzz:[new(EvidenceTestData.FuzzTarget(),EvidenceTestData.Corpus(),EvidenceTestData.D(8),EvidenceTestData.T(60),EvidenceTestData.C(10_001),EvidenceResult.Passed)]),
            EvidenceTestData.Subject(fuzz:[new(EvidenceTestData.FuzzTarget(),EvidenceTestData.Corpus(),EvidenceTestData.D(8),EvidenceTestData.T(60),EvidenceTestData.C(10_000),EvidenceResult.Failed)]),
            EvidenceTestData.Subject(models:[new(EvidenceDomain.Storage,EvidenceTestData.Corpus("model"),EvidenceTestData.D(9))]),
            EvidenceTestData.Subject(models:[new(EvidenceDomain.Control,EvidenceTestData.Corpus("other"),EvidenceTestData.D(9))]),
            EvidenceTestData.Subject(models:[new(EvidenceDomain.Control,EvidenceTestData.Corpus("model"),EvidenceTestData.D(40))]),
            EvidenceTestData.Subject(l0c:new(EvidenceTestData.L0C("other"),EvidenceTestData.D(10),EvidenceResult.Passed)),
            EvidenceTestData.Subject(l0c:new(EvidenceTestData.L0C(),EvidenceTestData.D(38),EvidenceResult.Passed)),
            EvidenceTestData.Subject(l0c:new(EvidenceTestData.L0C(),EvidenceTestData.D(10),EvidenceResult.Failed)),
            EvidenceTestData.Subject(checks:new(EvidenceResult.Failed,EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Passed)),
            EvidenceTestData.Subject(checks:new(EvidenceResult.Passed,EvidenceResult.Failed,EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Passed)),
            EvidenceTestData.Subject(checks:new(EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Failed,EvidenceResult.Passed,EvidenceResult.Passed)),
            EvidenceTestData.Subject(checks:new(EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Failed,EvidenceResult.Passed)),
            EvidenceTestData.Subject(checks:new(EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Passed,EvidenceResult.Failed)),
            EvidenceTestData.Subject(toolchain:EvidenceTestData.D(39)),EvidenceTestData.Subject(approver:EvidenceTestData.Approver("other")),
            EvidenceTestData.Subject(execution:EvidenceExecutionKind.ContentAddressedReuse),EvidenceTestData.Subject(exclusions:[new(EvidenceTestData.Exclusion(),EvidenceExclusionKind.GeneratedCode)])
        };
        foreach(var substituted in substitutions)
        {
            var decision=EvidenceTestData.Gate(manifest:EvidenceTestData.Manifest(substituted),context:EvidenceTestData.Context(subject:expected));
            await Assert.That(decision.IsAuthorized).IsFalse();
        }
        await Assert.That(EvidenceTestData.Gate(manifest:EvidenceTestData.Manifest(payload:EvidenceTestData.D(41))).Code).IsEqualTo(EvidenceCode.WrongSubject);
        await Assert.That(EvidenceTestData.Gate(manifest:new(EvidenceTestData.ManifestId("other"),EvidenceLane.Full,expected,EvidenceTestData.D(20))).Code).IsEqualTo(EvidenceCode.WrongSubject);
        await Assert.That(EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(payload:EvidenceTestData.D(42))).Code).IsEqualTo(EvidenceCode.WrongSubject);
    }

    [Test]
    public async Task Signature_identity_generation_expiry_and_opaque_outcomes_fail_closed()
    {
        await Assert.That(EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(profile:EvidenceTestData.Profile("other"))).Code).IsEqualTo(EvidenceCode.WrongSigningProfile);
        await Assert.That(EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(signer:EvidenceTestData.Signer("other"))).Code).IsEqualTo(EvidenceCode.WrongSigningIdentity);
        await Assert.That(EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(signatureId:EvidenceTestData.SignatureId("other"))).Code).IsEqualTo(EvidenceCode.WrongSignature);
        await Assert.That(EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(generation:EvidenceTestData.G(2))).Code).IsEqualTo(EvidenceCode.StaleGeneration);
        await Assert.That(EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(generation:EvidenceTestData.G(4))).Code).IsEqualTo(EvidenceCode.FutureGeneration);
        await Assert.That(EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(expiry:EvidenceTestData.Q(19))).Code).IsEqualTo(EvidenceCode.StaleExpiry);
        await Assert.That(EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(expiry:EvidenceTestData.Q(21))).Code).IsEqualTo(EvidenceCode.FutureExpiry);
        await Assert.That(EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(expiry:EvidenceTestData.Q(9)),context:EvidenceTestData.Context(expectedExpiry:EvidenceTestData.Q(9),current:EvidenceTestData.Q(10))).Code).IsEqualTo(EvidenceCode.Expired);
        await Assert.That(EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(expiry:EvidenceTestData.Q(10)),context:EvidenceTestData.Context(expectedExpiry:EvidenceTestData.Q(10),current:EvidenceTestData.Q(10))).IsAuthorized).IsTrue();
        foreach(var outcome in new[]{EvidenceSignatureVerificationOutcome.Invalid,EvidenceSignatureVerificationOutcome.Unknown,(EvidenceSignatureVerificationOutcome)99})
            await Assert.That(EvidenceTestData.Gate(context:EvidenceTestData.Context(verifier:new TestEvidenceVerifier(outcome))).IsAuthorized).IsFalse();
        var failure=EvidenceTestData.Gate(context:EvidenceTestData.Context(verifier:new TestEvidenceVerifier(throws:true)));
        await Assert.That(failure.Code).IsEqualTo(EvidenceCode.SignatureVerificationFailed);
        await Assert.That(failure.ToString()).DoesNotContain("secret verifier detail");
        await Assert.That(failure.AuthorizationScope).IsNull();
        var invalid=PreDeploymentEvidenceGate.Verify(null,null,null,null);
        await Assert.That(invalid.IsAuthorized).IsFalse();await Assert.That(invalid.AuthorizationScope).IsNull();
    }

    [Test]
    public async Task Every_gate_hold_path_discards_authorization_scope()
    {
        var feature=EvidenceTestData.Manifest(lane:EvidenceLane.Feature);
        var denials=new[]{
            PreDeploymentEvidenceGate.Verify(null,null,null,null),
            EvidenceTestData.Gate(manifest:EvidenceTestData.Manifest(payload:EvidenceTestData.D(31))),
            EvidenceTestData.Gate(policy:EvidenceTestData.Policy(tests:EvidenceTestData.C(101))),
            EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(profile:EvidenceTestData.Profile("other"))),
            EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(signer:EvidenceTestData.Signer("other"))),
            EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(signatureId:EvidenceTestData.SignatureId("other"))),
            EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(generation:EvidenceTestData.G(2))),
            EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(generation:EvidenceTestData.G(4))),
            EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(expiry:EvidenceTestData.Q(19))),
            EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(expiry:EvidenceTestData.Q(21))),
            EvidenceTestData.Gate(envelope:EvidenceTestData.Envelope(expiry:EvidenceTestData.Q(9)),context:EvidenceTestData.Context(expectedExpiry:EvidenceTestData.Q(9),current:EvidenceTestData.Q(10))),
            EvidenceTestData.Gate(context:EvidenceTestData.Context(verifier:new TestEvidenceVerifier(EvidenceSignatureVerificationOutcome.Invalid))),
            EvidenceTestData.Gate(context:EvidenceTestData.Context(verifier:new TestEvidenceVerifier(EvidenceSignatureVerificationOutcome.Unknown))),
            EvidenceTestData.Gate(context:EvidenceTestData.Context(verifier:new TestEvidenceVerifier(throws:true))),
            EvidenceTestData.Gate(manifest:feature,policy:EvidenceTestData.Policy(lane:EvidenceLane.Feature)),
        };
        foreach(var denial in denials)
        {
            await Assert.That(denial.IsAuthorized).IsFalse();
            await Assert.That(denial.Subject).IsNull();
            await Assert.That(denial.AuthorizationScope).IsNull();
        }
    }

    [Test]
    public async Task Opaque_verifier_runs_once_only_after_exact_and_policy_checks()
    {
        var mismatchVerifier=new TestEvidenceVerifier();
        var mismatch=EvidenceTestData.Gate(manifest:EvidenceTestData.Manifest(payload:EvidenceTestData.D(55)),context:EvidenceTestData.Context(verifier:mismatchVerifier));
        await Assert.That(mismatch.IsAuthorized).IsFalse();await Assert.That(mismatchVerifier.Calls).IsEqualTo(0);
        var policyVerifier=new TestEvidenceVerifier();
        var policyFailure=EvidenceTestData.Gate(policy:EvidenceTestData.Policy(branch:EvidenceTestData.P(100)),context:EvidenceTestData.Context(verifier:policyVerifier));
        await Assert.That(policyFailure.IsAuthorized).IsFalse();await Assert.That(policyVerifier.Calls).IsEqualTo(0);
        var validVerifier=new TestEvidenceVerifier();
        await Assert.That(EvidenceTestData.Gate(context:EvidenceTestData.Context(verifier:validVerifier)).IsAuthorized).IsTrue();
        await Assert.That(validVerifier.Calls).IsEqualTo(1);
    }
}
