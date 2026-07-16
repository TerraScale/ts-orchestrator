using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Evidence;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class CiEvidenceReportAudit4CounterexampleTests
{
    [Test]
    public async Task Accepted_gate_output_retains_exact_validated_report_and_distinguishes_every_admissible_leaf()
    {
        var baselineSubject = EvidenceTestData.Subject();
        var baseline = Gate(baselineSubject);
        await Assert.That(baseline.IsAuthorized).IsTrue();
        await Assert.That(ReferenceEquals(baseline.Subject!.Report, baselineSubject)).IsTrue();

        foreach (var variant in AcceptedVariants())
        {
            var decision = Gate(variant.Subject, variant.Policy);
            await Assert.That(decision.IsAuthorized).IsTrue();
            await Assert.That(ReferenceEquals(decision.Subject!.Report, variant.Subject)).IsTrue();
            await Assert.That(decision).IsNotEqualTo(baseline);
        }
    }

    [Test]
    public async Task Exact_reconstruction_collection_permutations_culture_and_source_mutation_replay_deterministically()
    {
        var first = PermutedSubject(reverse: false, out var sources);
        var firstPolicy = PermutationPolicy();
        var firstDecision = UnderCulture("tr-TR", () => Gate(first, firstPolicy));
        sources.Binaries[0] = new(EvidenceTestData.Binary("mutated-after-snapshot"), EvidenceTestData.D(31));
        sources.Artifacts[0] = new(EvidenceTestData.Artifact("mutated-after-snapshot"), EvidenceArchitecture.LinuxX64, EvidenceTestData.D(31));
        sources.Suites[0] = EvidenceTestData.SuiteResult(suite: EvidenceTestData.Suite("mutated-after-snapshot"));
        sources.Fuzz[0] = Fuzz(target: "mutated-after-snapshot");
        sources.Models[0] = new(EvidenceDomain.Control, EvidenceTestData.Corpus("mutated-after-snapshot"), EvidenceTestData.D(31));
        sources.Exclusions[0] = new(EvidenceTestData.Exclusion("mutated-after-snapshot"), EvidenceExclusionKind.GeneratedCode);

        var replay = PermutedSubject(reverse: false, out _);
        var replayDecision = UnderCulture("ar-SA", () => Gate(replay, PermutationPolicy()));
        var permuted = PermutedSubject(reverse: true, out _);
        var permutedDecision = UnderCulture("ja-JP", () => Gate(permuted, PermutationPolicy()));

        await Assert.That(ReferenceEquals(firstDecision.Subject!.Report, first)).IsTrue();
        await Assert.That(ReferenceEquals(replayDecision.Subject!.Report, replay)).IsTrue();
        await Assert.That(firstDecision).IsEqualTo(replayDecision);
        await Assert.That(firstDecision).IsEqualTo(permutedDecision);
        await Assert.That(firstDecision.GetHashCode()).IsEqualTo(replayDecision.GetHashCode());
        await Assert.That(first.TestBinaries[0].Identity).IsEqualTo(EvidenceTestData.Binary("binary-a"));
    }

    [Test]
    public async Task Holds_remain_report_free_and_output_construction_routes_are_exactly_inventoried()
    {
        var hold = PreDeploymentEvidenceGate.Verify(null, null, null, null);
        await Assert.That(hold.IsAuthorized).IsFalse();
        await Assert.That(hold.Subject).IsNull();

        var subjectType = typeof(EvidenceDecisionSubject);
        await Assert.That(subjectType.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(subjectType.GetProperties().Where(property => property.SetMethod?.IsPublic == true)).IsEmpty();
        await Assert.That(subjectType.GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(method => method.Name is "Deconstruct" or "<Clone>$")).IsEmpty();
        await Assert.That(subjectType.Assembly.GetExportedTypes()
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(method => method.ReturnType == subjectType)
            .Select(Route).Order(StringComparer.Ordinal))
            .IsEquivalentTo(new[] { "EvidenceDecision.get_Subject()->EvidenceDecisionSubject" });

        var routeOutputs = new HashSet<Type>
        {
            typeof(EvidenceDecision), typeof(EvidenceDecisionSubject), typeof(EvidenceAuthorizationScope),
            typeof(EvidenceNumericTrace), typeof(EvidenceSubject),
        };
        var routes = subjectType.Assembly.GetExportedTypes()
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(method => routeOutputs.Contains(method.ReturnType))
            .Select(Route).Order(StringComparer.Ordinal).ToArray();
        await Assert.That(routes).IsEquivalentTo(new[]
        {
            "EvidenceAuthorizationScope.<Clone>$()->EvidenceAuthorizationScope",
            "EvidenceDecision.<Clone>$()->EvidenceDecision",
            "EvidenceDecision.get_AuthorizationScope()->EvidenceAuthorizationScope",
            "EvidenceDecision.get_Subject()->EvidenceDecisionSubject",
            "EvidenceDecision.get_Trace()->EvidenceNumericTrace",
            "EvidenceDecisionSubject.get_Report()->EvidenceSubject",
            "EvidenceGateContext.get_ExpectedSubject()->EvidenceSubject",
            "EvidenceManifest.get_Subject()->EvidenceSubject",
            "EvidenceNumericTrace.<Clone>$()->EvidenceNumericTrace",
            "PreDeploymentEvidenceGate.Verify(EvidenceManifest,EvidencePolicy,EvidenceSignedEnvelope,EvidenceGateContext)->EvidenceDecision",
        });

        var projections = typeof(EvidenceSubject).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(method => method.IsSpecialName && method.ReturnType.IsGenericType &&
                method.ReturnType.GetGenericTypeDefinition() == typeof(IReadOnlyList<>))
            .Select(Route).Order(StringComparer.Ordinal).ToArray();
        await Assert.That(projections).IsEquivalentTo(new[]
        {
            "EvidenceSubject.get_Artifacts()->IReadOnlyList<EvidenceArchitectureArtifact>",
            "EvidenceSubject.get_Exclusions()->IReadOnlyList<EvidenceExclusion>",
            "EvidenceSubject.get_Fuzz()->IReadOnlyList<EvidenceFuzzResult>",
            "EvidenceSubject.get_ModelCorpora()->IReadOnlyList<EvidenceModelCorpus>",
            "EvidenceSubject.get_Suites()->IReadOnlyList<EvidenceSuiteResult>",
            "EvidenceSubject.get_TestBinaries()->IReadOnlyList<EvidenceTestBinary>",
        });

        await Assert.That(routes.Where(route => route.Contains("PreDeploymentEvidenceGate", StringComparison.Ordinal)).Single())
            .IsEqualTo("PreDeploymentEvidenceGate.Verify(EvidenceManifest,EvidencePolicy,EvidenceSignedEnvelope,EvidenceGateContext)->EvidenceDecision");
        await Assert.That(new[] { typeof(EvidenceDecision), typeof(EvidenceAuthorizationScope), typeof(EvidenceNumericTrace) }
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Where(method => method.Name == "<Clone>$")).Count()).IsEqualTo(3);
        await Assert.That(Gate(EvidenceTestData.Subject()).Subject!.ToString()).IsEqualTo("<evidence-decision-subject>");
    }

    private static IReadOnlyList<AcceptedVariant> AcceptedVariants()
    {
        var storageSuite = EvidenceTestData.SuiteResult(EvidenceDomain.Storage);
        var storageModel = new EvidenceModelCorpus(EvidenceDomain.Storage, EvidenceTestData.Corpus("storage-model"), EvidenceTestData.D(29));
        var reuse = EvidenceTestData.ReuseFingerprint(20);
        return
        [
            new("tree-id", EvidenceTestData.Subject(tree: EvidenceTestData.Tree("tree-b"))),
            new("tree-digest", EvidenceTestData.Subject(treeDigest: EvidenceTestData.D(21))),
            new("dependency-id", EvidenceTestData.Subject(dependencyLock: EvidenceTestData.Lock("lock-b"))),
            new("dependency-digest", EvidenceTestData.Subject(dependencyDigest: EvidenceTestData.D(22))),
            new("schema-id", EvidenceTestData.Subject(schema: EvidenceTestData.Schema("schema-b"))),
            new("schema-digest", EvidenceTestData.Subject(schemaDigest: EvidenceTestData.D(23))),
            new("binary-id", EvidenceTestData.Subject(binaries: [new(EvidenceTestData.Binary("tests-b"), EvidenceTestData.D(4))])),
            new("binary-digest", EvidenceTestData.Subject(binaries: [new(EvidenceTestData.Binary(), EvidenceTestData.D(24))])),
            new("binary-count", EvidenceTestData.Subject(binaries: [new(EvidenceTestData.Binary(), EvidenceTestData.D(4)), new(EvidenceTestData.Binary("tests-b"), EvidenceTestData.D(24))])),
            new("artifact-id", EvidenceTestData.Subject(artifacts: Artifacts(x64Id: "x64-b"))),
            new("artifact-architecture", EvidenceTestData.Subject(artifacts:
                [new(EvidenceTestData.Artifact("orchestrator-x64"), EvidenceArchitecture.LinuxArm64, EvidenceTestData.D(5)), new(EvidenceTestData.Artifact("orchestrator-arm64"), EvidenceArchitecture.LinuxX64, EvidenceTestData.D(6))])),
            new("artifact-digest", EvidenceTestData.Subject(artifacts: Artifacts(x64Digest: 25))),
            new("suite-id", EvidenceTestData.Subject(suites: [EvidenceTestData.SuiteResult(suite: EvidenceTestData.Suite("control-b"))])),
            new("suite-domain", EvidenceTestData.Subject(suites: [storageSuite], models: [storageModel]), EvidenceTestData.Policy(domains: [EvidenceDomain.Storage])),
            new("suite-tests", EvidenceTestData.Subject(suites: [EvidenceTestData.SuiteResult(tests: EvidenceTestData.C(101))])),
            new("suite-properties", EvidenceTestData.Subject(suites: [EvidenceTestData.SuiteResult(properties: EvidenceTestData.C(1001))])),
            new("suite-branch", EvidenceTestData.Subject(suites: [EvidenceTestData.SuiteResult(branch: EvidenceTestData.P(91))])),
            new("suite-mutation", EvidenceTestData.Subject(suites: [EvidenceTestData.SuiteResult(mutation: EvidenceTestData.P(86))])),
            new("suite-schedules", EvidenceTestData.Subject(suites: [EvidenceTestData.SuiteResult(schedules: EvidenceTestData.C(10001))])),
            new("suite-seeds", EvidenceTestData.Subject(suites: [EvidenceTestData.SuiteResult(seeds: EvidenceTestData.C(101))])),
            new("suite-flakes", EvidenceTestData.Subject(suites: [EvidenceTestData.SuiteResult(flakes: EvidenceTestData.C(11))])),
            new("suite-model-count", EvidenceTestData.Subject(suites: [EvidenceTestData.SuiteResult(), storageSuite],
                models: [new(EvidenceDomain.Control, EvidenceTestData.Corpus("model"), EvidenceTestData.D(9)), storageModel]),
                EvidenceTestData.Policy(domains: [EvidenceDomain.Control, EvidenceDomain.Storage])),
            new("trace-id", EvidenceTestData.Subject(trace: Trace(id: "trace-b"))),
            new("trace-digest", EvidenceTestData.Subject(trace: Trace(digest: 26))),
            new("trace-requirements", EvidenceTestData.Subject(trace: Trace(requirements: 21))),
            new("trace-invariants", EvidenceTestData.Subject(trace: Trace(invariants: 11))),
            new("trace-errors", EvidenceTestData.Subject(trace: Trace(errors: 6))),
            new("trace-transitions", EvidenceTestData.Subject(trace: Trace(transitions: 9))),
            new("fuzz-target", EvidenceTestData.Subject(fuzz: [Fuzz(target: "manifest-b")])),
            new("fuzz-corpus", EvidenceTestData.Subject(fuzz: [Fuzz(corpus: "corpus-b")])),
            new("fuzz-digest", EvidenceTestData.Subject(fuzz: [Fuzz(digest: 27)])),
            new("fuzz-duration", EvidenceTestData.Subject(fuzz: [Fuzz(duration: 61)])),
            new("fuzz-cases", EvidenceTestData.Subject(fuzz: [Fuzz(cases: 10001)])),
            new("fuzz-count", EvidenceTestData.Subject(fuzz: [Fuzz(), Fuzz(target: "manifest-b", corpus: "corpus-b", digest: 27)])),
            new("model-corpus", EvidenceTestData.Subject(models: [new(EvidenceDomain.Control, EvidenceTestData.Corpus("model-b"), EvidenceTestData.D(9))])),
            new("model-digest", EvidenceTestData.Subject(models: [new(EvidenceDomain.Control, EvidenceTestData.Corpus("model"), EvidenceTestData.D(28))])),
            new("l0c-id", EvidenceTestData.Subject(l0c: new(EvidenceTestData.L0C("nats-b"), EvidenceTestData.D(10), EvidenceResult.Passed))),
            new("l0c-digest", EvidenceTestData.Subject(l0c: new(EvidenceTestData.L0C(), EvidenceTestData.D(29), EvidenceResult.Passed))),
            new("toolchain", EvidenceTestData.Subject(toolchain: EvidenceTestData.D(30))),
            new("approver", EvidenceTestData.Subject(approver: EvidenceTestData.Approver("owner-b"))),
            new("reuse-execution-and-proof", EvidenceTestData.Subject(execution: EvidenceExecutionKind.ContentAddressedReuse,
                reuseProof: new(reuse, reuse, EvidenceChangeKind.ShardOnly)), EvidenceTestData.Policy(cold: false)),
            ReuseVariant("reuse-source", reuse with { Source = EvidenceTestData.D(41) }),
            ReuseVariant("reuse-contracts", reuse with { TransitiveContracts = EvidenceTestData.D(42) }),
            ReuseVariant("reuse-tests", reuse with { Tests = EvidenceTestData.D(43) }),
            ReuseVariant("reuse-corpus", reuse with { Corpus = EvidenceTestData.D(44) }),
            ReuseVariant("reuse-dependencies", reuse with { Dependencies = EvidenceTestData.D(45) }),
            ReuseVariant("reuse-generators", reuse with { Generators = EvidenceTestData.D(46) }),
            ReuseVariant("reuse-schemas", reuse with { Schemas = EvidenceTestData.D(47) }),
            ReuseVariant("reuse-toolchain", reuse with { Toolchain = EvidenceTestData.D(48) }),
            new("reuse-change", EvidenceTestData.Subject(execution: EvidenceExecutionKind.ContentAddressedReuse,
                reuseProof: new(reuse, reuse, EvidenceChangeKind.None)), EvidenceTestData.Policy(cold: false)),
            new("exclusion-id", EvidenceTestData.Subject(exclusions: [new(EvidenceTestData.Exclusion("generated-b"), EvidenceExclusionKind.GeneratedCode)]),
                EvidenceTestData.Policy(exclusions: [EvidenceTestData.Exclusion("generated-b")])),
            new("exclusion-kind", EvidenceTestData.Subject(exclusions: [new(EvidenceTestData.Exclusion(), EvidenceExclusionKind.TrivialWiring)]),
                EvidenceTestData.Policy(exclusions: [EvidenceTestData.Exclusion()])),
            new("exclusion-count", EvidenceTestData.Subject(exclusions:
                [new(EvidenceTestData.Exclusion(), EvidenceExclusionKind.GeneratedCode), new(EvidenceTestData.Exclusion("trivial"), EvidenceExclusionKind.TrivialWiring)]),
                EvidenceTestData.Policy(exclusions: [EvidenceTestData.Exclusion(), EvidenceTestData.Exclusion("trivial")])),
        ];
    }

    private static EvidenceDecision Gate(EvidenceSubject subject, EvidencePolicy? policy = null)
    {
        var payload = EvidenceTestData.D(20);
        return EvidenceTestData.Gate(manifest: EvidenceTestData.Manifest(subject, payload: payload), policy: policy,
            context: EvidenceTestData.Context(subject: subject, payload: payload));
    }

    private static EvidenceArchitectureArtifact[] Artifacts(string x64Id = "orchestrator-x64", byte x64Digest = 5) =>
        [new(EvidenceTestData.Artifact(x64Id), EvidenceArchitecture.LinuxX64, EvidenceTestData.D(x64Digest)),
            new(EvidenceTestData.Artifact("orchestrator-arm64"), EvidenceArchitecture.LinuxArm64, EvidenceTestData.D(6))];

    private static EvidenceRequirementTrace Trace(string id = "trace", byte digest = 7, ulong requirements = 20,
        ulong invariants = 10, ulong errors = 5, ulong transitions = 8) =>
        new(EvidenceTestData.Trace(id), EvidenceTestData.D(digest), EvidenceTestData.C(requirements),
            EvidenceTestData.C(invariants), EvidenceTestData.C(errors), EvidenceTestData.C(transitions));

    private static EvidenceFuzzResult Fuzz(string target = "manifest", string corpus = "corpus", byte digest = 8,
        ulong duration = 60, ulong cases = 10000) => new(EvidenceTestData.FuzzTarget(target), EvidenceTestData.Corpus(corpus),
        EvidenceTestData.D(digest), EvidenceTestData.T(duration), EvidenceTestData.C(cases), EvidenceResult.Passed);

    private static AcceptedVariant ReuseVariant(string name, EvidenceReuseFingerprint fingerprint) => new(name,
        EvidenceTestData.Subject(execution: EvidenceExecutionKind.ContentAddressedReuse,
            reuseProof: new(fingerprint, fingerprint, EvidenceChangeKind.ShardOnly)), EvidenceTestData.Policy(cold: false));

    private static EvidenceSubject PermutedSubject(bool reverse, out MutableSources sources)
    {
        var binaries = new EvidenceTestBinary?[] { new(EvidenceTestData.Binary("binary-a"), EvidenceTestData.D(31)), new(EvidenceTestData.Binary("binary-b"), EvidenceTestData.D(32)) };
        var artifacts = Artifacts();
        var suites = new[] { EvidenceTestData.SuiteResult(), EvidenceTestData.SuiteResult(EvidenceDomain.Storage) };
        var fuzz = new[] { Fuzz(target: "fuzz-a", corpus: "fuzz-corpus-a"), Fuzz(target: "fuzz-b", corpus: "fuzz-corpus-b", digest: 9) };
        var models = new[] { new EvidenceModelCorpus(EvidenceDomain.Control, EvidenceTestData.Corpus("model-a"), EvidenceTestData.D(10)),
            new EvidenceModelCorpus(EvidenceDomain.Storage, EvidenceTestData.Corpus("model-b"), EvidenceTestData.D(11)) };
        var exclusions = new[] { new EvidenceExclusion(EvidenceTestData.Exclusion("generated"), EvidenceExclusionKind.GeneratedCode),
            new EvidenceExclusion(EvidenceTestData.Exclusion("trivial"), EvidenceExclusionKind.TrivialWiring) };
        sources = new(binaries, artifacts, suites, fuzz, models, exclusions);
        return EvidenceTestData.Subject(binaries: reverse ? binaries.Reverse() : binaries,
            artifacts: reverse ? artifacts.Reverse() : artifacts, suites: reverse ? suites.Reverse() : suites,
            fuzz: reverse ? fuzz.Reverse() : fuzz, models: reverse ? models.Reverse() : models,
            exclusions: reverse ? exclusions.Reverse() : exclusions);
    }

    private static EvidencePolicy PermutationPolicy() => EvidenceTestData.Policy(domains: [EvidenceDomain.Control, EvidenceDomain.Storage],
        exclusions: [EvidenceTestData.Exclusion("generated"), EvidenceTestData.Exclusion("trivial")]);

    private static T UnderCulture<T>(string culture, Func<T> action)
    {
        var original = CultureInfo.CurrentCulture;
        var originalUi = CultureInfo.CurrentUICulture;
        try { CultureInfo.CurrentCulture = new(culture); CultureInfo.CurrentUICulture = new(culture); return action(); }
        finally { CultureInfo.CurrentCulture = original; CultureInfo.CurrentUICulture = originalUi; }
    }

    private static string Route(MethodInfo method) => $"{method.DeclaringType!.Name}.{method.Name}({string.Join(',', method.GetParameters().Select(parameter => TypeName(parameter.ParameterType)))})->{TypeName(method.ReturnType)}";
    private static string TypeName(Type type) => type.IsGenericType
        ? $"{type.Name[..type.Name.IndexOf('`')]}<{string.Join(',', type.GetGenericArguments().Select(TypeName))}>"
        : type.Name;

    private sealed record AcceptedVariant(string Name, EvidenceSubject Subject, EvidencePolicy? Policy = null);
    private sealed record MutableSources(EvidenceTestBinary?[] Binaries, EvidenceArchitectureArtifact[] Artifacts,
        EvidenceSuiteResult[] Suites, EvidenceFuzzResult[] Fuzz, EvidenceModelCorpus[] Models, EvidenceExclusion[] Exclusions);
}
