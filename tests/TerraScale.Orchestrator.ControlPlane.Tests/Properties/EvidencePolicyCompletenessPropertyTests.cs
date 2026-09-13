using TerraScale.Orchestrator.ControlPlane.Evidence;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class EvidencePolicyCompletenessPropertyTests
{
    private const int Cases = 1_000;

    [Test]
    public async Task Every_declared_suite_must_meet_policy_floors_for_1000_independently_oracled_cases()
    {
        var observedModes = new HashSet<int>();
        for (var seed = 0; seed < Cases; seed++)
        {
            var mode = seed % 7;
            observedModes.Add(mode);
            var storage = mode switch
            {
                1 => EvidenceTestData.SuiteResult(EvidenceDomain.Storage, tests: EvidenceTestData.C(99)),
                2 => EvidenceTestData.SuiteResult(EvidenceDomain.Storage, properties: EvidenceTestData.C(999)),
                3 => EvidenceTestData.SuiteResult(EvidenceDomain.Storage, branch: EvidenceTestData.P(89)),
                4 => EvidenceTestData.SuiteResult(EvidenceDomain.Storage, mutation: EvidenceTestData.P(84)),
                5 => EvidenceTestData.SuiteResult(EvidenceDomain.Storage, schedules: EvidenceTestData.C(9_999)),
                6 => EvidenceTestData.SuiteResult(EvidenceDomain.Storage, flakes: EvidenceTestData.C(9)),
                _ => EvidenceTestData.SuiteResult(EvidenceDomain.Storage),
            };
            var suites = seed % 2 == 0
                ? new[] { EvidenceTestData.SuiteResult(), storage }
                : new[] { storage, EvidenceTestData.SuiteResult() };
            var models = seed % 3 == 0
                ? new[] { Model(EvidenceDomain.Storage, "storage"), Model(EvidenceDomain.Control, "control") }
                : new[] { Model(EvidenceDomain.Control, "control"), Model(EvidenceDomain.Storage, "storage") };
            var subject = EvidenceTestData.Subject(suites: suites, models: models);

            var result = EvidencePolicyEvaluator.Evaluate(
                EvidenceTestData.Manifest(subject),
                EvidenceTestData.Policy(domains: [EvidenceDomain.Control]));

            await Assert.That(result.Code).IsEqualTo(mode == 0 ? EvidenceCode.Allowed : EvidenceCode.ThresholdNotMet);
        }
        await Assert.That(observedModes.Count).IsEqualTo(7);
    }

    [Test]
    public async Task Suite_and_model_corpus_domain_inventories_must_match_for_1000_permuted_cases()
    {
        for (var seed = 0; seed < Cases; seed++)
        {
            var mode = seed % 5;
            var suites = mode switch
            {
                1 => new[] { EvidenceTestData.SuiteResult() },
                2 => new[] { EvidenceTestData.SuiteResult(), EvidenceTestData.SuiteResult(EvidenceDomain.Storage) },
                3 => new[] { EvidenceTestData.SuiteResult(EvidenceDomain.Storage), EvidenceTestData.SuiteResult() },
                _ => new[] { EvidenceTestData.SuiteResult(), EvidenceTestData.SuiteResult(EvidenceDomain.Storage) },
            };
            var models = mode switch
            {
                1 => new[] { Model(EvidenceDomain.Control, "control"), Model(EvidenceDomain.Storage, "storage") },
                2 => new[] { Model(EvidenceDomain.Control, "control") },
                3 => new[] { Model(EvidenceDomain.Storage, "storage") },
                _ => seed % 2 == 0
                    ? new[] { Model(EvidenceDomain.Control, "control"), Model(EvidenceDomain.Storage, "storage") }
                    : new[] { Model(EvidenceDomain.Storage, "storage"), Model(EvidenceDomain.Control, "control") },
            };
            var policyDomains = mode == 4
                ? new[] { EvidenceDomain.Control, EvidenceDomain.Storage, EvidenceDomain.Security }
                : new[] { EvidenceDomain.Control };

            var result = EvidencePolicyEvaluator.Evaluate(
                EvidenceTestData.Manifest(EvidenceTestData.Subject(suites: suites, models: models)),
                EvidenceTestData.Policy(domains: policyDomains));

            await Assert.That(result.Code).IsEqualTo(mode == 0 ? EvidenceCode.Allowed : EvidenceCode.MissingDomain);
        }
    }

    [Test]
    public async Task Gate_decision_and_numeric_trace_match_exact_independent_oracle_for_1000_cases()
    {
        for (var seed = 0; seed < Cases; seed++)
        {
            var mode = seed % 9;
            var generation = 1_000UL + (ulong)seed;
            var expiry = 4_000UL + (ulong)seed;
            var envelope = EvidenceTestData.Envelope(
                profile: mode == 1 ? EvidenceTestData.Profile("other") : null,
                signer: mode == 2 ? EvidenceTestData.Signer("other") : null,
                signatureId: mode == 3 ? EvidenceTestData.SignatureId("other") : null,
                generation: EvidenceTestData.G(mode == 4 ? generation - 1 : mode == 5 ? generation + 1 : generation),
                expiry: EvidenceTestData.Q(mode == 6 ? expiry - 1 : mode == 7 ? expiry + 1 : expiry));
            var context = EvidenceTestData.Context(
                generation: EvidenceTestData.G(generation),
                expectedExpiry: EvidenceTestData.Q(expiry),
                current: EvidenceTestData.Q(mode == 8 ? expiry + 1 : expiry));

            var decision = EvidenceTestData.Gate(envelope: envelope, context: context);
            var expected = mode switch
            {
                1 => EvidenceCode.WrongSigningProfile,
                2 => EvidenceCode.WrongSigningIdentity,
                3 => EvidenceCode.WrongSignature,
                4 => EvidenceCode.StaleGeneration,
                5 => EvidenceCode.FutureGeneration,
                6 => EvidenceCode.StaleExpiry,
                7 => EvidenceCode.FutureExpiry,
                8 => EvidenceCode.Expired,
                _ => EvidenceCode.Allowed,
            };

            await Assert.That(decision.Code).IsEqualTo(expected);
            await Assert.That(decision.Action).IsEqualTo(mode == 0 ? EvidenceAction.AllowL1SCredentialRelease : EvidenceAction.Hold);
            await Assert.That(decision.Subject is null).IsEqualTo(mode != 0);
            await Assert.That(decision.AuthorizationScope is null).IsEqualTo(mode != 0);
            await Assert.That(decision.IsAuthorized).IsEqualTo(mode == 0);
            if (mode == 0)
            {
                await Assert.That(decision.Subject).IsTypeOf<EvidenceDecisionSubject>();
                await Assert.That(decision.Subject!.PayloadDigest).IsEqualTo(envelope.Material.PayloadDigest);
                await Assert.That(decision.Subject.PayloadDigest).IsEqualTo(EvidenceTestData.D(20));
                var scope = decision.AuthorizationScope!;
                await Assert.That(scope.Manifest).IsEqualTo(EvidenceTestData.ManifestId());
                await Assert.That(scope.Lane).IsEqualTo(EvidenceLane.Full);
                await Assert.That(scope.Target).IsEqualTo(EvidenceGateTarget.L1SCredentialRelease);
                await Assert.That(scope.SigningProfile).IsEqualTo(envelope.Material.SigningProfile);
                await Assert.That(scope.SigningIdentity).IsEqualTo(envelope.Material.SigningIdentity);
                await Assert.That(scope.SignatureIdentity).IsEqualTo(envelope.Material.SignatureIdentity);
                await Assert.That(scope.Generation).IsEqualTo(envelope.Material.Generation);
                await Assert.That(scope.ExpirySequence).IsEqualTo(envelope.Material.ExpirySequence);
            }
            await Assert.That(decision.Trace).IsNotNull();
            await Assert.That(decision.Trace!.Generation.Value).IsEqualTo(envelope.Material.Generation.Value);
            await Assert.That(decision.Trace.CurrentSequence.Value).IsEqualTo(context.CurrentSequence.Value);
            await Assert.That(decision.Trace.ExpirySequence.Value).IsEqualTo(envelope.Material.ExpirySequence.Value);
            await Assert.That(decision.Trace.DomainCount).IsEqualTo(1UL);
            await Assert.That(decision.Trace.TestBinaryCount).IsEqualTo(1UL);
        }
    }

    private static EvidenceModelCorpus Model(EvidenceDomain domain, string id) =>
        new(domain, EvidenceTestData.Corpus(id), EvidenceTestData.D((byte)((int)domain + 20)));
}

