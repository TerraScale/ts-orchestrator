using System.Collections;
using System.Globalization;
using System.Reflection;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Security;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class SecurityPolicyCompletenessPropertyTests
{
    private const int Cases = 1000;
    private static readonly (SecurityDecisionCode, SecurityDecisionOutcome)[][] EnrollmentNonPass =
    [
        [], [(SecurityDecisionCode.AttestationCurrent, SecurityDecisionOutcome.Held)],
        [(SecurityDecisionCode.EvidenceComplete, SecurityDecisionOutcome.Held), (SecurityDecisionCode.EvidenceUnique, SecurityDecisionOutcome.Held)],
        [(SecurityDecisionCode.EvidenceComplete, SecurityDecisionOutcome.Held), (SecurityDecisionCode.EvidenceUnique, SecurityDecisionOutcome.Held), (SecurityDecisionCode.EvidenceConsistent, SecurityDecisionOutcome.Held)],
        Reject(SecurityDecisionCode.OperationMatches), Reject(SecurityDecisionCode.PrincipalMatches), Reject(SecurityDecisionCode.CellMatches),
        Reject(SecurityDecisionCode.RoleMatches), Reject(SecurityDecisionCode.GenerationCurrent), Reject(SecurityDecisionCode.AttestationCurrent),
        Reject(SecurityDecisionCode.BootstrapUnused), Reject(SecurityDecisionCode.IssuerCurrent), Reject(SecurityDecisionCode.RevocationCurrent), Reject(SecurityDecisionCode.IssuerScopeValid),
        Reject(SecurityDecisionCode.SubjectKeyMatches),
        [.. Reject(SecurityDecisionCode.SubjectKeyMatches), .. Hold(SecurityDecisionCode.AttestationCurrent)],
        Reject(SecurityDecisionCode.GenerationCurrent), Reject(SecurityDecisionCode.GenerationCurrent),
        [.. Reject(SecurityDecisionCode.GenerationCurrent), .. Hold(SecurityDecisionCode.AttestationCurrent)],
    ];
    private static readonly SecurityDecisionCode[] EnrollmentReasonOrder =
    [
        SecurityDecisionCode.EvidenceComplete, SecurityDecisionCode.EvidenceUnique, SecurityDecisionCode.EvidenceConsistent,
        SecurityDecisionCode.OperationMatches, SecurityDecisionCode.PrincipalMatches, SecurityDecisionCode.SubjectKeyMatches,
        SecurityDecisionCode.CellMatches, SecurityDecisionCode.RoleMatches, SecurityDecisionCode.GenerationCurrent,
        SecurityDecisionCode.AttestationCurrent, SecurityDecisionCode.BootstrapUnused, SecurityDecisionCode.IssuerScopeValid,
        SecurityDecisionCode.IssuerCurrent, SecurityDecisionCode.RevocationCurrent,
    ];
    private static readonly (SecurityDecisionCode, SecurityDecisionOutcome)[][] CertificateNonPass =
    [
        [], [], [], [], Reject(SecurityDecisionCode.RevocationCurrent), Reject(SecurityDecisionCode.GenerationCurrent),
        Reject(SecurityDecisionCode.CellMatches), Reject(SecurityDecisionCode.ValidityEvidenceExact), Reject(SecurityDecisionCode.IssuerScopeValid),
        Reject(SecurityDecisionCode.IssuerCurrent), Reject(SecurityDecisionCode.PolicyCurrent), Reject(SecurityDecisionCode.UsageAllowed),
        Reject(SecurityDecisionCode.ValidityAllowsAction), Reject(SecurityDecisionCode.CompromiseProven), Reject(SecurityDecisionCode.IssuerScopeValid), [],
    ];
    private static readonly (SecurityDecisionCode, SecurityDecisionOutcome)[][] AuthorizationNonPass =
    [
        [], Hold(SecurityDecisionCode.EvidenceComplete),
        [.. Hold(SecurityDecisionCode.EvidenceComplete), .. Hold(SecurityDecisionCode.EvidenceUnique)],
        [.. Hold(SecurityDecisionCode.EvidenceComplete), .. Hold(SecurityDecisionCode.EvidenceUnique), .. Hold(SecurityDecisionCode.EvidenceConsistent)],
        Reject(SecurityDecisionCode.PrincipalMatches), Reject(SecurityDecisionCode.GenerationCurrent), Reject(SecurityDecisionCode.RevocationCurrent),
        Reject(SecurityDecisionCode.PolicyCurrent), Reject(SecurityDecisionCode.ExactGrantPresent), Reject(SecurityDecisionCode.PrivilegeBounded),
    ];
    private static readonly (SecurityDecisionCode, SecurityDecisionOutcome)[][] LeaseNonPass =
    [
        [], [], [], Hold(SecurityDecisionCode.SecretAvailable), Reject(SecurityDecisionCode.SecretVersionRetained),
        [.. Reject(SecurityDecisionCode.PolicyCurrent), .. Reject(SecurityDecisionCode.ExactGrantPresent)],
        Reject(SecurityDecisionCode.GenerationCurrent), Reject(SecurityDecisionCode.RevocationCurrent), Reject(SecurityDecisionCode.ExactGrantPresent),
        Reject(SecurityDecisionCode.LeaseExact), Reject(SecurityDecisionCode.LeaseValidityAllowsAction), Reject(SecurityDecisionCode.LeaseValidityAllowsAction),
    ];
    private static readonly (SecurityDecisionCode, SecurityDecisionOutcome)[][] SurvivalNonPass =
    [
        [], Hold(SecurityDecisionCode.EvidenceUnique),
        [.. Hold(SecurityDecisionCode.EvidenceUnique), .. Reject(SecurityDecisionCode.SurvivalReferencesExact)],
        [.. Hold(SecurityDecisionCode.EvidenceUnique), .. Reject(SecurityDecisionCode.SurvivalReferencesExact)],
        Reject(SecurityDecisionCode.SurvivalReferencesExact), Reject(SecurityDecisionCode.SurvivalReferencesExact),
        Reject(SecurityDecisionCode.SurvivalReferencesExact), Reject(SecurityDecisionCode.SurvivalReferencesExact),
        Reject(SecurityDecisionCode.SurvivalReferencesExact), Reject(SecurityDecisionCode.SurvivalReferencesExact), Reject(SecurityDecisionCode.SurvivalReferencesExact),
        Reject(SecurityDecisionCode.BundleGenerationNotRollback),
    ];

    [Test]
    public async Task Enrollment_trust_scope_generation_and_single_use_precedence_hold_for_1000_cases()
    {
        var expected = new (bool Authorized, Type Intent, SecurityDecisionCode? Code, SecurityDecisionOutcome Outcome)[]
        {
            (true, typeof(IssueIdentityIntent), null, 0),
            (true, typeof(AttestIdentityIntent), SecurityDecisionCode.AttestationCurrent, SecurityDecisionOutcome.Held),
            (false, typeof(HoldSecurityOperationIntent), SecurityDecisionCode.EvidenceUnique, SecurityDecisionOutcome.Held),
            (false, typeof(HoldSecurityOperationIntent), SecurityDecisionCode.EvidenceConsistent, SecurityDecisionOutcome.Held),
            (false, typeof(HoldSecurityOperationIntent), SecurityDecisionCode.OperationMatches, SecurityDecisionOutcome.Rejected),
            (false, typeof(HoldSecurityOperationIntent), SecurityDecisionCode.PrincipalMatches, SecurityDecisionOutcome.Rejected),
            (false, typeof(HoldSecurityOperationIntent), SecurityDecisionCode.CellMatches, SecurityDecisionOutcome.Rejected),
            (false, typeof(HoldSecurityOperationIntent), SecurityDecisionCode.RoleMatches, SecurityDecisionOutcome.Rejected),
            (false, typeof(HoldSecurityOperationIntent), SecurityDecisionCode.GenerationCurrent, SecurityDecisionOutcome.Rejected),
            (false, typeof(HoldSecurityOperationIntent), SecurityDecisionCode.AttestationCurrent, SecurityDecisionOutcome.Rejected),
            (false, typeof(HoldSecurityOperationIntent), SecurityDecisionCode.BootstrapUnused, SecurityDecisionOutcome.Rejected),
            (false, typeof(HoldSecurityOperationIntent), SecurityDecisionCode.IssuerCurrent, SecurityDecisionOutcome.Rejected),
            (false, typeof(HoldSecurityOperationIntent), SecurityDecisionCode.RevocationCurrent, SecurityDecisionOutcome.Rejected),
            (false, typeof(HoldSecurityOperationIntent), SecurityDecisionCode.IssuerScopeValid, SecurityDecisionOutcome.Rejected),
            (false, typeof(HoldSecurityOperationIntent), SecurityDecisionCode.SubjectKeyMatches, SecurityDecisionOutcome.Rejected),
            (false, typeof(HoldSecurityOperationIntent), SecurityDecisionCode.SubjectKeyMatches, SecurityDecisionOutcome.Rejected),
            (false, typeof(HoldSecurityOperationIntent), SecurityDecisionCode.GenerationCurrent, SecurityDecisionOutcome.Rejected),
            (false, typeof(HoldSecurityOperationIntent), SecurityDecisionCode.GenerationCurrent, SecurityDecisionOutcome.Rejected),
            (false, typeof(HoldSecurityOperationIntent), SecurityDecisionCode.GenerationCurrent, SecurityDecisionOutcome.Rejected),
        };
        var executed = 0; for (var seed = 1; seed <= Cases; seed++)
        {
            var variant = seed % expected.Length; var request = SecurityCompletenessData.Enrollment(variant, (ulong)seed);
            var decision = SecurityDecisionEngine.EvaluateEnrollment(request); var oracle = expected[variant];
            Require(decision.Authorized == oracle.Authorized && decision.Intent.GetType() == oracle.Intent, seed, "enrollment decision");
            RequireNonPass(decision, EnrollmentNonPass[variant], seed, "enrollment complete trace");
            Require(decision.Trace.Select(x => x.Code).SequenceEqual(variant is 2 or 3
                ? EnrollmentReasonOrder[..3]
                : EnrollmentReasonOrder), seed, "enrollment exact reason order");
            Require(decision.Intent.OperationId == request.OperationId, seed, "enrollment subject");
            if (decision.Intent is IssueIdentityIntent issue) Require(ReferenceEquals(issue.Request, request) &&
                ReferenceEquals(issue.Request.CurrentPrincipalGeneration, request.CurrentPrincipalGeneration) &&
                issue.Principal == request.ExpectedPrincipal && issue.Issuer == request.Issuer, seed, "identity intent binding");
            if (decision.Intent is AttestIdentityIntent attest) Require(ReferenceEquals(attest.Request, request) &&
                ReferenceEquals(attest.Request.CurrentPrincipalGeneration, request.CurrentPrincipalGeneration) &&
                attest.AttestationId == request.Attestations.Single().Id, seed, "attestation intent binding");
            if (oracle.Code is { } code) Require(Outcome(decision, code) == oracle.Outcome, seed, "enrollment trace");
            if (variant == 0) Require(decision.Trace.All(x => x.Outcome == SecurityDecisionOutcome.Passed), seed, "enrollment accepted trace");
            if (variant == 1) Require(decision.Trace.Count(x => x.Outcome == SecurityDecisionOutcome.Held) == 1 &&
                decision.Trace.All(x => x.Outcome is SecurityDecisionOutcome.Passed or SecurityDecisionOutcome.Held), seed, "attestation trace");
            if (variant is 14 or 15) Require(decision.Intent is HoldSecurityOperationIntent &&
                decision.Intent is not IssueIdentityIntent && decision.Intent is not AttestIdentityIntent, seed, "subject-key substitution denied");
            if (variant is 16 or 17 or 18) Require(decision.Intent is HoldSecurityOperationIntent &&
                decision.Intent is not IssueIdentityIntent && decision.Intent is not AttestIdentityIntent, seed, "coherent generation replay denied");
            Require(Canonical(decision) == Canonical(SecurityDecisionEngine.EvaluateEnrollment(SecurityCompletenessData.Enrollment(variant, (ulong)seed))), seed, "enrollment replay");
            executed++;
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Certificate_action_scope_expiry_and_revocation_precedence_hold_for_1000_cases()
    {
        var accepted = new[] { typeof(IssueCertificateIntent), typeof(RenewCertificateIntent), typeof(RotateCertificateIntent), typeof(RevokeCertificateIntent) };
        var rejectionCodes = new[] { SecurityDecisionCode.RevocationCurrent, SecurityDecisionCode.GenerationCurrent, SecurityDecisionCode.CellMatches,
            SecurityDecisionCode.ValidityEvidenceExact, SecurityDecisionCode.IssuerScopeValid, SecurityDecisionCode.IssuerCurrent,
            SecurityDecisionCode.PolicyCurrent, SecurityDecisionCode.UsageAllowed, SecurityDecisionCode.ValidityAllowsAction, SecurityDecisionCode.CompromiseProven,
            SecurityDecisionCode.IssuerScopeValid };
        var executed = 0; for (var seed = 1; seed <= Cases; seed++)
        {
            var variant = seed % 16; var request = SecurityCompletenessData.Certificate(variant, (ulong)seed);
            var decision = SecurityDecisionEngine.EvaluateCertificate(request);
            RequireNonPass(decision, CertificateNonPass[variant], seed, "certificate complete trace");
            if (variant < 4 || variant == 15) Require(decision.Authorized && decision.Intent.GetType() == (variant == 15 ? typeof(RenewCertificateIntent) : accepted[variant]), seed, "certificate action");
            else Require(!decision.Authorized && decision.Intent is HoldSecurityOperationIntent &&
                Outcome(decision, rejectionCodes[variant - 4]) == SecurityDecisionOutcome.Rejected, seed, "certificate rejection");
            Require(decision.Intent.OperationId == request.OperationId, seed, "certificate subject");
            if (decision.Authorized) Require(CertificateRequest(decision.Intent) == request, seed, "certificate intent binding");
            if (variant < 4 || variant == 15) Require(decision.Trace.All(x => x.Outcome is SecurityDecisionOutcome.Passed or SecurityDecisionOutcome.NotApplicable), seed, "certificate accepted trace");
            if (variant == 14) Require(decision.Trace.Count(x => x.Outcome is SecurityDecisionOutcome.Rejected or SecurityDecisionOutcome.Held) == 1 &&
                Outcome(decision, SecurityDecisionCode.IssuerScopeValid) == SecurityDecisionOutcome.Rejected, seed, "global issuer cell scope precedence");
            executed++;
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Mutation_authorization_is_exact_default_deny_and_precedence_stable_for_1000_cases()
    {
        var codes = new[] { SecurityDecisionCode.EvidenceComplete, SecurityDecisionCode.EvidenceUnique, SecurityDecisionCode.EvidenceConsistent,
            SecurityDecisionCode.PrincipalMatches, SecurityDecisionCode.GenerationCurrent, SecurityDecisionCode.RevocationCurrent,
            SecurityDecisionCode.PolicyCurrent, SecurityDecisionCode.ExactGrantPresent, SecurityDecisionCode.PrivilegeBounded };
        var executed = 0; for (var seed = 1; seed <= Cases; seed++)
        {
            var variant = seed % 10; var request = SecurityCompletenessData.Authorization(variant, (ulong)seed);
            var decision = SecurityDecisionEngine.Authorize(request);
            RequireNonPass(decision, AuthorizationNonPass[variant], seed, "authorization complete trace");
            if (variant == 0)
            {
                Require(decision.Authorized && decision.Intent is AuthorizeCapabilityIntent,seed,"authorization intent");
                var intent=(AuthorizeCapabilityIntent)decision.Intent;
                Require(intent.PrincipalId == request.PrincipalId && intent.Capability == request.Capability &&
                    intent.ResourceScope == request.ResourceScope, seed, "authorization subject");
                Require(intent.Evidence == request.PrincipalEvidence[0] && intent.Grant == request.Grants[0] &&
                    intent.ExpectedPrincipalGeneration == request.ExpectedPrincipalGeneration &&
                    intent.CurrentPrincipalGeneration == request.CurrentPrincipalGeneration &&
                    intent.PolicyGeneration == request.PolicyGeneration && intent.CurrentPolicyGeneration == request.CurrentPolicyGeneration &&
                    intent.CurrentRevocationGeneration == request.CurrentRevocationGeneration,seed,"authorization provenance");
                Require(decision.Trace.All(x => x.Outcome == SecurityDecisionOutcome.Passed), seed, "authorization accepted trace");
            }
            else
            {
                var outcome = Outcome(decision, codes[variant - 1]);
                Require(!decision.Authorized && decision.Intent is HoldSecurityOperationIntent && outcome is SecurityDecisionOutcome.Rejected or SecurityDecisionOutcome.Held,
                    seed, "authorization deny");
            }
            executed++;
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Lease_generation_expiry_revocation_and_revoke_precedence_hold_for_1000_cases()
    {
        var codes = new[] { SecurityDecisionCode.SecretAvailable, SecurityDecisionCode.SecretVersionRetained, SecurityDecisionCode.PolicyCurrent,
            SecurityDecisionCode.GenerationCurrent, SecurityDecisionCode.RevocationCurrent, SecurityDecisionCode.ExactGrantPresent,
            SecurityDecisionCode.LeaseExact, SecurityDecisionCode.LeaseValidityAllowsAction, SecurityDecisionCode.LeaseValidityAllowsAction };
        var executed = 0; for (var seed = 1; seed <= Cases; seed++)
        {
            var variant = seed % 12; var request = SecurityCompletenessData.Lease(variant, (ulong)seed);
            var decision = SecurityDecisionEngine.EvaluateLease(request);
            RequireNonPass(decision, LeaseNonPass[variant], seed, "lease complete trace");
            if (variant < 3)
            {
                var types = new[] { typeof(GrantSecretLeaseIntent), typeof(RenewSecretLeaseIntent), typeof(RevokeSecretLeaseIntent) };
                Require(decision.Authorized && decision.Intent.GetType() == types[variant], seed, "lease action");
                Require(LeaseRequest(decision.Intent) == request, seed, "lease intent binding");
                Require(decision.Trace.All(x => x.Outcome is SecurityDecisionOutcome.Passed or SecurityDecisionOutcome.NotApplicable), seed, "lease accepted trace");
                if (variant == 2) Require(Outcome(decision, SecurityDecisionCode.SecretAvailable) == SecurityDecisionOutcome.NotApplicable &&
                    Outcome(decision, SecurityDecisionCode.SecretVersionRetained) == SecurityDecisionOutcome.NotApplicable &&
                    Outcome(decision, SecurityDecisionCode.PolicyCurrent) == SecurityDecisionOutcome.NotApplicable, seed, "revoke precedence");
            }
            else
            {
                Require(!decision.Authorized && Outcome(decision, codes[variant - 3]) is SecurityDecisionOutcome.Rejected or SecurityDecisionOutcome.Held,
                    seed, "lease deny");
            }
            Require(decision.Intent.OperationId == request.OperationId, seed, "lease subject");
            executed++;
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Survival_secret_scope_retention_digest_and_availability_hold_for_1000_cases()
    {
        var executed = 0; for (var seed = 1; seed <= Cases; seed++)
        {
            var variant = seed % 12; var request = SecurityCompletenessData.Survival(variant, (ulong)seed);
            var decision = SecurityDecisionEngine.EvaluateSurvivalSecrets(request);
            RequireNonPass(decision, SurvivalNonPass[variant], seed, "survival complete trace");
            if (variant == 0)
                Require(decision.Authorized && decision.Intent is AcceptSurvivalSecretReferencesIntent accepted && accepted.Request == request,
                    seed, "survival accept");
            else
            {
                var code = variant <= 3 ? SecurityDecisionCode.EvidenceUnique :
                    variant == 11 ? SecurityDecisionCode.BundleGenerationNotRollback : SecurityDecisionCode.SurvivalReferencesExact;
                var outcome = variant <= 3 ? SecurityDecisionOutcome.Held : SecurityDecisionOutcome.Rejected;
                Require(!decision.Authorized && Outcome(decision, code) == outcome, seed, "survival deny");
            }
            Require(decision.Intent.OperationId == request.OperationId && !Canonical(decision).Contains("plaintext", StringComparison.OrdinalIgnoreCase), seed, "survival subject");
            if (variant == 0) Require(decision.Trace.All(x => x.Outcome == SecurityDecisionOutcome.Passed), seed, "survival accepted trace");
            Require(decision.Trace.Select(x => x.Code).SequenceEqual([
                SecurityDecisionCode.EvidenceUnique,
                SecurityDecisionCode.SurvivalReferencesExact,
                SecurityDecisionCode.BundleGenerationNotRollback]), seed, "survival exact reason order");
            executed++;
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Security_decisions_are_permutation_culture_and_replay_stable_for_1000_cases()
    {
        var cultures = new[] { "tr-TR", "ar-SA", "ja-JP" };
        var executed = 0; for (var seed = 1; seed <= Cases; seed++)
        {
            var baseline = UnderCulture("en-US", () => CultureFingerprint((ulong)seed, reverse: false));
            var alternate = UnderCulture(cultures[seed % cultures.Length], () => CultureFingerprint((ulong)seed, reverse: true));
            Require(baseline == alternate, seed, "cross-culture permutation replay");
            executed++;
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Caller_enumerables_are_bounded_before_extra_current_and_fatal_failures_propagate()
    {
        var baseline = SecurityCompletenessData.Enrollment(0, 1);
        var endless = new ProbeEnumerable<BootstrapEnrollmentEvidence>(baseline.BootstrapEvidence[0]);
        await Assert.That(Fails<ArgumentException>(() => CopyEnrollment(baseline, endless))).IsTrue();
        await Assert.That(endless.CurrentReads).IsEqualTo(SecurityTechnicalLimits.MaximumCapturedItems);
        await Assert.That(endless.DisposeCalls).IsEqualTo(1);
        foreach (var phase in Enum.GetValues<EnumerableFailurePhase>())
        {
            var error = Catch<ArgumentException>(() => CopyEnrollment(baseline, new ThrowingEnumerable<BootstrapEnrollmentEvidence>(phase, new InvalidOperationException("sensitive-marker"))));
            await Assert.That(error).IsNotNull();
            await Assert.That(error!.Message).DoesNotContain("sensitive-marker");
        }
        foreach (var phase in Enum.GetValues<EnumerableFailurePhase>())
            foreach (var fatal in new Exception[] { new OutOfMemoryException(), new StackOverflowException(), new AccessViolationException() })
                await Assert.That(Fails(fatal.GetType(), () => CopyEnrollment(baseline, new ThrowingEnumerable<BootstrapEnrollmentEvidence>(phase, fatal)))).IsTrue();
    }

    [Test]
    public async Task Accepted_outputs_remain_construction_closed_and_strict_seed_sensitive_corpus_replays()
    {
        await Assert.That(typeof(SecurityDecision).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(SecurityIntent).Assembly.GetTypes().Where(t => typeof(SecurityIntent).IsAssignableFrom(t))
            .SelectMany(t => t.GetConstructors(BindingFlags.Public | BindingFlags.Instance))).IsEmpty();
        var entries = SecurityPolicyReplayCorpus.Load();
        foreach (var entry in entries)
        {
            var input = SecurityCompletenessData.InputFingerprint(entry.Kind, entry.Variant, entry.Seed);
            var output = SecurityCompletenessData.OutputFingerprint(SecurityCompletenessData.Decide(entry.Kind, entry.Variant, entry.Seed));
            Require(input == entry.Input && output == entry.Output, checked((int)entry.Seed), entry.Id);
        }
        foreach (var kind in new[] { "enrollment", "certificate", "authorization", "lease", "survival" })
        {
            const ulong seed = 777;
            var exactInput = SecurityCompletenessData.InputFingerprint(kind, 0, seed);
            var mutatedInput = SecurityCompletenessData.InputFingerprint(kind, kind == "survival" ? 6 : 4, seed);
            var exactOutput = SecurityCompletenessData.OutputFingerprint(SecurityCompletenessData.Decide(kind, 0, seed));
            var mutatedOutput = SecurityCompletenessData.OutputFingerprint(SecurityCompletenessData.Decide(kind, kind == "survival" ? 6 : 4, seed));
            Require(exactInput != mutatedInput && exactOutput != mutatedOutput, (int)seed, kind + " same-seed mutation sensitivity");
        }
        await Assert.That(entries.Count).IsEqualTo(13);
        await Assert.That(entries.Where(entry => entry.Kind == "enrollment" && entry.Variant is 16 or 17 or 18)
            .Select(entry => entry.Variant)).IsEquivalentTo(new[] { 16, 17, 18 });
    }

    [Test]
    public async Task Replay_parser_rejects_unknown_duplicate_unbounded_and_noncanonical_input()
    {
        await Assert.That(SecurityPolicyReplayCorpus.ReadBounded(new MemoryStream(new byte[32768])).Length).IsEqualTo(32768);
        await Assert.That(Fails<InvalidDataException>(() => SecurityPolicyReplayCorpus.ReadBounded(new MemoryStream(new byte[32769])))).IsTrue();
        var invalid = new[]
        {
            "{}", "{\"schema\":\"terrascale.security-policy-replay.v1\",\"entries\":[],\"extra\":1}",
            "{\"schema\":\"terrascale.security-policy-replay.v1\",\"entries\":[{\"id\":\"x\",\"id\":\"y\",\"seed\":1,\"kind\":\"enrollment\",\"variant\":0,\"input\":\"i\",\"output\":\"o\"}]}",
            CorpusJson(EntryJson("x", seed: "0")), CorpusJson(EntryJson("x", seed: "-1")),
            CorpusJson(EntryJson("x", seed: "18446744073709551616")), CorpusJson(EntryJson("x", seed: "\"1\"")),
            CorpusJson(EntryJson("x"), EntryJson("x", seed: "2")), CorpusJson(EntryJson("x"), EntryJson("y")),
            CorpusJson(EntryJson("x", kind: "unknown")), CorpusJson(EntryJson("x", variant: "99")),
            CorpusJson(EntryJson("x", input: "")), CorpusJson(EntryJson("x", output: "")),
            CorpusJson(ExactEntryJson("x").Replace("\"input\":\"op=", "\"input\":\"wrong-op=", StringComparison.Ordinal)),
            CorpusJson(ExactEntryJson("x").Replace("\"output\":\"authorized=", "\"output\":\"wrong-authorized=", StringComparison.Ordinal)),
            CorpusJson(EntryJson("Upper")), CorpusJson(EntryJson("under_score")), CorpusJson(EntryJson("-leading")),
            CorpusJson(EntryJson("trailing-")), CorpusJson(EntryJson("double--hyphen")), CorpusJson(EntryJson(new string('a', 65))),
            "{/*comment*/\"schema\":\"terrascale.security-policy-replay.v1\",\"entries\":[]}",
            "{\"schema\":\"terrascale.security-policy-replay.v1\",\"entries\":[],}",
            "{\"schema\":\"terrascale.security-policy-replay.v1\",\"entries\":[]} trailing",
        };
        foreach (var json in invalid) await Assert.That(Fails<Exception>(() => SecurityPolicyReplayCorpus.Parse(Encoding.UTF8.GetBytes(json), false))).IsTrue();
    }

    private static EnrollmentRequest CopyEnrollment(EnrollmentRequest value, IEnumerable<BootstrapEnrollmentEvidence> evidence) => new(
        value.OperationId, value.ExpectedPrincipal, value.CurrentPrincipalGeneration, value.SubjectKeyId, value.AttestationPolicyGeneration, value.Issuer,
        value.CurrentIssuerGeneration, value.CurrentRevocationGeneration, evidence, value.Attestations);
    private static CertificateLifecycleRequest CertificateRequest(SecurityIntent intent) => intent switch
    {
        IssueCertificateIntent value => value.Request, RenewCertificateIntent value => value.Request,
        RotateCertificateIntent value => value.Request, RevokeCertificateIntent value => value.Request,
        _ => throw new InvalidOperationException("Certificate intent expected."),
    };
    private static SecretLeaseRequest LeaseRequest(SecurityIntent intent) => intent switch
    {
        GrantSecretLeaseIntent value => value.Request, RenewSecretLeaseIntent value => value.Request,
        RevokeSecretLeaseIntent value => value.Request, _ => throw new InvalidOperationException("Lease intent expected."),
    };
    private static SecurityDecisionOutcome Outcome(SecurityDecision decision, SecurityDecisionCode code) => decision.Trace.Single(x => x.Code == code).Outcome;
    private static (SecurityDecisionCode, SecurityDecisionOutcome)[] Reject(SecurityDecisionCode code) => [(code, SecurityDecisionOutcome.Rejected)];
    private static (SecurityDecisionCode, SecurityDecisionOutcome)[] Hold(SecurityDecisionCode code) => [(code, SecurityDecisionOutcome.Held)];
    private static void RequireNonPass(SecurityDecision decision, IReadOnlyList<(SecurityDecisionCode, SecurityDecisionOutcome)> expected, int seed, string property)
    {
        var actual = decision.Trace.Where(x => x.Outcome is SecurityDecisionOutcome.Rejected or SecurityDecisionOutcome.Held)
            .Select(x => (x.Code, x.Outcome)).ToArray();
        Require(actual.SequenceEqual(expected), seed, property + " expected=" + string.Join(',', expected) + " actual=" + string.Join(',', actual));
    }
    private static string CultureFingerprint(ulong seed, bool reverse)
    {
        var survival = SecurityCompletenessData.Survival(0, seed, reverse);
        var authorization = SecurityCompletenessData.ConflictingAuthorization(seed, reverse);
        return string.Join("||", Canonical(SecurityDecisionEngine.EvaluateEnrollment(SecurityCompletenessData.Enrollment((int)(seed % 19), seed))),
            Canonical(SecurityDecisionEngine.EvaluateCertificate(SecurityCompletenessData.Certificate((int)(seed % 16), seed))),
            Canonical(SecurityDecisionEngine.Authorize(authorization)), Canonical(SecurityDecisionEngine.EvaluateLease(SecurityCompletenessData.Lease((int)(seed % 12), seed))),
            Canonical(SecurityDecisionEngine.EvaluateSurvivalSecrets(survival)));
    }
    private static string UnderCulture(string name, Func<string> action)
    {
        var culture = CultureInfo.CurrentCulture; var uiCulture = CultureInfo.CurrentUICulture;
        try { CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(name); CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(name); return action(); }
        finally { CultureInfo.CurrentCulture = culture; CultureInfo.CurrentUICulture = uiCulture; }
    }
    private static string Canonical(SecurityDecision decision) => $"{decision.Authorized}|{decision.Intent.GetType().Name}|{decision.Intent.OperationId.Value}|" +
        string.Join(';', decision.Trace.Select(x => $"{x.Code}:{x.Outcome}:{x.Observed}:{x.Required}"));
    private static void Require(bool condition, int seed, string property) { if (!condition) throw new InvalidOperationException($"Property {property} failed at seed {seed}."); }
    private static bool Fails<T>(Action action) where T : Exception { try { action(); return false; } catch (T) { return true; } }
    private static bool Fails(Type type, Action action) { try { action(); return false; } catch (Exception exception) { return exception.GetType() == type; } }
    private static T? Catch<T>(Action action) where T : Exception { try { action(); return null; } catch (T exception) { return exception; } }
    private static string EntryJson(string id, string seed = "1", string kind = "enrollment", string variant = "0", string input = "i", string output = "o") =>
        $"{{\"id\":\"{id}\",\"seed\":{seed},\"kind\":\"{kind}\",\"variant\":{variant},\"input\":\"{input}\",\"output\":\"{output}\"}}";
    private static string ExactEntryJson(string id)
    {
        const string kind = "enrollment"; const int variant = 0; const ulong seed = 1;
        return EntryJson(id, seed.ToString(CultureInfo.InvariantCulture), kind, variant.ToString(CultureInfo.InvariantCulture),
            SecurityCompletenessData.InputFingerprint(kind, variant, seed),
            SecurityCompletenessData.OutputFingerprint(SecurityCompletenessData.Decide(kind, variant, seed)));
    }
    private static string CorpusJson(params string[] entries) => $"{{\"schema\":\"terrascale.security-policy-replay.v1\",\"entries\":[{string.Join(',', entries)}]}}";
}

internal enum EnumerableFailurePhase { GetEnumerator, MoveNext, Current, Dispose }

internal sealed class ProbeEnumerable<T>(T value) : IEnumerable<T>
{
    internal int CurrentReads { get; private set; }
    internal int DisposeCalls { get; private set; }
    public IEnumerator<T> GetEnumerator() => new Enumerator(this, value);
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    private sealed class Enumerator(ProbeEnumerable<T> owner, T value) : IEnumerator<T>
    {
        public T Current { get { owner.CurrentReads++; return value; } }
        object? IEnumerator.Current => Current;
        public bool MoveNext() => true;
        public void Reset() => throw new NotSupportedException();
        public void Dispose() => owner.DisposeCalls++;
    }
}

internal sealed class ThrowingEnumerable<T>(EnumerableFailurePhase phase, Exception exception) : IEnumerable<T>
{
    public IEnumerator<T> GetEnumerator() => phase == EnumerableFailurePhase.GetEnumerator ? throw exception : new Enumerator(phase, exception);
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    private sealed class Enumerator(EnumerableFailurePhase phase, Exception exception) : IEnumerator<T>
    {
        public T Current => phase == EnumerableFailurePhase.Current ? throw exception : default!;
        object? IEnumerator.Current => Current;
        public bool MoveNext() => phase == EnumerableFailurePhase.MoveNext ? throw exception : true;
        public void Reset() => throw new NotSupportedException();
        public void Dispose() { if (phase == EnumerableFailurePhase.Dispose) throw exception; }
    }
}
