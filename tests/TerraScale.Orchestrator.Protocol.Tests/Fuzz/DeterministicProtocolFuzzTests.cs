using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Protocol.Tests.Fuzz;

public sealed class DeterministicProtocolFuzzTests
{
    private const int CasesPerFamily = 10_000;
    private const ulong NumericSeed = 0x11C0FFEEUL;
    private const ulong OpaqueSeed = 0x22C0FFEEUL;
    private const ulong SubjectSeed = 0x33C0FFEEUL;
    private const ulong PolicySeed = 0x44C0FFEEUL;
    private const ulong EnvelopeSeed = 0x55C0FFEEUL;
    private const ulong DecisionSeed = 0x66C0FFEEUL;

    [Test]
    public async Task NumericAndOpaqueFactoriesRunTenThousandDeterministicBoundedCasesPerFamily()
    {
        var numericFirst = RunNumeric(NumericSeed);
        var numericReplay = RunNumeric(NumericSeed);
        var opaqueFirst = RunOpaque(OpaqueSeed);
        var opaqueReplay = RunOpaque(OpaqueSeed);
        await Assert.That(numericFirst).IsEqualTo(numericReplay);
        await Assert.That(opaqueFirst).IsEqualTo(opaqueReplay);
        await Assert.That(numericFirst.Cases).IsEqualTo(CasesPerFamily);
        await Assert.That(numericFirst.Accepted).IsGreaterThan(0);
        await Assert.That(numericFirst.Rejected).IsGreaterThan(0);
        await Assert.That(numericFirst.Diversity).IsGreaterThan(5_000);
        await Assert.That(opaqueFirst.Cases).IsEqualTo(CasesPerFamily);
        await Assert.That(opaqueFirst.Accepted).IsGreaterThan(0);
        await Assert.That(opaqueFirst.Rejected).IsGreaterThan(0);
        await Assert.That(opaqueFirst.Diversity).IsGreaterThan(9_000);
    }

    [Test]
    public async Task SubjectAndPatternParsersRunTenThousandCasesCultureIndependently()
    {
        var original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new("tr-TR");
            var first = RunSubjects(SubjectSeed);
            CultureInfo.CurrentCulture = new("ar-SA");
            var replay = RunSubjects(SubjectSeed);
            await Assert.That(first).IsEqualTo(replay);
            await Assert.That(first.SubjectCases).IsEqualTo(CasesPerFamily);
            await Assert.That(first.PatternCases).IsEqualTo(CasesPerFamily);
            await Assert.That(first.SubjectAccepted).IsGreaterThan(1_000);
            await Assert.That(first.SubjectRejected).IsGreaterThan(1_000);
            await Assert.That(first.PatternAccepted).IsGreaterThan(1_000);
            await Assert.That(first.PatternRejected).IsGreaterThan(1_000);
            await Assert.That(first.SubjectErrors).IsEqualTo(6);
            await Assert.That(first.PatternErrors).IsEqualTo(5);
        }
        finally { CultureInfo.CurrentCulture = original; }
    }

    [Test]
    public async Task LimitAndPermissionPolicyValidatorsRunTenThousandPermutationStableCases()
    {
        var first = RunPolicies(PolicySeed);
        var replay = RunPolicies(PolicySeed);
        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(CasesPerFamily);
        await Assert.That(first.Accepted).IsGreaterThan(1_000);
        await Assert.That(first.Rejected).IsGreaterThan(1_000);
        await Assert.That(first.Reasons).IsEqualTo(5);
    }

    [Test]
    public async Task EnvelopeValidatorRunsTenThousandCasesFailClosedAndSecretSafe()
    {
        var original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new("tr-TR");
            var first = RunEnvelopes(EnvelopeSeed);
            CultureInfo.CurrentCulture = new("ar-SA");
            var replay = RunEnvelopes(EnvelopeSeed);
            await Assert.That(first).IsEqualTo(replay);
            await Assert.That(first.Cases).IsEqualTo(CasesPerFamily);
            await Assert.That(first.Accepted).IsGreaterThan(0);
            await Assert.That(first.Rejected).IsGreaterThan(5_000);
            await Assert.That(first.Errors).IsEqualTo(15);
        }
        finally { CultureInfo.CurrentCulture = original; }
    }

    [Test]
    public async Task PatternMatchingAndAuthorizationRunTenThousandExactDecisionCases()
    {
        var first = RunDecisions(DecisionSeed);
        var replay = RunDecisions(DecisionSeed);
        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(CasesPerFamily);
        await Assert.That(first.Allowed).IsGreaterThan(1_000);
        await Assert.That(first.Denied).IsGreaterThan(1_000);
        await Assert.That(first.Reasons).IsEqualTo(5);
    }

    [Test]
    public async Task PublicParserAndValidatorInventoryIsClosedAndRegistered()
    {
        var assembly = typeof(CommandEnvelope).Assembly;
        var discovered = assembly.GetExportedTypes().SelectMany(static type => type.GetMethods(
                BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Where(static method => method.Name is "TryCreate" or "TryParse" or "TryCopyFrom" or "CopyFrom" or "Validate")
            .Select(method => $"{type.FullName}.{method.Name}"))
            .OrderBy(static value => value, StringComparer.Ordinal).ToArray();
        var expected = new[]
        {
            "TerraScale.Orchestrator.Protocol.CommandEnvelopeValidator.Validate",
            "TerraScale.Orchestrator.Protocol.DeliveryAttempt.TryCreate",
            "TerraScale.Orchestrator.Protocol.DesiredGeneration.TryCreate",
            "TerraScale.Orchestrator.Protocol.OpaquePayload.CopyFrom",
            "TerraScale.Orchestrator.Protocol.OpaqueSignature.TryCopyFrom",
            "TerraScale.Orchestrator.Protocol.PayloadDigest.TryCopyFrom",
            "TerraScale.Orchestrator.Protocol.ProtocolRevision.TryCreate",
            "TerraScale.Orchestrator.Protocol.Subjects.ConcreteSubject.TryParse",
            "TerraScale.Orchestrator.Protocol.Subjects.SubjectGrammarLimits.TryCreate",
            "TerraScale.Orchestrator.Protocol.Subjects.SubjectPermissionPattern.TryParse",
            "TerraScale.Orchestrator.Protocol.Subjects.SubjectPermissionPolicy.TryCreate",
            "TerraScale.Orchestrator.Protocol.WriterEpoch.TryCreate",
        }.OrderBy(static value => value, StringComparer.Ordinal).ToArray();
        await Assert.That(discovered).IsEquivalentTo(expected);
        await Assert.That(assembly.GetExportedTypes().Where(static type =>
            type.Name.Contains("Header", StringComparison.Ordinal) || type.Name.Contains("Snapshot", StringComparison.Ordinal))
            .SelectMany(static type => type.GetMethods(BindingFlags.Public | BindingFlags.Static))
            .Any(static method => method.Name.Contains("Parse", StringComparison.Ordinal) ||
                method.Name.Contains("Validate", StringComparison.Ordinal))).IsFalse();
        var instanceSurfaces = assembly.GetExportedTypes().SelectMany(static type => type.GetMethods(
                BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(static method => method.Name is "Authorize" or "Matches")
            .Select(method => $"{type.FullName}.{method.Name}"))
            .OrderBy(static value => value, StringComparer.Ordinal).ToArray();
        await Assert.That(instanceSurfaces).IsEquivalentTo(new[]
        {
            "TerraScale.Orchestrator.Protocol.Subjects.SubjectPermissionPattern.Matches",
            "TerraScale.Orchestrator.Protocol.Subjects.SubjectPermissionPolicy.Authorize",
        });
        await Assert.That(default(CommandValidationResult).IsValid).IsFalse();
        await Assert.That(default(SubjectPermissionDecision).IsAllowed).IsFalse();
    }

    [Test]
    public async Task EmbeddedRegressionCorpusIsBoundedContentAddressedAndReplayable()
    {
        var loaded = ProtocolRegressionCorpus.LoadEmbedded();
        await Assert.That(loaded.Code).IsEqualTo(CorpusLoadCode.Accepted);
        await Assert.That(loaded.Entries.Count).IsEqualTo(3);
        foreach (var entry in loaded.Entries)
        {
            await Assert.That(ProtocolRegressionCorpus.Digest(entry)).IsEqualTo(entry.Digest);
            ReplayCorpus(entry);
        }

        var collisionLeft = new ProtocolCorpusEntry("family", 1, "a|expected=b", "c", new string('0', 64));
        var collisionRight = new ProtocolCorpusEntry("family", 1, "a", "b|expected=c", new string('0', 64));
        await Assert.That(ProtocolRegressionCorpus.Canonical(collisionLeft))
            .IsNotEqualTo(ProtocolRegressionCorpus.Canonical(collisionRight));

        var source = "{\"version\":1,\"entries\":[]}";
        await Assert.That(ProtocolRegressionCorpus.Load(source.Replace("\"entries\"", "\"unknown\"",
            StringComparison.Ordinal)).Code).IsEqualTo(CorpusLoadCode.InvalidSchema);
        await Assert.That(ProtocolRegressionCorpus.Load(source.Replace("\"version\":1", "\"version\":2",
            StringComparison.Ordinal)).Code).IsEqualTo(CorpusLoadCode.InvalidSchema);
        await Assert.That(ProtocolRegressionCorpus.Load("{\"version\":1,\"version\":1,\"entries\":[]}").Code)
            .IsEqualTo(CorpusLoadCode.InvalidSchema);
        await Assert.That(ProtocolRegressionCorpus.Load($"{{\"version\":1,\"entries\":[{string.Join(',',
            Enumerable.Repeat("{}", 65))}]}}").Code).IsEqualTo(CorpusLoadCode.InvalidSchema);
        await Assert.That(ProtocolRegressionCorpus.Load("{\"version\":1,\"entries\":[[[[[[[[[[]]]]]]]]]]}").Code)
            .IsEqualTo(CorpusLoadCode.InvalidJson);
        var tampered = "{\"version\":1,\"entries\":[{\"family\":\"concrete-subject\",\"seed\":17," +
            "\"input\":\"a..b\",\"expected\":\"EmptyToken\",\"digest\":\"" + new string('0', 64) + "\"}]}";
        await Assert.That(ProtocolRegressionCorpus.Load(tampered).Code).IsEqualTo(CorpusLoadCode.InvalidDigest);
        await Assert.That(ProtocolRegressionCorpus.Load(new string('x', 32_769)).Code).IsEqualTo(CorpusLoadCode.TooLarge);
        await Assert.That(ProtocolRegressionCorpus.Load("{").Code).IsEqualTo(CorpusLoadCode.InvalidJson);
    }

    [Test]
    public async Task PermissionPatternEnumerationIsTotalBoundedAndFailClosedForAllowAndDeny()
    {
        SubjectGrammarLimits.TryCreate(64, 8, 16, 3, out var limits);
        var exact = new SubjectPermissionPattern?[] { Pattern("a.*"), Pattern("b.*"), Pattern("c.*") };
        await Assert.That(SubjectPermissionPolicy.TryCreate(exact, [], limits, out var exactAllow, out var exactAllowError)).IsTrue();
        await Assert.That(exactAllowError).IsEqualTo(SubjectPermissionPolicyError.None);
        await Assert.That(SubjectPermissionPolicy.TryCreate([], exact, limits, out var exactDeny, out var exactDenyError)).IsTrue();
        await Assert.That(exactDenyError).IsEqualTo(SubjectPermissionPolicyError.None);
        var maxPlusOne = exact.Append(Pattern("d.*")).ToArray();
        await Assert.That(SubjectPermissionPolicy.TryCreate(maxPlusOne, [], limits, out _, out var allowPlusOne)).IsFalse();
        await Assert.That(allowPlusOne).IsEqualTo(SubjectPermissionPolicyError.TooManyPatterns);
        await Assert.That(SubjectPermissionPolicy.TryCreate([], maxPlusOne, limits, out _, out var denyPlusOne)).IsFalse();
        await Assert.That(denyPlusOne).IsEqualTo(SubjectPermissionPolicyError.TooManyPatterns);
        await Assert.That(SubjectPermissionPolicy.TryCreate(InfinitePatterns(), [], limits, out _, out var allowBound)).IsFalse();
        await Assert.That(allowBound).IsEqualTo(SubjectPermissionPolicyError.TooManyPatterns);
        await Assert.That(SubjectPermissionPolicy.TryCreate([], InfinitePatterns(), limits, out _, out var denyBound)).IsFalse();
        await Assert.That(denyBound).IsEqualTo(SubjectPermissionPolicyError.TooManyPatterns);
        var maxPlusOneCurrent = new MaxPlusOneCurrentThrowEnumerable(exact!);
        await Assert.That(SubjectPermissionPolicy.TryCreate(maxPlusOneCurrent, [], limits, out _, out var allowCurrentBound)).IsFalse();
        await Assert.That(allowCurrentBound).IsEqualTo(SubjectPermissionPolicyError.TooManyPatterns);
        await Assert.That(SubjectPermissionPolicy.TryCreate([], maxPlusOneCurrent, limits, out _, out var denyCurrentBound)).IsFalse();
        await Assert.That(denyCurrentBound).IsEqualTo(SubjectPermissionPolicyError.TooManyPatterns);

        var throwing = new IEnumerable<SubjectPermissionPattern?>[]
        {
            new ThrowBeforeEnumerable(), new ThrowAfterEnumerable(Pattern("a.*")),
            new CurrentThrowEnumerable(), new DisposeThrowEnumerable(Pattern("a.*")),
        };
        foreach (var source in throwing)
        {
            await Assert.That(SubjectPermissionPolicy.TryCreate(source, [], limits, out var allow, out var allowError)).IsFalse();
            await Assert.That(allow).IsNull();
            await Assert.That(allowError).IsEqualTo(SubjectPermissionPolicyError.EnumerationFailed);
            await Assert.That(allowError.ToString()).DoesNotContain("iterator-secret");
            await Assert.That(SubjectPermissionPolicy.TryCreate([], source, limits, out var deny, out var denyError)).IsFalse();
            await Assert.That(deny).IsNull();
            await Assert.That(denyError).IsEqualTo(SubjectPermissionPolicyError.EnumerationFailed);
        }
    }

    private static FuzzSummary RunNumeric(ulong seed)
    {
        var generator = new DeterministicGenerator(seed); var accepted = 0; var rejected = 0; ulong digest = 0;
        var values = new HashSet<long>();
        for (var index = 0; index < CasesPerFamily; index++)
        {
            var value = index % 7 switch { 0 => 0, 1 => -1, 2 => long.MinValue, 3 => long.MaxValue,
                _ => (long)(generator.Next() & long.MaxValue) + 1 };
            var expected = value > 0;
            var results = new[] { ProtocolRevision.TryCreate(value, out var protocol),
                DesiredGeneration.TryCreate(value, out var generation), WriterEpoch.TryCreate(value, out var epoch),
                DeliveryAttempt.TryCreate(value, out var attempt) };
            Require(results.All(result => result == expected), "numeric", index);
            Require(!expected ? !protocol.IsValid && !generation.IsValid && !epoch.IsValid && !attempt.IsValid :
                protocol.Value == value && generation.Value == value && epoch.Value == value && attempt.Value == value,
                "numeric-output", index);
            if (expected) accepted++; else rejected++;
            values.Add(value);
            digest = Mix(digest, expected ? value : index);
        }
        return new(CasesPerFamily, accepted, rejected, values.Count, digest);
    }

    private static FuzzSummary RunOpaque(ulong seed)
    {
        var generator = new DeterministicGenerator(seed); var accepted = 0; var rejected = 0; ulong digest = 0;
        var shapes = new HashSet<(int Length, byte First, byte Last)>();
        for (var index = 0; index < CasesPerFamily; index++)
        {
            var length = index % 257; var bytes = new byte[length]; generator.Fill(bytes);
            var original = bytes.ToArray(); var payload = OpaquePayload.CopyFrom(bytes);
            var digestAccepted = PayloadDigest.TryCopyFrom(bytes, out var payloadDigest);
            var signatureAccepted = OpaqueSignature.TryCopyFrom(bytes, out var signature);
            if (bytes.Length > 0) bytes[0] ^= 0xff;
            Require(payload.Bytes.SequenceEqual(original), "opaque-copy", index);
            Require(digestAccepted == (length > 0) && signatureAccepted == (length > 0), "opaque-empty", index);
            Require(payload.ToString() == "<opaque-payload>" &&
                (payloadDigest is null || payloadDigest.ToString() == "<payload-digest>") &&
                (signature is null || signature.ToString() == "<opaque-signature>"), "opaque-redaction", index);
            if (length > 1)
            {
                var truncated = OpaquePayload.CopyFrom(original.AsSpan(0, length - 1));
                var extended = OpaquePayload.CopyFrom([.. original, 0]);
                Require(!payload.Equals(truncated) && !payload.Equals(extended), "opaque-truncate-extend", index);
            }
            if (digestAccepted) accepted++; else rejected++;
            shapes.Add((length, length == 0 ? (byte)0 : original[0], length == 0 ? (byte)0 : original[^1]));
            digest = Mix(digest, length == 0 ? 0 : original[0] + length);
        }
        return new(CasesPerFamily, accepted, rejected, shapes.Count, digest);
    }

    private static SubjectSummary RunSubjects(ulong seed)
    {
        var generator = new DeterministicGenerator(seed); var limits = Limits();
        var subjectAccepted = 0; var subjectRejected = 0; var patternAccepted = 0; var patternRejected = 0;
        var subjectErrors = new HashSet<SubjectGrammarError>(); var patternErrors = new HashSet<SubjectGrammarError>();
        ulong digest = 0;
        for (var index = 0; index < CasesPerFamily; index++)
        {
            var token = $"a{generator.NextInt(1_000)}";
            var subjectText = (index % 8) switch { 0 => $"{token}.b", 1 => $"{token}.*", 2 => "a..b",
                3 => new string('x', 65), 4 => "a. b", 5 => "a.\ud800", 6 => "alpha.🚀",
                _ => $"{new string('x', 16)}.z" };
            var subjectOk = ConcreteSubject.TryParse(subjectText, limits, out var subject, out var subjectError);
            var subjectReplay = ConcreteSubject.TryParse(subjectText, limits, out var replaySubject, out var replayError);
            var expectedSubjectError = (index % 8) switch { 0 or 6 or 7 => SubjectGrammarError.None,
                1 => SubjectGrammarError.WildcardNotAllowed, 2 => SubjectGrammarError.EmptyToken,
                3 => SubjectGrammarError.SubjectTooLong, 4 => SubjectGrammarError.WhitespaceNotAllowed,
                _ => SubjectGrammarError.InvalidUnicodeScalarSequence };
            Require(subjectOk == subjectReplay && subjectError == replayError &&
                (subjectOk ? subject!.Equals(replaySubject) && subjectError == SubjectGrammarError.None :
                    subject is null && replaySubject is null && subjectError != SubjectGrammarError.None) &&
                subjectError == expectedSubjectError, "subject-replay", index);
            if (subjectOk) subjectAccepted++; else subjectRejected++;
            subjectErrors.Add(subjectError);

            var patternText = (index % 8) switch { 0 => $"{token}.*", 1 => $"{token}.>", 2 => "a.>.b",
                3 => "a.**", 4 => "a..b", 5 => new string('x', 65), 6 => "alpha.🚀", _ => ">" };
            var patternOk = SubjectPermissionPattern.TryParse(patternText, limits, out var pattern, out var patternError);
            var patternReplay = SubjectPermissionPattern.TryParse(patternText, limits, out var replayPattern, out var patternReplayError);
            var expectedPatternError = (index % 8) switch { 0 or 1 or 6 or 7 => SubjectGrammarError.None,
                2 => SubjectGrammarError.TerminalWildcardMustBeFinal, 3 => SubjectGrammarError.InvalidWildcard,
                4 => SubjectGrammarError.EmptyToken, _ => SubjectGrammarError.SubjectTooLong };
            Require(patternOk == patternReplay && patternError == patternReplayError &&
                (patternOk ? pattern!.Equals(replayPattern) && patternError == SubjectGrammarError.None :
                    pattern is null && replayPattern is null && patternError != SubjectGrammarError.None) &&
                patternError == expectedPatternError, "pattern-replay", index);
            if (patternOk)
            {
                Require(pattern!.Matches(null) == false, "pattern-null", index);
                patternAccepted++;
            }
            else patternRejected++;
            patternErrors.Add(patternError);
            digest = Mix(digest, ((long)subjectError << 16) | (long)patternError);
        }
        return new(CasesPerFamily, CasesPerFamily, subjectAccepted, subjectRejected, patternAccepted, patternRejected,
            subjectErrors.Count, patternErrors.Count, digest);
    }

    private static PolicySummary RunPolicies(ulong seed)
    {
        var generator = new DeterministicGenerator(seed); var accepted = 0; var rejected = 0; ulong digest = 0;
        var reasons = new HashSet<SubjectPermissionPolicyError>();
        for (var index = 0; index < CasesPerFamily; index++)
        {
            var maxSubject = generator.NextInt(80) + 1; var maxToken = generator.NextInt(20) + 1;
            var tokenLimit = index % 9 == 0 ? maxSubject + 1 : maxToken;
            var shouldCreateLimits = tokenLimit <= maxSubject;
            var limitsOk = SubjectGrammarLimits.TryCreate(maxSubject, 8, tokenLimit, 3, out var limits);
            Require(limitsOk == shouldCreateLimits, "limits", index);
            if (!limitsOk) { rejected++; digest = Mix(digest, index); continue; }
            var alpha = Pattern($"alpha{index % 10}.*"); var beta = Pattern("beta.*"); var blocked = Pattern("blocked.>");
            SubjectPermissionPattern?[] allow; SubjectPermissionPattern?[] deny;
            switch (index % 5)
            {
                case 0: allow = [alpha, beta]; deny = [blocked]; break;
                case 1: allow = [alpha, alpha]; deny = []; break;
                case 2: allow = [alpha]; deny = [alpha]; break;
                case 3: allow = [alpha, beta, blocked]; deny = [Pattern("extra.*")]; break;
                default: allow = [alpha, null]; deny = []; break;
            }
            var ok = SubjectPermissionPolicy.TryCreate(allow, deny, limits, out var policy, out var error);
            var replayOk = SubjectPermissionPolicy.TryCreate(allow.Reverse(), deny.Reverse(), limits,
                out var replay, out var replayError);
            var expectedError = (index % 5) switch { 0 => SubjectPermissionPolicyError.None,
                1 => SubjectPermissionPolicyError.DuplicatePattern, 2 => SubjectPermissionPolicyError.PatternInAllowAndDeny,
                3 => SubjectPermissionPolicyError.TooManyPatterns, _ => SubjectPermissionPolicyError.NullPattern };
            Require(ok == replayOk && error == replayError && error == expectedError &&
                ok == (expectedError == SubjectPermissionPolicyError.None), "policy-replay", index);
            reasons.Add(error);
            if (ok)
            {
                Require(policy!.AllowPatterns.SequenceEqual(replay!.AllowPatterns) &&
                    policy.DenyPatterns.SequenceEqual(replay.DenyPatterns), "policy-permutation", index);
                var allowed = Subject($"alpha{index % 10}.one");
                Require(policy.Authorize(allowed).Reason == SubjectPermissionReason.AllowedByPattern &&
                    policy.Authorize(Subject("blocked.one")).Reason == SubjectPermissionReason.DeniedByPattern &&
                    !policy.Authorize(null).IsAllowed, "policy-authority", index);
                accepted++;
            }
            else { Require(policy is null && error != SubjectPermissionPolicyError.None, "policy-fail-closed", index); rejected++; }
            digest = Mix(digest, (long)error);
        }
        return new(CasesPerFamily, accepted, rejected, reasons.Count, digest);
    }

    private static EnvelopeSummary RunEnvelopes(ulong seed)
    {
        var generator = new DeterministicGenerator(seed); var accepted = 0; var rejected = 0; ulong digest = 0;
        var errors = new HashSet<CommandValidationError>();
        for (var index = 0; index < CasesPerFamily; index++)
        {
            var category = index % 15; CommandEnvelope? envelope = ProtocolTestData.ValidEnvelope();
            CommandValidationContext? context = ProtocolTestData.ValidContext();
            var expected = CommandValidationError.None;
            switch (category)
            {
                case 1: envelope = null; expected = CommandValidationError.MalformedEnvelope; break;
                case 2: envelope = ProtocolTestData.ValidEnvelope(protocol: ProtocolTestData.Protocol(2)); expected = CommandValidationError.UnsupportedProtocolVersion; break;
                case 3: envelope = ProtocolTestData.ValidEnvelope(issuedAt: ProtocolTestData.Now.AddMinutes(1), expiresAt: ProtocolTestData.Now.AddMinutes(-1)); expected = CommandValidationError.InvalidValidityWindow; break;
                case 4: envelope = ProtocolTestData.ValidEnvelope(issuedAt: ProtocolTestData.Now.AddMinutes(3),
                    expiresAt: ProtocolTestData.Now.AddMinutes(4)); expected = CommandValidationError.NotYetValid; break;
                case 5: envelope = ProtocolTestData.ValidEnvelope(issuedAt: ProtocolTestData.Now.AddMinutes(-4),
                    expiresAt: ProtocolTestData.Now.AddMinutes(-3)); expected = CommandValidationError.Expired; break;
                case 6: envelope = ProtocolTestData.ValidEnvelope(cell: ProtocolTestData.Cell("sfo")); expected = CommandValidationError.WrongCell; break;
                case 7: envelope = ProtocolTestData.ValidEnvelope(aggregate: ProtocolTestData.Aggregate("allocation/other")); expected = CommandValidationError.WrongAggregateIdentity; break;
                case 8: envelope = ProtocolTestData.ValidEnvelope(generation: ProtocolTestData.Generation(9)); expected = CommandValidationError.StaleGeneration; break;
                case 9: envelope = ProtocolTestData.ValidEnvelope(epoch: ProtocolTestData.Epoch(6)); expected = CommandValidationError.StaleWriterEpoch; break;
                case 10: envelope = ProtocolTestData.ValidEnvelope(payload: OpaquePayload.CopyFrom([1, 2, 3])); expected = CommandValidationError.PayloadDigestMismatch; break;
                case 11: context = ProtocolTestData.ValidContext(signatureVerifier: new TestSignatureVerifier(false)); expected = CommandValidationError.InvalidSignature; break;
                case 12: context = ProtocolTestData.ValidContext(digestVerifier: new OutcomeDigestVerifier((VerificationOutcome)7)); expected = CommandValidationError.PayloadDigestVerificationFailed; break;
                case 13: context = ProtocolTestData.ValidContext(signatureVerifier: new OutcomeSignatureVerifier((VerificationOutcome)7)); expected = CommandValidationError.SignatureVerificationFailed; break;
                case 14: context = null; expected = CommandValidationError.InvalidValidationContext; break;
            }
            var now = ProtocolTestData.Now.AddTicks(generator.NextInt(3) - 1);
            var result = CommandEnvelopeValidator.Validate(envelope, context, now);
            var replay = CommandEnvelopeValidator.Validate(envelope, context, now);
            Require(result == replay && result.Error == expected && result.IsValid == (expected == CommandValidationError.None),
                "envelope-replay", index);
            Require((result.Acceptance is not null) == result.IsValid, "envelope-receipt-scope", index);
            Require(!result.ToString().Contains("secret-material", StringComparison.Ordinal) &&
                (envelope?.ToString() ?? string.Empty).Contains("Payload = <redacted>", StringComparison.Ordinal) == (envelope is not null),
                "envelope-secret", index);
            errors.Add(result.Error); if (result.IsValid) accepted++; else rejected++;
            digest = MixReceipt(digest, result);
        }
        return new(CasesPerFamily, accepted, rejected, errors.Count, digest);
    }

    private static ulong MixReceipt(ulong digest, CommandValidationResult result)
    {
        digest = Mix(digest, (long)result.Error);
        if (result.Acceptance is not { } acceptance) return digest;
        var fingerprint = string.Join('|', acceptance.ProtocolVersion.Value.ToString(CultureInfo.InvariantCulture),
            acceptance.Cell.Value, acceptance.AggregateId.Value,
            acceptance.DesiredGeneration.Value.ToString(CultureInfo.InvariantCulture),
            acceptance.WriterEpoch.Value.ToString(CultureInfo.InvariantCulture), acceptance.OperationId.Value,
            acceptance.IdempotencyKey.Value, acceptance.IssuedAt.UtcTicks.ToString(CultureInfo.InvariantCulture),
            acceptance.ExpiresAt.UtcTicks.ToString(CultureInfo.InvariantCulture),
            acceptance.Attempt.Value.ToString(CultureInfo.InvariantCulture),
            Convert.ToHexString(acceptance.PayloadDigest.Bytes), Convert.ToHexString(acceptance.Signature.Bytes),
            acceptance.ValidatedAt.UtcTicks.ToString(CultureInfo.InvariantCulture));
        foreach (var character in fingerprint) digest = Mix(digest, character);
        return digest;
    }

    private static DecisionSummary RunDecisions(ulong seed)
    {
        var generator = new DeterministicGenerator(seed); var allowed = 0; var denied = 0; ulong digest = 0;
        var reasons = new HashSet<SubjectPermissionReason>();
        for (var index = 0; index < CasesPerFamily; index++)
        {
            var suffix = generator.NextInt(1_000).ToString(CultureInfo.InvariantCulture);
            var category = index % 7;
            var pattern = category switch { 0 => Pattern($"alpha{suffix}.value"), 1 => Pattern($"alpha{suffix}.*"),
                2 => Pattern($"alpha{suffix}.>"), _ => Pattern($"other{suffix}.*") };
            var subject = Subject(category switch { 0 or 1 => $"alpha{suffix}.value", 2 => $"alpha{suffix}.one.two",
                _ => $"alpha{suffix}.value" });
            var expectedMatch = category is 0 or 1 or 2;
            Require(pattern.Matches(subject) == expectedMatch && pattern.Matches(subject) == expectedMatch,
                "pattern-match", index);
            var allow = category == 4 ? Array.Empty<SubjectPermissionPattern?>() : category == 5 ?
                [Pattern($"other{suffix}.>")] : category == 3 ? [Pattern(">")] : [Pattern($"alpha{suffix}.>")];
            var deny = category == 3 ? new SubjectPermissionPattern?[] { Pattern($"alpha{suffix}.>") } : [];
            Require(SubjectPermissionPolicy.TryCreate(allow, deny, Limits(), out var policy, out _), "decision-policy", index);
            var decision = policy!.Authorize(category == 6 ? null : subject);
            var expectedReason = category switch { 0 or 1 or 2 => SubjectPermissionReason.AllowedByPattern,
                3 => SubjectPermissionReason.DeniedByPattern, 4 => SubjectPermissionReason.DeniedEmptyAllowSet,
                5 => SubjectPermissionReason.DeniedNoAllowMatch, _ => SubjectPermissionReason.DeniedInvalidSubject };
            Require(decision.Reason == expectedReason && decision.IsAllowed ==
                (expectedReason == SubjectPermissionReason.AllowedByPattern), "policy-decision", index);
            reasons.Add(decision.Reason); if (decision.IsAllowed) allowed++; else denied++;
            digest = Mix(digest, (long)decision.Reason);
        }
        return new(CasesPerFamily, allowed, denied, reasons.Count, digest);
    }

    private static void ReplayCorpus(ProtocolCorpusEntry entry)
    {
        var repetitions = checked((int)(entry.Seed % 7) + 2);
        for (var replay = 0; replay < repetitions; replay++) switch (entry.Family)
        {
            case "concrete-subject":
                Require(!ConcreteSubject.TryParse(entry.Input, Limits(), out _, out var subjectError) &&
                    subjectError.ToString() == entry.Expected, "corpus-subject", entry.Seed); break;
            case "permission-pattern":
                Require(!SubjectPermissionPattern.TryParse(entry.Input, Limits(), out _, out var patternError) &&
                    patternError.ToString() == entry.Expected, "corpus-pattern", entry.Seed); break;
            case "command-envelope":
                var revision = 0L;
                var parsed = entry.Input.StartsWith("protocol:", StringComparison.Ordinal) &&
                    long.TryParse(entry.Input.AsSpan("protocol:".Length), NumberStyles.None,
                        CultureInfo.InvariantCulture, out revision) && revision > 0;
                Require(parsed,
                    "corpus-envelope-mutation", entry.Seed);
                var result = CommandEnvelopeValidator.Validate(ProtocolTestData.ValidEnvelope(
                    protocol: ProtocolTestData.Protocol(revision)), ProtocolTestData.ValidContext(), ProtocolTestData.Now);
                Require(result.Error.ToString() == entry.Expected, "corpus-envelope", entry.Seed); break;
            default: throw new InvalidOperationException("Unknown bounded corpus family.");
        }
    }

    private static SubjectGrammarLimits Limits() { SubjectGrammarLimits.TryCreate(64, 8, 16, 16, out var value); return value!; }
    private static SubjectPermissionPattern Pattern(string value) { SubjectPermissionPattern.TryParse(value, Limits(), out var result, out _); return result!; }
    private static ConcreteSubject Subject(string value) { ConcreteSubject.TryParse(value, Limits(), out var result, out _); return result!; }
    private static IEnumerable<SubjectPermissionPattern?> InfinitePatterns()
    {
        for (var index = 0; ; index++) yield return Pattern($"p{index}.*");
    }
    private static ulong Mix(ulong digest, long value) => unchecked((digest ^ (ulong)value) * 1099511628211UL + 1469598103934665603UL);
    private static void Require(bool condition, string family, long seed)
    {
        if (!condition) throw new InvalidOperationException($"Deterministic fuzz invariant failed: {family}, seed {seed.ToString(CultureInfo.InvariantCulture)}.");
    }

    private sealed class OutcomeDigestVerifier(VerificationOutcome outcome) : IPayloadDigestVerifier
    { public VerificationOutcome Verify(OpaquePayload payload, PayloadDigest expectedDigest) => outcome; }
    private sealed class OutcomeSignatureVerifier(VerificationOutcome outcome) : ICommandSignatureVerifier
    { public VerificationOutcome Verify(CommandSignedMaterial signedMaterial, OpaqueSignature signature) => outcome; }
    private sealed record FuzzSummary(int Cases, int Accepted, int Rejected, int Diversity, ulong Digest);
    private sealed record SubjectSummary(int SubjectCases, int PatternCases, int SubjectAccepted, int SubjectRejected,
        int PatternAccepted, int PatternRejected, int SubjectErrors, int PatternErrors, ulong Digest);
    private sealed record PolicySummary(int Cases, int Accepted, int Rejected, int Reasons, ulong Digest);
    private sealed record EnvelopeSummary(int Cases, int Accepted, int Rejected, int Errors, ulong Digest);
    private sealed record DecisionSummary(int Cases, int Allowed, int Denied, int Reasons, ulong Digest);

    private sealed class ThrowBeforeEnumerable : IEnumerable<SubjectPermissionPattern?>
    {
        public IEnumerator<SubjectPermissionPattern?> GetEnumerator() => throw new InvalidOperationException("iterator-secret");
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }
    private sealed class ThrowAfterEnumerable(SubjectPermissionPattern pattern) : IEnumerable<SubjectPermissionPattern?>
    {
        public IEnumerator<SubjectPermissionPattern?> GetEnumerator()
        {
            yield return pattern;
            throw new InvalidOperationException("iterator-secret");
        }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }
    private sealed class DisposeThrowEnumerable(SubjectPermissionPattern pattern) : IEnumerable<SubjectPermissionPattern?>
    {
        public IEnumerator<SubjectPermissionPattern?> GetEnumerator() => new DisposeThrowEnumerator(pattern);
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }
    private sealed class CurrentThrowEnumerable : IEnumerable<SubjectPermissionPattern?>
    {
        public IEnumerator<SubjectPermissionPattern?> GetEnumerator() => new CurrentThrowEnumerator();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }
    private sealed class MaxPlusOneCurrentThrowEnumerable(IReadOnlyList<SubjectPermissionPattern?> values) :
        IEnumerable<SubjectPermissionPattern?>
    {
        public IEnumerator<SubjectPermissionPattern?> GetEnumerator() => new MaxPlusOneCurrentThrowEnumerator(values);
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }
    private sealed class MaxPlusOneCurrentThrowEnumerator(IReadOnlyList<SubjectPermissionPattern?> values) :
        IEnumerator<SubjectPermissionPattern?>
    {
        private int index = -1;
        public SubjectPermissionPattern? Current => index < values.Count ? values[index] :
            throw new InvalidOperationException("iterator-secret-max-plus-one");
        object? System.Collections.IEnumerator.Current => Current;
        public bool MoveNext() { index++; return index <= values.Count; }
        public void Reset() => throw new NotSupportedException();
        public void Dispose() { }
    }
    private sealed class CurrentThrowEnumerator : IEnumerator<SubjectPermissionPattern?>
    {
        private bool moved;
        public SubjectPermissionPattern? Current => throw new InvalidOperationException("iterator-secret");
        object? System.Collections.IEnumerator.Current => Current;
        public bool MoveNext() { if (moved) return false; moved = true; return true; }
        public void Reset() => throw new NotSupportedException();
        public void Dispose() { }
    }
    private sealed class DisposeThrowEnumerator(SubjectPermissionPattern pattern) : IEnumerator<SubjectPermissionPattern?>
    {
        private bool moved;
        public SubjectPermissionPattern? Current => pattern;
        object? System.Collections.IEnumerator.Current => Current;
        public bool MoveNext() { if (moved) return false; moved = true; return true; }
        public void Reset() => throw new NotSupportedException();
        public void Dispose() => throw new InvalidOperationException("iterator-secret");
    }

    private sealed class DeterministicGenerator(ulong state)
    {
        public ulong Next()
        {
            state += 0x9E3779B97F4A7C15UL;
            var value = state; value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9UL;
            value = (value ^ (value >> 27)) * 0x94D049BB133111EBUL;
            return value ^ (value >> 31);
        }
        public int NextInt(int exclusiveMaximum) => (int)(Next() % (uint)exclusiveMaximum);
        public void Fill(Span<byte> destination)
        {
            for (var index = 0; index < destination.Length; index++) destination[index] = (byte)Next();
        }
    }
}
