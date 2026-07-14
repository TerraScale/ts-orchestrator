using System.Globalization;
using System.Text;
using TerraScale.Orchestrator.Contracts;
using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Protocol.Tests.Fuzz;

public sealed class ProtocolContractCompletenessPropertyTests
{
    private const int Cases = 1_000;
    private static readonly DateTimeOffset Now = new(2026, 7, 13, 16, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task CommandAdmissionRunsOneThousandDistinctExactOracleCasesCultureIndependently()
    {
        var original = CultureInfo.CurrentCulture;
        var originalUi = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("en-US");
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("en-US");
            var baseline = RunCommandAdmission();
            foreach (var cultureName in new[] { "tr-TR", "ar-SA", "ja-JP" })
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultureName);
                CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(cultureName);
                await Assert.That(RunCommandAdmission()).IsEqualTo(baseline);
            }

            await Assert.That(baseline.Cases).IsEqualTo(Cases);
            await Assert.That(baseline.DistinctInputs).IsEqualTo(Cases);
            await Assert.That(baseline.Errors).IsEqualTo(15);
            await Assert.That(baseline.Accepted).IsGreaterThan(50);
            await Assert.That(baseline.Rejected).IsGreaterThan(900);
            await Assert.That(baseline.DistinctAcceptedOutputs).IsEqualTo(baseline.Accepted);
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
            CultureInfo.CurrentUICulture = originalUi;
        }
    }

    [Test]
    public async Task SignedMaterialBindsEveryFieldForOneThousandDistinctEnvelopes()
    {
        var fingerprints = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < Cases; index++)
        {
            var fixture = Fixture(index);
            var envelope = fixture.Envelope;
            var material = envelope.SignedMaterial;

            Require(material.ProtocolVersion == envelope.ProtocolVersion, index);
            Require(material.Cell == envelope.Cell, index);
            Require(material.AggregateId == envelope.AggregateId, index);
            Require(material.DesiredGeneration == envelope.DesiredGeneration, index);
            Require(material.WriterEpoch == envelope.WriterEpoch, index);
            Require(material.OperationId == envelope.OperationId, index);
            Require(material.IdempotencyKey == envelope.IdempotencyKey, index);
            Require(material.IssuedAt == envelope.IssuedAt, index);
            Require(material.ExpiresAt == envelope.ExpiresAt, index);
            Require(material.Attempt == envelope.Attempt, index);
            Require(material.Payload.Equals(envelope.Payload), index);
            Require(material.PayloadDigest.Equals(envelope.PayloadDigest), index);
            Require(material.ToString() == "<command-signed-material>", index);
            fingerprints.Add(Fingerprint(envelope));
        }

        await Assert.That(fingerprints.Count).IsEqualTo(Cases);
    }

    [Test]
    public async Task VersionCompatibilityRejectsOneThousandDistinctUnknownPositiveVersionsBeforeVerification()
    {
        var calls = 0;
        for (var index = 0; index < Cases; index++)
        {
            var unknown = Protocol(index + 2);
            var fixture = Fixture(index, protocol: unknown);
            var digest = new CountingDigestVerifier(() => calls++);
            var signature = new CountingSignatureVerifier(() => calls++);
            var context = Context(fixture, [Protocol(1)], digest, signature);
            var result = CommandEnvelopeValidator.Validate(fixture.Envelope, context, Now);

            Require(result.Error == CommandValidationError.UnsupportedProtocolVersion, index);
        }

        await Assert.That(calls).IsEqualTo(0);
    }

    [Test]
    public async Task OpaqueFactoriesCopyAndCompareOneThousandDistinctBinaryInputsWithoutInventingACeiling()
    {
        var shapes = new HashSet<(int Length, byte First, byte Last)>();
        for (var index = 0; index < Cases; index++)
        {
            var bytes = Enumerable.Range(0, index + 1)
                .Select(offset => unchecked((byte)(offset * 31 + index * 17)))
                .ToArray();
            var original = bytes.ToArray();
            var payload = OpaquePayload.CopyFrom(bytes);
            Require(PayloadDigest.TryCopyFrom(bytes, out var digest), index);
            Require(OpaqueSignature.TryCopyFrom(bytes, out var signature), index);

            bytes[0] ^= 0xff;
            Require(payload.Bytes.SequenceEqual(original), index);
            Require(digest!.Bytes.SequenceEqual(original), index);
            Require(signature!.Bytes.SequenceEqual(original), index);
            Require(!payload.Equals(OpaquePayload.CopyFrom(original.AsSpan(0, original.Length - 1))), index);
            Require(!payload.Equals(OpaquePayload.CopyFrom([.. original, (byte)index])), index);
            Require(payload.ToString() == "<opaque-payload>", index);
            Require(digest.ToString() == "<payload-digest>", index);
            Require(signature.ToString() == "<opaque-signature>", index);
            shapes.Add((original.Length, original[0], original[^1]));
        }

        await Assert.That(shapes.Count).IsEqualTo(Cases);
    }

    [Test]
    public async Task SubjectLimitsRetainDocumentedUtf16SemanticsForOneThousandDistinctUnicodeInputs()
    {
        var values = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < Cases; index++)
        {
            var value = $"cell{index.ToString(CultureInfo.InvariantCulture)}.rocket\U0001F680";
            var longestToken = value.Split('.').Max(static token => token.Length);
            Require(SubjectGrammarLimits.TryCreate(value.Length, 2, longestToken, 4, out var exact), index);
            Require(ConcreteSubject.TryParse(value, exact, out var subject, out var exactError), index);
            Require(exactError == SubjectGrammarError.None && subject!.Value == value, index);

            Require(SubjectGrammarLimits.TryCreate(value.Length - 1, 2, longestToken, 4, out var tooShort), index);
            Require(!ConcreteSubject.TryParse(value, tooShort, out _, out var shortError), index);
            Require(shortError == SubjectGrammarError.SubjectTooLong, index);
            values.Add(value);
        }

        await Assert.That(values.Count).IsEqualTo(Cases);
    }

    [Test]
    public async Task CorpusParserRunsOneThousandDistinctStrictSchemaAndEncodingMutations()
    {
        var outcomes = new HashSet<CorpusLoadCode>();
        var inputs = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < Cases; index++)
        {
            var category = index % 10;
            var unique = index.ToString(CultureInfo.InvariantCulture);
            var validEntry = Entry(index + 1, $"a..b{unique}", "EmptyToken");
            var valid = Document(validEntry);
            byte[] bytes;
            CorpusLoadCode expected;
            switch (category)
            {
                case 0:
                    bytes = Utf8(valid.Replace("\"entries\"", $"\"unknown{unique}\"", StringComparison.Ordinal));
                    expected = CorpusLoadCode.InvalidSchema;
                    break;
                case 1:
                    bytes = Utf8(valid.Replace("\"version\":1", "\"version\":1,\"version\":1", StringComparison.Ordinal));
                    expected = CorpusLoadCode.InvalidSchema;
                    break;
                case 2:
                    bytes = Utf8(valid.Replace("concrete-subject", $"unknown-family-{unique}", StringComparison.Ordinal));
                    expected = CorpusLoadCode.InvalidSchema;
                    break;
                case 3:
                    bytes = Utf8(valid.Replace("EmptyToken", $"UnknownError{unique}", StringComparison.Ordinal));
                    expected = CorpusLoadCode.InvalidSchema;
                    break;
                case 4:
                    bytes = Utf8(valid.Replace($"\"seed\":{index + 1}", "\"seed\":0", StringComparison.Ordinal));
                    expected = CorpusLoadCode.InvalidSchema;
                    break;
                case 5:
                    bytes = Utf8(valid[..^3] + unique);
                    expected = CorpusLoadCode.InvalidJson;
                    break;
                case 6:
                    bytes = [.. Utf8($"{{\"version\":1,\"entries\":[\"{unique}"), 0xc3, (byte)(index & 0x7f)];
                    expected = CorpusLoadCode.InvalidJson;
                    break;
                case 7:
                    bytes = new byte[32_769];
                    bytes.AsSpan().Fill(unchecked((byte)index));
                    expected = CorpusLoadCode.TooLarge;
                    break;
                case 8:
                    bytes = Utf8(valid.Replace("\"input\"", $"\"extra{unique}\":\"x\",\"input\"", StringComparison.Ordinal));
                    expected = CorpusLoadCode.InvalidSchema;
                    break;
                default:
                    bytes = Utf8(valid.Replace(validEntry.Digest, new string((char)('a' + index % 6), 64), StringComparison.Ordinal));
                    expected = CorpusLoadCode.InvalidDigest;
                    break;
            }

            var result = ProtocolRegressionCorpus.Load(bytes);
            Require(result.Code == expected, index);
            Require(result.Entries.Count == 0, index);
            outcomes.Add(result.Code);
            inputs.Add(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)));
        }

        await Assert.That(inputs.Count).IsEqualTo(Cases);
        await Assert.That(outcomes.Count).IsEqualTo(4);
    }

    [Test]
    public async Task EmbeddedCorpusIsWholeFilePinnedAndStrictUtf8()
    {
        await Assert.That(ProtocolRegressionCorpus.LoadEmbedded().Code).IsEqualTo(CorpusLoadCode.Accepted);
        await Assert.That(ProtocolRegressionCorpus.Load("{\"version\":1,\"entries\":[]}\ud800").Code)
            .IsEqualTo(CorpusLoadCode.InvalidJson);

        var valid = Utf8(Document(Entry(1, "a..b", "EmptyToken")));
        await Assert.That(ProtocolRegressionCorpus.Load(valid, requireContentAddress: true).Code)
            .IsEqualTo(CorpusLoadCode.ContentAddressMismatch);
        await Assert.That(ProtocolRegressionCorpus.Load(Encoding.UTF8.GetString(valid)
            .Replace("\"seed\":1", "\"seed\":2", StringComparison.Ordinal)).Code)
            .IsEqualTo(CorpusLoadCode.InvalidDigest);
        await Assert.That(ProtocolRegressionCorpus.Load(Encoding.UTF8.GetString(valid)
            .Replace("a..b", "a...b", StringComparison.Ordinal)).Code)
            .IsEqualTo(CorpusLoadCode.InvalidDigest);

        await using var partial = new PartialReadStream(valid, 3);
        var read = ProtocolRegressionCorpus.ReadBounded(partial);
        await Assert.That(read).IsNotNull();
        await Assert.That(read!).IsEquivalentTo(valid);
        await using var exactStream = new PartialReadStream(new byte[32_768], 7);
        await using var oversizedStream = new PartialReadStream(new byte[32_769], 7);
        await Assert.That(ProtocolRegressionCorpus.ReadBounded(exactStream)).IsNotNull();
        await Assert.That(ProtocolRegressionCorpus.ReadBounded(oversizedStream)).IsNull();
    }

    private static AdmissionSummary RunCommandAdmission()
    {
        var accepted = 0;
        var rejected = 0;
        var errors = new HashSet<CommandValidationError>();
        var inputs = new HashSet<string>(StringComparer.Ordinal);
        var acceptedOutputs = new HashSet<string>(StringComparer.Ordinal);
        ulong digest = 1469598103934665603UL;
        for (var index = 0; index < Cases; index++)
        {
            var category = index % 16;
            var fixture = Fixture(index);
            var envelope = fixture.Envelope;
            CommandValidationContext? context = Context(fixture);
            var expected = CommandValidationError.None;
            switch (category)
            {
                case 1: envelope = Fixture(index, protocol: Protocol(2)).Envelope; expected = CommandValidationError.UnsupportedProtocolVersion; break;
                case 2: envelope = Fixture(index, cell: Cell($"wrong{index}" )).Envelope; expected = CommandValidationError.WrongCell; break;
                case 3: envelope = Fixture(index, aggregate: Aggregate($"wrong/{index}")).Envelope; expected = CommandValidationError.WrongAggregateIdentity; break;
                case 4: envelope = Fixture(index, generation: Generation(10_000 + index - 1)).Envelope; expected = CommandValidationError.StaleGeneration; break;
                case 5: envelope = Fixture(index, epoch: Epoch(20_000 + index - 1)).Envelope; expected = CommandValidationError.StaleWriterEpoch; break;
                case 6: envelope = Fixture(index, issuedAt: Now.AddMinutes(3), expiresAt: Now.AddMinutes(4)).Envelope; expected = CommandValidationError.NotYetValid; break;
                case 7: envelope = Fixture(index, issuedAt: Now.AddMinutes(-4), expiresAt: Now.AddMinutes(-3)).Envelope; expected = CommandValidationError.Expired; break;
                case 8: envelope = Fixture(index, issuedAt: Now.AddMinutes(1), expiresAt: Now.AddMinutes(-1)).Envelope; expected = CommandValidationError.InvalidValidityWindow; break;
                case 9: envelope = Fixture(index, payload: OpaquePayload.CopyFrom([0xff, (byte)index])).Envelope; expected = CommandValidationError.PayloadDigestMismatch; break;
                case 10: context = Context(fixture, signature: new TestSignatureVerifier(false)); expected = CommandValidationError.InvalidSignature; break;
                case 11: context = Context(fixture, digest: new TestDigestVerifier(throws: true)); expected = CommandValidationError.PayloadDigestVerificationFailed; break;
                case 12: context = Context(fixture, signature: new TestSignatureVerifier(throws: true)); expected = CommandValidationError.SignatureVerificationFailed; break;
                case 13: context = null; expected = CommandValidationError.InvalidValidationContext; break;
                case 14: envelope = Fixture(index, attempt: default(DeliveryAttempt)).Envelope; expected = CommandValidationError.MalformedEnvelope; break;
                case 15: envelope = Fixture(index, protocol: default(ProtocolRevision)).Envelope; expected = CommandValidationError.MalformedEnvelope; break;
            }

            var result = CommandEnvelopeValidator.Validate(envelope, context, Now);
            var replay = CommandEnvelopeValidator.Validate(envelope, context, Now);
            Require(result == replay && result.Error == expected && result.IsValid == (expected == CommandValidationError.None), index);
            Require((result.Acceptance is not null) == result.IsValid, index);
            Require(!result.ToString().Contains("secret", StringComparison.OrdinalIgnoreCase), index);
            if (result.IsValid)
            {
                accepted++;
                acceptedOutputs.Add(ResultFingerprint(result));
            }
            else rejected++;
            errors.Add(result.Error);
            inputs.Add(Fingerprint(envelope) + ":" + category.ToString(CultureInfo.InvariantCulture));
            foreach (var character in ResultFingerprint(result))
                digest = unchecked((digest ^ character) * 1099511628211UL);
        }

        return new(Cases, accepted, rejected, errors.Count, inputs.Count, acceptedOutputs.Count, digest);
    }

    private static FixtureData Fixture(
        int index,
        ProtocolRevision? protocol = null,
        CellId? cell = null,
        AggregateId? aggregate = null,
        DesiredGeneration? generation = null,
        WriterEpoch? epoch = null,
        DateTimeOffset? issuedAt = null,
        DateTimeOffset? expiresAt = null,
        DeliveryAttempt? attempt = null,
        OpaquePayload? payload = null)
    {
        var bytes = BitConverter.GetBytes(index + 1);
        var fixtureCell = cell ?? Cell($"cell{index}");
        var fixtureAggregate = aggregate ?? Aggregate($"allocation/{index}");
        var fixtureGeneration = generation ?? Generation(10_000 + index);
        var fixtureEpoch = epoch ?? Epoch(20_000 + index);
        var fixturePayload = payload ?? OpaquePayload.CopyFrom(bytes);
        PayloadDigest.TryCopyFrom(bytes, out var digest);
        OpaqueSignature.TryCopyFrom([0x51, .. bytes], out var signature);
        var envelope = new CommandEnvelope(
            protocol ?? Protocol(1), fixtureCell, fixtureAggregate, fixtureGeneration, fixtureEpoch,
            Operation($"operation/{index}"), Idempotency($"idempotency/{index}"),
            issuedAt ?? Now.AddSeconds(-index % 60), expiresAt ?? Now.AddMinutes(2).AddSeconds(index % 60),
            attempt ?? Attempt(index + 1), fixturePayload, digest!, signature!);
        return new(envelope, fixtureCell, fixtureAggregate, fixtureGeneration, fixtureEpoch);
    }

    private static CommandValidationContext Context(
        FixtureData fixture,
        IEnumerable<ProtocolRevision>? accepted = null,
        IPayloadDigestVerifier? digest = null,
        ICommandSignatureVerifier? signature = null) =>
        new(fixture.Cell, fixture.Aggregate, fixture.Generation, fixture.Epoch, accepted ?? [Protocol(1)],
            TimeSpan.FromMinutes(2), digest ?? new TestDigestVerifier(), signature ?? new TestSignatureVerifier());

    private static ProtocolCorpusEntry Entry(long seed, string input, string expected)
    {
        var provisional = new ProtocolCorpusEntry("concrete-subject", seed, input, expected, new string('0', 64));
        return provisional with { Digest = ProtocolRegressionCorpus.Digest(provisional) };
    }

    private static string Document(ProtocolCorpusEntry entry) =>
        $"{{\"version\":1,\"entries\":[{{\"family\":\"{entry.Family}\",\"seed\":{entry.Seed.ToString(CultureInfo.InvariantCulture)}," +
        $"\"input\":\"{entry.Input}\",\"expected\":\"{entry.Expected}\",\"digest\":\"{entry.Digest}\"}}]}}";

    private static string Fingerprint(CommandEnvelope envelope) => string.Join('|',
        envelope.ProtocolVersion.Value.ToString(CultureInfo.InvariantCulture), envelope.Cell.Value,
        envelope.AggregateId.Value, envelope.DesiredGeneration.Value.ToString(CultureInfo.InvariantCulture),
        envelope.WriterEpoch.Value.ToString(CultureInfo.InvariantCulture), envelope.OperationId.Value,
        envelope.IdempotencyKey.Value, envelope.IssuedAt.UtcTicks.ToString(CultureInfo.InvariantCulture),
        envelope.ExpiresAt.UtcTicks.ToString(CultureInfo.InvariantCulture), envelope.Attempt.Value.ToString(CultureInfo.InvariantCulture),
        Convert.ToHexString(envelope.Payload.Bytes));

    private static string ResultFingerprint(CommandValidationResult result)
    {
        if (result.Acceptance is not { } acceptance)
            return result.Error.ToString();
        return string.Join('|', result.Error.ToString(), acceptance.ProtocolVersion.Value.ToString(CultureInfo.InvariantCulture), acceptance.Cell.Value,
            acceptance.AggregateId.Value, acceptance.DesiredGeneration.Value.ToString(CultureInfo.InvariantCulture),
            acceptance.WriterEpoch.Value.ToString(CultureInfo.InvariantCulture), acceptance.OperationId.Value,
            acceptance.IdempotencyKey.Value, acceptance.IssuedAt.UtcTicks.ToString(CultureInfo.InvariantCulture),
            acceptance.ExpiresAt.UtcTicks.ToString(CultureInfo.InvariantCulture), acceptance.Attempt.Value.ToString(CultureInfo.InvariantCulture),
            Convert.ToHexString(acceptance.PayloadDigest.Bytes), Convert.ToHexString(acceptance.Signature.Bytes),
            acceptance.ValidatedAt.UtcTicks.ToString(CultureInfo.InvariantCulture));
    }

    private static byte[] Utf8(string value) => Encoding.UTF8.GetBytes(value);
    private static void Require(bool condition, long seed)
    {
        if (!condition) throw new InvalidOperationException($"Protocol completeness property failed at seed {seed.ToString(CultureInfo.InvariantCulture)}.");
    }

    private static ProtocolRevision Protocol(long value) { ProtocolRevision.TryCreate(value, out var result); return result; }
    private static DesiredGeneration Generation(long value) { DesiredGeneration.TryCreate(value, out var result); return result; }
    private static WriterEpoch Epoch(long value) { WriterEpoch.TryCreate(value, out var result); return result; }
    private static DeliveryAttempt Attempt(long value) { DeliveryAttempt.TryCreate(value, out var result); return result; }
    private static CellId Cell(string value) { CellId.TryCreate(value, out var result); return result; }
    private static AggregateId Aggregate(string value) { AggregateId.TryCreate(value, out var result); return result; }
    private static OperationId Operation(string value) { OperationId.TryCreate(value, out var result); return result; }
    private static IdempotencyKey Idempotency(string value) { IdempotencyKey.TryCreate(value, out var result); return result; }

    private sealed record FixtureData(CommandEnvelope Envelope, CellId Cell, AggregateId Aggregate,
        DesiredGeneration Generation, WriterEpoch Epoch);
    private sealed record AdmissionSummary(int Cases, int Accepted, int Rejected, int Errors, int DistinctInputs,
        int DistinctAcceptedOutputs, ulong Digest);

    private sealed class CountingDigestVerifier(Action called) : IPayloadDigestVerifier
    {
        public VerificationOutcome Verify(OpaquePayload payload, PayloadDigest expectedDigest)
        { called(); return VerificationOutcome.Valid; }
    }

    private sealed class CountingSignatureVerifier(Action called) : ICommandSignatureVerifier
    {
        public VerificationOutcome Verify(CommandSignedMaterial signedMaterial, OpaqueSignature signature)
        { called(); return VerificationOutcome.Valid; }
    }

    private sealed class PartialReadStream(byte[] bytes, int maximumChunk) : Stream
    {
        private int position;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => position; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = Math.Min(Math.Min(count, maximumChunk), bytes.Length - position);
            if (read <= 0) return 0;
            Array.Copy(bytes, position, buffer, offset, read);
            position += read;
            return read;
        }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
