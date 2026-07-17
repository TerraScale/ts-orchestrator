using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsCellEnvelopeTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task KmsBoundarySignsCompleteCellMaterialAndValidatesExactEnvelope()
    {
        var handoff = CellHandoff();
        var spec = handoff.Cells.Single();
        var signer = new TestSigner([9, 8, 7, 6]);

        var envelope = NativeGitOpsCellEnvelope.Sign(
            handoff,
            "gru",
            writerEpoch: 7,
            Now.AddMinutes(-1),
            Now.AddMinutes(1),
            signer);
        var validation = NativeGitOpsCellEnvelope.Validate(
            envelope,
            handoff,
            "gru",
            expectedWriterEpoch: 7,
            Now,
            TimeSpan.FromSeconds(5),
            new TestVerifier([9, 8, 7, 6]));

        await Assert.That(validation.IsAccepted).IsTrue();
        await Assert.That(validation.ProtocolError).IsEqualTo(CommandValidationError.None);
        await Assert.That(signer.Material).IsNotNull();
        await Assert.That(signer.Material!.Cell.Value).IsEqualTo("gru");
        await Assert.That(signer.Material.DesiredGeneration.Value).IsEqualTo(spec.Generation);
        await Assert.That(signer.Material.WriterEpoch.Value).IsEqualTo(7);
        await Assert.That(signer.Material.Payload.Bytes.SequenceEqual(spec.Payload.Span)).IsTrue();
        await Assert.That(envelope.OperationId.Value).IsEqualTo($"gitops/{handoff.HandoffDigest}/gru");
        await Assert.That(envelope.IdempotencyKey.Value).IsEqualTo($"gitops/{spec.PayloadSha256}");
    }

    [Test]
    public async Task RegionalValidationNeedsOnlyTheBoundedAggregateDigestDescriptor()
    {
        var handoff = CellHandoff();
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var envelope = NativeGitOpsCellEnvelope.Sign(
            handoff,
            "gru",
            7,
            Now.AddMinutes(-1),
            Now.AddMinutes(1),
            new TestSigner([4, 5, 6]));

        var accepted = NativeGitOpsCellEnvelope.Validate(
            envelope,
            descriptor,
            "gru",
            7,
            Now,
            TimeSpan.Zero,
            new TestVerifier([4, 5, 6]));
        var corruptDescriptor = descriptor with
        {
            HandoffDigest = "f123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        };
        var rejected = NativeGitOpsCellEnvelope.Validate(
            envelope,
            corruptDescriptor,
            "gru",
            7,
            Now,
            TimeSpan.Zero,
            new TestVerifier([4, 5, 6]));

        await Assert.That(accepted.IsAccepted).IsTrue();
        await Assert.That(descriptor.Cells).HasSingleItem();
        await Assert.That(descriptor.Cells.Single().PayloadSha256)
            .IsEqualTo(handoff.Cells.Single().PayloadSha256);
        await Assert.That(rejected.Error).IsEqualTo(NativeGitOpsCellEnvelopeError.InvalidInput);
    }

    [Test]
    public async Task CellGenerationEpochAndPayloadSubstitutionFailBeforeSignatureVerification()
    {
        var handoff = CellHandoff();
        var spec = handoff.Cells.Single();
        var envelope = NativeGitOpsCellEnvelope.Sign(
            handoff,
            "gru",
            7,
            Now.AddMinutes(-1),
            Now.AddMinutes(1),
            new TestSigner([1]));
        var verifier = new TestVerifier([1]);
        var wrongCell = NativeGitOpsCellEnvelope.Validate(
            envelope,
            handoff,
            "sfo",
            7,
            Now,
            TimeSpan.Zero,
            verifier);
        var wrongEpoch = NativeGitOpsCellEnvelope.Validate(
            envelope,
            handoff,
            "gru",
            8,
            Now,
            TimeSpan.Zero,
            verifier);
        var wrongPayload = NativeGitOpsCellEnvelope.Validate(
            envelope,
            CellHandoff(ApiV2),
            "gru",
            7,
            Now,
            TimeSpan.Zero,
            verifier);

        await Assert.That(wrongCell.Error).IsEqualTo(NativeGitOpsCellEnvelopeError.InvalidInput);
        await Assert.That(wrongEpoch.Error).IsEqualTo(NativeGitOpsCellEnvelopeError.WrongCellSpec);
        await Assert.That(wrongPayload.Error).IsEqualTo(NativeGitOpsCellEnvelopeError.WrongCellSpec);
        await Assert.That(verifier.Calls).IsEqualTo(0);
    }

    [Test]
    public async Task InvalidSignatureAndExpiredEnvelopeRemainProtocolRejections()
    {
        var handoff = CellHandoff();
        var envelope = NativeGitOpsCellEnvelope.Sign(
            handoff,
            "gru",
            7,
            Now.AddMinutes(-2),
            Now.AddMinutes(-1),
            new TestSigner([1, 2, 3]));
        var invalid = NativeGitOpsCellEnvelope.Validate(
            envelope,
            handoff,
            "gru",
            7,
            Now.AddMinutes(-1).AddSeconds(-30),
            TimeSpan.Zero,
            new TestVerifier([3, 2, 1]));
        var expired = NativeGitOpsCellEnvelope.Validate(
            envelope,
            handoff,
            "gru",
            7,
            Now,
            TimeSpan.Zero,
            new TestVerifier([1, 2, 3]));

        await Assert.That(invalid.Error).IsEqualTo(NativeGitOpsCellEnvelopeError.ProtocolRejected);
        await Assert.That(invalid.ProtocolError).IsEqualTo(CommandValidationError.InvalidSignature);
        await Assert.That(expired.Error).IsEqualTo(NativeGitOpsCellEnvelopeError.ProtocolRejected);
        await Assert.That(expired.ProtocolError).IsEqualTo(CommandValidationError.Expired);
    }

    [Test]
    public async Task EmptyOrOversizedSignerOutputCannotCreateAnEnvelope()
    {
        var handoff = CellHandoff();

        await Assert.That(() => NativeGitOpsCellEnvelope.Sign(
                handoff,
                "gru",
                7,
                Now,
                Now.AddMinutes(1),
                new TestSigner([])))
            .Throws<InvalidDataException>();
        await Assert.That(() => NativeGitOpsCellEnvelope.Sign(
                handoff,
                "gru",
                7,
                Now,
                Now.AddMinutes(1),
                new TestSigner(new byte[NativeGitOpsCellEnvelope.MaximumSignatureBytes + 1])))
            .Throws<InvalidDataException>();
    }

    private const string ApiV1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ApiV2 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private static NativeGitOpsCellHandoff CellHandoff(string digest = ApiV1)
    {
        const string repository = "TerraScale/TerraScale.Orchestrator";
        const string commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
        const string tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
        const string blob = "217eb74224043ba2feb48d137756c8a9331c44ee";
        var content = Encoding.UTF8.GetBytes($$"""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":4,"workloads":[{"id":"api","role":"Api","artifactDigest":"{{digest}}","cells":["gru"]}]}
            """);
        var proposed = NativeGitOpsManifest.Parse(content);
        var revision = new ForgejoResolvedRevision(repository, commit, tree, signatureVerified: true);
        var file = new ForgejoSourceFile(
            repository,
            commit,
            NativeGitOpsSourceLoader.ManifestPath,
            blob,
            Convert.ToHexStringLower(SHA256.HashData(content)),
            content);
        return NativeGitOpsCellSpecCompiler.Compile(
            new(revision, file, proposed, NativeGitOpsDiff.Compare(null, proposed)));
    }

    private sealed class TestSigner(byte[] signature) : INativeGitOpsCellSpecSigner
    {
        internal CommandSignedMaterial? Material { get; private set; }

        public OpaqueSignature Sign(CommandSignedMaterial material)
        {
            Material = material;
            OpaqueSignature.TryCopyFrom(signature, out var value);
            return value!;
        }
    }

    private sealed class TestVerifier(byte[] expected) : ICommandSignatureVerifier
    {
        internal int Calls { get; private set; }

        public VerificationOutcome Verify(CommandSignedMaterial signedMaterial, OpaqueSignature signature)
        {
            Calls++;
            return signature.Bytes.SequenceEqual(expected)
                ? VerificationOutcome.Valid
                : VerificationOutcome.Invalid;
        }
    }
}
