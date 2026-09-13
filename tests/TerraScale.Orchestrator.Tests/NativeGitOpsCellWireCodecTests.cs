using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsCellWireCodecTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task RawPayloadAndCanonicalHeadersRoundTripIntoRegionalValidation()
    {
        var handoff = Handoff();
        var envelope = NativeGitOpsCellEnvelope.Sign(
            handoff,
            "gru",
            7,
            Now.AddMinutes(-1),
            Now.AddMinutes(1),
            new TestSigner([1, 2, 3]));

        var wire = NativeGitOpsCellWireCodec.Encode(handoff, envelope);
        var decoded = NativeGitOpsCellWireCodec.Decode(wire.Payload, wire.Headers);
        var validated = NativeGitOpsCellEnvelope.Validate(
            decoded.Envelope,
            decoded.Handoff,
            "gru",
            7,
            Now,
            TimeSpan.Zero,
            new TestVerifier([1, 2, 3]));

        await Assert.That(validated.IsAccepted).IsTrue();
        await Assert.That(decoded.Handoff.Cells.Count).IsEqualTo(2);
        await Assert.That(decoded.Handoff.HandoffDigest).IsEqualTo(handoff.HandoffDigest);
        await Assert.That(decoded.Envelope.Payload.Bytes.SequenceEqual(envelope.Payload.Bytes)).IsTrue();
        await Assert.That(decoded.Envelope.Signature.Equals(envelope.Signature)).IsTrue();
    }

    [Test]
    public async Task DuplicateUnknownAndNonCanonicalHeadersFailClosed()
    {
        var wire = Wire();
        var duplicate = wire.Headers.Concat([wire.Headers.First()]);
        var unknown = wire.Headers.Select(pair => pair.Key == "TS-CellSpec-Schema"
            ? new KeyValuePair<string, string>("TS-Unknown", pair.Value)
            : pair);
        var nonCanonicalNumber = Replace(wire, "TS-Writer-Epoch", "07");
        var nonCanonicalSignature = Replace(wire, "TS-Signature", "AQ");

        await Assert.That(() => NativeGitOpsCellWireCodec.Decode(wire.Payload, duplicate))
            .Throws<InvalidDataException>();
        await Assert.That(() => NativeGitOpsCellWireCodec.Decode(wire.Payload, unknown))
            .Throws<InvalidDataException>();
        await Assert.That(() => NativeGitOpsCellWireCodec.Decode(wire.Payload, nonCanonicalNumber))
            .Throws<InvalidDataException>();
        await Assert.That(() => NativeGitOpsCellWireCodec.Decode(wire.Payload, nonCanonicalSignature))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task PayloadDescriptorAndSignatureSubstitutionFailBeforeDelivery()
    {
        var wire = Wire();
        var payload = wire.Payload.ToArray();
        payload[^2] ^= 1;
        var reversedCells = Replace(
            wire,
            "TS-Handoff-Cells",
            string.Join(';', wire.Headers["TS-Handoff-Cells"].Split(';').Reverse()));
        var oversizedSignature = Replace(
            wire,
            "TS-Signature",
            Convert.ToBase64String(new byte[NativeGitOpsCellEnvelope.MaximumSignatureBytes + 1]));

        await Assert.That(() => NativeGitOpsCellWireCodec.Decode(payload, wire.Headers))
            .Throws<InvalidDataException>();
        await Assert.That(() => NativeGitOpsCellWireCodec.Decode(wire.Payload, reversedCells))
            .Throws<InvalidDataException>();
        await Assert.That(() => NativeGitOpsCellWireCodec.Decode(wire.Payload, oversizedSignature))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task WireEnvelopeFitsTheDefaultOneMiBServerPayloadBoundary()
    {
        var wire = Wire();
        var headerBytes = wire.Headers.Sum(pair =>
            Encoding.UTF8.GetByteCount(pair.Key) + Encoding.UTF8.GetByteCount(pair.Value) + 4);

        await Assert.That(wire.Payload.Length)
            .IsLessThanOrEqualTo(NativeGitOpsCellSpecCompiler.MaximumCellSpecBytes);
        await Assert.That(headerBytes).IsLessThanOrEqualTo(NativeGitOpsCellWireCodec.MaximumHeaderBytes);
        await Assert.That(wire.Payload.Length + headerBytes)
            .IsLessThanOrEqualTo(NativeGitOpsCellWireCodec.MaximumWireBytes);
    }

    private static NativeGitOpsCellWireMessage Wire()
    {
        var handoff = Handoff();
        var envelope = NativeGitOpsCellEnvelope.Sign(
            handoff,
            "gru",
            7,
            Now.AddMinutes(-1),
            Now.AddMinutes(1),
            new TestSigner([1, 2, 3]));
        return NativeGitOpsCellWireCodec.Encode(handoff, envelope);
    }

    private static IEnumerable<KeyValuePair<string, string>> Replace(
        NativeGitOpsCellWireMessage wire,
        string name,
        string value) => wire.Headers.Select(pair => pair.Key == name
        ? new KeyValuePair<string, string>(pair.Key, value)
        : pair);

    private static NativeGitOpsCellHandoff Handoff()
    {
        const string repository = "TerraScale/TerraScale.Orchestrator";
        const string commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
        const string tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
        const string blob = "217eb74224043ba2feb48d137756c8a9331c44ee";
        const string digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        var content = Encoding.UTF8.GetBytes($$"""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":4,"workloads":[{"id":"platform","role":"CustomerDashboard","artifactDigest":"{{digest}}","cells":["gru","sfo"]}]}
            """);
        var proposed = NativeGitOpsManifest.Parse(content);
        return NativeGitOpsCellSpecCompiler.Compile(new(
            new(repository, commit, tree, signatureVerified: true),
            new(
                repository,
                commit,
                NativeGitOpsSourceLoader.ManifestPath,
                blob,
                Convert.ToHexStringLower(SHA256.HashData(content)),
                content),
            proposed,
            NativeGitOpsDiff.Compare(null, proposed)));
    }

    private sealed class TestSigner(byte[] signature) : INativeGitOpsCellSpecSigner
    {
        public OpaqueSignature Sign(CommandSignedMaterial material)
        {
            OpaqueSignature.TryCopyFrom(signature, out var value);
            return value!;
        }
    }

    private sealed class TestVerifier(byte[] expected) : ICommandSignatureVerifier
    {
        public VerificationOutcome Verify(CommandSignedMaterial signedMaterial, OpaqueSignature signature) =>
            signature.Bytes.SequenceEqual(expected) ? VerificationOutcome.Valid : VerificationOutcome.Invalid;
    }
}

