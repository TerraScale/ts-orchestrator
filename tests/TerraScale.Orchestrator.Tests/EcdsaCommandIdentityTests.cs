using System.Runtime.Versioning;
using System.Security.Cryptography;
using TerraScale.Orchestrator.Contracts;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class EcdsaCommandIdentityTests
{
    [Test]
    public async Task PrivateIntermediateSignsAndRotatingPublicTrustVerifiesExactMaterial()
    {
        if (!OperatingSystem.IsLinux()) return;
        var directory = Path.Combine(Path.GetTempPath(), $"ts-command-signing-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var first = WriteKey(directory, "first");
            var second = WriteKey(directory, "second");
            using var firstSigner = EcdsaCommandSigner.LoadPrivatePem(first.Private);
            using var secondSigner = EcdsaCommandSigner.LoadPrivatePem(second.Private);
            using var rotating = EcdsaCommandSignatureVerifier.LoadPublicPem([first.Public, second.Public]);
            using var secondOnly = EcdsaCommandSignatureVerifier.LoadPublicPem([second.Public]);
            var material = Material("job/one");
            var changed = Material("job/two");
            var firstSignature = firstSigner.Sign(material);
            var secondSignature = secondSigner.Sign(material);
            ReadOnlyMemory<byte> detachedMaterial = "artifact-subject"u8.ToArray();
            ReadOnlyMemory<byte> changedDetachedMaterial = "changed-artifact-subject"u8.ToArray();
            var detachedSignature = firstSigner.Sign(detachedMaterial);

            await Assert.That(firstSigner is IRepositoryCiJobSigner).IsTrue();
            await Assert.That(firstSigner is INativeGitOpsCellSpecSigner).IsTrue();
            await Assert.That(firstSigner is IRepositoryCiArtifactAttestationSigner).IsTrue();
            await Assert.That(rotating.Verify(material, firstSignature)).IsEqualTo(VerificationOutcome.Valid);
            await Assert.That(rotating.Verify(material, secondSignature)).IsEqualTo(VerificationOutcome.Valid);
            await Assert.That(rotating.Verify(changed, firstSignature)).IsEqualTo(VerificationOutcome.Invalid);
            await Assert.That(secondOnly.Verify(material, firstSignature)).IsEqualTo(VerificationOutcome.Invalid);
            await Assert.That(secondOnly.Verify(material, secondSignature)).IsEqualTo(VerificationOutcome.Valid);
            await Assert.That(rotating.Verify(firstSigner.Identity, detachedMaterial, detachedSignature))
                .IsEqualTo(VerificationOutcome.Valid);
            await Assert.That(rotating.Verify(secondSigner.Identity, detachedMaterial, detachedSignature))
                .IsEqualTo(VerificationOutcome.Invalid);
            await Assert.That(rotating.Verify(firstSigner.Identity, changedDetachedMaterial, detachedSignature))
                .IsEqualTo(VerificationOutcome.Invalid);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Test]
    public async Task SignatureEnvelopeAndKeyFilesFailClosed()
    {
        if (!OperatingSystem.IsLinux()) return;
        var directory = Path.Combine(Path.GetTempPath(), $"ts-command-signing-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var key = WriteKey(directory, "valid");
            using var signer = EcdsaCommandSigner.LoadPrivatePem(key.Private);
            using var verifier = EcdsaCommandSignatureVerifier.LoadPublicPem([key.Public]);
            var signature = signer.Sign(Material("job/one"));
            var corrupt = signature.Bytes.ToArray();
            corrupt[4] = 2;
            OpaqueSignature.TryCopyFrom(corrupt, out var corruptSignature);
            File.SetUnixFileMode(key.Private, UnixFileMode.UserRead | UnixFileMode.GroupRead);

            await Assert.That(verifier.Verify(Material("job/one"), corruptSignature!))
                .IsEqualTo(VerificationOutcome.Invalid);
            // Load failures must name the offending file PATH (never its contents) so an
            // operator can find the exact rejected credential without reading key material.
            var permissive = await Assert.That(() => EcdsaCommandSigner.LoadPrivatePem(key.Private))
                .Throws<ArgumentException>();
            await Assert.That(permissive!.Message).Contains(key.Private);
            var privateAsTrust = await Assert.That(() => EcdsaCommandSignatureVerifier.LoadPublicPem([key.Private]))
                .Throws<ArgumentException>();
            await Assert.That(privateAsTrust!.Message).Contains(key.Private);

            using var wrongCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            var wrongPublic = Path.Combine(directory, "wrong-public.pem");
            await File.WriteAllTextAsync(wrongPublic, wrongCurve.ExportSubjectPublicKeyInfoPem());
            var wrongCurveFailure = await Assert.That(() =>
                    EcdsaCommandSignatureVerifier.LoadPublicPem([wrongPublic]))
                .Throws<ArgumentException>();
            await Assert.That(wrongCurveFailure!.Message).Contains(wrongPublic);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static CommandSignedMaterial Material(string aggregate)
    {
        ProtocolRevision.TryCreate(1, out var protocol);
        CellId.TryCreate("global", out var cell);
        AggregateId.TryCreate(aggregate, out var aggregateId);
        DesiredGeneration.TryCreate(7, out var generation);
        WriterEpoch.TryCreate(5, out var epoch);
        OperationId.TryCreate("dispatch/job", out var operation);
        IdempotencyKey.TryCreate("ci-job-one", out var idempotency);
        DeliveryAttempt.TryCreate(1, out var attempt);
        var payload = OpaquePayload.CopyFrom("payload"u8);
        PayloadDigest.TryCopyFrom(SHA256.HashData(payload.Bytes), out var digest);
        OpaqueSignature.TryCopyFrom([1], out var placeholder);
        return new CommandEnvelope(
            protocol,
            cell,
            aggregateId,
            generation,
            epoch,
            operation,
            idempotency,
            new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero),
            new(2026, 7, 17, 14, 0, 0, TimeSpan.Zero),
            attempt,
            payload,
            digest!,
            placeholder!).SignedMaterial;
    }

    [SupportedOSPlatform("linux")]
    private static KeyFiles WriteKey(string directory, string name)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privatePath = Path.Combine(directory, $"{name}-private.pem");
        var publicPath = Path.Combine(directory, $"{name}-public.pem");
        File.WriteAllText(privatePath, key.ExportPkcs8PrivateKeyPem());
        File.WriteAllText(publicPath, key.ExportSubjectPublicKeyInfoPem());
        File.SetUnixFileMode(privatePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return new(privatePath, publicPath);
    }

    private sealed record KeyFiles(string Private, string Public);
}
