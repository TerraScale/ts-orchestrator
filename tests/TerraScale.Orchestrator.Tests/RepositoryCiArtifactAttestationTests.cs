using System.Security.Cryptography;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiArtifactAttestationTests
{
    private readonly HashSignature artifactTrust = new(1);
    private readonly HashSignature runtimeTrust = new(2);

    [Test]
    public async Task NativeArtifactRequiresIndependentExactSignatureAndRuntimeProof()
    {
        var subject = Subject(RepositoryCiArchitecture.LinuxArm64, 'a');
        var artifact = RepositoryCiArtifactAttestation.Sign(
            subject,
            artifactTrust);
        var runtime = RepositoryCiArtifactAttestation.ObserveRuntime(
            subject,
            subject.Digest,
            runtimeTrust);

        var verified = RepositoryCiArtifactAttestation.Validate(
            subject,
            artifact,
            runtime,
            artifactTrust,
            runtimeTrust);
        var wrongRuntimeTrust = RepositoryCiArtifactAttestation.Validate(
            subject,
            artifact,
            runtime,
            artifactTrust,
            artifactTrust);

        await Assert.That(verified).IsNotNull();
        await Assert.That(verified!.SigningIdentity).IsEqualTo(artifact.SigningIdentity);
        await Assert.That(verified.Signature).IsEqualTo(artifact.SignatureId);
        await Assert.That(verified.ObservedRuntimeDigest).IsEqualTo(subject.Digest);
        await Assert.That(wrongRuntimeTrust).IsNull();
    }

    [Test]
    public async Task PackageArtifactRequiresNoRuntimeProofAndCannotCreateOne()
    {
        var subject = Subject(RepositoryCiArchitecture.Any, 'b');
        var artifact = RepositoryCiArtifactAttestation.Sign(
            subject,
            artifactTrust);

        var verified = RepositoryCiArtifactAttestation.Validate(
            subject,
            artifact,
            null,
            artifactTrust,
            runtimeTrust);

        await Assert.That(verified).IsNotNull();
        await Assert.That(verified!.ObservedRuntimeDigest).IsNull();
        await Assert.That(() => RepositoryCiArtifactAttestation.ObserveRuntime(
                subject,
                subject.Digest,
                runtimeTrust))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task SubjectSignatureIdentityAndObservedDigestSubstitutionFailClosed()
    {
        var subject = Subject(RepositoryCiArchitecture.LinuxX64, 'c');
        var artifact = RepositoryCiArtifactAttestation.Sign(
            subject,
            artifactTrust);
        var wrongRuntime = RepositoryCiArtifactAttestation.ObserveRuntime(
            subject,
            new(Digest('d')),
            runtimeTrust);
        var changedSubject = subject with { Digest = new(Digest('e')) };
        var changedEntrypoints = subject with
        {
            EntrypointsDigest = RepositoryCiArtifactAttestation.EntrypointsDigest(
                subject.Architecture,
                ["different"]),
        };

        await Assert.That(RepositoryCiArtifactAttestation.Validate(
                subject,
                artifact,
                wrongRuntime,
                artifactTrust,
                runtimeTrust))
            .IsNull();
        await Assert.That(RepositoryCiArtifactAttestation.Validate(
                changedSubject,
                artifact,
                null,
                artifactTrust,
                runtimeTrust))
            .IsNull();
        await Assert.That(RepositoryCiArtifactAttestation.Validate(
                changedEntrypoints,
                artifact,
                null,
                artifactTrust,
                runtimeTrust))
            .IsNull();
        await Assert.That(RepositoryCiArtifactAttestation.Validate(
                subject,
                artifact with { SignatureId = new("substituted-signature") },
                null,
                artifactTrust,
                runtimeTrust))
            .IsNull();
    }

    [Test]
    public async Task SignedAttestationReaderReturnsOnlyCryptographicallyVerifiedProofs()
    {
        var subject = Subject(RepositoryCiArchitecture.LinuxArm64, 'f');
        var artifact = RepositoryCiArtifactAttestation.Sign(
            subject,
            artifactTrust);
        var runtime = RepositoryCiArtifactAttestation.ObserveRuntime(
            subject,
            subject.Digest,
            runtimeTrust);
        var artifactReads = 0;
        var runtimeReads = 0;
        var verifier = new RepositoryCiSignedArtifactAttestationVerifier(
            (_, token) =>
            {
                token.ThrowIfCancellationRequested();
                artifactReads++;
                return Task.FromResult<RepositoryCiSignedArtifact?>(artifact);
            },
            (_, token) =>
            {
                token.ThrowIfCancellationRequested();
                runtimeReads++;
                return Task.FromResult<RepositoryCiSignedRuntimeObservation?>(runtime);
            },
            artifactTrust,
            runtimeTrust);

        var verified = await verifier.VerifyAsync(subject, default);

        await Assert.That(verified).IsNotNull();
        await Assert.That(artifactReads).IsEqualTo(1);
        await Assert.That(runtimeReads).IsEqualTo(1);
    }

    private static RepositoryCiArtifactSubject Subject(
        RepositoryCiArchitecture architecture,
        char digest) => new(
        Digest('1'),
        new("candidate-job"),
        new("TerraScale/TerraScale.Orchestrator"),
        architecture,
        new(Digest(digest)),
        RepositoryCiArtifactAttestation.EntrypointsDigest(
            architecture,
            architecture == RepositoryCiArchitecture.Any ? [] : ["app"]));

    private static string Digest(char value) => new(value, 64);

    private sealed class HashSignature(byte domain) :
        IRepositoryCiArtifactAttestationSigner,
        IRepositoryCiArtifactSignatureVerifier
    {
        public string Identity => $"test-key-{domain}";

        public OpaqueSignature Sign(ReadOnlyMemory<byte> canonicalMaterial)
        {
            var bytes = new byte[canonicalMaterial.Length + 1];
            bytes[0] = domain;
            canonicalMaterial.Span.CopyTo(bytes.AsSpan(1));
            OpaqueSignature.TryCopyFrom(SHA256.HashData(bytes), out var signature);
            return signature!;
        }

        public VerificationOutcome Verify(
            string signingIdentity,
            ReadOnlyMemory<byte> canonicalMaterial,
            OpaqueSignature signature) => signingIdentity == Identity && Sign(canonicalMaterial).Equals(signature)
            ? VerificationOutcome.Valid
            : VerificationOutcome.Invalid;
    }
}

