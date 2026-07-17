using System.Security.Cryptography;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiArtifactAttestationJournalTests
{
    private readonly HashSignature artifactTrust = new(1);
    private readonly HashSignature runtimeTrust = new(2);

    [Test]
    public async Task SignedProofsAreDurableAndExactReplayConverges()
    {
        var fixture = Create();

        var artifactRecorded = await fixture.Journal.RecordArtifactAsync(
            fixture.Artifact, 7, 11, static () => true);
        var runtimeRecorded = await fixture.Journal.RecordRuntimeAsync(
            fixture.Runtime, 7, 12, static () => true);
        var artifactReplay = await fixture.Journal.RecordArtifactAsync(
            fixture.Artifact, 7, 11, static () => true);
        var runtimeReplay = await fixture.Journal.RecordRuntimeAsync(
            fixture.Runtime, 7, 12, static () => true);
        var artifact = await fixture.Journal.ReadArtifactAsync(fixture.Subject);
        var runtime = await fixture.Journal.ReadRuntimeAsync(fixture.Subject);

        await Assert.That(artifactRecorded)
            .IsEqualTo(RepositoryCiArtifactAttestationJournalDisposition.Recorded);
        await Assert.That(runtimeRecorded)
            .IsEqualTo(RepositoryCiArtifactAttestationJournalDisposition.Recorded);
        await Assert.That(artifactReplay)
            .IsEqualTo(RepositoryCiArtifactAttestationJournalDisposition.Duplicate);
        await Assert.That(runtimeReplay)
            .IsEqualTo(RepositoryCiArtifactAttestationJournalDisposition.Duplicate);
        await Assert.That(artifact).IsEqualTo(fixture.Artifact);
        await Assert.That(runtime).IsEqualTo(fixture.Runtime);
        await Assert.That(fixture.Ledger.Mutations).IsEqualTo(2);
        await Assert.That(fixture.Objects.Values.Count).IsEqualTo(2);
    }

    [Test]
    public async Task DifferentSignedBytesCannotReplaceAnExistingSubjectProof()
    {
        var fixture = Create();
        var replacement = RepositoryCiArtifactAttestation.Sign(fixture.Subject, new HashSignature(3));
        await fixture.Journal.RecordArtifactAsync(fixture.Artifact, 7, 11, static () => true);

        var conflict = await fixture.Journal.RecordArtifactAsync(
            replacement, 8, 13, static () => true);

        await Assert.That(conflict)
            .IsEqualTo(RepositoryCiArtifactAttestationJournalDisposition.IdentityConflict);
        await Assert.That(await fixture.Journal.ReadArtifactAsync(fixture.Subject))
            .IsEqualTo(fixture.Artifact);
        await Assert.That(fixture.Objects.Values.Count).IsEqualTo(1);
    }

    [Test]
    public async Task ObjectAndPointerCorruptionFailBeforeProofProjection()
    {
        var objectFixture = Create();
        await objectFixture.Journal.RecordArtifactAsync(
            objectFixture.Artifact, 7, 11, static () => true);
        objectFixture.Objects.Values.Single().Value[0] ^= 1;

        await Assert.That(async () => await objectFixture.Journal.ReadArtifactAsync(objectFixture.Subject))
            .Throws<InvalidDataException>();

        var pointerFixture = Create();
        await pointerFixture.Journal.RecordArtifactAsync(
            pointerFixture.Artifact, 7, 11, static () => true);
        pointerFixture.Ledger.CorruptFirst();

        await Assert.That(async () => await pointerFixture.Journal.ReadArtifactAsync(pointerFixture.Subject))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task AuthorityLossAfterObjectWritePublishesNoWinnerPointer()
    {
        var fixture = Create();
        var checks = 0;

        var stale = await fixture.Journal.RecordArtifactAsync(
            fixture.Artifact,
            7,
            11,
            () => ++checks == 1);

        await Assert.That(stale)
            .IsEqualTo(RepositoryCiArtifactAttestationJournalDisposition.StaleAuthority);
        await Assert.That(await fixture.Journal.ReadArtifactAsync(fixture.Subject)).IsNull();
        await Assert.That(fixture.Ledger.Mutations).IsEqualTo(0);
        await Assert.That(fixture.Objects.Values.Count).IsEqualTo(1);
    }

    [Test]
    public async Task DurableReadersFeedTheCryptographicCandidateGate()
    {
        var fixture = Create();
        await fixture.Journal.RecordArtifactAsync(fixture.Artifact, 7, 11, static () => true);
        await fixture.Journal.RecordRuntimeAsync(fixture.Runtime, 7, 12, static () => true);
        var verifier = new RepositoryCiSignedArtifactAttestationVerifier(
            fixture.Journal.ReadArtifactAsync,
            fixture.Journal.ReadRuntimeAsync,
            artifactTrust,
            runtimeTrust);

        var verified = await verifier.VerifyAsync(fixture.Subject, default);

        await Assert.That(verified).IsNotNull();
        await Assert.That(verified!.SigningIdentity).IsEqualTo(fixture.Artifact.SigningIdentity);
        await Assert.That(verified.ObservedRuntimeDigest).IsEqualTo(fixture.Subject.Digest);
    }

    private Fixture Create()
    {
        var subject = new RepositoryCiArtifactSubject(
            Digest('a'),
            new("candidate-job"),
            new("TerraScale/TerraScale.Orchestrator"),
            RepositoryCiArchitecture.LinuxArm64,
            new(Digest('b')),
            RepositoryCiArtifactAttestation.EntrypointsDigest(
                RepositoryCiArchitecture.LinuxArm64,
                ["app"]));
        var artifact = RepositoryCiArtifactAttestation.Sign(subject, artifactTrust);
        var runtime = RepositoryCiArtifactAttestation.ObserveRuntime(subject, subject.Digest, runtimeTrust);
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        return new(
            subject,
            artifact,
            runtime,
            ledger,
            objects,
            new(ledger, objects));
    }

    private sealed record Fixture(
        RepositoryCiArtifactSubject Subject,
        RepositoryCiSignedArtifact Artifact,
        RepositoryCiSignedRuntimeObservation Runtime,
        ForgejoWebhookJournalTests.TestLedger Ledger,
        TestObjectStore Objects,
        RepositoryCiArtifactAttestationJournal Journal);

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

    private sealed class TestObjectStore : IDeliveryObjectStore
    {
        internal Dictionary<string, byte[]> Values { get; } = new(StringComparer.Ordinal);

        public Task PutAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Values.TryGetValue(name, out var content)) throw new IOException("Missing test object.");
            return Task.FromResult(content.ToArray());
        }
    }

    private static string Digest(char value) => new(value, 64);
}
