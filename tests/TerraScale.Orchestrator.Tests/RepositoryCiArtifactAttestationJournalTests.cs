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

    [Test]
    public async Task ControllerIssuesArtifactProofButStillRequiresIndependentNativeObservation()
    {
        var fixture = Create();
        var verifier = new RepositoryCiSignedArtifactAttestationVerifier(
            fixture.Journal.ReadArtifactAsync,
            fixture.Journal.ReadRuntimeAsync,
            artifactTrust,
            runtimeTrust);
        var issuing = new RepositoryCiIssuingArtifactAttestationVerifier(
            fixture.Journal,
            artifactTrust,
            verifier,
            7,
            11,
            static () => true);

        var beforeRuntime = await issuing.VerifyAsync(fixture.Subject, default);
        await fixture.Journal.RecordRuntimeAsync(fixture.Runtime, 7, 12, static () => true);
        var complete = await issuing.VerifyAsync(fixture.Subject, default);

        await Assert.That(beforeRuntime).IsNull();
        await Assert.That(complete).IsNotNull();
        await Assert.That(await fixture.Journal.ReadArtifactAsync(fixture.Subject)).IsNotNull();
        await Assert.That(complete!.ObservedRuntimeDigest).IsEqualTo(fixture.Subject.Digest);
        await Assert.That(fixture.Ledger.Mutations).IsEqualTo(2);
        await Assert.That(fixture.Objects.Values.Count).IsEqualTo(2);
    }

    [Test]
    public async Task LostAuthorityCannotIssueArtifactProof()
    {
        var fixture = Create();
        var verifier = new RepositoryCiSignedArtifactAttestationVerifier(
            fixture.Journal.ReadArtifactAsync,
            fixture.Journal.ReadRuntimeAsync,
            artifactTrust,
            runtimeTrust);
        var issuing = new RepositoryCiIssuingArtifactAttestationVerifier(
            fixture.Journal,
            artifactTrust,
            verifier,
            7,
            11,
            static () => false);

        await Assert.That(async () => await issuing.VerifyAsync(fixture.Subject, default))
            .Throws<RepositoryCiArtifactProofAuthorityLostException>();
        await Assert.That(fixture.Ledger.Mutations).IsEqualTo(0);
        await Assert.That(fixture.Objects.Values).IsEmpty();
    }

    [Test]
    public async Task ConcurrentSameSubjectAttestationsAdoptTheDurableWinner()
    {
        // Randomized signatures mean two leaders attesting the same exact subject under the same
        // authority produce different bytes; the CAS keeps one winner and the loser must adopt it
        // instead of failing the pipeline.
        var fixture = Create();
        await fixture.Journal.RecordRuntimeAsync(fixture.Runtime, 7, 11, static () => true);
        var verifier = new RepositoryCiSignedArtifactAttestationVerifier(
            fixture.Journal.ReadArtifactAsync,
            fixture.Journal.ReadRuntimeAsync,
            new TrustingArtifactVerifier(),
            runtimeTrust);
        var first = new RepositoryCiIssuingArtifactAttestationVerifier(
            fixture.Journal, new RandomizedSigner(10), verifier, 7, 20, static () => true);
        var second = new RepositoryCiIssuingArtifactAttestationVerifier(
            fixture.Journal, new RandomizedSigner(11), verifier, 7, 21, static () => true);

        var results = await Task.WhenAll(
            first.VerifyAsync(fixture.Subject, default),
            second.VerifyAsync(fixture.Subject, default));

        await Assert.That(results[0]).IsNotNull();
        await Assert.That(results[1]).IsNotNull();
        await Assert.That(await fixture.Journal.ReadArtifactAsync(fixture.Subject)).IsNotNull();
        await Assert.That(fixture.Ledger.Mutations).IsEqualTo(2);
    }

    private sealed class RandomizedSigner(byte domain) : IRepositoryCiArtifactAttestationSigner
    {
        public string Identity => $"test-random-{domain}";

        public OpaqueSignature Sign(ReadOnlyMemory<byte> canonicalMaterial)
        {
            var bytes = new byte[canonicalMaterial.Length + 2];
            bytes[0] = domain;
            bytes[1] = (byte)RandomNumberGenerator.GetInt32(256);
            canonicalMaterial.Span.CopyTo(bytes.AsSpan(2));
            OpaqueSignature.TryCopyFrom(SHA256.HashData(bytes), out var signature);
            return signature!;
        }
    }

    private sealed class TrustingArtifactVerifier : IRepositoryCiArtifactSignatureVerifier
    {
        public VerificationOutcome Verify(
            string signingIdentity,
            ReadOnlyMemory<byte> canonicalMaterial,
            OpaqueSignature signature) => VerificationOutcome.Valid;
    }

    [Test]
    public async Task LostAdmissionRaceReclaimsTheOrphanedProofObject()
    {
        // The race: the reader sees no pointer, a concurrent winner creates one for DIFFERENT
        // proof bytes, and this attempt's CAS loses. The loser's content-addressed object is
        // unreferenced by any durable pointer and must be reclaimed, not leaked forever.
        var fixture = Create();
        var replacement = RepositoryCiArtifactAttestation.Sign(fixture.Subject, new HashSignature(3));
        var winnerContent = RepositoryCiArtifactAttestationJournal.Serialize(
            RepositoryCiArtifactProofDocument.From(replacement));
        await fixture.Objects.PutAsync(ProofObjectName(winnerContent), winnerContent, default);
        var raced = new RepositoryCiArtifactAttestationJournal(
            new ProofRaceLedger(winnerContent), fixture.Objects);

        var loser = await raced.RecordArtifactAsync(fixture.Artifact, 7, 11, static () => true);

        await Assert.That(loser)
            .IsEqualTo(RepositoryCiArtifactAttestationJournalDisposition.IdentityConflict);
        // Exactly the winner's object survives: the loser's was reclaimed after the lost race.
        await Assert.That(fixture.Objects.Values.Count).IsEqualTo(1);
        await Assert.That(fixture.Objects.Values.Keys.Single()).IsEqualTo(ProofObjectName(winnerContent));
        await Assert.That(fixture.Objects.Deletions).IsEqualTo(1);
        // The durable winner still reads back intact (its object was never touched).
        await Assert.That(await raced.ReadArtifactAsync(fixture.Subject)).IsEqualTo(replacement);
    }

    [Test]
    public async Task LostAdmissionRaceAgainstIdenticalBytesKeepsTheSharedObject()
    {
        // Same-content CAS loss: the winner's pointer names the SAME content-addressed object
        // the loser just wrote, so reclamation must keep it — deleting it would orphan the
        // winner's durable pointer.
        var fixture = Create();
        var winnerContent = RepositoryCiArtifactAttestationJournal.Serialize(
            RepositoryCiArtifactProofDocument.From(fixture.Artifact));
        var raced = new RepositoryCiArtifactAttestationJournal(
            new ProofRaceLedger(winnerContent), fixture.Objects);

        var duplicate = await raced.RecordArtifactAsync(fixture.Artifact, 7, 11, static () => true);

        await Assert.That(duplicate)
            .IsEqualTo(RepositoryCiArtifactAttestationJournalDisposition.Duplicate);
        await Assert.That(fixture.Objects.Values.Count).IsEqualTo(1);
        await Assert.That(fixture.Objects.Deletions).IsEqualTo(0);
        await Assert.That(await raced.ReadArtifactAsync(fixture.Subject)).IsEqualTo(fixture.Artifact);
    }

    [Test]
    public async Task APointerFlippingToTheLosersContentBeforeReclaimKeepsTheObject()
    {
        // TOCTOU collapse: between the conflict disposition and the reclaim's delete, the
        // durable pointer at the key is replaced by one naming the LOSER's exact content
        // (retention pruned the winner; a same-content writer re-created it). The reclaim
        // re-reads the pointer and must skip the delete — deleting would orphan the new
        // winner's durable pointer.
        var fixture = Create();
        var winnerContent = RepositoryCiArtifactAttestationJournal.Serialize(
            RepositoryCiArtifactProofDocument.From(
                RepositoryCiArtifactAttestation.Sign(fixture.Subject, new HashSignature(3))));
        var raced = new RepositoryCiArtifactAttestationJournal(
            new ProofRaceLedger(winnerContent, flipToProposedOnReclaim: true), fixture.Objects);

        var loser = await raced.RecordArtifactAsync(fixture.Artifact, 7, 11, static () => true);

        await Assert.That(loser)
            .IsEqualTo(RepositoryCiArtifactAttestationJournalDisposition.IdentityConflict);
        // The winner's pointer AND object were pruned before the flip, so the loser's object
        // is the only one — and it SURVIVES the reclaim (a reclaim that deleted would leave
        // zero objects and a dangling pointer).
        var loserObject = RepositoryCiArtifactAttestationJournal.Serialize(
            RepositoryCiArtifactProofDocument.From(fixture.Artifact));
        await Assert.That(fixture.Objects.Values.Count).IsEqualTo(1);
        await Assert.That(fixture.Objects.Values.Keys.Single()).IsEqualTo(ProofObjectName(loserObject));
        await Assert.That(fixture.Objects.Deletions).IsEqualTo(0);
        // The flipped pointer names the loser's content, whose object survived: it reads back.
        await Assert.That(await raced.ReadArtifactAsync(fixture.Subject)).IsEqualTo(fixture.Artifact);
    }

    private static string ProofObjectName(byte[] content) =>
        $"ci-artifact-proof-{Convert.ToHexStringLower(SHA256.HashData(content))}";

    /// <summary>
    /// A ledger that loses the create compare-and-set exactly like a concurrent winner: a
    /// durable pointer for <paramref name="winnerContent"/> appears between the journal's read
    /// and its create, so the create throws the admission conflict instead of admitting. With
    /// <paramref name="flipToProposedOnReclaim"/>, the read AFTER the conflict handler's read
    /// returns the PROPOSED pointer instead — simulating the winner being replaced by the
    /// loser's own content before the reclaim's delete.
    /// </summary>
    private sealed class ProofRaceLedger(byte[] winnerContent, bool flipToProposedOnReclaim = false) : IForgejoDeliveryLedger
    {
        private readonly Dictionary<string, ForgejoDeliveryLedgerEntry> entries = new(StringComparer.Ordinal);
        private string? proposedPointer;
        private int readsAfterConflict;

        public Task<ForgejoDeliveryLedgerEntry?> GetAsync(string key, CancellationToken cancellationToken)
        {
            if (entries.TryGetValue(key, out var entry) && flipToProposedOnReclaim &&
                proposedPointer is not null && ++readsAfterConflict >= 2)
                return Task.FromResult<ForgejoDeliveryLedgerEntry?>(new(proposedPointer, entry.Revision + 1, key));
            return Task.FromResult(entries.GetValueOrDefault(key));
        }

        public Task<ForgejoDeliveryLedgerEntry> CreateAsync(
            string key, string value, CancellationToken cancellationToken)
        {
            if (entries.ContainsKey(key)) throw new ForgejoDeliveryLedgerConflictException(new InvalidOperationException());
            var document = RepositoryCiArtifactAttestationJournal.DeserializeProof(winnerContent);
            var pointer = new RepositoryCiArtifactProofPointerDocument(
                1,
                RepositoryCiArtifactProofKind.ArtifactSignature,
                RepositoryCiArtifactAttestation.SubjectDigest(document.Subject.Value()),
                Convert.ToHexStringLower(SHA256.HashData(winnerContent)),
                ProofObjectName(winnerContent),
                7,
                11);
            var pointerJson = System.Text.Json.JsonSerializer.Serialize(
                pointer,
                RepositoryCiArtifactAttestationJournalJsonContext.Default.RepositoryCiArtifactProofPointerDocument);
            entries[key] = new(pointerJson, 1, key);
            proposedPointer = value;
            throw new ForgejoDeliveryLedgerConflictException(new InvalidOperationException());
        }

        public Task<ForgejoDeliveryLedgerEntry> UpdateAsync(
            string key, string value, ulong revision, CancellationToken cancellationToken) =>
            throw new ForgejoDeliveryLedgerConflictException(new InvalidOperationException());

        public async IAsyncEnumerable<string> ListKeysAsync(
            string filter,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.CompletedTask;
            yield break;
        }

        public Task DeleteAsync(string key, ulong revision, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    [Test]
    public async Task BoundedProofHistoryPrunesPointersAndTheirObjects()
    {
        var fixture = Create(cap: 2, pruneInterval: 1);
        foreach (var index in new[] { 2, 3 })
        {
            var subject = fixture.Subject with { Job = new($"candidate-job-{index}") };
            var artifact = RepositoryCiArtifactAttestation.Sign(subject, artifactTrust);
            var runtime = RepositoryCiArtifactAttestation.ObserveRuntime(subject, subject.Digest, runtimeTrust);
            await fixture.Journal.RecordArtifactAsync(artifact, 7, 11, static () => true);
            await fixture.Journal.RecordRuntimeAsync(runtime, 7, 12, static () => true);
        }

        // Four proofs recorded under a cap of two: the two oldest pointers and their proof
        // objects are gone, the two newest stay, and object storage shrank with the pointers.
        await Assert.That(fixture.Ledger.Values.Count).IsEqualTo(2);
        await Assert.That(fixture.Objects.Values.Count).IsEqualTo(2);
        await Assert.That(fixture.Objects.Deletions).IsGreaterThanOrEqualTo(2);
    }

    private Fixture Create(int cap = 8192, int pruneInterval = 64)
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
            new(ledger, objects, cap, pruneInterval));
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

    private sealed class TestObjectStore : IDeliveryObjectStore, IDeliveryRetentionObjectStore
    {
        internal Dictionary<string, byte[]> Values { get; } = new(StringComparer.Ordinal);
        internal int Deletions { get; private set; }

        public Task DeleteIfExistsAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Values.Remove(name);
            Deletions++;
            return Task.CompletedTask;
        }

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

