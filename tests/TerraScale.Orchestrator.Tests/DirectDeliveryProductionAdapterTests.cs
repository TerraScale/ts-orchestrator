using System.IO;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Delivery.DeployHandoff;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Production direct-delivery adapters: admitted targets from configuration, durable signed
/// artifact evidence, and the composition boundary that fails closed without them. The restart
/// and handoff tests run over the real durable adapters (journal, target, evidence) so the
/// idempotency and resume contracts are proven at the shape production composes.
/// </summary>
public sealed class DirectDeliveryProductionAdapterTests
{
    [Test]
    public async Task Admitted_targets_admit_only_the_configured_service_environment_and_regions()
    {
        var targets = DirectDeliveryAdmittedTargets.Parse(["authentication:development:gru,sfo"]);

        await Assert.That(targets.Admits(new("authentication", "development", ["gru"]))).IsTrue();
        await Assert.That(targets.Admits(new("authentication", "development", ["gru", "sfo"]))).IsTrue();
        await Assert.That(targets.Admits(new("authentication", "development", ["sfo", "gru"]))).IsTrue();
        await Assert.That(targets.Admits(new("authentication", "development", ["fra"]))).IsFalse();
        await Assert.That(targets.Admits(new("authentication", "production", ["gru"]))).IsFalse();
        await Assert.That(targets.Admits(new("platform", "development", ["gru"]))).IsFalse();
        await Assert.That(targets.Admits(new("authentication", "development", []))).IsFalse();
        await Assert.That(targets.Admits(new("authentication", null, ["gru"]))).IsFalse();
    }

    [Test]
    public async Task Admitted_targets_reject_malformed_configuration()
    {
        await Assert.That(() => DirectDeliveryAdmittedTargets.Parse(["authentication:development"]))
            .Throws<ArgumentException>();
        await Assert.That(() => DirectDeliveryAdmittedTargets.Parse(["authentication:staging:gru"]))
            .Throws<ArgumentException>();
        await Assert.That(() => DirectDeliveryAdmittedTargets.Parse(["authentication:development:gru,gru"]))
            .Throws<ArgumentException>();
        await Assert.That(() => DirectDeliveryAdmittedTargets.Parse(["authentication:development:"]))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task Evidence_journal_keeps_the_first_durable_claim_per_artifact()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new DirectDeliveryArtifactEvidenceJournal(ledger);
        var signer = new HashSignature(1);

        var first = await journal.RecordAsync(Evidence(commit: CommitA), signer, default);
        var duplicate = await journal.RecordAsync(Evidence(commit: CommitA), signer, default);
        var conflict = await journal.RecordAsync(Evidence(commit: CommitB), signer, default);

        await Assert.That(first).IsEqualTo(DirectDeliveryArtifactEvidenceDisposition.Recorded);
        await Assert.That(duplicate).IsEqualTo(DirectDeliveryArtifactEvidenceDisposition.Duplicate);
        await Assert.That(conflict).IsEqualTo(DirectDeliveryArtifactEvidenceDisposition.IdentityConflict);
        await Assert.That(ledger.Values).HasSingleItem();
    }

    [Test]
    public async Task Production_provenance_verifies_only_durable_signed_evidence()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        var journal = new DirectDeliveryArtifactEvidenceJournal(ledger);
        await journal.RecordAsync(Evidence(commit: CommitA), trust, default);
        var provenance = new DirectDeliveryProductionProvenance(journal, trust);

        var verified = await provenance.VerifyAsync(
            Request(commit: CommitA), Artifact(), default);
        var wrongCommit = await provenance.VerifyAsync(
            Request(commit: CommitB), Artifact(), default);
        var wrongManifest = await provenance.VerifyAsync(
            Request(commit: CommitA), Artifact(manifest: OtherManifestDigest), default);
        var noEvidence = await provenance.VerifyAsync(
            Request(commit: CommitA, artifactDigest: UnrecordedArtifactDigest), Artifact(UnrecordedArtifactDigest), default);
        var untrusted = await new DirectDeliveryProductionProvenance(
                journal, new HashSignature(2))
            .VerifyAsync(Request(commit: CommitA), Artifact(), default);
        var sourceless = await provenance.VerifyAsync(
            Request(commit: CommitA) with { Source = null }, Artifact(), default);

        await Assert.That(verified.Verified).IsTrue();
        await Assert.That(wrongCommit.Verified).IsFalse();
        await Assert.That(wrongManifest.Verified).IsFalse();
        await Assert.That(noEvidence.Verified).IsFalse();
        await Assert.That(untrusted.Verified).IsFalse();
        await Assert.That(sourceless.Verified).IsFalse();
    }

    [Test]
    public async Task Production_adapter_composition_fails_closed_without_configuration()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);

        await Assert.That(() => DirectDeliveryRuntimeAdapterSet.Create(
                ledger, DirectDeliveryDeploymentMode.Production,
                static () => true, static _ => true,
                admittedTargets: null, evidenceVerifier: trust))
            .Throws<InvalidOperationException>();
        await Assert.That(() => DirectDeliveryRuntimeAdapterSet.Create(
                ledger, DirectDeliveryDeploymentMode.Production,
                static () => true, static _ => true,
                admittedTargets: Targets(), evidenceVerifier: null))
            .Throws<InvalidOperationException>();
        var development = DirectDeliveryRuntimeAdapterSet.Create(
            ledger, DirectDeliveryDeploymentMode.Development,
            static () => true, static _ => true, Targets(), trust);
        await Assert.That(development.ArtifactBuilder).IsNotNull();
    }

    [Test]
    public async Task A_delivery_replays_its_terminal_receipt_after_a_runtime_restart()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        await RecordEvidence(ledger, trust, ArtifactDigest, ManifestDigest, CommitA);
        var first = HandoffRuntime(ledger, trust);
        var receipt = await first.DeliverManifestAsync(Manifest("operation-restart-1"));
        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        var mutations = ledger.Mutations;
        await Assert.That(await CountKeysAsync(ledger, "direct.operation.>")).IsEqualTo(1);
        await Assert.That(await CountKeysAsync(ledger, "direct.target.>")).IsEqualTo(1);

        // Restart: a fresh runtime over the same durable state must not mutate anything to
        // answer the same operation, and must not admit a second journal record for it.
        var restarted = HandoffRuntime(ledger, trust);
        var replay = await restarted.DeliverManifestAsync(Manifest("operation-restart-1"));

        await Assert.That(replay.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        await Assert.That(replay.OperationId).IsEqualTo("operation-restart-1");
        await Assert.That(ledger.Mutations).IsEqualTo(mutations);
        await Assert.That(await CountKeysAsync(ledger, "direct.operation.>")).IsEqualTo(1);
        await Assert.That(await CountKeysAsync(ledger, "direct.target.>")).IsEqualTo(1);
    }

    [Test]
    public async Task A_crash_between_apply_and_persist_resumes_to_success_with_rollback_material_intact()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        // A previous deployment leaves the region running the prior artifact.
        await RecordEvidence(ledger, trust, PreviousArtifactDigest, PreviousManifestDigest, CommitA);
        await HandoffRuntime(ledger, trust).DeliverManifestAsync(
            Manifest("operation-crash-0", PreviousArtifactDigest, PreviousManifestDigest, CommitA));
        var mutations = ledger.Mutations;

        // The crashed run persisted its write-ahead 'applying' record and completed the target
        // mutation, but never persisted 'applied': exactly the durable state a restart sees.
        await RecordEvidence(ledger, trust, ArtifactDigest, ManifestDigest, CommitA);
        var request = DeployHandoffMapper.Map(Manifest("operation-crash-1")).Request!.Delivery;
        await new NatsDirectDeliveryTarget(new LedgerAdapter(ledger))
            .ApplyAsync(request, Artifact(), "gru", default);
        var journal = new NatsDirectDeliveryJournal(ledger);
        await journal.AppendAsync(new(
            "operation-crash-1",
            DirectDeliveryCoordinator.RequestFingerprint(request),
            DeliveryJournalState.Applying,
            null,
            ArtifactDigest,
            [new("gru", "applying", PreviousArtifactDigest, PreviousManifestDigest: PreviousManifestDigest)]), default);

        var restarted = HandoffRuntime(ledger, trust);
        var receipt = await restarted.DeliverManifestAsync(Manifest("operation-crash-1"));

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        var record = await journal.ReadAsync("operation-crash-1", default);
        await Assert.That(record!.State).IsEqualTo(DeliveryJournalState.Succeeded);
        // The pre-mutation identity of the crashed run is still the durable rollback target.
        await Assert.That(record.Regions!.Single(static region => region.Region == "gru")
            .PreviousArtifactDigest).IsEqualTo(PreviousArtifactDigest);
        await Assert.That(ledger.Mutations).IsGreaterThan(mutations);
    }

    [Test]
    public async Task Customer_content_never_moves_through_an_unselected_region()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        await RecordEvidence(ledger, trust, ArtifactDigest, ManifestDigest, CommitA);
        // The allow-list admits gru and sfo, but this delivery selects gru only.
        var receipt = await HandoffRuntime(ledger, trust).DeliverManifestAsync(
            SingleRegionManifest("operation-single-region"));

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        await Assert.That(receipt.Target!.Regions).IsEquivalentTo(["gru"]);
        await Assert.That(await CountKeysAsync(ledger, "direct.target.>")).IsEqualTo(1);
        var record = await new NatsDirectDeliveryJournal(ledger)
            .ReadAsync("operation-single-region", default);
        await Assert.That(record!.Regions!.Select(static region => region.Region)).IsEquivalentTo(["gru"]);
    }

    [Test]
    public async Task An_unadmitted_production_target_fails_closed_without_mutation()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        await RecordEvidence(ledger, trust, ArtifactDigest, ManifestDigest, CommitA);
        var manifest = UnadmittedManifest("operation-unadmitted");

        var receipt = await HandoffRuntime(ledger, trust).DeliverManifestAsync(manifest);

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.UnknownTarget);
        await Assert.That(await CountKeysAsync(ledger, "direct.target.>")).IsEqualTo(0);
    }

    [Test]
    public async Task A_rejected_handoff_manifest_never_reaches_the_target_mutation_path()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        await RecordEvidence(ledger, trust, ArtifactDigest, ManifestDigest, CommitA);
        var unknownField = Manifest("operation-rejected")
            .Replace("\"reason\":", "\"promotionStage\":\"x\",\"reason\":");

        var receipt = await HandoffRuntime(ledger, trust).DeliverManifestAsync(unknownField);

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.InvalidInput);
        await Assert.That(receipt.Error.Message).Contains("handoff_");
        await Assert.That(await CountKeysAsync(ledger, "direct.target.>")).IsEqualTo(0);
        await Assert.That(await CountKeysAsync(ledger, "direct.operation.>")).IsEqualTo(0);
    }

    [Test]
    public async Task A_transplanted_evidence_record_is_corruption_at_the_journal_boundary()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        await RecordEvidence(ledger, trust, ArtifactDigest, ManifestDigest, CommitA);

        // The attack: a KV writer copies the legitimately signed record for digest X under
        // digest Y's key. The journal must reject the key↔content mismatch as corruption.
        var original = await ledger.GetAsync(EvidenceKey(ArtifactDigest), default);
        await ledger.CreateAsync(EvidenceKey(UnrecordedArtifactDigest), original!.Value, default);

        await Assert.That(async () => await new DirectDeliveryArtifactEvidenceJournal(new LedgerAdapter(ledger))
                .ReadAsync(UnrecordedArtifactDigest, default))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task A_transplanted_evidence_record_cannot_admit_an_unattested_digest()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        // The signed record binds commit A and its digests for ArtifactDigest only; the request
        // below matches every recorded field EXCEPT that it deploys UnrecordedArtifactDigest,
        // for which no evidence was ever signed. Only the digest binding separates them.
        await RecordEvidence(ledger, trust, ArtifactDigest, ManifestDigest, CommitA);
        var original = await ledger.GetAsync(EvidenceKey(ArtifactDigest), default);
        await ledger.CreateAsync(EvidenceKey(UnrecordedArtifactDigest), original!.Value, default);

        var receipt = await HandoffRuntime(ledger, trust).DeliverManifestAsync(
            Manifest("operation-transplant", UnrecordedArtifactDigest, ManifestDigest, CommitA));

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.ProvenanceFailed);
        await Assert.That(await CountKeysAsync(ledger, "direct.target.>")).IsEqualTo(0);
    }

    [Test]
    public async Task Evidence_verifies_with_real_ecdsa_keys_and_rejects_wrong_keys_and_other_domains()
    {
        using var identity = EcdsaIdentity.Create();
        using var other = EcdsaIdentity.Create();
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new DirectDeliveryArtifactEvidenceJournal(new LedgerAdapter(ledger));
        await journal.RecordAsync(Evidence(commit: CommitA), identity.Signer, default);
        var recorded = await journal.ReadAsync(ArtifactDigest, default);

        await Assert.That(recorded).IsNotNull();
        await Assert.That(DirectDeliveryArtifactEvidenceJournal.Verifies(recorded!, identity.Verifier)).IsTrue();
        await Assert.That(DirectDeliveryArtifactEvidenceJournal.Verifies(recorded!, other.Verifier)).IsFalse();

        // Cross-domain: a CI artifact-attestation signature over ci/* material must never
        // verify as delivery evidence over the delivery/* material, even from the same key.
        var subject = new RepositoryCiArtifactSubject(
            PlainDigest('a'),
            new("transplant-job"),
            new("TerraScale/TerraScale.Orchestrator"),
            RepositoryCiArchitecture.LinuxArm64,
            new(PlainDigest('b')),
            RepositoryCiArtifactAttestation.EntrypointsDigest(RepositoryCiArchitecture.LinuxArm64, ["app"]));
        var ciSignature = RepositoryCiArtifactAttestation.Sign(subject, identity.Signer).Signature;
        await Assert.That(DirectDeliveryArtifactEvidenceJournal.Verifies(
                new DirectDeliverySignedArtifactEvidence(Evidence(commit: CommitA), identity.Signer.Identity, ciSignature),
                identity.Verifier))
            .IsFalse();
    }

    [Test]
    public async Task Production_composition_refuses_an_empty_admitted_target_set()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var empty = DirectDeliveryAdmittedTargets.Parse([]);

        await Assert.That(empty.IsEmpty).IsTrue();
        await Assert.That(() => DirectDeliveryRuntimeAdapterSet.Create(
                new LedgerAdapter(ledger), DirectDeliveryDeploymentMode.Production,
                static () => true, static _ => true,
                empty, new HashSignature(1)))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Production_has_no_artifact_builder_and_refuses_source_only_requests()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        var (authorizer, provenance, targetResolver, journal, artifactBuilder) =
            DirectDeliveryRuntimeAdapterSet.Create(
                new LedgerAdapter(ledger),
                DirectDeliveryDeploymentMode.Production,
                static () => true,
                static _ => true,
                Targets(),
                trust);
        await Assert.That(artifactBuilder).IsNull();

        var service = new DirectDeliveryService(
            authorizer, provenance, targetResolver, journal, artifactBuilder,
            auditIdFactory: static () => "audit-test");
        var receipt = await service.DeliverAsync(Request(commit: CommitA) with { Artifact = null });

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.InvalidInput);
        await Assert.That(await CountKeysAsync(ledger, "direct.target.>")).IsEqualTo(0);
        await Assert.That(await CountKeysAsync(ledger, "direct.operation.>")).IsEqualTo(0);
    }

    private static DeployHandoffDeliveryRuntime HandoffRuntime(
        ForgejoWebhookJournalTests.TestLedger ledger,
        HashSignature trust)
    {
        var (authorizer, provenance, targetResolver, journal, artifactBuilder) =
            DirectDeliveryRuntimeAdapterSet.Create(
                new LedgerAdapter(ledger),
                DirectDeliveryDeploymentMode.Production,
                static () => true,
                static _ => true,
                Targets(),
                trust);
        return new(new DirectDeliveryService(
            authorizer, provenance, targetResolver, journal, artifactBuilder,
            auditIdFactory: static () => "audit-test"));
    }

    private static DirectDeliveryAdmittedTargets Targets() =>
        DirectDeliveryAdmittedTargets.Parse(["authentication:development:gru,sfo"]);

    private static Task RecordEvidence(
        ForgejoWebhookJournalTests.TestLedger ledger,
        IRepositoryCiArtifactAttestationSigner signer,
        string artifactDigest,
        string manifestDigest,
        string commit) =>
        new DirectDeliveryArtifactEvidenceJournal(new LedgerAdapter(ledger))
            .RecordAsync(
                new DirectDeliveryArtifactEvidence(
                    "TerraScale/TerraScale.Orchestrator", commit, TreeDigest, artifactDigest, manifestDigest, "service"),
                signer,
                default);

    private static async Task<int> CountKeysAsync(
        ForgejoWebhookJournalTests.TestLedger ledger,
        string filter)
    {
        var count = 0;
        await foreach (var _ in ledger.ListKeysAsync(filter, default))
            count++;
        return count;
    }

    private static DirectDeliveryArtifactEvidence Evidence(string commit) => new(
        "TerraScale/TerraScale.Orchestrator", commit, TreeDigest, ArtifactDigest, ManifestDigest, "service");

    private static DeliveryRequest Request(string commit, string artifactDigest = ArtifactDigest) => new(
        1,
        "operation-provenance",
        new("TerraScale/TerraScale.Orchestrator", commit, TreeDigest),
        Artifact(artifactDigest),
        new("authentication", "development", ["gru"]),
        ConfigurationDigest,
        null,
        "actor-1",
        "direct customer change");

    private static DeliveryArtifact Artifact(
        string digest = ArtifactDigest,
        string manifest = ManifestDigest) => new(digest, manifest, "service");

    private static string Manifest(
        string operationId,
        string artifactDigest = ArtifactDigest,
        string manifestDigest = ManifestDigest,
        string commit = CommitA) => $$"""
        {
          "schemaVersion": 1,
          "operationId": "{{operationId}}",
          "source": { "repository": "TerraScale/TerraScale.Orchestrator", "commit": "{{commit}}", "treeDigest": "{{TreeDigest}}" },
          "artifact": { "digest": "{{artifactDigest}}", "manifestDigest": "{{manifestDigest}}", "kind": "service", "architecture": "linux/arm64" },
          "target": { "service": "authentication", "environment": "development", "regions": ["gru"] },
          "configurationRevision": "{{ConfigurationDigest}}",
          "requestedBy": "actor-1",
          "reason": "direct customer change"
        }
        """;

    private static string SingleRegionManifest(string operationId) => Manifest(operationId);

    private static string UnadmittedManifest(string operationId) =>
        Manifest(operationId).Replace("\"environment\": \"development\"", "\"environment\": \"production\"");

    private const string CommitA = "0123456789abcdef0123456789abcdef01234567";
    private const string CommitB = "fedcba9876543210fedcba9876543210fedcba98";
    private const string TreeDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ConfigurationDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string ArtifactDigest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    private const string ManifestDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string OtherManifestDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    private const string UnrecordedArtifactDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    private const string PreviousArtifactDigest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    private const string PreviousManifestDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    /// <summary>A deterministic admitted signing identity: signs and verifies the same digest.</summary>
    internal sealed class HashSignature(byte domain) :
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

    /// <summary>The durable evidence key for one artifact digest, as the journal derives it.</summary>
    private static string EvidenceKey(string artifactDigest) =>
        "direct.evidence." + Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(artifactDigest.ToLowerInvariant())));

    private static string PlainDigest(char value) => new(value, 64);

    /// <summary>An ephemeral real P-256 command identity: signs and verifies real ECDSA envelopes.</summary>
    private sealed class EcdsaIdentity : IDisposable
    {
        private readonly EcdsaCommandSigner signer;
        private readonly string publicPath;

        private EcdsaIdentity(EcdsaCommandSigner signer, string publicPath)
        {
            this.signer = signer;
            this.publicPath = publicPath;
        }

        internal EcdsaCommandSignatureVerifier Verifier { get; private set; } = null!;

        internal EcdsaCommandSigner Signer => signer;

        internal static EcdsaIdentity Create()
        {
            var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var privateKeyPath = Path.Combine(Path.GetTempPath(), $"ts-dd-ev-private-{Guid.NewGuid():N}.pem");
            var publicPath = Path.Combine(Path.GetTempPath(), $"ts-dd-ev-public-{Guid.NewGuid():N}.pem");
            File.WriteAllText(privateKeyPath, key.ExportPkcs8PrivateKeyPem());
            File.WriteAllText(publicPath, key.ExportSubjectPublicKeyInfoPem());
            if (OperatingSystem.IsLinux())
                File.SetUnixFileMode(privateKeyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var signer = EcdsaCommandSigner.LoadPrivatePem(privateKeyPath);
            var identity = new EcdsaIdentity(signer, publicPath)
            {
                Verifier = EcdsaCommandSignatureVerifier.LoadPublicPem([publicPath]),
            };
            File.Delete(privateKeyPath);
            return identity;
        }

        public void Dispose()
        {
            Verifier.Dispose();
            signer.Dispose();
            File.Delete(publicPath);
        }
    }

    /// <summary>Adapts the test ledger to the ledger interface without NATS types.</summary>
    internal sealed class LedgerAdapter(ForgejoWebhookJournalTests.TestLedger ledger) :
        IForgejoDeliveryLedger
    {
        public Task<ForgejoDeliveryLedgerEntry?> GetAsync(string key, CancellationToken cancellationToken) =>
            ledger.GetAsync(key, cancellationToken);

        public Task<ForgejoDeliveryLedgerEntry> CreateAsync(string key, string value, CancellationToken cancellationToken) =>
            ledger.CreateAsync(key, value, cancellationToken);

        public Task<ForgejoDeliveryLedgerEntry> UpdateAsync(string key, string value, ulong revision, CancellationToken cancellationToken) =>
            ledger.UpdateAsync(key, value, revision, cancellationToken);
    }

    /// <summary>A ledger whose every operation fails with an infrastructure-class exception.</summary>
    internal sealed class UnavailableLedger : IForgejoDeliveryLedger
    {
        public Task<ForgejoDeliveryLedgerEntry?> GetAsync(string key, CancellationToken cancellationToken) =>
            throw new IOException("the evidence ledger is unreachable");

        public Task<ForgejoDeliveryLedgerEntry> CreateAsync(string key, string value, CancellationToken cancellationToken) =>
            throw new IOException("the evidence ledger is unreachable");

        public Task<ForgejoDeliveryLedgerEntry> UpdateAsync(string key, string value, ulong revision, CancellationToken cancellationToken) =>
            throw new IOException("the evidence ledger is unreachable");
    }
}
