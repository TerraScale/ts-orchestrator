using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Delivery.DeployHandoff;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// The signed payload-kind ingress behind the direct-delivery mutation endpoint: exactly two
/// canonical payload shapes are admitted behind one signed seam, a signed handoff manifest
/// executes as ONE canonical journaled DeliveryRequest bound to the live authority lease, and
/// tampered, unsigned, non-canonical, or mapper-rejected input fails closed with a typed refusal.
/// </summary>
public sealed class DirectDeliveryCommandIngressTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 25, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task A_signed_manifest_executes_as_one_canonical_journaled_delivery_request()
    {
        using var identity = EcdsaIdentity.Create();
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        await RecordEvidence(ledger, identity);
        var manifest = CanonicalManifest("operation-ingress-1");
        var (payload, headers) = Sign(manifest, identity);

        // The endpoint observes a live lease of generation 9 / epoch 4. The manifest signer
        // cannot claim that lease, so its envelope carries no lease claims: admission still
        // succeeds for the manifest kind and the runtime stamps the live lease at execution.
        var admission = Decode(payload, headers, identity, expectedGeneration: 9, expectedEpoch: 4);
        await Assert.That(admission.Kind).IsEqualTo(DirectDeliveryCommandPayloadKind.DeployHandoffManifest);
        await Assert.That(admission.IsExecutable).IsTrue();

        var receipt = await new DeployHandoffDeliveryRuntime(DeliveryService(ledger, identity.Verifier))
            .DeliverMappedAsync(admission.Handoff!, 9, 4, admission.Attempt);

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        await Assert.That(await CountKeysAsync(ledger, "direct.operation.>")).IsEqualTo(1);
        await Assert.That(await CountKeysAsync(ledger, "direct.target.>")).IsEqualTo(1);
        var record = await new NatsDirectDeliveryJournal(new DirectDeliveryProductionAdapterTests.LedgerAdapter(ledger))
            .ReadAsync("operation-ingress-1", default);
        var stamped = DirectDeliveryCoordinator.RequestFingerprint(admission.Handoff!.Request!.Delivery with
        {
            AuthorityGeneration = 9,
            WriterEpoch = 4,
            Attempt = admission.Attempt,
        });
        await Assert.That(record).IsNotNull();
        await Assert.That(record!.RequestFingerprint).IsEqualTo(stamped);
        await Assert.That(record.AuthorityGeneration).IsEqualTo(9);
        await Assert.That(record.WriterEpoch).IsEqualTo(4);

        // A duplicate delivery of the same signed envelope replays the same terminal receipt
        // and journals nothing new.
        var replay = await new DeployHandoffDeliveryRuntime(DeliveryService(ledger, identity.Verifier))
            .DeliverMappedAsync(Decode(payload, headers, identity, 9, 4).Handoff!, 9, 4, 1);
        await Assert.That(replay.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        await Assert.That(await CountKeysAsync(ledger, "direct.operation.>")).IsEqualTo(1);
    }

    [Test]
    public async Task A_signed_delivery_request_still_passes_the_lease_fence_through_the_ingress()
    {
        using var identity = EcdsaIdentity.Create();
        var request = Request(authorityGeneration: 9, writerEpoch: 4);
        var (payload, headers) = DirectDeliveryCommandWire.Encode(
            request, "gru", Now.AddMinutes(-1), Now.AddMinutes(10), identity.Signer.Sign);

        var admitted = Decode(payload, headers, identity, expectedGeneration: 9, expectedEpoch: 4);
        var stale = Decode(payload, headers, identity, expectedGeneration: 10, expectedEpoch: 4);

        await Assert.That(admitted.Kind).IsEqualTo(DirectDeliveryCommandPayloadKind.DeliveryRequest);
        await Assert.That(admitted.Request!.OperationId).IsEqualTo(request.OperationId);
        await Assert.That(admitted.IsExecutable).IsTrue();
        await Assert.That(stale.Kind).IsEqualTo(DirectDeliveryCommandPayloadKind.None);
        await Assert.That(stale.Error).IsEqualTo(DirectDeliveryCommandWireError.ValidationRejected);
        await Assert.That(stale.ValidationError).IsEqualTo(CommandValidationError.StaleGeneration);
        await Assert.That(DirectDeliveryCommandIngress.RefusalReceipt(stale).Error.Code)
            .IsEqualTo(DirectDeliveryErrorCode.UnauthorizedActor);
    }

    [Test]
    public async Task A_tampered_payload_is_refused_before_any_dispatch()
    {
        using var identity = EcdsaIdentity.Create();
        var (payload, headers) = Sign(CanonicalManifest("operation-tampered"), identity);
        // One flipped payload byte breaks the signed payload digest.
        payload[10] ^= 1;

        var admission = Decode(payload, headers, identity, expectedGeneration: 9, expectedEpoch: 4);

        await Assert.That(admission.Kind).IsEqualTo(DirectDeliveryCommandPayloadKind.None);
        await Assert.That(admission.Error).IsEqualTo(DirectDeliveryCommandWireError.MalformedEnvelope);
        await Assert.That(DirectDeliveryCommandIngress.RefusalReceipt(admission).Error.Code)
            .IsEqualTo(DirectDeliveryErrorCode.InvalidInput);
    }

    [Test]
    public async Task An_unsigned_or_wrongly_signed_manifest_is_a_typed_denial()
    {
        using var identity = EcdsaIdentity.Create();
        using var other = EcdsaIdentity.Create();
        var (payload, headers) = Sign(CanonicalManifest("operation-unsigned"), identity);
        var garbageSignature = new Dictionary<string, string>(headers, StringComparer.Ordinal)
        {
            ["Signature"] = Convert.ToBase64String(SHA256.HashData(Guid.NewGuid().ToByteArray())),
        };
        var byUntrustedKey = Sign(CanonicalManifest("operation-unsigned"), other);

        var badSignature = Decode(payload, garbageSignature, identity, expectedGeneration: 9, expectedEpoch: 4);
        var untrustedKey = Decode(byUntrustedKey.Payload, byUntrustedKey.Headers, identity,
            expectedGeneration: 9, expectedEpoch: 4);

        await Assert.That(badSignature.Kind).IsEqualTo(DirectDeliveryCommandPayloadKind.None);
        await Assert.That(badSignature.Error).IsEqualTo(DirectDeliveryCommandWireError.ValidationRejected);
        await Assert.That(untrustedKey.Kind).IsEqualTo(DirectDeliveryCommandPayloadKind.None);
        await Assert.That(untrustedKey.Error).IsEqualTo(DirectDeliveryCommandWireError.ValidationRejected);
        await Assert.That(DirectDeliveryCommandIngress.RefusalReceipt(badSignature).Error.Code)
            .IsEqualTo(DirectDeliveryErrorCode.UnauthorizedActor);
        await Assert.That(DirectDeliveryCommandIngress.RefusalReceipt(untrustedKey).Error.Code)
            .IsEqualTo(DirectDeliveryErrorCode.UnauthorizedActor);
    }

    [Test]
    public async Task A_non_canonical_manifest_or_mismatched_operation_identity_is_refused()
    {
        using var identity = EcdsaIdentity.Create();
        var canonical = CanonicalManifest("operation-canonical");
        var spaced = " " + canonical;
        var (spacedPayload, spacedHeaders) = SignBytes(Encoding.UTF8.GetBytes(spaced), "operation-canonical", identity);
        var (payload, headers) = Sign(canonical, identity, operationId: "operation-canonical" + "-other");

        var nonCanonical = Decode(spacedPayload, spacedHeaders, identity, expectedGeneration: 9, expectedEpoch: 4);
        var mismatched = Decode(payload, headers, identity, expectedGeneration: 9, expectedEpoch: 4);

        await Assert.That(nonCanonical.Kind).IsEqualTo(DirectDeliveryCommandPayloadKind.None);
        await Assert.That(nonCanonical.Error).IsEqualTo(DirectDeliveryCommandWireError.MalformedEnvelope);
        await Assert.That(mismatched.Kind).IsEqualTo(DirectDeliveryCommandPayloadKind.None);
        await Assert.That(mismatched.Error).IsEqualTo(DirectDeliveryCommandWireError.MalformedEnvelope);
    }

    [Test]
    public async Task A_mapper_rejected_manifest_produces_a_refusal_naming_the_handoff_error()
    {
        using var identity = EcdsaIdentity.Create();
        var secret = CanonicalManifest("operation-secret") .Replace(
            "\"reason\":\"direct customer change\"",
            "\"reason\":\"password: hunter2\"");
        var (payload, headers) = Sign(secret, identity);

        var admission = Decode(payload, headers, identity, expectedGeneration: 9, expectedEpoch: 4);
        var refusal = DirectDeliveryCommandIngress.RefusalReceipt(admission);

        await Assert.That(admission.Kind).IsEqualTo(DirectDeliveryCommandPayloadKind.DeployHandoffManifest);
        await Assert.That(admission.IsExecutable).IsFalse();
        await Assert.That(refusal.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(refusal.Error.Code).IsEqualTo(DirectDeliveryErrorCode.InvalidInput);
        await Assert.That(refusal.Error.Message).Contains("handoff_secret_rejected");
    }

    private static DirectDeliveryCommandAdmission Decode(
        byte[] payload,
        IReadOnlyDictionary<string, string> headers,
        EcdsaIdentity identity,
        long expectedGeneration,
        long expectedEpoch) =>
        DirectDeliveryCommandIngress.Decode(
            payload,
            headers,
            "gru",
            Now,
            TimeSpan.FromMinutes(5),
            identity.Verifier,
            expectedGeneration,
            expectedEpoch);

    private static (byte[] Payload, IReadOnlyDictionary<string, string> Headers) Sign(
        string manifestJson,
        EcdsaIdentity identity,
        string? operationId = null) =>
        SignBytes(
            Encoding.UTF8.GetBytes(manifestJson),
            // The envelope's operation identity is the manifest's own operationId: the signed
            // claim and the payload claim must name the same operation.
            operationId ?? JsonDocument.Parse(manifestJson).RootElement.GetProperty("operationId").GetString()
                ?? string.Empty,
            identity);

    private static (byte[] Payload, IReadOnlyDictionary<string, string> Headers) SignBytes(
        byte[] payload,
        string operationId,
        EcdsaIdentity identity)
    {
        var headers = DirectDeliveryCommandWire.EncodeSignedHeaders(
            payload,
            operationId,
            generation: 1,
            epoch: 1,
            attempt: 1,
            "gru",
            Now.AddMinutes(-1),
            Now.AddMinutes(10),
            identity.Signer.Sign);
        return (payload, headers);
    }

    private static string CanonicalManifest(string operationId) =>
        DeployHandoffMapper.SerializeManifest(new DeployHandoffManifest(
            1,
            operationId,
            new DeployHandoffSource("TerraScale/TerraScale.Orchestrator", Commit, TreeDigest),
            new DeployHandoffArtifact(
                "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "package",
                "linux/arm64"),
            null,
            new DeployHandoffTarget("authentication", "development", ["gru"]),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            null,
            "actor-1",
            "direct customer change",
            null));

    private static DeliveryRequest Request(long authorityGeneration, long writerEpoch) => new(
        1,
        "operation-direct",
        new("TerraScale/TerraScale.Orchestrator", Commit, TreeDigest),
        new(
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "package"),
        new("authentication", "development", ["gru"]),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        null,
        "actor-1",
        "direct customer change",
        authorityGeneration,
        writerEpoch);

    private static DirectDeliveryService DeliveryService(
        ForgejoWebhookJournalTests.TestLedger ledger,
        IRepositoryCiArtifactSignatureVerifier evidenceVerifier)
    {
        var (authorizer, provenance, targetResolver, journal, artifactBuilder) =
            DirectDeliveryRuntimeAdapterSet.Create(
                new DirectDeliveryProductionAdapterTests.LedgerAdapter(ledger),
                DirectDeliveryDeploymentMode.Production,
                static () => true,
                static _ => true,
                DirectDeliveryAdmittedTargets.Parse(["authentication:development:gru"]),
                evidenceVerifier);
        return new(authorizer, provenance, targetResolver, journal, artifactBuilder,
            auditIdFactory: static () => "audit-test");
    }

    private static Task RecordEvidence(
        ForgejoWebhookJournalTests.TestLedger ledger,
        EcdsaIdentity identity)
    {
        return new DirectDeliveryArtifactEvidenceJournal(new DirectDeliveryProductionAdapterTests.LedgerAdapter(ledger))
            .RecordAsync(
                new DirectDeliveryArtifactEvidence(
                    "TerraScale/TerraScale.Orchestrator",
                    Commit,
                    TreeDigest,
                    "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "package"),
                identity.Signer,
                default);
    }

    private static async Task<int> CountKeysAsync(ForgejoWebhookJournalTests.TestLedger ledger, string filter)
    {
        var count = 0;
        await foreach (var _ in ledger.ListKeysAsync(filter, default))
            count++;
        return count;
    }

    private const string Commit = "0123456789abcdef0123456789abcdef01234567";
    private const string TreeDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// <summary>An ephemeral real P-256 command identity for signing and verifying envelopes.</summary>
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
            var privateKeyPath = Path.Combine(Path.GetTempPath(), $"ts-dd-in-private-{Guid.NewGuid():N}.pem");
            var publicPath = Path.Combine(Path.GetTempPath(), $"ts-dd-in-public-{Guid.NewGuid():N}.pem");
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
}
