using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Contracts;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Regression coverage for the signed direct-delivery mutation seam: no request reaches the
/// coordinator before its command envelope validates (signature, cell, validity window, payload
/// digest, canonical bytes).
/// </summary>
public sealed class DirectDeliveryCommandWireTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 24, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Valid_signed_envelope_round_trips_to_the_exact_request()
    {
        using var identity = KeyIdentity.Create();
        var (payload, headers) = identity.Encode(Request(), "gru");

        var receipt = DirectDeliveryCommandWire.Decode(
            payload,
            headers,
            "gru",
            Now,
            TimeSpan.FromMinutes(5),
            identity.Verifier);

        await Assert.That(receipt.Error).IsEqualTo(DirectDeliveryCommandWireError.None);
        await Assert.That(receipt.ValidationError).IsEqualTo(CommandValidationError.None);
        await Assert.That(receipt.Request!.OperationId).IsEqualTo("operation-1");
        await Assert.That(receipt.Request!.Target!.Regions!).IsEquivalentTo(["gru", "sfo"]);
    }

    [Test]
    public async Task VersionOneReceiptsMatchTheDeployWireFixtures()
    {
        var source = new DeliverySource("TerraScale/TerraScale.Orchestrator", new string('a', 40), ValidDigest);
        var target = new DeliveryTarget("authentication", "development", ["gru", "sfo"]);
        var rollback = new DeliveryRollback(false, null, DeliveryRollbackStatus.NotRequired, null);
        var success = new DeliveryReceipt(
            1,
            "operation-1",
            DeliveryReceiptStatus.Succeeded,
            source,
            ArtifactDigest,
            target,
            new DeliveryProvenance(true, ValidDigest, null),
            new DeliveryHealth([new DeliveryHealthCheck("http", DeliveryHealthStatus.Passed)], true),
            rollback,
            "audit-1",
            new DeliveryErrorInfo(null, null, null),
            ValidDigest);
        var preArtifactFailure = new DeliveryReceipt(
            1,
            "operation-1",
            DeliveryReceiptStatus.Failed,
            source,
            null,
            target,
            new DeliveryProvenance(false, ValidDigest, null),
            new DeliveryHealth([], false),
            rollback,
            "audit-1",
            new DeliveryErrorInfo(
                DirectDeliveryErrorCode.UnauthorizedActor,
                "The actor is not authorized for this target.",
                "Use an authenticated actor with deployment permission."),
            null);

        await Assert.That(DeliveryWireCodec.SerializeReceipt(success)).IsEqualTo(SuccessReceiptJson);
        await Assert.That(DeliveryWireCodec.SerializeReceipt(preArtifactFailure)).IsEqualTo(PreArtifactFailureReceiptJson);
    }

    [Test]
    public async Task Authority_generation_writer_epoch_and_attempt_are_carried_and_signed()
    {
        using var identity = KeyIdentity.Create();
        var request = Request() with { AuthorityGeneration = 7, WriterEpoch = 5, Attempt = 3 };
        var (payload, headers) = identity.Encode(request, "gru");

        await Assert.That(headers["Generation"]).IsEqualTo("7");
        await Assert.That(headers["Epoch"]).IsEqualTo("5");
        await Assert.That(headers["Attempt"]).IsEqualTo("3");
        var receipt = DirectDeliveryCommandWire.Decode(
            payload, headers, "gru", Now, TimeSpan.FromMinutes(5), identity.Verifier);

        await Assert.That(receipt.Error).IsEqualTo(DirectDeliveryCommandWireError.None);
        // JSON round-trip rebuilds Regions as a List; compare the fields that define identity
        // rather than record equality over IReadOnlyList collection types.
        await Assert.That(receipt.Request!.OperationId).IsEqualTo(request.OperationId);
        await Assert.That(receipt.Request.AuthorityGeneration).IsEqualTo(request.AuthorityGeneration);
        await Assert.That(receipt.Request.WriterEpoch).IsEqualTo(request.WriterEpoch);
        await Assert.That(receipt.Request.Attempt).IsEqualTo(request.Attempt);
        await Assert.That(receipt.Request.Target!.Regions!)
            .IsEquivalentTo(request.Target!.Regions!);
    }

    [Test]
    public async Task Tampered_payload_headers_and_operation_identity_fail_closed()
    {
        using var identity = KeyIdentity.Create();
        var (payload, headers) = identity.Encode(Request(), "gru");

        var tamperedPayload = DirectDeliveryCommandWire.Decode(
            Encoding.UTF8.GetBytes(
                Encoding.UTF8.GetString(payload).Replace("operation-1", "operation-2", StringComparison.Ordinal)),
            headers,
            "gru",
            Now,
            TimeSpan.FromMinutes(5),
            identity.Verifier);
        var staleDigest = DirectDeliveryCommandWire.Decode(
            payload,
            Copy(headers, "PayloadSha256", new string('0', 64)),
            "gru",
            Now,
            TimeSpan.FromMinutes(5),
            identity.Verifier);
        var wrongCell = DirectDeliveryCommandWire.Decode(
            payload,
            Copy(headers, "Cell", "sfo"),
            "gru",
            Now,
            TimeSpan.FromMinutes(5),
            identity.Verifier);
        var wrongOperation = DirectDeliveryCommandWire.Decode(
            payload,
            Copy(headers, "Operation", "operation-2"),
            "gru",
            Now,
            TimeSpan.FromMinutes(5),
            identity.Verifier);
        var nonCanonical = DirectDeliveryCommandWire.Decode(
            Encoding.UTF8.GetBytes(" " + Encoding.UTF8.GetString(payload)),
            headers,
            "gru",
            Now,
            TimeSpan.FromMinutes(5),
            identity.Verifier);

        await Assert.That(tamperedPayload.Error).IsEqualTo(DirectDeliveryCommandWireError.MalformedEnvelope);
        await Assert.That(staleDigest.Error).IsEqualTo(DirectDeliveryCommandWireError.MalformedEnvelope);
        await Assert.That(wrongCell.Error).IsEqualTo(DirectDeliveryCommandWireError.MalformedEnvelope);
        await Assert.That(wrongOperation.Error).IsEqualTo(DirectDeliveryCommandWireError.MalformedEnvelope);
        await Assert.That(nonCanonical.Error).IsEqualTo(DirectDeliveryCommandWireError.MalformedEnvelope);
        await Assert.That(tamperedPayload.Request).IsNull();
    }

    [Test]
    public async Task Signature_validity_window_and_header_failures_reject_with_typed_errors()
    {
        using var identity = KeyIdentity.Create();
        var (payload, headers) = identity.Encode(Request(), "gru");

        var badSignature = DirectDeliveryCommandWire.Decode(
            payload,
            Copy(headers, "Signature", Convert.ToBase64String(new byte[64])),
            "gru",
            Now,
            TimeSpan.FromMinutes(5),
            identity.Verifier);
        var expired = DirectDeliveryCommandWire.Decode(
            payload,
            headers,
            "gru",
            Now.AddDays(2),
            TimeSpan.FromMinutes(5),
            identity.Verifier);
        var untrustedKey = DirectDeliveryCommandWire.Decode(
            payload,
            headers,
            "gru",
            Now,
            TimeSpan.FromMinutes(5),
            UntrustedVerifier());
        var missingHeaders = DirectDeliveryCommandWire.Decode(
            payload,
            headers.Where(static item => item.Key != "Signature"),
            "gru",
            Now,
            TimeSpan.FromMinutes(5),
            identity.Verifier);

        await Assert.That(badSignature.Error).IsEqualTo(DirectDeliveryCommandWireError.ValidationRejected);
        await Assert.That(badSignature.ValidationError).IsEqualTo(CommandValidationError.InvalidSignature);
        await Assert.That(expired.Error).IsEqualTo(DirectDeliveryCommandWireError.ValidationRejected);
        await Assert.That(expired.ValidationError).IsEqualTo(CommandValidationError.Expired);
        await Assert.That(untrustedKey.Error).IsEqualTo(DirectDeliveryCommandWireError.ValidationRejected);
        await Assert.That(untrustedKey.ValidationError).IsEqualTo(CommandValidationError.InvalidSignature);
        await Assert.That(missingHeaders.Error).IsEqualTo(DirectDeliveryCommandWireError.MalformedEnvelope);
        await Assert.That(badSignature.Request).IsNull();
        await Assert.That(expired.Request).IsNull();
    }

    [Test]
    public async Task ExtremeHeaderTimestampsAreMalformedNeverAnUnhandledThrow()
    {
        using var identity = KeyIdentity.Create();
        var (payload, headers) = identity.Encode(Request(), "gru");

        foreach (var extreme in new[] { long.MaxValue, long.MinValue })
        {
            var issued = Copy(headers, "Issued", extreme.ToString(System.Globalization.CultureInfo.InvariantCulture));
            var expires = Copy(headers, "Expires", extreme.ToString(System.Globalization.CultureInfo.InvariantCulture));
            var byIssued = DirectDeliveryCommandWire.Decode(
                payload, issued, "gru", Now, TimeSpan.FromMinutes(5), identity.Verifier);
            var byExpires = DirectDeliveryCommandWire.Decode(
                payload, expires, "gru", Now, TimeSpan.FromMinutes(5), identity.Verifier);

            await Assert.That(byIssued.Error).IsEqualTo(DirectDeliveryCommandWireError.MalformedEnvelope);
            await Assert.That(byIssued.Request).IsNull();
            await Assert.That(byExpires.Error).IsEqualTo(DirectDeliveryCommandWireError.MalformedEnvelope);
            await Assert.That(byExpires.Request).IsNull();
        }
    }

    [Test]
    public async Task PayloadAndHeaderAuthorityIdentityMismatchIsMalformed()
    {
        // Headers carry (and the signature covers) Generation=7 while the canonical payload
        // JSON says authorityGeneration=8: the envelope itself validates, so the mismatch must
        // surface as MalformedEnvelope at the identity binding — a signed lie about identity is
        // never admitted as a valid request.
        using var identity = KeyIdentity.Create();
        var request = Request() with { AuthorityGeneration = 8 };
        var payload = Encoding.UTF8.GetBytes(DeliveryWireCodec.SerializeRequest(request));
        var digest = Convert.FromHexString(Convert.ToHexStringLower(SHA256.HashData(payload)));
        var headerGeneration = 7L;
        var material = new CommandSignedMaterial(
            ProtocolRevision.TryCreate(1, out var protocol) ? protocol : default,
            CellId.TryCreate("gru", out var cell) ? cell : default,
            AggregateId.TryCreate(DirectDeliveryCommandWire.Aggregate, out var aggregate) ? aggregate : default,
            DesiredGeneration.TryCreate(headerGeneration, out var generation) ? generation : default,
            WriterEpoch.TryCreate(1, out var epoch) ? epoch : default,
            OperationId.TryCreate(request.OperationId!, out var operation) ? operation : default,
            IdempotencyKey.TryCreate(request.OperationId!, out var idempotency) ? idempotency : default,
            Now.AddMinutes(-1),
            Now.AddMinutes(10),
            DeliveryAttempt.TryCreate(1, out var attempt) ? attempt : default,
            OpaquePayload.CopyFrom(payload),
            PayloadDigest.TryCopyFrom(digest, out var payloadDigest) && payloadDigest is not null
                ? payloadDigest
                : throw new InvalidOperationException("The test payload digest is invalid."));
        var signature = identity.Sign(material);
        var headers = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Schema"] = "1",
            ["Protocol"] = "1",
            ["Type"] = "direct-delivery",
            ["Cell"] = "gru",
            ["Operation"] = request.OperationId!,
            ["Generation"] = headerGeneration.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Epoch"] = "1",
            ["Attempt"] = "1",
            ["Issued"] = Now.AddMinutes(-1).ToUnixTimeMilliseconds()
                .ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Expires"] = Now.AddMinutes(10).ToUnixTimeMilliseconds()
                .ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["PayloadSha256"] = Convert.ToHexStringLower(SHA256.HashData(payload)),
            ["Signature"] = Convert.ToBase64String(signature.Bytes),
        };

        var receipt = DirectDeliveryCommandWire.Decode(
            payload, headers, "gru", Now, TimeSpan.FromMinutes(5), identity.Verifier);

        await Assert.That(receipt.Error).IsEqualTo(DirectDeliveryCommandWireError.MalformedEnvelope);
        await Assert.That(receipt.Request).IsNull();
    }

    private static EcdsaCommandSignatureVerifier UntrustedVerifier()
    {
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pem = other.ExportSubjectPublicKeyInfoPem();
        var path = Path.Combine(Path.GetTempPath(), $"ts-dd-untrusted-{Guid.NewGuid():N}.pem");
        File.WriteAllText(path, pem);
        return EcdsaCommandSignatureVerifier.LoadPublicPem([path]);
    }

    private static Dictionary<string, string> Copy(Dictionary<string, string> headers, string name, string value) =>
        new(headers, StringComparer.Ordinal) { [name] = value };

    private static DeliveryRequest Request() => new(
        1,
        "operation-1",
        new("TerraScale/TerraScale.Orchestrator", new string('a', 40), ValidDigest),
        new(ArtifactDigest, ValidDigest, "service"),
        new("authentication", "development", ["gru", "sfo"]),
        ValidDigest,
        null,
        "actor-1",
        "direct customer change");

    private const string ValidDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ArtifactDigest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    private const string SuccessReceiptJson = """{"schemaVersion":1,"operationId":"operation-1","status":"succeeded","source":{"repository":"TerraScale/TerraScale.Orchestrator","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","treeDigest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},"artifactDigest":"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","target":{"service":"authentication","environment":"development","regions":["gru","sfo"]},"provenance":{"verified":true,"configurationRevision":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","migrationRevision":null},"health":{"checks":[{"name":"http","status":"passed"}],"converged":true},"rollback":{"attempted":false,"targetArtifactDigest":null,"status":"not_required","targetManifestDigest":null},"auditId":"audit-1","error":{"code":null,"message":null,"remediation":null},"artifactManifestDigest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}""";
    private const string PreArtifactFailureReceiptJson = """{"schemaVersion":1,"operationId":"operation-1","status":"failed","source":{"repository":"TerraScale/TerraScale.Orchestrator","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","treeDigest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},"artifactDigest":null,"target":{"service":"authentication","environment":"development","regions":["gru","sfo"]},"provenance":{"verified":false,"configurationRevision":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","migrationRevision":null},"health":{"checks":[],"converged":false},"rollback":{"attempted":false,"targetArtifactDigest":null,"status":"not_required","targetManifestDigest":null},"auditId":"audit-1","error":{"code":"unauthorized_actor","message":"The actor is not authorized for this target.","remediation":"Use an authenticated actor with deployment permission."},"artifactManifestDigest":null}""";

    private sealed class KeyIdentity : IDisposable
    {
        private readonly EcdsaCommandSigner signer;
        private readonly string publicPath;

        private KeyIdentity(EcdsaCommandSigner signer, string publicPath)
        {
            this.signer = signer;
            this.publicPath = publicPath;
        }

        internal EcdsaCommandSignatureVerifier Verifier { get; private set; } = null!;

        internal static KeyIdentity Create()
        {
            var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var privateKeyPath = Path.Combine(Path.GetTempPath(), $"ts-dd-private-{Guid.NewGuid():N}.pem");
            var publicPath = Path.Combine(Path.GetTempPath(), $"ts-dd-public-{Guid.NewGuid():N}.pem");
            File.WriteAllText(privateKeyPath, key.ExportPkcs8PrivateKeyPem());
            File.WriteAllText(publicPath, key.ExportSubjectPublicKeyInfoPem());
            if (OperatingSystem.IsLinux())
                File.SetUnixFileMode(privateKeyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var signer = EcdsaCommandSigner.LoadPrivatePem(privateKeyPath);
            var identity = new KeyIdentity(signer, publicPath)
            {
                Verifier = EcdsaCommandSignatureVerifier.LoadPublicPem([publicPath]),
            };
            File.Delete(privateKeyPath);
            return identity;
        }

        internal TerraScale.Orchestrator.Delivery.EcdsaCommandSigner Signer => signer;

        internal OpaqueSignature Sign(CommandSignedMaterial material) => signer.Sign(material);

        internal (byte[] Payload, Dictionary<string, string> Headers) Encode(
            DeliveryRequest request,
            string cell)
        {
            var (payload, headers) = DirectDeliveryCommandWire.Encode(
                request,
                cell,
                Now.AddMinutes(-1),
                Now.AddMinutes(10),
                signer.Sign);
            return (payload, new Dictionary<string, string>(headers, StringComparer.Ordinal));
        }

        public void Dispose()
        {
            signer.Dispose();
            Verifier.Dispose();
            File.Delete(publicPath);
        }
    }
}

