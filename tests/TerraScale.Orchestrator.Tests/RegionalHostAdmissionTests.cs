using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class RegionalHostAdmissionTests
{
    [Test]
    public async Task Production_configuration_requires_signed_admission_material()
    {
        var environment = new Dictionary<string, string?>
        {
            ["TS_ORCH_HOST_NODE_ID"] = "node-1"
        };

        await Assert.That(() => RegionalHostAdmissionConfiguration.Load(
                key => environment.GetValueOrDefault(key), "gru"))
            .Throws<ArgumentException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Authorized_enrollment_is_cached_after_durable_replay_acceptance(bool jwtCredentials)
    {
        var directory = Directory.CreateTempSubdirectory("ts-host-admission-");
        try
        {
            var now = DateTimeOffset.UtcNow;
            using var grantKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var issuer = new BootstrapGrantIssuer("grant-key", 1,
                BootstrapTrustKeyPurpose.GrantSigning, grantKey);
            using var enrollmentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var enrollmentSigner = new RegionalNodeEnrollmentSigner("enrollment-key", 2, enrollmentKey);
            using var workloadKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest("CN=host", workloadKey,
                HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            using var certificate = request.CreateSelfSigned(now.AddMinutes(-1), now.AddHours(1));
            var fingerprint = BootstrapWorkloadIdentity.CertificateFingerprint(
                certificate.PublicKey.ExportSubjectPublicKeyInfo());
            var natsSeed = NATS.Client.Core.NKeys.CreateUserSeed();
            var natsUser = NATS.Client.Core.NKeys.PublicKeyFromSeed(natsSeed);
            var project = new BootstrapSystemProjectUlds(
                new BootstrapUlid("00000000000000000000000000"),
                new BootstrapUlid("00000000000000000000000001"),
                new BootstrapUlid("00000000000000000000000002"));
            var grant = issuer.Sign(new BootstrapGrantPayload(
                "00000000000000000000000003",
                new string('a', 64),
                issuer.KeyId,
                issuer.KeyVersion,
                BootstrapKeyPurposeCodes.GrantSigning,
                project,
                "node-1",
                fingerprint,
                now.AddSeconds(-1),
                now.AddMinutes(5),
                [BootstrapGrantOperation.EnsureSystemProjectConfiguration]));
            var scope = new RegionalNodeEnrollmentScope("production", [Runtime.AdmittedRole.TerraBaseMember]);
            var enrollment = enrollmentSigner.Sign(
                "GRU", "node-1", 1, "A-account", natsUser,
                new string('0', 64),
                "gru-cluster", scope, grant);

            var enrollmentPath = Path.Combine(directory.FullName, "enrollment.json");
            var signerPath = Path.Combine(directory.FullName, "enrollment-signer.pem");
            var trustPath = Path.Combine(directory.FullName, "trust.json");
            var credentialsPath = Path.Combine(directory.FullName, "credentials.bundle");
            var certificatePath = Path.Combine(directory.FullName, "host.cer");
            var certificateKeyPath = Path.Combine(directory.FullName, "host.key");
            var caPath = Path.Combine(directory.FullName, "host-ca.cer");
            var natsSeedPath = Path.Combine(directory.FullName, "nats.seed");
            var natsContents = jwtCredentials ? NatsAuthenticationFilesTests.Credentials(natsSeed) : natsSeed;
            await File.WriteAllTextAsync(natsSeedPath, natsContents);
            NatsAuthenticationFiles Authentication() => NatsAuthenticationFiles.Resolve(
                jwtCredentials ? null : natsSeedPath, jwtCredentials ? natsSeedPath : null, "test")!;
            await File.WriteAllTextAsync(signerPath, enrollmentKey.ExportSubjectPublicKeyInfoPem());
            await File.WriteAllTextAsync(certificatePath, certificate.ExportCertificatePem());
            await File.WriteAllTextAsync(certificateKeyPath, workloadKey.ExportPkcs8PrivateKeyPem());
            await File.WriteAllTextAsync(caPath, certificate.ExportCertificatePem());
            var credentialManifest = new
            {
                schemaVersion = 1,
                files = new[]
                {
                    new { path = natsSeedPath, sha256 = Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(natsContents))) },
                    new { path = caPath, sha256 = Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(certificate.ExportCertificatePem()))) },
                    new { path = certificatePath, sha256 = Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(certificate.ExportCertificatePem()))) },
                    new { path = certificateKeyPath, sha256 = Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(workloadKey.ExportPkcs8PrivateKeyPem()))) }
                }
            };
            var credentialBytes = JsonSerializer.SerializeToUtf8Bytes(credentialManifest);
            var credentialDigest = Convert.ToHexStringLower(SHA256.HashData(credentialBytes));
            enrollment = enrollmentSigner.Sign(
                "GRU", "node-1", 1, "A-account", natsUser, credentialDigest,
                "gru-cluster", scope, grant);
            await File.WriteAllTextAsync(enrollmentPath, JsonSerializer.Serialize(enrollment));
            await File.WriteAllBytesAsync(credentialsPath, credentialBytes);
            await File.WriteAllTextAsync(trustPath, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                bundleVersion = 1,
                currentGrantSigningKeyId = issuer.KeyId,
                currentGrantSigningKeyVersion = issuer.KeyVersion,
                keys = new[]
                {
                    new
                    {
                        keyId = issuer.KeyId,
                        keyVersion = issuer.KeyVersion,
                        purpose = (int)BootstrapTrustKeyPurpose.GrantSigning,
                        subjectPublicKeyInfo = Convert.ToBase64String(grantKey.ExportSubjectPublicKeyInfo()),
                        acceptedUntil = (DateTimeOffset?)null
                    }
                }
            }));
            if (OperatingSystem.IsLinux())
            {
                File.SetUnixFileMode(credentialsPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                File.SetUnixFileMode(natsSeedPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                File.SetUnixFileMode(certificateKeyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                File.SetUnixFileMode(certificatePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                File.SetUnixFileMode(caPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            var configuration = new RegionalHostAdmissionConfiguration(
                enrollmentPath,
                signerPath,
                trustPath,
                credentialsPath,
                "node-1",
                "GRU",
                "A-account",
                "gru-cluster",
                "enrollment-key",
                2,
                project,
                BootstrapGrantOperation.EnsureSystemProjectConfiguration,
                TimeSpan.FromMinutes(15), scope);

            File.Delete(credentialsPath);
            var pendingReplay = new FakeReplayStore();
            using (var pendingGate = RegionalHostAdmissionGate.LoadForTests(
                       configuration,
                       pendingReplay,
                       Authentication(),
                       new NatsTlsFiles(caPath, certificatePath, certificateKeyPath)))
            {
                var pending = await pendingGate.ObserveAsync(CancellationToken.None);
                await Assert.That(pending.Ready).IsFalse();
                await Assert.That(pending.Reason).IsEqualTo("credential-bundle-not-ready");
                await Assert.That(pendingReplay.Calls).IsEqualTo(0);
            }
            await File.WriteAllBytesAsync(credentialsPath, credentialBytes);
            if (OperatingSystem.IsLinux())
                File.SetUnixFileMode(credentialsPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            var wrongAccountReplay = new FakeReplayStore();
            using (var wrongAccountGate = RegionalHostAdmissionGate.LoadForTests(
                       configuration with { NatsAccountPublicKey = "A-other" },
                       wrongAccountReplay,
                       Authentication(),
                       new NatsTlsFiles(caPath, certificatePath, certificateKeyPath)))
            {
                var wrongAccount = await wrongAccountGate.ObserveAsync(CancellationToken.None);
                await Assert.That(wrongAccount.Ready).IsFalse();
                await Assert.That(wrongAccount.Reason).IsEqualTo("regional-enrollment-AccountMismatch");
                await Assert.That(wrongAccountReplay.Calls).IsEqualTo(0);
            }

            foreach (var wrongScope in new[]
                     {
                         new RegionalNodeEnrollmentScope("staging", [Runtime.AdmittedRole.TerraBaseMember]),
                         new RegionalNodeEnrollmentScope("production", [Runtime.AdmittedRole.Authentication]),
                         new RegionalNodeEnrollmentScope("production", [Runtime.AdmittedRole.TerraBaseMember, Runtime.AdmittedRole.Authentication]),
                     })
            {
                var wrongScopeReplay = new FakeReplayStore();
                using var wrongScopeGate = RegionalHostAdmissionGate.LoadForTests(
                    configuration with { Scope = wrongScope }, wrongScopeReplay, Authentication(),
                    new NatsTlsFiles(caPath, certificatePath, certificateKeyPath));
                var wrongScopeResult = await wrongScopeGate.ObserveAsync(CancellationToken.None);
                await Assert.That(wrongScopeResult.Ready).IsFalse();
                await Assert.That(wrongScopeResult.Reason).IsEqualTo("regional-enrollment-ScopeMismatch");
                await Assert.That(wrongScopeReplay.Calls).IsEqualTo(0);
            }
            using var startupDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var runtimeError = await Assert.That(async () =>
            {
                await using var runtime = await NatsRuntime.StartAsync(
                    new OrchestratorOptions(OrchestratorCommand.Check, "gru", "nats://127.0.0.1:1", 1, "node-1"),
                    startupDeadline.Token,
                    hostConvergence: new HostConvergenceConfiguration([Runtime.AdmittedRole.Authentication],
                        "production", directory.FullName, Runtime.HostArchitecture.Arm64),
                    hostAdmission: configuration);
            }).Throws<InvalidOperationException>();
            await Assert.That(runtimeError!.Message).Contains("roles and environment");

            var replay = new FakeReplayStore();
            using var gate = RegionalHostAdmissionGate.LoadForTests(
                configuration,
                replay,
                Authentication(),
                new NatsTlsFiles(caPath, certificatePath, certificateKeyPath));

            var first = await gate.ObserveAsync(CancellationToken.None);
            var second = await gate.ObserveAsync(CancellationToken.None);

            await Assert.That(first.Ready).IsTrue();
            await Assert.That(second.Ready).IsTrue();
            await Assert.That(replay.Calls).IsEqualTo(1);
        }
        finally
        {
            Directory.Delete(directory.FullName, recursive: true);
        }
    }

    private sealed class FakeReplayStore : IRegionalNodeEnrollmentDurableReplayStore
    {
        private readonly InMemoryRegionalNodeEnrollmentReplayStore inner = new();
        public int Calls { get; private set; }

        public ValueTask<bool> TryAcceptAsync(
            string nodeId,
            ulong generation,
            string grantId,
            string nonce,
            CancellationToken cancellationToken)
        {
            Calls++;
            return ValueTask.FromResult(inner.TryAccept(nodeId, generation, grantId, nonce));
        }
    }
}
