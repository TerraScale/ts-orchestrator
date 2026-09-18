using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Operations;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// The operator's deploy encoding must be admitted by the controller's signed-command decoder:
/// the exact manifest ComposeManifest produces, signed the way the CLI signs it, decodes into
/// an executable mapping with no error and no lease claim.
/// </summary>
public sealed class OperatorDeployWireTests
{
    [Test]
    public async Task OperatorSignedManifestIsAdmittedByTheControllerDecoder()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-operator-deploy-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var privateKey = Path.Combine(directory, "operator.pem");
            var publicKey = Path.Combine(directory, "operator.pub.pem");
            var privateKeyPem = key.ExportPkcs8PrivateKeyPem();
            var publicKeyPem = key.ExportSubjectPublicKeyInfoPem();
            await File.WriteAllTextAsync(privateKey, privateKeyPem);
            await File.WriteAllTextAsync(publicKey, publicKeyPem);
            if (OperatingSystem.IsLinux())
                File.SetUnixFileMode(privateKey, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            var values = OperatorCli.ParseValues(
            [
                "--key-file", privateKey,
                "--service", "terrabase-server",
                "--digest", "sha256:" + new string('1', 64),
                "--manifest-digest", "sha256:" + new string('2', 64),
                "--regions", "gru,sfo",
                "--source-repository", "TerraScale/TerraBase",
                "--source-commit", new string('a', 40),
                "--source-tree-digest", "sha256:" + new string('3', 64),
                "--reason", "ship v1.2.3"
            ]);
            var manifest = OperatorCli.ComposeManifest(values, _ => null);
            await Assert.That(manifest.OperationId).IsEqualTo(
                $"deploy-terrabase-server-{new string('1', 12)}");

            using var signer = EcdsaCommandSigner.LoadPrivatePem(privateKey);
            using var verifier = EcdsaCommandSignatureVerifier.LoadPublicPem([publicKey]);
            var payload = Encoding.UTF8.GetBytes(
                TerraScale.Orchestrator.Delivery.DeployHandoff.DeployHandoffMapper.SerializeManifest(manifest));
            var issuedAt = DateTimeOffset.UtcNow.AddSeconds(-5);
            var headers = DirectDeliveryCommandWire.EncodeSignedHeaders(
                payload,
                manifest.OperationId!,
                generation: 1,
                epoch: 1,
                attempt: 1,
                "gru",
                issuedAt,
                issuedAt.AddMinutes(5),
                signer.Sign);

            var admission = DirectDeliveryCommandIngress.Decode(
                payload,
                headers,
                "gru",
                DateTimeOffset.UtcNow,
                TimeSpan.FromMinutes(1),
                verifier,
                expectedGeneration: null,
                expectedEpoch: null);

            await Assert.That(admission.Error).IsEqualTo(DirectDeliveryCommandWireError.None);
            await Assert.That(admission.Kind)
                .IsEqualTo(DirectDeliveryCommandPayloadKind.DeployHandoffManifest);
            await Assert.That(admission.Handoff!.IsAdmittedForTargetMutation).IsTrue();
            await Assert.That(admission.Handoff.Request!.Delivery.Target!.Regions)
                .IsEquivalentTo(["gru", "sfo"]);
        }
        finally
        {
            Directory.Delete(directory, true);
        }
    }

    [Test]
    public async Task DeployRequiresTheClosedFlagSet()
    {
        await Assert.That(() => OperatorCli.ComposeManifest(
                OperatorCli.ParseValues(["--service", "terrabase-server"]),
                _ => null))
            .Throws<ArgumentException>();
        await Assert.That(() => OperatorCli.ParseValues(["--free-form", "value"]))
            .Throws<ArgumentException>();
    }
}
