using System.Security.Cryptography;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Issue #7 role separation: repository-CI job dispatch, artifact attestation/delivery
/// evidence, and native runtime observation must use independently configured — and therefore
/// independently revocable — key material, and a signature from one role must never verify
/// under another role's trust root.
/// </summary>
public sealed class DeliveryRoleIdentityTests
{
    [Test]
    public async Task ConfiguredRolesCarryDistinctKeyMaterialAndNeverFallBackToTheCommandIdentity()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Root();
        try
        {
            using var command = CommandIdentity(root, "command");
            using var roles = Roles(root, "ci-job", "ci-artifact", KeyPair(root, "ci-runtime"), command);

            await Assert.That(roles.CiJob).IsNotNull();
            await Assert.That(roles.CiArtifact).IsNotNull();
            await Assert.That(roles.CiArtifactSignatures).IsNotNull();
            await Assert.That(roles.CiRuntimeSignatures).IsNotNull();
            await Assert.That(roles.CiJob!.Identity).IsNotEqualTo(roles.CiArtifact!.Identity);
            await Assert.That(roles.CiJob.Identity).IsNotEqualTo(command.Signer!.Identity);
            await Assert.That(roles.CiArtifact.Identity).IsNotEqualTo(command.Signer.Identity);
            // Each role verifies its own material and rejects every other role's.
            await Assert.That(Verify(roles.CiArtifactSignatures!, roles.CiArtifact!, ArtifactMaterial()))
                .IsTrue();
            await Assert.That(Verify(roles.CiArtifactSignatures!, roles.CiJob!, ArtifactMaterial()))
                .IsFalse();
            await Assert.That(Verify(roles.CiArtifactSignatures!, command.Signer!, ArtifactMaterial()))
                .IsFalse();
        }
        finally
        {
            Cleanup(root);
        }
    }

    [Test]
    public async Task ARuntimeObservationSignatureNeverVerifiesAsAnArtifactSignature()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Root();
        try
        {
            using var command = CommandIdentity(root, "command");
            // The runner side of the runtime role: its own key, trusted only through
            // TS_ORCH_CI_RUNTIME_TRUST_KEY_FILES.
            var runner = KeyPair(root, "ci-runtime");
            using var runnerSigner = EcdsaCommandSigner.LoadPrivatePem(runner.Private);
            using var roles = Roles(root, "ci-job", "ci-artifact", runner, command);

            var subject = Subject();
            var observation = RepositoryCiArtifactAttestation.ObserveRuntime(
                subject,
                subject.Digest,
                runnerSigner);
            var artifact = RepositoryCiArtifactAttestation.Sign(subject, roles.CiArtifact!);

            // Positive controls: each proof verifies under its own role's trust root.
            await Assert.That(RepositoryCiArtifactAttestation.ValidateRuntime(
                    observation, roles.CiRuntimeSignatures!))
                .IsTrue();
            await Assert.That(RepositoryCiArtifactAttestation.Validate(
                    subject,
                    artifact,
                    observation,
                    roles.CiArtifactSignatures!,
                    roles.CiRuntimeSignatures!))
                .IsNotNull();
            // Cross-role rejection at the key boundary: the runtime observation's signature must
            // not verify under the artifact role's trust root, and the artifact signature must
            // not verify under the runtime role's trust root.
            await Assert.That(RepositoryCiArtifactAttestation.ValidateRuntime(
                    observation, roles.CiArtifactSignatures!))
                .IsFalse();
            await Assert.That(Verify(roles.CiRuntimeSignatures!, roles.CiArtifact!, ArtifactMaterial()))
                .IsFalse();
        }
        finally
        {
            Cleanup(root);
        }
    }

    [Test]
    public async Task RequiredRolesRefuseCompositionWithoutTheirOwnConfiguredIdentity()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Root();
        try
        {
            using var command = CommandIdentity(root, "command");

            var missingJob = await Assert.That(() => DeliveryRoleIdentityRuntime.Open(
                    null,
                    command,
                    [DeliverySigningRole.CiJob]))
                .Throws<InvalidOperationException>();
            await Assert.That(missingJob!.Message).Contains("TS_ORCH_CI_JOB_SIGNING_KEY_FILE");

            var missingArtifact = await Assert.That(() => DeliveryRoleIdentityRuntime.Open(
                    null,
                    command,
                    [DeliverySigningRole.CiArtifact]))
                .Throws<InvalidOperationException>();
            await Assert.That(missingArtifact!.Message)
                .Contains("TS_ORCH_CI_ARTIFACT_SIGNING_KEY_FILE");
            await Assert.That(missingArtifact.Message)
                .Contains("TS_ORCH_CI_ARTIFACT_TRUST_KEY_FILES");

            var missingRuntime = await Assert.That(() => DeliveryRoleIdentityRuntime.Open(
                    null,
                    command,
                    [DeliverySigningRole.CiRuntime]))
                .Throws<InvalidOperationException>();
            await Assert.That(missingRuntime!.Message).Contains("TS_ORCH_CI_RUNTIME_TRUST_KEY_FILES");

            // Every role configured: composition opens with all three distinct trust roots.
            var config = DeliveryRoleIdentityConfiguration.Resolve(VariableMap(
                KeyPair(root, "ci-job"),
                KeyPair(root, "ci-artifact"),
                KeyPair(root, "ci-runtime").Public));
            using var configured = DeliveryRoleIdentityRuntime.Open(
                config,
                command,
                [DeliverySigningRole.CiJob, DeliverySigningRole.CiArtifact, DeliverySigningRole.CiRuntime]);
            await Assert.That(configured.CiJob!.Identity).IsNotEqualTo(configured.CiArtifact!.Identity);
        }
        finally
        {
            Cleanup(root);
        }
    }

    [Test]
    public async Task SharingOneKeyFileOrKeyMaterialAcrossRolesFailsClosed()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Root();
        try
        {
            var job = KeyPair(root, "ci-job");
            var artifact = KeyPair(root, "ci-artifact");
            var runtime = KeyPair(root, "ci-runtime");

            // The same private key file configured for two roles is a path-level violation.
            var sharedFile = await Assert.That(() =>
                    DeliveryRoleIdentityConfiguration.Resolve(VariableMap(
                        (job.Private, job.Public),
                        (job.Private, artifact.Public),
                        runtime.Public)))
                .Throws<ArgumentException>();
            await Assert.That(sharedFile!.Message).Contains("must not share key files");

            // Distinct files holding the same key material still couple the roles: the
            // runtime trust must not admit the job role's public key.
            var copiedMaterial = await Assert.That(() => DeliveryRoleIdentityRuntime.Open(
                    DeliveryRoleIdentityConfiguration.Resolve(VariableMap(job, artifact, job.Public)),
                    null))
                .Throws<InvalidOperationException>();
            await Assert.That(copiedMaterial!.Message).Contains("distinct key material");
        }
        finally
        {
            Cleanup(root);
        }
    }

    [Test]
    public async Task ARoleKeyReusingTheCommandIdentityMaterialFailsClosed()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Root();
        try
        {
            using var command = CommandIdentity(root, "command");
            // A role key that IS the command signing key re-couples the base identity with the
            // CI roles; the projection from roles to base must refuse it.
            var shared = (Path.Combine(root, "command.private.pem"), Path.Combine(root, "command.public.pem"));
            var artifact = KeyPair(root, "ci-artifact");
            var runtime = KeyPair(root, "ci-runtime");

            var violation = await Assert.That(() => DeliveryRoleIdentityRuntime.Open(
                    DeliveryRoleIdentityConfiguration.Resolve(VariableMap(shared, artifact, runtime.Public)),
                    command))
                .Throws<InvalidOperationException>();

            await Assert.That(violation!.Message).Contains("the shared command identity");
        }
        finally
        {
            Cleanup(root);
        }
    }

    private static bool Verify(
        EcdsaCommandSignatureVerifier verifier,
        EcdsaCommandSigner signer,
        byte[] material) =>
        verifier.Verify(
            signer.Identity,
            material,
            signer.Sign(new ReadOnlyMemory<byte>(material))) == VerificationOutcome.Valid;

    private static byte[] ArtifactMaterial() => "artifact-role-material"u8.ToArray();

    private static RepositoryCiArtifactSubject Subject() => new(
        new string('1', 64),
        new("candidate-job"),
        new("TerraScale/TerraScale.Orchestrator"),
        RepositoryCiArchitecture.LinuxArm64,
        new(new string('a', 64)),
        RepositoryCiArtifactAttestation.EntrypointsDigest(
            RepositoryCiArchitecture.LinuxArm64, ["app"]));

    private static CommandIdentityRuntime CommandIdentity(string root, string name)
    {
        var pair = KeyPair(root, name);
        return CommandIdentityRuntime.Open(
            CommandIdentityConfiguration.Resolve(pair.Private, pair.Public)
                ?? throw new InvalidOperationException("The test command identity did not resolve."));
    }

    private static DeliveryRoleIdentityRuntime Roles(
        string root,
        string job,
        string artifact,
        (string Private, string Public) runtime,
        CommandIdentityRuntime command) =>
        DeliveryRoleIdentityRuntime.Open(
            DeliveryRoleIdentityConfiguration.Resolve(VariableMap(
                KeyPair(root, job),
                KeyPair(root, artifact),
                runtime.Public)),
            command,
            [DeliverySigningRole.CiJob, DeliverySigningRole.CiArtifact, DeliverySigningRole.CiRuntime])!;

    private static Func<string, string?> VariableMap(
        (string Private, string Public) job,
        (string Private, string Public) artifact,
        string runtimeTrust) => key => key switch
    {
        DeliveryRoleIdentityConfigurationVariableNames.CiJobSigning => job.Private,
        DeliveryRoleIdentityConfigurationVariableNames.CiArtifactSigning => artifact.Private,
        DeliveryRoleIdentityConfigurationVariableNames.CiArtifactTrust => artifact.Public,
        DeliveryRoleIdentityConfigurationVariableNames.CiRuntimeTrust => runtimeTrust,
        _ => null,
    };

    private static (string Private, string Public) KeyPair(string root, string name)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privatePath = Path.Combine(root, $"{name}.private.pem");
        var publicPath = Path.Combine(root, $"{name}.public.pem");
        File.WriteAllText(privatePath, key.ExportPkcs8PrivateKeyPem());
        File.WriteAllText(publicPath, key.ExportSubjectPublicKeyInfoPem());
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(privatePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.SetUnixFileMode(publicPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        return (privatePath, publicPath);
    }

    private static string Root() =>
        Directory.CreateDirectory(Path.Combine(
            Path.GetTempPath(),
            $"ts-orch-role-identity-{Guid.NewGuid():N}")).FullName;

    private static void Cleanup(string root)
    {
        foreach (var file in Directory.EnumerateFiles(root))
            System.IO.File.Delete(file);
        Directory.Delete(root);
    }
}

internal static class DeliveryRoleIdentityConfigurationVariableNames
{
    internal const string CiJobSigning = "TS_ORCH_CI_JOB_SIGNING_KEY_FILE";
    internal const string CiArtifactSigning = "TS_ORCH_CI_ARTIFACT_SIGNING_KEY_FILE";
    internal const string CiArtifactTrust = "TS_ORCH_CI_ARTIFACT_TRUST_KEY_FILES";
    internal const string CiRuntimeTrust = "TS_ORCH_CI_RUNTIME_TRUST_KEY_FILES";
}

