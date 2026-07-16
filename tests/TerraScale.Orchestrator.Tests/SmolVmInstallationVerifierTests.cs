using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.Lab.SmolVm;

namespace TerraScale.Orchestrator.Tests;

public sealed class SmolVmInstallationVerifierTests
{
    [Test]
    public async Task ExactArtifactClosureCanBeUsedLocallyButNotClaimDeploymentQualification()
    {
        var fixture = await Fixture.CreateAsync(internallyQualified: false);
        try
        {
            var installation = await SmolVmInstallationVerifier.VerifyAsync(
                fixture.PinPath,
                fixture.InstallationRoot,
                requireInternalProvenance: false,
                CancellationToken.None);

            await Assert.That(installation.Version).IsEqualTo("1.5.0");
            await Assert.That(installation.Artifacts).Count().IsEqualTo(5);
            await Assert.That(installation.InternalProvenanceQualified).IsFalse();
            await Assert.That(async () => await SmolVmInstallationVerifier.VerifyAsync(
                    fixture.PinPath,
                    fixture.InstallationRoot,
                    requireInternalProvenance: true,
                    CancellationToken.None))
                .Throws<InvalidOperationException>();
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Test]
    public async Task ChangedLauncherIsRejectedBeforeItCanStartAVmServer()
    {
        var fixture = await Fixture.CreateAsync(internallyQualified: true);
        try
        {
            await File.AppendAllTextAsync(Path.Combine(fixture.InstallationRoot, "smolvm"), "tamper");

            await Assert.That(async () => await SmolVmInstallationVerifier.VerifyAsync(
                    fixture.PinPath,
                    fixture.InstallationRoot,
                    requireInternalProvenance: true,
                    CancellationToken.None))
                .Throws<InvalidOperationException>();
        }
        finally
        {
            fixture.Dispose();
        }
    }

    private sealed record Fixture(string Root, string PinPath, string InstallationRoot) : IDisposable
    {
        private static readonly (string Path, string Role)[] Artifacts =
        [
            (".version", "installed-version-metadata"),
            ("smolvm", "launcher"),
            ("smolvm-bin", "runtime"),
            ("lib/libkrun.so", "hypervisor-library"),
            ("lib/libkrunfw.so.5.5.0", "firmware-library")
        ];

        public static async Task<Fixture> CreateAsync(bool internallyQualified)
        {
            var root = Path.Combine(Path.GetTempPath(), $"smolvm-install-{Guid.NewGuid():N}");
            var installation = Path.Combine(root, "installation");
            Directory.CreateDirectory(installation);
            var entries = new List<object>();
            foreach (var artifact in Artifacts)
            {
                var fullPath = Path.Combine(installation, artifact.Path);
                Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
                await File.WriteAllTextAsync(fullPath, $"fixed {artifact.Role}");
                await using var stream = File.OpenRead(fullPath);
                entries.Add(new
                {
                    path = artifact.Path,
                    role = artifact.Role,
                    sha256 = Convert.ToHexStringLower(await SHA256.HashDataAsync(stream))
                });
            }
            var pin = Path.Combine(root, "pin.json");
            var status = internallyQualified ? "established" : "not-established";
            await File.WriteAllTextAsync(pin, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                runtime = "smolvm",
                version = "1.5.0",
                hostPlatform = new
                {
                    operatingSystem = "linux",
                    architecture = "x86_64"
                },
                distributionArtifacts = entries,
                provenance = new
                {
                    source = new { commit = "6b178e16a7b95af0ed57ca69a1bbc0202e04157d" },
                    terrascaleSupplyChain = new
                    {
                        internalMirrorStatus = status,
                        internalSignatureStatus = status
                    }
                }
            }));
            return new(root, pin, installation);
        }

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
