using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator;
using TerraScale.Orchestrator.ControlPlane.Providers;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Composition-root startup behavior: run admission without CI signing material for
/// verifier-only roles (member hosts), SIGINT/SIGTERM shutdown triggers, bounded global control
/// boot retry, and fail-stop observation of the unobserved WAN/global completions.
/// </summary>
public sealed class ProgramStartupTests
{
    [Test]
    public async Task MemberHostRunCompositionAdmitsWithoutTheCiArtifactPrivateKey()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Root();
        try
        {
            // A bare member host: `run` with regional control only — no global NATS, no CI pool.
            var options = new OrchestratorOptions(
                OrchestratorCommand.Run, "gru", "tls://regional-control.internal:4222", 3);
            var roles = ProductionRoleComposition.ProductionCiRoles(
                options, OrchestratorRuntimeComposition.Plan(options));

            await Assert.That(roles.Contains(DeliverySigningRole.CiArtifactTrust)).IsTrue();
            await Assert.That(roles.Contains(DeliverySigningRole.CiRuntime)).IsTrue();
            // The PRIVATE signing key role is only for a CI signer controller.
            await Assert.That(roles.Contains(DeliverySigningRole.CiArtifact)).IsFalse();
            await Assert.That(roles.Contains(DeliverySigningRole.CiJob)).IsFalse();

            // Admission with ONLY the public trust keys (no TS_ORCH_CI_ARTIFACT_SIGNING_KEY_FILE)
            // succeeds, and evidence verification still resolves against the public trust list.
            using var command = CommandIdentity(root, "command");
            var artifactTrust = KeyPair(root, "ci-artifact");
            var runtimeTrust = KeyPair(root, "ci-runtime");
            using var identities = DeliveryRoleIdentityRuntime.Open(
                DeliveryRoleIdentityConfiguration.Resolve(TrustOnly(artifactTrust.Public, runtimeTrust.Public)),
                command,
                roles);
            await Assert.That(identities.CiArtifactSignatures).IsNotNull();
        }
        finally
        {
            Cleanup(root);
        }
    }

    [Test]
    public async Task CiSignerControllerStillFailsClosedWithoutTheArtifactSigningKey()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Root();
        try
        {
            var pool = await PoolAsync(root);
            var options = new OrchestratorOptions(
                OrchestratorCommand.Run, "gru", "tls://regional-control.internal:4222", 3)
            {
                OciCiRunnerPool = pool,
            };
            var startupPlan = OrchestratorRuntimeComposition.Describe(
                "gru",
                hasDirectory: false,
                hasDirectoryService: false,
                hasAuthority: true,
                hasForgejo: false,
                hasCi: true,
                hasNativeGitOps: false,
                StartsCiConsumption: true,
                RegistersDirectDeliveryEndpoint: true);
            var roles = ProductionRoleComposition.ProductionCiRoles(options, startupPlan);
            await Assert.That(roles.Contains(DeliverySigningRole.CiArtifact)).IsTrue();
            await Assert.That(roles.Contains(DeliverySigningRole.CiJob)).IsTrue();

            // The signer controller carries the attestation PRIVATE key: its absence fails
            // closed at startup, never at first attestation. (The job signing key IS
            // configured here so the artifact requirement is the one that fails.)
            using var command = CommandIdentity(root, "command");
            var jobSigning = KeyPair(root, "ci-job");
            var artifactTrust = KeyPair(root, "ci-artifact");
            var runtimeTrust = KeyPair(root, "ci-runtime");
            var missing = await Assert.That(() => DeliveryRoleIdentityRuntime.Open(
                    DeliveryRoleIdentityConfiguration.Resolve(key => key switch
                    {
                        "TS_ORCH_CI_JOB_SIGNING_KEY_FILE" => jobSigning.Private,
                        "TS_ORCH_CI_ARTIFACT_TRUST_KEY_FILES" => artifactTrust.Public,
                        "TS_ORCH_CI_RUNTIME_TRUST_KEY_FILES" => runtimeTrust.Public,
                        _ => null,
                    }),
                    command,
                    roles))
                .Throws<InvalidOperationException>();
            await Assert.That(missing!.Message).Contains("TS_ORCH_CI_ARTIFACT_SIGNING_KEY_FILE");
        }
        finally
        {
            Cleanup(root);
        }
    }

    [Test]
    public async Task SigintAndSigtermTriggersCancelTheSharedShutdownToken()
    {
        // SIGTERM — the signal systemd's unit stop delivers — cancels the shutdown token
        // instead of terminating the process, so the graceful disposal chain runs.
        using var sigtermShutdown = new CancellationTokenSource();
        using var sigtermWiring = ShutdownSignals.Wire(sigtermShutdown);
        var sigterm = new PosixSignalContext(PosixSignal.SIGTERM);
        sigtermWiring.OnPosixSignal(sigterm);
        await Assert.That(sigterm.Cancel).IsTrue();
        await Assert.That(sigtermShutdown.IsCancellationRequested).IsTrue();

        // The SIGINT handler routes into the same shared trigger.
        using var sigintShutdown = new CancellationTokenSource();
        using var sigintWiring = ShutdownSignals.Wire(sigintShutdown);
        sigintWiring.Trigger();
        await Assert.That(sigintShutdown.IsCancellationRequested).IsTrue();
    }

    private sealed class FakeGlobalRuntime;

    [Test]
    public async Task GlobalControlBootRetriesTransientFailuresAndObservesEveryAttempt()
    {
        var attempts = 0;
        var failures = new List<(int Attempt, Exception Failure)>();
        var started = new FakeGlobalRuntime();

        var runtime = await GlobalControlStartup.StartWithRetryAsync<FakeGlobalRuntime>(
            _ =>
            {
                attempts++;
                return attempts < 3
                    ? Task.FromException<FakeGlobalRuntime>(new InvalidOperationException("global NATS is electing"))
                    : Task.FromResult(started);
            },
            (attempt, exception) => failures.Add((attempt, exception)),
            CancellationToken.None,
            _ => TimeSpan.Zero);

        await Assert.That(ReferenceEquals(runtime, started)).IsTrue();
        await Assert.That(failures.Count).IsEqualTo(2);
        await Assert.That(failures[0].Attempt).IsEqualTo(1);
        await Assert.That(failures[1].Attempt).IsEqualTo(2);
    }

    [Test]
    public async Task GlobalControlBootIsBoundedAndDegradesToRegionalAfterMaxAttempts()
    {
        var attempts = 0;
        var runtime = await GlobalControlStartup.StartWithRetryAsync<FakeGlobalRuntime>(
            _ =>
            {
                attempts++;
                return Task.FromException<FakeGlobalRuntime>(new InvalidOperationException("auth rejected"));
            },
            (_, _) => { },
            CancellationToken.None,
            _ => TimeSpan.Zero);

        await Assert.That(runtime).IsNull();
        await Assert.That(attempts).IsEqualTo(GlobalControlStartup.MaxStartAttempts);
    }

    [Test]
    public async Task FaultedGlobalCompletionLogsAndFailsTheProcess()
    {
        var faulted = Task.FromException(new InvalidOperationException(
            "The regional authority candidate is fenced and must restart."));
        var logged = new List<string>();

        var failure = await Assert.That(() => RunCompletion.FailStopOnFaultedAsync(
                "global authority",
                faulted,
                CancellationToken.None,
                logged.Add))
            .Throws<InvalidOperationException>();
        await Assert.That(failure!.Message).Contains("fenced");
        await Assert.That(logged.Count).IsEqualTo(1);
        await Assert.That(logged[0]).Contains("global authority runtime failed");
    }

    [Test]
    public async Task FaultedGlobalCompletionSurfacesThroughTheRunAwait()
    {
        var regional = Task.Delay(Timeout.InfiniteTimeSpan);
        var faulted = Task.FromException(new InvalidOperationException(
            "The regional authority candidate is fenced and must restart."));

        await Assert.That(async () => await RunCompletion.AwaitAsync(
                regional,
                faulted,
                null,
                CancellationToken.None))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task FaultedNativeGitOpsCompletionAlsoFailsTheProcess()
    {
        var regional = Task.Delay(Timeout.InfiniteTimeSpan);
        var faulted = Task.FromException(new InvalidDataException("relay worker died"));

        await Assert.That(async () => await RunCompletion.AwaitAsync(
                regional,
                null,
                faulted,
                CancellationToken.None))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task UnexpectedCleanGlobalStopStillFailsStop()
    {
        var regional = Task.Delay(Timeout.InfiniteTimeSpan);

        await Assert.That(async () => await RunCompletion.AwaitAsync(
                regional,
                Task.CompletedTask,
                null,
                CancellationToken.None))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ShutdownCancellationStaysGracefulAndRegionalFaultsStillFail()
    {
        using var cancellation = new CancellationTokenSource();
        var regional = Task.Delay(Timeout.InfiniteTimeSpan, cancellation.Token);
        var global = Task.Delay(Timeout.InfiniteTimeSpan);
        await cancellation.CancelAsync();

        // Graceful stop: cancellation propagates without the fail-stop error.
        await Assert.That(async () => await RunCompletion.AwaitAsync(
                regional,
                global,
                null,
                cancellation.Token))
            .Throws<OperationCanceledException>();

        var faultedRegional = Task.FromException(new InvalidOperationException("regional loop died"));
        await Assert.That(async () => await RunCompletion.AwaitAsync(
                faultedRegional,
                null,
                null,
                CancellationToken.None))
            .Throws<InvalidOperationException>();
    }

    private static Func<string, string?> TrustOnly(string artifactTrust, string runtimeTrust) => key => key switch
    {
        "TS_ORCH_CI_ARTIFACT_TRUST_KEY_FILES" => artifactTrust,
        "TS_ORCH_CI_RUNTIME_TRUST_KEY_FILES" => runtimeTrust,
        _ => null,
    };

    private static CommandIdentityRuntime CommandIdentity(string root, string name)
    {
        var pair = KeyPair(root, name);
        return CommandIdentityRuntime.Open(
            CommandIdentityConfiguration.Resolve(pair.Private, pair.Public)
                ?? throw new InvalidOperationException("The test command identity did not resolve."));
    }

    private static async Task<OciCiRunnerPoolConfiguration> PoolAsync(string root)
    {
        await File.WriteAllTextAsync(
            Path.Combine(root, "runner.cloud-init"),
            "#cloud-config\nruncmd:\n  - [oci, secrets, secret-bundle, get, --secret-id, ocid1.vaultsecret.oc1..runner]\n");
        var path = Path.Combine(root, "pool.json");
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            endpoint = "https://iaas.sa-saopaulo-1.oraclecloud.com/",
            compartmentId = "ocid1.compartment.oc1..ci",
            availabilityDomain = "sa-saopaulo-1-ad-1",
            faultDomain = "FAULT-DOMAIN-1",
            subnetId = "ocid1.subnet.oc1.sa-saopaulo-1.ci",
            networkSecurityGroupIds = new[] { "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.ci" },
            imageId = "ocid1.image.oc1.sa-saopaulo-1.runner",
            generation = 7,
            idleSeconds = 60,
            pollSeconds = 10,
            runners = new[]
            {
                new { runner = "ci-untrusted-1", zone = "untrusted-product", sequence = 10, bootstrapFile = "runner.cloud-init" },
            }
        }));
        return OciCiRunnerPoolConfiguration.Load(path)!;
    }

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
            $"ts-orch-program-startup-{Guid.NewGuid():N}")).FullName;

    private static void Cleanup(string root)
    {
        foreach (var file in Directory.EnumerateFiles(root))
            File.Delete(file);
        Directory.Delete(root);
    }
}
