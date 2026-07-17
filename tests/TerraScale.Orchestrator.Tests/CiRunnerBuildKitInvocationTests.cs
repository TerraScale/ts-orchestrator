using System.Runtime.Versioning;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class CiRunnerBuildKitInvocationTests
{
    [Test]
    public async Task ClosedInvocationUsesOnlyRuntimePathsAndFixedRecipe()
    {
        var fixture = Fixture();
        try
        {
            var invocation = CiRunnerBuildKitInvocationCompiler.Create(
                fixture.Plan,
                fixture.Source,
                fixture.Runtime);

            await Assert.That(invocation.Executable).IsEqualTo("/usr/bin/buildctl");
            await Assert.That(invocation.WorkingDirectory).IsEqualTo(fixture.Source.Root);
            await Assert.That(invocation.Arguments.SequenceEqual(new[]
            {
                "--addr", "unix:///run/user/1000/buildkit/buildkitd.sock",
                "build",
                "--progress", "plain",
                "--frontend", "dockerfile.v0",
                "--local", $"context={fixture.Source.Root}",
                "--local", $"dockerfile={fixture.Source.Root}",
                "--opt", "filename=.terrascale/ci.Dockerfile",
                "--opt", "target=ci-build",
                "--opt", $"build-arg:TS_CI_JOB={fixture.Plan.Job}",
                "--opt", $"build-arg:TS_CI_PLAN_DIGEST={fixture.Plan.Digest}",
                "--no-cache",
                "--metadata-file", Path.Combine(fixture.Output, $"ci-{fixture.Plan.ExecutionIdentityDigest}", "metadata.json"),
                "--output", $"type=local,dest={Path.Combine(fixture.Output, $"ci-{fixture.Plan.ExecutionIdentityDigest}", "evidence")}",
            })).IsTrue();
            await Assert.That(invocation.Environment.Keys).IsEquivalentTo(new[]
            {
                "PATH", "HOME", "XDG_RUNTIME_DIR", "DOCKER_CONFIG", "BUILDKIT_PROGRESS", "NO_COLOR",
            });
            await Assert.That(invocation.Environment.ContainsKey("DOCKER_HOST")).IsFalse();
            await Assert.That(invocation.Timeout).IsEqualTo(TimeSpan.FromMinutes(15));
            await Assert.That(invocation.MaximumLogBytes).IsEqualTo(16L * 1024 * 1024);
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Test]
    public async Task TrustedMultiPlatformInvocationMapsOnlyTheClosedArchitectureSet()
    {
        var fixture = Fixture();
        try
        {
            var original = fixture.Plan;
            var build = new CiRunnerBuildKitPlan(
                CiRunnerExecutionPlanner.Frontend,
                "ci-candidate",
                [RepositoryCiArchitecture.LinuxX64, RepositoryCiArchitecture.LinuxArm64],
                CiRunnerExecutionOutputKind.CandidateArtifacts,
                original.Build.Network,
                original.Build.Credentials,
                CiRunnerCacheScope.TrustedVerified,
                "trusted-cache",
                original.Build.CpuMilliCores,
                original.Build.MemoryBytes,
                original.Build.EphemeralDiskBytes,
                original.Build.Pids,
                original.Build.MaximumLogBytes,
                TimeSpan.FromHours(1));
            var plan = new CiRunnerExecutionPlan(
                original.PipelineDigest,
                original.Job,
                original.JobDigest,
                original.ExecutionIdentityDigest,
                original.Attempt,
                original.Source,
                build);
            var source = fixture.Source with { PlanDigest = plan.Digest };

            var invocation = CiRunnerBuildKitInvocationCompiler.Create(plan, source, fixture.Runtime);

            await Assert.That(invocation.Arguments).Contains("platform=linux/amd64,linux/arm64");
            await Assert.That(invocation.Arguments).DoesNotContain("--no-cache");
            await Assert.That(invocation.ExportDirectory).EndsWith("/candidate");
            await Assert.That(invocation.Timeout).IsEqualTo(TimeSpan.FromHours(1));
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Test]
    public async Task SubstitutedMaterializationAndUnsafeRuntimePathsFailClosed()
    {
        var fixture = Fixture();
        try
        {
            await Assert.That(() => CiRunnerBuildKitInvocationCompiler.Create(
                    fixture.Plan,
                    fixture.Source with { PlanDigest = new string('f', 64) },
                    fixture.Runtime))
                .Throws<InvalidDataException>();
            await Assert.That(() => CiRunnerBuildKitRuntime.Create(
                    "/tmp/runtime",
                    fixture.Home,
                    fixture.Output,
                    fixture.DockerConfig))
                .Throws<ArgumentException>();
            var outputInSource = CiRunnerBuildKitRuntime.Create(
                "/run/user/1000",
                fixture.Home,
                Path.Combine(fixture.Source.Root, "output"),
                fixture.DockerConfig);
            await Assert.That(() => CiRunnerBuildKitInvocationCompiler.Create(
                    fixture.Plan,
                    fixture.Source,
                    outputInSource))
                .Throws<InvalidDataException>();
            var homeInSource = CiRunnerBuildKitRuntime.Create(
                "/run/user/1000",
                fixture.Source.Root,
                fixture.Output,
                fixture.DockerConfig);
            await Assert.That(() => CiRunnerBuildKitInvocationCompiler.Create(
                    fixture.Plan,
                    fixture.Source,
                    homeInSource))
                .Throws<InvalidDataException>();
        }
        finally
        {
            fixture.Dispose();
        }
    }

    internal static InvocationFixture Fixture()
    {
        var root = Path.Combine(Path.GetTempPath(), $"ci-buildkit-{Guid.NewGuid():N}");
        var sourceRoot = Path.Combine(root, "source");
        var home = Path.Combine(root, "home");
        var output = Path.Combine(root, "output");
        var dockerConfig = Path.Combine(root, "docker-config");
        Directory.CreateDirectory(Path.Combine(sourceRoot, ".terrascale"));
        Directory.CreateDirectory(home);
        Directory.CreateDirectory(output);
        Directory.CreateDirectory(dockerConfig);
        File.WriteAllText(Path.Combine(sourceRoot, ".terrascale", "ci-v2.json"), "{}");
        File.WriteAllText(Path.Combine(sourceRoot, ".terrascale", "ci.Dockerfile"), "FROM scratch\n");
        var plan = CiRunnerSourceMaterializerTests.Plan([0x1f, 0x8b, 0x08, 1]);
        var source = new CiRunnerMaterializedSource(
            sourceRoot,
            plan.Digest,
            plan.Source.BundleSha256,
            2,
            16,
            new string('e', 64),
            new string('f', 64));
        return new(
            root,
            home,
            output,
            dockerConfig,
            plan,
            source,
            CiRunnerBuildKitRuntime.Create("/run/user/1000", home, output, dockerConfig));
    }

    internal sealed record InvocationFixture(
        string Root,
        string Home,
        string Output,
        string DockerConfig,
        CiRunnerExecutionPlan Plan,
        CiRunnerMaterializedSource Source,
        CiRunnerBuildKitRuntime Runtime) : IDisposable
    {
        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
