using System.Net.Sockets;
using System.Runtime.Versioning;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class CiRunnerBuildKitDaemonTests
{
    [Test]
    public async Task CompilerEmitsOneClosedRootlessDaemonInvocation()
    {
        using var fixture = new Fixture();

        var invocation = CiRunnerBuildKitDaemonInvocationCompiler.Create(fixture.Runtime);

        await Assert.That(invocation.Executable).IsEqualTo("/usr/bin/rootlesskit");
        await Assert.That(invocation.Arguments.SequenceEqual([
            "--net=slirp4netns",
            "--copy-up=/etc",
            "--disable-host-loopback",
            $"--state-dir={fixture.Home}/rootlesskit-state",
            "/usr/bin/buildkitd",
            "--rootless",
            "--addr", "unix:///run/user/1000/buildkit/buildkitd.sock",
            "--root", $"{fixture.Home}/buildkit-state",
        ])).IsTrue();
        await Assert.That(invocation.Environment).IsEquivalentTo(new Dictionary<string, string>
        {
            ["PATH"] = "/usr/bin:/bin",
            ["HOME"] = fixture.Home,
            ["XDG_RUNTIME_DIR"] = "/run/user/1000",
            ["NO_COLOR"] = "1",
        });
        await Assert.That(invocation.Arguments).DoesNotContain("--oci-worker-no-process-sandbox");
        await Assert.That(invocation.Arguments.Any(static value => value.Contains("docker.sock"))).IsFalse();
    }

    [Test]
    public async Task HomeOutputOverlapIsRejectedBeforeProcessStartup()
    {
        using var fixture = new Fixture();
        var overlapping = new[]
        {
            CiRunnerBuildKitRuntime.Create(
                "/run/user/1000",
                fixture.Home,
                Path.Combine(fixture.Home, "output"),
                fixture.DockerConfig),
            CiRunnerBuildKitRuntime.Create(
                "/run/user/1000",
                fixture.Home,
                fixture.Root,
                fixture.DockerConfig),
            CiRunnerBuildKitRuntime.Create(
                "/run/user/1000",
                fixture.Home,
                fixture.Output,
                fixture.Output),
        };

        foreach (var runtime in overlapping)
            await Assert.That(() => CiRunnerBuildKitDaemonInvocationCompiler.Create(runtime))
                .Throws<InvalidDataException>();
    }

    [Test]
    public async Task MutatedInvocationIsRejectedBeforeProcessStartup()
    {
        using var fixture = new Fixture();
        var invocation = CiRunnerBuildKitDaemonInvocationCompiler.Create(fixture.Runtime);
        var arguments = invocation.Arguments.Concat(["--oci-worker-no-process-sandbox"]).ToArray();

        await Assert.That(() => CiRunnerBuildKitDaemonInvocationCompiler.Validate(
                invocation with { Arguments = Array.AsReadOnly(arguments) }))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task LinuxInspectorDistinguishesARealUnixSocketFromRegularOutput()
    {
        using var fixture = new Fixture();
        var path = Path.Combine(fixture.Root, "daemon.sock");
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        socket.Bind(new UnixDomainSocketEndPoint(path));

        await Assert.That(CiRunnerBuildKitExecutor.FileKind(path)).IsEqualTo(CiRunnerOutputFileKind.Socket);
        await Assert.That(CiRunnerBuildKitExecutor.FileKind(fixture.File))
            .IsEqualTo(CiRunnerOutputFileKind.Regular);
    }

    private sealed class Fixture : IDisposable
    {
        internal Fixture()
        {
            Root = Path.Combine(Path.GetTempPath(), $"ci-daemon-{Guid.NewGuid():N}");
            Home = Path.Combine(Root, "home");
            Output = Path.Combine(Root, "output");
            DockerConfig = Path.Combine(Root, "docker-config");
            foreach (var directory in new[] { Root, Home, Output, DockerConfig })
                Directory.CreateDirectory(directory);
            File = Path.Combine(Root, "regular");
            System.IO.File.WriteAllText(File, "value");
            Runtime = CiRunnerBuildKitRuntime.Create("/run/user/1000", Home, Output, DockerConfig);
        }

        internal string Root { get; }
        internal string Home { get; }
        internal string Output { get; }
        internal string DockerConfig { get; }
        internal string File { get; }
        internal CiRunnerBuildKitRuntime Runtime { get; }

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
