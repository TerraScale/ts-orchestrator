using TerraScale.Orchestrator.Lab.SmolVm;

namespace TerraScale.Orchestrator.Tests;

public sealed class SmolVmServerSessionTests
{
    [Test]
    public async Task ServerUsesVerifiedLauncherPrivateSocketAndHardeningArguments()
    {
        var launcher = "/opt/terrascale/smolvm/smolvm";
        var installation = new SmolVmVerifiedInstallation(
            "1.5.0",
            "6b178e16a7b95af0ed57ca69a1bbc0202e04157d",
            launcher,
            false,
            [new("launcher", launcher, new string('a', 64))]);

        var startInfo = SmolVmServerSession.CreateStartInfo(
            installation,
            "/run/user/1000/ts-lab/smolvm.sock",
            "/var/tmp/ts-lab/data");

        await Assert.That(startInfo.FileName).IsEqualTo(launcher);
        await Assert.That(startInfo.UseShellExecute).IsFalse();
        await Assert.That(startInfo.ArgumentList).Contains("unix:///run/user/1000/ts-lab/smolvm.sock");
        await Assert.That(startInfo.ArgumentList).Contains("--seccomp");
        await Assert.That(startInfo.ArgumentList).Contains("enforce");
        await Assert.That(startInfo.ArgumentList).Contains("--landlock");
        await Assert.That(startInfo.Environment["SMOLVM_DATA_DIR"]).IsEqualTo("/var/tmp/ts-lab/data");
    }

    [Test]
    public async Task UnverifiedOrWrongVersionLauncherCannotBeStarted()
    {
        var installation = new SmolVmVerifiedInstallation(
            "1.6.0",
            "different",
            "/bin/false",
            false,
            []);

        await Assert.That(() => SmolVmServerSession.CreateStartInfo(
                installation,
                "/tmp/socket",
                "/tmp/data"))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task StaleUnixSocketIsRemovedButLiveListenerIsFenced()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"smolvm-socket-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "server.sock");
        try
        {
            using (var stale = new System.Net.Sockets.Socket(
                       System.Net.Sockets.AddressFamily.Unix,
                       System.Net.Sockets.SocketType.Stream,
                       System.Net.Sockets.ProtocolType.Unspecified))
            {
                stale.Bind(new System.Net.Sockets.UnixDomainSocketEndPoint(path));
            }
            await SmolVmServerSession.PrepareSocketPathAsync(path, CancellationToken.None);
            await Assert.That(Path.Exists(path)).IsFalse();

            using var live = new System.Net.Sockets.Socket(
                System.Net.Sockets.AddressFamily.Unix,
                System.Net.Sockets.SocketType.Stream,
                System.Net.Sockets.ProtocolType.Unspecified);
            live.Bind(new System.Net.Sockets.UnixDomainSocketEndPoint(path));
            live.Listen();
            await Assert.That(async () => await SmolVmServerSession.PrepareSocketPathAsync(
                    path,
                    CancellationToken.None))
                .Throws<InvalidOperationException>();
            await Assert.That(Path.Exists(path)).IsTrue();
        }
        finally
        {
            if (Path.Exists(path))
            {
                File.Delete(path);
            }
            Directory.Delete(directory);
        }
    }
}
