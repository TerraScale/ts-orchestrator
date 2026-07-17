using System.Runtime.Versioning;
using System.Runtime.InteropServices;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class CiRunnerBuildKitExecutorTests
{
    [Test]
    public async Task SuccessfulProcessProducesBoundedContentEvidence()
    {
        using var fixture = CiRunnerBuildKitInvocationTests.Fixture();
        var process = new RecordingProcess(invocation =>
        {
            Directory.CreateDirectory(invocation.ExportDirectory);
            File.WriteAllText(Path.Combine(invocation.ExportDirectory, "result.txt"), "passed");
            File.WriteAllText(invocation.MetadataFile, "{\"result\":\"ok\"}");
            return Exited(0);
        });

        var result = await new CiRunnerBuildKitExecutor(process).ExecuteAsync(
            fixture.Plan,
            fixture.Source,
            fixture.Runtime);

        await Assert.That(result.Disposition).IsEqualTo(CiRunnerBuildKitExecutionDisposition.Succeeded);
        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(result.OutputFiles).IsEqualTo(1);
        await Assert.That(result.OutputBytes).IsEqualTo(6);
        await Assert.That(result.OutputSha256.Length).IsEqualTo(64);
        await Assert.That(result.MetadataSha256.Length).IsEqualTo(64);
        await Assert.That(process.Invocations).HasSingleItem();
    }

    [Test]
    public async Task FailureTimeoutAndLogOverflowRemovePartialOutput()
    {
        foreach (var processResult in new[]
        {
            Exited(7),
            new CiRunnerBuildKitProcessResult(
                CiRunnerBuildKitProcessDisposition.TimedOut, -1, new string('a', 64), 0),
            new CiRunnerBuildKitProcessResult(
                CiRunnerBuildKitProcessDisposition.LogLimitExceeded, -1, new string('a', 64), 16),
        })
        {
            using var fixture = CiRunnerBuildKitInvocationTests.Fixture();
            var process = new RecordingProcess(invocation =>
            {
                File.WriteAllText(Path.Combine(invocation.OutputDirectory, "partial"), "partial");
                return processResult;
            });

            var result = await new CiRunnerBuildKitExecutor(process).ExecuteAsync(
                fixture.Plan,
                fixture.Source,
                fixture.Runtime);

            await Assert.That(result.Disposition).IsNotEqualTo(CiRunnerBuildKitExecutionDisposition.Succeeded);
            await Assert.That(Directory.Exists(process.Invocations.Single().OutputDirectory)).IsFalse();
            await Assert.That(result.OutputSha256).IsEmpty();
        }
    }

    [Test]
    public async Task LinkedDuplicateMetadataAndSpecialOutputFailClosed()
    {
        using var linkedFixture = CiRunnerBuildKitInvocationTests.Fixture();
        var linked = new RecordingProcess(invocation =>
        {
            Directory.CreateDirectory(invocation.ExportDirectory);
            File.CreateSymbolicLink(Path.Combine(invocation.ExportDirectory, "link"), "/etc/passwd");
            File.WriteAllText(invocation.MetadataFile, "{}");
            return Exited(0);
        });
        await Assert.That(async () => await new CiRunnerBuildKitExecutor(linked).ExecuteAsync(
                linkedFixture.Plan,
                linkedFixture.Source,
                linkedFixture.Runtime))
            .Throws<InvalidDataException>();
        await Assert.That(Directory.Exists(linked.Invocations.Single().OutputDirectory)).IsFalse();

        using var metadataFixture = CiRunnerBuildKitInvocationTests.Fixture();
        var metadata = new RecordingProcess(invocation =>
        {
            Directory.CreateDirectory(invocation.ExportDirectory);
            File.WriteAllText(Path.Combine(invocation.ExportDirectory, "result"), "ok");
            File.WriteAllText(invocation.MetadataFile, "{\"x\":1,\"x\":2}");
            return Exited(0);
        });
        await Assert.That(async () => await new CiRunnerBuildKitExecutor(metadata).ExecuteAsync(
                metadataFixture.Plan,
                metadataFixture.Source,
                metadataFixture.Runtime))
            .Throws<InvalidDataException>();
        await Assert.That(Directory.Exists(metadata.Invocations.Single().OutputDirectory)).IsFalse();

        using var fifoFixture = CiRunnerBuildKitInvocationTests.Fixture();
        var fifo = new RecordingProcess(invocation =>
        {
            Directory.CreateDirectory(invocation.ExportDirectory);
            if (MkFifo(Path.Combine(invocation.ExportDirectory, "pipe"), 0x180) != 0)
                throw new InvalidOperationException("mkfifo failed in the test fixture.");
            File.WriteAllText(invocation.MetadataFile, "{}");
            return Exited(0);
        });
        await Assert.That(async () => await new CiRunnerBuildKitExecutor(fifo).ExecuteAsync(
                fifoFixture.Plan,
                fifoFixture.Source,
                fifoFixture.Runtime))
            .Throws<InvalidDataException>();
        await Assert.That(Directory.Exists(fifo.Invocations.Single().OutputDirectory)).IsFalse();
    }

    [Test]
    public async Task ProcessRunnerClearsEnvironmentBoundsLogsAndEnforcesTimeout()
    {
        var root = Path.Combine(Path.GetTempPath(), $"ci-process-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var overflow = Invocation(root, "printf '0123456789abcdef'", TimeSpan.FromSeconds(5), 8);
            var overflowResult = await new ProcessCiRunnerBuildKitProcess().RunAsync(overflow, default);
            await Assert.That(overflowResult.Disposition)
                .IsEqualTo(CiRunnerBuildKitProcessDisposition.LogLimitExceeded);
            await Assert.That(overflowResult.LogBytes).IsEqualTo(8);

            var environment = Invocation(
                root,
                "test -z \"${HOME+x}\"",
                TimeSpan.FromSeconds(5),
                1024);
            var environmentResult = await new ProcessCiRunnerBuildKitProcess().RunAsync(environment, default);
            await Assert.That(environmentResult.ExitCode).IsEqualTo(0);

            var timeout = Invocation(root, "sleep 60", TimeSpan.FromMilliseconds(100), 1024);
            var timeoutResult = await new ProcessCiRunnerBuildKitProcess().RunAsync(timeout, default);
            await Assert.That(timeoutResult.Disposition).IsEqualTo(CiRunnerBuildKitProcessDisposition.TimedOut);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static CiRunnerBuildKitInvocation Invocation(
        string root,
        string command,
        TimeSpan timeout,
        long maximumLogBytes) => new(
            "/usr/bin/bash",
            Array.AsReadOnly(new[] { "-c", command }),
            root,
            new System.Collections.ObjectModel.ReadOnlyDictionary<string, string>(
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["PATH"] = "/usr/bin:/bin",
                }),
            Path.Combine(root, "output"),
            Path.Combine(root, "output", "export"),
            Path.Combine(root, "output", "metadata.json"),
            timeout,
            maximumLogBytes);

    private static CiRunnerBuildKitProcessResult Exited(int exitCode) => new(
        CiRunnerBuildKitProcessDisposition.Exited,
        exitCode,
        new string('a', 64),
        0);

    [DllImport("libc", EntryPoint = "mkfifo", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int MkFifo(string path, uint mode);

    private sealed class RecordingProcess(
        Func<CiRunnerBuildKitInvocation, CiRunnerBuildKitProcessResult> execute)
        : ICiRunnerBuildKitProcess
    {
        internal List<CiRunnerBuildKitInvocation> Invocations { get; } = [];

        public Task<CiRunnerBuildKitProcessResult> RunAsync(
            CiRunnerBuildKitInvocation invocation,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Invocations.Add(invocation);
            return Task.FromResult(execute(invocation));
        }
    }
}
