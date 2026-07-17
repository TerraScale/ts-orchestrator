using System.Runtime.Versioning;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class CiRunnerExecutionCoordinatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task DurableSuccessCompletesTheLeaseAndRemovesPrivateWorkspaces()
    {
        using var fixture = await Fixture.CreateAsync();
        var sink = new RecordingSink((evidence, export, _) =>
        {
            if (!Directory.Exists(export)) throw new InvalidOperationException("Missing validated export.");
            return Task.FromResult(new CiRunnerDurableWorkloadResult(Digest('a'), 0));
        });

        var receipt = await fixture.Coordinator(sink).ExecuteAsync(
            fixture.Accepted,
            fixture.Runner,
            fixture.Isolation,
            fixture.Runtime,
            fixture.Workspace,
            "runner-operation-1");
        var recovered = await fixture.Journal.ReadAsync(
            fixture.Accepted.Command.Runner,
            fixture.Accepted.Command.PipelineDigest,
            fixture.Accepted.Command.Job);

        await Assert.That(receipt.Disposition).IsEqualTo(CiRunnerExecutionCoordinatorDisposition.Completed);
        await Assert.That(receipt.ExecutionDisposition).IsEqualTo(RepositoryCiJobExecutionDisposition.Completed);
        await Assert.That(recovered!.Phase).IsEqualTo(RepositoryCiJobExecutionPhase.Succeeded);
        await Assert.That(recovered.EvidenceDigest).IsEqualTo(Digest('a'));
        await Assert.That(sink.Evidences).HasSingleItem();
        await Assert.That(sink.Evidences[0].Succeeded).IsTrue();
        await Assert.That(sink.Evidences[0].BuildDisposition)
            .IsEqualTo(CiRunnerBuildKitExecutionDisposition.Succeeded);
        await Assert.That(Directory.EnumerateFileSystemEntries(fixture.Workspace)).IsEmpty();
        await Assert.That(Directory.EnumerateFileSystemEntries(fixture.Output)).IsEmpty();
    }

    [Test]
    public async Task ProcessAndRejectedSourceFailuresBecomeTypedDurableTerminalResults()
    {
        using (var processFailure = await Fixture.CreateAsync(exitCode: 17))
        {
            var sink = new RecordingSink((_, _, _) =>
                Task.FromResult(new CiRunnerDurableWorkloadResult(Digest('b'), 2)));
            var receipt = await processFailure.Coordinator(sink).ExecuteAsync(
                processFailure.Accepted,
                processFailure.Runner,
                processFailure.Isolation,
                processFailure.Runtime,
                processFailure.Workspace,
                "runner-operation-process-failure");

            await Assert.That(receipt.Execution!.Phase).IsEqualTo(RepositoryCiJobExecutionPhase.Failed);
            await Assert.That(receipt.Execution.FailureKind).IsEqualTo(RepositoryCiJobFailureKind.WorkloadFailed);
            await Assert.That(receipt.Execution.RequiredTestSkips).IsEqualTo(2);
            await Assert.That(sink.Evidences.Single().FailureCode)
                .IsEqualTo(CiRunnerWorkloadFailureCode.ProcessFailed);
            await Assert.That(sink.ExportDirectories.Single()).IsNull();
        }

        var archive = CiRunnerSourceMaterializerTests.ValidArchive();
        using (var sourceFailure = await Fixture.CreateAsync(archive, archive[..^1]))
        {
            var sink = new RecordingSink((_, _, _) =>
                Task.FromResult(new CiRunnerDurableWorkloadResult(Digest('c'), 0)));
            var receipt = await sourceFailure.Coordinator(sink).ExecuteAsync(
                sourceFailure.Accepted,
                sourceFailure.Runner,
                sourceFailure.Isolation,
                sourceFailure.Runtime,
                sourceFailure.Workspace,
                "runner-operation-source-failure");

            await Assert.That(receipt.Execution!.Phase).IsEqualTo(RepositoryCiJobExecutionPhase.Failed);
            await Assert.That(receipt.Execution.FailureKind).IsEqualTo(RepositoryCiJobFailureKind.PolicyDenied);
            await Assert.That(sink.Evidences.Single().FailureCode)
                .IsEqualTo(CiRunnerWorkloadFailureCode.SourceRejected);
            await Assert.That(sourceFailure.Process.Invocations).IsEmpty();
        }
    }

    [Test]
    public async Task ResultPersistenceFailureLeavesTheLeaseRecoverableAndCleansLocalState()
    {
        using var fixture = await Fixture.CreateAsync();
        var sink = new RecordingSink((_, _, _) => throw new IOException("simulated result store outage"));

        await Assert.That(async () => await fixture.Coordinator(sink).ExecuteAsync(
                fixture.Accepted,
                fixture.Runner,
                fixture.Isolation,
                fixture.Runtime,
                fixture.Workspace,
                "runner-operation-store-outage"))
            .Throws<IOException>();
        var recovered = await fixture.Journal.ReadAsync(
            fixture.Accepted.Command.Runner,
            fixture.Accepted.Command.PipelineDigest,
            fixture.Accepted.Command.Job);

        await Assert.That(recovered!.Phase).IsEqualTo(RepositoryCiJobExecutionPhase.Running);
        await Assert.That(recovered.EvidenceDigest).IsEmpty();
        await Assert.That(Directory.EnumerateFileSystemEntries(fixture.Workspace)).IsEmpty();
        await Assert.That(Directory.EnumerateFileSystemEntries(fixture.Output)).IsEmpty();
    }

    [Test]
    public async Task TakeoverFencesTerminalCommitAfterDurablePersistence()
    {
        using var fixture = await Fixture.CreateAsync();
        var sink = new RecordingSink(async (_, _, cancellationToken) =>
        {
            var takeover = await fixture.Journal.AcquireAsync(
                fixture.Accepted,
                "runner-operation-takeover",
                Now.AddMinutes(5).AddSeconds(1),
                TimeSpan.FromMinutes(5),
                cancellationToken);
            if (takeover.Disposition != RepositoryCiJobExecutionDisposition.TakenOver)
                throw new InvalidOperationException("The test takeover did not acquire the expired lease.");
            return new(Digest('d'), 0);
        });

        var receipt = await fixture.Coordinator(sink).ExecuteAsync(
            fixture.Accepted,
            fixture.Runner,
            fixture.Isolation,
            fixture.Runtime,
            fixture.Workspace,
            "runner-operation-original");

        await Assert.That(receipt.Disposition).IsEqualTo(CiRunnerExecutionCoordinatorDisposition.LeaseLost);
        await Assert.That(receipt.ExecutionDisposition).IsEqualTo(RepositoryCiJobExecutionDisposition.StaleLease);
        await Assert.That(receipt.Execution!.LeaseId).IsEqualTo("runner-operation-takeover");
        await Assert.That(receipt.Execution.Phase).IsEqualTo(RepositoryCiJobExecutionPhase.Running);
    }

    private static string Digest(char value) => new(value, 64);

    private sealed class RecordingSink(
        Func<CiRunnerWorkloadEvidence, string?, CancellationToken, Task<CiRunnerDurableWorkloadResult>> persist)
        : ICiRunnerWorkloadResultSink
    {
        internal List<CiRunnerWorkloadEvidence> Evidences { get; } = [];
        internal List<string?> ExportDirectories { get; } = [];

        public Task<CiRunnerDurableWorkloadResult> PersistAsync(
            CiRunnerWorkloadEvidence evidence,
            string? exportDirectory,
            CancellationToken cancellationToken)
        {
            Evidences.Add(evidence);
            ExportDirectories.Add(exportDirectory);
            return persist(evidence, exportDirectory, cancellationToken);
        }
    }

    private sealed class RecordingProcess(int exitCode) : ICiRunnerBuildKitProcess
    {
        internal List<CiRunnerBuildKitInvocation> Invocations { get; } = [];

        public Task<CiRunnerBuildKitProcessResult> RunAsync(
            CiRunnerBuildKitInvocation invocation,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Invocations.Add(invocation);
            if (exitCode == 0)
            {
                Directory.CreateDirectory(invocation.ExportDirectory);
                File.WriteAllText(Path.Combine(invocation.ExportDirectory, "result.txt"), "passed");
                File.WriteAllText(invocation.MetadataFile, "{\"result\":\"ok\"}");
            }
            return Task.FromResult(new CiRunnerBuildKitProcessResult(
                CiRunnerBuildKitProcessDisposition.Exited,
                exitCode,
                Digest('e'),
                0));
        }
    }

    private sealed class ObjectStore(byte[] content) : IDeliveryObjectStore
    {
        public Task PutAsync(string name, ReadOnlyMemory<byte> value, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(content.ToArray());
        }
    }

    private sealed class FixedTimeProvider : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class Fixture : IDisposable
    {
        private Fixture(
            string root,
            string workspace,
            string output,
            RepositoryCiAcceptedJob accepted,
            RepositoryCiJobExecutionJournal journal,
            RunnerEvidence runner,
            CiRunnerIsolationEvidence isolation,
            CiRunnerBuildKitRuntime runtime,
            CiRunnerSourceMaterializer materializer,
            RecordingProcess process)
        {
            Root = root;
            Workspace = workspace;
            Output = output;
            Accepted = accepted;
            Journal = journal;
            Runner = runner;
            Isolation = isolation;
            Runtime = runtime;
            Materializer = materializer;
            Process = process;
        }

        internal string Root { get; }
        internal string Workspace { get; }
        internal string Output { get; }
        internal RepositoryCiAcceptedJob Accepted { get; }
        internal RepositoryCiJobExecutionJournal Journal { get; }
        internal RunnerEvidence Runner { get; }
        internal CiRunnerIsolationEvidence Isolation { get; }
        internal CiRunnerBuildKitRuntime Runtime { get; }
        internal CiRunnerSourceMaterializer Materializer { get; }
        internal RecordingProcess Process { get; }

        internal CiRunnerExecutionCoordinator Coordinator(ICiRunnerWorkloadResultSink sink) => new(
            Journal,
            Materializer,
            new(Process),
            sink,
            new FixedTimeProvider());

        internal static async Task<Fixture> CreateAsync(
            byte[]? signedArchive = null,
            byte[]? storedArchive = null,
            int exitCode = 0)
        {
            signedArchive ??= CiRunnerSourceMaterializerTests.ValidArchive();
            storedArchive ??= signedArchive;
            var accepted = await RepositoryCiJobInboxTests.AcceptedAsync(signedArchive);
            var journal = new RepositoryCiJobExecutionJournal(new ForgejoWebhookJournalTests.TestLedger());
            await journal.PrepareAsync(accepted, Now);
            var root = Path.Combine(Path.GetTempPath(), $"ci-coordinator-{Guid.NewGuid():N}");
            var workspace = Path.Combine(root, "workspace");
            var home = Path.Combine(root, "home");
            var output = Path.Combine(root, "output");
            var dockerConfig = Path.Combine(root, "docker-config");
            foreach (var directory in new[] { root, workspace, home, output, dockerConfig })
            {
                Directory.CreateDirectory(directory);
                File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                    UnixFileMode.UserExecute);
            }
            var process = new RecordingProcess(exitCode);
            return new(
                root,
                workspace,
                output,
                accepted,
                journal,
                CiRunnerExecutionPlannerTests.Runner(accepted.Command),
                CiRunnerExecutionPlannerTests.Isolation(accepted.Command),
                CiRunnerBuildKitRuntime.Create("/run/user/1000", home, output, dockerConfig),
                new(new ObjectStore(storedArchive)),
                process);
        }

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
