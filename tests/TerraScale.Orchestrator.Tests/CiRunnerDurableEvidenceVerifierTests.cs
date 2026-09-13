using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class CiRunnerDurableEvidenceVerifierTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task CanonicalEvidenceMustMatchTheExactAcceptedExecution()
    {
        var fixture = await Fixture.CreateAsync();

        var verified = await fixture.Verifier.VerifyAsync(fixture.Execution, default);

        await Assert.That(verified).IsTrue();
    }

    [Test]
    public async Task CanonicalArchitectureRootEvidenceSurvivesControllerReadback()
    {
        var fixture = await Fixture.CreateAsync(withArtifacts: true);

        var verified = await fixture.Verifier.VerifyAsync(fixture.Execution, default);

        await Assert.That(verified).IsTrue();
    }

    [Test]
    public async Task ContentCorruptionFailsTheTerminalEvidenceDigest()
    {
        var fixture = await Fixture.CreateAsync();
        fixture.Store.Values[$"ci-result-evidence-{fixture.Execution.EvidenceDigest}"][0] ^= 1;

        var verified = await fixture.Verifier.VerifyAsync(fixture.Execution, default);

        await Assert.That(verified).IsFalse();
    }

    [Test]
    public async Task ReferencedLogCorruptionFailsBeforeResultProjection()
    {
        var fixture = await Fixture.CreateAsync();
        fixture.Store.Values[fixture.LogObject][0] ^= 1;

        var verified = await fixture.Verifier.VerifyAsync(fixture.Execution, default);

        await Assert.That(verified).IsFalse();
    }

    [Test]
    public async Task ReferencedArtifactCorruptionFailsBeforeResultProjection()
    {
        var fixture = await Fixture.CreateAsync();
        fixture.Store.Values[fixture.ArtifactObject][0] ^= 1;

        var verified = await fixture.Verifier.VerifyAsync(fixture.Execution, default);

        await Assert.That(verified).IsFalse();
    }

    [Test]
    public async Task RehashedUnsafeLogStillFailsBeforeResultProjection()
    {
        var fixture = await Fixture.CreateAsync(unsafeLog: true);

        var verified = await fixture.Verifier.VerifyAsync(fixture.Execution, default);

        await Assert.That(verified).IsFalse();
    }

    [Test]
    public async Task RehashedArtifactCannotExceedItsDeclaredBound()
    {
        var fixture = await Fixture.CreateAsync(artifactBytesAdjustment: -1);

        var verified = await fixture.Verifier.VerifyAsync(fixture.Execution, default);

        await Assert.That(verified).IsFalse();
    }

    [Test]
    public async Task RehashedEvidenceFromAnotherLeaseCannotSatisfyTheExecutionPointer()
    {
        var fixture = await Fixture.CreateAsync(changeLeaseSequence: true);

        var verified = await fixture.Verifier.VerifyAsync(fixture.Execution, default);

        await Assert.That(verified).IsFalse();
    }

    [Test]
    public async Task InvalidArchitectureArtifactDeclarationFailsBeforeProjection()
    {
        var fixture = await Fixture.CreateAsync(invalidArtifact: true);

        var verified = await fixture.Verifier.VerifyAsync(fixture.Execution, default);

        await Assert.That(verified).IsFalse();
    }

    private sealed record Fixture(
        TestObjectStore Store,
        CiRunnerDurableEvidenceVerifier Verifier,
        RepositoryCiJobExecutionSnapshot Execution,
        string LogObject,
        string ArtifactObject)
    {
        internal static async Task<Fixture> CreateAsync(
            bool changeLeaseSequence = false,
            bool unsafeLog = false,
            int artifactBytesAdjustment = 0,
            bool invalidArtifact = false,
            bool withArtifacts = false)
        {
            var accepted = await RepositoryCiJobInboxTests.AcceptedAsync();
            var journal = new RepositoryCiJobExecutionJournal(
                new ForgejoWebhookJournalTests.TestLedger());
            await journal.PrepareAsync(accepted, Now);
            var acquired = await journal.AcquireAsync(
                accepted,
                accepted.Command.Operation,
                Now.AddSeconds(1),
                TimeSpan.FromMinutes(5));
            var execution = acquired.Execution!;
            var log = unsafeLog ? "password=hunter2"u8.ToArray() : "redacted build log"u8.ToArray();
            var artifact = "deterministic artifact archive"u8.ToArray();
            var workload = new CiRunnerWorkloadEvidence(
                1,
                execution.Document.Runner,
                execution.Document.PipelineDigest,
                execution.Document.Job,
                execution.Document.JobDigest,
                execution.Document.ExecutionIdentityDigest,
                execution.Document.PayloadDigest,
                execution.Document.SignatureDigest,
                execution.Document.StreamSequence,
                execution.Document.AcceptanceRevision,
                execution.Document.Attempt,
                execution.Document.LeaseSequence + (changeLeaseSequence ? 1 : 0),
                Digest('a'),
                Digest('b'),
                Digest('c'),
                Digest('d'),
                CiRunnerBuildKitExecutionDisposition.Succeeded,
                0,
                Hash(log),
                log.LongLength,
                Digest('f'),
                Digest('1'),
                1,
                1024,
                true,
                RepositoryCiJobFailureKind.Unspecified,
                CiRunnerWorkloadFailureCode.Unspecified);
            var logObject = $"ci-result-log-{workload.LogSha256}";
            var artifactObject = $"ci-result-artifact-{workload.OutputSha256}";
            var stored = new CiRunnerStoredWorkloadEvidence(
                2,
                workload,
                logObject,
                workload.LogSha256,
                workload.LogBytes,
                artifactObject,
                Hash(artifact),
                artifact.LongLength + artifactBytesAdjustment,
                invalidArtifact || withArtifacts
                    ? [new(
                        "TerraScale/TerraScale.Orchestrator",
                        invalidArtifact
                            ? RepositoryCiArchitecture.Unspecified
                            : RepositoryCiArchitecture.LinuxX64,
                        "linux-x64",
                        Digest('2'),
                        1,
                        100,
                        ["app"])]
                    : [],
                0,
                30);
            var content = JsonSerializer.SerializeToUtf8Bytes(
                stored,
                CiRunnerDurableResultJsonContext.Default.CiRunnerStoredWorkloadEvidence);
            var digest = Convert.ToHexStringLower(SHA256.HashData(content));
            var store = new TestObjectStore();
            store.Values[logObject] = log;
            store.Values[artifactObject] = artifact;
            store.Values[$"ci-result-evidence-{digest}"] = content;
            var completed = await journal.CompleteAsync(
                execution,
                true,
                digest,
                0,
                RepositoryCiJobFailureKind.Unspecified,
                Now.AddSeconds(2));
            return new(store, new(store), completed.Execution!, logObject, artifactObject);
        }
    }

    private static string Digest(char value) => new(value, 64);

    private static string Hash(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));

    private sealed class TestObjectStore : IDeliveryObjectStore
    {
        internal Dictionary<string, byte[]> Values { get; } = new(StringComparer.Ordinal);

        public Task PutAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Values[name].ToArray());
        }
    }
}

