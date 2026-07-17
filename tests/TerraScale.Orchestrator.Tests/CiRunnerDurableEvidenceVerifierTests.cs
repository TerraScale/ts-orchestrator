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
    public async Task ContentCorruptionFailsTheTerminalEvidenceDigest()
    {
        var fixture = await Fixture.CreateAsync();
        fixture.Store.Values[$"ci-result-evidence-{fixture.Execution.EvidenceDigest}"][0] ^= 1;

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

    private sealed record Fixture(
        TestObjectStore Store,
        CiRunnerDurableEvidenceVerifier Verifier,
        RepositoryCiJobExecutionSnapshot Execution)
    {
        internal static async Task<Fixture> CreateAsync(bool changeLeaseSequence = false)
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
                Digest('e'),
                128,
                Digest('f'),
                Digest('1'),
                1,
                1024,
                true,
                RepositoryCiJobFailureKind.Unspecified,
                CiRunnerWorkloadFailureCode.Unspecified);
            var stored = new CiRunnerStoredWorkloadEvidence(
                1,
                workload,
                $"ci-result-log-{workload.LogSha256}",
                workload.LogSha256,
                workload.LogBytes,
                $"ci-result-artifact-{workload.OutputSha256}",
                Digest('2'),
                512,
                0,
                30);
            var content = JsonSerializer.SerializeToUtf8Bytes(
                stored,
                CiRunnerDurableResultJsonContext.Default.CiRunnerStoredWorkloadEvidence);
            var digest = Convert.ToHexStringLower(SHA256.HashData(content));
            var store = new TestObjectStore();
            store.Values[$"ci-result-evidence-{digest}"] = content;
            var completed = await journal.CompleteAsync(
                execution,
                true,
                digest,
                0,
                RepositoryCiJobFailureKind.Unspecified,
                Now.AddSeconds(2));
            return new(store, new(store), completed.Execution!);
        }
    }

    private static string Digest(char value) => new(value, 64);

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
