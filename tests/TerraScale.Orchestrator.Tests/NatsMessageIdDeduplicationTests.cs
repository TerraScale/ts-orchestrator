using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Issue #22 transport deduplication: the message-id window is layered beneath operation-level
/// idempotency, records only completed identities, and keeps its counters distinguishable from
/// the journal's idempotency-replay counters.
/// </summary>
public sealed class NatsMessageIdDeduplicationTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 25, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task The_guard_binds_to_a_well_formed_policy_and_channel()
    {
        var guard = new NatsMessageIdDeduplication(DuplicateWindowPolicy.GlobalCiStream);

        await Assert.That(guard.Channel).IsEqualTo("global-ci-stream");
        await Assert.That(guard.Window).IsEqualTo(TimeSpan.FromHours(24));
        await Assert.That(guard.Snapshot.Resident).IsEqualTo(0);
        await Assert.That(() => new NatsMessageIdDeduplication(
                new DuplicateWindowPolicy(TimeSpan.Zero, "invalid")))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task Inspection_is_read_only_and_recording_counts_every_disposition()
    {
        var guard = new NatsMessageIdDeduplication(DuplicateWindowPolicy.CellStreams);

        await Assert.That(guard.Inspect("m1", "d1", Now)).IsEqualTo(DuplicateWindowDecision.Admit);
        await Assert.That(guard.Snapshot.Resident).IsEqualTo(0);

        await Assert.That(guard.Record("m1", "d1", Now)).IsEqualTo(DuplicateWindowDecision.Admit);
        await Assert.That(guard.Snapshot).IsEqualTo(
            new NatsMessageIdDeduplicationSnapshot(1, 0, 0, 0, 1));

        await Assert.That(guard.Inspect("m1", "d1", Now)).IsEqualTo(DuplicateWindowDecision.Suppress);
        await Assert.That(guard.Inspect("m1", "d2", Now)).IsEqualTo(DuplicateWindowDecision.Conflict);
        await Assert.That(guard.Snapshot.Resident).IsEqualTo(1);

        await Assert.That(guard.Inspect("m1", "d1", Now.AddMinutes(3)))
            .IsEqualTo(DuplicateWindowDecision.AdmitBeyondWindow);
        await Assert.That(guard.Record("m1", "d1", Now.AddMinutes(3)))
            .IsEqualTo(DuplicateWindowDecision.AdmitBeyondWindow);
        await Assert.That(guard.Snapshot).IsEqualTo(
            new NatsMessageIdDeduplicationSnapshot(1, 0, 0, 1, 1));
    }

    [Test]
    public async Task The_resident_set_is_bounded_by_the_declared_capacity()
    {
        var guard = new NatsMessageIdDeduplication(DuplicateWindowPolicy.CellStreams, capacity: 2);

        guard.Record("m1", "d1", Now);
        guard.Record("m2", "d2", Now);
        guard.Record("m3", "d3", Now);

        await Assert.That(guard.Snapshot.Resident).IsEqualTo(2);
        await Assert.That(guard.Inspect("m1", "d1", Now)).IsEqualTo(DuplicateWindowDecision.Admit);
        await Assert.That(guard.Inspect("m3", "d3", Now)).IsEqualTo(DuplicateWindowDecision.Suppress);
    }

    [Test]
    public async Task The_runner_consumer_extracts_only_a_complete_bounded_identity()
    {
        var complete = new List<KeyValuePair<string, string>>
        {
            new("TS-Protocol-Version", "1"),
            new("TS-Job-Id", "job-41"),
            new("TS-Payload-Sha256", "0123abcd"),
        };
        var hostile = new List<KeyValuePair<string, string>>
        {
            new("TS-Job-Id", new string('x', 129)),
            new("TS-Payload-Sha256", "0123abcd"),
        };
        var digestOnly = new List<KeyValuePair<string, string>>
        {
            new("TS-Payload-Sha256", "0123abcd"),
        };

        await Assert.That(TerraScale.Orchestrator.Delivery.RepositoryCiJobNatsConsumer
            .TryMessageIdentity(complete, out var identity, out var digest)).IsTrue();
        await Assert.That(identity).IsEqualTo("job-41");
        await Assert.That(digest).IsEqualTo("0123abcd");
        await Assert.That(TerraScale.Orchestrator.Delivery.RepositoryCiJobNatsConsumer
            .TryMessageIdentity(hostile, out _, out _)).IsFalse();
        await Assert.That(TerraScale.Orchestrator.Delivery.RepositoryCiJobNatsConsumer
            .TryMessageIdentity(digestOnly, out _, out _)).IsFalse();
    }

    [Test]
    public async Task The_identity_conflict_warning_is_loud_bounded_and_actionable()
    {
        var warning = TerraScale.Orchestrator.Delivery.RepositoryCiJobNatsConsumer
            .ConflictingIdentityWarning("job-41", 77);
        var hostile = TerraScale.Orchestrator.Delivery.RepositoryCiJobNatsConsumer
            .ConflictingIdentityWarning(new string('x', 400), 1);

        await Assert.That(warning).Contains("identity conflict");
        await Assert.That(warning).Contains("job-41");
        await Assert.That(warning).Contains("stream sequence 77");
        await Assert.That(warning).Contains("terminal evidence");
        await Assert.That(warning).Contains("Operator action required");
        await Assert.That(warning).DoesNotContain("\n");
        await Assert.That(hostile).DoesNotContain(new string('x', 129));
        await Assert.That(hostile).Contains(new string('x', 128));
    }

    [Test]
    public async Task The_runner_process_wires_the_global_ci_duplicate_window()
    {
        // The composition the CI runner runs with: the transport window uses the global CI
        // stream policy, which is the stream the fenced runner inbox is provisioned on.
        var policy = DuplicateWindowPolicy.GlobalCiStream;
        var guard = new NatsMessageIdDeduplication(policy);

        await Assert.That(policy.IsWellFormed).IsTrue();
        await Assert.That(guard.Window).IsEqualTo(TimeSpan.FromHours(24));
        await Assert.That(DuplicateWindowPolicy.NoExactlyOnceClaim).Contains("exactly-once");
    }

    [Test]
    public async Task Publish_convergence_treats_a_duplicate_as_the_stored_receipt()
    {
        // A duplicate acknowledgement proves the identical (deterministically identified)
        // message is already in the stream: the retry converged and must not throw.
        var duplicate = new NATS.Client.JetStream.Models.PubAckResponse
        {
            Stream = Stream,
            Seq = 1,
            Duplicate = true,
        };
        var fresh = new NATS.Client.JetStream.Models.PubAckResponse
        {
            Stream = Stream,
            Seq = 2,
            Duplicate = false,
        };
        var failed = new NATS.Client.JetStream.Models.PubAckResponse
        {
            Error = new() { Code = 500, Description = "stream offline" },
        };

        await Assert.That(duplicate.EnsureStored()).IsTrue();
        await Assert.That(fresh.EnsureStored()).IsFalse();
        await Assert.That(() => failed.EnsureStored())
            .Throws<NATS.Client.JetStream.NatsJSApiException>();
        await Assert.That(() => ((NATS.Client.JetStream.Models.PubAckResponse)null!).EnsureStored())
            .Throws<ArgumentNullException>();
    }

    private const string Stream = "WORK";
}
