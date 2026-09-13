using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Protocol.Tests;

public sealed class MessagingDeliverySemanticsTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 25, 12, 0, 0, TimeSpan.Zero);

    private static readonly AuthorityLeaseClaim LiveClaim =
        new(7, 42, Now.AddSeconds(10), "gru-regional", "gru-controller-controller-1");

    [Test]
    public async Task The_landed_redelivery_policy_is_pinned()
    {
        var policy = BoundedRedeliveryPolicy.Landed;

        await Assert.That(policy.IsWellFormed).IsTrue();
        await Assert.That(policy.MaximumDeliveries).IsEqualTo(5);
        await Assert.That(policy.AckWait).IsEqualTo(TimeSpan.FromSeconds(1));
        await Assert.That(policy.MaximumAckPending).IsEqualTo(8);
        await Assert.That(string.Join(',', policy.BackoffLadder.Select(static step => step.TotalSeconds)))
            .IsEqualTo("1,5,15,30");
        await Assert.That(policy.ExhaustionRequiresTerminalEvidence).IsTrue();
    }

    [Test]
    public async Task The_landed_redelivery_policy_matches_the_landed_cellspec_consumer_profiles()
    {
        var regional = new NatsTopology("gru", 3, "controller-1").CellSpecConsumer;
        var global = new GlobalNatsTopology(3).CellSpecConsumer("gru");
        var policy = BoundedRedeliveryPolicy.Landed;

        foreach (var consumer in new[] { regional, global })
        {
            await Assert.That(consumer.MaxDeliver).IsEqualTo(policy.MaximumDeliveries);
            await Assert.That(consumer.MaxAckPending).IsEqualTo(policy.MaximumAckPending);
            await Assert.That(consumer.AckWait).IsEqualTo(policy.AckWait);
            await Assert.That(string.Join(',', consumer.Backoff?.Select(static step => step.TotalSeconds) ?? []))
                .IsEqualTo(string.Join(',', policy.BackoffLadder.Select(static step => step.TotalSeconds)));
        }
    }

    [Test]
    public async Task Redelivery_policies_must_be_bounded_and_monotonic()
    {
        await Assert.That(new BoundedRedeliveryPolicy(0, [TimeSpan.FromSeconds(1)], 1, true).IsWellFormed).IsFalse();
        await Assert.That(new BoundedRedeliveryPolicy(
            5, Array.Empty<TimeSpan>(), 1, true).IsWellFormed).IsFalse();
        await Assert.That(new BoundedRedeliveryPolicy(
            5, [TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(1)], 1, true).IsWellFormed).IsFalse();
        await Assert.That(new BoundedRedeliveryPolicy(
            5, [TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1)], 1, true).IsWellFormed).IsFalse();
        await Assert.That(new BoundedRedeliveryPolicy(5, [TimeSpan.FromSeconds(1)], 0, true).IsWellFormed).IsFalse();
        await Assert.That(new BoundedRedeliveryPolicy(5, [TimeSpan.FromSeconds(1)], 8, false).IsWellFormed).IsFalse();
    }

    [Test]
    public async Task Acknowledgement_requires_a_durable_effect_and_double_ack()
    {
        await Assert.That(DurableEffectAcknowledgementPolicy.Landed.IsWellFormed).IsTrue();
        await Assert.That(DurableEffectAcknowledgementPolicy.Landed.RequiresDoubleAck).IsTrue();
        await Assert.That(new DurableEffectAcknowledgementPolicy(
            false, null, "journal acceptance").IsWellFormed).IsFalse();
    }

    [Test]
    public async Task Cancellation_never_admits_a_partial_acknowledgement()
    {
        await Assert.That(CancellationPolicy.Landed.IsWellFormed).IsTrue();
        await Assert.That(new CancellationPolicy(true, true).IsWellFormed).IsFalse();
    }

    [Test]
    public async Task Deterministic_conflicts_terminate_immediately_with_terminal_evidence()
    {
        foreach (var deliveryCount in new[] { 1, 3, 5 })
        {
            var decision = PoisonMessagePolicy.Decide(
                deterministicConflict: true,
                malformedInput: false,
                operationalCapacityFailure: false,
                deliveryCount,
                5,
                BoundedRedeliveryPolicy.Landed.BackoffLadder);

            await Assert.That(decision.Disposition).IsEqualTo(PoisonDisposition.Terminate);
            await Assert.That(decision.Reason).IsEqualTo(PoisonTerminalReason.DeterministicIdentityConflict);
        }
    }

    [Test]
    public async Task Transient_failures_retry_on_the_backoff_ladder_and_clamp_beyond_its_end()
    {
        var first = PoisonMessagePolicy.Decide(false, false, false, 1, 5, BoundedRedeliveryPolicy.Landed.BackoffLadder);
        await Assert.That(first.Disposition).IsEqualTo(PoisonDisposition.RetryWithDelay);
        await Assert.That(first.Delay).IsEqualTo(TimeSpan.FromSeconds(1));

        var reorderedFarBeyondLadder = PoisonMessagePolicy.Decide(
            false, false, false, 99, 5, BoundedRedeliveryPolicy.Landed.BackoffLadder);
        await Assert.That(reorderedFarBeyondLadder.Delay).IsEqualTo(TimeSpan.FromSeconds(30));
    }

    [Test]
    public async Task Malformed_input_retries_until_the_budget_is_exhausted_then_requires_terminal_evidence()
    {
        var beforeExhaustion = PoisonMessagePolicy.Decide(
            false, true, false, 4, 5, BoundedRedeliveryPolicy.Landed.BackoffLadder);
        await Assert.That(beforeExhaustion.Disposition).IsEqualTo(PoisonDisposition.RetryWithDelay);
        await Assert.That(beforeExhaustion.Reason).IsEqualTo(PoisonTerminalReason.MalformedEnvelope);

        var exhausted = PoisonMessagePolicy.Decide(
            false, true, false, 5, 5, BoundedRedeliveryPolicy.Landed.BackoffLadder);
        await Assert.That(exhausted.Disposition).IsEqualTo(PoisonDisposition.Exhausted);
        await Assert.That(exhausted.Reason).IsEqualTo(PoisonTerminalReason.MalformedEnvelope);

        var stillRetrying = PoisonMessagePolicy.Decide(
            false, true, false, 2, 5, BoundedRedeliveryPolicy.Landed.BackoffLadder);
        await Assert.That(stillRetrying.Disposition).IsEqualTo(PoisonDisposition.RetryWithDelay);
    }

    [Test]
    public async Task Operational_capacity_failures_hold_loudly_and_never_terminate_a_healthy_message()
    {
        var decision = PoisonMessagePolicy.Decide(
            false, false, true, 3, 5, BoundedRedeliveryPolicy.Landed.BackoffLadder);

        await Assert.That(decision.Disposition).IsEqualTo(PoisonDisposition.HoldForOperator);
        await Assert.That(decision.Reason).IsEqualTo(PoisonTerminalReason.JournalRetentionOverflow);
        await Assert.That(decision.Delay).IsEqualTo(TimeSpan.FromSeconds(30));
    }

    [Test]
    public async Task Invalid_poison_inputs_decide_nothing_rather_than_guessing()
    {
        var decision = PoisonMessagePolicy.Decide(false, false, false, 0, 5, [TimeSpan.FromSeconds(1)]);
        await Assert.That(decision.Disposition).IsEqualTo(PoisonDisposition.Unspecified);
    }

    [Test]
    public async Task Duplicate_windows_are_transport_suppression_only_and_never_claim_exactly_once()
    {
        await Assert.That(DuplicateWindowPolicy.CellStreams.Window).IsEqualTo(TimeSpan.FromMinutes(2));
        await Assert.That(DuplicateWindowPolicy.GlobalCiStream.Window).IsEqualTo(TimeSpan.FromHours(24));
        await Assert.That(DuplicateWindowPolicy.NoExactlyOnceClaim).Contains("exactly-once");
        await Assert.That(new DuplicateWindowPolicy(TimeSpan.Zero, "channel").IsWellFormed).IsFalse();
        await Assert.That(new DuplicateWindowPolicy(TimeSpan.FromDays(8), "channel").IsWellFormed).IsFalse();
    }

    [Test]
    public async Task The_duplicate_window_suppresses_replays_flags_conflicts_and_expires()
    {
        var window = new MessageIdDuplicateWindow(TimeSpan.FromMinutes(2), capacity: 4);

        await Assert.That(window.Observe("m1", "digest-a", Now))
            .IsEqualTo(DuplicateWindowDecision.Admit);
        await Assert.That(window.Observe("m1", "digest-a", Now.AddSeconds(30)))
            .IsEqualTo(DuplicateWindowDecision.Suppress);

        // Same message id with a different payload digest is a conflict, never a silent drop.
        await Assert.That(window.Observe("m1", "digest-b", Now.AddSeconds(40)))
            .IsEqualTo(DuplicateWindowDecision.Conflict);

        // Beyond the window the transport no longer suppresses; idempotency decides the effect.
        await Assert.That(window.Observe("m1", "digest-a", Now.AddMinutes(3)))
            .IsEqualTo(DuplicateWindowDecision.AdmitBeyondWindow);

        await Assert.That(window.Observe("", "digest", Now)).IsEqualTo(DuplicateWindowDecision.Admit);
    }

    [Test]
    public async Task The_duplicate_window_evicts_oldest_entries_at_capacity()
    {
        var window = new MessageIdDuplicateWindow(TimeSpan.FromMinutes(2), capacity: 2);

        window.Observe("m1", "d1", Now);
        window.Observe("m2", "d2", Now);
        window.Observe("m3", "d3", Now);

        await Assert.That(window.Count).IsEqualTo(2);
        await Assert.That(window.Observe("m1", "d1", Now.AddSeconds(1)))
            .IsEqualTo(DuplicateWindowDecision.Admit);
    }

    [Test]
    public async Task Beyond_window_reobservation_of_a_resident_id_keeps_exactly_one_fifo_slot()
    {
        // A beyond-window refresh of a RESIDENT id must not re-enqueue it: Remove + Remember
        // would leave the id's old eviction slot queued, so later evictions dequeue ids that
        // are no longer tracked and observed.Count can exceed capacity.
        var window = new MessageIdDuplicateWindow(TimeSpan.FromMinutes(2), capacity: 3);

        window.Observe("a", "da", Now);
        window.Observe("b", "db", Now);
        window.Observe("c", "dc", Now);
        window.Observe("a", "da", Now.AddMinutes(5));
        await Assert.That(window.Count).IsEqualTo(3);

        // Fresh ids push the queue forward until the stale "a" slot would surface while "a"
        // itself is no longer tracked; every insertion must still respect the capacity.
        foreach (var fresh in new[] { "d", "e", "f", "g" })
        {
            window.Observe(fresh, "d-" + fresh, Now.AddMinutes(5));
            await Assert.That(window.Count <= 3).IsTrue();
        }
    }

    [Test]
    public async Task Beyond_window_reobservation_churn_keeps_the_capacity_bound_and_correct_decisions()
    {
        const int capacity = 3;
        var window = new MessageIdDuplicateWindow(TimeSpan.FromMinutes(2), capacity);
        var churnIds = new[] { "redelivery-0", "redelivery-1", "redelivery-2", "redelivery-3" };

        for (var round = 0; round < 120; round++)
        {
            var now = Now.AddMinutes(5 * round);

            // Re-observe a churn id beyond the window: admitted either because it stayed
            // resident (AdmitBeyondWindow) or because capacity pressure evicted it (Admit).
            var decision = window.Observe(churnIds[round % churnIds.Length], "digest-churn", now);
            await Assert.That(decision is DuplicateWindowDecision.Admit
                or DuplicateWindowDecision.AdmitBeyondWindow).IsTrue();
            await Assert.That(window.Count <= capacity).IsTrue();

            // The refresh is resident now: an in-window replay with the same digest suppresses.
            await Assert.That(window.Observe(churnIds[round % churnIds.Length], "digest-churn", now))
                .IsEqualTo(DuplicateWindowDecision.Suppress);
            await Assert.That(window.Count <= capacity).IsTrue();

            // Fresh ids keep flowing, forcing evictions across the churn.
            await Assert.That(window.Observe($"fresh-{round}", $"digest-{round}", now))
                .IsEqualTo(DuplicateWindowDecision.Admit);
            await Assert.That(window.Count <= capacity).IsTrue();
        }
    }

    [Test]
    public async Task Queue_group_ownership_admits_only_the_live_fenced_leader()
    {
        await Assert.That(QueueGroupOwnership.Decide(LiveClaim, true, 7, 42, requiresAuthority: true))
            .IsEqualTo(QueueGroupAdmission.Admit);

        await Assert.That(QueueGroupOwnership.Decide(LiveClaim, false, 7, 42, requiresAuthority: true))
            .IsEqualTo(QueueGroupAdmission.NotLeader);
        await Assert.That(QueueGroupOwnership.Decide(null, true, 7, 42, requiresAuthority: true))
            .IsEqualTo(QueueGroupAdmission.NotLeader);
    }

    [Test]
    public async Task Stale_and_superseded_epochs_are_fenced_or_left_for_the_new_holder()
    {
        // A reordered stale delivery from an older epoch: fence it — do not act, do not acknowledge.
        await Assert.That(QueueGroupOwnership.Decide(LiveClaim, true, 6, 41, requiresAuthority: true))
            .IsEqualTo(QueueGroupAdmission.StaleEpoch);

        // A message from a newer epoch: this holder lost the lease; leave the work.
        await Assert.That(QueueGroupOwnership.Decide(LiveClaim, true, 8, 43, requiresAuthority: true))
            .IsEqualTo(QueueGroupAdmission.LeaseLost);

        // Same epoch but a different generation: stale claim, fenced.
        await Assert.That(QueueGroupOwnership.Decide(LiveClaim, true, 7, 43, requiresAuthority: true))
            .IsEqualTo(QueueGroupAdmission.StaleEpoch);
    }

    [Test]
    public async Task Equivalent_worker_queue_groups_do_not_require_the_authority_lease()
    {
        await Assert.That(QueueGroupOwnership.Decide(LiveClaim, isLeader: false, 0, 0, requiresAuthority: false))
            .IsEqualTo(QueueGroupAdmission.Admit);
    }

    [Test]
    public async Task Authoritative_writes_require_the_same_live_claim_before_effect_and_before_acknowledgement()
    {
        await Assert.That(QueueGroupOwnership.MayCommitAuthoritativeWrite(LiveClaim, LiveClaim, Now)).IsTrue();

        // Lease expired between effect and acknowledgement: withhold.
        var expired = LiveClaim with { LeaseExpiresAt = Now.AddSeconds(-1) };
        await Assert.That(QueueGroupOwnership.MayCommitAuthoritativeWrite(expired, expired, Now)).IsFalse();

        // Split writer: a different candidate took over between effect and acknowledgement.
        var successor = LiveClaim with { Epoch = 8, KvRevision = 43, CandidateId = "gru-controller-controller-2" };
        await Assert.That(QueueGroupOwnership.MayCommitAuthoritativeWrite(LiveClaim, successor, Now)).IsFalse();
        await Assert.That(QueueGroupOwnership.MayCommitAuthoritativeWrite(successor, LiveClaim, Now)).IsFalse();
        await Assert.That(QueueGroupOwnership.MayCommitAuthoritativeWrite(null, LiveClaim, Now)).IsFalse();
        await Assert.That(QueueGroupOwnership.MayCommitAuthoritativeWrite(LiveClaim, null, Now)).IsFalse();
    }
}

