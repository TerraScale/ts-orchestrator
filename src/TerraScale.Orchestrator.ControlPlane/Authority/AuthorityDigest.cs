using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace TerraScale.Orchestrator.ControlPlane.Authority;

public static class AuthorityDigest
{
    public static readonly string EmptyJournalDigest = Hash("TerraScale.AuthorityJournal.v1");

    public static string Event(AuthorityEvent @event) => Hash(EncodeEvent(@event, false));

    public static string State(AuthorityState state) => Hash(Encode(
        "authority-state-v1", state.AuthorityId, state.CandidateId, state.Status,
        state.LastSequence, state.JournalDigest, state.HighestEpoch, state.HighestKvRevision, state.Confirmed,
        state.PendingSet, state.PendingDelete, state.PendingReadRequestId, state.PendingReadCandidateId,
        state.ReadResumeStatus, state.LastCompletedRequestId, state.LastError));

    public static string Decision(
        AuthorityState state,
        IReadOnlyList<AuthorityEvent> events,
        IReadOnlyList<AuthorityIntent> intents,
        IReadOnlyList<AuthorityError> errors,
        MutationAuthorityPermit? permit) => Hash(Encode("authority-decision-v1", State(state), events, intents, errors, permit));

    private static string EncodeEvent(AuthorityEvent @event, bool includeDigest) => @event switch
    {
        AuthoritySetRequested value => Encode("set-requested", Common(value, includeDigest), value.Pending),
        AuthoritySetConfirmed value => Encode("set-confirmed", Common(value, includeDigest), value.Observation, value.Health, value.WasRenewal),
        AuthoritySetRejected value => Encode("set-rejected", Common(value, includeDigest), value.Outcome, value.Observation, value.Error),
        AuthorityDeleteRequested value => Encode("delete-requested", Common(value, includeDigest), value.Pending),
        AuthorityDeleteConfirmed value => Encode("delete-confirmed", Common(value, includeDigest), value.Observation),
        AuthorityReadRequested value => Encode("read-requested", Common(value, includeDigest), value.ResumeStatus),
        AuthorityReadConfirmed value => Encode("read-confirmed", Common(value, includeDigest), value.Observation, value.Health),
        AuthorityHeld value => Encode("held", Common(value, includeDigest), value.HeldFrom, value.Observation, value.Error),
        AuthorityFencedEvent value => Encode("fenced", Common(value, includeDigest), value.Observation, value.Error),
        _ => throw new ArgumentOutOfRangeException(nameof(@event)),
    };

    private static object?[] Common(AuthorityEvent value, bool includeDigest) =>
        [value.Sequence, value.PreviousDigest, includeDigest ? value.EventDigest : null,
            value.AuthorityId, value.CandidateId, value.RequestId];

    private static string Encode(params object?[] values)
    {
        var builder = new StringBuilder();
        foreach (var value in values) Append(builder, value);
        return builder.ToString();
    }

    private static void Append(StringBuilder builder, object? value)
    {
        switch (value)
        {
            case null: builder.Append("N;"); return;
            case string text: builder.Append('S').Append(text.Length).Append(':').Append(text).Append(';'); return;
            case bool boolean: builder.Append(boolean ? "B1;" : "B0;"); return;
            case long number: builder.Append('L').Append(number.ToString(CultureInfo.InvariantCulture)).Append(';'); return;
            case Enum enumeration: Append(builder, Convert.ToInt64(enumeration, CultureInfo.InvariantCulture)); return;
            case DateTimeOffset instant:
                builder.Append('T').Append(instant.ToUniversalTime().Ticks.ToString(CultureInfo.InvariantCulture)).Append(';'); return;
            case TimeSpan duration:
                builder.Append('D').Append(duration.Ticks.ToString(CultureInfo.InvariantCulture)).Append(';'); return;
            case AuthorityLease lease:
                Append(builder, Encode("lease-v1", lease.CandidateId, lease.LeaseId, lease.ServerIssuedAt, lease.Duration)); return;
            case AuthorityObservation observation:
                Append(builder, Encode("observation-v1", observation.AuthorityId, observation.KvRevision,
                    observation.Epoch, observation.ObservationId, observation.Lease)); return;
            case AuthorityHealth health:
                Append(builder, Encode("health-v1", health.ServerTime, health.MonotonicElapsed,
                    health.PartitionCertain, health.ClockCertain)); return;
            case PendingAuthoritySet pending:
                Append(builder, Encode("pending-set-v1", pending.RequestId, pending.ExpectedRevision,
                    pending.ExpectedEpoch, pending.ProposedEpoch, pending.ProposedLease,
                    pending.ExpectedObservation, pending.RequestedAtHealth, pending.IsRenewal)); return;
            case PendingAuthorityDelete pending:
                Append(builder, Encode("pending-delete-v1", pending.RequestId, pending.ExpectedRevision,
                    pending.ExpectedEpoch, pending.ExpectedLease, pending.RequestedAtHealth)); return;
            case AuthorityError error:
                Append(builder, Encode("error-v1", error.Code, error.Requirement, error.Message)); return;
            case AuthorityEvent @event: Append(builder, EncodeEvent(@event, true)); return;
            case CompareAndSetLeaseIntent intent:
                Append(builder, Encode("cas-set-v1", intent.AuthorityId, intent.RequestId,
                    intent.ExpectedRevision, intent.ExpectedEpoch, intent.ProposedEpoch, intent.ProposedLease)); return;
            case CompareAndDeleteLeaseIntent intent:
                Append(builder, Encode("cas-delete-v1", intent.AuthorityId, intent.RequestId,
                    intent.ExpectedRevision, intent.ExpectedEpoch, intent.ExpectedLease)); return;
            case ReadAuthorityIntent intent:
                Append(builder, Encode("read-v1", intent.AuthorityId, intent.RequestId, intent.CandidateId,
                    intent.ResumeStatus, intent.ExpectedHighestEpoch, intent.ExpectedHighestKvRevision,
                    intent.ExpectedConfirmedObservation)); return;
            case MutationAuthorityPermit permit:
                Append(builder, Encode("mutation-permit-v1", permit.AuthorityId, permit.CandidateId,
                    permit.LeaseId, permit.Epoch, permit.KvRevision, permit.ObservationId,
                    permit.EvaluatedServerTime, permit.EvaluatedMonotonicElapsed)); return;
            case System.Collections.IEnumerable sequence:
                var items = sequence.Cast<object?>().ToArray();
                builder.Append('A').Append(items.Length).Append('[');
                foreach (var item in items) Append(builder, item);
                builder.Append("];"); return;
            default: throw new ArgumentException($"Unsupported digest value {value.GetType().FullName}.", nameof(value));
        }
    }

    private static string Hash(string value) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
