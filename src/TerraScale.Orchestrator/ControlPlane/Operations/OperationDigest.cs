using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Cysharp.Text;

namespace TerraScale.Orchestrator.ControlPlane.Operations;

public static class OperationDigest
{
    public static readonly string EmptyJournalDigest = Hash("TerraScale.OperationJournal.v1");

    public static string Authorization(
        long sequence,
        string previousDigest,
        string operationId,
        long writerEpoch,
        DesiredOperation desired,
        AuthorizationEvidence evidence,
        IReadOnlyList<string> compensations) => Hash(Encode(
            "authorization-v1", sequence, previousDigest, operationId, writerEpoch,
            desired, evidence, compensations));

    public static string Event(OperationEvent @event) => Hash(EncodeEvent(@event, includeEventDigest: false));

    public static string State(OperationState state) => Hash(Encode(
        "state-v1", state.OperationId, state.Checkpoint, state.LastSequence,
        state.JournalDigest, state.HighestWriterEpoch, state.Desired,
        state.ExpectedObservation, state.PermittedCompensations,
        state.Authorization, state.Dispatch, state.Recovery, state.Observation, state.Terminal, state.Hold));

    public static string Decision(
        OperationState state,
        IReadOnlyList<OperationEvent> events,
        IReadOnlyList<OperationIntent> intents,
        IReadOnlyList<OperationError> errors) => Hash(Encode(
            "decision-v1", State(state), events, intents, errors));

    private static string EncodeEvent(OperationEvent @event, bool includeEventDigest) => @event switch
    {
        OperationPrepared value => Encode("prepared", value.Sequence, value.PreviousDigest,
            includeEventDigest ? value.EventDigest : null, value.OperationId, value.WriterEpoch,
            value.RecordedAt, value.Desired, value.ExpectedObservation, value.PermittedCompensations),
        OperationAuthorized value => Encode("authorized", value.Sequence, value.PreviousDigest,
            includeEventDigest ? value.EventDigest : null, value.OperationId, value.WriterEpoch,
            value.RecordedAt, value.Evidence, value.AuthorizationDigest),
        OperationDispatchRecorded value => Encode("dispatch", value.Sequence, value.PreviousDigest,
            includeEventDigest ? value.EventDigest : null, value.OperationId, value.WriterEpoch,
            value.RecordedAt, value.ExecutorId, value.Attempt),
        OperationRecoveryRecorded value => Encode("recovery", value.Sequence, value.PreviousDigest,
            includeEventDigest ? value.EventDigest : null, value.OperationId, value.WriterEpoch,
            value.RecordedAt, value.ExecutorId, value.DispatchSequence),
        OperationObservationRecorded value => Encode("observation", value.Sequence, value.PreviousDigest,
            includeEventDigest ? value.EventDigest : null, value.OperationId, value.WriterEpoch,
            value.RecordedAt, value.ObservationId, value.TargetIdentity, value.Generation,
            value.TerminalState, value.Outcome, value.ProviderWorkRequestId),
        OperationTerminalRecorded value => Encode("terminal", value.Sequence, value.PreviousDigest,
            includeEventDigest ? value.EventDigest : null, value.OperationId, value.WriterEpoch,
            value.RecordedAt, value.Outcome, value.TerminalState),
        OperationHeld value => Encode("held", value.Sequence, value.PreviousDigest,
            includeEventDigest ? value.EventDigest : null, value.OperationId, value.WriterEpoch,
            value.RecordedAt, value.HeldAfter, value.Error),
        _ => throw new ArgumentOutOfRangeException(nameof(@event)),
    };

    private static string Encode(params object?[] values)
    {
        using var builder = new ZStringWriter();
        foreach (var value in values)
        {
            Append(builder, value);
        }

        return builder.ToString();
    }

    private static void Append(ZStringWriter builder, object? value)
    {
        switch (value)
        {
            case null:
                builder.Write("N;");
                return;
            case string text:
                {
                    builder.Write('S');
                    builder.Write(text.Length);
                    builder.Write(':');
                    builder.Write(text);
                    builder.Write(';');
                }
                return;
            case bool boolean:
                builder.Write(boolean ? "B1;" : "B0;");
                return;
            case Enum enumeration:
                Append(builder, Convert.ToInt64(enumeration, CultureInfo.InvariantCulture));
                return;
            case long number:
                {
                    builder.Write('L');
                    builder.Write(number.ToString(CultureInfo.InvariantCulture));
                    builder.Write(';');
                }
                return;
            case DateTimeOffset instant:
                {
                    builder.Write('T');
                    builder.Write(instant.ToUniversalTime().Ticks.ToString(CultureInfo.InvariantCulture));
                    builder.Write(';');
                }
                return;
            case DesiredOperation desired:
                Append(builder, Encode("desired-v1", desired.AggregateId, desired.Generation,
                    desired.ResourceVersion, desired.OperationKind, desired.TargetIdentity,
                    desired.DesiredTerminalState, desired.PayloadDigest, desired.IdempotencyKey,
                    desired.Deadline));
                return;
            case ObservedResource observed:
                Append(builder, Encode("observed-v1", observed.AggregateId, observed.Generation,
                    observed.ResourceVersion, observed.ObservationId, observed.TargetIdentity,
                    observed.State, observed.PositivelyOwned));
                return;
            case AuthorizationEvidence evidence:
                Append(builder, Encode("authorization-evidence-v1", evidence.Observation,
                    evidence.ApprovalDigest, evidence.EvidenceDigest, evidence.ApprovalsSatisfied,
                evidence.PolicySatisfied, evidence.QuorumSatisfied, evidence.BudgetSatisfied, evidence.TenantId));
                return;
            case OperationError error:
                Append(builder, Encode("error-v1", error.Code, error.Requirement, error.Message));
                return;
            case OperationEvent @event:
                Append(builder, EncodeEvent(@event, includeEventDigest: true));
                return;
            case DispatchProviderIntent intent:
                Append(builder, Encode("dispatch-intent-v2", intent.OperationId,
                    intent.OperationKind, intent.AggregateId, intent.DesiredGeneration,
                    intent.DesiredResourceVersion, intent.TargetIdentity, intent.DesiredTerminalState,
                    intent.PayloadDigest, intent.IdempotencyKey, intent.AuthorizedObservationId,
                    intent.AuthorizedResourceVersion, intent.PermittedCompensations, intent.AuthorizationSequence,
                    intent.AuthorizationDigest, intent.AuthorizingEpoch, intent.ExecutorEpoch,
                    intent.ExecutorId, intent.DispatchAttempt, intent.Deadline));
                return;
            case ReconcileProviderIntent intent:
                Append(builder, Encode("reconcile-intent-v1", intent.OperationId,
                    intent.TargetIdentity, intent.DesiredGeneration, intent.IdempotencyKey,
                    intent.ProviderWorkRequestId, intent.AuthorizationSequence,
                    intent.AuthorizationDigest));
                return;
            case OperationState state:
                Append(builder, State(state));
                return;
            case System.Collections.ICollection collection:
                {
                    builder.Write('A');
                    builder.Write(collection.Count);
                    builder.Write('[');
                }
                foreach (var item in collection) Append(builder, item);
                builder.Write("];");
                return;
            case System.Collections.IEnumerable sequence:
                var items = sequence.Cast<object?>().ToArray();
                {
                    builder.Write('A');
                    builder.Write(items.Length);
                    builder.Write('[');
                }
                foreach (var item in items) Append(builder, item);
                builder.Write("];");
                return;
            default:
                throw new ArgumentException($"Unsupported digest value {value.GetType().FullName}.", nameof(value));
        }
    }

    private static string Hash(string value) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}

