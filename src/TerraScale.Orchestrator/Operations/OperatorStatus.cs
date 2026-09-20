using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Operations;

/// <summary>
/// Authenticated, read-only regional operator view. It deliberately contains only
/// bounded workload identities and aggregate progress; database names, instance ids,
/// credentials, payloads, and customer data never cross this contract.
/// </summary>
public sealed record OperatorStatusDocument(
    int SchemaVersion,
    string Cell,
    string Instance,
    bool Healthy,
    DateTimeOffset ObservedAt,
    IReadOnlyList<OperatorWorkloadStatus> Workloads,
    IReadOnlyList<OperatorActionStatus> Actions,
    IReadOnlyList<string> Needs)
{
    public const int CurrentSchemaVersion = 1;

    public void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion ||
            string.IsNullOrWhiteSpace(Cell) || Cell.Length > 64 ||
            string.IsNullOrWhiteSpace(Instance) || Instance.Length > 128 ||
            ObservedAt == default || Workloads is null || Actions is null || Needs is null ||
            Workloads.Count > 64 || Actions.Count > 128 || Needs.Count > 64 ||
            Workloads.Any(static item => item is null) ||
            Actions.Any(static item => item is null) ||
            Needs.Any(static item => string.IsNullOrWhiteSpace(item) || item.Length > 128) ||
            Needs.Distinct(StringComparer.Ordinal).Count() != Needs.Count)
        {
            throw new InvalidOperationException("The operator status document is invalid.");
        }

        foreach (var workload in Workloads) workload.Validate();
        foreach (var action in Actions) action.Validate();
    }
}

public sealed record OperatorWorkloadStatus(
    string Workload,
    string Role,
    int DesiredReplicas,
    int ObservedReplicas,
    int ReadyReplicas,
    int ProgressPercent,
    string State,
    long DesiredGeneration,
    long? ObservedGeneration,
    DateTimeOffset? LastObservedAt,
    IReadOnlyList<string> Needs,
    int MinReplicas = 1,
    int MaxReplicas = 1024,
    string PendingScaleAction = "hold")
{
    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(Workload) || string.IsNullOrWhiteSpace(Role) ||
            Workload.Length > 128 || Role.Length > 64 ||
            DesiredReplicas < 0 || ObservedReplicas < 0 || ReadyReplicas < 0 ||
            ReadyReplicas > ObservedReplicas || ProgressPercent is < 0 or > 100 ||
            DesiredGeneration < 0 || ObservedGeneration is < 0 ||
            State.Length > 64 || Needs is null || Needs.Count > 16 ||
            Needs.Any(static item => string.IsNullOrWhiteSpace(item) || item.Length > 128) ||
            Needs.Distinct(StringComparer.Ordinal).Count() != Needs.Count ||
            MinReplicas < 1 || MaxReplicas < MinReplicas || MaxReplicas > 1024 ||
            PendingScaleAction is not ("hold" or "scale-out" or "scale-in" or "blocked"))
        {
            throw new InvalidOperationException("The operator workload status is invalid.");
        }
    }
}

public sealed record OperatorActionStatus(
    string Kind,
    string State,
    int ProgressPercent,
    DateTimeOffset ObservedAt,
    string? Error)
{
    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(Kind) || Kind.Length > 128 ||
            string.IsNullOrWhiteSpace(State) || State.Length > 64 ||
            ProgressPercent is < 0 or > 100 || ObservedAt == default ||
            Error is { Length: > 128 })
        {
            throw new InvalidOperationException("The operator action status is invalid.");
        }
    }
}

[JsonSerializable(typeof(OperatorStatusDocument))]
[JsonSerializable(typeof(OperatorWorkloadStatus))]
[JsonSerializable(typeof(OperatorActionStatus))]
internal sealed partial class OperatorStatusJsonContext : JsonSerializerContext;
