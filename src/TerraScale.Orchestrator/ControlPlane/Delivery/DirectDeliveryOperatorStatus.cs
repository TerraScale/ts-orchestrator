using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>One region's durable progress inside a direct-delivery operation.</summary>
public sealed record DirectDeliveryOperatorRegionStatus(
    [property: JsonPropertyName("region")] string Region,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("errorCode")] string? ErrorCode);

/// <summary>
/// The bounded, redacted operator view of one direct-delivery operation, projected read-only
/// from the durable journal record. It reports the current operation state, per-region
/// progress, health, rollback state, and the actionable failure — and never request text,
/// actor identities, request fingerprints, credentials, or any customer content.
/// </summary>
public sealed record DirectDeliveryOperatorStatus(
    [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
    [property: JsonPropertyName("exists")] bool Exists,
    [property: JsonPropertyName("operationId")] string? OperationId,
    [property: JsonPropertyName("operation")] string Operation,
    [property: JsonPropertyName("artifactDigest")] string? ArtifactDigest,
    [property: JsonPropertyName("target")] DeliveryTarget? Target,
    [property: JsonPropertyName("regionProgress")] IReadOnlyList<DirectDeliveryOperatorRegionStatus> RegionProgress,
    [property: JsonPropertyName("health")] DirectDeliveryOperatorHealth? Health,
    [property: JsonPropertyName("rollback")] DirectDeliveryOperatorRollback? Rollback,
    [property: JsonPropertyName("failure")] DeliveryErrorInfo? Failure,
    [property: JsonPropertyName("requiresOperatorAction")] bool RequiresOperatorAction,
    [property: JsonPropertyName("attempt")] int Attempt)
{
    public const int CurrentSchemaVersion = 1;

    /// <summary>
    /// The operation state reported when no durable record exists for the requested operation
    /// identity: unknown, not failed — an operator asked about an operation this journal never
    /// admitted (or whose completed history was pruned under the retention bound).
    /// </summary>
    public const string UnknownOperation = "unknown_operation";
}

/// <summary>The redacted health projection of one operation's latest durable receipt.</summary>
public sealed record DirectDeliveryOperatorHealth(
    [property: JsonPropertyName("checks")] IReadOnlyList<DeliveryHealthCheck> Checks,
    [property: JsonPropertyName("converged")] bool? Converged,
    [property: JsonPropertyName("state")] string State)
{
    public const string Passed = "passed";
    public const string Failed = "failed";
    public const string Unknown = "unknown";
}

/// <summary>The redacted rollback projection: durable rollback state and recovery anchor.</summary>
public sealed record DirectDeliveryOperatorRollback(
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("targetArtifactDigest")] string? TargetArtifactDigest,
    [property: JsonPropertyName("attempted")] bool Attempted)
{
    public const string None = "none";
    public const string InProgress = "in_progress";
    public const string Pending = "pending";
    public const string Succeeded = "succeeded";
    public const string Failed = "failed";
}

/// <summary>
/// The pure, in-process projection from durable direct-delivery journal records to the operator
/// status surface. No infrastructure, no wall clock, and no mutation: it only re-shapes what the
/// journal already durably recorded, so an operator reading it can never influence a delivery.
/// </summary>
public static class DirectDeliveryOperatorStatusProjection
{
    /// <summary>Projects one durable journal record; a null record is a valid, reportable state.</summary>
    public static DirectDeliveryOperatorStatus Project(DeliveryJournalRecord? record)
    {
        if (record is not { } current)
            return new(
                DirectDeliveryOperatorStatus.CurrentSchemaVersion,
                Exists: false,
                OperationId: null,
                Operation: DirectDeliveryOperatorStatus.UnknownOperation,
                ArtifactDigest: null,
                Target: null,
                RegionProgress: [],
                Health: null,
                Rollback: null,
                Failure: null,
                RequiresOperatorAction: false,
                Attempt: 0);
        var receipt = current.Receipt;
        var regions = (current.Regions ?? Array.Empty<DeliveryRegionProgress>()).ToArray();
        var rollbackRegions = regions.Where(static region =>
            region.State is "rollback_pending" or "rolling_back" or "rollback_failed" or "rollback_succeeded")
            .ToArray();
        return new(
            DirectDeliveryOperatorStatus.CurrentSchemaVersion,
            Exists: true,
            OperationId: current.OperationId,
            Operation: current.State,
            ArtifactDigest: current.ArtifactDigest,
            Target: SafeTarget(receipt?.Target),
            RegionProgress: regions
                .Select(static region => new DirectDeliveryOperatorRegionStatus(
                    region.Region, region.State, region.ErrorCode))
                .ToArray(),
            Health: ProjectHealth(receipt),
            Rollback: ProjectRollback(current.State, receipt, rollbackRegions),
            Failure: receipt?.Error is { Code: not null } error ? error : null,
            RequiresOperatorAction: RequiresOperatorAction(current.State, receipt, regions),
            Attempt: current.Attempt);
    }

    /// <summary>Serializes the projection for an operator surface; bounded and redacted by construction.</summary>
    public static string Serialize(DirectDeliveryOperatorStatus status) =>
        JsonSerializer.Serialize(
            status ?? throw new ArgumentNullException(nameof(status)),
            OperatorStatusJsonOptions.Options);

    private static DirectDeliveryOperatorHealth? ProjectHealth(DeliveryReceipt? receipt)
    {
        if (receipt is null)
            return new([], null, DirectDeliveryOperatorHealth.Unknown);
        var checks = (receipt.Health?.Checks ?? Array.Empty<DeliveryHealthCheck>()).ToArray();
        var converged = receipt.Health?.Converged;
        var failed = checks.Any(static check => check.Status == DeliveryHealthStatus.Failed) ||
            converged == false;
        return new(
            checks,
            converged,
            failed ? DirectDeliveryOperatorHealth.Failed : DirectDeliveryOperatorHealth.Passed);
    }

    private static DirectDeliveryOperatorRollback? ProjectRollback(
        string state,
        DeliveryReceipt? receipt,
        IReadOnlyList<DeliveryRegionProgress> rollbackRegions)
    {
        if (receipt?.Rollback is { } recorded)
            return new(
                recorded.Status,
                recorded.TargetArtifactDigest,
                recorded.Attempted);
        if (state == DeliveryJournalState.RollingBack ||
            rollbackRegions.Any(static region => region.State == "rolling_back"))
            return new(DirectDeliveryOperatorRollback.InProgress, null, true);
        if (rollbackRegions.Any(static region => region.State == "rollback_pending"))
            return new(DirectDeliveryOperatorRollback.Pending, null, true);
        if (rollbackRegions.Any(static region => region.State == "rollback_failed"))
            return new(DirectDeliveryOperatorRollback.Failed, null, true);
        return new(DirectDeliveryOperatorRollback.None, null, false);
    }

    /// <summary>
    /// Derived from the durable shape only: a terminal failure, an owed or failed rollback, or a
    /// receipt-less failed record all require an operator decision; completed operations do not.
    /// </summary>
    private static bool RequiresOperatorAction(
        string state,
        DeliveryReceipt? receipt,
        IReadOnlyList<DeliveryRegionProgress> regions) =>
        state == DeliveryJournalState.Failed ||
        receipt?.Rollback.Status == DeliveryRollbackStatus.Failed ||
        receipt?.Error.Code == DirectDeliveryErrorCode.JournalUnavailable ||
        regions.Any(static region =>
            region.State is "rollback_pending" or "rollback_failed");

    private static DeliveryTarget? SafeTarget(DeliveryTarget? target) =>
        target is { Regions: { } regions }
            ? new DeliveryTarget(target.Service, target.Environment, regions.ToArray())
            : null;
}

internal static class OperatorStatusJsonOptions
{
    internal static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };
}

