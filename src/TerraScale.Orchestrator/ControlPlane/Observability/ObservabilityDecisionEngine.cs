using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Observability;

public static class ObservabilityDecisionEngine
{
    public static ObservabilityDecision EvaluateTelemetryAdmission(TelemetryAdmissionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var trace = new List<ObservabilityDecisionReason>();
        var spec = request.Spec;
        var scopeExact = spec.TenantId == request.AuthorizedTenantId && spec.CellId == request.AuthorizedCellId &&
                         request.Cardinality.TenantId == spec.TenantId && request.Cardinality.CellId == spec.CellId && request.Cardinality.SignalId == spec.SignalId;
        trace.Add(Reject(ObservabilityDecisionCode.ScopeExact, scopeExact));
        trace.Add(Reject(ObservabilityDecisionCode.OperationExact, request.Cardinality.OperationId == spec.OperationId));

        var generationExact = spec.SchemaGeneration == request.CurrentSchemaGeneration && request.Cardinality.SchemaGeneration == request.CurrentSchemaGeneration;
        var futureGeneration = spec.SchemaGeneration.Value > request.CurrentSchemaGeneration.Value || request.Cardinality.SchemaGeneration.Value > request.CurrentSchemaGeneration.Value;
        trace.Add(futureGeneration ? Held(ObservabilityDecisionCode.GenerationCurrent, Math.Max(spec.SchemaGeneration.Value, request.Cardinality.SchemaGeneration.Value), request.CurrentSchemaGeneration.Value) : Reject(ObservabilityDecisionCode.GenerationCurrent, generationExact, spec.SchemaGeneration.Value, request.CurrentSchemaGeneration.Value));
        trace.Add(Reject(ObservabilityDecisionCode.SchemaExact, spec.SchemaDigest == request.ExpectedSchemaDigest && request.Cardinality.SchemaDigest == request.ExpectedSchemaDigest));

        var sequenceExact = request.Cardinality.Sequence == request.CurrentSequence;
        trace.Add(request.Cardinality.Sequence.Value > request.CurrentSequence.Value
            ? Held(ObservabilityDecisionCode.EvidenceComplete, request.Cardinality.Sequence.Value, request.CurrentSequence.Value)
            : Reject(ObservabilityDecisionCode.EvidenceComplete, sequenceExact && request.Cardinality.Completeness == EvidenceCompleteness.Complete));

        var catalog = request.LabelCatalog.ToDictionary(v => v.Key);
        var known = spec.Labels.All(label => catalog.TryGetValue(label.Key, out var entry) && entry.AllowedValues.Contains(label.Value));
        var secretFree = spec.Labels.All(label => catalog.TryGetValue(label.Key, out var entry) && entry.Classification == LabelClassification.BoundedPublic);
        trace.Add(Reject(ObservabilityDecisionCode.LabelsBounded, known));
        trace.Add(Reject(ObservabilityDecisionCode.SecretFree, secretFree));

        var withinBudget = request.Cardinality.ExistingSeries < request.ScopeBudget.Value;
        trace.Add(Reject(ObservabilityDecisionCode.CardinalityWithinBudget, withinBudget, request.Cardinality.ExistingSeries, request.ScopeBudget.Value));

        if (trace.Any(v => v.Outcome == ObservabilityDecisionOutcome.Rejected)) return Deny(spec.OperationId, trace, true);
        if (trace.Any(v => v.Outcome == ObservabilityDecisionOutcome.Held)) return Deny(spec.OperationId, trace, false);
        return Decision(true, trace, new AdmitTelemetryIntent(spec));
    }

    public static ObservabilityDecision EvaluateRegionalHealth(RegionalHealthRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var trace = new List<ObservabilityDecisionReason>();
        var findings = new List<RegionalSignalFinding>();
        var duplicateSignals = request.Observations.GroupBy(o => o.Signal).Count(g => g.Count() > 1);
        trace.Add(Hold(ObservabilityDecisionCode.EvidenceComplete, duplicateSignals == 0, (ulong)duplicateSignals, 0));

        var exactCount = 0UL;
        var persistenceCount = 0UL;
        var retentionCount = 0UL;
        var ingestCount = 0UL;
        var queryCount = 0UL;
        var spoolCount = 0UL;
        var hardReject = request.Observations.Any(o => !request.Policies.Any(p => p.Signal == o.Signal));
        var held = duplicateSignals != 0;

        foreach (var policy in request.Policies)
        {
            var observations = request.Observations.Where(o => o.Signal == policy.Signal).ToArray();
            if (observations.Length != 1)
            {
                held = true;
                findings.Add(new RegionalSignalFinding(policy.Signal, TelemetryAvailability.Unknown, TelemetryAvailability.Unknown, SpoolStatus.Unknown, false));
                continue;
            }

            var observation = observations[0];
            var scopeExact = observation.OperationId == request.OperationId && observation.CellId == request.CellId && observation.SchemaDigest == request.SchemaDigest;
            var sequenceExact = observation.Sequence == request.CurrentSequence;
            var generationExact = observation.Generation == request.Generation;
            if (!scopeExact) { hardReject = true; findings.Add(new RegionalSignalFinding(policy.Signal, TelemetryAvailability.Unknown, TelemetryAvailability.Unknown, SpoolStatus.Unknown, false)); continue; }
            if (!sequenceExact || !generationExact) { held = true; findings.Add(new RegionalSignalFinding(policy.Signal, TelemetryAvailability.Unknown, TelemetryAvailability.Unknown, SpoolStatus.Unknown, false)); continue; }
            exactCount++;

            var persistence = observation.Persistence == policy.Persistence;
            var retention = observation.Retention == policy.Retention;
            if (persistence) persistenceCount++;
            if (retention) retentionCount++;
            if (!persistence || !retention)
            {
                hardReject = true;
                findings.Add(new RegionalSignalFinding(policy.Signal, TelemetryAvailability.Unknown, TelemetryAvailability.Unknown, SpoolStatus.Unknown, false));
                continue;
            }

            var ingestAvailable = observation.HealthyIngestReplicas >= policy.MinimumIngestReplicas.Value;
            var queryAvailable = observation.HealthyQueryReplicas >= policy.MinimumQueryReplicas.Value;
            var spoolSafe = observation.LocalSpoolBytes <= policy.SpoolLimit.Value && observation.SpoolStatus is SpoolStatus.Healthy or SpoolStatus.NearLimit;
            if (ingestAvailable) ingestCount++;
            if (queryAvailable) queryCount++;
            if (spoolSafe) spoolCount++;

            var ingest = ingestAvailable
                ? observation.CentralReachable ? TelemetryAvailability.Available : TelemetryAvailability.Degraded
                : TelemetryAvailability.Unavailable;
            var query = queryAvailable ? TelemetryAvailability.Available : TelemetryAvailability.Unavailable;
            findings.Add(new RegionalSignalFinding(policy.Signal, ingest, query, observation.SpoolStatus, observation.SpoolStatus == SpoolStatus.ExhaustedWithLoss));
        }

        var required = checked((ulong)request.Policies.Count);
        trace.Add(hardReject ? Reject(ObservabilityDecisionCode.ScopeExact, false, exactCount, required) : held ? Held(ObservabilityDecisionCode.ScopeExact, exactCount, required) : Pass(ObservabilityDecisionCode.ScopeExact, exactCount, required));
        trace.Add(hardReject ? Reject(ObservabilityDecisionCode.PersistenceExact, persistenceCount == required, persistenceCount, required) : Hold(ObservabilityDecisionCode.PersistenceExact, persistenceCount == required, persistenceCount, required));
        trace.Add(hardReject ? Reject(ObservabilityDecisionCode.RetentionExact, retentionCount == required, retentionCount, required) : Hold(ObservabilityDecisionCode.RetentionExact, retentionCount == required, retentionCount, required));
        trace.Add(Hold(ObservabilityDecisionCode.IngestHaSatisfied, ingestCount == required, ingestCount, required));
        trace.Add(Hold(ObservabilityDecisionCode.QueryHaSatisfied, queryCount == required, queryCount, required));
        trace.Add(Hold(ObservabilityDecisionCode.SpoolWithinPolicy, spoolCount == required, spoolCount, required));
        var intent = new AggregateRegionalTelemetryIntent(request, new ReadOnlyCollection<RegionalSignalFinding>(findings.OrderBy(f => f.Signal).ToArray()));
        return Decision(trace.All(v => v.Outcome == ObservabilityDecisionOutcome.Passed), trace, intent);
    }

    public static ObservabilityDecision EvaluateGrafanaProjection(GrafanaProjectionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var trace = new List<ObservabilityDecisionReason>();
        var inventoryScope = request.Inventory.OperationId == request.OperationId && request.Inventory.OwnerId == request.OwnerId &&
                             request.Inventory.TenantId == request.TenantId && request.Inventory.CellId == request.CellId;
        trace.Add(!inventoryScope ? Reject(ObservabilityDecisionCode.EvidenceComplete, false)
            : request.Inventory.Generation.Value > request.Generation.Value ? Held(ObservabilityDecisionCode.EvidenceComplete, request.Inventory.Generation.Value, request.Generation.Value)
            : request.Inventory.Generation != request.Generation ? Reject(ObservabilityDecisionCode.EvidenceComplete, false, request.Inventory.Generation.Value, request.Generation.Value)
            : request.Inventory.Sequence.Value > request.CurrentSequence.Value ? Held(ObservabilityDecisionCode.EvidenceComplete, request.Inventory.Sequence.Value, request.CurrentSequence.Value)
            : request.Inventory.Sequence != request.CurrentSequence ? Reject(ObservabilityDecisionCode.EvidenceComplete, false, request.Inventory.Sequence.Value, request.CurrentSequence.Value)
            : Hold(ObservabilityDecisionCode.EvidenceComplete, request.Inventory.Completeness == EvidenceCompleteness.Complete));
        trace.Add(Reject(ObservabilityDecisionCode.ProjectionGenerationNotRollback,
            request.Generation.Value >= request.CurrentAcceptedGeneration.Value,
            request.Generation.Value, request.CurrentAcceptedGeneration.Value));
        trace.Add(Reject(ObservabilityDecisionCode.ProjectionSequenceNotRollback,
            request.CurrentSequence.Value >= request.CurrentAcceptedSequence.Value,
            request.CurrentSequence.Value, request.CurrentAcceptedSequence.Value));
        var desiredScope = request.Desired.All(r => r.OwnerId == request.OwnerId && r.TenantId == request.TenantId && r.CellId == request.CellId && r.Generation == request.Generation);
        trace.Add(Reject(ObservabilityDecisionCode.ScopeExact, desiredScope));
        var accesses = request.Desired.Select(r => r.Selection).OfType<AccessSelection>().ToArray();
        var accessExact = accesses.All(access => LeastPrivilege(access, request)) && accesses.GroupBy(access => access.UserId).All(group => group.Count() == 1);
        trace.Add(Reject(ObservabilityDecisionCode.AccessExact, accessExact));

        var future = request.Observed.Any(r => r.Generation.Value > request.Generation.Value);
        var ownedScope = request.Observed.Where(r => r.Ownership == GrafanaOwnership.ManagedExact)
            .All(r => r.OwnerId == request.OwnerId && r.TenantId == request.TenantId && r.CellId == request.CellId);
        trace.Add(future ? Held(ObservabilityDecisionCode.GenerationCurrent, request.Observed.Max(r => r.Generation.Value), request.Generation.Value) : Reject(ObservabilityDecisionCode.GenerationCurrent, true));
        trace.Add(Reject(ObservabilityDecisionCode.OwnershipExact, ownedScope));
        if (trace.Any(v => v.Outcome != ObservabilityDecisionOutcome.Passed))
            return Decision(false, trace, new HoldObservabilityIntent(request.OperationId));

        var changes = new List<GrafanaChange>();
        var observedById = request.Observed.ToDictionary(r => r.Id);
        var desiredIds = request.Desired.Select(r => r.Id).ToHashSet();
        foreach (var desired in request.Desired)
        {
            if (!observedById.TryGetValue(desired.Id, out var observed))
            {
                changes.Add(new CreateGrafanaResource(desired, request.Inventory));
                continue;
            }
            if (observed.Ownership != GrafanaOwnership.ManagedExact)
            {
                changes.Add(new ReportGrafanaDrift(observed, request.Inventory));
                continue;
            }
            if (observed.Kind != desired.Selection.Kind || observed.Digest != desired.Digest || observed.Generation != desired.Generation ||
                observed.ManagedProvenance is not { } provenance || provenance.ReleaseId != desired.ReleaseId || provenance.Selection != desired.Selection)
                changes.Add(new UpdateGrafanaResource(desired, observed, request.Inventory));
        }
        foreach (var observed in request.Observed.Where(r => !desiredIds.Contains(r.Id)))
            changes.Add(observed.Ownership == GrafanaOwnership.ManagedExact ? new DeleteGrafanaResource(observed, request.Inventory) : new ReportGrafanaDrift(observed, request.Inventory));

        var projectionCount = ObservabilityArithmetic.CheckedAdd((ulong)request.Desired.Count, (ulong)request.Observed.Count);
        trace.Add(Pass(ObservabilityDecisionCode.ProjectionExact, projectionCount, projectionCount));
        return Decision(true, trace, new ProjectGrafanaIntent(request, new ReadOnlyCollection<GrafanaChange>(changes.OrderBy(c => c.Id.Value, StringComparer.Ordinal).ToArray())));
    }

    public static ObservabilityDecision EvaluateAlertRouting(AlertRoutingRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var trace = new List<ObservabilityDecisionReason>();
        var alert = request.Alert;
        trace.Add(Reject(ObservabilityDecisionCode.OperationExact, alert.OperationId == request.ExpectedOperationId));
        trace.Add(Reject(ObservabilityDecisionCode.ScopeExact, alert.TenantId == request.ExpectedTenantId && alert.CellId == request.ExpectedCellId && alert.SignalId == request.ExpectedSignalId));
        trace.Add(alert.Generation.Value > request.CurrentGeneration.Value ? Held(ObservabilityDecisionCode.GenerationCurrent, alert.Generation.Value, request.CurrentGeneration.Value) : Reject(ObservabilityDecisionCode.GenerationCurrent, alert.Generation == request.CurrentGeneration));
        trace.Add(Reject(ObservabilityDecisionCode.SchemaExact, alert.RuleDigest == request.ExpectedRuleDigest));
        var dedupeExact = request.Dedupe.OperationId == request.ExpectedOperationId && request.Dedupe.TenantId == request.ExpectedTenantId &&
                          request.Dedupe.CellId == request.ExpectedCellId && request.Dedupe.SignalId == request.ExpectedSignalId &&
                          request.Dedupe.Generation == request.CurrentGeneration && request.Dedupe.RuleDigest == request.ExpectedRuleDigest &&
                          request.Dedupe.ContactId == request.ContactId && request.Dedupe.Contact == request.Contact &&
                          request.Dedupe.Severity == alert.Severity && request.Dedupe.State == alert.State;
        var sequenceExact = request.Dedupe.Sequence == request.CurrentSequence;
        var sequenceFuture = request.Dedupe.Sequence.Value > request.CurrentSequence.Value;
        trace.Add(!dedupeExact ? Reject(ObservabilityDecisionCode.EvidenceComplete, false) : sequenceFuture ? Held(ObservabilityDecisionCode.EvidenceComplete, request.Dedupe.Sequence.Value, request.CurrentSequence.Value) : Reject(ObservabilityDecisionCode.EvidenceComplete, sequenceExact && request.Dedupe.Completeness == EvidenceCompleteness.Complete));
        var unique = !request.Dedupe.DeliveredEvents.Contains(new AlertDeliveryKey(alert.AlertId, alert.State));
        trace.Add(Hold(ObservabilityDecisionCode.DedupeUnique, unique));
        if (trace.Any(v => v.Outcome != ObservabilityDecisionOutcome.Passed)) return Decision(false, trace, new HoldObservabilityIntent(alert.OperationId));
        return Decision(true, trace, new RouteAlertIntent(request));
    }

    private static bool LeastPrivilege(AccessSelection access, GrafanaProjectionRequest request) => (access.Entry, access.Access, access.Subject) switch
    {
        (OperatorRoleCatalogEntry.TenantViewer, TelemetryAccess.TenantReader, TenantAccessSubject subject) => request.AccessBoundary == GrafanaAccessBoundary.Tenant && subject.TenantId == request.TenantId,
        (OperatorRoleCatalogEntry.CellViewer, TelemetryAccess.CellOperator, CellAccessSubject subject) => request.AccessBoundary == GrafanaAccessBoundary.Cell && subject.CellId == request.CellId,
        (OperatorRoleCatalogEntry.GlobalViewer, TelemetryAccess.GlobalOperator, GlobalAccessSubject subject) => request.AccessBoundary == GrafanaAccessBoundary.Global && subject.AuthorityId == request.OwnerId,
        _ => false,
    };

    private static ObservabilityDecisionReason Pass(ObservabilityDecisionCode code, ulong observed = 1, ulong required = 1) => new(code, ObservabilityDecisionOutcome.Passed, observed, required);
    private static ObservabilityDecisionReason Reject(ObservabilityDecisionCode code, bool pass, ulong observed = 0, ulong required = 1) => new(code, pass ? ObservabilityDecisionOutcome.Passed : ObservabilityDecisionOutcome.Rejected, pass && observed == 0 ? required : observed, required);
    private static ObservabilityDecisionReason Hold(ObservabilityDecisionCode code, bool pass, ulong observed = 0, ulong required = 1) => new(code, pass ? ObservabilityDecisionOutcome.Passed : ObservabilityDecisionOutcome.Held, pass && observed == 0 ? required : observed, required);
    private static ObservabilityDecisionReason Held(ObservabilityDecisionCode code, ulong observed, ulong required) => new(code, ObservabilityDecisionOutcome.Held, observed, required);
    private static ObservabilityDecision Decision(bool authorized, List<ObservabilityDecisionReason> trace, ObservabilityIntent intent) => new(authorized, new ReadOnlyCollection<ObservabilityDecisionReason>(trace.ToArray()), intent);
    private static ObservabilityDecision Deny(ObservabilityOperationId operationId, List<ObservabilityDecisionReason> trace, bool drop) => Decision(false, trace, drop ? new DropTelemetryIntent(operationId) : new HoldObservabilityIntent(operationId));
}
