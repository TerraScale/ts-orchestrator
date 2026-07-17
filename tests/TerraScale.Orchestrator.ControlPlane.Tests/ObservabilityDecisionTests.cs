using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Observability;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class ObservabilityDecisionTests
{
    [Test]
    public async Task ExactBoundedTelemetryIsAdmitted()
    {
        var decision = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(Admission());
        await Assert.That(decision.Authorized).IsTrue();
        await Assert.That(decision.Intent is AdmitTelemetryIntent).IsTrue();
        await Assert.That(Reason(decision, ObservabilityDecisionCode.CardinalityWithinBudget).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Passed);
    }

    [Test]
    public async Task UnknownUnboundedAndSecretLabelsRejectBeforeIngest()
    {
        var unknown = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(Admission(labels: [new(new("unknown"), new("value"))]));
        var secretCatalog = new TelemetryLabelCatalogEntry(new("region"), LabelClassification.SecretBearingForbidden, new(2), [new ObservabilityLabelValue("gru")]);
        var secret = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(Admission(catalog: [secretCatalog]));
        var unboundedCatalog = new TelemetryLabelCatalogEntry(new("region"), LabelClassification.UnboundedForbidden, new(2), []);
        var unbounded = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(Admission(catalog: [unboundedCatalog]));
        await Assert.That(unknown.Intent is DropTelemetryIntent).IsTrue();
        await Assert.That(Reason(secret, ObservabilityDecisionCode.SecretFree).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Rejected);
        await Assert.That(unbounded.Authorized).IsFalse();
    }

    [Test]
    public async Task TenantCellAndOperationReplayRejects()
    {
        var tenant = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(Admission(authorizedTenant: new("tenant-b")));
        var cell = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(Admission(authorizedCell: new("sfo")));
        var operation = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(Admission(cardinality: Cardinality(operation: new("operation-2"))));
        await Assert.That(Reason(tenant, ObservabilityDecisionCode.ScopeExact).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Rejected);
        await Assert.That(cell.Authorized).IsFalse();
        await Assert.That(operation.Authorized).IsFalse();
    }

    [Test]
    public async Task StaleAndOutOfOrderEvidenceRejectsWhileFutureEvidenceHolds()
    {
        var stale = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(Admission(specGeneration: 4));
        var outOfOrder = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(Admission(cardinality: Cardinality(sequence: 8)));
        var future = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(Admission(specGeneration: 6));
        var futureSequence = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(Admission(cardinality: Cardinality(sequence: 10)));
        await Assert.That(Reason(stale, ObservabilityDecisionCode.GenerationCurrent).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Rejected);
        await Assert.That(outOfOrder.Authorized).IsFalse();
        await Assert.That(Reason(future, ObservabilityDecisionCode.GenerationCurrent).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Held);
        await Assert.That(Reason(futureSequence, ObservabilityDecisionCode.EvidenceComplete).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Held);
        await Assert.That(future.Intent is HoldObservabilityIntent).IsTrue();
    }

    [Test]
    public async Task IncompleteCardinalityAndBudgetExplosionDefaultDeny()
    {
        var incomplete = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(Admission(cardinality: Cardinality(completeness: EvidenceCompleteness.Incomplete)));
        var exhausted = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(Admission(cardinality: Cardinality(existing: 100), budget: 100));
        var maximum = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(Admission(cardinality: Cardinality(existing: ulong.MaxValue), budget: ulong.MaxValue));
        await Assert.That(incomplete.Authorized).IsFalse();
        await Assert.That(Reason(exhausted, ObservabilityDecisionCode.CardinalityWithinBudget).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Rejected);
        await Assert.That(maximum.Authorized).IsFalse();
    }

    [Test]
    public async Task RegionalSignalsPreserveIndependentIngestQueryAndCentralLossState()
    {
        var decision = ObservabilityDecisionEngine.EvaluateRegionalHealth(Health(
            observations: Observations(metricCentral: false, logIngest: 1, traceQuery: 1)));
        var intent = (AggregateRegionalTelemetryIntent)decision.Intent;
        await Assert.That(decision.Authorized).IsFalse();
        await Assert.That(intent.Findings.Single(f => f.Signal == TelemetrySignalKind.Metric).Ingest).IsEqualTo(TelemetryAvailability.Degraded);
        await Assert.That(intent.Findings.Single(f => f.Signal == TelemetrySignalKind.Log).Ingest).IsEqualTo(TelemetryAvailability.Unavailable);
        await Assert.That(intent.Findings.Single(f => f.Signal == TelemetrySignalKind.Log).Query).IsEqualTo(TelemetryAvailability.Available);
        await Assert.That(intent.Findings.Single(f => f.Signal == TelemetrySignalKind.Trace).Query).IsEqualTo(TelemetryAvailability.Unavailable);
    }

    [Test]
    public async Task RegionalPolicySetIsClosedAndDuplicateObservationsHold()
    {
        await Assert.That(Throws<ArgumentException>(() => new RegionalHealthRequest(Operation, Cell, new(5), new(9), Digest(), new(3), [], []))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new RegionalHealthRequest(Operation, Cell, new(5), new(9), Digest(), new(3), [Policy(TelemetrySignalKind.Metric)], []))).IsTrue();
        var duplicate = Observations().Append(Observation(TelemetrySignalKind.Metric));
        var decision = ObservabilityDecisionEngine.EvaluateRegionalHealth(Health(observations: duplicate));
        await Assert.That(decision.Authorized).IsFalse();
        await Assert.That(Reason(decision, ObservabilityDecisionCode.EvidenceComplete).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Held);
    }

    [Test]
    public async Task MissingSignalProducesTypedUnknownFindingAndHoldsPromotion()
    {
        var observations = Observations().Where(o => o.Signal != TelemetrySignalKind.Trace);
        var decision = ObservabilityDecisionEngine.EvaluateRegionalHealth(Health(observations: observations));
        var intent = (AggregateRegionalTelemetryIntent)decision.Intent;
        await Assert.That(decision.Authorized).IsFalse();
        await Assert.That(Reason(decision, ObservabilityDecisionCode.ScopeExact).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Held);
        await Assert.That(intent.Findings.Single(f => f.Signal == TelemetrySignalKind.Trace).Ingest).IsEqualTo(TelemetryAvailability.Unknown);
    }

    [Test]
    public async Task StalePersistenceAndRetentionEvidenceCannotFabricateHealth()
    {
        var stale = Observations().Select(o => o.Signal == TelemetrySignalKind.Metric ? Observation(o.Signal, sequence: 8) : o);
        var persistence = Observations().Select(o => o.Signal == TelemetrySignalKind.Log ? Observation(o.Signal, persistence: TelemetryPersistence.Memory) : o);
        var retention = Observations().Select(o => o.Signal == TelemetrySignalKind.Trace ? Observation(o.Signal, retention: 12) : o);
        var persistenceDecision = ObservabilityDecisionEngine.EvaluateRegionalHealth(Health(observations: persistence));
        await Assert.That(ObservabilityDecisionEngine.EvaluateRegionalHealth(Health(observations: stale)).Authorized).IsFalse();
        await Assert.That(Reason(persistenceDecision, ObservabilityDecisionCode.PersistenceExact).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Rejected);
        await Assert.That(((AggregateRegionalTelemetryIntent)persistenceDecision.Intent).Findings.Single(f => f.Signal == TelemetrySignalKind.Log).Ingest).IsEqualTo(TelemetryAvailability.Unknown);
        await Assert.That(ObservabilityDecisionEngine.EvaluateRegionalHealth(Health(observations: retention)).Authorized).IsFalse();
    }

    [Test]
    public async Task SpoolExhaustionEmitsExplicitDataLossFindingWithoutBlockingProductSemantics()
    {
        var exhausted = Observations().Select(o => o.Signal == TelemetrySignalKind.Metric
            ? Observation(o.Signal, central: false, spoolBytes: 1001, spool: SpoolStatus.ExhaustedWithLoss)
            : o);
        var decision = ObservabilityDecisionEngine.EvaluateRegionalHealth(Health(observations: exhausted));
        var finding = ((AggregateRegionalTelemetryIntent)decision.Intent).Findings.Single(f => f.Signal == TelemetrySignalKind.Metric);
        await Assert.That(decision.Authorized).IsFalse();
        await Assert.That(finding.DataLoss).IsTrue();
        await Assert.That(Reason(decision, ObservabilityDecisionCode.SpoolWithinPolicy).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Held);
    }

    [Test]
    public async Task ExactGrafanaDriftEmitsClosedCreateUpdateDeleteAndReportChanges()
    {
        var desired = new[] { Desired("create", DashboardCatalogEntry.FleetOverview), Desired("update", DashboardCatalogEntry.CellHealth), Desired("same", DashboardCatalogEntry.Capacity) };
        var observed = new[]
        {
            Observed("update", digest: OtherDigest(), entry: DashboardCatalogEntry.CellHealth), Observed("same", entry: DashboardCatalogEntry.Capacity), Observed("delete"),
            Observed("foreign", ownership: GrafanaOwnership.Unmanaged, owner: new("human")),
        };
        var decision = ObservabilityDecisionEngine.EvaluateGrafanaProjection(Projection(desired, observed));
        var changes = ((ProjectGrafanaIntent)decision.Intent).Changes;
        await Assert.That(decision.Authorized).IsTrue();
        await Assert.That(changes.Count).IsEqualTo(4);
        await Assert.That(changes.Any(c => c is CreateGrafanaResource { Id.Value: "create" })).IsTrue();
        await Assert.That(changes.Any(c => c is UpdateGrafanaResource { Id.Value: "update" })).IsTrue();
        await Assert.That(changes.Any(c => c is DeleteGrafanaResource { Id.Value: "delete" })).IsTrue();
        await Assert.That(changes.Any(c => c is ReportGrafanaDrift { Id.Value: "foreign" })).IsTrue();
        await Assert.That(changes.All(c => c.Inventory.Sequence == new ObservabilitySequence(9))).IsTrue();
    }

    [Test]
    public async Task UnmanagedResourceWithDesiredIdentityIsReportedNeverAdopted()
    {
        var decision = ObservabilityDecisionEngine.EvaluateGrafanaProjection(Projection(
            [Desired("dashboard", DashboardCatalogEntry.FleetOverview)],
            [Observed("dashboard", ownership: GrafanaOwnership.Unmanaged, owner: new("human"))]));
        var changes = ((ProjectGrafanaIntent)decision.Intent).Changes;
        await Assert.That(changes.Single() is ReportGrafanaDrift).IsTrue();
        await Assert.That(changes.Any(c => c is UpdateGrafanaResource or DeleteGrafanaResource)).IsFalse();
    }

    [Test]
    public async Task IncompleteOrReplayedGrafanaInventoryHoldsAllMutation()
    {
        var incomplete = ObservabilityDecisionEngine.EvaluateGrafanaProjection(Projection(
            [Desired("dashboard", DashboardCatalogEntry.FleetOverview)], [], completeness: EvidenceCompleteness.Incomplete));
        var replay = ObservabilityDecisionEngine.EvaluateGrafanaProjection(Projection(
            [Desired("dashboard", DashboardCatalogEntry.FleetOverview)], [], inventoryOperation: new("operation-2")));
        var future = ObservabilityDecisionEngine.EvaluateGrafanaProjection(Projection(
            [Desired("dashboard", DashboardCatalogEntry.FleetOverview)], [], inventoryGeneration: 6));
        await Assert.That(incomplete.Authorized).IsFalse();
        await Assert.That(incomplete.Intent is HoldObservabilityIntent).IsTrue();
        await Assert.That(replay.Authorized).IsFalse();
        await Assert.That(Reason(future, ObservabilityDecisionCode.EvidenceComplete).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Held);
    }

    [Test]
    public async Task GrafanaScopeAccessAndFutureObservationCannotBroadenAuthority()
    {
        var escalation = DesiredAccess("access", OperatorRoleCatalogEntry.TenantViewer, TelemetryAccess.GlobalOperator);
        var globalInTenant = DesiredAccess("global", OperatorRoleCatalogEntry.GlobalViewer, TelemetryAccess.GlobalOperator, subject: new GlobalAccessSubject(Owner));
        var duplicateUser = new[]
        {
            DesiredAccess("access-a", OperatorRoleCatalogEntry.TenantViewer, TelemetryAccess.TenantReader, roleId: new("role-a")),
            DesiredAccess("access-b", OperatorRoleCatalogEntry.TenantViewer, TelemetryAccess.TenantReader, roleId: new("role-b")),
        };
        var wrongTenant = new DesiredGrafanaResource(new("dashboard"), Owner, new("tenant-b"), Cell, new(5), new("release-5"), Digest(), new DashboardSelection(DashboardCatalogEntry.FleetOverview));
        var future = Observed("dashboard", generation: 6);
        await Assert.That(Reason(ObservabilityDecisionEngine.EvaluateGrafanaProjection(Projection([escalation], [])), ObservabilityDecisionCode.AccessExact).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Rejected);
        await Assert.That(ObservabilityDecisionEngine.EvaluateGrafanaProjection(Projection([globalInTenant], [])).Authorized).IsFalse();
        await Assert.That(ObservabilityDecisionEngine.EvaluateGrafanaProjection(Projection([globalInTenant], [], boundary: GrafanaAccessBoundary.Global)).Authorized).IsTrue();
        await Assert.That(ObservabilityDecisionEngine.EvaluateGrafanaProjection(Projection(duplicateUser, [])).Authorized).IsFalse();
        await Assert.That(ObservabilityDecisionEngine.EvaluateGrafanaProjection(Projection([wrongTenant], [])).Authorized).IsFalse();
        await Assert.That(Reason(ObservabilityDecisionEngine.EvaluateGrafanaProjection(Projection([], [future])), ObservabilityDecisionCode.GenerationCurrent).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Held);
    }

    [Test]
    public async Task GrafanaInventorySequenceIsExactAndEveryChangeCarriesCasProof()
    {
        var stale = ObservabilityDecisionEngine.EvaluateGrafanaProjection(Projection([Desired("create", DashboardCatalogEntry.FleetOverview)], [], currentSequence: 9, inventorySequence: 8));
        var future = ObservabilityDecisionEngine.EvaluateGrafanaProjection(Projection([Desired("create", DashboardCatalogEntry.FleetOverview)], [], currentSequence: 9, inventorySequence: 10));
        var exactRequest = Projection([Desired("create", DashboardCatalogEntry.FleetOverview)], [], currentSequence: 9, inventorySequence: 9);
        var first = ObservabilityDecisionEngine.EvaluateGrafanaProjection(exactRequest);
        var replay = ObservabilityDecisionEngine.EvaluateGrafanaProjection(exactRequest);
        var changes = ((ProjectGrafanaIntent)first.Intent).Changes;
        await Assert.That(stale.Authorized).IsFalse();
        await Assert.That(Reason(future, ObservabilityDecisionCode.EvidenceComplete).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Held);
        await Assert.That(changes.All(c => c.Inventory.Sequence == new ObservabilitySequence(9))).IsTrue();
        await Assert.That(Serialize(first)).IsEqualTo(Serialize(replay));
    }

    [Test]
    public async Task ExactAlertRoutesOnceToReviewedContact()
    {
        var decision = ObservabilityDecisionEngine.EvaluateAlertRouting(AlertRoute());
        var intent = (RouteAlertIntent)decision.Intent;
        await Assert.That(decision.Authorized).IsTrue();
        await Assert.That(intent.Contact).IsEqualTo(ContactCatalogEntry.GlobalOnCall);
        await Assert.That(intent.ContactId).IsEqualTo(new ObservabilityContactId("global-oncall"));
    }

    [Test]
    public async Task AlertDedupeIncompleteDuplicateAndReplayHoldWithoutRoute()
    {
        var incomplete = ObservabilityDecisionEngine.EvaluateAlertRouting(AlertRoute(completeness: EvidenceCompleteness.Incomplete));
        var duplicate = ObservabilityDecisionEngine.EvaluateAlertRouting(AlertRoute(routed: [new AlertDeliveryKey(new("alert-1"), AlertState.Firing)]));
        var replay = ObservabilityDecisionEngine.EvaluateAlertRouting(AlertRoute(dedupeOperation: new("operation-2")));
        await Assert.That(incomplete.Authorized).IsFalse();
        await Assert.That(Reason(duplicate, ObservabilityDecisionCode.DedupeUnique).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Held);
        await Assert.That(replay.Intent is HoldObservabilityIntent).IsTrue();
    }

    [Test]
    public async Task AlertDedupeFreshnessAndExactRouteSubjectAreMandatory()
    {
        var stale = ObservabilityDecisionEngine.EvaluateAlertRouting(AlertRoute(dedupeSequence: 8));
        var future = ObservabilityDecisionEngine.EvaluateAlertRouting(AlertRoute(dedupeSequence: 10));
        var signal = ObservabilityDecisionEngine.EvaluateAlertRouting(AlertRoute(dedupeSignal: new("other-signal")));
        var digest = ObservabilityDecisionEngine.EvaluateAlertRouting(AlertRoute(dedupeDigest: OtherDigest()));
        var contact = ObservabilityDecisionEngine.EvaluateAlertRouting(AlertRoute(dedupeContact: new("regional-oncall")));
        var state = ObservabilityDecisionEngine.EvaluateAlertRouting(AlertRoute(alertState: AlertState.Resolved, dedupeState: AlertState.Firing));
        await Assert.That(stale.Authorized).IsFalse();
        await Assert.That(Reason(future, ObservabilityDecisionCode.EvidenceComplete).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Held);
        await Assert.That(signal.Authorized).IsFalse();
        await Assert.That(digest.Authorized).IsFalse();
        await Assert.That(contact.Authorized).IsFalse();
        await Assert.That(state.Authorized).IsFalse();
    }

    [Test]
    public async Task AlertStateTransitionRoutesButExactEventDoesNotRepeat()
    {
        var firingDelivered = new AlertDeliveryKey(new("alert-1"), AlertState.Firing);
        var resolved = ObservabilityDecisionEngine.EvaluateAlertRouting(AlertRoute(routed: [firingDelivered], alertState: AlertState.Resolved));
        var repeatedFiring = ObservabilityDecisionEngine.EvaluateAlertRouting(AlertRoute(routed: [firingDelivered], alertState: AlertState.Firing));
        await Assert.That(resolved.Intent is RouteAlertIntent).IsTrue();
        await Assert.That(repeatedFiring.Authorized).IsFalse();
    }

    [Test]
    public async Task AuthorizedDecisionsContainOnlyPassedReasons()
    {
        var decisions = new[]
        {
            ObservabilityDecisionEngine.EvaluateTelemetryAdmission(Admission()),
            ObservabilityDecisionEngine.EvaluateRegionalHealth(Health()),
            ObservabilityDecisionEngine.EvaluateGrafanaProjection(Projection([Desired("dashboard", DashboardCatalogEntry.FleetOverview)], [])),
            ObservabilityDecisionEngine.EvaluateAlertRouting(AlertRoute()),
            ObservabilityDecisionEngine.EvaluateRegionalHealth(Health(observations: Observations(logIngest: 1))),
        };
        await Assert.That(decisions.Where(d => d.Authorized).SelectMany(d => d.Trace).All(r => r.Outcome == ObservabilityDecisionOutcome.Passed)).IsTrue();
    }

    [Test]
    public async Task AlertTenantDigestOperationAndGenerationReplayFailClosed()
    {
        var tenant = ObservabilityDecisionEngine.EvaluateAlertRouting(AlertRoute(alertTenant: new("tenant-b")));
        var digest = ObservabilityDecisionEngine.EvaluateAlertRouting(AlertRoute(alertDigest: OtherDigest()));
        var operation = ObservabilityDecisionEngine.EvaluateAlertRouting(AlertRoute(alertOperation: new("operation-2")));
        var future = ObservabilityDecisionEngine.EvaluateAlertRouting(AlertRoute(alertGeneration: 6));
        await Assert.That(tenant.Authorized).IsFalse();
        await Assert.That(digest.Authorized).IsFalse();
        await Assert.That(operation.Authorized).IsFalse();
        await Assert.That(Reason(future, ObservabilityDecisionCode.GenerationCurrent).Outcome).IsEqualTo(ObservabilityDecisionOutcome.Held);
    }

    [Test]
    public async Task InputsAreDefensiveCultureAndPermutationDeterministic()
    {
        var labels = new List<TelemetryLabel> { new(new("region"), new("gru")) };
        var request = Admission(labels: labels);
        labels.Clear();
        await Assert.That(request.Spec.Labels.Count).IsEqualTo(1);

        string? baseline = null;
        foreach (var culture in new[] { "en-US", "tr-TR", "ar-SA" })
        foreach (var desired in new[]
        {
            new[] { Desired("a", DashboardCatalogEntry.FleetOverview), Desired("b", DashboardCatalogEntry.CellHealth) },
            new[] { Desired("b", DashboardCatalogEntry.CellHealth), Desired("a", DashboardCatalogEntry.FleetOverview) },
        })
        {
            var original = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
                var serialized = Serialize(ObservabilityDecisionEngine.EvaluateGrafanaProjection(Projection(desired, [])));
                baseline ??= serialized;
                await Assert.That(serialized).IsEqualTo(baseline);
            }
            finally { CultureInfo.CurrentCulture = original; }
        }
    }

    [Test]
    public async Task QueryConfigCredentialsIoAndPublicIntentForgeryAreUnrepresentable()
    {
        var types = typeof(ObservabilityDecisionEngine).Assembly.GetTypes().Where(t => t.Namespace == "TerraScale.Orchestrator.ControlPlane.Observability").ToArray();
        var forbiddenNames = new[] { "QueryText", "ConfigText", "Json", "Credential", "Password", "PrivateKey", "SecretValue", "Endpoint", "Url", "Command", "Callback" };
        await Assert.That(types.SelectMany(t => t.GetProperties()).Any(p => forbiddenNames.Any(n => p.Name.Contains(n, StringComparison.OrdinalIgnoreCase)))).IsFalse();
        var forbiddenTypes = new[] { typeof(byte[]), typeof(Stream), typeof(Delegate), typeof(DateTime), typeof(DateTimeOffset), typeof(System.Diagnostics.Process) };
        await Assert.That(types.SelectMany(t => t.GetProperties()).Any(p => forbiddenTypes.Contains(p.PropertyType))).IsFalse();
        await Assert.That(types.Where(t => typeof(ObservabilityIntent).IsAssignableFrom(t) && !t.IsAbstract).SelectMany(t => t.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).Any()).IsFalse();
        await Assert.That(types.Where(t => typeof(GrafanaChange).IsAssignableFrom(t) && !t.IsAbstract).SelectMany(t => t.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).Any()).IsFalse();
        await Assert.That(typeof(ObservabilityDecision).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(Serialize(ObservabilityDecisionEngine.EvaluateTelemetryAdmission(Admission()))).DoesNotContain("secret");
    }

    [Test]
    public async Task UnknownZeroDuplicateAndMalformedInputsFailClosed()
    {
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new ObservabilityGeneration(0))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new ObservabilityDigest("mutable-tag"))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new ObservabilityTenantId("bad/path"))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new DashboardSelection((DashboardCatalogEntry)0))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => Admission(labels: [new(new("region"), new("gru")), new(new("region"), new("sfo"))]))).IsTrue();
    }

    [Test]
    public async Task EveryCallerControlledCollectionRejectsBoundaryPlusOne()
    {
        var labels = new[] { new TelemetryLabel(new("region"), new("gru")), new TelemetryLabel(new("service"), new("platform")) };
        await Assert.That(Throws<ArgumentException>(() => new TelemetryAdmissionSpec(Operation, Tenant, Cell, new("platform"), new("signal-1"), new("metric"), TelemetrySignalKind.Metric, new(5), Digest(), new(1), labels))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new TelemetryLabelCatalogEntry(new("region"), LabelClassification.BoundedPublic, new(1), [new ObservabilityLabelValue("gru"), new ObservabilityLabelValue("sfo")]))).IsTrue();

        var spec = new TelemetryAdmissionSpec(Operation, Tenant, Cell, new("platform"), new("signal-1"), new("metric"), TelemetrySignalKind.Metric, new(5), Digest(), new(1), [labels[0]]);
        var catalogs = new[]
        {
            new TelemetryLabelCatalogEntry(new("region"), LabelClassification.BoundedPublic, new(1), [new ObservabilityLabelValue("gru")]),
            new TelemetryLabelCatalogEntry(new("service"), LabelClassification.BoundedPublic, new(1), [new ObservabilityLabelValue("platform")]),
        };
        await Assert.That(Throws<ArgumentException>(() => new TelemetryAdmissionRequest(spec, Tenant, Cell, new(5), Digest(), new(9), new(100), new(1), catalogs, Cardinality()))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new RegionalHealthRequest(Operation, Cell, new(5), new(9), Digest(), new(3), [Policy(TelemetrySignalKind.Metric), Policy(TelemetrySignalKind.Log), Policy(TelemetrySignalKind.Trace)], Observations().Append(Observation(TelemetrySignalKind.Metric))))).IsTrue();

        var inventory = new GrafanaInventoryEvidence(Operation, Owner, Tenant, Cell, new(5), new(9), EvidenceCompleteness.Complete, new(1), []);
        await Assert.That(Throws<ArgumentException>(() => new GrafanaProjectionRequest(Operation, Owner, Tenant, Cell, GrafanaAccessBoundary.Tenant, new(5), new(9), new(5), new(9), new(1), [Desired("a", DashboardCatalogEntry.FleetOverview), Desired("b", DashboardCatalogEntry.CellHealth)], inventory))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new GrafanaInventoryEvidence(Operation, Owner, Tenant, Cell, new(5), new(9), EvidenceCompleteness.Complete, new(1), [Observed("a"), Observed("b")]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new AlertDedupeEvidence(Operation, Tenant, Cell, new("signal-1"), new(5), Digest(), new(9), new("global-oncall"), ContactCatalogEntry.GlobalOnCall, AlertSeverity.Critical, AlertState.Firing, EvidenceCompleteness.Complete, new(1), [new AlertDeliveryKey(new("a"), AlertState.Firing), new AlertDeliveryKey(new("b"), AlertState.Firing)]))).IsTrue();
        await Assert.That(ObservabilityArithmetic.CheckedAdd(ulong.MaxValue - 1, 1)).IsEqualTo(ulong.MaxValue);
        await Assert.That(Throws<OverflowException>(() => ObservabilityArithmetic.CheckedAdd(ulong.MaxValue, 1))).IsTrue();
    }

    private static ObservabilityOperationId Operation { get; } = new("operation-1");
    private static ObservabilityTenantId Tenant { get; } = new("tenant-a");
    private static ObservabilityCellId Cell { get; } = new("gru");
    private static ObservabilityOwnerId Owner { get; } = new("terrascale");
    private static ObservabilityDigest Digest() => new(new string('a', 64));
    private static ObservabilityDigest OtherDigest() => new(new string('b', 64));

    private static CardinalityEvidence Cardinality(ObservabilityOperationId? operation = null, ulong generation = 5, ulong sequence = 9, EvidenceCompleteness completeness = EvidenceCompleteness.Complete, ulong existing = 10) =>
        new(operation ?? Operation, Tenant, Cell, new("signal-1"), new(generation), Digest(), new(sequence), completeness, existing);

    private static TelemetryAdmissionRequest Admission(
        IEnumerable<TelemetryLabel>? labels = null, IEnumerable<TelemetryLabelCatalogEntry>? catalog = null,
        ObservabilityTenantId? authorizedTenant = null, ObservabilityCellId? authorizedCell = null,
        CardinalityEvidence? cardinality = null, ulong specGeneration = 5, ulong budget = 100)
    {
        var spec = new TelemetryAdmissionSpec(Operation, Tenant, Cell, new("platform"), new("signal-1"), new("request-count"), TelemetrySignalKind.Metric,
            new(specGeneration), Digest(), new(10), labels ?? [new TelemetryLabel(new("region"), new("gru"))]);
        return new(spec, authorizedTenant ?? Tenant, authorizedCell ?? Cell, new(5), Digest(), new(9), new(budget), new(10),
            catalog ?? [new TelemetryLabelCatalogEntry(new("region"), LabelClassification.BoundedPublic, new(10), [new ObservabilityLabelValue("gru"), new ObservabilityLabelValue("sfo")])], cardinality ?? Cardinality());
    }

    private static RegionalSignalPolicy Policy(TelemetrySignalKind signal) => new(signal, TelemetryPersistence.LocalEncryptedSpool, new(24), new(2), new(2), new(1000), SpoolOverflowPolicy.DropOldestAndAlert);
    private static RegionalSignalObservation Observation(TelemetrySignalKind signal, ulong generation = 5, ulong sequence = 9,
        TelemetryPersistence persistence = TelemetryPersistence.LocalEncryptedSpool, ulong retention = 24,
        ulong ingest = 2, ulong query = 2, ulong spoolBytes = 100, bool central = true, SpoolStatus spool = SpoolStatus.Healthy) =>
        new(Operation, Cell, signal, new(generation), new(sequence), Digest(), persistence, new(retention), ingest, query, spoolBytes, central, spool);
    private static RegionalSignalObservation[] Observations(bool metricCentral = true, ulong logIngest = 2, ulong traceQuery = 2) =>
    [
        Observation(TelemetrySignalKind.Metric, central: metricCentral),
        Observation(TelemetrySignalKind.Log, ingest: logIngest),
        Observation(TelemetrySignalKind.Trace, query: traceQuery),
    ];
    private static RegionalHealthRequest Health(IEnumerable<RegionalSignalObservation>? observations = null) =>
        new(Operation, Cell, new(5), new(9), Digest(), new(10), [Policy(TelemetrySignalKind.Metric), Policy(TelemetrySignalKind.Log), Policy(TelemetrySignalKind.Trace)], observations ?? Observations());

    private static DesiredGrafanaResource Desired(string id, DashboardCatalogEntry entry) => new(new(id), Owner, Tenant, Cell, new(5), new("release-5"), Digest(), new DashboardSelection(entry));
    private static DesiredGrafanaResource DesiredAccess(string id, OperatorRoleCatalogEntry role, TelemetryAccess access, ObservabilityUserId? user = null, GrafanaAccessSubject? subject = null, ObservabilityRoleId? roleId = null) => new(new(id), Owner, Tenant, Cell, new(5), new("release-5"), Digest(), new AccessSelection(role, access, roleId ?? new("operator-role"), user ?? new("operator-user"), subject ?? new TenantAccessSubject(Tenant)));
    private static ObservedGrafanaResource Observed(string id, ObservabilityDigest? digest = null, GrafanaOwnership ownership = GrafanaOwnership.ManagedExact, ObservabilityOwnerId? owner = null, ulong generation = 5, DashboardCatalogEntry entry = DashboardCatalogEntry.FleetOverview) =>
        new(new(id), owner ?? Owner, Tenant, Cell, new(generation), digest ?? Digest(), TelemetryProjectionKind.Dashboard, ownership,
            ownership == GrafanaOwnership.ManagedExact ? new(new("release-5"), new DashboardSelection(entry)) : null);
    private static GrafanaProjectionRequest Projection(IEnumerable<DesiredGrafanaResource> desired, IEnumerable<ObservedGrafanaResource> observed,
        EvidenceCompleteness completeness = EvidenceCompleteness.Complete, ObservabilityOperationId? inventoryOperation = null, ulong inventoryGeneration = 5,
        ulong currentSequence = 9, ulong inventorySequence = 9, GrafanaAccessBoundary boundary = GrafanaAccessBoundary.Tenant,
        ulong currentAcceptedGeneration = 5, ulong currentAcceptedSequence = 9) =>
        new(Operation, Owner, Tenant, Cell, boundary, new(5), new(currentSequence), new(currentAcceptedGeneration), new(currentAcceptedSequence), new(20), desired, new GrafanaInventoryEvidence(inventoryOperation ?? Operation, Owner, Tenant, Cell, new(inventoryGeneration), new(inventorySequence), completeness, new(20), observed));

    private static AlertRoutingRequest AlertRoute(
        EvidenceCompleteness completeness = EvidenceCompleteness.Complete, IEnumerable<AlertDeliveryKey>? routed = null,
        ObservabilityOperationId? dedupeOperation = null, ObservabilityOperationId? alertOperation = null,
        ObservabilityTenantId? alertTenant = null, ObservabilityDigest? alertDigest = null, ulong alertGeneration = 5,
        ulong dedupeSequence = 9, ObservabilitySignalId? dedupeSignal = null, ObservabilityDigest? dedupeDigest = null,
        ObservabilityContactId? dedupeContact = null, ContactCatalogEntry dedupeContactCatalog = ContactCatalogEntry.GlobalOnCall,
        AlertState alertState = AlertState.Firing, AlertState? dedupeState = null)
    {
        var alert = new AlertEvent(new("alert-1"), alertOperation ?? Operation, alertTenant ?? Tenant, Cell, new("signal-1"), new(alertGeneration), alertDigest ?? Digest(), AlertSeverity.Critical, alertState);
        var dedupe = new AlertDedupeEvidence(dedupeOperation ?? Operation, Tenant, Cell, dedupeSignal ?? new("signal-1"), new(5), dedupeDigest ?? Digest(), new(dedupeSequence), dedupeContact ?? new("global-oncall"), dedupeContactCatalog, AlertSeverity.Critical, dedupeState ?? alertState, completeness, new(20), routed ?? []);
        return new(alert, Operation, Tenant, Cell, new("signal-1"), new(5), Digest(), new(9), new("global-oncall"), ContactCatalogEntry.GlobalOnCall, dedupe);
    }

    private static ObservabilityDecisionReason Reason(ObservabilityDecision decision, ObservabilityDecisionCode code) => decision.Trace.Single(r => r.Code == code);
    private static string Serialize(ObservabilityDecision decision)
    {
        var changes = decision.Intent is ProjectGrafanaIntent projection ? string.Join(',', projection.Changes.Select(c => $"{c.GetType().Name}:{c.Id.Value}")) : string.Empty;
        return $"{decision.Authorized}|{decision.Intent.GetType().Name}|{changes}|{string.Join(';', decision.Trace.Select(r => $"{r.Code}:{r.Outcome}:{r.Observed}:{r.Required}"))}";
    }
    private static bool Throws<T>(Action action) where T : Exception { try { action(); return false; } catch (T) { return true; } }
}
