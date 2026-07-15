using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Observability;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class ObservabilityProjectionProvenanceAudit4Tests
{
    [Test]
    public async Task Release_only_and_same_kind_catalog_mismatches_require_update()
    {
        var desired = Desired("dashboard", new DashboardSelection(DashboardCatalogEntry.FleetOverview));

        var releaseMismatch = Decide(desired, Observed(desired, new("release-other"), desired.Selection));
        var selectionMismatch = Decide(desired, Observed(desired, desired.ReleaseId, new DashboardSelection(DashboardCatalogEntry.CellHealth)));

        await AssertUpdateRetainsExactEvidence(releaseMismatch, desired);
        await AssertUpdateRetainsExactEvidence(selectionMismatch, desired);
    }

    [Test]
    public async Task Every_catalog_selection_family_is_exact_and_exact_provenance_is_a_noop()
    {
        var cases = new (GrafanaCatalogSelection Exact, GrafanaCatalogSelection Other)[]
        {
            (new DashboardSelection(DashboardCatalogEntry.FleetOverview), new DashboardSelection(DashboardCatalogEntry.CellHealth)),
            (new DatasourceSelection(DatasourceCatalogEntry.ExactStateProjection), new DatasourceSelection(DatasourceCatalogEntry.Metrics)),
            (new FolderSelection(FolderCatalogEntry.GlobalOperations), new FolderSelection(FolderCatalogEntry.RegionalOperations)),
            (new AlertSelection(AlertCatalogEntry.CellUnavailable), new AlertSelection(AlertCatalogEntry.TelemetryDataLoss)),
            (new ContactSelection(ContactCatalogEntry.GlobalOnCall), new ContactSelection(ContactCatalogEntry.RegionalOnCall)),
            (Access(), Access(entry: OperatorRoleCatalogEntry.CellViewer)),
        };

        for (var index = 0; index < cases.Length; index++)
        {
            var desired = Desired($"resource-{index}", cases[index].Exact);
            var exact = Decide(desired, Observed(desired, desired.ReleaseId, cases[index].Exact));
            var mismatch = Decide(desired, Observed(desired, desired.ReleaseId, cases[index].Other));

            await Assert.That(exact.Authorized).IsTrue();
            await Assert.That(((ProjectGrafanaIntent)exact.Intent).Changes).IsEmpty();
            await AssertUpdateRetainsExactEvidence(mismatch, desired);
            await Assert.That(ProvenanceFingerprint(new(desired.ReleaseId, cases[index].Exact)))
                .IsNotEqualTo(ProvenanceFingerprint(new(desired.ReleaseId, cases[index].Other)));
        }
    }

    [Test]
    public async Task Every_access_selection_field_is_part_of_managed_provenance()
    {
        var exact = Access();
        GrafanaCatalogSelection[] mismatches =
        [
            Access(entry: OperatorRoleCatalogEntry.CellViewer),
            Access(access: TelemetryAccess.CellOperator),
            Access(roleId: new("role-b")),
            Access(userId: new("user-b")),
            Access(subject: new TenantAccessSubject(new("tenant-b"))),
        ];

        var desired = Desired("access", exact);
        foreach (var mismatch in mismatches)
        {
            var decision = Decide(desired, Observed(desired, desired.ReleaseId, mismatch));
            await AssertUpdateRetainsExactEvidence(decision, desired);
            await Assert.That(ProvenanceFingerprint(((UpdateGrafanaResource)((ProjectGrafanaIntent)decision.Intent).Changes.Single()).Observed.ManagedProvenance!))
                .IsNotEqualTo(ProvenanceFingerprint(new(desired.ReleaseId, exact)));
        }
    }

    [Test]
    public async Task Managed_provenance_constructor_is_single_state_and_kind_exact()
    {
        var desired = Desired("resource", new DashboardSelection(DashboardCatalogEntry.FleetOverview));
        var provenance = new ManagedGrafanaProjectionProvenance(desired.ReleaseId, desired.Selection);

        await Assert.That(Throws<ArgumentException>(() => RawObserved(desired, GrafanaOwnership.ManagedExact, null))).IsTrue();
        foreach (var ownership in new[] { GrafanaOwnership.Unmanaged, GrafanaOwnership.Conflicting, GrafanaOwnership.Unknown })
        {
            await Assert.That(Throws<ArgumentException>(() => RawObserved(desired, ownership, provenance))).IsTrue();
            await Assert.That(RawObserved(desired, ownership, null).ManagedProvenance).IsNull();
        }

        await Assert.That(ReferenceEquals(RawObserved(desired, GrafanaOwnership.ManagedExact, provenance).ManagedProvenance, provenance)).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new ObservedGrafanaResource(
            desired.Id, Owner, Tenant, Cell, Generation, Digest, TelemetryProjectionKind.Folder, GrafanaOwnership.ManagedExact, provenance))).IsTrue();
    }

    [Test]
    public async Task Unmanaged_and_conflicting_resources_remain_report_only()
    {
        var desired = Desired("resource", new DashboardSelection(DashboardCatalogEntry.FleetOverview));
        foreach (var ownership in new[] { GrafanaOwnership.Unmanaged, GrafanaOwnership.Conflicting })
        {
            var decision = Decide(desired, RawObserved(desired, ownership, null));
            var change = ((ProjectGrafanaIntent)decision.Intent).Changes.Single();
            await Assert.That(decision.Authorized).IsTrue();
            await Assert.That(change is ReportGrafanaDrift).IsTrue();
            await Assert.That(change is UpdateGrafanaResource or DeleteGrafanaResource).IsFalse();
        }
    }

    [Test]
    public async Task Provenance_fingerprint_is_complete_replayable_culture_and_permutation_stable()
    {
        var baseline = new ManagedGrafanaProjectionProvenance(new("release-5"), Access());
        var variants = new[]
        {
            new ManagedGrafanaProjectionProvenance(new("release-other"), Access()),
            new ManagedGrafanaProjectionProvenance(new("release-5"), Access(entry: OperatorRoleCatalogEntry.CellViewer)),
            new ManagedGrafanaProjectionProvenance(new("release-5"), Access(access: TelemetryAccess.CellOperator)),
            new ManagedGrafanaProjectionProvenance(new("release-5"), Access(roleId: new("role-b"))),
            new ManagedGrafanaProjectionProvenance(new("release-5"), Access(userId: new("user-b"))),
            new ManagedGrafanaProjectionProvenance(new("release-5"), Access(subject: new TenantAccessSubject(new("tenant-b")))),
            new ManagedGrafanaProjectionProvenance(new("release-5"), Access(subject: new CellAccessSubject(new("sfo")))),
            new ManagedGrafanaProjectionProvenance(new("release-5"), Access(subject: new GlobalAccessSubject(new("authority-b")))),
        };
        await Assert.That(variants.Select(ProvenanceFingerprint).All(value => value != ProvenanceFingerprint(baseline))).IsTrue();

        string? expected = null;
        foreach (var culture in new[] { "en-US", "tr-TR", "ar-SA" })
        foreach (var reverse in new[] { false, true })
        {
            var previous = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
                var a = Desired("a", new DashboardSelection(DashboardCatalogEntry.FleetOverview));
                var b = Desired("b", new FolderSelection(FolderCatalogEntry.GlobalOperations));
                DesiredGrafanaResource[] desired = [a, b];
                ObservedGrafanaResource[] observed = [Observed(a, a.ReleaseId, a.Selection), Observed(b, b.ReleaseId, b.Selection)];
                if (reverse) { Array.Reverse(desired); Array.Reverse(observed); }
                var request = Request(desired, observed);
                var first = ObservabilityDecisionEngine.EvaluateGrafanaProjection(request);
                var replay = ObservabilityDecisionEngine.EvaluateGrafanaProjection(request);
                var actual = ProjectionFingerprint((ProjectGrafanaIntent)first.Intent);
                expected ??= actual;
                await Assert.That(actual).IsEqualTo(expected);
                await Assert.That(ProjectionFingerprint((ProjectGrafanaIntent)replay.Intent)).IsEqualTo(actual);
            }
            finally { CultureInfo.CurrentCulture = previous; }
        }
    }

    [Test]
    public async Task Public_decision_intent_change_and_factory_surfaces_are_exhaustive()
    {
        var assembly = typeof(ObservabilityDecision).Assembly;
        var decisionFactories = assembly.GetTypes().SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Static))
            .Where(method => method.ReturnType == typeof(ObservabilityDecision)).ToArray();
        await Assert.That(decisionFactories.Select(method => method.Name).Order().SequenceEqual(new[]
        {
            nameof(ObservabilityDecisionEngine.EvaluateAlertRouting),
            nameof(ObservabilityDecisionEngine.EvaluateGrafanaProjection),
            nameof(ObservabilityDecisionEngine.EvaluateRegionalHealth),
            nameof(ObservabilityDecisionEngine.EvaluateTelemetryAdmission),
        })).IsTrue();
        await Assert.That(decisionFactories.All(method => method.DeclaringType == typeof(ObservabilityDecisionEngine))).IsTrue();
        await Assert.That(typeof(ObservabilityDecision).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();

        var closedOutputTypes = assembly.GetTypes().Where(type => typeof(ObservabilityIntent).IsAssignableFrom(type) || typeof(GrafanaChange).IsAssignableFrom(type)).ToArray();
        await Assert.That(closedOutputTypes.SelectMany(type => type.GetConstructors(BindingFlags.Public | BindingFlags.Instance))).IsEmpty();
        await Assert.That(assembly.GetTypes().SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Static))
            .Where(method => typeof(ObservabilityIntent).IsAssignableFrom(method.ReturnType) || typeof(GrafanaChange).IsAssignableFrom(method.ReturnType))).IsEmpty();
        await Assert.That(typeof(ObservedGrafanaResource).GetConstructors(BindingFlags.Public | BindingFlags.Instance).Single().GetParameters().Last().ParameterType)
            .IsEqualTo(typeof(ManagedGrafanaProjectionProvenance));
    }

    private static readonly ObservabilityOwnerId Owner = new("terrascale");
    private static readonly ObservabilityTenantId Tenant = new("tenant-a");
    private static readonly ObservabilityCellId Cell = new("gru");
    private static readonly ObservabilityOperationId Operation = new("operation-1");
    private static readonly ObservabilityGeneration Generation = new(5);
    private static readonly ObservabilitySequence Sequence = new(9);
    private static readonly ObservabilityDigest Digest = new(new string('a', 64));

    private static AccessSelection Access(
        OperatorRoleCatalogEntry entry = OperatorRoleCatalogEntry.TenantViewer,
        TelemetryAccess access = TelemetryAccess.TenantReader,
        ObservabilityRoleId? roleId = null,
        ObservabilityUserId? userId = null,
        GrafanaAccessSubject? subject = null) =>
        new(entry, access, roleId ?? new("role-a"), userId ?? new("user-a"), subject ?? new TenantAccessSubject(Tenant));

    private static DesiredGrafanaResource Desired(string id, GrafanaCatalogSelection selection) =>
        new(new(id), Owner, Tenant, Cell, Generation, new("release-5"), Digest, selection);

    private static ObservedGrafanaResource Observed(DesiredGrafanaResource desired, ObservabilityReleaseId releaseId, GrafanaCatalogSelection selection) =>
        RawObserved(desired, GrafanaOwnership.ManagedExact, new(releaseId, selection));

    private static ObservedGrafanaResource RawObserved(DesiredGrafanaResource desired, GrafanaOwnership ownership, ManagedGrafanaProjectionProvenance? provenance) =>
        new(desired.Id, desired.OwnerId, desired.TenantId, desired.CellId, desired.Generation, desired.Digest, desired.Selection.Kind, ownership, provenance);

    private static GrafanaProjectionRequest Request(IEnumerable<DesiredGrafanaResource> desired, IEnumerable<ObservedGrafanaResource> observed)
    {
        var inventory = new GrafanaInventoryEvidence(Operation, Owner, Tenant, Cell, Generation, Sequence, EvidenceCompleteness.Complete, new(20), observed);
        return new(Operation, Owner, Tenant, Cell, GrafanaAccessBoundary.Tenant, Generation, Sequence, Generation, Sequence, new(20), desired, inventory);
    }

    private static ObservabilityDecision Decide(DesiredGrafanaResource desired, ObservedGrafanaResource observed) =>
        ObservabilityDecisionEngine.EvaluateGrafanaProjection(Request([desired], [observed]));

    private static async Task AssertUpdateRetainsExactEvidence(ObservabilityDecision decision, DesiredGrafanaResource desired)
    {
        var intent = (ProjectGrafanaIntent)decision.Intent;
        var update = (UpdateGrafanaResource)intent.Changes.Single();
        await Assert.That(decision.Authorized).IsTrue();
        await Assert.That(ReferenceEquals(intent.Request.Desired.Single(), desired)).IsTrue();
        await Assert.That(ReferenceEquals(update.Resource, desired)).IsTrue();
        await Assert.That(ReferenceEquals(update.Observed, intent.Request.Observed.Single())).IsTrue();
        await Assert.That(ReferenceEquals(update.Inventory, intent.Request.Inventory)).IsTrue();
    }

    private static string ProjectionFingerprint(ProjectGrafanaIntent intent) =>
        string.Join("|", intent.Request.Desired.Select(resource => Field(resource.Id.Value) + Field(resource.ReleaseId.Value) + SelectionFingerprint(resource.Selection))) + "#" +
        string.Join("|", intent.Request.Observed.Select(resource => Field(resource.Id.Value) + ProvenanceFingerprint(resource.ManagedProvenance!))) + "#" +
        string.Join("|", intent.Changes.Select(change => change.GetType().Name + ":" + change.Id.Value));

    private static string ProvenanceFingerprint(ManagedGrafanaProjectionProvenance provenance) =>
        Field(provenance.ReleaseId.Value) + SelectionFingerprint(provenance.Selection);

    private static string SelectionFingerprint(GrafanaCatalogSelection selection) => selection switch
    {
        DashboardSelection value => Field(nameof(DashboardSelection)) + Field(((int)value.Kind).ToString(CultureInfo.InvariantCulture)) + Field(((int)value.Entry).ToString(CultureInfo.InvariantCulture)),
        DatasourceSelection value => Field(nameof(DatasourceSelection)) + Field(((int)value.Kind).ToString(CultureInfo.InvariantCulture)) + Field(((int)value.Entry).ToString(CultureInfo.InvariantCulture)),
        FolderSelection value => Field(nameof(FolderSelection)) + Field(((int)value.Kind).ToString(CultureInfo.InvariantCulture)) + Field(((int)value.Entry).ToString(CultureInfo.InvariantCulture)),
        AlertSelection value => Field(nameof(AlertSelection)) + Field(((int)value.Kind).ToString(CultureInfo.InvariantCulture)) + Field(((int)value.Entry).ToString(CultureInfo.InvariantCulture)),
        ContactSelection value => Field(nameof(ContactSelection)) + Field(((int)value.Kind).ToString(CultureInfo.InvariantCulture)) + Field(((int)value.Entry).ToString(CultureInfo.InvariantCulture)),
        AccessSelection value => Field(nameof(AccessSelection)) + Field(((int)value.Kind).ToString(CultureInfo.InvariantCulture)) + Field(((int)value.Entry).ToString(CultureInfo.InvariantCulture)) +
            Field(((int)value.Access).ToString(CultureInfo.InvariantCulture)) + Field(value.RoleId.Value) + Field(value.UserId.Value) + SubjectFingerprint(value.Subject),
        _ => throw new ArgumentOutOfRangeException(nameof(selection)),
    };

    private static string SubjectFingerprint(GrafanaAccessSubject subject) => subject switch
    {
        TenantAccessSubject value => Field(nameof(TenantAccessSubject)) + Field(((int)value.Boundary).ToString(CultureInfo.InvariantCulture)) + Field(value.TenantId.Value),
        CellAccessSubject value => Field(nameof(CellAccessSubject)) + Field(((int)value.Boundary).ToString(CultureInfo.InvariantCulture)) + Field(value.CellId.Value),
        GlobalAccessSubject value => Field(nameof(GlobalAccessSubject)) + Field(((int)value.Boundary).ToString(CultureInfo.InvariantCulture)) + Field(value.AuthorityId.Value),
        _ => throw new ArgumentOutOfRangeException(nameof(subject)),
    };

    private static string Field(string value) => $"{value.Length.ToString(CultureInfo.InvariantCulture)}:{value}";
    private static bool Throws<T>(Action action) where T : Exception { try { action(); return false; } catch (T) { return true; } }
}
