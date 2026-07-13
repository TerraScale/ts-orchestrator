using System.Collections.ObjectModel;
using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.ControlPlane.Observability;

internal static partial class ObservabilityIdentity
{
    public static string Token(string value, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);
        if (value.Length is < 1 or > 128 || !TokenPattern().IsMatch(value))
            throw new ArgumentException("Identity must be a bounded canonical token.", name);
        return value;
    }

    public static string Digest(string value, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);
        if (value.Length != 64 || value.Any(c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new ArgumentException("Digest must be canonical SHA-256.", name);
        return value;
    }

    [GeneratedRegex("^[a-z0-9][a-z0-9]*(?:[.-][a-z0-9]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex TokenPattern();
}

public abstract record ObservabilityToken
{
    internal ObservabilityToken(string value, string name) => Value = ObservabilityIdentity.Token(value, name);
    public string Value { get; }
    public sealed override string ToString() => Value;
}

public sealed record ObservabilityCellId : ObservabilityToken { public ObservabilityCellId(string value) : base(value, nameof(value)) { } }
public sealed record ObservabilityTenantId : ObservabilityToken { public ObservabilityTenantId(string value) : base(value, nameof(value)) { } }
public sealed record ObservabilityServiceId : ObservabilityToken { public ObservabilityServiceId(string value) : base(value, nameof(value)) { } }
public sealed record ObservabilitySignalId : ObservabilityToken { public ObservabilitySignalId(string value) : base(value, nameof(value)) { } }
public sealed record ObservabilityMetricId : ObservabilityToken { public ObservabilityMetricId(string value) : base(value, nameof(value)) { } }
public sealed record ObservabilityLabelKey : ObservabilityToken { public ObservabilityLabelKey(string value) : base(value, nameof(value)) { } }
public sealed record ObservabilityLabelValue : ObservabilityToken { public ObservabilityLabelValue(string value) : base(value, nameof(value)) { } }
public sealed record GrafanaDashboardId : ObservabilityToken { public GrafanaDashboardId(string value) : base(value, nameof(value)) { } }
public sealed record GrafanaDatasourceId : ObservabilityToken { public GrafanaDatasourceId(string value) : base(value, nameof(value)) { } }
public sealed record GrafanaFolderId : ObservabilityToken { public GrafanaFolderId(string value) : base(value, nameof(value)) { } }
public sealed record ObservabilityAlertId : ObservabilityToken { public ObservabilityAlertId(string value) : base(value, nameof(value)) { } }
public sealed record ObservabilityContactId : ObservabilityToken { public ObservabilityContactId(string value) : base(value, nameof(value)) { } }
public sealed record ObservabilityRoleId : ObservabilityToken { public ObservabilityRoleId(string value) : base(value, nameof(value)) { } }
public sealed record ObservabilityUserId : ObservabilityToken { public ObservabilityUserId(string value) : base(value, nameof(value)) { } }
public sealed record ObservabilityReleaseId : ObservabilityToken { public ObservabilityReleaseId(string value) : base(value, nameof(value)) { } }
public sealed record ObservabilityOperationId : ObservabilityToken { public ObservabilityOperationId(string value) : base(value, nameof(value)) { } }
public sealed record ObservabilityOwnerId : ObservabilityToken { public ObservabilityOwnerId(string value) : base(value, nameof(value)) { } }

public sealed record ObservabilityDigest
{
    public ObservabilityDigest(string sha256) => Sha256 = ObservabilityIdentity.Digest(sha256, nameof(sha256));
    public string Sha256 { get; }
}

public abstract record PositiveObservabilityNumber
{
    internal PositiveObservabilityNumber(ulong value, string name) => Value = value > 0 ? value : throw new ArgumentOutOfRangeException(name);
    public ulong Value { get; }
}

public sealed record ObservabilityGeneration : PositiveObservabilityNumber { public ObservabilityGeneration(ulong value) : base(value, nameof(value)) { } }
public sealed record ObservabilitySequence : PositiveObservabilityNumber { public ObservabilitySequence(ulong value) : base(value, nameof(value)) { } }
public sealed record CardinalityLimit : PositiveObservabilityNumber { public CardinalityLimit(ulong value) : base(value, nameof(value)) { } }
public sealed record RetentionHours : PositiveObservabilityNumber { public RetentionHours(ulong value) : base(value, nameof(value)) { } }
public sealed record SpoolByteLimit : PositiveObservabilityNumber { public SpoolByteLimit(ulong value) : base(value, nameof(value)) { } }
public sealed record ReplicaCount : PositiveObservabilityNumber { public ReplicaCount(ulong value) : base(value, nameof(value)) { } }
public sealed record EnumerationLimit : PositiveObservabilityNumber { public EnumerationLimit(ulong value) : base(value, nameof(value)) { } }

public enum TelemetrySignalKind { Metric = 1, Log = 2, Trace = 3 }
public enum TelemetryPersistence { Memory = 1, LocalEncryptedSpool = 2, ReplicatedRegional = 3, DurableObjectBacked = 4 }
public enum TelemetryAccess { TenantReader = 1, CellOperator = 2, GlobalOperator = 3 }
public enum TelemetryProjectionKind { Datasource = 1, Folder = 2, Dashboard = 3, Alert = 4, ContactPoint = 5, AccessPolicy = 6 }
public enum TelemetryAction { Admit = 1, Drop = 2, Aggregate = 3, Create = 4, Update = 5, Delete = 6, ReportDrift = 7, RouteAlert = 8, Hold = 9 }
public enum EvidenceCompleteness { Complete = 1, Incomplete = 2, Unknown = 3 }
public enum LabelClassification { BoundedPublic = 1, SecretBearingForbidden = 2, UnboundedForbidden = 3 }
public enum TelemetryAvailability { Available = 1, Degraded = 2, Unavailable = 3, Unknown = 4 }
public enum SpoolOverflowPolicy { DropOldestAndAlert = 1, SampleAndAlert = 2 }
public enum SpoolStatus { Healthy = 1, NearLimit = 2, ExhaustedWithLoss = 3, Unknown = 4 }
public enum GrafanaOwnership { ManagedExact = 1, Unmanaged = 2, Conflicting = 3, Unknown = 4 }
public enum AlertSeverity { Warning = 1, Critical = 2 }
public enum AlertState { Firing = 1, Resolved = 2 }
public enum DashboardCatalogEntry { FleetOverview = 1, CellHealth = 2, Capacity = 3, Failure = 4, Storage = 5, Deployments = 6, Nats = 7, Cost = 8, RegionalState = 9, SecurityMetadata = 10, TelemetryPipeline = 11 }
public enum DatasourceCatalogEntry { ExactStateProjection = 1, Metrics = 2, Logs = 3, Traces = 4, Alerts = 5 }
public enum FolderCatalogEntry { GlobalOperations = 1, RegionalOperations = 2, TenantOperations = 3 }
public enum AlertCatalogEntry { CellUnavailable = 1, TelemetryDataLoss = 2, IngestUnavailable = 3, QueryUnavailable = 4, HaReplicaLoss = 5, SyntheticFailure = 6 }
public enum ContactCatalogEntry { GlobalOnCall = 1, RegionalOnCall = 2, SecurityOnCall = 3 }
public enum OperatorRoleCatalogEntry { TenantViewer = 1, CellViewer = 2, GlobalViewer = 3 }
public enum GrafanaAccessBoundary { Tenant = 1, Cell = 2, Global = 3 }

internal static class ObservabilityGuards
{
    public static T Defined<T>(T value, string name) where T : struct, Enum => Enum.IsDefined(value) ? value : throw new ArgumentOutOfRangeException(name);

    public static IReadOnlyList<T> CopyBounded<T>(IEnumerable<T> source, EnumerationLimit limit, string name) where T : notnull
    {
        ArgumentNullException.ThrowIfNull(source, name);
        ArgumentNullException.ThrowIfNull(limit);
        var values = new List<T>();
        foreach (var value in source)
        {
            if ((ulong)values.Count >= limit.Value) throw new ArgumentException("Collection exceeds its explicit bound.", name);
            if (value is null) throw new ArgumentException("Null evidence is forbidden.", name);
            values.Add(value);
        }
        return new ReadOnlyCollection<T>(values);
    }
}

public static class ObservabilityArithmetic
{
    public static ulong CheckedAdd(ulong left, ulong right) => checked(left + right);
}

public sealed record TelemetryLabel
{
    public TelemetryLabel(ObservabilityLabelKey key, ObservabilityLabelValue value)
    { Key = key ?? throw new ArgumentNullException(nameof(key)); Value = value ?? throw new ArgumentNullException(nameof(value)); }
    public ObservabilityLabelKey Key { get; }
    public ObservabilityLabelValue Value { get; }
}

public sealed record TelemetryLabelCatalogEntry
{
    public TelemetryLabelCatalogEntry(ObservabilityLabelKey key, LabelClassification classification, EnumerationLimit allowedValueLimit, IEnumerable<ObservabilityLabelValue> allowedValues)
    {
        Key = key ?? throw new ArgumentNullException(nameof(key));
        Classification = ObservabilityGuards.Defined(classification, nameof(classification));
        AllowedValueLimit = allowedValueLimit ?? throw new ArgumentNullException(nameof(allowedValueLimit));
        AllowedValues = ObservabilityGuards.CopyBounded(allowedValues, AllowedValueLimit, nameof(allowedValues)).OrderBy(v => v.Value, StringComparer.Ordinal).ToArray();
        if (AllowedValues.Count != AllowedValues.Distinct().Count()) throw new ArgumentException("Duplicate label value.", nameof(allowedValues));
        if (Classification == LabelClassification.BoundedPublic && AllowedValues.Count == 0) throw new ArgumentException("Public labels require a bounded value catalog.", nameof(allowedValues));
    }
    public ObservabilityLabelKey Key { get; }
    public LabelClassification Classification { get; }
    public EnumerationLimit AllowedValueLimit { get; }
    public IReadOnlyList<ObservabilityLabelValue> AllowedValues { get; }
}

public sealed record TelemetryAdmissionSpec
{
    public TelemetryAdmissionSpec(ObservabilityOperationId operationId, ObservabilityTenantId tenantId, ObservabilityCellId cellId, ObservabilityServiceId serviceId, ObservabilitySignalId signalId, ObservabilityMetricId metricId, TelemetrySignalKind signalKind, ObservabilityGeneration schemaGeneration, ObservabilityDigest schemaDigest, EnumerationLimit labelLimit, IEnumerable<TelemetryLabel> labels)
    {
        OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId)); TenantId = tenantId ?? throw new ArgumentNullException(nameof(tenantId)); CellId = cellId ?? throw new ArgumentNullException(nameof(cellId)); ServiceId = serviceId ?? throw new ArgumentNullException(nameof(serviceId)); SignalId = signalId ?? throw new ArgumentNullException(nameof(signalId)); MetricId = metricId ?? throw new ArgumentNullException(nameof(metricId)); SignalKind = ObservabilityGuards.Defined(signalKind, nameof(signalKind)); SchemaGeneration = schemaGeneration ?? throw new ArgumentNullException(nameof(schemaGeneration)); SchemaDigest = schemaDigest ?? throw new ArgumentNullException(nameof(schemaDigest)); LabelLimit = labelLimit ?? throw new ArgumentNullException(nameof(labelLimit)); Labels = ObservabilityGuards.CopyBounded(labels, LabelLimit, nameof(labels)).OrderBy(v => v.Key.Value, StringComparer.Ordinal).ToArray(); if (Labels.Select(v => v.Key).Distinct().Count() != Labels.Count) throw new ArgumentException("Duplicate label key.", nameof(labels));
    }
    public ObservabilityOperationId OperationId { get; }
    public ObservabilityTenantId TenantId { get; }
    public ObservabilityCellId CellId { get; }
    public ObservabilityServiceId ServiceId { get; }
    public ObservabilitySignalId SignalId { get; }
    public ObservabilityMetricId MetricId { get; }
    public TelemetrySignalKind SignalKind { get; }
    public ObservabilityGeneration SchemaGeneration { get; }
    public ObservabilityDigest SchemaDigest { get; }
    public EnumerationLimit LabelLimit { get; }
    public IReadOnlyList<TelemetryLabel> Labels { get; }
}

public sealed record CardinalityEvidence
{
    public CardinalityEvidence(ObservabilityOperationId operationId, ObservabilityTenantId tenantId, ObservabilityCellId cellId, ObservabilitySignalId signalId, ObservabilityGeneration schemaGeneration, ObservabilityDigest schemaDigest, ObservabilitySequence sequence, EvidenceCompleteness completeness, ulong existingSeries)
    { OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId)); TenantId = tenantId ?? throw new ArgumentNullException(nameof(tenantId)); CellId = cellId ?? throw new ArgumentNullException(nameof(cellId)); SignalId = signalId ?? throw new ArgumentNullException(nameof(signalId)); SchemaGeneration = schemaGeneration ?? throw new ArgumentNullException(nameof(schemaGeneration)); SchemaDigest = schemaDigest ?? throw new ArgumentNullException(nameof(schemaDigest)); Sequence = sequence ?? throw new ArgumentNullException(nameof(sequence)); Completeness = ObservabilityGuards.Defined(completeness, nameof(completeness)); ExistingSeries = existingSeries; }
    public ObservabilityOperationId OperationId { get; }
    public ObservabilityTenantId TenantId { get; }
    public ObservabilityCellId CellId { get; }
    public ObservabilitySignalId SignalId { get; }
    public ObservabilityGeneration SchemaGeneration { get; }
    public ObservabilityDigest SchemaDigest { get; }
    public ObservabilitySequence Sequence { get; }
    public EvidenceCompleteness Completeness { get; }
    public ulong ExistingSeries { get; }
}

public sealed record TelemetryAdmissionRequest
{
    public TelemetryAdmissionRequest(TelemetryAdmissionSpec spec, ObservabilityTenantId authorizedTenantId, ObservabilityCellId authorizedCellId, ObservabilityGeneration currentSchemaGeneration, ObservabilityDigest expectedSchemaDigest, ObservabilitySequence currentSequence, CardinalityLimit scopeBudget, EnumerationLimit catalogLimit, IEnumerable<TelemetryLabelCatalogEntry> labelCatalog, CardinalityEvidence cardinality)
    {
        Spec = spec ?? throw new ArgumentNullException(nameof(spec)); AuthorizedTenantId = authorizedTenantId ?? throw new ArgumentNullException(nameof(authorizedTenantId)); AuthorizedCellId = authorizedCellId ?? throw new ArgumentNullException(nameof(authorizedCellId)); CurrentSchemaGeneration = currentSchemaGeneration ?? throw new ArgumentNullException(nameof(currentSchemaGeneration)); ExpectedSchemaDigest = expectedSchemaDigest ?? throw new ArgumentNullException(nameof(expectedSchemaDigest)); CurrentSequence = currentSequence ?? throw new ArgumentNullException(nameof(currentSequence)); ScopeBudget = scopeBudget ?? throw new ArgumentNullException(nameof(scopeBudget)); CatalogLimit = catalogLimit ?? throw new ArgumentNullException(nameof(catalogLimit)); LabelCatalog = ObservabilityGuards.CopyBounded(labelCatalog, CatalogLimit, nameof(labelCatalog)).OrderBy(v => v.Key.Value, StringComparer.Ordinal).ToArray(); if (LabelCatalog.Select(v => v.Key).Distinct().Count() != LabelCatalog.Count) throw new ArgumentException("Duplicate label catalog key.", nameof(labelCatalog)); Cardinality = cardinality ?? throw new ArgumentNullException(nameof(cardinality));
    }
    public TelemetryAdmissionSpec Spec { get; }
    public ObservabilityTenantId AuthorizedTenantId { get; }
    public ObservabilityCellId AuthorizedCellId { get; }
    public ObservabilityGeneration CurrentSchemaGeneration { get; }
    public ObservabilityDigest ExpectedSchemaDigest { get; }
    public ObservabilitySequence CurrentSequence { get; }
    public CardinalityLimit ScopeBudget { get; }
    public EnumerationLimit CatalogLimit { get; }
    public IReadOnlyList<TelemetryLabelCatalogEntry> LabelCatalog { get; }
    public CardinalityEvidence Cardinality { get; }
}

public sealed record RegionalSignalPolicy
{
    public RegionalSignalPolicy(TelemetrySignalKind signal, TelemetryPersistence persistence, RetentionHours retention, ReplicaCount minimumIngestReplicas, ReplicaCount minimumQueryReplicas, SpoolByteLimit spoolLimit, SpoolOverflowPolicy overflowPolicy)
    { Signal = ObservabilityGuards.Defined(signal, nameof(signal)); Persistence = ObservabilityGuards.Defined(persistence, nameof(persistence)); Retention = retention ?? throw new ArgumentNullException(nameof(retention)); MinimumIngestReplicas = minimumIngestReplicas ?? throw new ArgumentNullException(nameof(minimumIngestReplicas)); MinimumQueryReplicas = minimumQueryReplicas ?? throw new ArgumentNullException(nameof(minimumQueryReplicas)); SpoolLimit = spoolLimit ?? throw new ArgumentNullException(nameof(spoolLimit)); OverflowPolicy = ObservabilityGuards.Defined(overflowPolicy, nameof(overflowPolicy)); }
    public TelemetrySignalKind Signal { get; }
    public TelemetryPersistence Persistence { get; }
    public RetentionHours Retention { get; }
    public ReplicaCount MinimumIngestReplicas { get; }
    public ReplicaCount MinimumQueryReplicas { get; }
    public SpoolByteLimit SpoolLimit { get; }
    public SpoolOverflowPolicy OverflowPolicy { get; }
}

public sealed record RegionalSignalObservation
{
    public RegionalSignalObservation(ObservabilityOperationId operationId, ObservabilityCellId cellId, TelemetrySignalKind signal, ObservabilityGeneration generation, ObservabilitySequence sequence, ObservabilityDigest schemaDigest, TelemetryPersistence persistence, RetentionHours retention, ulong healthyIngestReplicas, ulong healthyQueryReplicas, ulong localSpoolBytes, bool centralReachable, SpoolStatus spoolStatus)
    { OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId)); CellId = cellId ?? throw new ArgumentNullException(nameof(cellId)); Signal = ObservabilityGuards.Defined(signal, nameof(signal)); Generation = generation ?? throw new ArgumentNullException(nameof(generation)); Sequence = sequence ?? throw new ArgumentNullException(nameof(sequence)); SchemaDigest = schemaDigest ?? throw new ArgumentNullException(nameof(schemaDigest)); Persistence = ObservabilityGuards.Defined(persistence, nameof(persistence)); Retention = retention ?? throw new ArgumentNullException(nameof(retention)); HealthyIngestReplicas = healthyIngestReplicas; HealthyQueryReplicas = healthyQueryReplicas; LocalSpoolBytes = localSpoolBytes; CentralReachable = centralReachable; SpoolStatus = ObservabilityGuards.Defined(spoolStatus, nameof(spoolStatus)); }
    public ObservabilityOperationId OperationId { get; }
    public ObservabilityCellId CellId { get; }
    public TelemetrySignalKind Signal { get; }
    public ObservabilityGeneration Generation { get; }
    public ObservabilitySequence Sequence { get; }
    public ObservabilityDigest SchemaDigest { get; }
    public TelemetryPersistence Persistence { get; }
    public RetentionHours Retention { get; }
    public ulong HealthyIngestReplicas { get; }
    public ulong HealthyQueryReplicas { get; }
    public ulong LocalSpoolBytes { get; }
    public bool CentralReachable { get; }
    public SpoolStatus SpoolStatus { get; }
}

public sealed record RegionalHealthRequest
{
    public RegionalHealthRequest(ObservabilityOperationId operationId, ObservabilityCellId cellId, ObservabilityGeneration generation, ObservabilitySequence currentSequence, ObservabilityDigest schemaDigest, EnumerationLimit observationLimit, IEnumerable<RegionalSignalPolicy> policies, IEnumerable<RegionalSignalObservation> observations)
    { OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId)); CellId = cellId ?? throw new ArgumentNullException(nameof(cellId)); Generation = generation ?? throw new ArgumentNullException(nameof(generation)); CurrentSequence = currentSequence ?? throw new ArgumentNullException(nameof(currentSequence)); SchemaDigest = schemaDigest ?? throw new ArgumentNullException(nameof(schemaDigest)); ObservationLimit = observationLimit ?? throw new ArgumentNullException(nameof(observationLimit)); Policies = ObservabilityGuards.CopyBounded(policies, new EnumerationLimit((ulong)Enum.GetValues<TelemetrySignalKind>().Length), nameof(policies)).OrderBy(p => p.Signal).ToArray(); Observations = ObservabilityGuards.CopyBounded(observations, ObservationLimit, nameof(observations)).OrderBy(o => o.Signal).ToArray(); if (Policies.Select(p => p.Signal).Distinct().Count() != Policies.Count) throw new ArgumentException("Duplicate signal policy.", nameof(policies)); var required = Enum.GetValues<TelemetrySignalKind>(); if (!Policies.Select(p => p.Signal).SequenceEqual(required)) throw new ArgumentException("Metric, log, and trace policies are all required.", nameof(policies)); }
    public ObservabilityOperationId OperationId { get; }
    public ObservabilityCellId CellId { get; }
    public ObservabilityGeneration Generation { get; }
    public ObservabilitySequence CurrentSequence { get; }
    public ObservabilityDigest SchemaDigest { get; }
    public EnumerationLimit ObservationLimit { get; }
    public IReadOnlyList<RegionalSignalPolicy> Policies { get; }
    public IReadOnlyList<RegionalSignalObservation> Observations { get; }
}

public sealed record RegionalSignalFinding
{
    internal RegionalSignalFinding(TelemetrySignalKind signal, TelemetryAvailability ingest, TelemetryAvailability query, SpoolStatus spool, bool dataLoss)
    { Signal = signal; Ingest = ingest; Query = query; Spool = spool; DataLoss = dataLoss; }
    public TelemetrySignalKind Signal { get; }
    public TelemetryAvailability Ingest { get; }
    public TelemetryAvailability Query { get; }
    public SpoolStatus Spool { get; }
    public bool DataLoss { get; }
}

public abstract record GrafanaCatalogSelection
{
    internal GrafanaCatalogSelection(TelemetryProjectionKind kind) => Kind = kind;
    public TelemetryProjectionKind Kind { get; }
}
public sealed record DashboardSelection : GrafanaCatalogSelection { public DashboardSelection(DashboardCatalogEntry entry) : base(TelemetryProjectionKind.Dashboard) => Entry = ObservabilityGuards.Defined(entry, nameof(entry)); public DashboardCatalogEntry Entry { get; } }
public sealed record DatasourceSelection : GrafanaCatalogSelection { public DatasourceSelection(DatasourceCatalogEntry entry) : base(TelemetryProjectionKind.Datasource) => Entry = ObservabilityGuards.Defined(entry, nameof(entry)); public DatasourceCatalogEntry Entry { get; } }
public sealed record FolderSelection : GrafanaCatalogSelection { public FolderSelection(FolderCatalogEntry entry) : base(TelemetryProjectionKind.Folder) => Entry = ObservabilityGuards.Defined(entry, nameof(entry)); public FolderCatalogEntry Entry { get; } }
public sealed record AlertSelection : GrafanaCatalogSelection { public AlertSelection(AlertCatalogEntry entry) : base(TelemetryProjectionKind.Alert) => Entry = ObservabilityGuards.Defined(entry, nameof(entry)); public AlertCatalogEntry Entry { get; } }
public sealed record ContactSelection : GrafanaCatalogSelection { public ContactSelection(ContactCatalogEntry entry) : base(TelemetryProjectionKind.ContactPoint) => Entry = ObservabilityGuards.Defined(entry, nameof(entry)); public ContactCatalogEntry Entry { get; } }
public abstract record GrafanaAccessSubject { internal GrafanaAccessSubject(GrafanaAccessBoundary boundary) => Boundary = boundary; public GrafanaAccessBoundary Boundary { get; } }
public sealed record TenantAccessSubject : GrafanaAccessSubject { public TenantAccessSubject(ObservabilityTenantId tenantId) : base(GrafanaAccessBoundary.Tenant) => TenantId = tenantId ?? throw new ArgumentNullException(nameof(tenantId)); public ObservabilityTenantId TenantId { get; } }
public sealed record CellAccessSubject : GrafanaAccessSubject { public CellAccessSubject(ObservabilityCellId cellId) : base(GrafanaAccessBoundary.Cell) => CellId = cellId ?? throw new ArgumentNullException(nameof(cellId)); public ObservabilityCellId CellId { get; } }
public sealed record GlobalAccessSubject : GrafanaAccessSubject { public GlobalAccessSubject(ObservabilityOwnerId authorityId) : base(GrafanaAccessBoundary.Global) => AuthorityId = authorityId ?? throw new ArgumentNullException(nameof(authorityId)); public ObservabilityOwnerId AuthorityId { get; } }
public sealed record AccessSelection : GrafanaCatalogSelection { public AccessSelection(OperatorRoleCatalogEntry entry, TelemetryAccess access, ObservabilityRoleId roleId, ObservabilityUserId userId, GrafanaAccessSubject subject) : base(TelemetryProjectionKind.AccessPolicy) { Entry = ObservabilityGuards.Defined(entry, nameof(entry)); Access = ObservabilityGuards.Defined(access, nameof(access)); RoleId = roleId ?? throw new ArgumentNullException(nameof(roleId)); UserId = userId ?? throw new ArgumentNullException(nameof(userId)); Subject = subject ?? throw new ArgumentNullException(nameof(subject)); } public OperatorRoleCatalogEntry Entry { get; } public TelemetryAccess Access { get; } public ObservabilityRoleId RoleId { get; } public ObservabilityUserId UserId { get; } public GrafanaAccessSubject Subject { get; } }

public sealed record GrafanaResourceId : ObservabilityToken { public GrafanaResourceId(string value) : base(value, nameof(value)) { } }

public sealed record DesiredGrafanaResource
{
    public DesiredGrafanaResource(GrafanaResourceId id, ObservabilityOwnerId ownerId, ObservabilityTenantId tenantId, ObservabilityCellId cellId, ObservabilityGeneration generation, ObservabilityReleaseId releaseId, ObservabilityDigest digest, GrafanaCatalogSelection selection)
    { Id = id ?? throw new ArgumentNullException(nameof(id)); OwnerId = ownerId ?? throw new ArgumentNullException(nameof(ownerId)); TenantId = tenantId ?? throw new ArgumentNullException(nameof(tenantId)); CellId = cellId ?? throw new ArgumentNullException(nameof(cellId)); Generation = generation ?? throw new ArgumentNullException(nameof(generation)); ReleaseId = releaseId ?? throw new ArgumentNullException(nameof(releaseId)); Digest = digest ?? throw new ArgumentNullException(nameof(digest)); Selection = selection ?? throw new ArgumentNullException(nameof(selection)); }
    public GrafanaResourceId Id { get; }
    public ObservabilityOwnerId OwnerId { get; }
    public ObservabilityTenantId TenantId { get; }
    public ObservabilityCellId CellId { get; }
    public ObservabilityGeneration Generation { get; }
    public ObservabilityReleaseId ReleaseId { get; }
    public ObservabilityDigest Digest { get; }
    public GrafanaCatalogSelection Selection { get; }
}

public sealed record ObservedGrafanaResource
{
    public ObservedGrafanaResource(GrafanaResourceId id, ObservabilityOwnerId ownerId, ObservabilityTenantId tenantId, ObservabilityCellId cellId, ObservabilityGeneration generation, ObservabilityDigest digest, TelemetryProjectionKind kind, GrafanaOwnership ownership)
    { Id = id ?? throw new ArgumentNullException(nameof(id)); OwnerId = ownerId ?? throw new ArgumentNullException(nameof(ownerId)); TenantId = tenantId ?? throw new ArgumentNullException(nameof(tenantId)); CellId = cellId ?? throw new ArgumentNullException(nameof(cellId)); Generation = generation ?? throw new ArgumentNullException(nameof(generation)); Digest = digest ?? throw new ArgumentNullException(nameof(digest)); Kind = ObservabilityGuards.Defined(kind, nameof(kind)); Ownership = ObservabilityGuards.Defined(ownership, nameof(ownership)); }
    public GrafanaResourceId Id { get; }
    public ObservabilityOwnerId OwnerId { get; }
    public ObservabilityTenantId TenantId { get; }
    public ObservabilityCellId CellId { get; }
    public ObservabilityGeneration Generation { get; }
    public ObservabilityDigest Digest { get; }
    public TelemetryProjectionKind Kind { get; }
    public GrafanaOwnership Ownership { get; }
}

public sealed record GrafanaInventoryEvidence
{
    public GrafanaInventoryEvidence(ObservabilityOperationId operationId, ObservabilityOwnerId ownerId, ObservabilityTenantId tenantId, ObservabilityCellId cellId, ObservabilityGeneration generation, ObservabilitySequence sequence, EvidenceCompleteness completeness, EnumerationLimit resourceLimit, IEnumerable<ObservedGrafanaResource> resources)
    { OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId)); OwnerId = ownerId ?? throw new ArgumentNullException(nameof(ownerId)); TenantId = tenantId ?? throw new ArgumentNullException(nameof(tenantId)); CellId = cellId ?? throw new ArgumentNullException(nameof(cellId)); Generation = generation ?? throw new ArgumentNullException(nameof(generation)); Sequence = sequence ?? throw new ArgumentNullException(nameof(sequence)); Completeness = ObservabilityGuards.Defined(completeness, nameof(completeness)); ResourceLimit = resourceLimit ?? throw new ArgumentNullException(nameof(resourceLimit)); Resources = ObservabilityGuards.CopyBounded(resources, ResourceLimit, nameof(resources)).OrderBy(r => r.Id.Value, StringComparer.Ordinal).ToArray(); if (Resources.Select(r => r.Id).Distinct().Count() != Resources.Count) throw new ArgumentException("Duplicate observed Grafana resource identity.", nameof(resources)); }
    public ObservabilityOperationId OperationId { get; }
    public ObservabilityOwnerId OwnerId { get; }
    public ObservabilityTenantId TenantId { get; }
    public ObservabilityCellId CellId { get; }
    public ObservabilityGeneration Generation { get; }
    public ObservabilitySequence Sequence { get; }
    public EvidenceCompleteness Completeness { get; }
    public EnumerationLimit ResourceLimit { get; }
    public IReadOnlyList<ObservedGrafanaResource> Resources { get; }
}

public sealed record GrafanaProjectionRequest
{
    public GrafanaProjectionRequest(ObservabilityOperationId operationId, ObservabilityOwnerId ownerId, ObservabilityTenantId tenantId, ObservabilityCellId cellId, GrafanaAccessBoundary accessBoundary, ObservabilityGeneration generation, ObservabilitySequence currentSequence, EnumerationLimit desiredLimit, IEnumerable<DesiredGrafanaResource> desired, GrafanaInventoryEvidence inventory)
    { OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId)); OwnerId = ownerId ?? throw new ArgumentNullException(nameof(ownerId)); TenantId = tenantId ?? throw new ArgumentNullException(nameof(tenantId)); CellId = cellId ?? throw new ArgumentNullException(nameof(cellId)); AccessBoundary = ObservabilityGuards.Defined(accessBoundary, nameof(accessBoundary)); Generation = generation ?? throw new ArgumentNullException(nameof(generation)); CurrentSequence = currentSequence ?? throw new ArgumentNullException(nameof(currentSequence)); DesiredLimit = desiredLimit ?? throw new ArgumentNullException(nameof(desiredLimit)); Desired = ObservabilityGuards.CopyBounded(desired, DesiredLimit, nameof(desired)).OrderBy(r => r.Id.Value, StringComparer.Ordinal).ToArray(); if (Desired.Select(r => r.Id).Distinct().Count() != Desired.Count) throw new ArgumentException("Duplicate desired Grafana resource identity."); Inventory = inventory ?? throw new ArgumentNullException(nameof(inventory)); }
    public ObservabilityOperationId OperationId { get; }
    public ObservabilityOwnerId OwnerId { get; }
    public ObservabilityTenantId TenantId { get; }
    public ObservabilityCellId CellId { get; }
    public GrafanaAccessBoundary AccessBoundary { get; }
    public ObservabilityGeneration Generation { get; }
    public ObservabilitySequence CurrentSequence { get; }
    public EnumerationLimit DesiredLimit { get; }
    public IReadOnlyList<DesiredGrafanaResource> Desired { get; }
    public GrafanaInventoryEvidence Inventory { get; }
    public IReadOnlyList<ObservedGrafanaResource> Observed => Inventory.Resources;
}

public sealed record AlertEvent
{
    public AlertEvent(ObservabilityAlertId alertId, ObservabilityOperationId operationId, ObservabilityTenantId tenantId, ObservabilityCellId cellId, ObservabilitySignalId signalId, ObservabilityGeneration generation, ObservabilityDigest ruleDigest, AlertSeverity severity, AlertState state)
    { AlertId = alertId ?? throw new ArgumentNullException(nameof(alertId)); OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId)); TenantId = tenantId ?? throw new ArgumentNullException(nameof(tenantId)); CellId = cellId ?? throw new ArgumentNullException(nameof(cellId)); SignalId = signalId ?? throw new ArgumentNullException(nameof(signalId)); Generation = generation ?? throw new ArgumentNullException(nameof(generation)); RuleDigest = ruleDigest ?? throw new ArgumentNullException(nameof(ruleDigest)); Severity = ObservabilityGuards.Defined(severity, nameof(severity)); State = ObservabilityGuards.Defined(state, nameof(state)); }
    public ObservabilityAlertId AlertId { get; }
    public ObservabilityOperationId OperationId { get; }
    public ObservabilityTenantId TenantId { get; }
    public ObservabilityCellId CellId { get; }
    public ObservabilitySignalId SignalId { get; }
    public ObservabilityGeneration Generation { get; }
    public ObservabilityDigest RuleDigest { get; }
    public AlertSeverity Severity { get; }
    public AlertState State { get; }
}

public sealed record AlertRoutingRequest
{
    public AlertRoutingRequest(AlertEvent alert, ObservabilityOperationId expectedOperationId, ObservabilityTenantId expectedTenantId, ObservabilityCellId expectedCellId, ObservabilitySignalId expectedSignalId, ObservabilityGeneration currentGeneration, ObservabilityDigest expectedRuleDigest, ObservabilitySequence currentSequence, ObservabilityContactId contactId, ContactCatalogEntry contact, AlertDedupeEvidence dedupe)
    { Alert = alert ?? throw new ArgumentNullException(nameof(alert)); ExpectedOperationId = expectedOperationId ?? throw new ArgumentNullException(nameof(expectedOperationId)); ExpectedTenantId = expectedTenantId ?? throw new ArgumentNullException(nameof(expectedTenantId)); ExpectedCellId = expectedCellId ?? throw new ArgumentNullException(nameof(expectedCellId)); ExpectedSignalId = expectedSignalId ?? throw new ArgumentNullException(nameof(expectedSignalId)); CurrentGeneration = currentGeneration ?? throw new ArgumentNullException(nameof(currentGeneration)); ExpectedRuleDigest = expectedRuleDigest ?? throw new ArgumentNullException(nameof(expectedRuleDigest)); CurrentSequence = currentSequence ?? throw new ArgumentNullException(nameof(currentSequence)); ContactId = contactId ?? throw new ArgumentNullException(nameof(contactId)); Contact = ObservabilityGuards.Defined(contact, nameof(contact)); Dedupe = dedupe ?? throw new ArgumentNullException(nameof(dedupe)); }
    public AlertEvent Alert { get; }
    public ObservabilityOperationId ExpectedOperationId { get; }
    public ObservabilityTenantId ExpectedTenantId { get; }
    public ObservabilityCellId ExpectedCellId { get; }
    public ObservabilitySignalId ExpectedSignalId { get; }
    public ObservabilityGeneration CurrentGeneration { get; }
    public ObservabilityDigest ExpectedRuleDigest { get; }
    public ObservabilitySequence CurrentSequence { get; }
    public ObservabilityContactId ContactId { get; }
    public ContactCatalogEntry Contact { get; }
    public AlertDedupeEvidence Dedupe { get; }
}

public sealed record AlertDedupeEvidence
{
    public AlertDedupeEvidence(ObservabilityOperationId operationId, ObservabilityTenantId tenantId, ObservabilityCellId cellId, ObservabilitySignalId signalId, ObservabilityGeneration generation, ObservabilityDigest ruleDigest, ObservabilitySequence sequence, ObservabilityContactId contactId, ContactCatalogEntry contact, AlertSeverity severity, AlertState state, EvidenceCompleteness completeness, EnumerationLimit deliveredEventLimit, IEnumerable<AlertDeliveryKey> deliveredEvents)
    { OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId)); TenantId = tenantId ?? throw new ArgumentNullException(nameof(tenantId)); CellId = cellId ?? throw new ArgumentNullException(nameof(cellId)); SignalId = signalId ?? throw new ArgumentNullException(nameof(signalId)); Generation = generation ?? throw new ArgumentNullException(nameof(generation)); RuleDigest = ruleDigest ?? throw new ArgumentNullException(nameof(ruleDigest)); Sequence = sequence ?? throw new ArgumentNullException(nameof(sequence)); ContactId = contactId ?? throw new ArgumentNullException(nameof(contactId)); Contact = ObservabilityGuards.Defined(contact, nameof(contact)); Severity = ObservabilityGuards.Defined(severity, nameof(severity)); State = ObservabilityGuards.Defined(state, nameof(state)); Completeness = ObservabilityGuards.Defined(completeness, nameof(completeness)); DeliveredEventLimit = deliveredEventLimit ?? throw new ArgumentNullException(nameof(deliveredEventLimit)); DeliveredEvents = ObservabilityGuards.CopyBounded(deliveredEvents, DeliveredEventLimit, nameof(deliveredEvents)).OrderBy(v => v.AlertId.Value, StringComparer.Ordinal).ThenBy(v => v.State).ToArray(); if (DeliveredEvents.Distinct().Count() != DeliveredEvents.Count) throw new ArgumentException("Duplicate alert delivery evidence.", nameof(deliveredEvents)); }
    public ObservabilityOperationId OperationId { get; }
    public ObservabilityTenantId TenantId { get; }
    public ObservabilityCellId CellId { get; }
    public ObservabilitySignalId SignalId { get; }
    public ObservabilityGeneration Generation { get; }
    public ObservabilityDigest RuleDigest { get; }
    public ObservabilitySequence Sequence { get; }
    public ObservabilityContactId ContactId { get; }
    public ContactCatalogEntry Contact { get; }
    public AlertSeverity Severity { get; }
    public AlertState State { get; }
    public EvidenceCompleteness Completeness { get; }
    public EnumerationLimit DeliveredEventLimit { get; }
    public IReadOnlyList<AlertDeliveryKey> DeliveredEvents { get; }
}

public sealed record AlertDeliveryKey
{
    public AlertDeliveryKey(ObservabilityAlertId alertId, AlertState state)
    { AlertId = alertId ?? throw new ArgumentNullException(nameof(alertId)); State = ObservabilityGuards.Defined(state, nameof(state)); }
    public ObservabilityAlertId AlertId { get; }
    public AlertState State { get; }
}

public enum ObservabilityDecisionCode { EvidenceComplete = 1, ScopeExact = 2, OperationExact = 3, GenerationCurrent = 4, SchemaExact = 5, LabelsBounded = 6, SecretFree = 7, CardinalityWithinBudget = 8, PersistenceExact = 9, RetentionExact = 10, IngestHaSatisfied = 11, QueryHaSatisfied = 12, SpoolWithinPolicy = 13, OwnershipExact = 14, AccessExact = 15, ProjectionExact = 16, DedupeUnique = 17 }
public enum ObservabilityDecisionOutcome { Passed = 1, Rejected = 2, Held = 3, NotApplicable = 4 }
public sealed record ObservabilityDecisionReason { internal ObservabilityDecisionReason(ObservabilityDecisionCode code, ObservabilityDecisionOutcome outcome, ulong observed, ulong required) { Code = code; Outcome = outcome; Observed = observed; Required = required; } public ObservabilityDecisionCode Code { get; } public ObservabilityDecisionOutcome Outcome { get; } public ulong Observed { get; } public ulong Required { get; } }

public abstract record ObservabilityIntent { internal ObservabilityIntent(ObservabilityOperationId operationId) => OperationId = operationId; public ObservabilityOperationId OperationId { get; } }
public sealed record AdmitTelemetryIntent : ObservabilityIntent { internal AdmitTelemetryIntent(TelemetryAdmissionSpec spec) : base(spec.OperationId) => Spec = spec; public TelemetryAdmissionSpec Spec { get; } }
public sealed record DropTelemetryIntent : ObservabilityIntent { internal DropTelemetryIntent(ObservabilityOperationId operationId) : base(operationId) { } }
public sealed record AggregateRegionalTelemetryIntent : ObservabilityIntent { internal AggregateRegionalTelemetryIntent(RegionalHealthRequest request, IReadOnlyList<RegionalSignalFinding> findings) : base(request.OperationId) { Request = request; Findings = findings; } public RegionalHealthRequest Request { get; } public IReadOnlyList<RegionalSignalFinding> Findings { get; } }
public abstract record GrafanaChange { internal GrafanaChange(GrafanaResourceId id, GrafanaInventoryEvidence inventory) { Id = id; Inventory = inventory; } public GrafanaResourceId Id { get; } public GrafanaInventoryEvidence Inventory { get; } }
public sealed record CreateGrafanaResource : GrafanaChange { internal CreateGrafanaResource(DesiredGrafanaResource resource, GrafanaInventoryEvidence inventory) : base(resource.Id, inventory) => Resource = resource; public DesiredGrafanaResource Resource { get; } }
public sealed record UpdateGrafanaResource : GrafanaChange { internal UpdateGrafanaResource(DesiredGrafanaResource resource, ObservedGrafanaResource observed, GrafanaInventoryEvidence inventory) : base(resource.Id, inventory) { Resource = resource; Observed = observed; } public DesiredGrafanaResource Resource { get; } public ObservedGrafanaResource Observed { get; } }
public sealed record DeleteGrafanaResource : GrafanaChange { internal DeleteGrafanaResource(ObservedGrafanaResource resource, GrafanaInventoryEvidence inventory) : base(resource.Id, inventory) => Resource = resource; public ObservedGrafanaResource Resource { get; } }
public sealed record ReportGrafanaDrift : GrafanaChange { internal ReportGrafanaDrift(ObservedGrafanaResource resource, GrafanaInventoryEvidence inventory) : base(resource.Id, inventory) => Resource = resource; public ObservedGrafanaResource Resource { get; } }
public sealed record ProjectGrafanaIntent : ObservabilityIntent { internal ProjectGrafanaIntent(GrafanaProjectionRequest request, IReadOnlyList<GrafanaChange> changes) : base(request.OperationId) { Request = request; Changes = changes; } public GrafanaProjectionRequest Request { get; } public IReadOnlyList<GrafanaChange> Changes { get; } }
public sealed record RouteAlertIntent : ObservabilityIntent { internal RouteAlertIntent(AlertRoutingRequest request) : base(request.Alert.OperationId) { AlertId = request.Alert.AlertId; ContactId = request.ContactId; Contact = request.Contact; } public ObservabilityAlertId AlertId { get; } public ObservabilityContactId ContactId { get; } public ContactCatalogEntry Contact { get; } }
public sealed record HoldObservabilityIntent : ObservabilityIntent { internal HoldObservabilityIntent(ObservabilityOperationId operationId) : base(operationId) { } }
public sealed record ObservabilityDecision { internal ObservabilityDecision(bool authorized, IReadOnlyList<ObservabilityDecisionReason> trace, ObservabilityIntent intent) { Authorized = authorized; Trace = trace; Intent = intent; } public bool Authorized { get; } public IReadOnlyList<ObservabilityDecisionReason> Trace { get; } public ObservabilityIntent Intent { get; } }
