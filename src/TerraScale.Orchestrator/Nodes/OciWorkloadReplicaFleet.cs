using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;
using Oci.Common;
using Oci.Common.Auth;
using Oci.Common.Model;
using Oci.CoreService;
using Oci.CoreService.Models;
using Oci.CoreService.Requests;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.ControlPlane.Providers;
using TerraScale.Orchestrator.Scheduler.Autoscaling;

namespace TerraScale.Orchestrator.Nodes;

/// <summary>
/// The per-cell OCI workload fleet file.  A file is deliberately regional: one
/// Compute endpoint and one launch template per independently scaled workload.
/// It contains no credentials; instance principals authenticate the transport.
/// </summary>
public sealed class OciWorkloadFleetConfigurationFile
{
    private const int MaximumConfigurationBytes = 96 * 1024;
    private const int MaximumBootstrapBytes = 32 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private OciWorkloadFleetConfigurationFile(
        Uri endpoint,
        string region,
        IReadOnlyDictionary<string, OciWorkloadTemplate> workloads)
    {
        Endpoint = endpoint;
        Region = region;
        Workloads = workloads;
    }

    public Uri Endpoint { get; }
    public string Region { get; }
    internal IReadOnlyDictionary<string, OciWorkloadTemplate> Workloads { get; }
    internal IReadOnlyList<WorkloadScalePolicy> Policies => Workloads.Values
        .Select(static value => value.Policy)
        .OrderBy(static value => value.WorkloadId, StringComparer.Ordinal)
        .ToArray();

    public static OciWorkloadFleetConfigurationFile? Load(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;
        var fullPath = Path.GetFullPath(path);
        var file = new FileInfo(fullPath);
        if (!file.Exists || file.LinkTarget is not null || file.Length is < 1 or > MaximumConfigurationBytes)
            throw new ArgumentException("The OCI workload fleet configuration must be a bounded regular file.", nameof(path));
        using var stream = File.OpenRead(fullPath);
        var document = JsonSerializer.Deserialize<FleetDocument>(stream, SerializerOptions)
            ?? throw new InvalidDataException("The OCI workload fleet configuration is empty.");
        if (document.SchemaVersion != 1 || !TerraScaleRegion.IsValid(document.Region) ||
            document.Workloads is not { Length: >= 1 and <= 16 })
            throw new InvalidDataException("The OCI workload fleet configuration has an unsupported shape.");
        if (!Uri.TryCreate(document.Endpoint, UriKind.Absolute, out var endpoint) ||
            endpoint.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(endpoint.UserInfo) ||
            endpoint.AbsolutePath != "/" || !endpoint.IsDefaultPort ||
            !string.IsNullOrEmpty(endpoint.Query) || !string.IsNullOrEmpty(endpoint.Fragment) ||
            !endpoint.Host.StartsWith("iaas.", StringComparison.Ordinal) ||
            !endpoint.Host.EndsWith(".oraclecloud.com", StringComparison.Ordinal) ||
            !string.Equals(endpoint.Host, $"iaas.{TerraScaleRegion.OciName(document.Region!)}.oraclecloud.com", StringComparison.Ordinal))
            throw new InvalidDataException("The OCI workload fleet endpoint is invalid.");

        var baseDirectory = file.DirectoryName ?? Directory.GetCurrentDirectory();
        var workloads = new Dictionary<string, OciWorkloadTemplate>(StringComparer.Ordinal);
        foreach (var workload in document.Workloads)
        {
            if (workload is null || string.IsNullOrWhiteSpace(workload.Workload) ||
                string.IsNullOrWhiteSpace(workload.Role) || workloads.ContainsKey(workload.Workload) ||
                workload.MinReplicas is < 1 or > AutoscalingTokens.MaximumReplicaCount ||
                workload.MaxReplicas is < 1 or > AutoscalingTokens.MaximumReplicaCount ||
                workload.MinReplicas > workload.MaxReplicas ||
                workload.ScaleUpConfirmTicks is < 1 or > 32 ||
                workload.ScaleDownConfirmTicks is < 1 or > 32 ||
                string.IsNullOrWhiteSpace(workload.CompartmentId) ||
                string.IsNullOrWhiteSpace(workload.AvailabilityDomain) ||
                string.IsNullOrWhiteSpace(workload.SubnetId) ||
                string.IsNullOrWhiteSpace(workload.ImageId) ||
                string.IsNullOrWhiteSpace(workload.BootstrapFile))
                throw new InvalidDataException("An OCI workload template has an unsupported shape.");
            var bootstrapPath = Path.GetFullPath(workload.BootstrapFile, baseDirectory);
            var bootstrapFile = new FileInfo(bootstrapPath);
            if (!bootstrapFile.Exists || bootstrapFile.LinkTarget is not null ||
                bootstrapFile.Length is < 1 or > MaximumBootstrapBytes)
                throw new InvalidDataException("An OCI workload bootstrap must be a bounded regular file.");
            var bootstrap = File.ReadAllBytes(bootstrapPath);
            var bootstrapText = StrictUtf8.GetString(bootstrap);
            if (!bootstrapText.StartsWith("#cloud-config", StringComparison.Ordinal) &&
                !bootstrapText.StartsWith("#!", StringComparison.Ordinal) ||
                ContainsCredential(bootstrapText))
                throw new InvalidDataException("An OCI workload bootstrap must be executable and contain no plaintext credential.");

            var policy = new WorkloadScalePolicy(
                workload.Workload,
                workload.Role,
                workload.MinReplicas,
                workload.MaxReplicas,
                workload.ScaleUpConfirmTicks,
                workload.ScaleDownConfirmTicks);
            var template = new OciCiRunnerLaunchTemplate(
                workload.CompartmentId,
                workload.AvailabilityDomain,
                workload.FaultDomain,
                workload.SubnetId,
                workload.NetworkSecurityGroupIds ?? [],
                workload.ImageId,
                workload.Generation > 0 ? workload.Generation : throw new InvalidDataException("An OCI workload generation must be positive."));
            workloads.Add(workload.Workload, new OciWorkloadTemplate(
                policy,
                template,
                Convert.ToBase64String(bootstrap),
                Convert.ToHexStringLower(SHA256.HashData(bootstrap))));
        }

        // Authentication is always independently configured. TerraBase may be
        // owned by the stateful placement fleet, in which case this generic file
        // intentionally contains only ts-auth; composition validation below
        // requires both policies when no placement fleet is configured.
        if (!workloads.ContainsKey("ts-auth"))
            throw new InvalidDataException("The OCI workload fleet must define an independent ts-auth policy.");
        return new(endpoint, document.Region!, workloads);
    }

    internal OciWorkloadTemplate TemplateFor(WorkloadScalePolicy policy) =>
        Workloads.TryGetValue(policy.WorkloadId, out var template)
            ? template
            : throw new InvalidOperationException($"No OCI workload template is configured for {policy.WorkloadId}.");

    private static bool ContainsCredential(string value) =>
        value.Contains("BEGIN NATS USER JWT", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("BEGIN USER NKEY SEED", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("PRIVATE KEY-----", StringComparison.OrdinalIgnoreCase);

    private sealed record FleetDocument(int? SchemaVersion, string? Region, string? Endpoint, WorkloadDocument[]? Workloads);
    private sealed record WorkloadDocument(
        string? Workload,
        string? Role,
        string? CompartmentId,
        string? AvailabilityDomain,
        string? FaultDomain,
        string? SubnetId,
        string[]? NetworkSecurityGroupIds,
        string? ImageId,
        long Generation,
        int MinReplicas,
        int MaxReplicas,
        int ScaleUpConfirmTicks,
        int ScaleDownConfirmTicks,
        string? BootstrapFile);
}

internal sealed record OciWorkloadTemplate(
    WorkloadScalePolicy Policy,
    OciCiRunnerLaunchTemplate LaunchTemplate,
    string BootstrapBase64,
    string BootstrapSha256);

/// <summary>Canonical region labels accepted by regional workload fleet files.</summary>
internal static class TerraScaleRegion
{
    internal static bool IsValid(string? value) => value is "GRU" or "SFO" or "FRA";

    /// <summary>
    /// Logical TerraScale cells intentionally keep their product names while OCI
    /// uses the official region key.  Keep this mapping in one place so a fleet
    /// cannot accidentally send a logical SFO workload to a different endpoint.
    /// </summary>
    internal static string OciName(string value) => value switch
    {
        "GRU" => "sa-saopaulo-1",
        "SFO" => "us-sanjose-1",
        "FRA" => "eu-frankfurt-1",
        _ => throw new ArgumentException("The TerraScale region is not admitted.", nameof(value)),
    };
}

internal sealed record OciWorkloadOperationRecord(
    int SchemaVersion,
    string Workload,
    string Action,
    string IdempotencyKey,
    string InstanceId,
    string WorkRequestId,
    DateTimeOffset StartedAt,
    string State = "requested",
    string? Error = null)
{
    internal const int CurrentSchemaVersion = 1;
}

[JsonSerializable(typeof(OciWorkloadOperationRecord))]
internal sealed partial class OciWorkloadReplicaJsonContext : JsonSerializerContext;

/// <summary>
/// OCI-backed independent replica driver.  Every workload has its own tags,
/// idempotency key, launch template, and policy state; an auth decision can never
/// create or retire a TerraBase instance.  The operation record is written before
/// returning from a provider call so a lost response is recovered by observation.
/// </summary>
internal sealed class OciWorkloadReplicaDriver : IWorkloadReplicaDriver, IDisposable
{
    private const int MaximumObservedInstances = 256;
    private const int MaximumOperationRecords = 64;
    private static readonly TimeSpan OperationRecoveryWindow = TimeSpan.FromHours(24);
    private readonly IOciCiRunnerComputeTransport transport;
    private readonly OciWorkloadFleetConfigurationFile configuration;
    private readonly INatsKVStore runtimeStore;
    private readonly Func<string, Task<int>> desiredReplicas;
    private readonly Func<bool> authorityStillValid;
    private readonly string cell;
    private readonly Dictionary<string, IReadOnlyList<ObservedWorkloadInstance>> last = new(StringComparer.Ordinal);

    internal OciWorkloadReplicaDriver(
        IOciCiRunnerComputeTransport transport,
        OciWorkloadFleetConfigurationFile configuration,
        INatsKVStore runtimeStore,
        Func<string, Task<int>> desiredReplicas,
        Func<bool> authorityStillValid,
        string cell)
    {
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.runtimeStore = runtimeStore ?? throw new ArgumentNullException(nameof(runtimeStore));
        this.desiredReplicas = desiredReplicas ?? throw new ArgumentNullException(nameof(desiredReplicas));
        this.authorityStillValid = authorityStillValid ?? throw new ArgumentNullException(nameof(authorityStillValid));
        this.cell = cell is { Length: > 0 } ? cell : throw new ArgumentException("The workload fleet cell is required.", nameof(cell));
    }

    public async Task<WorkloadScaleObservation> ObserveAsync(
        WorkloadScalePolicy policy,
        CancellationToken cancellationToken)
    {
        var template = configuration.TemplateFor(policy);
        var instances = await ListOwnedAsync(template, policy, cancellationToken).ConfigureAwait(false);
        var observations = new List<ObservedWorkloadInstance>(instances.Count);
        foreach (var instance in instances)
        {
            var ready = await IsReadyAsync(instance.InstanceId, policy.WorkloadId, cancellationToken).ConfigureAwait(false);
            observations.Add(new(instance.InstanceId, instance.ETag, instance.State, instance.CreateKey, ready));
        }
        var snapshot = Array.AsReadOnly(observations.OrderBy(static value => value.InstanceId, StringComparer.Ordinal).ToArray());
        last[policy.WorkloadId] = snapshot;
        await ReconcileLatestScaleOutAsync(policy.WorkloadId, snapshot, cancellationToken).ConfigureAwait(false);
        var desired = Math.Clamp(await desiredReplicas(policy.WorkloadId).ConfigureAwait(false), policy.MinReplicas, policy.MaxReplicas);
        var readyCount = snapshot.Count(static value => value.Ready);
        var pending = snapshot.Count(static value => value.State is not (Instance.LifecycleStateEnum.Running or Instance.LifecycleStateEnum.Stopped));
        var healthy = readyCount >= policy.MinReplicas && pending == 0;
        return new WorkloadScaleObservation(policy.WorkloadId, desired, snapshot.Count, readyCount, pending, healthy);
    }

    public async Task ApplyAsync(WorkloadScaleDecision decision, CancellationToken cancellationToken)
    {
        if (decision.Action is not (WorkloadScaleAction.ScaleOut or WorkloadScaleAction.ScaleIn))
            return;
        if (!authorityStillValid())
            throw new InvalidOperationException("Workload scaling authority was lost before the OCI mutation.");
        var template = configuration.TemplateFor(new WorkloadScalePolicy(
            decision.WorkloadId,
            decision.RoleKind,
            Math.Max(1, decision.TargetReplicas),
            Math.Max(1, decision.TargetReplicas)));
        var current = last.TryGetValue(decision.WorkloadId, out var snapshot) ? snapshot : [];
        if (decision.Action == WorkloadScaleAction.ScaleOut)
        {
            var recovered = await ReadLatestScaleOutAsync(decision.WorkloadId, cancellationToken).ConfigureAwait(false);
            var key = recovered is { Record: var operation } && IsRecoverable(operation)
                ? operation.IdempotencyKey
                : IdempotencyKey(decision.WorkloadId, decision.TargetReplicas, current.Count + 1);
            var request = OciWorkloadRequestCompiler.Launch(template, decision.WorkloadId, decision.RoleKind, key, cell);
            if (!authorityStillValid())
                throw new InvalidOperationException("Workload scaling authority was lost before the OCI launch.");
            var operationKey = recovered is { Record: var recoveredOperation } &&
                               recoveredOperation.IdempotencyKey == key
                ? recovered.Key
                : OperationKey(decision.WorkloadId, key);
            await PersistOperationAsync(new(
                OciWorkloadOperationRecord.CurrentSchemaVersion,
                decision.WorkloadId,
                "scale-out",
                key,
                string.Empty,
                string.Empty,
                recovered?.Record.StartedAt ?? DateTimeOffset.UtcNow,
                "requested"), operationKey, cancellationToken).ConfigureAwait(false);
            Oci.CoreService.Responses.LaunchInstanceResponse launchResponse;
            try
            {
                launchResponse = await transport.LaunchInstanceAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                // The requested record and OCI retry token survive a lost response. The next
                // tick repeats the same token and reconciles the provider's eventual instance.
                throw;
            }
            var instance = launchResponse.Instance ?? throw new InvalidDataException("OCI returned no workload instance.");
            await PersistOperationAsync(new(
                OciWorkloadOperationRecord.CurrentSchemaVersion,
                decision.WorkloadId,
                "scale-out",
                key,
                instance.Id,
                launchResponse.OpcWorkRequestId ?? string.Empty,
                DateTimeOffset.UtcNow,
                "submitted"), operationKey, cancellationToken).ConfigureAwait(false);
            await VerifyWorkRequestAsync(launchResponse.OpcWorkRequestId, cancellationToken).ConfigureAwait(false);
            return;
        }

        var victim = current
            .Where(static value => value.Ready && value.State is Instance.LifecycleStateEnum.Running or Instance.LifecycleStateEnum.Stopped)
            .OrderByDescending(static value => value.InstanceId, StringComparer.Ordinal)
            .FirstOrDefault();
        if (victim is null)
            return;
        if (!authorityStillValid())
            throw new InvalidOperationException("Workload scaling authority was lost before the OCI termination.");
        var terminate = new TerminateInstanceRequest
        {
            InstanceId = victim.InstanceId,
            IfMatch = victim.ETag,
            PreserveBootVolume = false,
            PreserveDataVolumesCreatedAtLaunch = false,
        };
        Oci.CoreService.Responses.TerminateInstanceResponse response;
        try
        {
            response = await transport.TerminateInstanceAsync(terminate, cancellationToken).ConfigureAwait(false);
        }
        catch (OciException failure) when (failure.StatusCode == HttpStatusCode.NotFound)
        {
            response = new Oci.CoreService.Responses.TerminateInstanceResponse();
        }
        await PersistOperationAsync(new(
            OciWorkloadOperationRecord.CurrentSchemaVersion,
            decision.WorkloadId,
            "scale-in",
            $"terminate:{victim.InstanceId}",
            victim.InstanceId,
            response.OpcWorkRequestId ?? string.Empty,
            DateTimeOffset.UtcNow,
            "submitted"), OperationKey(decision.WorkloadId, $"terminate:{victim.InstanceId}"), cancellationToken)
            .ConfigureAwait(false);
        await VerifyWorkRequestAsync(response.OpcWorkRequestId, cancellationToken).ConfigureAwait(false);
        await PersistOperationAsync(new(
            OciWorkloadOperationRecord.CurrentSchemaVersion,
            decision.WorkloadId,
            "scale-in",
            $"terminate:{victim.InstanceId}",
            victim.InstanceId,
            response.OpcWorkRequestId ?? string.Empty,
            DateTimeOffset.UtcNow,
            "retired"), OperationKey(decision.WorkloadId, $"terminate:{victim.InstanceId}"), cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<IReadOnlyList<ObservedWorkloadInstance>> ListOwnedAsync(
        OciWorkloadTemplate template,
        WorkloadScalePolicy policy,
        CancellationToken cancellationToken)
    {
        var instances = new List<ObservedWorkloadInstance>();
        string? page = null;
        do
        {
            var response = await transport.ListInstancesAsync(new ListInstancesRequest
            {
                CompartmentId = template.LaunchTemplate.CompartmentId,
                AvailabilityDomain = template.LaunchTemplate.AvailabilityDomain,
                Limit = 100,
                Page = page,
                SortBy = ListInstancesRequest.SortByEnum.Timecreated,
                SortOrder = ListInstancesRequest.SortOrderEnum.Asc,
            }, cancellationToken).ConfigureAwait(false);
            foreach (var instance in response.Items ?? [])
            {
                if (!OciWorkloadRequestCompiler.Owned(instance, policy.WorkloadId, policy.RoleKind))
                    continue;
                var detail = await transport.GetInstanceAsync(new GetInstanceRequest { InstanceId = instance.Id }, cancellationToken)
                    .ConfigureAwait(false);
                if (detail.Instance is null)
                    continue;
                var etag = detail.Etag ?? string.Empty;
                OciWorkloadRequestCompiler.RequireLaunchTemplate(detail.Instance, template, etag);
                var createKey = detail.Instance.FreeformTags?.GetValueOrDefault(OciWorkloadRequestCompiler.CreateKeyTag) ?? string.Empty;
                instances.Add(new(detail.Instance.Id, etag, detail.Instance.LifecycleState, createKey, false));
                if (instances.Count > MaximumObservedInstances)
                    throw new InvalidDataException("The OCI workload observation exceeded its bound.");
            }
            page = response.OpcNextPage;
        }
        while (!string.IsNullOrEmpty(page));
        return instances;
    }

    private async Task<bool> IsReadyAsync(string instanceId, string workload, CancellationToken cancellationToken)
    {
        try
        {
            var entry = await runtimeStore.GetEntryAsync<string>(
                $"host.{instanceId}.{workload}", cancellationToken: cancellationToken).ConfigureAwait(false);
            entry.EnsureSuccess();
            var observation = JsonSerializer.Deserialize(
                entry.Value ?? string.Empty,
                HostConvergenceJsonContext.Default.HostConvergenceObservation);
            return observation is { State: "converged" } && observation.ObservedAt >= DateTimeOffset.UtcNow.AddMinutes(-10) &&
                (workload != "terrabase-server" || observation.MemberUp == true);
        }
        catch (Exception exception) when (exception is NatsKVException or JsonException or InvalidOperationException)
        {
            return false;
        }
    }

    private async Task PersistOperationAsync(
        OciWorkloadOperationRecord record,
        string key,
        CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(record, OciWorkloadReplicaJsonContext.Default.OciWorkloadOperationRecord);
        await runtimeStore.PutAsync(key, json, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    private async Task ReconcileLatestScaleOutAsync(
        string workload,
        IReadOnlyList<ObservedWorkloadInstance> snapshot,
        CancellationToken cancellationToken)
    {
        var latest = await ReadLatestScaleOutAsync(workload, cancellationToken).ConfigureAwait(false);
        if (latest is not { Record: var record } || !IsRecoverable(record))
            return;

        var match = snapshot.FirstOrDefault(instance =>
            instance.InstanceId == record.InstanceId ||
            instance.CreateKey == record.IdempotencyKey);
        if (match is null)
            return;

        var nextState = match.Ready ? "converged" : "observed";
        if (record.State == nextState && record.InstanceId == match.InstanceId)
            return;
        await PersistOperationAsync(
            record with
            {
                InstanceId = match.InstanceId,
                State = nextState,
                Error = null
            },
            latest.Key,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<OperationEntry?> ReadLatestScaleOutAsync(
        string workload,
        CancellationToken cancellationToken)
    {
        var prefix = $"workload.operation.{workload}.";
        var records = new List<OperationEntry>();
        try
        {
            await foreach (var key in runtimeStore.GetKeysAsync(
                               [$"{prefix}>"],
                               new NatsKVWatchOpts { IgnoreDeletes = true },
                               cancellationToken).ConfigureAwait(false))
            {
                if (!key.StartsWith(prefix, StringComparison.Ordinal))
                    continue;
                if (records.Count >= MaximumOperationRecords)
                    throw new InvalidDataException("The OCI workload operation journal exceeded its bound.");
                NatsKVEntry<string> entry;
                try
                {
                    entry = await runtimeStore.GetEntryAsync<string>(key, cancellationToken: cancellationToken)
                        .ConfigureAwait(false);
                    entry.EnsureSuccess();
                }
                catch (NatsKVKeyNotFoundException)
                {
                    continue;
                }
                var record = JsonSerializer.Deserialize(
                    entry.Value ?? string.Empty,
                    OciWorkloadReplicaJsonContext.Default.OciWorkloadOperationRecord);
                if (record is not null && record.Action == "scale-out" && record.Workload == workload)
                    records.Add(new(key, record));
            }
        }
        catch (NotSupportedException)
        {
            // Minimal provider seams used by unit tests may only implement PutAsync.
            // Production NATS KV stores always expose key enumeration.
            return null;
        }

        return records
            .Where(static entry => entry.Record.StartedAt != default)
            .OrderByDescending(static entry => entry.Record.StartedAt)
            .FirstOrDefault();
    }

    private static bool IsRecoverable(OciWorkloadOperationRecord record) =>
        record.State is "requested" or "submitted" or "observed" &&
        record.StartedAt <= DateTimeOffset.UtcNow &&
        DateTimeOffset.UtcNow - record.StartedAt <= OperationRecoveryWindow;

    private async Task VerifyWorkRequestAsync(string? workRequestId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(workRequestId) ||
            transport is not IOciWorkRequestTransport workRequests)
            return;
        var response = await workRequests.GetWorkRequestAsync(workRequestId, cancellationToken).ConfigureAwait(false);
        var status = response.WorkRequest?.Status;
        if (status is Oci.WorkrequestsService.Models.WorkRequest.StatusEnum.Failed or
            Oci.WorkrequestsService.Models.WorkRequest.StatusEnum.Canceled)
            throw new InvalidOperationException($"OCI workload work request {status}.");
    }

    private static string OperationKey(string workload, string idempotencyKey) =>
        $"workload.operation.{workload}.{idempotencyKey.Replace(':', '-')}";

    private static string IdempotencyKey(string workload, int target, int ordinal) =>
        $"workload-{Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(workload)))[..16]}-{target.ToString(CultureInfo.InvariantCulture)}-{ordinal.ToString(CultureInfo.InvariantCulture)}";

    public void Dispose() => transport.Dispose();

    private sealed record ObservedWorkloadInstance(
        string InstanceId,
        string ETag,
        Instance.LifecycleStateEnum? State,
        string CreateKey,
        bool Ready);

    private sealed record OperationEntry(string Key, OciWorkloadOperationRecord Record);
}

internal static class OciWorkloadFleetComposition
{
    internal static void Validate(bool terraBasePlacementConfigured, OciWorkloadFleetConfigurationFile? workloadFleet)
    {
        if (workloadFleet is null)
        {
            if (terraBasePlacementConfigured)
                throw new InvalidOperationException(
                    "The stateful TerraBase placement fleet requires TS_ORCH_WORKLOAD_FLEET_FILE " +
                    "to provide the independent ts-auth scaling policy.");
            return;
        }
        var ownsTerraBase = workloadFleet.Workloads.ContainsKey("terrabase-server");
        if (terraBasePlacementConfigured && ownsTerraBase)
            throw new InvalidOperationException(
                "TerraBase capacity has two OCI owners. Remove terrabase-server from TS_ORCH_WORKLOAD_FLEET_FILE " +
                "when TS_ORCH_TERRABASE_RECONCILER is configured; the placement member fleet is the sole stateful scaler.");
        if (!terraBasePlacementConfigured && !ownsTerraBase)
            throw new InvalidOperationException(
                "The generic OCI workload fleet must define both ts-auth and terrabase-server policies " +
                "when TS_ORCH_TERRABASE_RECONCILER is not configured.");
    }
}

internal static class OciWorkloadRequestCompiler
{
    internal const string OwnerTag = "terrascale-owner";
    internal const string RoleTag = "terrascale-role";
    internal const string WorkloadTag = "terrascale-workload";
    internal const string CellTag = "terrascale-cell";
    internal const string BootstrapTag = "terrascale-bootstrap-sha256";
    internal const string CreateKeyTag = "terrascale-create-key";

    internal static LaunchInstanceRequest Launch(
        OciWorkloadTemplate template,
        string workload,
        string role,
        string createKey,
        string cell)
    {
        var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{cell}:{workload}:{createKey}")))[..16];
        return new LaunchInstanceRequest
        {
            OpcRetryToken = createKey,
            LaunchInstanceDetails = new LaunchInstanceDetails
            {
                AvailabilityDomain = template.LaunchTemplate.AvailabilityDomain,
                FaultDomain = template.LaunchTemplate.FaultDomain,
                CompartmentId = template.LaunchTemplate.CompartmentId,
                DisplayName = $"terrascale-{workload}-{hash}",
                HostnameLabel = $"ts-{hash}",
                Shape = OciCiRunnerRequestCompiler.Shape,
                ShapeConfig = new LaunchInstanceShapeConfigDetails
                {
                    Ocpus = OciCiRunnerRequestCompiler.Ocpus,
                    MemoryInGBs = OciCiRunnerRequestCompiler.MemoryInGbs,
                },
                SourceDetails = new InstanceSourceViaImageDetails
                {
                    ImageId = template.LaunchTemplate.ImageId,
                    BootVolumeSizeInGBs = 50,
                    BootVolumeVpusPerGB = 10,
                },
                CreateVnicDetails = new CreateVnicDetails
                {
                    SubnetId = template.LaunchTemplate.SubnetId,
                    NsgIds = template.LaunchTemplate.NetworkSecurityGroupIds.ToList(),
                    AssignPublicIp = false,
                    AssignIpv6Ip = false,
                    AssignPrivateDnsRecord = false,
                },
                Metadata = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["user_data"] = template.BootstrapBase64,
                },
                FreeformTags = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [OwnerTag] = "orchestrator",
                    [RoleTag] = role,
                    [WorkloadTag] = workload,
                    [CellTag] = cell,
                    [BootstrapTag] = template.BootstrapSha256,
                    [CreateKeyTag] = createKey,
                },
                IsPvEncryptionInTransitEnabled = true,
            }
        };
    }

    internal static bool Owned(Instance instance, string workload, string role) =>
        instance.FreeformTags is { } tags &&
        tags.TryGetValue(OwnerTag, out var owner) && owner == "orchestrator" &&
        tags.TryGetValue(RoleTag, out var actualRole) && actualRole == role &&
        tags.TryGetValue(WorkloadTag, out var actualWorkload) && actualWorkload == workload;

    internal static void RequireLaunchTemplate(
        Instance instance,
        OciWorkloadTemplate template,
        string etag)
    {
        if (string.IsNullOrWhiteSpace(etag) || instance.CompartmentId != template.LaunchTemplate.CompartmentId ||
            instance.AvailabilityDomain != template.LaunchTemplate.AvailabilityDomain ||
            instance.FaultDomain != template.LaunchTemplate.FaultDomain ||
            instance.Shape != OciCiRunnerRequestCompiler.Shape ||
            instance.ShapeConfig?.Ocpus != OciCiRunnerRequestCompiler.Ocpus ||
            instance.ShapeConfig.MemoryInGBs != OciCiRunnerRequestCompiler.MemoryInGbs ||
            instance.ImageId != template.LaunchTemplate.ImageId ||
            instance.SourceDetails is not InstanceSourceViaImageDetails source || source.ImageId != template.LaunchTemplate.ImageId ||
            instance.Metadata is not { Count: 1 } metadata || !metadata.TryGetValue("user_data", out var encoded) ||
            encoded != template.BootstrapBase64 || instance.FreeformTags is not { } tags ||
            !tags.TryGetValue(BootstrapTag, out var bootstrap) || bootstrap != template.BootstrapSha256)
            throw new InvalidDataException("An OCI workload instance does not match its exact launch template.");
    }
}

/// <summary>SDK transport factory shared by the workload and member fleets.</summary>
internal static class OciWorkloadComputeTransport
{
    internal static IOciCiRunnerComputeTransport CreateForInstancePrincipal(string endpoint)
    {
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.UserInfo) || uri.AbsolutePath != "/" || !string.IsNullOrEmpty(uri.Query) ||
            !uri.Host.StartsWith("iaas.", StringComparison.Ordinal) || !uri.Host.EndsWith(".oraclecloud.com", StringComparison.Ordinal))
            throw new ArgumentException("The OCI Compute endpoint is invalid.", nameof(endpoint));
        var provider = new InstancePrincipalsAuthenticationDetailsProvider();
        var clientConfiguration = new ClientConfiguration { TimeoutMillis = 30_000 };
        var endpointUri = uri.ToString().TrimEnd('/');
        var compute = new ComputeClient(provider, clientConfiguration, endpointUri);
        try
        {
            return new OciCiRunnerSdkTransport(
                compute,
                new VirtualNetworkClient(provider, clientConfiguration, endpointUri),
                new Oci.WorkrequestsService.WorkRequestClient(provider, clientConfiguration, endpointUri));
        }
        catch
        {
            compute.Dispose();
            throw;
        }
    }
}
