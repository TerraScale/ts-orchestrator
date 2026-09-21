using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Runtime;
using HostArchitecture = TerraScale.Orchestrator.Runtime.HostArchitecture;
using HostRole = TerraScale.Orchestrator.Runtime.AdmittedRole;
using HostRuntimePlan = TerraScale.Orchestrator.Runtime.HostRuntimePlan;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>
/// Which admitted roles this host process converges from durable desired state, and where the
/// immutable digest-addressed artifacts live.
/// </summary>
public sealed record HostConvergenceConfiguration(
    IReadOnlyList<HostRole> Roles,
    string Environment,
    string InstallRoot,
    HostArchitecture Architecture,
    string? EnvironmentDirectory = null,
    string? StateDirectoryRoot = null,
    string? MemberObservabilityUrl = null,
    string? ContainerdCliPath = null)
{
    public const string DefaultInstallRoot = "/opt/terrascale/artifacts";
    public const string DefaultStateDirectoryRoot = "/var/lib";

    internal static HostConvergenceConfiguration Parse(
        IReadOnlyList<string> roleNames,
        string? environment,
        string? installRoot,
        string? environmentDirectory = null,
        string? stateDirectoryRoot = null,
        HostArchitecture? architecture = null,
        string? memberObservabilityUrl = null,
        string? containerdCliPath = null) => new(
        roleNames.Select(HostRuntimeCli.ParseRole).ToArray(),
        environment is { Length: > 0 } ? environment : "production",
        string.IsNullOrWhiteSpace(installRoot) ? DefaultInstallRoot : installRoot,
        architecture ?? DetectArchitecture(),
        string.IsNullOrWhiteSpace(environmentDirectory) ? null : environmentDirectory,
        string.IsNullOrWhiteSpace(stateDirectoryRoot) ? DefaultStateDirectoryRoot : stateDirectoryRoot,
        string.IsNullOrWhiteSpace(memberObservabilityUrl) ? null : memberObservabilityUrl,
        string.IsNullOrWhiteSpace(containerdCliPath) ? null : containerdCliPath);

    internal static HostArchitecture DetectArchitecture() =>
        System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture switch
        {
            System.Runtime.InteropServices.Architecture.Arm64 => HostArchitecture.Arm64,
            _ => HostArchitecture.X64
        };
}

/// <summary>
/// The durable per-host convergence report other controllers and operators read. Published to
/// <c>ORCH_RUNTIME</c> under <c>host.{instance}.{artifactKey}</c> after every reconcile pass.
/// Schema 2 adds the member-health gauges of the hosted TerraBase member (liveness,
/// replication lag in sequences, role, replica acknowledgements); schema-1 documents
/// carry them absent and stay valid — readers tolerate both.
/// </summary>
internal sealed record HostConvergenceObservation(
    int SchemaVersion,
    string Cell,
    string Instance,
    string ArtifactKey,
    string Digest,
    string State,
    string? UnitName,
    DateTimeOffset ObservedAt,
    string? Error = null,
    bool? MemberUp = null,
    long? MemberReplicationLagSequences = null,
    string? MemberRole = null,
    int? MemberPeerAckCount = null,
    int? MemberMinReplicas = null)
{
    public const int CurrentSchemaVersion = 2;
    public const int MemberHealthSchemaVersion = 2;

    public void Validate()
    {
        if (SchemaVersion is not (1 or CurrentSchemaVersion) ||
            string.IsNullOrWhiteSpace(Cell) || string.IsNullOrWhiteSpace(Instance) ||
            string.IsNullOrWhiteSpace(ArtifactKey) ||
            Digest is not { Length: 71 } || !Digest.StartsWith("sha256:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(State) ||
            ObservedAt == default ||
            (SchemaVersion < MemberHealthSchemaVersion &&
                (MemberUp is not null || MemberReplicationLagSequences is not null ||
                 MemberRole is not null || MemberPeerAckCount is not null || MemberMinReplicas is not null)) ||
            MemberReplicationLagSequences is < 0 || MemberPeerAckCount is < 0 || MemberMinReplicas is < 1)
            throw new InvalidOperationException("The host convergence observation is invalid.");
    }
}

/// <summary>
/// The replace lease that serializes host replacements of one replicated stateful service
/// inside a cell. Acquired by compare-and-set, released by the owner; an expired lease may be
/// taken over so a crashed host cannot block the service forever.
/// </summary>
internal sealed record HostConvergenceReplaceLease(
    string Holder,
    DateTimeOffset ExpiresAt);

/// <summary>
/// The durable per-host, per-service retry backoff after one failed converge-and-rollback
/// cycle: a desired digest whose replacement keeps failing must not stop and restore the
/// healthy previous unit on every 5-second pass. Keyed <c>host.backoff.{instance}.{key}</c>
/// in <c>ORCH_RUNTIME</c>, so it survives process restarts; a cycle that converges clears it.
/// </summary>
internal sealed record HostConvergenceBackoff(
    string Digest,
    int Failures,
    DateTimeOffset NotBefore);

[JsonSerializable(typeof(HostConvergenceObservation))]
[JsonSerializable(typeof(HostConvergenceReplaceLease))]
[JsonSerializable(typeof(HostConvergenceBackoff))]
internal sealed partial class HostConvergenceJsonContext : JsonSerializerContext;

/// <summary>Copies immutable digest-addressed artifacts into a destination stream.</summary>
internal interface IHostArtifactSource
{
    Task CopyIntoAsync(string objectName, Stream destination, CancellationToken cancellationToken);
}

/// <summary>Converges and observes one admitted host runtime plan.</summary>
internal interface IHostRuntimeConverger
{
    Task ConvergeAsync(HostRuntimePlan plan, CancellationToken cancellationToken);
    Task StopAsync(HostRuntimePlan plan, CancellationToken cancellationToken);
    Task<SystemdAllocationObservation> ObserveAsync(HostRuntimePlan plan, CancellationToken cancellationToken);
}

/// <summary>
/// First-boot admission gate for a regional host. A host may read desired state
/// before admission, but it must not install, start, or consume a workload until
/// the signed regional enrollment and credential delivery have both completed.
/// </summary>
internal interface IHostAdmissionGate
{
    ValueTask<HostAdmissionSnapshot> ObserveAsync(CancellationToken cancellationToken);
}

internal sealed record HostAdmissionSnapshot(
    bool Authorized,
    bool MaterialReady,
    string Reason)
{
    internal bool Ready => Authorized && MaterialReady;
}

/// <summary>The one admitted host action a reconcile pass decided on.</summary>
internal enum HostConvergenceOutcomeState
{
    Converged = 1,
    RolledBack = 2,
    Failed = 3,
    RollbackFailed = 4
}

/// <summary>
/// Leaderless host convergence (Anna-style): each host converges itself from the durable,
/// already-admitted desired digest in <c>ORCH_DELIVERY</c> — admission stays fenced behind the
/// regional authority, but serving the admitted state needs no leader, so deploys keep flowing
/// while leadership churns. Artifacts are immutable digest-addressed files fetched from the
/// <c>ORCH_ARTIFACTS</c> NATS object store, so every host independently arrives at the same
/// bytes. Replicated stateful roles (minimum replicas above one) serialize their replacements
/// through an expiring KV lease so a cell never replaces two members at once.
/// </summary>
internal sealed class HostConvergenceRuntime : IAsyncDisposable
{
    private static readonly TimeSpan ReconcileInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan DefaultReplaceLeaseDuration = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan FailedCycleBackoffBase = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan FailedCycleBackoffMaximum = TimeSpan.FromMinutes(15);
    private const int MaximumConvergeAttempts = 3;

    /// <summary>How long a readiness poll waits before re-observing a starting unit. Tests shrink it.</summary>
    internal TimeSpan ObservationPollInterval { get; set; } = TimeSpan.FromSeconds(2);

    private readonly INatsKVStore delivery;
    private readonly INatsKVStore runtimeStore;
    private readonly IHostObservationPublisher reports;
    private readonly IHostArtifactSource artifacts;
    private readonly IHostRuntimeConverger converger;
    private readonly HostConvergenceConfiguration configuration;
    private readonly TerraScale.Orchestrator.Nodes.IMemberHealthSource? memberHealth;
    private readonly string cell;
    private readonly string instance;
    private readonly TimeSpan observationTimeout;
    private readonly TimeSpan replaceLeaseDuration;
    private readonly TimeSpan replaceLeaseRenewalInterval;
    private readonly IHostAdmissionGate? admission;
    private readonly CancellationTokenSource stopping = new();
    private readonly List<Task> loops = [];

    private HostConvergenceRuntime(
        INatsKVStore delivery,
        INatsKVStore runtimeStore,
        IHostObservationPublisher reports,
        IHostArtifactSource artifacts,
        IHostRuntimeConverger converger,
        HostConvergenceConfiguration configuration,
        string cell,
        string instance,
        TimeSpan? observationTimeout = null,
        TimeSpan? replaceLeaseDuration = null,
        IHostAdmissionGate? admission = null)
    {
        this.observationTimeout = observationTimeout ?? TimeSpan.FromSeconds(90);
        this.replaceLeaseDuration = replaceLeaseDuration ?? DefaultReplaceLeaseDuration;
        replaceLeaseRenewalInterval = this.replaceLeaseDuration / 3;
        this.admission = admission;
        this.delivery = delivery;
        this.runtimeStore = runtimeStore;
        this.reports = reports ?? throw new ArgumentNullException(nameof(reports));
        this.artifacts = artifacts;
        this.converger = converger;
        this.configuration = configuration;
        memberHealth = configuration.MemberObservabilityUrl is { } url
            ? new TerraScale.Orchestrator.Nodes.MemberHealthHttpSource(url)
            : null;
        this.cell = cell;
        this.instance = instance;
    }

    /// <summary>Constructs the runtime without starting any background loops; tests drive reconcile passes directly.</summary>
    internal static HostConvergenceRuntime Create(
        INatsKVStore delivery,
        INatsKVStore runtimeStore,
        IHostObservationPublisher reports,
        IHostArtifactSource artifacts,
        IHostRuntimeConverger converger,
        HostConvergenceConfiguration configuration,
        string cell,
        string instance,
        TimeSpan? observationTimeout = null,
        TimeSpan? replaceLeaseDuration = null,
        IHostAdmissionGate? admission = null) =>
        new(delivery, runtimeStore, reports, artifacts, converger, configuration, cell, instance,
            observationTimeout, replaceLeaseDuration, admission);

    /// <summary>Starts one reconcile loop per configured role. The loops never throw: failures are reported as observations.</summary>
    internal static HostConvergenceRuntime Start(
        INatsKVStore delivery,
        INatsKVStore runtimeStore,
        IHostObservationPublisher reports,
        IHostArtifactSource artifacts,
        IHostRuntimeConverger converger,
        HostConvergenceConfiguration configuration,
        string cell,
        string instance,
        TimeSpan? observationTimeout = null,
        TimeSpan? replaceLeaseDuration = null,
        IHostAdmissionGate? admission = null)
    {
        var runtimeLoop = Create(
            delivery, runtimeStore, reports, artifacts, converger, configuration, cell, instance,
            observationTimeout, replaceLeaseDuration, admission);
        runtimeLoop.loops.AddRange(configuration.Roles.Select(
            role => Task.Run(() => runtimeLoop.ReconcileLoopAsync(role, runtimeLoop.stopping.Token))));
        return runtimeLoop;
    }

    public async ValueTask DisposeAsync()
    {
        stopping.Cancel();
        try
        {
            await Task.WhenAll(loops.ToArray()).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        stopping.Dispose();
    }

    private async Task ReconcileLoopAsync(HostRole role, CancellationToken cancellationToken)
    {
        var descriptor = AdmittedRoleCatalog.Get(role);
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await ReconcileOnceAsync(role, descriptor, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                // A transient ledger or store failure must not kill the loop; the next pass
                // retries — but never silently: a persistently failing pass stays observable.
                Console.Error.WriteLine(
                    $"Host convergence pass for {role} failed ({exception.GetType().Name}); retrying next pass.");
            }
            try
            {
                await Task.Delay(ReconcileInterval, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
        }
    }

    /// <summary>One reconcile pass: read desired, install, converge, observe, report.</summary>
    internal async Task ReconcileOnceAsync(
        HostRole role,
        AdmittedRoleDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        var desired = await ReadDesiredDigestAsync(descriptor, cancellationToken).ConfigureAwait(false);
        if (desired is null)
        {
            // No admitted desired state for this service yet: nothing to converge, and never
            // an excuse to touch a running allocation.
            return;
        }
        if (admission is not null)
        {
            var gate = await admission.ObserveAsync(cancellationToken).ConfigureAwait(false);
            // An admitted agent can receive its retained volume before the member
            // starts. Publish enrollment independently of service convergence, and
            // overwrite a former ready report when credentials/admission are lost.
            await reports.PublishAsync(new HostAdmissionObservation(
                HostAdmissionObservation.CurrentSchemaVersion, cell, instance, configuration.Environment,
                descriptor.ArtifactKey, desired, gate.Ready, DateTimeOffset.UtcNow), cancellationToken).ConfigureAwait(false);
            if (!gate.Ready)
            {
                await ReportAsync(
                    descriptor,
                    desired,
                    new ConvergeOutcome(
                        HostConvergenceOutcomeState.Failed,
                        null,
                        gate.Reason is { Length: > 128 } ? gate.Reason[..128] : gate.Reason),
                    cancellationToken,
                    state: "blocked-admission").ConfigureAwait(false);
                return;
            }
        }
        var current = await ReadCurrentMarkerAsync(descriptor, cancellationToken).ConfigureAwait(false);
        if (current is { Digest: { } currentDigest } &&
            string.Equals(currentDigest, desired, StringComparison.Ordinal) &&
            await IsServingAsync(role, descriptor, desired, cancellationToken).ConfigureAwait(false))
        {
            // ORCH_RUNTIME observations expire independently of the local marker.
            // Refresh the durable observation on every loop so operator status and
            // readiness never report a healthy host from a stale five-minute record.
            await ReportAsync(
                descriptor,
                desired,
                new ConvergeOutcome(HostConvergenceOutcomeState.Converged, null),
                cancellationToken).ConfigureAwait(false);
            return;
        }

        if (await BackedOffAsync(descriptor, desired, cancellationToken).ConfigureAwait(false))
            return; // A previously failed cycle for this digest is still in backoff.

        await using var lease = descriptor.MinimumReplicas > 1
            ? await AcquireReplaceLeaseAsync(descriptor, cancellationToken).ConfigureAwait(false)
            : null;
        if (descriptor.MinimumReplicas > 1 && lease is null)
            return; // Another host is replacing its member right now; retry next pass.

        // The lease renews itself while this pass works and aborts it through the work token
        // the moment the lease is lost, so two hosts never replace members of one service
        // concurrently — not even when the work outlives a single lease duration.
        var work = lease?.Token ?? cancellationToken;
        var previous = current?.Digest;
        if (previous is { } previousDigest &&
            !string.Equals(previousDigest, desired, StringComparison.Ordinal))
        {
            // A runtime allocation is tied to its role identity, so an OCI
            // replacement must first stop and remove the allocation created for
            // the previous digest. The converger performs its own ownership fence.
            var previousPlan = PlanFor(role, descriptor, HexOf(previousDigest));
            await converger.StopAsync(previousPlan, work).ConfigureAwait(false);
        }
        var outcome = await InstallConvergeAndObserveAsync(role, descriptor, desired, work)
            .ConfigureAwait(false);
        if (outcome.State == HostConvergenceOutcomeState.Converged)
        {
            // Report before the marker: a failed report must not leave every later pass
            // early-returning on a stale observation; the next pass re-converges and
            // re-reports instead.
            await ReportAsync(descriptor, desired, outcome, cancellationToken).ConfigureAwait(false);
            await WriteCurrentMarkerAsync(descriptor, desired, previous, cancellationToken).ConfigureAwait(false);
            await ClearBackoffAsync(descriptor, cancellationToken).ConfigureAwait(false);
            return;
        }

        // The new version failed its post-converge observation: restore the exact previous
        // digest (artifact directories are immutable and never deleted, so it is still on
        // disk). A first deployment has nothing to restore.
        if (previous is { } rollbackDigest)
        {
            var rollback = await InstallConvergeAndObserveAsync(role, descriptor, rollbackDigest, work)
                .ConfigureAwait(false);
            if (rollback.State == HostConvergenceOutcomeState.Converged)
            {
                // Only a successfully restored previous digest is rolled-back truth: report
                // it and move the marker. A failed restore keeps the old marker (the next
                // pass retries from it) and reports rollback-failed against the desired
                // digest instead — never a rolled-back claim over a dead unit.
                await ReportAsync(
                    descriptor,
                    rollbackDigest,
                    rollback with { State = HostConvergenceOutcomeState.RolledBack },
                    cancellationToken).ConfigureAwait(false);
                await WriteCurrentMarkerAsync(descriptor, rollbackDigest, previous: null, cancellationToken)
                    .ConfigureAwait(false);
                await RecordFailedCycleAsync(descriptor, desired, cancellationToken).ConfigureAwait(false);
                return;
            }
            await ReportAsync(
                descriptor,
                desired,
                rollback with { State = HostConvergenceOutcomeState.RollbackFailed },
                cancellationToken).ConfigureAwait(false);
            await RecordFailedCycleAsync(descriptor, desired, cancellationToken).ConfigureAwait(false);
            return;
        }
        await ReportAsync(descriptor, desired, outcome, cancellationToken).ConfigureAwait(false);
        await RecordFailedCycleAsync(descriptor, desired, cancellationToken).ConfigureAwait(false);
    }

    internal sealed record ConvergeOutcome(
        HostConvergenceOutcomeState State,
        string? UnitName,
        string? Error = null);

    private async Task<ConvergeOutcome> InstallConvergeAndObserveAsync(
        HostRole role,
        AdmittedRoleDescriptor descriptor,
        string desiredDigest,
        CancellationToken cancellationToken)
    {
        try
        {
            var hex = HexOf(desiredDigest);
            var plan = PlanFor(role, descriptor, hex);
            // Native artifacts are copied into the immutable executable layout. OCI roles are
            // pulled by the composed containerd client from their digest-addressed image and
            // never materialized as host files.
            if (plan.Driver == RuntimeDriver.NativeSystemd)
            {
                var executable = plan.Systemd!.Executable;
                if (!File.Exists(executable))
                    await InstallArtifactAsync(descriptor, hex, executable, cancellationToken).ConfigureAwait(false);
            }
            InstallEnvironmentFile(plan);
            for (var attempt = 1; attempt <= MaximumConvergeAttempts; attempt++)
            {
                // A transient unit's ExecStart is fixed at creation: replacing a binary REQUIRES
                // stopping the old unit first (a stopped transient unit disappears, so the
                // converge below recreates it bound to the new digest's executable). Without
                // this, an upgrade would silently keep running — or restart — the old binary.
                await converger.StopAsync(plan, cancellationToken).ConfigureAwait(false);
                await converger.ConvergeAsync(plan, cancellationToken).ConfigureAwait(false);
                var deadline = DateTimeOffset.UtcNow + observationTimeout;
                while (DateTimeOffset.UtcNow < deadline)
                {
                    var observation = await converger.ObserveAsync(plan, cancellationToken).ConfigureAwait(false);
                    // Readiness gate: only an active unit with a live main process serves.
                    // 'activating' — including systemd auto-restart after a crash — is NOT
                    // serving: keep polling, and let the attempt fail (and the pass roll
                    // back) if the unit never comes up within the budget.
                    if (observation.State == SystemdAllocationState.Running &&
                        observation.MainProcessId is not null)
                        return new(HostConvergenceOutcomeState.Converged, observation.UnitName, null);
                    if (observation.State is not (SystemdAllocationState.Failed or SystemdAllocationState.Starting))
                        break;
                    await Task.Delay(ObservationPollInterval, cancellationToken).ConfigureAwait(false);
                }
            }
            return new(
                HostConvergenceOutcomeState.Failed,
                plan.Systemd?.UnitName,
                "The replaced runtime did not reach a running observation.");
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return new(HostConvergenceOutcomeState.Failed, null, exception.GetType().Name);
        }
    }

    private HostRuntimePlan PlanFor(HostRole role, AdmittedRoleDescriptor descriptor, string hex) =>
        HostRuntimePlan.Create(
            role,
            descriptor.DefaultDriver,
            AllocationIdFor(cell, instance, descriptor.ArtifactKey),
            new(hex),
            configuration.Architecture,
            installRoot: configuration.InstallRoot,
            stateRoot: configuration.StateDirectoryRoot);

    internal static RuntimeAllocationId AllocationIdFor(string cell, string instance, string artifactKey)
    {
        // Keep provider identity in enrollment/report bodies. Allocation names are
        // fixed DNS tokens and must not embed long, dotted OCI OCIDs. Length framing
        // preserves field boundaries; the same node/role remains stable across upgrades.
        var identity = $"{cell.Length}:{cell}{instance.Length}:{instance}{artifactKey.Length}:{artifactKey}";
        return new("host-" + Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(identity)))[..48]);
    }

    /// <summary>Fetches the artifact from the object store and installs it under its digest path after verifying the hash.</summary>
    private async Task InstallArtifactAsync(
        AdmittedRoleDescriptor descriptor,
        string hex,
        string executable,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(executable)
            ?? throw new InvalidOperationException("The artifact install path has no directory.");
        Directory.CreateDirectory(directory);
        var partial = Path.Combine(directory, $".partial-{Guid.NewGuid():N}");
        try
        {
            await using var target = File.Create(partial);
            var hashing = new HashingWriteStream(target);
            try
            {
                await artifacts.CopyIntoAsync($"sha256-{hex}", hashing, cancellationToken).ConfigureAwait(false);
            }
            catch (NatsObjNotFoundException)
            {
                throw new InvalidOperationException(
                    $"The artifact sha256-{hex[..12]} for {descriptor.ArtifactKey} is not in the artifact store.");
            }
            await hashing.FlushAsync(cancellationToken).ConfigureAwait(false);
            await target.FlushAsync(cancellationToken).ConfigureAwait(false);
            if (!hashing.Matches(hex))
                throw new InvalidOperationException(
                    $"The artifact sha256-{hex[..12]} for {descriptor.ArtifactKey} failed its content digest check.");
            if (OperatingSystem.IsLinux())
                File.SetUnixFileMode(partial,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                    UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                    UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
            File.Move(partial, executable);
        }
        finally
        {
            if (File.Exists(partial))
                File.Delete(partial);
        }
    }

    /// <summary>
    /// Copies the configured per-role environment file ({EnvironmentDirectory}/{artifactKey}.env)
    /// to the exact path the unit's EnvironmentFile property names. Without it a converged
    /// member starts with no TERRABASE_* configuration. Absent source or property is a no-op.
    /// </summary>
    private void InstallEnvironmentFile(HostRuntimePlan plan)
    {
        if (configuration.EnvironmentDirectory is not { } directory)
            return;
        var source = Path.Combine(directory, $"{AdmittedRoleCatalog.Get(plan.Role).ArtifactKey}.env");
        if (!File.Exists(source))
            return;
        var property = plan.Systemd?.Properties.FirstOrDefault(static value =>
            value.StartsWith("EnvironmentFile=-", StringComparison.Ordinal));
        if (property is null)
            return;
        var target = property["EnvironmentFile=-".Length..];
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        File.Copy(source, target, overwrite: true);
    }

    /// <summary>Stream wrapper that hashes while copying and compares against the expected hex digest once finalized.</summary>
    internal sealed class HashingWriteStream(Stream destination) : Stream
    {
        private readonly SHA256 hash = SHA256.Create();
        private bool finalized;

        internal bool Matches(string expectedHex) =>
            Convert.ToHexStringLower(GetHash()).Equals(expectedHex, StringComparison.OrdinalIgnoreCase);

        private byte[] GetHash()
        {
            if (!finalized)
            {
                hash.TransformFinalBlock([], 0, 0);
                finalized = true;
            }
            return hash.Hash ?? [];
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            hash.TransformBlock(buffer, offset, count, null, 0);
            destination.Write(buffer, offset, count);
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var array = buffer.ToArray();
            hash.TransformBlock(array, 0, array.Length, null, 0);
            await destination.WriteAsync(buffer, cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                GetHash();
                hash.Dispose();
                destination.Dispose();
            }
            base.Dispose(disposing);
        }

        public override void Flush() => destination.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => destination.SetLength(value);
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => destination.Length;
        public override long Position { get => destination.Position; set => destination.Position = value; }
    }

    /// <summary>True when the admitted unit for this role is already running (leaderless read of the local host).</summary>
    private async Task<bool> IsServingAsync(
        HostRole role,
        AdmittedRoleDescriptor descriptor,
        string desiredDigest,
        CancellationToken cancellationToken)
    {
        try
        {
            var plan = PlanFor(role, descriptor, HexOf(desiredDigest));
            var observation = await converger.ObserveAsync(plan, cancellationToken).ConfigureAwait(false);
            // The same readiness gate as a replacement: an auto-restarting unit is not
            // serving, so a crash-looping member is re-replaced instead of passively
            // early-returned as healthy.
            return observation.State == SystemdAllocationState.Running &&
                observation.MainProcessId is not null;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return false;
        }
    }

    private Task<string?> ReadDesiredDigestAsync(
        AdmittedRoleDescriptor descriptor,
        CancellationToken cancellationToken) => HostDesiredArtifactReader.ReadAsync(
            delivery, descriptor.ArtifactKey, configuration.Environment, cell, cancellationToken);

    private sealed record InstalledMarker(
        [property: JsonPropertyName("digest")] string? Digest,
        [property: JsonPropertyName("previousDigest")] string? PreviousDigest,
        [property: JsonPropertyName("installedAt")] DateTimeOffset InstalledAt);

    private Task<InstalledMarker?> ReadCurrentMarkerAsync(
        AdmittedRoleDescriptor descriptor,
        CancellationToken cancellationToken) =>
        ReadMarkerAsync(MarkerPath(descriptor), cancellationToken);

    private static async Task<InstalledMarker?> ReadMarkerAsync(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<InstalledMarker>(
                await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false));
        }
        catch (Exception exception) when (exception is IOException or JsonException)
        {
            return null;
        }
    }

    private Task WriteCurrentMarkerAsync(
        AdmittedRoleDescriptor descriptor,
        string digest,
        string? previous,
        CancellationToken cancellationToken)
    {
        var path = MarkerPath(descriptor);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        return File.WriteAllTextAsync(
            path,
            JsonSerializer.Serialize(new InstalledMarker(digest, previous, DateTimeOffset.UtcNow)),
            cancellationToken);
    }

    internal string MarkerPath(AdmittedRoleDescriptor descriptor) =>
        Path.Combine(configuration.InstallRoot, descriptor.ArtifactKey, "current.json");

    private async Task ReportAsync(
        AdmittedRoleDescriptor descriptor,
        string digest,
        ConvergeOutcome outcome,
        CancellationToken cancellationToken,
        string? state = null)
    {
        // The member-health gauges ride the same report: one scrape of the hosted
        // member's loopback listener, absent when this host runs no member (or the
        // member cannot be reached — the observation says so by omission, never by
        // inventing values).
        TerraScale.Orchestrator.Nodes.MemberObservation? member = null;
        if (memberHealth is not null)
        {
            try
            {
                member = await memberHealth.ObserveAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                member = null;
            }
        }
        var observation = new HostConvergenceObservation(
            HostConvergenceObservation.CurrentSchemaVersion,
            cell,
            instance,
            descriptor.ArtifactKey,
            digest,
            outcome.State switch
            {
                HostConvergenceOutcomeState.Converged => "converged",
                HostConvergenceOutcomeState.RolledBack => "rolled-back",
                HostConvergenceOutcomeState.RollbackFailed => "rollback-failed",
                _ => state ?? "failed"
            },
            outcome.UnitName,
            DateTimeOffset.UtcNow,
            outcome.Error,
            member?.Up,
            member?.ReplicationLagSequences,
            member?.Role,
            member?.PeerAckCount,
            member?.MinReplicas);
        observation.Validate();
        await reports.PublishAsync(observation, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Acquires the cell-scoped replace lease for one replicated service by compare-and-set.
    /// A lease whose holder crashed — including this same instance after a restart — is taken
    /// over once expired, so replacement never wedges. The returned handle renews the lease
    /// while its holder keeps working and aborts the attempt if the lease is lost.
    /// </summary>
    internal async Task<ReplaceLeaseHandle?> AcquireReplaceLeaseAsync(
        AdmittedRoleDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        var key = $"host.replace.{descriptor.ArtifactKey}";
        // A restarted process on the same host is a different claimant. A stale
        // handle must never renew or release that process's new acquisition.
        var holder = $"{cell}.{instance}.{Guid.NewGuid():N}";
        var leaseJson = JsonSerializer.Serialize(
            new HostConvergenceReplaceLease(holder, DateTimeOffset.UtcNow + replaceLeaseDuration),
            HostConvergenceJsonContext.Default.HostConvergenceReplaceLease);
        try
        {
            await runtimeStore.CreateAsync(key, leaseJson, cancellationToken: cancellationToken).ConfigureAwait(false);
            return new ReplaceLeaseHandle(this, key, holder, cancellationToken);
        }
        catch (Exception exception) when (exception is NatsKVCreateException or NatsKVWrongLastRevisionException)
        {
        }
        NatsKVEntry<string> entry;
        try
        {
            entry = await runtimeStore.GetEntryAsync<string>(key, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            entry.EnsureSuccess();
        }
        catch (Exception exception) when (
            exception is NatsKVKeyNotFoundException or NatsKVKeyDeletedException or NatsKVException)
        {
            return null;
        }
        HostConvergenceReplaceLease? existing = null;
        try
        {
            existing = JsonSerializer.Deserialize(
                entry.Value!, HostConvergenceJsonContext.Default.HostConvergenceReplaceLease);
        }
        catch (JsonException)
        {
        }
        // Only expiry gates a takeover: another host takes a crashed holder's lease, and a
        // restarted holder re-takes its own (TS_ORCH_INSTANCE is stable across restarts), so
        // a crash mid-replacement cannot wedge this host's member until the next admission.
        if (existing is null || existing.ExpiresAt > DateTimeOffset.UtcNow)
            return null;
        try
        {
            await runtimeStore.UpdateAsync(key, leaseJson, entry.Revision, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            return new ReplaceLeaseHandle(this, key, holder, cancellationToken);
        }
        catch (Exception exception) when (exception is NatsKVException)
        {
            return null;
        }
    }

    private async Task ReleaseReplaceLeaseAsync(string key, string holder)
    {
        try
        {
            var entry = await runtimeStore.GetEntryAsync<string>(key, cancellationToken: stopping.Token)
                .ConfigureAwait(false);
            entry.EnsureSuccess();
            var existing = JsonSerializer.Deserialize(
                entry.Value!, HostConvergenceJsonContext.Default.HostConvergenceReplaceLease);
            if (existing?.Holder == holder)
                await runtimeStore.DeleteAsync(key, new NatsKVDeleteOpts { Revision = entry.Revision },
                    cancellationToken: stopping.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is NatsKVException or JsonException or OperationCanceledException)
        {
            // An unreleased lease simply expires; replacement is delayed, never lost.
        }
    }

    private string BackoffKey(AdmittedRoleDescriptor descriptor) =>
        $"host.backoff.{instance}.{descriptor.ArtifactKey}";

    /// <summary>
    /// True while a failed cycle's backoff still bars a new attempt at this desired digest.
    /// The waiting pass re-writes the entry so the bucket's age purge cannot silently drop a
    /// long backoff. The backoff scopes to the digest that failed, so a newly admitted digest
    /// (the operator's remedy) is attempted immediately; a read failure fails open — one
    /// extra attempt beats wedging replacement on a store hiccup.
    /// </summary>
    private async Task<bool> BackedOffAsync(
        AdmittedRoleDescriptor descriptor,
        string desired,
        CancellationToken cancellationToken)
    {
        HostConvergenceBackoff? backoff;
        try
        {
            var entry = await runtimeStore.GetEntryAsync<string>(
                BackoffKey(descriptor), cancellationToken: cancellationToken).ConfigureAwait(false);
            entry.EnsureSuccess();
            backoff = JsonSerializer.Deserialize(
                entry.Value!, HostConvergenceJsonContext.Default.HostConvergenceBackoff);
        }
        catch (Exception exception) when (
            exception is NatsKVKeyNotFoundException or NatsKVKeyDeletedException or NatsKVException or JsonException)
        {
            return false;
        }
        if (backoff is null || backoff.Digest != desired || backoff.NotBefore <= DateTimeOffset.UtcNow)
            return false;
        try
        {
            await runtimeStore.PutAsync(
                BackoffKey(descriptor),
                JsonSerializer.Serialize(backoff, HostConvergenceJsonContext.Default.HostConvergenceBackoff),
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is NatsKVException)
        {
            // Losing the touch only risks the age purge ending the backoff early.
        }
        return true;
    }

    /// <summary>Records one failed converge-and-rollback cycle, doubling the next window per failure.</summary>
    private async Task RecordFailedCycleAsync(
        AdmittedRoleDescriptor descriptor,
        string desired,
        CancellationToken cancellationToken)
    {
        var failures = 1;
        try
        {
            var entry = await runtimeStore.GetEntryAsync<string>(
                BackoffKey(descriptor), cancellationToken: cancellationToken).ConfigureAwait(false);
            entry.EnsureSuccess();
            var existing = JsonSerializer.Deserialize(
                entry.Value!, HostConvergenceJsonContext.Default.HostConvergenceBackoff);
            if (existing is { Digest: var digest, Failures: var count } && digest == desired)
                failures = count + 1;
        }
        catch (Exception exception) when (
            exception is NatsKVKeyNotFoundException or NatsKVKeyDeletedException or NatsKVException or JsonException)
        {
            // No readable prior record: this failure starts a fresh backoff ladder.
        }
        var backoff = new HostConvergenceBackoff(
            desired,
            failures,
            DateTimeOffset.UtcNow + TimeSpan.FromTicks(Math.Min(
                FailedCycleBackoffBase.Ticks << Math.Min(failures - 1, 31),
                FailedCycleBackoffMaximum.Ticks)));
        try
        {
            await runtimeStore.PutAsync(
                BackoffKey(descriptor),
                JsonSerializer.Serialize(backoff, HostConvergenceJsonContext.Default.HostConvergenceBackoff),
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is NatsKVException)
        {
            // Losing the record costs one extra attempt; the next failed cycle re-records it.
        }
    }

    private async Task ClearBackoffAsync(AdmittedRoleDescriptor descriptor, CancellationToken cancellationToken)
    {
        try
        {
            await runtimeStore.DeleteAsync(BackoffKey(descriptor), cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is NatsKVException)
        {
            // A stale entry only delays the next replacement of a digest that just failed;
            // the serving early-return keeps this converged host passive regardless.
        }
    }

    internal static string HexOf(string digest) =>
        digest.StartsWith("sha256:", StringComparison.Ordinal)
            ? digest["sha256:".Length..].ToLowerInvariant()
            : digest.ToLowerInvariant();

    /// <summary>
    /// Refreshes the lease TTL on a cadence well under its duration while the holder works, so
    /// a live host's lease never expires mid-replacement and cannot be stolen from under it.
    /// </summary>
    private async Task RenewReplaceLeaseAsync(
        string key,
        string holder,
        CancellationTokenSource abort,
        CancellationToken stopped)
    {
        while (!stopped.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(replaceLeaseRenewalInterval, stopped).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            try
            {
                var entry = await runtimeStore.GetEntryAsync<string>(key, cancellationToken: stopped)
                    .ConfigureAwait(false);
                entry.EnsureSuccess();
                var existing = JsonSerializer.Deserialize(
                    entry.Value!, HostConvergenceJsonContext.Default.HostConvergenceReplaceLease);
                if (existing?.Holder != holder)
                {
                    abort.Cancel();
                    return;
                }
                var renewed = JsonSerializer.Serialize(
                    new HostConvergenceReplaceLease(holder, DateTimeOffset.UtcNow + replaceLeaseDuration),
                    HostConvergenceJsonContext.Default.HostConvergenceReplaceLease);
                await runtimeStore.UpdateAsync(key, renewed, entry.Revision, cancellationToken: stopped)
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is NatsKVException or JsonException)
            {
                // The lease was deleted, taken over, or raced away: abort the attempt rather
                // than keep replacing a member another host may be replacing concurrently.
                abort.Cancel();
                return;
            }
        }
    }

    /// <summary>
    /// A held replace lease. It renews the TTL while the holder is alive and working — an
    /// actively-working host can never have its lease (and member) stolen mid-replacement —
    /// and cancels <see cref="Token"/> as soon as renewal loses the lease, aborting the
    /// attempt. A holder that dies stops renewing, so its lease expires and a peer (or the
    /// restarted holder) takes over.
    /// </summary>
    internal sealed class ReplaceLeaseHandle : IAsyncDisposable
    {
        private readonly HostConvergenceRuntime owner;
        private readonly string key;
        private readonly string holder;
        private readonly CancellationTokenSource abort;
        private readonly CancellationTokenSource stopped = new();
        private readonly Task renewal;

        internal ReplaceLeaseHandle(
            HostConvergenceRuntime owner,
            string key,
            string holder,
            CancellationToken cancellationToken)
        {
            this.owner = owner;
            this.key = key;
            this.holder = holder;
            abort = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            renewal = Task.Run(() => this.owner.RenewReplaceLeaseAsync(key, holder, abort, stopped.Token));
        }

        /// <summary>Aborts while the holder is still working and the lease has been lost.</summary>
        internal CancellationToken Token => abort.Token;

        public async ValueTask DisposeAsync()
        {
            stopped.Cancel();
            try
            {
                await renewal.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            await owner.ReleaseReplaceLeaseAsync(key, holder).ConfigureAwait(false);
            abort.Dispose();
            stopped.Dispose();
        }
    }
}

/// <summary>The exact durable key the delivery target adapter writes for one service, environment, and region.</summary>
internal static class DirectDeliveryTargetKey
{
    public static string For(string service, string environment, string region) =>
        $"direct.target.{Token(service)}.{Token(environment)}.{Token(region)}";

    private static string Token(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value)))[..32];
}

/// <summary>Artifact source over the regional NATS object store.</summary>
internal sealed class NatsObjectArtifactSource(INatsObjStore store) : IHostArtifactSource
{
    public async Task CopyIntoAsync(string objectName, Stream destination, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(store);
        await store.GetAsync(objectName, destination, leaveOpen: true, cancellationToken);
    }
}

/// <summary>Converger over the fail-closed native systemd admission boundary.</summary>
internal sealed class SystemdHostConverger(
    ControlPlane.Runtime.INativeSystemdRuntimeLifecycleAdmissionFactory? admissionFactory = null) : IHostRuntimeConverger
{
    private readonly ControlPlane.Runtime.INativeSystemdRuntimeLifecycleAdmissionFactory admissionFactory =
        admissionFactory ?? new ControlPlane.Runtime.NativeSystemdRuntimeLifecycleAdmissionFactory();

    public Task ConvergeAsync(HostRuntimePlan plan, CancellationToken cancellationToken) =>
        admissionFactory.Admit(plan).ConvergeAsync(cancellationToken);

    public Task StopAsync(HostRuntimePlan plan, CancellationToken cancellationToken) =>
        admissionFactory.Admit(plan).StopAsync(cancellationToken);

    public Task<SystemdAllocationObservation> ObserveAsync(HostRuntimePlan plan, CancellationToken cancellationToken) =>
        admissionFactory.Admit(plan).ObserveAsync(cancellationToken);
}
