using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;
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
    HostArchitecture Architecture)
{
    public const string DefaultInstallRoot = "/opt/terrascale/artifacts";

    internal static HostConvergenceConfiguration Parse(
        IReadOnlyList<string> roleNames,
        string? environment,
        string? installRoot,
        HostArchitecture? architecture = null) => new(
        roleNames.Select(HostRuntimeCli.ParseRole).ToArray(),
        environment is { Length: > 0 } ? environment : "production",
        string.IsNullOrWhiteSpace(installRoot) ? DefaultInstallRoot : installRoot,
        architecture ?? DetectArchitecture());

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
    string? Error = null)
{
    public const int CurrentSchemaVersion = 1;

    public void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion ||
            string.IsNullOrWhiteSpace(Cell) || string.IsNullOrWhiteSpace(Instance) ||
            string.IsNullOrWhiteSpace(ArtifactKey) ||
            Digest is not { Length: 71 } || !Digest.StartsWith("sha256:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(State) ||
            ObservedAt == default)
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

[JsonSerializable(typeof(HostConvergenceObservation))]
[JsonSerializable(typeof(HostConvergenceReplaceLease))]
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
    Task<SystemdAllocationObservation> ObserveAsync(HostRuntimePlan plan, CancellationToken cancellationToken);
}

/// <summary>The one admitted host action a reconcile pass decided on.</summary>
internal enum HostConvergenceOutcomeState
{
    Converged = 1,
    RolledBack = 2,
    Failed = 3
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
    private static readonly TimeSpan ObservationPollInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan ReplaceLeaseDuration = TimeSpan.FromMinutes(5);
    private const int MaximumConvergeAttempts = 3;

    private readonly INatsKVStore delivery;
    private readonly INatsKVStore runtimeStore;
    private readonly INatsConnection connection;
    private readonly IHostArtifactSource artifacts;
    private readonly IHostRuntimeConverger converger;
    private readonly HostConvergenceConfiguration configuration;
    private readonly string cell;
    private readonly string instance;
    private readonly string agentObservationSubject;
    private readonly TimeSpan observationTimeout;
    private readonly CancellationTokenSource stopping = new();
    private readonly List<Task> loops = [];

    private HostConvergenceRuntime(
        INatsKVStore delivery,
        INatsKVStore runtimeStore,
        INatsConnection connection,
        IHostArtifactSource artifacts,
        IHostRuntimeConverger converger,
        HostConvergenceConfiguration configuration,
        string cell,
        string instance,
        TimeSpan? observationTimeout = null)
    {
        this.observationTimeout = observationTimeout ?? TimeSpan.FromSeconds(90);
        this.delivery = delivery;
        this.runtimeStore = runtimeStore;
        this.connection = connection;
        this.artifacts = artifacts;
        this.converger = converger;
        this.configuration = configuration;
        this.cell = cell;
        this.instance = instance;
        agentObservationSubject = NatsSubjectTaxonomy.HostAgentObservationSubject(cell, instance, "runtime");
    }

    /// <summary>Constructs the runtime without starting any background loops; tests drive reconcile passes directly.</summary>
    internal static HostConvergenceRuntime Create(
        INatsKVStore delivery,
        INatsKVStore runtimeStore,
        INatsConnection connection,
        IHostArtifactSource artifacts,
        IHostRuntimeConverger converger,
        HostConvergenceConfiguration configuration,
        string cell,
        string instance,
        TimeSpan? observationTimeout = null) =>
        new(delivery, runtimeStore, connection, artifacts, converger, configuration, cell, instance,
            observationTimeout);

    /// <summary>Starts one reconcile loop per configured role. The loops never throw: failures are reported as observations.</summary>
    internal static HostConvergenceRuntime Start(
        INatsKVStore delivery,
        INatsKVStore runtimeStore,
        INatsConnection connection,
        IHostArtifactSource artifacts,
        IHostRuntimeConverger converger,
        HostConvergenceConfiguration configuration,
        string cell,
        string instance,
        TimeSpan? observationTimeout = null)
    {
        var runtimeLoop = Create(
            delivery, runtimeStore, connection, artifacts, converger, configuration, cell, instance,
            observationTimeout);
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
            catch (Exception)
            {
                // A transient ledger or store failure must not kill the loop; the next pass retries.
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
        var current = await ReadCurrentMarkerAsync(descriptor, cancellationToken).ConfigureAwait(false);
        if (current is { Digest: { } currentDigest } &&
            string.Equals(currentDigest, desired, StringComparison.Ordinal) &&
            await IsServingAsync(role, descriptor, desired, cancellationToken).ConfigureAwait(false))
            return;

        await using var lease = descriptor.MinimumReplicas > 1
            ? await AcquireReplaceLeaseAsync(descriptor, cancellationToken).ConfigureAwait(false)
            : null;
        if (descriptor.MinimumReplicas > 1 && lease is null)
            return; // Another host is replacing its member right now; retry next pass.

        var previous = current?.Digest;
        var outcome = await InstallConvergeAndObserveAsync(role, descriptor, desired, cancellationToken)
            .ConfigureAwait(false);
        if (outcome.State == HostConvergenceOutcomeState.Converged)
        {
            await WriteCurrentMarkerAsync(descriptor, desired, previous, cancellationToken).ConfigureAwait(false);
            await ReportAsync(descriptor, desired, outcome, cancellationToken).ConfigureAwait(false);
            return;
        }

        // The new version failed its post-converge observation: restore the exact previous
        // digest (artifact directories are immutable and never deleted, so it is still on
        // disk) and report the rolled-back outcome. A first deployment has nothing to restore.
        if (previous is { } rollbackDigest)
        {
            var rollback = await InstallConvergeAndObserveAsync(role, descriptor, rollbackDigest, cancellationToken)
                .ConfigureAwait(false);
            await WriteCurrentMarkerAsync(descriptor, rollbackDigest, previous: null, cancellationToken)
                .ConfigureAwait(false);
            await ReportAsync(
                descriptor,
                rollbackDigest,
                rollback with { State = HostConvergenceOutcomeState.RolledBack },
                cancellationToken).ConfigureAwait(false);
            return;
        }
        await ReportAsync(descriptor, desired, outcome, cancellationToken).ConfigureAwait(false);
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
            // The plan owns the executable path (immutable digest layout); installation lands
            // exactly where the admitted systemd unit will run it.
            var executable = plan.Systemd!.Executable;
            if (!File.Exists(executable))
                await InstallArtifactAsync(descriptor, hex, executable, cancellationToken).ConfigureAwait(false);
            for (var attempt = 1; attempt <= MaximumConvergeAttempts; attempt++)
            {
                await converger.ConvergeAsync(plan, cancellationToken).ConfigureAwait(false);
                var deadline = DateTimeOffset.UtcNow + observationTimeout;
                while (DateTimeOffset.UtcNow < deadline)
                {
                    var observation = await converger.ObserveAsync(plan, cancellationToken).ConfigureAwait(false);
                    if (observation.State is SystemdAllocationState.Running or SystemdAllocationState.Starting)
                        return new(HostConvergenceOutcomeState.Converged, observation.UnitName, null);
                    if (observation.State is not SystemdAllocationState.Failed)
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
            RuntimeDriver.NativeSystemd,
            new($"host-{descriptor.ArtifactKey}-{instance}"),
            new(hex),
            configuration.Architecture,
            installRoot: configuration.InstallRoot);

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
            return observation.State is SystemdAllocationState.Running or SystemdAllocationState.Starting;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return false;
        }
    }

    private async Task<string?> ReadDesiredDigestAsync(
        AdmittedRoleDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        string? json;
        try
        {
            var entry = await delivery.GetEntryAsync<string>(
                DirectDeliveryTargetKey.For(descriptor.ArtifactKey, configuration.Environment, cell),
                cancellationToken: cancellationToken).ConfigureAwait(false);
            entry.EnsureSuccess();
            json = entry.Value;
        }
        catch (Exception exception) when (
            exception is NatsKVKeyNotFoundException or NatsKVKeyDeletedException or NatsKVException)
        {
            return null;
        }
        var state = JsonSerializer.Deserialize<DesiredArtifactState>(json ?? string.Empty, DeliveryWireCodec.JsonOptions);
        return state?.ArtifactDigest is { Length: 71 } digest ? digest.ToLowerInvariant() : null;
    }

    private sealed record DesiredArtifactState(
        [property: JsonPropertyName("artifactDigest")] string? ArtifactDigest,
        [property: JsonPropertyName("manifestDigest")] string? ManifestDigest,
        [property: JsonPropertyName("kind")] string? Kind);

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
        CancellationToken cancellationToken)
    {
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
                _ => "failed"
            },
            outcome.UnitName,
            DateTimeOffset.UtcNow,
            outcome.Error);
        observation.Validate();
        var json = JsonSerializer.Serialize(observation, HostConvergenceJsonContext.Default.HostConvergenceObservation);
        await runtimeStore.PutAsync($"host.{instance}.{descriptor.ArtifactKey}", json, cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        try
        {
            await connection.PublishAsync(agentObservationSubject, json, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }
        catch (NatsException)
        {
            // The durable KV observation above is the truth; the agent subject publish is
            // best-effort telemetry for live watchers.
        }
    }

    /// <summary>
    /// Acquires the cell-scoped replace lease for one replicated service by compare-and-set.
    /// A lease whose holder crashed is taken over after expiry, so replacement never wedges.
    /// </summary>
    internal async Task<IAsyncDisposable?> AcquireReplaceLeaseAsync(
        AdmittedRoleDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        var key = $"host.replace.{descriptor.ArtifactKey}";
        var holder = $"{cell}.{instance}";
        var leaseJson = JsonSerializer.Serialize(
            new HostConvergenceReplaceLease(holder, DateTimeOffset.UtcNow + ReplaceLeaseDuration),
            HostConvergenceJsonContext.Default.HostConvergenceReplaceLease);
        try
        {
            await runtimeStore.CreateAsync(key, leaseJson, cancellationToken: cancellationToken).ConfigureAwait(false);
            return new ReplaceLeaseHandle(this, key, holder);
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
        if (existing is null || existing.Holder == holder || existing.ExpiresAt > DateTimeOffset.UtcNow)
            return null;
        try
        {
            await runtimeStore.UpdateAsync(key, leaseJson, entry.Revision, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            return new ReplaceLeaseHandle(this, key, holder);
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
                await runtimeStore.DeleteAsync(key, cancellationToken: stopping.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is NatsKVException or JsonException or OperationCanceledException)
        {
            // An unreleased lease simply expires; replacement is delayed, never lost.
        }
    }

    internal static string HexOf(string digest) =>
        digest.StartsWith("sha256:", StringComparison.Ordinal)
            ? digest["sha256:".Length..].ToLowerInvariant()
            : digest.ToLowerInvariant();

    private sealed class ReplaceLeaseHandle(
        HostConvergenceRuntime owner,
        string key,
        string holder) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync() =>
            await owner.ReleaseReplaceLeaseAsync(key, holder).ConfigureAwait(false);
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

    public Task<SystemdAllocationObservation> ObserveAsync(HostRuntimePlan plan, CancellationToken cancellationToken) =>
        admissionFactory.Admit(plan).ObserveAsync(cancellationToken);
}
