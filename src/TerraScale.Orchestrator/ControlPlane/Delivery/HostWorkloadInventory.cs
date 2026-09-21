using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal sealed record HostWorkloadIdentity
{
    public HostWorkloadIdentity(string cell, string nodeId, string environment)
    {
        if (cell is not ("gru" or "sfo" or "fra")) throw new ArgumentException("A host inventory requires a regional cell.");
        Cell = cell;
        NodeId = RegionalNodeEnrollmentEnvelope.ValidateToken(nodeId, nameof(nodeId));
        Environment = new RegionalNodeEnrollmentScope(environment, [AdmittedRole.TerraBaseMember]).Environment;
    }
    public string Cell { get; }
    public string NodeId { get; }
    public string Environment { get; }

    internal void RequirePlan(HostRuntimePlan plan)
    {
        var descriptor = AdmittedRoleCatalog.Get(plan.Role);
        if (plan.AllocationId != HostConvergenceRuntime.AllocationIdFor(Cell, NodeId, descriptor.ArtifactKey))
            throw new InvalidDataException("The workload plan belongs to a different host allocation.");
    }
}

internal enum HostInventoryWriteStage { FileFlushed, Renamed, DirectoryFlushed }

/// <summary>
/// One supervisor's private local execution inventory. Intent is committed before dispatch;
/// a response, report ACK or installation marker is never needed to recover that intent.
/// The lock inode is never unlinked. The supervisor must protect this directory for its lifetime.
/// </summary>
internal sealed class HostWorkloadInventory : IDisposable
{
    private const int MaximumBytes = 4 * 1024 * 1024;
    private const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode PrivateDirectory = PrivateFile | UnixFileMode.UserExecute;
    private readonly object gate = new();
    private readonly FileStream owner;
    private readonly string directory;
    private readonly string path;
    private readonly Action<HostInventoryWriteStage>? afterWrite;
    private Dictionary<string, HostRuntimePlan> plans;
    private long revision;
    private bool poisoned;
    private bool claimed;
    private bool disposed;
    private readonly HostInventoryFiles.Identity directoryIdentity;
    private readonly HostInventoryFiles.Identity ownerIdentity;
    private byte[]? documentHash;
    private byte[]? ownerMarker;

    private HostWorkloadInventory(FileStream owner, string directory, HostWorkloadIdentity identity,
        Dictionary<string, HostRuntimePlan> plans, long revision, Action<HostInventoryWriteStage>? afterWrite)
    {
        this.owner = owner;
        this.directory = directory;
        path = Path.Combine(directory, "workloads.json");
        Identity = identity;
        this.plans = plans;
        this.revision = revision;
        this.afterWrite = afterWrite;
        directoryIdentity = HostInventoryFiles.Require(directory, directory: true);
        ownerIdentity = HostInventoryFiles.Of(owner.SafeFileHandle);
        if (ownerIdentity != HostInventoryFiles.Require(Path.Combine(directory, "owner.lock")))
            throw new InvalidDataException("Host inventory ownership changed during open.");
        if (File.Exists(path)) documentHash = HashDocument(path);
    }

    internal HostWorkloadIdentity Identity { get; }
    internal bool IsDisposed { get { lock (gate) return disposed; } }
    internal IReadOnlyList<HostRuntimePlan> Plans
    {
        get { lock (gate) { RequireUsable(); return plans.Values.Select(HostRuntimePlanSnapshot.Copy).ToArray(); } }
    }

    internal static HostWorkloadInventory Open(string directory, HostWorkloadIdentity identity,
        Action<HostInventoryWriteStage>? afterWrite = null)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Host execution inventory requires Linux.");
        directory = Path.GetFullPath(directory);
        RequireDirectory(directory);
        var lockPath = Path.Combine(directory, "owner.lock");
        RequireFileIfPresent(lockPath);
        var owner = new FileStream(lockPath, new FileStreamOptions
        {
            Mode = FileMode.OpenOrCreate, Access = FileAccess.ReadWrite, Share = FileShare.None, UnixCreateMode = PrivateFile
        });
        try
        {
            var path = Path.Combine(directory, "workloads.json");
            RequireFileIfPresent(path);
            var plans = new Dictionary<string, HostRuntimePlan>(StringComparer.Ordinal);
            long revision = 0;
            var marker = Encoding.ASCII.GetBytes(Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(identity, JsonOptions))));
            if (owner.Length != 0)
            {
                if (owner.Length != marker.Length) throw new InvalidDataException("The host ownership marker is invalid.");
                var persisted = new byte[marker.Length];
                owner.ReadExactly(persisted);
                if (!persisted.AsSpan().SequenceEqual(marker) || !File.Exists(path))
                    throw new InvalidDataException("An initialized host inventory is missing or belongs to another identity.");
            }
            if (File.Exists(path))
            {
                _ = NatsFileResolver.Resolve(path, "host workload inventory", MaximumBytes, ownerPrivate: true);
                using var input = File.OpenRead(path);
                var bytes = new byte[MaximumBytes + 1];
                var length = input.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
                if (length is < 1 or > MaximumBytes) throw new InvalidDataException("Host workload inventory exceeds its bounds.");
                var document = JsonSerializer.Deserialize<Document>(bytes.AsSpan(0, length), JsonOptions);
                if (document is not { SchemaVersion: 1, Revision: > 0, Plans.Count: <= 1024 } || document.Identity != identity)
                    throw new InvalidDataException("The host workload inventory does not match this host.");
                foreach (var entry in document.Plans)
                {
                    var plan = HostRuntimePlanSnapshot.Copy(entry.Plan);
                    identity.RequirePlan(plan);
                    if (CanonicalPlanFingerprint.Compute(plan) != entry.Fingerprint || !plans.TryAdd(entry.Fingerprint, plan))
                        throw new InvalidDataException("The workload inventory contains an ambiguous or changed plan.");
                }
                RequireCapacity(plans.Values);
                revision = document.Revision;
                // Empty marker + empty initial snapshot can result from interruption before
                // initialization completed. No operation is dispatched until both are durable.
                if (owner.Length == 0 && plans.Count != 0)
                    throw new InvalidDataException("A populated workload inventory lost its ownership marker.");
            }
            var inventory = new HostWorkloadInventory(owner, directory, identity, plans, revision, afterWrite);
            if (revision == 0) inventory.Save(plans);
            if (owner.Length == 0)
            {
                owner.Write(marker);
                owner.Flush(flushToDisk: true);
                SyncDirectory(directory);
            }
            inventory.ownerMarker = marker;
            inventory.RequireStorage();
            return inventory;
        }
        catch { owner.Dispose(); throw; }
    }

    internal void Claim()
    {
        lock (gate)
        {
            RequireUsable();
            if (claimed) throw new InvalidOperationException("The host inventory already belongs to a workload supervisor.");
            claimed = true;
        }
    }

    internal HostRuntimePlan Record(HostRuntimePlan candidate)
    {
        var canonical = HostRuntimePlanSnapshot.Copy(candidate);
        Identity.RequirePlan(canonical);
        lock (gate)
        {
            RequireUsable();
            var fingerprint = CanonicalPlanFingerprint.Compute(canonical);
            if (plans.ContainsKey(fingerprint)) return canonical;
            var next = new Dictionary<string, HostRuntimePlan>(plans, StringComparer.Ordinal) { [fingerprint] = canonical };
            RequireCapacity(next.Values);
            Save(next);
            return canonical;
        }
    }

    // Only an absent native object retires its evidence. A stopped unit can still exist
    // and must remain explainable during a subsequent native inventory scan.
    internal void ForgetAbsent(RuntimeDriver driver, string allocationId)
    {
        lock (gate)
        {
            RequireUsable();
            var next = plans.Where(pair => pair.Value.Driver != driver || pair.Value.AllocationId.Value != allocationId)
                .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
            if (next.Count != plans.Count) Save(next);
        }
    }

    private void Save(Dictionary<string, HostRuntimePlan> next)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var nextRevision = checked(revision + 1);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new Document(1, Identity, nextRevision,
            next.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new Entry(pair.Key, pair.Value)).ToArray()), JsonOptions);
        if (bytes.Length > MaximumBytes) throw new InvalidDataException("Host workload inventory exceeds its bounds.");
        var temporary = Path.Combine(directory, "pending-" + Guid.NewGuid().ToString("N"));
        try
        {
            RequireStorage();
            using (var output = new FileStream(temporary, new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, UnixCreateMode = PrivateFile
            }))
            {
                output.Write(bytes);
                output.Flush(flushToDisk: true);
            }
            afterWrite?.Invoke(HostInventoryWriteStage.FileFlushed);
            File.Move(temporary, path, overwrite: true);
            afterWrite?.Invoke(HostInventoryWriteStage.Renamed);
            SyncDirectory(directory);
            afterWrite?.Invoke(HostInventoryWriteStage.DirectoryFlushed);
            documentHash = SHA256.HashData(bytes);
            plans = next;
            revision = nextRevision;
        }
        catch { poisoned = true; throw; }
        finally
        {
            try { if (File.Exists(temporary)) File.Delete(temporary); }
            catch (IOException) { /* Orphaned private temporary files never authorize dispatch. */ }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static void RequireCapacity(IEnumerable<HostRuntimePlan> plans)
    {
        var groups = plans.GroupBy(plan => (plan.Driver, plan.AllocationId.Value)).ToArray();
        if (groups.Length > 32 || groups.Any(group => group.Count() > 32))
            throw new InvalidDataException("The host workload inventory is full.");
    }

    private void RequireUsable()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (poisoned) throw new InvalidOperationException("The host inventory lost durable write confirmation; restart recovery is required.");
        try { RequireStorage(); }
        catch { poisoned = true; throw; }
    }

    private static void RequireDirectory(string directory)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        _ = HostInventoryFiles.Require(directory, directory: true);
        var root = new DirectoryInfo(directory);
        if (!root.Exists || File.GetUnixFileMode(directory) != PrivateDirectory)
            throw new InvalidDataException("The host inventory needs an existing private directory.");
        for (DirectoryInfo? part = root; part is not null; part = part.Parent)
            if (part.LinkTarget is not null || part.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new InvalidDataException("The host inventory directory must not traverse links.");
    }

    private static void RequireFileIfPresent(string path) => HostInventoryFiles.Require(path, optional: true);

    private void RequireStorage()
    {
        RequireDirectory(directory);
        if (HostInventoryFiles.Require(directory, directory: true) != directoryIdentity ||
            HostInventoryFiles.Require(Path.Combine(directory, "owner.lock")) != ownerIdentity)
            throw new InvalidDataException("The host inventory ownership path was replaced.");
        if (ownerMarker is not null)
        {
            var bytes = new byte[ownerMarker.Length];
            if (owner.Length != bytes.Length || RandomAccess.Read(owner.SafeFileHandle, bytes, 0) != bytes.Length ||
                !bytes.AsSpan().SequenceEqual(ownerMarker))
                throw new InvalidDataException("The host inventory ownership marker changed.");
        }
        RequireFileIfPresent(path);
        if (documentHash is null ? File.Exists(path) : !documentHash.AsSpan().SequenceEqual(HashDocument(path)))
            throw new InvalidDataException("The host workload inventory changed outside its supervisor.");
    }

    private static byte[] HashDocument(string path)
    {
        RequireFileIfPresent(path);
        using var file = File.OpenRead(path);
        if (file.Length is < 1 or > MaximumBytes) throw new InvalidDataException("Host workload inventory exceeds its bounds.");
        var bytes = new byte[checked((int)file.Length)];
        file.ReadExactly(bytes);
        if (file.ReadByte() != -1) throw new InvalidDataException("Host workload inventory changed while reading.");
        return SHA256.HashData(bytes);
    }

    private static void SyncDirectory(string directory)
    {
        // O_DIRECTORY/O_NOFOLLOW differ between the Linux x64 and ARM64 ABIs.
        // Both use O_RDONLY=0 and O_CLOEXEC=0x80000. Reject unqualified ABIs.
        var flags = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => 0x10000 | 0x20000 | 0x80000,
            Architecture.Arm64 => 0x4000 | 0x8000 | 0x80000,
            _ => throw new PlatformNotSupportedException("Host inventory durability requires Linux x64 or ARM64.")
        };
        var descriptor = OpenDirectory(directory, flags);
        if (descriptor < 0) throw new IOException("Cannot open the host inventory directory for durability confirmation.",
            new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
        using var handle = new SafeFileHandle((IntPtr)descriptor, ownsHandle: true);
        if (Fsync(handle) != 0) throw new IOException("Cannot confirm host inventory directory durability.");
    }

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int OpenDirectory(string path, int flags);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Fsync(SafeFileHandle descriptor);

    public void Dispose()
    {
        lock (gate)
        {
            if (claimed && !disposed) throw new InvalidOperationException("The workload supervisor retains ownership until native operations settle.");
            Release();
        }
    }

    internal void ReleaseSupervisor() { lock (gate) Release(); }
    private void Release() { if (!disposed) { disposed = true; owner.Dispose(); } }

    internal static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        AllowDuplicateProperties = false, PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 16
    };
    private sealed record Entry(string Fingerprint, HostRuntimePlan Plan);
    private sealed record Document(int SchemaVersion, HostWorkloadIdentity Identity, long Revision, IReadOnlyList<Entry> Plans);
}
