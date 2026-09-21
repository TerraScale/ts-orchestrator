using System.Text.Json;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Bootstrap.Founding;

/// <summary>Exclusive local progress receipt. OCI tokens and fixed IPs also fence crash retries.</summary>
internal sealed class OciFoundingState : IDisposable
{
    private const UnixFileMode PrivateDirectory = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private readonly FileStream lease;
    private readonly string path;
    private readonly VerifiedOciFoundingPlan verified;

    private OciFoundingState(FileStream lease, string path, VerifiedOciFoundingPlan verified, Dictionary<string, string?> peers)
    {
        this.lease = lease;
        this.path = path;
        this.verified = verified;
        Peers = peers;
    }

    internal Dictionary<string, string?> Peers { get; }

    internal static OciFoundingState Open(string directory, VerifiedOciFoundingPlan verified)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Founding requires Linux file permissions.");
        var parent = new DirectoryInfo(Path.GetFullPath(directory));
        if (!parent.Exists || File.GetUnixFileMode(parent.FullName) != PrivateDirectory)
            throw new InvalidDataException("Founding state needs an existing private directory.");
        for (DirectoryInfo? part = parent; part is not null; part = part.Parent)
            if (part.LinkTarget is not null || part.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new InvalidDataException("Founding state must not traverse links.");
        var lockPath = Path.Combine(parent.FullName, "founding.lock");
        if (new FileInfo(lockPath).LinkTarget is not null ||
            File.Exists(lockPath) && File.GetUnixFileMode(lockPath) != PrivateFile)
            throw new InvalidDataException("The founding lock is not a private regular file.");
        var lease = new FileStream(lockPath, new FileStreamOptions
        {
            Mode = FileMode.OpenOrCreate, Access = FileAccess.ReadWrite, Share = FileShare.None,
            UnixCreateMode = PrivateFile
        });
        try
        {
            var path = Path.Combine(parent.FullName, "founding.json");
            var peers = new Dictionary<string, string?>(StringComparer.Ordinal);
            if (new FileInfo(path).LinkTarget is not null)
                throw new InvalidDataException("The founding receipt must not be a link.");
            if (File.Exists(path))
            {
                _ = NatsFileResolver.Resolve(path, "founding receipt", 16 * 1024, ownerPrivate: true);
                var document = JsonSerializer.Deserialize<Document>(
                    OciFoundingPlan.ReadFile(path, "founding receipt", 16 * 1024), OciFoundingPlan.JsonOptions);
                if (document is not { SchemaVersion: 1, Peers.Count: <= 2 } || document.PlanDigest != verified.Digest ||
                    document.SeedInstanceId != verified.Plan.SeedInstanceId || document.Peers.Any(entry =>
                        entry.Key is not ("peer-1" or "peer-2") || entry.Value is not null && !OciFoundingPlan.RegionalOcid(entry.Value, "instance")) ||
                    document.Peers.Values.Where(value => value is not null).Distinct(StringComparer.Ordinal).Count() !=
                    document.Peers.Values.Count(value => value is not null))
                    throw new InvalidDataException("The founding receipt does not match this exact grant.");
                peers = new(document.Peers, StringComparer.Ordinal);
            }
            var state = new OciFoundingState(lease, path, verified, peers);
            state.Save(); // Pin the grant before the first external operation.
            return state;
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    internal void Record(string slot, string? instanceId)
    {
        Peers[slot] = instanceId;
        Save();
    }

    private void Save()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var temporary = path + "." + Guid.NewGuid().ToString("N");
        try
        {
            using (var stream = new FileStream(temporary, new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, UnixCreateMode = PrivateFile
            }))
            {
                JsonSerializer.Serialize(stream, new Document(1, verified.Digest, verified.Plan.SeedInstanceId, Peers), OciFoundingPlan.JsonOptions);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    public void Dispose() => lease.Dispose();
    private sealed record Document(int SchemaVersion, string PlanDigest, string SeedInstanceId, Dictionary<string, string?> Peers);
}
