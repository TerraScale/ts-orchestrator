using System.Text;

namespace TerraScale.Orchestrator.Development;

internal sealed class LocalValidationLease : IDisposable
{
    private readonly FileStream stream;

    private LocalValidationLease(FileStream stream) => this.stream = stream;

    public static LocalValidationLease Acquire(string? scope = null)
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"terrascale-orchestrator-validation-{scope ?? Environment.UserName}.lock");
        try
        {
            return AcquireExclusive(path);
        }
        catch (IOException exception)
        {
            // A previous lab or attestation process that was killed during a bulk
            // stop leaves its lock file behind; recover it when the recorded
            // holder no longer exists instead of failing the restart.
            if (!TryReadHolder(path, out var holder) || (holder is int processId && IsProcessAlive(processId)))
            {
                throw new InvalidOperationException(
                    $"Another TerraScale Orchestrator test or lab run is already active (holder process {holder?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "unknown"}).",
                    exception);
            }

            try
            {
                File.Delete(path);
            }
            catch (IOException deletionException)
            {
                throw new InvalidOperationException(
                    $"A stale TerraScale Orchestrator validation lease from process {holder} could not be cleared: {path}",
                    deletionException);
            }

            try
            {
                return AcquireExclusive(path);
            }
            catch (IOException retryException)
            {
                throw new InvalidOperationException(
                    "Another TerraScale Orchestrator test or lab run is already active.",
                    retryException);
            }
        }
    }

    private static LocalValidationLease AcquireExclusive(string path)
    {
        var stream = new FileStream(
            path,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None,
            4096,
            FileOptions.WriteThrough);
        stream.SetLength(0);
        stream.Write(Encoding.UTF8.GetBytes(Environment.ProcessId.ToString(
            System.Globalization.CultureInfo.InvariantCulture)));
        stream.Flush(flushToDisk: true);
        return new(stream);
    }

    private static bool TryReadHolder(string path, out int? holder)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream);
            holder = int.TryParse(reader.ReadToEnd().Trim(), out var parsed) ? parsed : null;
            return true;
        }
        catch (IOException)
        {
            holder = null;
            return false;
        }
    }

    private static bool IsProcessAlive(int processId)
    {
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(processId);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    public void Dispose() => stream.Dispose();
}
