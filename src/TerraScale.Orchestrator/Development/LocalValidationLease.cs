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
        catch (IOException exception)
        {
            throw new InvalidOperationException(
                "Another TerraScale Orchestrator test or lab run is already active.",
                exception);
        }
    }

    public void Dispose() => stream.Dispose();
}
