using System.Diagnostics;

namespace TerraScale.Orchestrator;

internal static class ProcessLifecycle
{
    public static async Task WaitForExitAsync(Process process, CancellationToken cancellationToken)
    {
        try
        {
            await process.WaitForExitAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // The process exited between cancellation and the kill request.
            }

            await process.WaitForExitAsync();
            throw;
        }
    }
}
