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

            // The cancellation-aware overload can leave Process' async wait
            // state unusable after the kill. A synchronous wait is safe here:
            // the process has already been terminated and this keeps cleanup
            // deterministic without surfacing an unrelated runtime exception.
            process.WaitForExit();
            throw;
        }
    }
}

