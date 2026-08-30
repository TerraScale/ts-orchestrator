namespace TerraScale.Orchestrator.Tooling;

internal static class WorkspaceTopologyLeaseHolderCommand
{
    public static async Task<int> RunAsync(string[] arguments)
    {
        var (leaseNamespace, noisyStderr, ignoreStandardInput) = arguments switch
        {
            ["--namespace", var value] => (value, false, false),
            ["--namespace", var value, "--noisy-stderr", "--ignore-stdin"] =>
                (value, true, true),
            _ => throw new ToolValidationException(["workspace-topology-lease-holder requires --namespace <value>"])
        };

        if (string.IsNullOrEmpty(leaseNamespace))
        {
            throw new ToolValidationException(["workspace-topology-lease-holder requires --namespace <value>"]);
        }

        Environment.SetEnvironmentVariable("TERRASCALE_VALIDATION_LEASE_NAMESPACE", leaseNamespace);
        await using var lease = await WorkspaceTopologyLease.AcquireAsync(
            "development-lab", TimeSpan.FromSeconds(10));
        if (noisyStderr)
        {
            for (var written = 0; written < 128 * 1024; written += 1024)
            {
                Console.Error.Write(new string('x', 1024));
            }
            await Console.Error.FlushAsync();
        }
        Console.WriteLine("held");
        await Console.Out.FlushAsync();
        if (ignoreStandardInput)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan);
        }
        _ = await Console.In.ReadLineAsync();
        return 0;
    }
}
