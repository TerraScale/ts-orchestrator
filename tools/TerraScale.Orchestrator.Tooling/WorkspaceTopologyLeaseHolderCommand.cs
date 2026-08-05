using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tooling;

internal static class WorkspaceTopologyLeaseHolderCommand
{
    public static async Task<int> RunAsync(string[] arguments)
    {
        if (arguments is not ["--namespace", var leaseNamespace])
        {
            throw new ToolValidationException(["workspace-topology-lease-holder requires --namespace <value>"]);
        }

        Environment.SetEnvironmentVariable("TERRASCALE_VALIDATION_LEASE_NAMESPACE", leaseNamespace);
        await using var lease = await WorkspaceTopologyLease.AcquireAsync(
            "development-lab", TimeSpan.FromSeconds(10));
        Console.WriteLine("held");
        await Console.Out.FlushAsync();
        _ = await Console.In.ReadLineAsync();
        return 0;
    }
}
