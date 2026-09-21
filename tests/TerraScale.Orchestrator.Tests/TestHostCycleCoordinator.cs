using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

/// <summary>Controlled cycle boundary for native lifecycle tests; durable behavior has real R3 coverage.</summary>
internal sealed class TestHostCycleCoordinator : IHostCycleCoordinator
{
    internal bool AllowBegin { get; set; } = true;
    internal bool Unavailable { get; init; }
    internal bool FailFlush { get; set; }
    internal List<(HostConvergenceCycle Cycle, bool Succeeded)> Outcomes { get; } = [];
    internal int Flushed { get; private set; }
    public Task FlushAsync(AdmittedRole role, CancellationToken cancellationToken)
    {
        Flushed++;
        if (FailFlush) throw new IOException("Injected pending outcome failure.");
        return Task.CompletedTask;
    }
    public Task<HostConvergenceCycle?> BeginAsync(AdmittedRole role, string environment, string cell, string digest, CancellationToken cancellationToken)
    {
        if (Unavailable) throw new IOException("Injected cycle storage failure.");
        return Task.FromResult(AllowBegin ? new HostConvergenceCycle(role, digest, Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), 1) : null);
    }
    public Task FinishAsync(HostConvergenceCycle cycle, bool succeeded, CancellationToken cancellationToken)
    {
        Outcomes.Add((cycle, succeeded));
        return Task.CompletedTask;
    }
}
