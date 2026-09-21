using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

internal sealed class HostInventoryFixture : IAsyncDisposable
{
    internal string Directory { get; } = Path.Combine(Path.GetTempPath(), "ts-host-inventory-" + Guid.NewGuid().ToString("N"));
    internal HostWorkloadIdentity Identity { get; }
    internal HostWorkloadInventory Inventory { get; }
    internal static IHostNativeInventoryProbe EmptyProbe { get; } = new Probe();

    internal HostInventoryFixture(string node = "host-1", Action<HostInventoryWriteStage>? afterWrite = null)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        System.IO.Directory.CreateDirectory(Directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        Identity = new("gru", node, "production");
        Inventory = HostWorkloadInventory.Open(Directory, Identity, afterWrite);
    }

    internal HostRuntimePlan Plan(AdmittedRole role = AdmittedRole.TerraBaseMember, char digest = 'a', RuntimeDriver? driver = null) =>
        HostRuntimePlan.Create(role, driver ?? AdmittedRoleCatalog.Get(role).DefaultDriver,
            HostConvergenceRuntime.AllocationIdFor(Identity.Cell, Identity.NodeId, AdmittedRoleCatalog.Get(role).ArtifactKey),
            new(new string(digest, 64)), HostArchitecture.X64);

    public async ValueTask DisposeAsync()
    {
        try { Inventory.Dispose(); }
        catch (InvalidOperationException)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (!Inventory.IsDisposed) await Task.Delay(5, deadline.Token);
        }
        System.IO.Directory.Delete(Directory, recursive: true);
    }

    internal sealed class Probe : IHostNativeInventoryProbe
    {
        internal Func<HostWorkloadIdentity, CancellationToken, Task<HostNativeInventorySnapshot>> Read { get; set; } =
            (_, _) => Task.FromResult(new HostNativeInventorySnapshot([RuntimeDriver.NativeSystemd, RuntimeDriver.OciContainer], []));
        public Task<HostNativeInventorySnapshot> ReadAsync(HostWorkloadIdentity identity, CancellationToken cancellationToken) => Read(identity, cancellationToken);
    }
}
