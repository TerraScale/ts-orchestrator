using System.Diagnostics;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class HostWorkloadInventoryTests
{
    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    public async Task Interrupted_initialization_can_only_resume_an_empty_inventory(int stage)
    {
        await using var files = new HostInventoryFixture();
        files.Inventory.Dispose();
        File.Delete(Path.Combine(files.Directory, "owner.lock"));
        File.Delete(Path.Combine(files.Directory, "workloads.json"));
        await Assert.That(() => HostWorkloadInventory.Open(files.Directory, files.Identity, reached =>
        {
            if ((int)reached == stage) throw new IOException("Injected initial write interruption.");
        })).Throws<IOException>();
        using var recovered = HostWorkloadInventory.Open(files.Directory, files.Identity);
        await Assert.That(recovered.Plans).IsEmpty();
    }

    [Test]
    public async Task Hard_linked_inventory_files_and_linked_directory_ancestors_are_rejected()
    {
        await using var files = new HostInventoryFixture();
        files.Inventory.Dispose();
        var path = Path.Combine(files.Directory, "workloads.json");
        using (var link = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("ln")
        { ArgumentList = { path, path + ".alias" }, UseShellExecute = false })!)
        {
            await link.WaitForExitAsync();
            await Assert.That(link.ExitCode).IsEqualTo(0);
        }
        await Assert.That(Rejected(() => HostWorkloadInventory.Open(files.Directory, files.Identity))).IsTrue();
        File.Delete(path + ".alias");
        var alias = files.Directory + "-alias";
        Directory.CreateSymbolicLink(alias, files.Directory);
        try { await Assert.That(Rejected(() => HostWorkloadInventory.Open(alias, files.Identity))).IsTrue(); }
        finally { Directory.Delete(alias); }
    }

    [Test]
    [Arguments((int)AdmittedRole.Orchestrator)]
    [Arguments((int)AdmittedRole.TerraBaseMember)]
    [Arguments((int)AdmittedRole.ControlNatsServer)]
    public async Task Canonical_snapshot_and_fingerprint_preserve_custom_native_roots(int value)
    {
        await using var files = new HostInventoryFixture();
        var original = files.Plan((AdmittedRole)value);
        var custom = HostRuntimePlan.Create(original.Role, original.Driver, original.AllocationId, original.ArtifactDigest,
            original.Architecture, installRoot: "/srv/artifacts", stateRoot: "/srv/state");
        var copy = HostRuntimePlanSnapshot.Copy(custom);
        await Assert.That(CanonicalPlanFingerprint.Compute(copy)).IsEqualTo(CanonicalPlanFingerprint.Compute(custom));
        await Assert.That(CanonicalPlanFingerprint.Compute(copy)).IsNotEqualTo(CanonicalPlanFingerprint.Compute(original));
        await Assert.That(copy.Systemd!.Properties.Any(property => property.Contains("/srv/state/", StringComparison.Ordinal))).IsTrue();
    }

    [Test]
    public async Task Durable_roundtrip_preserves_both_drivers_and_exact_custom_root_plans()
    {
        await using var files = new HostInventoryFixture();
        var original = files.Plan();
        var native = HostRuntimePlan.Create(original.Role, original.Driver, original.AllocationId, original.ArtifactDigest,
            original.Architecture, installRoot: "/srv/artifacts", stateRoot: "/srv/state", encryptedWorkloadCredentials: true);
        var container = files.Plan(driver: RuntimeDriver.OciContainer);
        files.Inventory.Record(native);
        files.Inventory.Record(container);
        files.Inventory.Dispose();
        using var reopened = HostWorkloadInventory.Open(files.Directory, files.Identity);
        await Assert.That(reopened.Plans.Count).IsEqualTo(2);
        await Assert.That(reopened.Plans.Select(CanonicalPlanFingerprint.Compute))
            .IsEquivalentTo(new[] { CanonicalPlanFingerprint.Compute(native), CanonicalPlanFingerprint.Compute(container) });
        reopened.ForgetAbsent(RuntimeDriver.OciContainer, container.AllocationId.Value);
        await Assert.That(reopened.Plans.Single().Systemd!.Executable).IsEqualTo(native.Systemd!.Executable);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    public async Task Unconfirmed_write_poisoning_survives_restart_without_losing_committed_intent(int stage)
    {
        var fail = false;
        await using var files = new HostInventoryFixture(afterWrite: reached =>
        {
            if (fail && (int)reached == stage) throw new IOException("injected durability interruption");
        });
        fail = true;
        await Assert.That(() => files.Inventory.Record(files.Plan())).Throws<IOException>();
        await Assert.That(() => files.Inventory.Record(files.Plan())).Throws<InvalidOperationException>();
        files.Inventory.Dispose();
        using var recovered = HostWorkloadInventory.Open(files.Directory, files.Identity);
        await Assert.That(recovered.Plans.Count).IsEqualTo(stage == 0 ? 0 : 1);
    }

    [Test]
    [Arguments("missing-document")]
    [Arguments("corrupt-document")]
    [Arguments("missing-marker")]
    [Arguments("wrong-marker")]
    [Arguments("changed-fingerprint")]
    [Arguments("wrong-node")]
    public async Task Restart_rejects_lost_or_ambiguous_ownership(string kind)
    {
        await using var files = new HostInventoryFixture();
        files.Inventory.Record(files.Plan());
        files.Inventory.Dispose();
        var path = Path.Combine(files.Directory, "workloads.json");
        var marker = Path.Combine(files.Directory, "owner.lock");
        switch (kind)
        {
            case "missing-document": File.Delete(path); break;
            case "corrupt-document": File.WriteAllText(path, "{"); break;
            case "missing-marker": File.Delete(marker); break;
            case "wrong-marker": File.WriteAllText(marker, new string('b', 64)); break;
            case "changed-fingerprint":
                File.WriteAllText(path, File.ReadAllText(path).Replace(CanonicalPlanFingerprint.Compute(files.Plan()), new string('c', 64), StringComparison.Ordinal));
                break;
        }
        await Assert.That(Rejected(() => HostWorkloadInventory.Open(files.Directory,
            kind == "wrong-node" ? new("gru", "host-2", "production") : files.Identity))).IsTrue();
    }

    [Test]
    [Arguments("owner.lock")]
    [Arguments("workloads.json")]
    public async Task Rejects_FIFO_and_symlink_without_opening_them(string name)
    {
        await using var files = new HostInventoryFixture();
        files.Inventory.Dispose();
        var path = Path.Combine(files.Directory, name);
        File.Delete(path);
        using (var fifo = Process.Start(new ProcessStartInfo("mkfifo") { ArgumentList = { "-m", "600", path }, UseShellExecute = false })!)
        {
            await fifo.WaitForExitAsync();
            await Assert.That(fifo.ExitCode).IsEqualTo(0);
        }
        await Assert.That(Rejected(() => HostWorkloadInventory.Open(files.Directory, files.Identity))).IsTrue();
        File.Delete(path);
        File.CreateSymbolicLink(path, Path.Combine(files.Directory, "missing"));
        await Assert.That(Rejected(() => HostWorkloadInventory.Open(files.Directory, files.Identity))).IsTrue();
    }

    [Test]
    [Arguments("directory-mode")]
    [Arguments("file-mode")]
    [Arguments("replace-lock")]
    [Arguments("erase-marker")]
    [Arguments("erase-document")]
    [Arguments("change-document")]
    public async Task Active_supervisor_rechecks_storage_before_another_dispatch(string kind)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        await using var files = new HostInventoryFixture();
        var path = Path.Combine(files.Directory, "workloads.json");
        var marker = Path.Combine(files.Directory, "owner.lock");
        switch (kind)
        {
            case "directory-mode": File.SetUnixFileMode(files.Directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead); break;
            case "file-mode": File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead); break;
            case "replace-lock": File.Move(marker, marker + ".old"); File.WriteAllText(marker, ""); break;
            case "erase-marker":
                // The OS lock is advisory; simulate accidental owner-side truncation through another descriptor.
                using (var command = Process.Start(new ProcessStartInfo("truncate") { ArgumentList = { "-s", "0", marker }, UseShellExecute = false })!) await command.WaitForExitAsync();
                break;
            case "erase-document": File.Delete(path); break;
            case "change-document": File.AppendAllText(path, " "); break;
        }
        await Assert.That(Rejected(() => { files.Inventory.Record(files.Plan()); return null; })).IsTrue();
    }

    [Test]
    public async Task Recorded_snapshot_is_detached_and_systemd_fingerprint_binds_execution_fields()
    {
        await using var files = new HostInventoryFixture();
        var plan = files.Plan();
        var properties = plan.Systemd!.Properties.ToArray();
        var mutable = plan with { Systemd = plan.Systemd with { Properties = properties } };
        var recorded = files.Inventory.Record(mutable);
        properties[0] = "Type=oneshot";
        await Assert.That(recorded.Systemd!.Properties[0]).IsEqualTo("Type=exec");
        foreach (var altered in new[] {
            plan with { Systemd = plan.Systemd with { Executable = "/tmp/different" } },
            plan with { Systemd = plan.Systemd with { Arguments = ["unexpected"] } },
            mutable })
            await Assert.That(CanonicalPlanFingerprint.Compute(altered)).IsNotEqualTo(CanonicalPlanFingerprint.Compute(recorded));
        await Assert.That(Rejected(() => { files.Inventory.Record(mutable); return null; })).IsTrue();
        await Assert.That(Rejected(() => { files.Inventory.Record(plan with { AllocationId = new("foreign-host") }); return null; })).IsTrue();
    }

    internal static bool Rejected(Func<IDisposable?> action)
    {
        try { using var result = action(); return false; }
        catch (Exception exception) when (exception is IOException or InvalidDataException or JsonException or InvalidOperationException or ArgumentException)
        { return true; }
    }
}
