using System.Diagnostics;
using System.Text.Json;

namespace TerraScale.Orchestrator.Tests;

public sealed class RuntimePlannerEndToEndTests
{
    private const string Digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    public async Task ExecutablePlansAnAdmittedContainerAndRejectsAnArbitraryRole()
    {
        var accepted = await RunAsync(
            "runtime", "plan",
            "--role", "customer-dashboard",
            "--driver", "oci",
            "--allocation", "gru-dashboard-1",
            "--digest", Digest,
            "--architecture", "arm64");

        await Assert.That(accepted.ExitCode).IsEqualTo(0);
        await Assert.That(accepted.StandardError).IsEmpty();
        using var document = JsonDocument.Parse(accepted.StandardOutput);
        var root = document.RootElement;
        await Assert.That(root.GetProperty("role").GetString()).IsEqualTo("customerDashboard");
        await Assert.That(root.GetProperty("driver").GetString()).IsEqualTo("ociContainer");
        await Assert.That(root.GetProperty("oci").GetProperty("imageReference").GetString())
            .IsEqualTo($"registry.terrascale.internal/terrascale/terrascale-dashboard@sha256:{Digest}");
        await Assert.That(root.GetProperty("oci").GetProperty("security")
            .GetProperty("noNewPrivileges").GetBoolean()).IsTrue();

        var rejected = await RunAsync(
            "runtime", "plan",
            "--role", "arbitrary-container",
            "--allocation", "gru-dashboard-1",
            "--digest", Digest);

        await Assert.That(rejected.ExitCode).IsEqualTo(1);
        await Assert.That(rejected.StandardOutput).IsEmpty();
        await Assert.That(rejected.StandardError).Contains("Unknown or unadmitted role");

        var removedRole = await RunAsync(
            "runtime", "plan",
            "--role", "mcp-server",
            "--allocation", "gru-mcp-1",
            "--digest", Digest);

        await Assert.That(removedRole.ExitCode).IsEqualTo(1);
        await Assert.That(removedRole.StandardOutput).IsEmpty();
        await Assert.That(removedRole.StandardError).Contains("Unknown or unadmitted role");
    }

    private static async Task<(int ExitCode, string StandardOutput, string StandardError)> RunAsync(
        params string[] arguments)
    {
        using var process = new Process
        {
            StartInfo = new(Path.Combine(AppContext.BaseDirectory, "terrascale-orchestrator"))
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            }
        };
        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }
        process.Start();
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, await output, await error);
    }
}

