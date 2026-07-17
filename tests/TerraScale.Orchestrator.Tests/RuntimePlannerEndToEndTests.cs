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
            "--role", "platform",
            "--driver", "oci",
            "--allocation", "gru-platform-1",
            "--digest", Digest,
            "--architecture", "arm64");

        await Assert.That(accepted.ExitCode).IsEqualTo(0);
        await Assert.That(accepted.StandardError).IsEmpty();
        using var document = JsonDocument.Parse(accepted.StandardOutput);
        var root = document.RootElement;
        await Assert.That(root.GetProperty("role").GetString()).IsEqualTo("platform");
        await Assert.That(root.GetProperty("driver").GetString()).IsEqualTo("ociContainer");
        await Assert.That(root.GetProperty("oci").GetProperty("imageReference").GetString())
            .IsEqualTo($"registry.terrascale.internal/terrascale/terrascale-platform@sha256:{Digest}");
        await Assert.That(root.GetProperty("oci").GetProperty("security")
            .GetProperty("noNewPrivileges").GetBoolean()).IsTrue();

        var rejected = await RunAsync(
            "runtime", "plan",
            "--role", "arbitrary-container",
            "--allocation", "gru-platform-1",
            "--digest", Digest);

        await Assert.That(rejected.ExitCode).IsEqualTo(1);
        await Assert.That(rejected.StandardOutput).IsEmpty();
        await Assert.That(rejected.StandardError).Contains("Unknown or unadmitted role");
    }

    [Test]
    public async Task ExecutablePlansTheSmallRegionalControlPlaneLab()
    {
        var planned = await RunAsync("lab", "plan", "--profile", "dev-containers-control");

        await Assert.That(planned.ExitCode).IsEqualTo(0);
        await Assert.That(planned.StandardError).IsEmpty();
        using var document = JsonDocument.Parse(planned.StandardOutput);
        var root = document.RootElement;
        await Assert.That(root.GetProperty("profile").GetString())
            .IsEqualTo("dev-containers-control-three-cell-lean");
        await Assert.That(root.GetProperty("cells").GetArrayLength()).IsEqualTo(3);
        await Assert.That(root.GetProperty("globalResources").GetArrayLength()).IsEqualTo(0);
        var resources = root.GetProperty("cells")
            .EnumerateArray()
            .SelectMany(cell => cell.GetProperty("resources").EnumerateArray())
            .ToArray();
        await Assert.That(resources.Length).IsEqualTo(6);
        await Assert.That(resources.Select(resource => resource.GetProperty("kind").GetString()!))
            .IsEquivalentTo([
                "controlNats", "controllerAgent",
                "controlNats", "controllerAgent",
                "controlNats", "controllerAgent"
            ]);
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
