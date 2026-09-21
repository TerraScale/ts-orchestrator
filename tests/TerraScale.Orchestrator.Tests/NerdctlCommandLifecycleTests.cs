using System.Diagnostics;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class NerdctlCommandLifecycleTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Cancelled_command_is_rejected_before_process_start(bool containerd)
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var missing = Path.Combine(Path.GetTempPath(), "missing-host-command-" + Guid.NewGuid().ToString("N"));
        // An attempted start throws Win32Exception. Cancellation must win before dispatch.
        await Assert.That(async () =>
        {
            if (containerd) await new NerdctlContainerdClient(missing).StartAsync("terrascale", "test", cancellation.Token);
            else await new ProcessHostCommandRunner().RunAsync(missing, [], cancellation.Token);
        }).Throws<OperationCanceledException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Output_overflow_aborts_the_command_and_its_waiting_descendant(bool standardError)
    {
        if (!OperatingSystem.IsLinux()) return;
        using var command = new CommandFixture(standardError
            ? "printf '%05000000d' 0 >&2; wait"
            : "printf '%05000000d' 0; wait");
        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var execution = new NerdctlContainerdClient(command.Executable).StartAsync("terrascale", "test", cleanup.Token);
        try
        {
            var child = await command.ReleaseAsync(cleanup.Token);
            await Assert.That(async () => await execution.WaitAsync(TimeSpan.FromSeconds(5)))
                .Throws<InvalidOperationException>();
            await Assert.That(cleanup.IsCancellationRequested).IsFalse();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await LinuxTestProcess.WaitForTerminationAsync(child.Pid, child.StartTicks, deadline.Token);
        }
        finally
        {
            await cleanup.CancelAsync();
            try { await execution.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (Exception) { /* The assertion above owns the failure; cleanup must settle the command. */ }
        }
    }

    [Test]
    public async Task Output_at_the_limit_succeeds_without_exposing_command_output()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var command = new CommandFixture("printf '%065536d' 0; printf '%065536d' 0 >&2", child: false);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await new NerdctlContainerdClient(command.Executable).StartAsync("terrascale", "test", deadline.Token);
    }

    private sealed class CommandFixture : IDisposable
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "ts-command-lifecycle-" + Guid.NewGuid().ToString("N"));
        private readonly string pidPath;
        private readonly string releasePath;
        private LinuxTestProcess? spawnedChild;
        internal string Executable { get; }

        internal CommandFixture(string body, bool child = true)
        {
            Directory.CreateDirectory(directory);
            Executable = Path.Combine(directory, "nerdctl");
            pidPath = Path.Combine(directory, "child");
            releasePath = Path.Combine(directory, "release");
            var sleep = TestHostExecutables.Resolve("sleep");
            var spawn = child ? $"'{sleep}' 60 &\nchild=$!\nprintf '%s' \"$child\" > '{pidPath}'\nwhile [ ! -e '{releasePath}' ]; do '{sleep}' 0.01; done\n" : "";
            File.WriteAllText(Executable, $"#!{TestHostExecutables.Resolve("bash")}\n{spawn}{body}\n");
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(Executable, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        internal async Task<LinuxTestProcess> ReleaseAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (File.Exists(pidPath) && int.TryParse(await File.ReadAllTextAsync(pidPath, cancellationToken), out var pid))
                {
                    spawnedChild = LinuxTestProcess.Read(pid) ?? throw new InvalidOperationException("The command descendant exited before the test began.");
                    await File.WriteAllTextAsync(releasePath, "go", cancellationToken);
                    return spawnedChild;
                }
                await Task.Delay(10, cancellationToken);
            }
        }

        public void Dispose()
        {
            if (spawnedChild is { } child)
            {
                var observed = LinuxTestProcess.Read(child.Pid);
                if (observed is { Terminated: false } && observed.StartTicks == child.StartTicks)
                {
                    try { using var process = Process.GetProcessById(child.Pid); process.Kill(); }
                    catch (ArgumentException) { }
                    catch (InvalidOperationException) { }
                }
            }
            Directory.Delete(directory, recursive: true);
        }
    }
}
