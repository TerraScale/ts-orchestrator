using System.Diagnostics;

namespace TerraScale.Orchestrator.Lab.SmolVm;

internal sealed class SmolVmServerSession : IAsyncDisposable
{
    private readonly Process process;
    private readonly CancellationTokenSource outputStopping;

    private SmolVmServerSession(
        Process process,
        CancellationTokenSource outputStopping,
        SmolVmV1_5OpenApiClient client)
    {
        this.process = process;
        this.outputStopping = outputStopping;
        Client = client;
    }

    public SmolVmV1_5OpenApiClient Client { get; }
    public int ProcessId => process.Id;

    public static async Task<SmolVmServerSession> StartAsync(
        SmolVmVerifiedInstallation installation,
        string socketPath,
        string dataDirectory,
        TimeSpan startupTimeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(installation);
        if (!Path.IsPathFullyQualified(socketPath) || !Path.IsPathFullyQualified(dataDirectory))
        {
            throw new ArgumentException("SmolVM socket and data paths must be absolute.");
        }
        if (socketPath.Length > 100)
        {
            throw new ArgumentException("The SmolVM Unix socket path exceeds the portable Linux limit.", nameof(socketPath));
        }
        if (Path.Exists(socketPath))
        {
            throw new InvalidOperationException("The private SmolVM socket path is already occupied.");
        }
        if (startupTimeout <= TimeSpan.Zero || startupTimeout > TimeSpan.FromMinutes(2))
        {
            throw new ArgumentOutOfRangeException(nameof(startupTimeout));
        }

        CreatePrivateDirectory(Path.GetDirectoryName(socketPath)!);
        CreatePrivateDirectory(dataDirectory);
        var process = new Process
        {
            StartInfo = CreateStartInfo(installation, socketPath, dataDirectory),
            EnableRaisingEvents = true
        };
        var outputStopping = new CancellationTokenSource();
        SmolVmV1_5OpenApiClient? client = null;
        try
        {
            process.Start();
            _ = PumpAsync(process.StandardOutput, Console.Out, outputStopping.Token);
            _ = PumpAsync(process.StandardError, Console.Error, outputStopping.Token);
            client = SmolVmV1_5OpenApiClient.ConnectUnixSocket(socketPath, TimeSpan.FromSeconds(15));
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(startupTimeout);
            while (true)
            {
                deadline.Token.ThrowIfCancellationRequested();
                if (process.HasExited)
                {
                    throw new InvalidOperationException(
                        $"SmolVM server exited during startup with code {process.ExitCode}.");
                }
                if (Path.Exists(socketPath))
                {
                    try
                    {
                        _ = await client.ListMachinesAsync(deadline.Token);
                        return new(process, outputStopping, client);
                    }
                    catch (HttpRequestException)
                    {
                    }
                }
                await Task.Delay(TimeSpan.FromMilliseconds(100), deadline.Token);
            }
        }
        catch
        {
            client?.Dispose();
            await outputStopping.CancelAsync();
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(CancellationToken.None);
            }
            process.Dispose();
            outputStopping.Dispose();
            throw;
        }
    }

    internal static ProcessStartInfo CreateStartInfo(
        SmolVmVerifiedInstallation installation,
        string socketPath,
        string dataDirectory)
    {
        if (installation.Version != SmolVmV1_5OpenApiClient.ApiVersion ||
            installation.Artifacts.All(artifact => artifact.Role != "launcher") ||
            installation.LauncherPath != installation.Artifacts.Single(artifact => artifact.Role == "launcher").Path)
        {
            throw new InvalidOperationException("SmolVM server startup requires the verified v1.5.0 launcher closure.");
        }
        var startInfo = new ProcessStartInfo(installation.LauncherPath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var argument in new[]
                 {
                     "serve", "start",
                     "--listen", $"unix://{socketPath}",
                     "--seccomp", "enforce",
                     "--landlock", "enforce",
                     "--json-logs"
                 })
        {
            startInfo.ArgumentList.Add(argument);
        }
        startInfo.Environment["SMOLVM_DATA_DIR"] = dataDirectory;
        return startInfo;
    }

    private static void CreatePrivateDirectory(string path)
    {
        Directory.CreateDirectory(path);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private static async Task PumpAsync(
        StreamReader reader,
        TextWriter writer,
        CancellationToken cancellationToken)
    {
        try
        {
            while (await reader.ReadLineAsync(cancellationToken) is { } line)
            {
                if (!string.IsNullOrWhiteSpace(line))
                {
                    await writer.WriteLineAsync($"[smolvm] {line}");
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await outputStopping.CancelAsync();
        if (!process.HasExited)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync(CancellationToken.None);
        }
        process.Dispose();
        outputStopping.Dispose();
    }
}
