using System.Diagnostics;
using System.Text;
using System.Net.Http.Json;

namespace TerraScale.Orchestrator.Nodes;

/// <summary>
/// One TerraBase member running as a real child process. The caller supplies
/// the complete member environment (TERRABASE_* variables); this host owns the
/// process lifecycle: start, readiness on the loopback observability listener,
/// metrics scraping, graceful stop with kill escalation, and hard kill for
/// host-loss scenarios.
/// </summary>
public sealed class MemberProcessHost : IAsyncDisposable
{
    private const string MemberEnabledVariable = "TERRABASE_MEMBER_ENABLED";
    private const string PeerUrlVariable = "TERRABASE_PEER_URL";
    private const string ObservabilityUrlVariable = "TERRABASE_OBSERVABILITY_URL";

    private readonly HttpClient http = new() { Timeout = TimeSpan.FromSeconds(5) };
    private readonly StringBuilder output = new();
    private readonly string observabilityUrl;
    private readonly int peerPort;
    private Process? process;

    private MemberProcessHost(string observabilityUrl, int peerPort)
    {
        this.observabilityUrl = observabilityUrl;
        this.peerPort = peerPort;
    }

    /// <summary>Launches one member and waits for its readiness endpoint.</summary>
    /// <param name="member">The member launch description.</param>
    /// <param name="timeout">How long to wait for readiness.</param>
    /// <returns>The started member host.</returns>
    public static async Task<MemberProcessHost> StartAsync(MemberLaunchDescription member, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(member);
        var host = new MemberProcessHost($"http://127.0.0.1:{member.ObservabilityPort}", member.PeerPort);
        var info = new ProcessStartInfo
        {
            FileName = member.DotNetPath,
            Arguments = $"\"{member.HostAssemblyPath}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = member.WorkingDirectory,
        };
        foreach (var (variable, value) in member.Environment)
        {
            info.Environment[variable] = value;
        }

        info.Environment[MemberEnabledVariable] = "true";
        info.Environment[PeerUrlVariable] = $"https://127.0.0.1:{member.PeerPort}";
        info.Environment[ObservabilityUrlVariable] = $"http://127.0.0.1:{member.ObservabilityPort}";

        host.process = Process.Start(info) ?? throw new InvalidOperationException(
            $"The TerraBase member {member.NodeId} could not be started.");
        host.CaptureOutput();
        if (await host.WaitUntilReadyAsync(timeout))
        {
            return host;
        }

        var diagnostics = host.process.HasExited
            ? $"exit={host.process.ExitCode} output:{host.OutputTail()}"
            : $"running but never ready output:{host.OutputTail()}";
        await host.DisposeAsync();
        throw new TimeoutException(
            $"The TerraBase member {member.NodeId} did not become ready within {timeout}: {diagnostics}.");
    }

    /// <summary>Whether the member process is still alive.</summary>
    public bool IsAlive => process is { HasExited: false };

    /// <summary>The member's peer listener port.</summary>
    public int PeerPort => peerPort;

    private void CaptureOutput()
    {
        if (process is null)
        {
            return;
        }

        process.OutputDataReceived += (_, eventArgs) =>
        {
            if (eventArgs.Data is { Length: > 0 })
            {
                lock (output) { output.AppendLine(eventArgs.Data); }
            }
        };
        process.ErrorDataReceived += (_, eventArgs) =>
        {
            if (eventArgs.Data is { Length: > 0 })
            {
                lock (output) { output.AppendLine(eventArgs.Data); }
            }
        };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
    }

    private string OutputTail()
    {
        lock (output)
        {
            var text = output.ToString();
            return text.Length <= 4000 ? text : text[^4000..];
        }
    }

    /// <summary>
    /// Observes member health and replication lag from the loopback
    /// observability listener. A member that answers its health endpoint with
    /// a success code is up; the replication lag gauge is read when present.
    /// </summary>
    public async Task<MemberObservation> ObserveAsync(CancellationToken cancellationToken = default)
    {
        if (!IsAlive)
        {
            return new MemberObservation(false, 0);
        }

        try
        {
            using var response = await http.GetAsync($"{observabilityUrl}/api/v1/health", cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return new MemberObservation(false, 0);
            }

            var lag = await ScrapeReplicationLagAsync(cancellationToken);
            return new MemberObservation(true, lag);
        }
        catch (HttpRequestException)
        {
            return new MemberObservation(false, 0);
        }
        catch (TaskCanceledException)
        {
            return new MemberObservation(false, 0);
        }
    }

    private async Task<long> ScrapeReplicationLagAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var metrics = await http.GetAsync($"{observabilityUrl}/internal/metrics", cancellationToken);
            if (!metrics.IsSuccessStatusCode)
            {
                return 0;
            }

            var body = await metrics.Content.ReadAsStringAsync(cancellationToken);
            var total = 0L;
            foreach (var line in body.Split('\n'))
            {
                if (!line.StartsWith("terrabase_replication_lag_sequences", StringComparison.Ordinal))
                {
                    continue;
                }

                var separator = line.LastIndexOf('}');
                var valueText = separator < 0 ? line.Split(' ')[^1] : line[(separator + 1)..].Trim();
                if (long.TryParse(valueText, out var value) && value > 0)
                {
                    total += value;
                }
            }

            return total;
        }
        catch (HttpRequestException)
        {
            return 0;
        }
        catch (TaskCanceledException)
        {
            return 0;
        }
    }

    /// <summary>
    /// Stops the member gracefully with SIGTERM — the host flips its metrics
    /// to draining and exits cleanly — escalating to SIGKILL after the grace
    /// period.
    /// </summary>
    public async Task StopAsync(TimeSpan grace)
    {
        if (process is { } alive && !alive.HasExited)
        {
            SendSignal(alive.Id, "TERM");
            var exited = await Task.Run(() => alive.WaitForExit((int)grace.TotalMilliseconds), CancellationToken.None);
            if (!exited)
            {
                SendSignal(alive.Id, "KILL");
                await Task.Run(() => alive.WaitForExit(5000), CancellationToken.None);
            }
        }
    }

    /// <summary>Kills the member immediately; used to simulate host loss.</summary>
    public void Kill()
    {
        if (process is { } alive && !alive.HasExited)
        {
            SendSignal(alive.Id, "KILL");
            alive.WaitForExit(5000);
        }
    }

    private static void SendSignal(int processId, string signal)
    {
        using var killer = Process.Start(new ProcessStartInfo
        {
            FileName = "kill",
            Arguments = $"-{signal} {processId}",
            UseShellExecute = false,
            CreateNoWindow = true,
        });
        killer?.WaitForExit(2000);
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync(TimeSpan.FromSeconds(10));
        process?.Dispose();
        http.Dispose();
        GC.SuppressFinalize(this);
    }

    private async Task<bool> WaitUntilReadyAsync(TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        while (!cancellation.IsCancellationRequested)
        {
            if (process is { HasExited: true })
            {
                return false;
            }

            try
            {
                using var response = await http.GetAsync($"{observabilityUrl}/health/ready", cancellation.Token);
                if (response.IsSuccessStatusCode)
                {
                    return true;
                }
            }
            catch (HttpRequestException)
            {
            }
            catch (TaskCanceledException)
            {
                return false;
            }

            await Task.Delay(200, cancellation.Token);
        }

        return false;
    }
}

/// <summary>One observed member state for autoscaler snapshots.</summary>
public sealed record MemberObservation(bool Up, long ReplicationLagSequences);
