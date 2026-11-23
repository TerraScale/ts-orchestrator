using System.Text.Json;

namespace TsOrch.Cli;

internal sealed record class NetBirdLocalState(
    string DaemonState,
    string? Ip,
    string? Fqdn,
    bool ManagementConnected,
    bool SignalConnected,
    int PeerCount,
    bool? SshServerEnabled,
    string? ManagementUrl)
{
    public bool Connected => ManagementConnected && SignalConnected;
}

internal sealed record class NetBirdClientMissing;

internal sealed record class NetBirdLocalStatusUnreadable;

internal sealed record class NetBirdConnectionFailed(CliDiagnostic Diagnostic);

internal readonly union NetBirdLocalStatus(NetBirdLocalState, NetBirdClientMissing, NetBirdLocalStatusUnreadable);

internal readonly union NetBirdConnection(NetBirdLocalState, NetBirdConnectionFailed);

internal sealed class NetBirdClient(TimeProvider timeProvider)
{
    public const string InstallInstructions = "Install NetBird with: curl -fsSL https://pkgs.netbird.io/install.sh | sh";

    private const int FileNotFoundError = 2;

    private static readonly TimeSpan StatusTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(75);
    private static readonly TimeSpan ConnectionTimeout = TimeSpan.FromSeconds(45);
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);
    private static readonly string[] CredentialVariables = ["NB_SETUP_KEY", "NB_SETUP_KEY_FILE"];

    public async Task<NetBirdLocalStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        var outcome = await RunAsync(["status", "--json"], null, StatusTimeout, cancellationToken);
        return outcome switch
        {
            ProcessResult { ExitCode: 0 } result => ParseStatus(result.Stdout),
            ProcessResult => new NetBirdLocalStatusUnreadable(),
            ProcessLaunchFailed { NativeErrorCode: FileNotFoundError } => new NetBirdClientMissing(),
            ProcessLaunchFailed => new NetBirdLocalStatusUnreadable(),
        };
    }

    public async Task<NetBirdConnection> ConnectAsync(
        Uri url, string? hostname, NetBirdCredential? credential, bool disableServerSsh, CancellationToken cancellationToken)
    {
        List<string> arguments = ["up", "--management-url", url.AbsoluteUri.TrimEnd('/'), "--no-browser"];
        if (hostname is not null)
        {
            arguments.AddRange(["--hostname", hostname]);
        }

        if (disableServerSsh)
        {
            arguments.Add("--allow-server-ssh=false");
        }

        if (credential is not null)
        {
            arguments.AddRange(["--setup-key-file", "/dev/stdin"]);
        }

        var outcome = await RunAsync(arguments, credential?.Value, CommandTimeout, cancellationToken);
        return outcome switch
        {
            ProcessResult { ExitCode: 0 } => await WaitConnectedAsync(url, disableServerSsh, cancellationToken),
            ProcessResult => new NetBirdConnectionFailed(CliDiagnostic.Unavailable("NetBird up failed. Check the daemon and enrollment credentials.")),
            ProcessLaunchFailed => new NetBirdConnectionFailed(CliDiagnostic.Unavailable("NetBird up could not run to completion.")),
        };
    }

    public async Task<NetBirdConnection> DisableServerSshAsync(Uri url, string? hostname, CancellationToken cancellationToken)
    {
        var outcome = await RunAsync(["down"], null, CommandTimeout, cancellationToken);
        return outcome switch
        {
            ProcessResult { ExitCode: 0 } => await ConnectAsync(url, hostname, null, disableServerSsh: true, cancellationToken),
            ProcessResult or ProcessLaunchFailed
                => new NetBirdConnectionFailed(CliDiagnostic.Unavailable("NetBird could not reconnect with its SSH server disabled.")),
        };
    }

    private async Task<NetBirdConnection> WaitConnectedAsync(Uri url, bool disableServerSsh, CancellationToken cancellationToken)
    {
        var startedAt = timeProvider.GetTimestamp();
        while (timeProvider.GetElapsedTime(startedAt) < ConnectionTimeout)
        {
            var outcome = await GetStatusAsync(cancellationToken);
            var connected = outcome switch
            {
                NetBirdLocalState { Connected: true } state => state,
                NetBirdLocalState or NetBirdClientMissing or NetBirdLocalStatusUnreadable => null,
            };
            if (connected is { } active)
            {
                if (IsOtherManagementUrl(active, url))
                {
                    return new NetBirdConnectionFailed(CliDiagnostic.Unavailable("NetBird is connected to a different management URL."));
                }

                if (disableServerSsh is false || active.SshServerEnabled is false)
                {
                    return active;
                }

                if (active.SshServerEnabled is null)
                {
                    return new NetBirdConnectionFailed(CliDiagnostic.Unavailable("NetBird daemon status does not report whether its SSH server is enabled."));
                }
            }

            await Task.Delay(PollInterval, timeProvider, cancellationToken);
        }

        return new NetBirdConnectionFailed(CliDiagnostic.Unavailable(disableServerSsh
            ? "NetBird did not report connected management and signal with its SSH server disabled."
            : "NetBird management and signal did not both connect."));
    }

    public static bool IsOtherManagementUrl(NetBirdLocalState state, Uri expected) =>
        NetBirdApi.ParseUrl(state.ManagementUrl) is { } observed && (observed == expected) is false;

    private async Task<ProcessExecution> RunAsync(
        IReadOnlyList<string> arguments, string? input, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var deadline = new CancellationTokenSource(timeout, timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            return await ExternalProcess.RunWithInputAsync("netbird", arguments, input, CredentialVariables, linked.Token);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested is false)
        {
            return new ProcessLaunchFailed("netbird", "Timed out.");
        }
    }

    private static NetBirdLocalStatus ParseStatus(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            var management = NetBirdJson.Property(root, "management");
            var signal = NetBirdJson.Property(root, "signal");
            if (NetBirdJson.Text(root, "daemonStatus") is not { } daemonStatus
                || NetBirdJson.Boolean(management, "connected") is not { } managementConnected
                || NetBirdJson.Boolean(signal, "connected") is not { } signalConnected)
            {
                return new NetBirdLocalStatusUnreadable();
            }

            var peers = NetBirdJson.Property(root, "peers");
            var ssh = NetBirdJson.Property(root, "sshServer");
            return new NetBirdLocalState(
                daemonStatus,
                NetBirdJson.Text(root, "netbirdIp"),
                NetBirdJson.Text(root, "fqdn"),
                managementConnected,
                signalConnected,
                NetBirdJson.Number(peers, "total") ?? 0,
                NetBirdJson.Boolean(ssh, "enabled"),
                NetBirdApi.ParseUrl(NetBirdJson.Text(management, "url"))?.AbsoluteUri.TrimEnd('/'));
        }
        catch (JsonException)
        {
            return new NetBirdLocalStatusUnreadable();
        }
    }
}
