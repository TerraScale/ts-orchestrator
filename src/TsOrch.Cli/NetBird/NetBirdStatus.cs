using System.Globalization;
using System.Text.Json;

namespace TsOrch.Cli;

internal sealed record class NetBirdStatusOptions(string? FleetPath = null, string? Api = null, string? PatFile = null);

internal sealed record class NetBirdFleetState(
    string ManagementUrl,
    string? DnsDomain,
    bool? SetupRequired = null,
    bool? ServerEnrollmentReady = null,
    bool? OperatorEnrollmentReady = null,
    string? Problem = null);

internal sealed record class NetBirdStatusReport(NetBirdLocalState? Local, string? LocalProblem, NetBirdFleetState? Fleet, string? FleetProblem)
{
    public string ToJson() => JsonSerializer.Serialize(this, CliJsonContext.Default.NetBirdStatusReport);

    public void Write(TextWriter output)
    {
        if (Local is { } local)
        {
            output.WriteLine(string.Create(CultureInfo.InvariantCulture,
                $"Local NetBird: {local.DaemonState}, IP {local.Ip ?? "unassigned"}, FQDN {local.Fqdn ?? "unassigned"}, {local.PeerCount} peers"));
            output.WriteLine($"  Management: {Connected(local.ManagementConnected)}, signal: {Connected(local.SignalConnected)}");
        }
        else
        {
            output.WriteLine($"Local NetBird: {LocalProblem}");
        }

        if (Fleet is { } fleet)
        {
            output.WriteLine($"Fleet NetBird: {fleet.ManagementUrl}, DNS {fleet.DnsDomain ?? "unknown"}");
            output.WriteLine($"  Server enrollment: {Ready(fleet.ServerEnrollmentReady)}, operator enrollment: {Ready(fleet.OperatorEnrollmentReady)}");
            if (fleet.Problem is { } problem)
            {
                output.WriteLine($"  {problem}");
            }
        }
        else if (FleetProblem is { } problem)
        {
            output.WriteLine($"Fleet NetBird: {problem}");
        }
    }

    private static string Connected(bool connected) => connected ? "connected" : "disconnected";

    private static string Ready(bool? ready) => ready switch
    {
        true => "ready",
        false => "not ready",
        null => "unknown",
    };
}

internal sealed class NetBirdStatus(OrchApi backplane, TimeProvider timeProvider)
{
    public async Task<NetBirdStatusReport> ReadAsync(NetBirdStatusOptions options, CancellationToken cancellationToken)
    {
        var outcome = await new NetBirdClient(timeProvider).GetStatusAsync(cancellationToken);
        var local = outcome switch
        {
            NetBirdLocalState state => new NetBirdStatusReport(state, null, null, null),
            NetBirdClientMissing => new NetBirdStatusReport(null, NetBirdClient.InstallInstructions, null, null),
            NetBirdLocalStatusUnreadable => new NetBirdStatusReport(null, "Could not read NetBird daemon status.", null, null),
        };
        var observedUrl = local.Local?.ManagementUrl ?? Environment.GetEnvironmentVariable("TS_ORCH_NETBIRD_URL");
        var fleet = await ReadFleetAsync(options, observedUrl, cancellationToken);
        return local with { Fleet = fleet.State, FleetProblem = fleet.Problem };
    }

    private async Task<FleetReport> ReadFleetAsync(NetBirdStatusOptions options, string? observedUrl, CancellationToken cancellationToken)
    {
        if (options.Api is not null && options.FleetPath is null)
        {
            return await ProbeAsync(options, null, cancellationToken);
        }

        var outcome = await NetBirdFleet.LoadAsync(backplane, options.FleetPath, cancellationToken);
        return outcome switch
        {
            FleetConfig { NetBird: null } fleet when options.PatFile is not null && observedUrl is not null
                => await ProbeAsync(options with { Api = observedUrl }, fleet, cancellationToken),
            FleetConfig fleet => await ProbeAsync(options, fleet, cancellationToken),
            NetBirdFleetUnavailable when options.FleetPath is null && options.PatFile is not null && observedUrl is not null
                => await ProbeAsync(options with { Api = observedUrl }, null, cancellationToken),
            NetBirdFleetUnavailable unavailable => new FleetReport(null, unavailable.Diagnostic.Message),
        };
    }

    private async Task<FleetReport> ProbeAsync(NetBirdStatusOptions options, FleetConfig? fleet, CancellationToken cancellationToken)
    {
        var config = fleet?.NetBird;
        if (NetBirdApi.ParseUrl(options.Api ?? config?.ManagementUrl) is not { } url)
        {
            return new FleetReport(null, options.Api is null && config is null
                ? "Fleet configuration has no NetBird management URL."
                : "NetBird management URL needs an HTTPS origin or a loopback HTTP origin.");
        }

        var state = new NetBirdFleetState(url.AbsoluteUri.TrimEnd('/'), config?.DnsDomain);
        using var api = new NetBirdApi(url, timeProvider);
        var outcome = await api.GetInstanceAsync(cancellationToken);
        state = outcome switch
        {
            NetBirdInstance { SetupRequired: true } => state with { SetupRequired = true, ServerEnrollmentReady = false, OperatorEnrollmentReady = false },
            NetBirdInstance => state with { SetupRequired = false },
            NetBirdApiProblem problem => state with { Problem = NetBirdApi.Describe(problem).Message },
        };
        if (state.SetupRequired is true)
        {
            return new FleetReport(state, null);
        }

        NetBirdCredentialRead token;
        if (options.PatFile is { } patFile)
        {
            token = await NetBirdCredentials.ReadFileAsync(patFile, cancellationToken);
        }
        else if (config is not null && fleet is not null && state.SetupRequired is false)
        {
            token = await NetBirdCredentials.ReadAsync(null, fleet.Oci.Vault, config.AdminPatSecret, timeProvider, cancellationToken);
        }
        else
        {
            return new FleetReport(state, null);
        }

        state = token switch
        {
            NetBirdCredential credential when NetBirdCredentials.IsToken(credential.Value)
                => await ReadReadinessAsync(api, credential, fleet, state, cancellationToken),
            NetBirdCredential => state with { Problem = "The NetBird admin PAT has an invalid format." },
            NetBirdCredentialUnavailable unavailable => state with { Problem = unavailable.Diagnostic.Message },
        };
        return new FleetReport(state, null);
    }

    private async Task<NetBirdFleetState> ReadReadinessAsync(
        NetBirdApi api, NetBirdCredential token, FleetConfig? fleet, NetBirdFleetState state, CancellationToken cancellationToken)
    {
        api.Token = token;
        var management = new NetBirdManagement(api, timeProvider);
        var account = await management.GetAccountAsync(cancellationToken);
        return account switch
        {
            NetBirdAccount current => await ReadGroupsAsync(management, fleet, state with { DnsDomain = current.DnsDomain ?? state.DnsDomain }, cancellationToken),
            NetBirdApiProblem problem => state with { Problem = NetBirdApi.Describe(problem).Message },
        };
    }

    private async Task<NetBirdFleetState> ReadGroupsAsync(
        NetBirdManagement management, FleetConfig? fleet, NetBirdFleetState state, CancellationToken cancellationToken)
    {
        var groups = await management.GetGroupsAsync(cancellationToken);
        return groups switch
        {
            IReadOnlyList<NetBirdGroup> configured => await ReadKeysAsync(management, fleet, configured, state, cancellationToken),
            NetBirdApiProblem problem => state with { Problem = NetBirdApi.Describe(problem).Message },
        };
    }

    private async Task<NetBirdFleetState> ReadKeysAsync(
        NetBirdManagement management, FleetConfig? fleet, IReadOnlyList<NetBirdGroup> groups, NetBirdFleetState state, CancellationToken cancellationToken)
    {
        var keys = await management.GetSetupKeysAsync(cancellationToken);
        return keys switch
        {
            IReadOnlyList<NetBirdSetupKey> configured => Readiness(fleet, groups, configured, state, timeProvider.GetUtcNow()),
            NetBirdApiProblem problem => state with { Problem = NetBirdApi.Describe(problem).Message },
        };
    }

    private static NetBirdFleetState Readiness(
        FleetConfig? fleet, IReadOnlyList<NetBirdGroup> groups, IReadOnlyList<NetBirdSetupKey> keys, NetBirdFleetState state, DateTimeOffset now)
    {
        var regionalNames = fleet is { } config
            ? config.Regions.Select(static region => NetBirdManagement.ServerGroup(region.Label)).ToHashSet(StringComparer.Ordinal)
            : groups.Where(static group => group.Name.EndsWith("-servers", StringComparison.Ordinal)).Select(static group => group.Name).ToHashSet(StringComparer.Ordinal);
        var servers = groups.Where(group => regionalNames.Contains(group.Name)).ToArray();
        var operators = groups.FirstOrDefault(static group => group.Name == NetBirdManagement.Operators);
        return state with
        {
            Problem = null,
            ServerEnrollmentReady = servers.Length > 0
                && regionalNames.SetEquals(servers.Select(static group => group.Name))
                && keys.Any(key => key.Name == NetBirdManagement.Servers && key.IsUsable(now)
                    && NetBirdManagement.SameSet(key.AutoGroups, servers.Select(static group => group.Id))),
            OperatorEnrollmentReady = operators is not null
                && keys.Any(key => key.Name == NetBirdManagement.Operators && key.IsUsable(now)
                    && NetBirdManagement.SameSet(key.AutoGroups, [operators.Id])),
        };
    }

    private sealed record class FleetReport(NetBirdFleetState? State, string? Problem);
}
