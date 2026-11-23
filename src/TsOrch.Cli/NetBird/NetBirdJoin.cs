using System.Net;

namespace TsOrch.Cli;

internal sealed record class NetBirdJoinOptions(string? FleetPath, string? Url, string? Hostname, string? SetupKeyFile);

internal sealed class NetBirdJoin(NetBirdClient client, CommandEnvironment environment)
{
    public async Task<int> RunAsync(NetBirdJoinOptions options, CancellationToken cancellationToken)
    {
        var installed = await client.GetStatusAsync(cancellationToken);
        return installed switch
        {
            NetBirdLocalState state => await LoadConfigurationAsync(state, options, cancellationToken),
            NetBirdClientMissing => environment.Fail(CliDiagnostic.Unavailable(NetBirdClient.InstallInstructions)),
            NetBirdLocalStatusUnreadable => environment.Fail(CliDiagnostic.Unavailable("Could not read NetBird daemon status.")),
        };
    }

    private async Task<int> LoadConfigurationAsync(
        NetBirdLocalState state, NetBirdJoinOptions options, CancellationToken cancellationToken)
    {
        if (options.FleetPath is null && options.Url is not null && options.SetupKeyFile is not null)
        {
            return await JoinAsync(state, options, null, cancellationToken);
        }

        var outcome = await NetBirdFleet.LoadAsync(environment.Api, options.FleetPath, cancellationToken);
        return outcome switch
        {
            FleetConfig fleet => await JoinAsync(state, options, fleet, cancellationToken),
            NetBirdFleetUnavailable unavailable => environment.Fail(unavailable.Diagnostic),
        };
    }

    private async Task<int> JoinAsync(NetBirdLocalState state, NetBirdJoinOptions options, FleetConfig? fleet, CancellationToken cancellationToken)
    {
        var config = fleet?.NetBird;
        if (NetBirdApi.ParseUrl(options.Url ?? config?.ManagementUrl) is not { } url)
        {
            return environment.Usage("NetBird management URL needs an HTTPS origin or a loopback HTTP origin.");
        }

        if (state.Connected)
        {
            return NetBirdClient.IsOtherManagementUrl(state, url)
                ? environment.Fail(CliDiagnostic.Unavailable("NetBird is connected to a different management URL. Disconnect it before joining."))
                : NetBirdEnrollment.Render(state, environment);
        }

        NetBirdCredentialRead key;
        if (options.SetupKeyFile is { } path)
        {
            key = await NetBirdCredentials.ReadFileAsync(path, cancellationToken);
        }
        else if (config is not null && fleet is not null)
        {
            key = await NetBirdCredentials.ReadAsync(null, fleet.Oci.Vault, config.OperatorsSetupKeySecret, environment.TimeProvider, cancellationToken);
        }
        else
        {
            return environment.Usage("Supply --setup-key-file or configure the operator setup key in the fleet.");
        }

        return key switch
        {
            NetBirdCredential credential => await ConnectAsync(url, options.Hostname ?? Dns.GetHostName(), credential, cancellationToken),
            NetBirdCredentialUnavailable unavailable => environment.Fail(unavailable.Diagnostic),
        };
    }

    private async Task<int> ConnectAsync(Uri url, string hostname, NetBirdCredential key, CancellationToken cancellationToken)
    {
        var outcome = await client.ConnectAsync(url, hostname, key, disableServerSsh: false, cancellationToken);
        return NetBirdEnrollment.Render(outcome, environment);
    }
}
