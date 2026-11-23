using System.Net;
using TsOrch.Oci;

namespace TsOrch.Cli;

internal sealed record class NetBirdEnrollmentOptions(string? Url, string? VaultId, string? SecretName, string? Hostname)
{
    public NetBirdEnrollmentOptions WithMetadata(OciNodeMetadata metadata) => new(
        Url ?? metadata.NetBirdUrl, VaultId ?? metadata.EnrollVault, SecretName ?? metadata.NetBirdSetupKeySecret, Hostname);
}

internal sealed class NetBirdEnrollment(NetBirdClient client, CommandEnvironment environment)
{
    public async Task<int> RunAsync(NetBirdEnrollmentOptions options, CancellationToken cancellationToken)
    {
        var outcome = await client.GetStatusAsync(cancellationToken);
        return outcome switch
        {
            NetBirdLocalState { Connected: true } state => await VerifyConnectedAsync(state, options, cancellationToken),
            NetBirdLocalState => await EnrollAsync(options, cancellationToken),
            NetBirdClientMissing => environment.Fail(CliDiagnostic.Unavailable(NetBirdClient.InstallInstructions)),
            NetBirdLocalStatusUnreadable => environment.Fail(CliDiagnostic.Unavailable("Could not read NetBird daemon status.")),
        };
    }

    private async Task<int> VerifyConnectedAsync(NetBirdLocalState state, NetBirdEnrollmentOptions options, CancellationToken cancellationToken)
    {
        var configured = NetBirdApi.ParseUrl(options.Url);
        if (options.Url is not null && configured is null)
        {
            return environment.Usage("NetBird management URL needs an HTTPS origin or a loopback HTTP origin.");
        }

        if (configured is { } expected && NetBirdClient.IsOtherManagementUrl(state, expected))
        {
            return environment.Fail(CliDiagnostic.Unavailable("NetBird is connected to a different management URL."));
        }

        if (state.SshServerEnabled is false)
        {
            return Connected(state, environment);
        }

        if (state.SshServerEnabled is null)
        {
            return environment.Fail(CliDiagnostic.Unavailable("NetBird daemon status does not report whether its SSH server is enabled."));
        }

        if ((configured ?? NetBirdApi.ParseUrl(state.ManagementUrl)) is not { } url)
        {
            return environment.Fail(CliDiagnostic.Unavailable("Could not resolve the connected NetBird management URL to enforce the SSH setting."));
        }

        var outcome = await client.DisableServerSshAsync(url, options.Hostname, cancellationToken);
        return Render(outcome, environment);
    }

    private async Task<int> EnrollAsync(NetBirdEnrollmentOptions options, CancellationToken cancellationToken)
    {
        var outcome = OciEnvironment.Resolve(mockUrlOverride: null);
        return outcome switch
        {
            OciEnvironment oci => await EnrollWithOciAsync(options, oci, cancellationToken),
            InvalidOciMockEndpoint invalid => environment.Usage(invalid.Message),
        };
    }

    private async Task<int> EnrollWithOciAsync(NetBirdEnrollmentOptions options, OciEnvironment oci, CancellationToken cancellationToken)
    {
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = OrchHttp.DefaultTimeout };
        using var clients = OciSetup.Create(http, oci, environment.TimeProvider);
        if (options.Url is not null && options.VaultId is not null && options.SecretName is not null)
        {
            return await ConnectFromVaultAsync(clients.Vault, options, cancellationToken);
        }

        var outcome = await clients.Imds.GetIdentityAsync(cancellationToken);
        return outcome switch
        {
            OciInstanceIdentity identity => await ConnectFromVaultAsync(clients.Vault, options.WithMetadata(identity.Node), cancellationToken),
            ImdsRequestRejected or ImdsUnavailable or ImdsDocumentInvalid
                => environment.Fail(CliDiagnostic.Unavailable("Could not read OCI instance metadata. Supply --url, --vault and --secret explicitly.")),
        };
    }

    private async Task<int> ConnectFromVaultAsync(OciVaultClient vault, NetBirdEnrollmentOptions options, CancellationToken cancellationToken)
    {
        if (NetBirdApi.ParseUrl(options.Url) is not { } url)
        {
            return environment.Usage("Configure a NetBird management URL with --url, TS_ORCH_NETBIRD_URL or ts_netbird_url.");
        }

        if (string.IsNullOrWhiteSpace(options.VaultId) || string.IsNullOrWhiteSpace(options.SecretName))
        {
            return environment.Usage("Configure the enrollment Vault and setup key secret with --vault and --secret, environment variables or OCI metadata.");
        }

        var key = await NetBirdCredentials.ReadInstanceVaultAsync(vault, options.VaultId, options.SecretName, cancellationToken);
        return key switch
        {
            NetBirdCredential setupKey => await ConnectAsync(url, options.Hostname ?? Dns.GetHostName(), setupKey, cancellationToken),
            NetBirdCredentialUnavailable unavailable => environment.Fail(unavailable.Diagnostic),
        };
    }

    private async Task<int> ConnectAsync(Uri url, string hostname, NetBirdCredential key, CancellationToken cancellationToken)
    {
        var outcome = await client.ConnectAsync(url, hostname, key, disableServerSsh: true, cancellationToken);
        return Render(outcome, environment);
    }

    public static int Render(NetBirdConnection outcome, CommandEnvironment environment) => outcome switch
    {
        NetBirdLocalState state => Connected(state, environment),
        NetBirdConnectionFailed failure => environment.Fail(failure.Diagnostic),
    };

    private static int Connected(NetBirdLocalState state, CommandEnvironment environment)
    {
        environment.Out.WriteLine(state.Fqdn is { } fqdn ? $"NetBird connected as {fqdn}." : "NetBird connected.");
        return ExitCodes.Ok;
    }
}
