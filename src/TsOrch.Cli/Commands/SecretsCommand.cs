using TsOrch.Oci;

namespace TsOrch.Cli;

internal static class SecretsCommand
{
    private const string UsageText = "ts-orch secrets check [-f PATH] | refresh <service>";
    private static readonly TimeSpan OciTimeout = TimeSpan.FromSeconds(30);

    public static IReadOnlyList<CliOption> Options { get; } = [new("file", 'f', true)];

    public static Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.Positionals switch
        {
            ["check"] => CheckAsync(arguments.Value("file") ?? SpecFiles.DefaultServicesPath, environment, cancellationToken),
            ["refresh", var service] when arguments.Value("file") is null => RefreshAsync(service, environment, cancellationToken),
            _ => Task.FromResult(environment.Usage($"usage: {UsageText}")),
        };

    private static async Task<int> CheckAsync(string path, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var loaded = await SpecFiles.LoadServicesAsync(path, cancellationToken);
        return loaded switch
        {
            IReadOnlyList<ServiceSpec> services => OciEnvironment.Resolve(mockUrlOverride: null) switch
            {
                OciEnvironment ociEnvironment => await CheckAsync(services, ociEnvironment, environment, cancellationToken),
                InvalidOciMockEndpoint invalid => environment.Usage(invalid.Message),
            },
            CliFileReadProblem failure => environment.Fail(CliFiles.Describe(failure)),
            ServiceDefinitionInvalid failure => environment.Fail(SpecFiles.Describe(failure)),
            DuplicateServiceDefinition failure => environment.Fail(SpecFiles.Describe(failure)),
            ServiceDefinitionsMissing failure => environment.Fail(SpecFiles.Describe(failure)),
        };
    }

    private static async Task<int> CheckAsync(
        IReadOnlyList<ServiceSpec> services,
        OciEnvironment ociEnvironment,
        CommandEnvironment environment,
        CancellationToken cancellationToken)
    {
        using var httpClient = new HttpClient { Timeout = OciTimeout };
        using var oci = OciSetup.Create(httpClient, ociEnvironment, environment.TimeProvider);
        Dictionary<SecretRef, SecretVersionCell> versions = [];
        var table = new TextTable("SERVICE", "ENV", "VAULT SECRET", "VERSION");
        var failures = 0;
        foreach (var service in services.OrderBy(static service => service.Name, StringComparer.Ordinal))
        {
            foreach (var (name, reference) in service.Secrets.OrderBy(static pair => pair.Key, StringComparer.Ordinal))
            {
                if (!versions.TryGetValue(reference, out var version))
                {
                    version = await ReadVersionAsync(oci.Vault, reference, cancellationToken);
                    versions[reference] = version;
                }

                failures += version.Readable ? 0 : 1;
                table.Add(service.Name, name, reference.Name, version.Text);
            }
        }

        table.WriteTo(environment.Out);
        environment.Out.WriteLine();
        environment.Out.WriteLine($"{versions.Count} distinct secret(s) referenced, {failures} unreadable reference(s).");
        return failures == 0
            ? ExitCodes.Ok
            : environment.Fail(CliDiagnostic.Unavailable($"{failures} secret reference(s) could not be read from OCI Vault."));
    }

    private static SecretVersionCell Unreadable(string message) => new($"UNREADABLE: {message}", Readable: false);

    private static async Task<SecretVersionCell> ReadVersionAsync(OciVaultClient vault, SecretRef reference, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(reference.Vault) || string.IsNullOrWhiteSpace(reference.Name))
        {
            return Unreadable("Secret reference needs both a vault id and a secret name.");
        }

        var read = await vault.GetSecretAsync(reference.Vault, reference.Name, cancellationToken);
        return read switch
        {
            VaultSecretBundle bundle => new SecretVersionCell(Display.Integer(bundle.VersionNumber), Readable: true),
            VaultRegionMissing failure => Unreadable(failure.Message),
            VaultSecretMissing failure => Unreadable(failure.Message),
            VaultAccessDenied failure => Unreadable(failure.Message),
            VaultUnavailable failure => Unreadable(failure.Message),
            VaultBundleInvalid failure => Unreadable(failure.Message),
            ImdsRequestRejected failure => Unreadable(failure.Message),
            ImdsUnavailable failure => Unreadable(failure.Message),
            ImdsDocumentInvalid failure => Unreadable(failure.Message),
            InvalidFederationCredentials failure => Unreadable(failure.Message),
            FederationRejected failure => Unreadable(failure.Message),
            FederationUnavailable failure => Unreadable(failure.Message),
            FederationTokenInvalid failure => Unreadable(failure.Message),
        };
    }

    private sealed record class SecretVersionCell(string Text, bool Readable);

    private static async Task<int> RefreshAsync(string service, CommandEnvironment environment, CancellationToken cancellationToken) =>
        await environment.Api.PostAsync(
            "/api/secrets/refresh",
            new SecretsRefreshRequest(service),
            CliJsonContext.Default.SecretsRefreshRequest,
            CliJsonContext.Default.SecretsRefreshResponse,
            response => Task.FromResult(Refreshed(response, environment.Out)), environment.Fail, cancellationToken);

    private static int Refreshed(SecretsRefreshResponse response, TextWriter output)
    {
        output.WriteLine($"Secret refresh for {response.Service} sent to {response.Nodes.Count} node(s): {Display.List(response.Nodes)}");
        return ExitCodes.Ok;
    }
}
