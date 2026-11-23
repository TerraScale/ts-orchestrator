using TsOrch.Oci;

namespace TsOrch.Cli;

internal static class SecretsCommand
{
    private const string UsageText = "ts-orch secrets check [-f PATH] | refresh <service>";
    private static readonly TimeSpan OciTimeout = TimeSpan.FromSeconds(30);

    public static IReadOnlyList<CliOption> Options { get; } = [new("file", 'f', true)];

    public static Task<OrchResult<int>> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.Positionals switch
        {
            ["check"] => CheckAsync(arguments.Value("file") ?? SpecFiles.DefaultServicesPath, environment, cancellationToken),
            ["refresh", var service] when arguments.Value("file") is null => RefreshAsync(service, environment, cancellationToken),
            _ => Task.FromResult<OrchResult<int>>(new Validation($"usage: {UsageText}")),
        };

    private static async Task<OrchResult<int>> CheckAsync(string path, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var loaded = await SpecFiles.LoadServicesAsync(path, cancellationToken);
        if (!loaded.TryGetValue(out var services, out var loadError))
        {
            return loadError;
        }

        if (!OciSetup.ResolveEnvironment(mockUrlOverride: null).TryGetValue(out var ociEnvironment, out var environmentError))
        {
            return environmentError;
        }

        using var httpClient = new HttpClient { Timeout = OciTimeout };
        using var oci = OciSetup.Create(httpClient, ociEnvironment, environment.TimeProvider);
        Dictionary<SecretRef, OrchResult<long>> versions = [];
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

                var cell = version switch
                {
                    long number => Display.Integer(number),
                    OrchError error => $"UNREADABLE: {error.Message}",
                };
                failures += version.TryGetValue(out _, out _) ? 0 : 1;
                table.Add(service.Name, name, reference.Name, cell);
            }
        }

        table.WriteTo(environment.Out);
        environment.Out.WriteLine();
        environment.Out.WriteLine($"{versions.Count} distinct secret(s) referenced, {failures} unreadable reference(s).");
        return failures == 0 ? ExitCodes.Ok : new Unavailable($"{failures} secret reference(s) could not be read from OCI Vault.");
    }

    private static async Task<OrchResult<long>> ReadVersionAsync(OciVaultClient vault, SecretRef reference, CancellationToken cancellationToken) =>
        string.IsNullOrWhiteSpace(reference.Vault) || string.IsNullOrWhiteSpace(reference.Name)
            ? new Validation("Secret reference needs both a vault id and a secret name.")
            : await vault.GetSecretVersionAsync(reference.Vault, reference.Name, cancellationToken);

    private static async Task<OrchResult<int>> RefreshAsync(string service, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var refreshed = await environment.Api.PostAsync(
            "/api/secrets/refresh",
            new SecretsRefreshRequest(service),
            CliJsonContext.Default.SecretsRefreshRequest,
            CliJsonContext.Default.SecretsRefreshResponse,
            cancellationToken);
        if (!refreshed.TryGetValue(out var response, out var error))
        {
            return error;
        }

        environment.Out.WriteLine($"Secret refresh for {response.Service} sent to {response.Nodes.Count} node(s): {Display.List(response.Nodes)}");
        return ExitCodes.Ok;
    }
}
