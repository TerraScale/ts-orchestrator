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
            _ => Task.FromResult(environment.Fail(new Validation($"usage: {UsageText}"))),
        };

    private static async Task<int> CheckAsync(string path, CommandEnvironment environment, CancellationToken cancellationToken) =>
        await SpecFiles.LoadServicesAsync(path, cancellationToken) switch
        {
            IReadOnlyList<ServiceSpec> services => OciEnvironment.Resolve(mockUrlOverride: null) switch
            {
                OciEnvironment ociEnvironment => await CheckAsync(services, ociEnvironment, environment, cancellationToken),
                Validation failure => environment.Fail(failure),
            },
            NotFound failure => environment.Fail(failure),
            Validation failure => environment.Fail(failure),
            Forbidden failure => environment.Fail(failure),
            Unavailable failure => environment.Fail(failure),
        };

    private static async Task<int> CheckAsync(
        IReadOnlyList<ServiceSpec> services,
        OciEnvironment ociEnvironment,
        CommandEnvironment environment,
        CancellationToken cancellationToken)
    {
        using var httpClient = new HttpClient { Timeout = OciTimeout };
        using var oci = OciSetup.Create(httpClient, ociEnvironment, environment.TimeProvider);
        Dictionary<SecretRef, Result<long, Validation, NotFound, Forbidden, Unavailable, InternalFailure>> versions = [];
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
                    Validation failure => Unreadable(failure.Message),
                    NotFound failure => Unreadable(failure.Message),
                    Forbidden failure => Unreadable(failure.Message),
                    Unavailable failure => Unreadable(failure.Message),
                    InternalFailure failure => Unreadable(failure.Message),
                };
                failures += version switch
                {
                    long => 0,
                    Validation or NotFound or Forbidden or Unavailable or InternalFailure => 1,
                };
                table.Add(service.Name, name, reference.Name, cell);
            }
        }

        table.WriteTo(environment.Out);
        environment.Out.WriteLine();
        environment.Out.WriteLine($"{versions.Count} distinct secret(s) referenced, {failures} unreadable reference(s).");
        return failures == 0
            ? ExitCodes.Ok
            : environment.Fail(new Unavailable($"{failures} secret reference(s) could not be read from OCI Vault."));
    }

    private static string Unreadable(string message) => $"UNREADABLE: {message}";

    private static async Task<Result<long, Validation, NotFound, Forbidden, Unavailable, InternalFailure>> ReadVersionAsync(
        OciVaultClient vault,
        SecretRef reference,
        CancellationToken cancellationToken) =>
        string.IsNullOrWhiteSpace(reference.Vault) || string.IsNullOrWhiteSpace(reference.Name)
            ? new Validation("Secret reference needs both a vault id and a secret name.")
            : await vault.GetSecretVersionAsync(reference.Vault, reference.Name, cancellationToken);

    private static async Task<int> RefreshAsync(string service, CommandEnvironment environment, CancellationToken cancellationToken) =>
        await environment.Api.PostAsync(
            "/api/secrets/refresh",
            new SecretsRefreshRequest(service),
            CliJsonContext.Default.SecretsRefreshRequest,
            CliJsonContext.Default.SecretsRefreshResponse,
            cancellationToken) switch
        {
            SecretsRefreshResponse response => Refreshed(response, environment.Out),
            Validation failure => environment.Fail(failure),
            NotFound failure => environment.Fail(failure),
            Conflict failure => environment.Fail(failure),
            Unauthorized failure => environment.Fail(failure),
            Forbidden failure => environment.Fail(failure),
            Unavailable failure => environment.Fail(failure),
        };

    private static int Refreshed(SecretsRefreshResponse response, TextWriter output)
    {
        output.WriteLine($"Secret refresh for {response.Service} sent to {response.Nodes.Count} node(s): {Display.List(response.Nodes)}");
        return ExitCodes.Ok;
    }
}
