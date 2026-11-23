using static System.FormattableString;

namespace TsOrch.Cli;

internal static class ServiceCommand
{
    private const string UsageText = "ts-orch service ls | apply -f <file-or-dir> | rm <name>";

    public static IReadOnlyList<CliOption> Options { get; } = [new("file", 'f', true)];

    public static Task<OrchResult<int>> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.Positionals switch
        {
            ["ls"] when arguments.Value("file") is null => ListAsync(environment, cancellationToken),
            ["apply"] when arguments.Value("file") is { } path => ApplyAsync(path, environment, cancellationToken),
            ["rm", var name] when arguments.Value("file") is null => RemoveAsync(name, environment, cancellationToken),
            _ => Task.FromResult<OrchResult<int>>(new Validation($"usage: {UsageText}")),
        };

    private static async Task<OrchResult<int>> ListAsync(CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var listed = await environment.Api.GetAsync("/api/services", CliJsonContext.Default.ServiceListResponse, cancellationToken);
        if (!listed.TryGetValue(out var response, out var error))
        {
            return error;
        }

        var table = new TextTable("SERVICE", "MODE", "PRIORITY", "REPLICAS", "CPU m", "MEM MiB", "PORT", "REGIONS", "IMAGE");
        foreach (var service in response.Services.OrderBy(static service => service.Name, StringComparer.Ordinal))
        {
            table.Add(
                service.Name,
                service.Mode.WireName,
                service.Priority.WireName,
                Invariant($"{service.Replicas} ({service.MinReplicas}-{service.MaxReplicas})"),
                Invariant($"{service.CpuRequestMilli}/{service.CpuLimitMilli}"),
                Invariant($"{service.MemRequestMiB}/{service.MemLimitMiB}"),
                Display.Integer(service.Port),
                Display.List(service.Regions),
                service.Image);
        }

        table.WriteTo(environment.Out);
        return ExitCodes.Ok;
    }

    private static async Task<OrchResult<int>> ApplyAsync(string path, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var loaded = await SpecFiles.LoadServicesAsync(path, cancellationToken);
        if (!loaded.TryGetValue(out var services, out var loadError))
        {
            return loadError;
        }

        var applied = await environment.Api.PostAsync(
            "/api/services",
            new ServicesDocument(services),
            CliJsonContext.Default.ServicesDocument,
            CliJsonContext.Default.ApplyResponse,
            cancellationToken);
        if (!applied.TryGetValue(out var response, out var error))
        {
            return error;
        }

        foreach (var service in response.Applied)
        {
            var rollout = service.RolloutId is { } id ? $" (rollout {id} started)" : string.Empty;
            environment.Out.WriteLine($"{service.Name}: {service.Result.WireName}{rollout}");
        }

        return ExitCodes.Ok;
    }

    private static async Task<OrchResult<int>> RemoveAsync(string name, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var removed = await environment.Api.DeleteAsync($"/api/services/{Uri.EscapeDataString(name)}", CliJsonContext.Default.DeletedServiceResponse, cancellationToken);
        if (!removed.TryGetValue(out var response, out var error))
        {
            return error;
        }

        environment.Out.WriteLine($"Deleted service {response.Deleted}.");
        return ExitCodes.Ok;
    }
}
