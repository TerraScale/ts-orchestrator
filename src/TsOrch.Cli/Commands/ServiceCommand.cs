using static System.FormattableString;

namespace TsOrch.Cli;

internal static class ServiceCommand
{
    private const string UsageText = "ts-orch service ls | apply -f <file-or-dir> | rm <name>";

    public static IReadOnlyList<CliOption> Options { get; } = [new("file", 'f', true)];

    public static Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.Positionals switch
        {
            ["ls"] when arguments.Value("file") is null => ListAsync(environment, cancellationToken),
            ["apply"] when arguments.Value("file") is { } path => ApplyAsync(path, environment, cancellationToken),
            ["rm", var name] when arguments.Value("file") is null => RemoveAsync(name, environment, cancellationToken),
            _ => Task.FromResult(environment.Fail(new Validation($"usage: {UsageText}"))),
        };

    private static async Task<int> ListAsync(CommandEnvironment environment, CancellationToken cancellationToken) =>
        await environment.Api.GetAsync("/api/services", CliJsonContext.Default.ServiceListResponse, cancellationToken) switch
        {
            ServiceListResponse response => Render(response, environment.Out),
            Validation failure => environment.Fail(failure),
            NotFound failure => environment.Fail(failure),
            Unauthorized failure => environment.Fail(failure),
            Forbidden failure => environment.Fail(failure),
            Unavailable failure => environment.Fail(failure),
        };

    private static int Render(ServiceListResponse response, TextWriter output)
    {
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

        table.WriteTo(output);
        return ExitCodes.Ok;
    }

    private static async Task<int> ApplyAsync(string path, CommandEnvironment environment, CancellationToken cancellationToken) =>
        await SpecFiles.LoadServicesAsync(path, cancellationToken) switch
        {
            IReadOnlyList<ServiceSpec> services => await environment.Api.PostAsync(
                "/api/services",
                new ServicesDocument(services),
                CliJsonContext.Default.ServicesDocument,
                CliJsonContext.Default.ApplyResponse,
                cancellationToken) switch
            {
                ApplyResponse response => Report(response, environment.Out),
                Validation failure => environment.Fail(failure),
                NotFound failure => environment.Fail(failure),
                Conflict failure => environment.Fail(failure),
                Unauthorized failure => environment.Fail(failure),
                Forbidden failure => environment.Fail(failure),
                Unavailable failure => environment.Fail(failure),
            },
            NotFound failure => environment.Fail(failure),
            Validation failure => environment.Fail(failure),
            Forbidden failure => environment.Fail(failure),
            Unavailable failure => environment.Fail(failure),
        };

    private static int Report(ApplyResponse response, TextWriter output)
    {
        foreach (var service in response.Applied)
        {
            var rollout = service.RolloutId is { } id ? $" (rollout {id} started)" : string.Empty;
            output.WriteLine($"{service.Name}: {service.Result.WireName}{rollout}");
        }

        return ExitCodes.Ok;
    }

    private static async Task<int> RemoveAsync(string name, CommandEnvironment environment, CancellationToken cancellationToken) =>
        await environment.Api.DeleteAsync($"/api/services/{Uri.EscapeDataString(name)}", CliJsonContext.Default.DeletedServiceResponse, cancellationToken) switch
        {
            DeletedServiceResponse response => Deleted(response, environment.Out),
            Validation failure => environment.Fail(failure),
            NotFound failure => environment.Fail(failure),
            Conflict failure => environment.Fail(failure),
            Unauthorized failure => environment.Fail(failure),
            Forbidden failure => environment.Fail(failure),
            Unavailable failure => environment.Fail(failure),
        };

    private static int Deleted(DeletedServiceResponse response, TextWriter output)
    {
        output.WriteLine($"Deleted service {response.Deleted}.");
        return ExitCodes.Ok;
    }
}
