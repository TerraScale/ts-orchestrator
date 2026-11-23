using System.Diagnostics;

namespace TsOrch.Cli;

internal readonly union ServiceDiff(IReadOnlyList<DiffItem>, CliFileReadProblem, ServiceDefinitionInvalid,
    DuplicateServiceDefinition, ServiceDefinitionsMissing, BackplaneProblem);

internal static class DiffCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("file", 'f', true)];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(0, "ts-orch diff [-f PATH]") switch
        {
            CommandPositionalsAccepted => await RunDiffAsync(arguments.Value("file") ?? SpecFiles.DefaultServicesPath, environment, cancellationToken),
            CommandPositionalsInvalid invalid => environment.Usage($"usage: {invalid.Usage}"),
        };

    private static async Task<int> RunDiffAsync(string path, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var outcome = await FetchAsync(environment.Api, path, cancellationToken);
        return outcome switch
        {
            IReadOnlyList<DiffItem> items => Render(items, environment.Out),
            CliFileReadProblem failure => environment.Fail(CliFiles.Describe(failure)),
            ServiceDefinitionInvalid failure => environment.Fail(SpecFiles.Describe(failure)),
            DuplicateServiceDefinition failure => environment.Fail(SpecFiles.Describe(failure)),
            ServiceDefinitionsMissing failure => environment.Fail(SpecFiles.Describe(failure)),
            BackplaneProblem failure => environment.Fail(failure),
        };
    }

    public static async Task<ServiceDiff> FetchAsync(OrchApi api, string path, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(api);
        var loaded = await SpecFiles.LoadServicesAsync(path, cancellationToken);
        return loaded switch
        {
            IReadOnlyList<ServiceSpec> services => await DiffAsync(api, services, cancellationToken),
            CliFileReadProblem failure => failure,
            ServiceDefinitionInvalid failure => failure,
            DuplicateServiceDefinition failure => failure,
            ServiceDefinitionsMissing failure => failure,
        };
    }

    private static Task<ServiceDiff> DiffAsync(OrchApi api, IReadOnlyList<ServiceSpec> services, CancellationToken cancellationToken) =>
        api.PostAsync(
            "/api/services/diff",
            new ServicesDocument(services),
            CliJsonContext.Default.ServicesDocument,
            CliJsonContext.Default.DiffResponse,
            static response => Task.FromResult(new ServiceDiff(response.Diff)),
            static failure => failure,
            cancellationToken);

    private static int Render(IReadOnlyList<DiffItem> items, TextWriter output)
    {
        if (items.Count == 0)
        {
            output.WriteLine("No differences: live desired state matches the local service definitions.");
            return ExitCodes.Ok;
        }

        foreach (var item in items)
        {
            output.WriteLine(item.Kind switch
            {
                DiffKind.Added => $"+ {item.Service}  (not deployed yet)",
                DiffKind.Changed => $"~ {item.Service}  {string.Join(", ", item.Fields)}",
                DiffKind.Removed => $"- {item.Service}  (live only)",
                _ => throw new UnreachableException(),
            });
        }

        var added = items.Count(static item => item.Kind == DiffKind.Added);
        var changed = items.Count(static item => item.Kind == DiffKind.Changed);
        var removed = items.Count(static item => item.Kind == DiffKind.Removed);
        output.WriteLine();
        output.WriteLine($"{added} added, {changed} changed, {removed} removed");
        return ExitCodes.Ok;
    }
}
