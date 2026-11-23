using System.Diagnostics;

namespace TsOrch.Cli;

internal static class DiffCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("file", 'f', true)];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(0, "ts-orch diff [-f PATH]") switch
        {
            Done => await FetchAsync(environment.Api, arguments.Value("file") ?? SpecFiles.DefaultServicesPath, cancellationToken) switch
            {
                IReadOnlyList<DiffItem> items => Render(items, environment.Out),
                Validation failure => environment.Fail(failure),
                NotFound failure => environment.Fail(failure),
                Conflict failure => environment.Fail(failure),
                Unauthorized failure => environment.Fail(failure),
                Forbidden failure => environment.Fail(failure),
                Unavailable failure => environment.Fail(failure),
            },
            Validation failure => environment.Fail(failure),
        };

    public static async Task<Result<IReadOnlyList<DiffItem>, Validation, NotFound, Conflict, Unauthorized, Forbidden, Unavailable>> FetchAsync(
        OrchApi api,
        string path,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(api);
        return await SpecFiles.LoadServicesAsync(path, cancellationToken) switch
        {
            IReadOnlyList<ServiceSpec> services => await DiffAsync(api, services, cancellationToken),
            NotFound failure => failure,
            Validation failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
        };
    }

    private static async Task<Result<IReadOnlyList<DiffItem>, Validation, NotFound, Conflict, Unauthorized, Forbidden, Unavailable>> DiffAsync(
        OrchApi api,
        IReadOnlyList<ServiceSpec> services,
        CancellationToken cancellationToken) =>
        await api.PostAsync(
            "/api/services/diff",
            new ServicesDocument(services),
            CliJsonContext.Default.ServicesDocument,
            CliJsonContext.Default.DiffResponse,
            cancellationToken) switch
        {
            DiffResponse response => new Result<IReadOnlyList<DiffItem>, Validation, NotFound, Conflict, Unauthorized, Forbidden, Unavailable>(response.Diff),
            Validation failure => failure,
            NotFound failure => failure,
            Conflict failure => failure,
            Unauthorized failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
        };

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
