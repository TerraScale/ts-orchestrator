using System.Diagnostics;

namespace TsOrch.Cli;

internal static class DiffCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("file", 'f', true)];

    public static async Task<OrchResult<int>> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        if (!arguments.ExpectPositionals(0, "ts-orch diff [-f PATH]").TryGetValue(out _, out var usageError))
        {
            return usageError;
        }

        var diff = await FetchAsync(environment.Api, arguments.Value("file") ?? SpecFiles.DefaultServicesPath, cancellationToken);
        if (!diff.TryGetValue(out var items, out var error))
        {
            return error;
        }

        if (items.Count == 0)
        {
            environment.Out.WriteLine("No differences: live desired state matches the local service definitions.");
            return ExitCodes.Ok;
        }

        foreach (var item in items)
        {
            environment.Out.WriteLine(item.Kind switch
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
        environment.Out.WriteLine();
        environment.Out.WriteLine($"{added} added, {changed} changed, {removed} removed");
        return ExitCodes.Ok;
    }

    public static async Task<OrchResult<IReadOnlyList<DiffItem>>> FetchAsync(OrchApi api, string path, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(api);
        var loaded = await SpecFiles.LoadServicesAsync(path, cancellationToken);
        if (!loaded.TryGetValue(out var services, out var loadError))
        {
            return loadError;
        }

        var diff = await api.PostAsync(
            "/api/services/diff",
            new ServicesDocument(services),
            CliJsonContext.Default.ServicesDocument,
            CliJsonContext.Default.DiffResponse,
            cancellationToken);
        return diff switch
        {
            DiffResponse response => new OrchResult<IReadOnlyList<DiffItem>>(response.Diff),
            OrchError error => error,
        };
    }
}
