namespace TsOrch.Cli;

internal static class SpecFiles
{
    public const string DefaultServicesPath = "deploy/services";
    public const string DefaultFleetPath = "deploy/fleet.json";

    public static Task<OrchResult<FleetConfig>> LoadFleetAsync(string path, CancellationToken cancellationToken) =>
        CliFiles.ReadJsonAsync(Path.GetFullPath(path), FleetJsonContext.Default.FleetConfig, cancellationToken);

    public static async Task<OrchResult<IReadOnlyList<ServiceSpec>>> LoadServicesAsync(string path, CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        IReadOnlyList<string> files = Directory.Exists(fullPath)
            ? [.. Directory.EnumerateFiles(fullPath, "*.json").Order(StringComparer.Ordinal)]
            : [fullPath];
        if (files.Count == 0)
        {
            return new NotFound($"{fullPath} holds no *.json service definitions.");
        }

        List<ServiceSpec> services = [];
        foreach (var file in files)
        {
            var loaded = await LoadFileAsync(file, cancellationToken);
            if (!loaded.TryGetValue(out var specs, out var error))
            {
                return error;
            }

            services.AddRange(specs);
        }

        if (services.GroupBy(static service => service.Name, StringComparer.Ordinal).FirstOrDefault(static group => group.Count() > 1) is { } duplicate)
        {
            return new Validation($"Service '{duplicate.Key}' is defined more than once under {fullPath}.");
        }

        return new OrchResult<IReadOnlyList<ServiceSpec>>(services);
    }

    private static async Task<OrchResult<IReadOnlyList<ServiceSpec>>> LoadFileAsync(string file, CancellationToken cancellationToken)
    {
        var text = await CliFiles.ReadTextAsync(file, cancellationToken);
        if (!text.TryGetValue(out var content, out var error))
        {
            return error;
        }

        return content.TrimStart().StartsWith('[')
            ? await CliFiles.ReadJsonAsync(file, FleetJsonContext.Default.IReadOnlyListServiceSpec, cancellationToken)
            : await LoadSingleAsync(file, cancellationToken);
    }

    private static async Task<OrchResult<IReadOnlyList<ServiceSpec>>> LoadSingleAsync(string file, CancellationToken cancellationToken)
    {
        var loaded = await CliFiles.ReadJsonAsync(file, FleetJsonContext.Default.ServiceSpec, cancellationToken);
        return loaded switch
        {
            ServiceSpec spec => new OrchResult<IReadOnlyList<ServiceSpec>>([spec]),
            OrchError error => error,
        };
    }
}
