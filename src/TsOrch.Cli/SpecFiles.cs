namespace TsOrch.Cli;

internal static class SpecFiles
{
    public const string DefaultServicesPath = "deploy/services";
    public const string DefaultFleetPath = "deploy/fleet.json";

    public static Task<Result<FleetConfig, NotFound, Validation, Forbidden, Unavailable>> LoadFleetAsync(string path, CancellationToken cancellationToken) =>
        CliFiles.ReadJsonAsync(Path.GetFullPath(path), FleetJsonContext.Default.FleetConfig, cancellationToken);

    public static async Task<Result<IReadOnlyList<ServiceSpec>, NotFound, Validation, Forbidden, Unavailable>> LoadServicesAsync(string path, CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        IReadOnlyList<string> files = Directory.Exists(fullPath)
            ? [.. Directory.EnumerateFiles(fullPath, "*.json").Order(StringComparer.Ordinal)]
            : [fullPath];
        if (files.Count == 0)
        {
            return new NotFound($"{fullPath} holds no *.json service definitions.");
        }

        return await LoadFromAsync(files, 0, [], fullPath, cancellationToken);
    }

    private static async Task<Result<IReadOnlyList<ServiceSpec>, NotFound, Validation, Forbidden, Unavailable>> LoadFromAsync(
        IReadOnlyList<string> files,
        int index,
        IReadOnlyList<ServiceSpec> loaded,
        string fullPath,
        CancellationToken cancellationToken)
    {
        if (index == files.Count)
        {
            return Distinct(loaded, fullPath) switch
            {
                IReadOnlyList<ServiceSpec> services => new Result<IReadOnlyList<ServiceSpec>, NotFound, Validation, Forbidden, Unavailable>(services),
                Validation failure => failure,
            };
        }

        return await LoadFileAsync(files[index], cancellationToken) switch
        {
            IReadOnlyList<ServiceSpec> specs => await LoadFromAsync(files, index + 1, [.. loaded, .. specs], fullPath, cancellationToken),
            NotFound failure => failure,
            Validation failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
        };
    }

    private static Result<IReadOnlyList<ServiceSpec>, Validation> Distinct(IReadOnlyList<ServiceSpec> services, string fullPath) =>
        services.GroupBy(static service => service.Name, StringComparer.Ordinal).FirstOrDefault(static group => group.Count() > 1) is { } duplicate
            ? new Validation($"Service '{duplicate.Key}' is defined more than once under {fullPath}.")
            : new Result<IReadOnlyList<ServiceSpec>, Validation>(services);

    private static async Task<Result<IReadOnlyList<ServiceSpec>, NotFound, Validation, Forbidden, Unavailable>> LoadFileAsync(string file, CancellationToken cancellationToken) =>
        await CliFiles.ReadTextAsync(file, cancellationToken) switch
        {
            string content when content.TrimStart().StartsWith('[') => await CliFiles.ReadJsonAsync(file, FleetJsonContext.Default.IReadOnlyListServiceSpec, cancellationToken),
            string => await LoadSingleAsync(file, cancellationToken),
            NotFound failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
        };

    private static async Task<Result<IReadOnlyList<ServiceSpec>, NotFound, Validation, Forbidden, Unavailable>> LoadSingleAsync(string file, CancellationToken cancellationToken) =>
        await CliFiles.ReadJsonAsync(file, FleetJsonContext.Default.ServiceSpec, cancellationToken) switch
        {
            ServiceSpec spec => new Result<IReadOnlyList<ServiceSpec>, NotFound, Validation, Forbidden, Unavailable>([spec]),
            NotFound failure => failure,
            Validation failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
        };
}
