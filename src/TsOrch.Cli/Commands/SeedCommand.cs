namespace TsOrch.Cli;

internal static class SeedCommand
{
    public static IReadOnlyList<CliOption> Options { get; } =
    [
        new("fleet", null, true),
        new("services", null, true),
        new("replace", null, false),
        new("pool-id", null, true),
    ];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(0, "ts-orch seed [--fleet PATH] [--services DIR] [--replace] [--pool-id REGION=OCID]...") switch
        {
            CommandPositionalsAccepted => await ParsePoolsAndLoadAsync(arguments, environment, cancellationToken),
            CommandPositionalsInvalid invalid => environment.Usage($"usage: {invalid.Usage}"),
        };

    private static async Task<int> ParsePoolsAndLoadAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        Dictionary<string, string> poolIds = [with(StringComparer.Ordinal)];
        foreach (var entry in arguments.Values("pool-id"))
        {
            var separator = entry.IndexOf('=', StringComparison.Ordinal);
            if (separator <= 0 || separator >= entry.Length - 1)
            {
                return environment.Usage($"--pool-id must be <region>=<ocid>, got '{entry}'.");
            }

            poolIds[entry[..separator]] = entry[(separator + 1)..];
        }

        return await LoadFleetAsync(arguments, poolIds, environment, cancellationToken);
    }

    private static async Task<int> LoadFleetAsync(
        CliArguments arguments,
        Dictionary<string, string> poolIds,
        CommandEnvironment environment,
        CancellationToken cancellationToken)
    {
        var read = await SpecFiles.LoadFleetAsync(arguments.Value("fleet") ?? SpecFiles.DefaultFleetPath, cancellationToken);
        return read switch
        {
            FleetConfig fleet => await LoadServicesAsync(arguments, fleet, MergePoolIds(fleet, poolIds), environment, cancellationToken),
            CliFileReadProblem failure => environment.Fail(CliFiles.Describe(failure)),
            FleetDefinitionInvalid failure => environment.Fail(SpecFiles.Describe(failure)),
        };
    }

    private static Dictionary<string, string>? MergePoolIds(FleetConfig fleet, Dictionary<string, string> overrides)
    {
        Dictionary<string, string> merged = [with(StringComparer.Ordinal)];
        foreach (var region in fleet.Regions)
        {
            if (!string.IsNullOrWhiteSpace(region.InstancePoolId))
            {
                merged[region.Label] = region.InstancePoolId;
            }
        }

        foreach (var (region, poolId) in overrides)
        {
            merged[region] = poolId;
        }

        return merged.Count > 0 ? merged : null;
    }

    private static async Task<int> LoadServicesAsync(
        CliArguments arguments,
        FleetConfig fleet,
        IReadOnlyDictionary<string, string>? poolIds,
        CommandEnvironment environment,
        CancellationToken cancellationToken)
    {
        var read = await SpecFiles.LoadServicesAsync(arguments.Value("services") ?? SpecFiles.DefaultServicesPath, cancellationToken);
        return read switch
        {
            IReadOnlyList<ServiceSpec> services => await SeedAsync(new SeedRequest(fleet, services, arguments.Flag("replace"), poolIds), environment, cancellationToken),
            CliFileReadProblem failure => environment.Fail(CliFiles.Describe(failure)),
            ServiceDefinitionInvalid failure => environment.Fail(SpecFiles.Describe(failure)),
            DuplicateServiceDefinition failure => environment.Fail(SpecFiles.Describe(failure)),
            ServiceDefinitionsMissing failure => environment.Fail(SpecFiles.Describe(failure)),
        };
    }

    private static async Task<int> SeedAsync(SeedRequest request, CommandEnvironment environment, CancellationToken cancellationToken) =>
        await environment.Api.PostAsync("/api/fleet/seed", request, CliJsonContext.Default.SeedRequest, CliJsonContext.Default.SeedResponse, response => Task.FromResult(Report(response, environment.Out)), environment.Fail, cancellationToken);

    private static int Report(SeedResponse response, TextWriter output)
    {
        output.WriteLine($"Seeded regions: {Display.List(response.Regions)}");
        output.WriteLine($"Services added: {Display.List(response.Services.Added)}");
        output.WriteLine($"Services replaced: {Display.List(response.Services.Replaced)}");
        output.WriteLine($"Services skipped: {Display.List(response.Services.Skipped)}");
        return ExitCodes.Ok;
    }
}
