namespace TsOrch.Cli;

internal static class SeedCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("fleet", null, true), new("services", null, true), new("replace", null, false)];

    public static async Task<OrchResult<int>> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        if (!arguments.ExpectPositionals(0, "ts-orch seed [--fleet PATH] [--services DIR] [--replace]").TryGetValue(out _, out var usageError))
        {
            return usageError;
        }

        var fleetResult = await SpecFiles.LoadFleetAsync(arguments.Value("fleet") ?? SpecFiles.DefaultFleetPath, cancellationToken);
        if (!fleetResult.TryGetValue(out var fleet, out var fleetError))
        {
            return fleetError;
        }

        var servicesResult = await SpecFiles.LoadServicesAsync(arguments.Value("services") ?? SpecFiles.DefaultServicesPath, cancellationToken);
        if (!servicesResult.TryGetValue(out var services, out var servicesError))
        {
            return servicesError;
        }

        var seeded = await environment.Api.PostAsync(
            "/api/fleet/seed",
            new SeedRequest(fleet, services, arguments.Flag("replace")),
            CliJsonContext.Default.SeedRequest,
            CliJsonContext.Default.SeedResponse,
            cancellationToken);
        if (!seeded.TryGetValue(out var response, out var seedError))
        {
            return seedError;
        }

        environment.Out.WriteLine($"Seeded regions: {Display.List(response.Regions)}");
        environment.Out.WriteLine($"Services added: {Display.List(response.Services.Added)}");
        environment.Out.WriteLine($"Services replaced: {Display.List(response.Services.Replaced)}");
        environment.Out.WriteLine($"Services skipped: {Display.List(response.Services.Skipped)}");
        return ExitCodes.Ok;
    }
}
