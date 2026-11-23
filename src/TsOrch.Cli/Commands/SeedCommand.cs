namespace TsOrch.Cli;

internal static class SeedCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("fleet", null, true), new("services", null, true), new("replace", null, false)];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(0, "ts-orch seed [--fleet PATH] [--services DIR] [--replace]") switch
        {
            Done => await SpecFiles.LoadFleetAsync(arguments.Value("fleet") ?? SpecFiles.DefaultFleetPath, cancellationToken) switch
            {
                FleetConfig fleet => await SpecFiles.LoadServicesAsync(arguments.Value("services") ?? SpecFiles.DefaultServicesPath, cancellationToken) switch
                {
                    IReadOnlyList<ServiceSpec> services => await SeedAsync(new SeedRequest(fleet, services, arguments.Flag("replace")), environment, cancellationToken),
                    NotFound failure => environment.Fail(failure),
                    Validation failure => environment.Fail(failure),
                    Forbidden failure => environment.Fail(failure),
                    Unavailable failure => environment.Fail(failure),
                },
                NotFound failure => environment.Fail(failure),
                Validation failure => environment.Fail(failure),
                Forbidden failure => environment.Fail(failure),
                Unavailable failure => environment.Fail(failure),
            },
            Validation failure => environment.Fail(failure),
        };

    private static async Task<int> SeedAsync(SeedRequest request, CommandEnvironment environment, CancellationToken cancellationToken) =>
        await environment.Api.PostAsync("/api/fleet/seed", request, CliJsonContext.Default.SeedRequest, CliJsonContext.Default.SeedResponse, cancellationToken) switch
        {
            SeedResponse response => Report(response, environment.Out),
            Validation failure => environment.Fail(failure),
            NotFound failure => environment.Fail(failure),
            Conflict failure => environment.Fail(failure),
            Unauthorized failure => environment.Fail(failure),
            Forbidden failure => environment.Fail(failure),
            Unavailable failure => environment.Fail(failure),
        };

    private static int Report(SeedResponse response, TextWriter output)
    {
        output.WriteLine($"Seeded regions: {Display.List(response.Regions)}");
        output.WriteLine($"Services added: {Display.List(response.Services.Added)}");
        output.WriteLine($"Services replaced: {Display.List(response.Services.Replaced)}");
        output.WriteLine($"Services skipped: {Display.List(response.Services.Skipped)}");
        return ExitCodes.Ok;
    }
}
