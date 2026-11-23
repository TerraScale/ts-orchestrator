namespace TsOrch.Cli;

internal static class SeedCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("fleet", null, true), new("services", null, true), new("replace", null, false)];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(0, "ts-orch seed [--fleet PATH] [--services DIR] [--replace]") switch
        {
            CommandPositionalsAccepted => await LoadFleetAsync(arguments, environment, cancellationToken),
            CommandPositionalsInvalid invalid => environment.Usage($"usage: {invalid.Usage}"),
        };

    private static async Task<int> LoadFleetAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var read = await SpecFiles.LoadFleetAsync(arguments.Value("fleet") ?? SpecFiles.DefaultFleetPath, cancellationToken);
        return read switch
        {
            FleetConfig fleet => await LoadServicesAsync(arguments, fleet, environment, cancellationToken),
            CliFileReadProblem failure => environment.Fail(CliFiles.Describe(failure)),
            FleetDefinitionInvalid failure => environment.Fail(SpecFiles.Describe(failure)),
        };
    }

    private static async Task<int> LoadServicesAsync(CliArguments arguments, FleetConfig fleet, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var read = await SpecFiles.LoadServicesAsync(arguments.Value("services") ?? SpecFiles.DefaultServicesPath, cancellationToken);
        return read switch
        {
            IReadOnlyList<ServiceSpec> services => await SeedAsync(new SeedRequest(fleet, services, arguments.Flag("replace")), environment, cancellationToken),
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
