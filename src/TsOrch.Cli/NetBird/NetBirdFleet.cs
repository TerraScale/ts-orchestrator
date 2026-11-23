namespace TsOrch.Cli;

internal sealed record class NetBirdFleetUnavailable(CliDiagnostic Diagnostic);

internal readonly union NetBirdFleetLookup(FleetConfig, NetBirdFleetUnavailable);

internal static class NetBirdFleet
{
    public static async Task<NetBirdFleetLookup> LoadAsync(OrchApi api, string? path, CancellationToken cancellationToken)
    {
        if (path is not null)
        {
            var file = await SpecFiles.LoadFleetAsync(path, cancellationToken);
            return file switch
            {
                FleetConfig fleet => fleet,
                CliFileReadProblem problem => new NetBirdFleetUnavailable(CliFiles.Describe(problem)),
                FleetDefinitionInvalid invalid => new NetBirdFleetUnavailable(SpecFiles.Describe(invalid)),
            };
        }

        var outcome = await api.GetFleetAsync(cancellationToken);
        return outcome switch
        {
            FleetConfig fleet => fleet,
            BackplaneProblem problem => new NetBirdFleetUnavailable(CliDiagnostic.From(problem, unexpectedConflict: true)),
        };
    }
}
