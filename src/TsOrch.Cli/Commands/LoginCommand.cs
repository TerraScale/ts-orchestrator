namespace TsOrch.Cli;

internal static class LoginCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("key", null, true), new("url", null, true)];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(0, "ts-orch login [--key PATH] [--url URL]") switch
        {
            Done => OperatorSettings.Resolve(arguments.Value("url"), arguments.Value("key")) switch
            {
                OperatorSettings settings => await LoginAsync(settings, environment, cancellationToken),
                Validation failure => environment.Fail(failure),
            },
            Validation failure => environment.Fail(failure),
        };

    private static async Task<int> LoginAsync(OperatorSettings settings, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var baseUrl = settings.ExplicitUrl ?? OperatorSettings.DefaultUrl;
        return await SshLogin.LoginAsync(environment.Http, baseUrl, settings.KeyPath, settings.SessionFile, interactive: true, cancellationToken) switch
        {
            CliSession session => Report(session, settings, environment),
            Validation failure => environment.Fail(failure),
            Unauthorized failure => environment.Fail(failure),
            Forbidden failure => environment.Fail(failure),
            Unavailable failure => environment.Fail(failure),
        };
    }

    private static int Report(CliSession session, OperatorSettings settings, CommandEnvironment environment)
    {
        environment.Out.WriteLine(
            $"Signed in to {session.Url} as {session.Owner} ({session.Role.WireName}) until {Display.Time(session.ExpiresAt)}; session saved to {settings.SessionFile}.");
        return ExitCodes.Ok;
    }
}
