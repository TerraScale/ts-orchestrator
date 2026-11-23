namespace TsOrch.Cli;

internal static class LoginCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("key", null, true), new("url", null, true)];

    public static async Task<OrchResult<int>> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        if (!arguments.ExpectPositionals(0, "ts-orch login [--key PATH] [--url URL]").TryGetValue(out _, out var usageError))
        {
            return usageError;
        }

        if (!OperatorSettings.Resolve(arguments.Value("url"), arguments.Value("key")).TryGetValue(out var settings, out var settingsError))
        {
            return settingsError;
        }

        var baseUrl = settings.ExplicitUrl ?? OperatorSettings.DefaultUrl;
        var login = await SshLogin.LoginAsync(environment.Http, baseUrl, settings.KeyPath, settings.SessionFile, interactive: true, cancellationToken);
        if (!login.TryGetValue(out var session, out var loginError))
        {
            return loginError;
        }

        environment.Out.WriteLine(
            $"Signed in to {session.Url} as {session.Owner} ({session.Role.WireName}) until {Display.Time(session.ExpiresAt)}; session saved to {settings.SessionFile}.");
        return ExitCodes.Ok;
    }
}
