namespace TsOrch.Cli;

internal static class LoginCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("key", null, true), new("url", null, true)];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(0, "ts-orch login [--key PATH] [--url URL]") switch
        {
            CommandPositionalsAccepted => OperatorSettings.Resolve(arguments.Value("url"), arguments.Value("key")) switch
            {
                OperatorSettings settings => await LoginAsync(settings, environment, cancellationToken),
                InvalidBackplaneUrl invalid => environment.Usage(invalid.Message),
            },
            CommandPositionalsInvalid invalid => environment.Usage($"usage: {invalid.Usage}"),
        };

    private static async Task<int> LoginAsync(OperatorSettings settings, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var baseUrl = settings.ExplicitUrl ?? OperatorSettings.DefaultUrl;
        var outcome = await SshLogin.LoginAsync(environment.Http, baseUrl, settings.KeyPath, settings.SessionFile, interactive: true, cancellationToken);
        return outcome switch
        {
            CliSession session => Report(session, settings, environment),
            SshKeyInvalid invalid => environment.Usage(invalid.Message),
            SshKeyUnreadable unreadable => environment.Fail(unreadable.Diagnostic),
            ProcessLaunchFailed failed => environment.Fail(CliDiagnostic.Unavailable(failed.Message)),
            SshChallengeNamespaceInvalid invalid => environment.Fail(SshLogin.Describe(invalid)),
            SshSigningFailed failed => environment.Fail(SshLogin.Describe(failed)),
            SshChallengeFileUnavailable unavailable => environment.Fail(SshLogin.Describe(unavailable)),
            SshBackplaneRejected rejected => environment.Fail(SshLogin.Describe(rejected)),
            SshSessionWriteFailed failed => environment.Fail(failed.Diagnostic),
        };
    }

    private static int Report(CliSession session, OperatorSettings settings, CommandEnvironment environment)
    {
        environment.Out.WriteLine(
            $"Signed in to {session.Url} as {session.Owner} ({session.Role.WireName}) until {Display.Time(session.ExpiresAt)}; session saved to {settings.SessionFile}.");
        return ExitCodes.Ok;
    }
}
