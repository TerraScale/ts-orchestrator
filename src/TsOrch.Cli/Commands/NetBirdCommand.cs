namespace TsOrch.Cli;

internal static class NetBirdCommand
{
    public const string Usage = """
        ts-orch netbird init [--fleet PATH] [--api URL] [--pat-file PATH] [--owner-password-file PATH] [--write-setup-keys-dir DIR]
               ts-orch netbird join [--fleet PATH] [--url URL] [--hostname NAME] [--setup-key-file PATH]
               ts-orch netbird enroll [--url URL] [--vault OCID] [--secret NAME] [--hostname NAME]
               ts-orch netbird status [--json] [--fleet PATH] [--api URL] [--pat-file PATH]
        """;

    public static IReadOnlyList<CliOption> Options { get; } =
    [
        new("fleet", null, true),
        new("api", null, true),
        new("pat-file", null, true),
        new("owner-password-file", null, true),
        new("write-setup-keys-dir", null, true),
        new("url", null, true),
        new("hostname", null, true),
        new("setup-key-file", null, true),
        new("vault", null, true),
        new("secret", null, true),
        new("json", null, false),
    ];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        if (arguments.Positionals is not [var verb] || arguments.Trailing.Count > 0)
        {
            return environment.Usage($"usage: {Usage}");
        }

        if (InvalidOption(verb, arguments) is { } option)
        {
            return environment.Usage($"Option '--{option}' is not available for netbird {verb}.");
        }

        foreach (var named in Options)
        {
            if (arguments.Value(named.Name) is { } value && string.IsNullOrWhiteSpace(value))
            {
                return environment.Usage($"Option '--{named.Name}' needs a non-empty value.");
            }
        }

        var client = new NetBirdClient(environment.TimeProvider);
        return verb switch
        {
            "init" => await InitAsync(arguments, environment, cancellationToken),
            "join" => await new NetBirdJoin(client, environment).RunAsync(
                new NetBirdJoinOptions(arguments.Value("fleet"), arguments.Value("url"), arguments.Value("hostname"), arguments.Value("setup-key-file")),
                cancellationToken),
            "enroll" => await new NetBirdEnrollment(client, environment).RunAsync(
                new NetBirdEnrollmentOptions(
                    arguments.Setting("url", "TS_ORCH_NETBIRD_URL"),
                    arguments.Setting("vault", "TS_ORCH_ENROLL_SECRET_VAULT"),
                    arguments.Setting("secret", "TS_ORCH_NETBIRD_SETUP_KEY_SECRET"),
                    arguments.Setting("hostname", "TS_ORCH_NODE_ID")),
                cancellationToken),
            "status" => await StatusAsync(arguments, environment, cancellationToken),
            _ => environment.Usage($"usage: {Usage}"),
        };
    }

    private static string? InvalidOption(string verb, CliArguments arguments)
    {
        IReadOnlyList<string> allowed = verb switch
        {
            "init" => ["fleet", "api", "pat-file", "owner-password-file", "write-setup-keys-dir"],
            "join" => ["fleet", "url", "hostname", "setup-key-file"],
            "enroll" => ["url", "vault", "secret", "hostname"],
            "status" => ["json", "fleet", "api", "pat-file"],
            _ => [],
        };
        return Options.Select(static option => option.Name).FirstOrDefault(name =>
            (arguments.Flag(name) || arguments.Value(name) is not null) && allowed.Contains(name, StringComparer.Ordinal) is false);
    }

    private static async Task<int> InitAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var outcome = await NetBirdFleet.LoadAsync(environment.Api, arguments.Value("fleet"), cancellationToken);
        return outcome switch
        {
            FleetConfig fleet => await new NetBirdInitializer(environment).RunAsync(fleet,
                new NetBirdInitOptions(arguments.Value("api"), arguments.Value("pat-file"), arguments.Value("owner-password-file"), arguments.Value("write-setup-keys-dir")),
                cancellationToken),
            NetBirdFleetUnavailable unavailable => environment.Fail(unavailable.Diagnostic),
        };
    }

    private static async Task<int> StatusAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var options = new NetBirdStatusOptions(arguments.Value("fleet"), arguments.Value("api"), arguments.Value("pat-file"));
        var report = await new NetBirdStatus(environment.Api, environment.TimeProvider).ReadAsync(options, cancellationToken);
        if (arguments.Flag("json"))
        {
            environment.Out.WriteLine(report.ToJson());
        }
        else
        {
            report.Write(environment.Out);
        }

        return report.Local is null && report.Fleet is null ? ExitCodes.ServiceUnavailable : ExitCodes.Ok;
    }
}
