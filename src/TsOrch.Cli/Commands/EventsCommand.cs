namespace TsOrch.Cli;

internal static class EventsCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("follow", 'f', false), new("region", null, true), new("limit", null, true)];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(0, "ts-orch events [-f] [--region R] [--limit N]") switch
        {
            CommandPositionalsAccepted => arguments.Int("limit", 100, 1, 2_000) switch
            {
                int limit when arguments.Flag("follow") => await FollowAsync(arguments.Value("region"), limit, environment, cancellationToken),
                int limit => await ListAsync(arguments.Value("region"), limit, environment, cancellationToken),
                InvalidCliInteger invalid => environment.Usage(invalid.Message),
            },
            CommandPositionalsInvalid invalid => environment.Usage($"usage: {invalid.Usage}"),
        };

    public static string Path(string? region, int limit, bool follow) =>
        Query.Build("/api/events", ("region", region), ("limit", Display.Integer(limit)), ("follow", follow ? "1" : null));

    private static async Task<int> FollowAsync(string? region, int limit, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var output = environment.Out;
        var streamed = await environment.Api.StreamAsync(
            Path(region, limit, follow: true),
            CliJsonContext.Default.EventRecord,
            async (record, token) =>
            {
                await output.WriteLineAsync(Format(record).AsMemory(), token);
                await output.FlushAsync(token);
            },
            cancellationToken);
        return streamed switch
        {
            BackplaneStreamCompleted => ExitCodes.Ok,
            BackplaneProblem failure => environment.FailRead(failure),
        };
    }

    private static async Task<int> ListAsync(string? region, int limit, CommandEnvironment environment, CancellationToken cancellationToken) =>
        await environment.Api.GetAsync(Path(region, limit, follow: false), CliJsonContext.Default.EventListResponse, response => Task.FromResult(Print(response.Events, environment.Out)), environment.FailRead, cancellationToken);

    private static int Print(IReadOnlyList<EventRecord> events, TextWriter output)
    {
        foreach (var record in events)
        {
            output.WriteLine(Format(record));
        }

        return ExitCodes.Ok;
    }

    private static string Format(EventRecord record)
    {
        var detail = string.Join(' ', record.Detail.OrderBy(static pair => pair.Key, StringComparer.Ordinal).Select(static pair => $"{pair.Key}={pair.Value}"));
        return $"{Display.Time(record.Ts)}  {record.Region ?? "-",-6}  {record.Kind.WireName,-18}  {record.Subject}  {detail}".TrimEnd();
    }
}
