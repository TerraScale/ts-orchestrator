namespace TsOrch.Cli;

internal static class EventsCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("follow", 'f', false), new("region", null, true), new("limit", null, true)];

    public static async Task<OrchResult<int>> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        if (!arguments.ExpectPositionals(0, "ts-orch events [-f] [--region R] [--limit N]").TryGetValue(out _, out var usageError))
        {
            return usageError;
        }

        if (!arguments.Int("limit", 100, 1, 2_000).TryGetValue(out var limit, out var limitError))
        {
            return limitError;
        }

        var region = arguments.Value("region");
        var output = environment.Out;
        if (arguments.Flag("follow"))
        {
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
                Done => ExitCodes.Ok,
                OrchError error => error,
            };
        }

        var listed = await environment.Api.GetAsync(Path(region, limit, follow: false), CliJsonContext.Default.EventListResponse, cancellationToken);
        if (!listed.TryGetValue(out var response, out var listError))
        {
            return listError;
        }

        foreach (var record in response.Events)
        {
            output.WriteLine(Format(record));
        }

        return ExitCodes.Ok;
    }

    public static string Path(string? region, int limit, bool follow) =>
        Query.Build("/api/events", ("region", region), ("limit", Display.Integer(limit)), ("follow", follow ? "1" : null));

    private static string Format(EventRecord record)
    {
        var detail = string.Join(' ', record.Detail.OrderBy(static pair => pair.Key, StringComparer.Ordinal).Select(static pair => $"{pair.Key}={pair.Value}"));
        return $"{Display.Time(record.Ts)}  {record.Region ?? "-",-6}  {record.Kind.WireName,-18}  {record.Subject}  {detail}".TrimEnd();
    }
}
