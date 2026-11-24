using System.Globalization;

namespace TsOrch.Cli;

internal static class TlsCommand
{
    private const string UsageText = "ts-orch tls status | ensure";
    private static readonly TimeSpan EnsureTimeout = TimeSpan.FromMinutes(3);

    public static IReadOnlyList<CliOption> Options { get; } = [];

    public static Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.Positionals switch
        {
            ["status"] => StatusAsync(environment, cancellationToken),
            ["ensure"] => EnsureAsync(environment, cancellationToken),
            _ => Task.FromResult(environment.Usage($"usage: {UsageText}")),
        };

    private static async Task<int> StatusAsync(CommandEnvironment environment, CancellationToken cancellationToken) =>
        await environment.Api.GetAsync("/api/tls", CliJsonContext.Default.TlsStatusResponse, response => Task.FromResult(RenderStatus(response, environment.Out)), environment.FailRead, cancellationToken);

    private static async Task<int> EnsureAsync(CommandEnvironment environment, CancellationToken cancellationToken) =>
        await environment.Api.PostEmptyAsync("/api/tls/ensure", CliJsonContext.Default.TlsEnsureResponse, EnsureTimeout, response => Task.FromResult(RenderEnsure(response, environment.Out)), environment.Fail, cancellationToken);

    private static int RenderStatus(TlsStatusResponse status, TextWriter output)
    {
        if (!status.Configured)
        {
            output.WriteLine("TLS certificate: not configured");
        }
        else
        {
            output.WriteLine($"TLS domains: {Display.List(status.Domains)}");
            if (status.NotAfter is { } notAfter)
            {
                output.WriteLine($"Valid until: {DateTimeOffset.FromUnixTimeMilliseconds(notAfter).ToString("O", CultureInfo.InvariantCulture)}");
            }

            if (status.RenewedAt is { } renewedAt)
            {
                output.WriteLine($"Renewed at:  {DateTimeOffset.FromUnixTimeMilliseconds(renewedAt).ToString("O", CultureInfo.InvariantCulture)}");
            }
        }

        if (status.Error is { } error)
        {
            output.WriteLine($"Last error:  {error.Message}");
        }

        return ExitCodes.Ok;
    }

    private static int RenderEnsure(TlsEnsureResponse response, TextWriter output)
    {
        var action = response.Renewed ? "Renewed" : "Current";
        output.WriteLine($"{action} TLS certificate for {Display.List(response.Domains)}");
        output.WriteLine($"Valid until: {DateTimeOffset.FromUnixTimeMilliseconds(response.NotAfter).ToString("O", CultureInfo.InvariantCulture)}");
        output.WriteLine($"Pushed to:   {Display.List(response.PushedTo)}");
        return ExitCodes.Ok;
    }
}
