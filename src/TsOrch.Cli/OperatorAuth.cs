namespace TsOrch.Cli;

internal sealed record class OperatorCredentials(Uri BaseUrl, string Token, DateTimeOffset? ExpiresAt);

internal sealed class OperatorAuth(OrchHttp http, CliConsole console, TimeProvider timeProvider, bool interactive)
{
    private static readonly TimeSpan ExpiryMargin = TimeSpan.FromMinutes(1);

    private OperatorCredentials? _credentials;

    public async Task<Result<OperatorCredentials, Validation, Unauthorized, Forbidden, Unavailable>> GetAsync(CancellationToken cancellationToken)
    {
        if (_credentials is { } cached && (cached.ExpiresAt is not { } expiresAt || expiresAt - ExpiryMargin > timeProvider.GetUtcNow()))
        {
            return cached;
        }

        return OperatorSettings.Resolve(urlOverride: null, keyOverride: null) switch
        {
            OperatorSettings settings => await SignInAsync(settings, cancellationToken),
            Validation failure => failure,
        };
    }

    private async Task<Result<OperatorCredentials, Validation, Unauthorized, Forbidden, Unavailable>> SignInAsync(
        OperatorSettings settings,
        CancellationToken cancellationToken)
    {
        if (settings.Token is { } directToken)
        {
            return Remember(new OperatorCredentials(settings.ExplicitUrl ?? OperatorSettings.DefaultUrl, directToken, ExpiresAt: null));
        }

        var session = await CliFiles.ReadJsonAsync(settings.SessionFile, CliJsonContext.Default.CliSession, cancellationToken) switch
        {
            CliSession found => found,
            NotFound => null,
            Validation failure => Warn(failure.Message),
            Forbidden failure => Warn(failure.Message),
            Unavailable failure => Warn(failure.Message),
        };
        var sessionUrl = session is not null && Uri.TryCreate(session.Url, UriKind.Absolute, out var parsed) ? parsed : null;
        var baseUrl = settings.ExplicitUrl ?? sessionUrl ?? OperatorSettings.DefaultUrl;
        if (session is not null && sessionUrl == baseUrl && DateTimeOffset.FromUnixTimeMilliseconds(session.ExpiresAt) - ExpiryMargin > timeProvider.GetUtcNow())
        {
            return Remember(new OperatorCredentials(baseUrl, session.Token, DateTimeOffset.FromUnixTimeMilliseconds(session.ExpiresAt)));
        }

        if (!SshLogin.KeyAvailable(settings.KeyPath))
        {
            return new Unauthorized($"No valid ts-orch session for {baseUrl} and no SSH key at {settings.KeyPath}; run `ts-orch login --key <path>`.");
        }

        console.Error.WriteLine($"ts-orch: signing in to {baseUrl} with {settings.KeyPath}");
        return await SshLogin.LoginAsync(http, baseUrl, settings.KeyPath, settings.SessionFile, interactive, cancellationToken) switch
        {
            CliSession fresh => Remember(new OperatorCredentials(baseUrl, fresh.Token, DateTimeOffset.FromUnixTimeMilliseconds(fresh.ExpiresAt))),
            Validation failure => failure,
            Unauthorized failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
        };
    }

    private OperatorCredentials Remember(OperatorCredentials credentials)
    {
        _credentials = credentials;
        return credentials;
    }

    private CliSession? Warn(string message)
    {
        console.Error.WriteLine($"ts-orch: ignoring the cached session: {message}");
        return null;
    }
}
