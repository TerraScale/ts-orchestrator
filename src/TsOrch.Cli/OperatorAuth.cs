namespace TsOrch.Cli;

internal sealed record class OperatorCredentials(Uri BaseUrl, string Token, DateTimeOffset? ExpiresAt);

internal sealed class OperatorAuth(OrchHttp http, CliConsole console, TimeProvider timeProvider, bool interactive)
{
    private static readonly TimeSpan ExpiryMargin = TimeSpan.FromMinutes(1);

    private OperatorCredentials? _credentials;

    public async Task<OrchResult<OperatorCredentials>> GetAsync(CancellationToken cancellationToken)
    {
        if (_credentials is { } cached && (cached.ExpiresAt is not { } expiresAt || expiresAt - ExpiryMargin > timeProvider.GetUtcNow()))
        {
            return cached;
        }

        if (!OperatorSettings.Resolve(urlOverride: null, keyOverride: null).TryGetValue(out var settings, out var settingsError))
        {
            return settingsError;
        }

        if (settings.Token is { } directToken)
        {
            return Remember(new OperatorCredentials(settings.ExplicitUrl ?? OperatorSettings.DefaultUrl, directToken, ExpiresAt: null));
        }

        var stored = await CliFiles.ReadJsonAsync(settings.SessionFile, CliJsonContext.Default.CliSession, cancellationToken);
        var session = stored switch
        {
            CliSession found => found,
            NotFound => null,
            OrchError error => Warn(error),
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
        var login = await SshLogin.LoginAsync(http, baseUrl, settings.KeyPath, settings.SessionFile, interactive, cancellationToken);
        return login switch
        {
            CliSession fresh => Remember(new OperatorCredentials(baseUrl, fresh.Token, DateTimeOffset.FromUnixTimeMilliseconds(fresh.ExpiresAt))),
            OrchError error => error,
        };
    }

    private OperatorCredentials Remember(OperatorCredentials credentials)
    {
        _credentials = credentials;
        return credentials;
    }

    private CliSession? Warn(OrchError error)
    {
        console.Error.WriteLine($"ts-orch: ignoring the cached session: {error.Message}");
        return null;
    }
}
