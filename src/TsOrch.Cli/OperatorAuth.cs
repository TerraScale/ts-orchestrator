namespace TsOrch.Cli;

internal sealed record class OperatorCredentials(Uri BaseUrl, string Token, DateTimeOffset? ExpiresAt);

internal sealed record class OperatorKeyMissing(Uri BaseUrl, string Path)
{
    public string Message => $"No valid ts-orch session for {BaseUrl} and no SSH key at {Path}; run `ts-orch login --key <path>`.";
}

internal sealed record class OperatorSignInFailed(CliDiagnostic Diagnostic);

internal readonly union OperatorAuthentication(OperatorCredentials, InvalidBackplaneUrl, OperatorKeyMissing, OperatorSignInFailed);

internal sealed class OperatorAuth(OrchHttp http, CliConsole console, TimeProvider timeProvider, bool interactive)
{
    private static readonly TimeSpan ExpiryMargin = TimeSpan.FromMinutes(1);

    private OperatorCredentials? _credentials;

    public async Task<OperatorAuthentication> GetAsync(CancellationToken cancellationToken)
    {
        if (_credentials is { } cached && (cached.ExpiresAt is not { } expiresAt || expiresAt - ExpiryMargin > timeProvider.GetUtcNow()))
        {
            return cached;
        }

        return OperatorSettings.Resolve(urlOverride: null, keyOverride: null) switch
        {
            OperatorSettings settings => await SignInAsync(settings, cancellationToken),
            InvalidBackplaneUrl invalid => invalid,
        };
    }

    private async Task<OperatorAuthentication> SignInAsync(OperatorSettings settings, CancellationToken cancellationToken)
    {
        if (settings.Token is { } directToken)
        {
            return Remember(new OperatorCredentials(settings.ExplicitUrl ?? OperatorSettings.DefaultUrl, directToken, ExpiresAt: null));
        }

        var session = await ReadSessionAsync(settings.SessionFile, cancellationToken);
        var sessionUrl = session is not null && Uri.TryCreate(session.Url, UriKind.Absolute, out var parsed) ? parsed : null;
        var baseUrl = settings.ExplicitUrl ?? sessionUrl ?? OperatorSettings.DefaultUrl;
        if (session is not null && sessionUrl == baseUrl && DateTimeOffset.FromUnixTimeMilliseconds(session.ExpiresAt) - ExpiryMargin > timeProvider.GetUtcNow())
        {
            return Remember(new OperatorCredentials(baseUrl, session.Token, DateTimeOffset.FromUnixTimeMilliseconds(session.ExpiresAt)));
        }

        if (!SshLogin.KeyAvailable(settings.KeyPath))
        {
            return new OperatorKeyMissing(baseUrl, settings.KeyPath);
        }

        console.Error.WriteLine($"ts-orch: signing in to {baseUrl} with {settings.KeyPath}");
        var outcome = await SshLogin.LoginAsync(http, baseUrl, settings.KeyPath, settings.SessionFile, interactive, cancellationToken);
        return outcome switch
        {
            CliSession fresh => Remember(new OperatorCredentials(baseUrl, fresh.Token, DateTimeOffset.FromUnixTimeMilliseconds(fresh.ExpiresAt))),
            SshKeyInvalid invalid => new OperatorSignInFailed(CliDiagnostic.Usage(invalid.Message)),
            SshKeyUnreadable unreadable => new OperatorSignInFailed(unreadable.Diagnostic),
            ProcessLaunchFailed failed => new OperatorSignInFailed(CliDiagnostic.Unavailable(failed.Message)),
            SshChallengeNamespaceInvalid invalid => new OperatorSignInFailed(SshLogin.Describe(invalid)),
            SshSigningFailed failed => new OperatorSignInFailed(SshLogin.Describe(failed)),
            SshChallengeFileUnavailable unavailable => new OperatorSignInFailed(SshLogin.Describe(unavailable)),
            SshBackplaneRejected rejected => new OperatorSignInFailed(SshLogin.Describe(rejected)),
            SshSessionWriteFailed failed => new OperatorSignInFailed(failed.Diagnostic),
        };
    }

    private async Task<CliSession?> ReadSessionAsync(string path, CancellationToken cancellationToken)
    {
        var read = await CliFiles.ReadTextAsync(path, cancellationToken);
        return read switch
        {
            string body => DecodeSession(path, body),
            CliFileReadProblem problem => problem switch
            {
                CliFileMissing => null,
                CliFileReadDenied or CliFileReadInterrupted => Warn(CliFiles.Describe(problem).Message),
            },
        };
    }

    private CliSession? DecodeSession(string path, string body) =>
        OrchHttp.Decode(body, CliJsonContext.Default.CliSession, out var error) is { } session
        && session.ExpiresAt is >= -62_135_596_800_000 and <= 253_402_300_799_999
            ? session
            : Warn($"Invalid session in {path}: {error ?? "Expiry is out of range."}");

    private OperatorCredentials Remember(OperatorCredentials credentials)
    {
        _credentials = credentials;
        return credentials;
    }

    private CliSession? Warn(string message)
    {
        console.Error.WriteLine($"ts-orch: {message}");
        return null;
    }
}
