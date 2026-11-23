namespace TsOrch.Cli;

internal sealed record class OperatorSettings(Uri? ExplicitUrl, string? Token, string KeyPath, string SessionFile)
{
    public const string UrlVariable = "TS_ORCH_URL";
    public const string TokenVariable = "TS_ORCH_TOKEN";
    public const string KeyVariable = "TS_ORCH_SSH_KEY";
    public const string SessionVariable = "TS_ORCH_SESSION_FILE";

    public static Uri DefaultUrl { get; } = new("https://orch.terrascale.tech/");

    public static Result<OperatorSettings, Validation> Resolve(string? urlOverride, string? keyOverride)
    {
        var keyPath = CliFiles.ExpandHome(keyOverride ?? Variable(KeyVariable) ?? "~/.ssh/id_ed25519");
        var sessionFile = CliFiles.ExpandHome(Variable(SessionVariable) ?? "~/.cache/ts-orch/session.json");
        if ((urlOverride ?? Variable(UrlVariable)) is not { } urlText)
        {
            return new OperatorSettings(null, Variable(TokenVariable), keyPath, sessionFile);
        }

        return ParseUrl(urlText) switch
        {
            Uri explicitUrl => new OperatorSettings(explicitUrl, Variable(TokenVariable), keyPath, sessionFile),
            Validation failure => failure,
        };
    }

    public static Result<Uri, Validation> ParseUrl(string text) =>
        Uri.TryCreate(text, UriKind.Absolute, out var url) && (url.Scheme == Uri.UriSchemeHttps || url.Scheme == Uri.UriSchemeHttp)
            ? url
            : new Validation($"'{text}' is not an absolute http(s) URL.");

    private static string? Variable(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : null;
}
