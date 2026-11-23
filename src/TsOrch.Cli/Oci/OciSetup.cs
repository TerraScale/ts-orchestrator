using TsOrch.Oci;

namespace TsOrch.Cli;

internal sealed record class OciClients(OciEnvironment Environment, OciImdsClient Imds, OciInstancePrincipal Principal, OciVaultClient Vault) : IDisposable
{
    public void Dispose() => Principal.Dispose();
}

internal static class OciSetup
{
    public static OrchResult<OciEnvironment> ResolveEnvironment(string? mockUrlOverride)
    {
        if (mockUrlOverride is null)
        {
            var configured = Environment.GetEnvironmentVariable(OciEnvironment.MockUrlVariable);
            return string.IsNullOrWhiteSpace(configured) || ParseMockUrl(configured) is not null
                ? OciEnvironment.FromEnvironment()
                : new Validation($"{OciEnvironment.MockUrlVariable} must be an absolute URL, got '{configured}'.");
        }

        return ParseMockUrl(mockUrlOverride) is { } mockUrl
            ? new OciMock(mockUrl)
            : new Validation($"--oci-mock-url must be an absolute URL, got '{mockUrlOverride}'.");
    }

    public static OciClients Create(HttpClient httpClient, OciEnvironment environment, TimeProvider timeProvider)
    {
        var imds = new OciImdsClient(httpClient, environment);
        var principal = new OciInstancePrincipal(httpClient, environment, imds, new OciRequestSigner(timeProvider), timeProvider);
        return new OciClients(environment, imds, principal, new OciVaultClient(httpClient, environment, imds, principal));
    }

    private static Uri? ParseMockUrl(string text) =>
        Uri.TryCreate(text.EndsWith('/') ? text : text + "/", UriKind.Absolute, out var url) ? url : null;
}
