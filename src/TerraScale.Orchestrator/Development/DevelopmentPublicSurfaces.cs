namespace TerraScale.Orchestrator.Development;

/// <summary>
/// Public browser-facing surfaces published by DevHost Tailscale Serve.
/// When DevHost launches the lab it injects absolute HTTPS URLs so product
/// cookies, OAuth redirect_uri values, and CORS origins use MagicDNS rather
/// than loopback (which is unreachable from other tailnet devices).
/// </summary>
internal static class DevelopmentPublicSurfaces
{
    public const string PublicDashboardUrlEnvironmentVariable = "TERRASCALE_DEVHOST_PUBLIC_DASHBOARD_URL";
    public const string PublicDashboardApiUrlEnvironmentVariable = "TERRASCALE_DEVHOST_PUBLIC_DASHBOARD_API_URL";
    public const string PublicAuthenticationUrlEnvironmentVariable = "TERRASCALE_DEVHOST_PUBLIC_AUTH_URL";

    public static string? PublicDashboardUrl(Func<string, string?>? getEnvironmentVariable = null) =>
        ReadAbsoluteHttpUrl(PublicDashboardUrlEnvironmentVariable, getEnvironmentVariable);

    public static string? PublicDashboardApiUrl(Func<string, string?>? getEnvironmentVariable = null) =>
        ReadAbsoluteHttpUrl(PublicDashboardApiUrlEnvironmentVariable, getEnvironmentVariable);

    public static string? PublicAuthenticationUrl(Func<string, string?>? getEnvironmentVariable = null) =>
        ReadAbsoluteHttpUrl(PublicAuthenticationUrlEnvironmentVariable, getEnvironmentVariable);

    public static string ResolveDashboardPublicUrl(
        int localPort,
        Func<string, string?>? getEnvironmentVariable = null) =>
        PublicDashboardUrl(getEnvironmentVariable)
        ?? $"http://127.0.0.1:{localPort.ToString(System.Globalization.CultureInfo.InvariantCulture)}";

    private static string? ReadAbsoluteHttpUrl(
        string name,
        Func<string, string?>? getEnvironmentVariable)
    {
        var read = getEnvironmentVariable ?? Environment.GetEnvironmentVariable;
        var value = read(name)?.Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("http" or "https") ||
            string.IsNullOrWhiteSpace(uri.Host))
        {
            return null;
        }

        return value.TrimEnd('/');
    }
}
