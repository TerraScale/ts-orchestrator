using System.Globalization;

namespace TsOrch.AppHost;

internal sealed record class AppHostArgumentInvalid(string Message);

internal readonly union AppHostPort(int, AppHostArgumentInvalid);

internal readonly union AppHostUrl(Uri, AppHostArgumentInvalid);

internal static class AppHostArguments
{
    public static bool Has(IReadOnlyList<string> args, string flag) => args.Contains(flag, StringComparer.Ordinal);

    public static string? Value(IReadOnlyList<string> args, string name)
    {
        for (var index = 0; index < args.Count - 1; index++)
        {
            if (string.Equals(args[index], name, StringComparison.Ordinal))
            {
                return args[index + 1];
            }
        }

        return null;
    }

    public static IReadOnlyList<string> Values(IReadOnlyList<string> args, string name)
    {
        List<string> values = [];
        for (var index = 0; index < args.Count - 1; index++)
        {
            if (string.Equals(args[index], name, StringComparison.Ordinal))
            {
                values.Add(args[index + 1]);
            }
        }

        return values;
    }

    public static AppHostPort Port(IReadOnlyList<string> args, string name)
    {
        if (Value(args, name) is not { } raw)
        {
            return new AppHostArgumentInvalid($"{name} <port> is required.");
        }

        if (!int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
        {
            return new AppHostArgumentInvalid($"{name} must be a TCP port between 1 and 65535, got '{raw}'.");
        }

        return port;
    }

    public static AppHostUrl AbsoluteUrl(IReadOnlyList<string> args, string name)
    {
        if (Value(args, name) is not { } raw)
        {
            return new AppHostArgumentInvalid($"{name} <url> is required.");
        }

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var url) || (url.Scheme != Uri.UriSchemeHttp && url.Scheme != Uri.UriSchemeHttps))
        {
            return new AppHostArgumentInvalid($"{name} must be an absolute http(s) URL, got '{raw}'.");
        }

        return url;
    }
}
