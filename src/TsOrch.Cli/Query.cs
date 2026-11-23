using System.Text;

namespace TsOrch.Cli;

internal static class Query
{
    public static string Build(string path, params ReadOnlySpan<(string Name, string? Value)> parameters)
    {
        var builder = new StringBuilder(path);
        var separator = '?';
        foreach (var (name, value) in parameters)
        {
            if (value is null)
            {
                continue;
            }

            builder.Append(separator).Append(Uri.EscapeDataString(name)).Append('=').Append(Uri.EscapeDataString(value));
            separator = '&';
        }

        return builder.ToString();
    }
}
