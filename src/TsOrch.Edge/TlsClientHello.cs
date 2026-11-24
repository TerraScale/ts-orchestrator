namespace TsOrch.Edge;

internal static class TlsClientHello
{
    public static bool IsValidServerName(ReadOnlySpan<char> serverName)
    {
        if (serverName is [.., '.'])
        {
            serverName = serverName[..^1];
        }

        if (serverName.Length is 0 or > 253)
        {
            return false;
        }

        foreach (var range in serverName.Split('.'))
        {
            var label = serverName[range];
            if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-')
            {
                return false;
            }

            foreach (var character in label)
            {
                if (!char.IsAsciiLetterOrDigit(character) && character != '-')
                {
                    return false;
                }
            }
        }

        return true;
    }
}
