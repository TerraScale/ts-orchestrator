using System.Globalization;
using System.Text;

namespace TerraScale.Orchestrator.Bootstrap;

/// <summary>
/// Canonical length-prefixed encoding for every signed cold-bootstrap value.
/// Each field becomes one "length:value;" record, exactly like the CreateNode
/// handoff receipt codec in <c>ControlPlane/Providers/CreateNodeHandoffReceipt.cs</c>.
/// Encoding is deterministic and strict parsing rejects any reordered,
/// resized, padded, or trailing content, so the signed bytes always cover the
/// exact typed payload the verifier rebuilds.
/// </summary>
internal static class BootstrapGrantCanonical
{
    public static string Encode(params object[] fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        var builder = new StringBuilder(fields.Length * 32);
        foreach (var field in fields) Append(builder, Convert.ToString(field, CultureInfo.InvariantCulture) ?? string.Empty);
        return builder.ToString();
    }

    public static string EncodeFields(IReadOnlyList<string> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        var builder = new StringBuilder(fields.Count * 32);
        foreach (var field in fields) Append(builder, field);
        return builder.ToString();
    }

    /// <summary>Strictly parses "length:value;" records. Throws <see cref="FormatException"/> on any deviation.</summary>
    public static List<string> Parse(string text)
    {
        ArgumentException.ThrowIfNullOrEmpty(text);
        var records = new List<string>();
        var position = 0;
        while (position < text.Length)
        {
            var separator = text.IndexOf(':', position);
            if (separator < 0) throw new FormatException("A canonical record must contain a length separator.");
            var lengthText = text[position..separator];
            if (lengthText.Length is 0 or > 9 || lengthText.Any(static c => c is < '0' or > '9'))
                throw new FormatException("A canonical record length must be a bounded decimal.");
            var length = int.Parse(lengthText, CultureInfo.InvariantCulture);
            var valueStart = separator + 1;
            var valueEnd = valueStart + length;
            if (valueEnd >= text.Length || text[valueEnd] != ';')
                throw new FormatException("A canonical record must end exactly after its declared length.");
            records.Add(text[valueStart..valueEnd]);
            position = valueEnd + 1;
        }

        return records;
    }

    public static string ValidateToken(string value, string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(value, name);
        if (value.Length > 128 || !value.All(static c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '.' or '-'))
            throw new ArgumentException("Bootstrap grant tokens are bounded canonical ASCII identifiers.", name);
        return value;
    }

    public static string ValidateLowercaseHex(string value, int expectedLength, string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(value, name);
        if (value.Length != expectedLength || value.Any(static c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new ArgumentException($"The value must be {expectedLength} lowercase hexadecimal characters.", name);
        return value;
    }

    private static void Append(StringBuilder builder, string value)
    {
        builder.Append(value.Length.ToString(CultureInfo.InvariantCulture));
        builder.Append(':');
        builder.Append(value);
        builder.Append(';');
    }
}
