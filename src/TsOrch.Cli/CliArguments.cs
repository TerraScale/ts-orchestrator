using System.Globalization;

namespace TsOrch.Cli;

internal sealed record class CliOption(string Name, char? Short, bool TakesValue);

internal sealed record class InvalidCliInteger(string Label, string Input, int Min, int Max)
{
    public string Message => string.Create(CultureInfo.InvariantCulture, $"{Label} must be an integer between {Min} and {Max}, got '{Input}'.");
}

internal sealed record class InvalidCliBoolean(string Label, string Input)
{
    public string Message => $"{Label} must be 'true' or 'false', got '{Input}'.";
}

internal sealed record class UnknownCliOption(string Name);

internal sealed record class CliOptionValueMissing(string Name);

internal sealed record class CliOptionValueUnexpected(string Name);

internal readonly union CliInteger(int, InvalidCliInteger);

internal readonly union CliBoolean(bool, InvalidCliBoolean);

internal readonly union CliArgumentParse(CliArguments, UnknownCliOption, CliOptionValueMissing, CliOptionValueUnexpected);

internal sealed class CliArguments
{
    private const string HelpName = "help";

    private readonly Dictionary<string, string> _values;
    private readonly HashSet<string> _flags;

    private CliArguments(List<string> positionals, List<string> trailing, Dictionary<string, string> values, HashSet<string> flags)
    {
        Positionals = positionals;
        Trailing = trailing;
        _values = values;
        _flags = flags;
    }

    public IReadOnlyList<string> Positionals { get; }

    public IReadOnlyList<string> Trailing { get; }

    public bool HelpRequested => _flags.Contains(HelpName);

    public string? Value(string name) => _values.GetValueOrDefault(name);

    public bool Flag(string name) => _flags.Contains(name);

    public string? Setting(string name, string environmentVariable) =>
        Value(name) ?? (Environment.GetEnvironmentVariable(environmentVariable) is { Length: > 0 } fromEnvironment ? fromEnvironment : null);

    public CliInteger Int(string name, int fallback, int min, int max) =>
        Value(name) is not { } text
            ? fallback
            : ParseInt($"--{name}", text, min, max);

    public static CliInteger ParseInt(string label, string text, int min, int max) =>
        int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) && parsed >= min && parsed <= max
            ? parsed
            : new InvalidCliInteger(label, text, min, max);

    public static CliBoolean ParseBool(string label, string text) => text switch
    {
        "true" => true,
        "false" => false,
        _ => new InvalidCliBoolean(label, text),
    };

    public static CliArgumentParse Parse(IReadOnlyList<string> args, IReadOnlyList<CliOption> options)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(options);
        List<string> positionals = [];
        List<string> trailing = [];
        Dictionary<string, string> values = [with(StringComparer.Ordinal)];
        HashSet<string> flags = [with(StringComparer.Ordinal)];
        for (var index = 0; index < args.Count; index++)
        {
            var token = args[index];
            if (token == "--")
            {
                trailing.AddRange(args.Skip(index + 1));
                break;
            }

            if (token is "-h" or "--help")
            {
                flags.Add(HelpName);
                continue;
            }

            if (token.Length < 2 || token[0] != '-')
            {
                positionals.Add(token);
                continue;
            }

            var (lookup, inline) = SplitToken(token);
            var option = lookup switch
            {
                ['-', '-', .. var longName] => options.FirstOrDefault(candidate => candidate.Name == longName),
                [_, var shortName] => options.FirstOrDefault(candidate => candidate.Short == shortName),
                _ => null,
            };
            if (option is null)
            {
                return new UnknownCliOption(lookup);
            }

            if (!option.TakesValue)
            {
                if (inline is not null)
                {
                    return new CliOptionValueUnexpected(option.Name);
                }

                flags.Add(option.Name);
                continue;
            }

            if (inline is not null)
            {
                values[option.Name] = inline;
                continue;
            }

            if (index + 1 >= args.Count)
            {
                return new CliOptionValueMissing(option.Name);
            }

            values[option.Name] = args[++index];
        }

        return new CliArguments(positionals, trailing, values, flags);
    }

    private static (string Lookup, string? Inline) SplitToken(string token)
    {
        if (!token.StartsWith("--", StringComparison.Ordinal))
        {
            return (token, null);
        }

        var separator = token.IndexOf('=', StringComparison.Ordinal);
        return separator < 0 ? (token, null) : (token[..separator], token[(separator + 1)..]);
    }
}
