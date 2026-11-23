using System.Globalization;

namespace TsOrch.Cli;

internal sealed record class CliOption(string Name, char? Short, bool TakesValue);

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

    public OrchResult<int> Int(string name, int fallback, int min, int max) =>
        Value(name) is not { } text
            ? fallback
            : ParseInt($"--{name}", text, min, max);

    public static OrchResult<int> ParseInt(string label, string text, int min, int max) =>
        int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) && parsed >= min && parsed <= max
            ? parsed
            : new Validation(string.Create(CultureInfo.InvariantCulture, $"{label} must be an integer between {min} and {max}, got '{text}'."));

    public static OrchResult<bool> ParseBool(string label, string text) => text switch
    {
        "true" => true,
        "false" => false,
        _ => new Validation($"{label} must be 'true' or 'false', got '{text}'."),
    };

    public static OrchResult<CliArguments> Parse(IReadOnlyList<string> args, IReadOnlyList<CliOption> options)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(options);
        List<string> positionals = [];
        List<string> trailing = [];
        Dictionary<string, string> values = new(StringComparer.Ordinal);
        HashSet<string> flags = new(StringComparer.Ordinal);
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
                return new Validation($"Unknown option '{lookup}'.");
            }

            if (!option.TakesValue)
            {
                if (inline is not null)
                {
                    return new Validation($"Option '--{option.Name}' does not take a value.");
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
                return new Validation($"Option '--{option.Name}' needs a value.");
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
