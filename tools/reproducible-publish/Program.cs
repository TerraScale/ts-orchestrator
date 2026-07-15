using System.Globalization;
using System.Security.Cryptography;

namespace TerraScale.ReproduciblePublish;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args is ["--compute-input-digest", var sourceRoot])
        {
            try
            {
                Console.WriteLine(ReproduciblePublisher.ComputeInputTreeDigest(sourceRoot).Sha256);
                return 0;
            }
            catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException or CryptographicException)
            {
                return (int)PublishFailureCode.InvalidArgument;
            }
        }
        if (!TryParse(args, out var request)) return (int)PublishFailureCode.InvalidArgument;
        var result = await ReproduciblePublisher.RunAsync(request!).ConfigureAwait(false);
        WriteCanonical(result);
        return result.Successful ? 0 : (int)result.Failure;
    }

    public static bool TryParse(IReadOnlyList<string> args, out ReproduciblePublishRequest? request)
    {
        request = null;
        try
        {
            var values = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            for (var index = 0; index < args.Count; index += 2)
            {
                if (index + 1 >= args.Count || !args[index].StartsWith("--", StringComparison.Ordinal)) return false;
                if (!values.TryGetValue(args[index], out var entries)) values[args[index]] = entries = [];
                entries.Add(args[index + 1]);
            }
            var expected = new[] { "--source-root", "--first-output-root", "--repeat-output-root", "--tree-digest", "--configuration", "--rid", "--timeout-seconds", "--diagnostic-character-limit", "--output-item-limit", "--source-date-epoch" };
            if (values.Keys.Any(key => !expected.Contains(key, StringComparer.Ordinal))) return false;
            if (expected.Where(key => key != "--rid").Any(key => !values.TryGetValue(key, out var entry) || entry.Count != 1)) return false;
            if (!values.TryGetValue("--rid", out var rids) || rids.Count != 2) return false;
            if (!StringComparer.Ordinal.Equals(One(values, "--configuration"), "Release")) return false;
            var targets = rids.Select(ParseTarget).ToArray();
            if (!uint.TryParse(One(values, "--timeout-seconds"), NumberStyles.None, CultureInfo.InvariantCulture, out var timeout)) return false;
            if (!uint.TryParse(One(values, "--diagnostic-character-limit"), NumberStyles.None, CultureInfo.InvariantCulture, out var diagnostics)) return false;
            if (!uint.TryParse(One(values, "--output-item-limit"), NumberStyles.None, CultureInfo.InvariantCulture, out var outputItems)) return false;
            if (!long.TryParse(One(values, "--source-date-epoch"), NumberStyles.None, CultureInfo.InvariantCulture, out var epoch)) return false;
            request = new ReproduciblePublishRequest(
                One(values, "--source-root"), One(values, "--first-output-root"), One(values, "--repeat-output-root"),
                new InputTreeDigest(One(values, "--tree-digest")), PublishConfiguration.Release, targets,
                new PositiveSeconds(timeout), new DiagnosticCharacterLimit(diagnostics), new OutputItemLimit(outputItems), epoch);
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or OverflowException)
        {
            request = null;
            return false;
        }
    }

    private static PublishTarget ParseTarget(string value) => value switch
    {
        "linux-x64" => PublishTarget.LinuxX64,
        "linux-arm64" => PublishTarget.LinuxArm64,
        _ => throw new ArgumentException("Unexpected RID.", nameof(value)),
    };

    private static string One(IReadOnlyDictionary<string, List<string>> values, string key) => values[key][0];

    private static void WriteCanonical(ReproduciblePublishResult result)
    {
        Console.WriteLine($"status={(result.Successful ? "success" : "failure")}");
        Console.WriteLine($"failure={result.Failure}");
        Console.WriteLine($"tree-sha256={result.TreeDigest.Sha256}");
        Console.WriteLine($"stdout-characters={result.StandardOutputCharacters.ToString(CultureInfo.InvariantCulture)}");
        Console.WriteLine($"stderr-characters={result.StandardErrorCharacters.ToString(CultureInfo.InvariantCulture)}");
        foreach (var artifact in result.Artifacts.OrderBy(a => a.Target))
        {
            Console.WriteLine($"artifact={artifact.Rid},{artifact.ByteLength.ToString(CultureInfo.InvariantCulture)},{artifact.Sha256},{artifact.RepeatSha256},{artifact.Reproducible.ToString().ToLowerInvariant()}");
        }
    }
}
