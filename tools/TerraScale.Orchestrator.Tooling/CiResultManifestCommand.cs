using System.Globalization;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace TerraScale.Orchestrator.Tooling;

internal sealed record CiResultManifestOptions(
    string Job,
    string PlanDigest,
    string Output,
    IReadOnlyList<string> TrxFiles,
    IReadOnlyList<CiResultArtifactOption> Artifacts);

internal sealed record CiResultArtifactOption(
    string Artifact,
    string Architecture,
    string Path,
    IReadOnlyList<string> Entrypoints);

internal static class CiResultManifestCommand
{
    private const int MaximumTrxFiles = 32;
    private const long MaximumTrxBytes = 32L * 1024 * 1024;
    private const int MaximumTests = 1_000_000;
    private static readonly XNamespace TrxNamespace =
        "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
    private static readonly string[] CounterNames =
    [
        "total", "executed", "passed", "failed", "error", "timeout", "aborted", "inconclusive",
        "passedButRunAborted", "notRunnable", "notExecuted", "disconnected", "warning", "completed",
        "inProgress", "pending",
    ];

    public static int Run(string[] arguments)
    {
        var options = Parse(arguments);
        var requiredTestSkips = 0;
        var tests = 0;
        foreach (var path in options.TrxFiles)
        {
            var summary = ReadTrx(path);
            if (summary.Total > MaximumTests - tests || summary.Skipped > MaximumTests - requiredTestSkips)
                throw new ToolValidationException(["TRX totals exceed the CI result manifest bound"]);
            tests += summary.Total;
            requiredTestSkips += summary.Skipped;
        }

        var output = Path.GetFullPath(options.Output);
        var parent = Path.GetDirectoryName(output)
            ?? throw new ToolValidationException(["ci-result-manifest output has no parent directory"]);
        Directory.CreateDirectory(parent);
        using var content = new MemoryStream();
        using (var writer = new Utf8JsonWriter(content))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", 2);
            writer.WriteString("job", options.Job);
            writer.WriteString("planDigest", options.PlanDigest);
            writer.WriteBoolean("succeeded", true);
            writer.WriteNumber("requiredTestSkips", requiredTestSkips);
            writer.WriteStartArray("artifacts");
            foreach (var artifact in options.Artifacts)
            {
                writer.WriteStartObject();
                writer.WriteString("artifact", artifact.Artifact);
                writer.WriteString("architecture", artifact.Architecture);
                writer.WriteString("path", artifact.Path);
                writer.WriteStartArray("entrypoints");
                foreach (var entrypoint in artifact.Entrypoints) writer.WriteStringValue(entrypoint);
                writer.WriteEndArray();
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        File.WriteAllBytes(output, content.ToArray());
        if (OperatingSystem.IsLinux())
            File.SetUnixFileMode(output, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return 0;
    }

    internal static CiResultManifestOptions Parse(string[] arguments)
    {
        string? job = null;
        string? planDigest = null;
        string? output = null;
        var trx = new List<string>();
        var artifacts = new List<CiResultArtifactOption>();
        for (var index = 0; index < arguments.Length; index += 2)
        {
            if (index + 1 == arguments.Length)
                throw new ToolValidationException(["ci-result-manifest options require values"]);
            var value = arguments[index + 1];
            switch (arguments[index])
            {
                case "--job" when job is null:
                    job = value;
                    break;
                case "--plan-digest" when planDigest is null:
                    planDigest = value;
                    break;
                case "--output" when output is null:
                    output = value;
                    break;
                case "--trx" when trx.Count < MaximumTrxFiles:
                    trx.Add(Path.GetFullPath(value));
                    break;
                case "--artifact" when artifacts.Count < 2:
                    artifacts.Add(ParseArtifact(value));
                    break;
                default:
                    throw new ToolValidationException(["ci-result-manifest contains an unknown, duplicate, or excessive option"]);
            }
        }

        var errors = new List<string>();
        if (job is not { Length: >= 1 and <= 512 } ||
            job.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character)))
            errors.Add("ci-result-manifest job is invalid");
        if (!Digest(planDigest)) errors.Add("ci-result-manifest plan digest is invalid");
        if (string.IsNullOrWhiteSpace(output)) errors.Add("ci-result-manifest output is required");
        if (artifacts.Select(static value => value.Architecture).Distinct(StringComparer.Ordinal).Count() !=
                artifacts.Count ||
            artifacts.Select(static value => value.Path).Distinct(StringComparer.Ordinal).Count() != artifacts.Count ||
            artifacts.Any(left => artifacts.Any(right => left != right &&
                right.Path.StartsWith(left.Path + '/', StringComparison.Ordinal))))
            errors.Add("ci-result-manifest artifact roots must be distinct and non-overlapping");
        if (errors.Count != 0) throw new ToolValidationException(errors);
        return new(job!, planDigest!, output!, trx.AsReadOnly(), artifacts.AsReadOnly());
    }

    private static CiResultArtifactOption ParseArtifact(string value)
    {
        var fields = value.Split('|');
        if (fields is not [var artifact, var architecture, var path, var declaredEntrypoints] ||
            !ArtifactId(artifact) || architecture is not ("Any" or "LinuxX64" or "LinuxArm64") ||
            !RelativePath(path))
            throw new ToolValidationException(["ci-result-manifest artifact declaration is invalid"]);
        var entrypoints = declaredEntrypoints.Length == 0
            ? []
            : declaredEntrypoints.Split(',', StringSplitOptions.None);
        if (architecture == "Any" && entrypoints.Length != 0 ||
            architecture != "Any" && entrypoints.Length is not (>= 1 and <= 8) ||
            entrypoints.Any(static value => !RelativePath(value)) ||
            entrypoints.Distinct(StringComparer.Ordinal).Count() != entrypoints.Length ||
            !entrypoints.SequenceEqual(entrypoints.Order(StringComparer.Ordinal), StringComparer.Ordinal))
            throw new ToolValidationException(["ci-result-manifest artifact entrypoints are invalid"]);
        return new(artifact, architecture, path, Array.AsReadOnly(entrypoints));
    }

    internal static (int Total, int Skipped) ReadTrx(string path)
    {
        var file = new FileInfo(path);
        if (!file.Exists || file.LinkTarget is not null || file.Length is < 1 or > MaximumTrxBytes)
            throw new ToolValidationException([$"TRX result is missing, empty, or oversized: {path}"]);
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaximumTrxBytes,
        };
        XDocument document;
        try
        {
            using var reader = XmlReader.Create(path, settings);
            document = XDocument.Load(reader, LoadOptions.None);
        }
        catch (XmlException exception)
        {
            throw new ToolValidationException([$"TRX result is invalid XML: {exception.Message}"]);
        }

        var root = document.Root;
        var results = root?.Elements(TrxNamespace + "Results").SingleOrDefault();
        var summary = root?.Elements(TrxNamespace + "ResultSummary").SingleOrDefault();
        var counters = summary?.Elements(TrxNamespace + "Counters").SingleOrDefault();
        if (root?.Name != TrxNamespace + "TestRun" || results is null || summary is null || counters is null ||
            (string?)summary.Attribute("outcome") != "Completed" ||
            counters.Attributes().Select(static attribute => attribute.Name.LocalName)
                .Order(StringComparer.Ordinal)
                .SequenceEqual(CounterNames.Order(StringComparer.Ordinal)) is false)
            throw new ToolValidationException([$"TRX result has an invalid summary: {path}"]);

        var values = CounterNames.ToDictionary(
            static name => name,
            name => Number(counters, name, path),
            StringComparer.Ordinal);
        var rows = results.Elements(TrxNamespace + "UnitTestResult").ToArray();
        var identities = new HashSet<Guid>();
        var passed = 0;
        var skipped = 0;
        foreach (var row in rows)
        {
            if (!Guid.TryParse((string?)row.Attribute("executionId"), out var execution) ||
                !identities.Add(execution) || string.IsNullOrWhiteSpace((string?)row.Attribute("testName")))
                throw new ToolValidationException([$"TRX result contains an invalid test identity: {path}"]);
            switch ((string?)row.Attribute("outcome"))
            {
                case "Passed":
                    passed++;
                    break;
                case "NotExecuted":
                    skipped++;
                    break;
                default:
                    throw new ToolValidationException([$"TRX result contains a non-successful outcome: {path}"]);
            }
        }

        var invalid = new[]
        {
            "failed", "error", "timeout", "aborted", "inconclusive", "passedButRunAborted", "notRunnable",
            "disconnected", "warning", "completed", "inProgress", "pending",
        }.Any(name => values[name] != 0);
        if (values["total"] is < 1 or > MaximumTests || rows.Length != values["total"] ||
            values["executed"] != passed || values["passed"] != passed ||
            values["notExecuted"] != skipped || passed + skipped != rows.Length || invalid)
            throw new ToolValidationException([$"TRX result counters do not match successful test rows: {path}"]);
        return (values["total"], skipped);
    }

    private static int Number(XElement counters, string name, string path) =>
        int.TryParse((string?)counters.Attribute(name), NumberStyles.None, CultureInfo.InvariantCulture, out var value) &&
            value >= 0
            ? value
            : throw new ToolValidationException([$"TRX result has an invalid {name} counter: {path}"]);

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');

    private static bool ArtifactId(string? value) => value is { Length: >= 1 and <= 256 } &&
        value[0] != '/' && !value.Contains("//", StringComparison.Ordinal) &&
        value.All(static character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or
            >= '0' and <= '9' or '.' or '_' or '-' or '/') &&
        value.Split('/').All(static segment => segment is not ("" or "." or ".."));

    private static bool RelativePath(string? value) => value is { Length: >= 1 and <= 1024 } &&
        value[0] != '/' && !value.EndsWith('/') && !value.Contains("//", StringComparison.Ordinal) &&
        value.All(static character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or
            >= '0' and <= '9' or '.' or '_' or '-' or '/') &&
        value.Split('/').All(static segment => segment is not ("" or "." or ".."));
}

