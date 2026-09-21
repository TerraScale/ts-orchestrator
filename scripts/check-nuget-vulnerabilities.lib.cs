// Fail closed when restored NuGet packages have known vulnerabilities.
// Port of the former scripts/check_nuget_vulnerabilities.py — same fail-closed
// rules, same messages, same exit codes (0 clean, 1 findings/failure, 2 usage).

using System.Diagnostics;
using System.Text.Json;

namespace TerraScale.Ci;

public sealed class AuditReportException(string message) : Exception(message);

public static class CheckNugetVulnerabilities
{
    public delegate (int ExitCode, string StdOut, string StdErr) AuditRunner(string project);

    /// <summary>Validate NuGet v1 audit output before interpreting absence of findings.</summary>
    public static List<JsonElement> ValidateReport(JsonDocument report, string project)
    {
        var root = report.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new AuditReportException("unsupported or missing report version");
        }
        if (
            !root.TryGetProperty("version", out var version)
            || version.ValueKind != JsonValueKind.Number
            || !long.TryParse(version.GetRawText(), System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture, out var versionValue)
            || versionValue != 1
        )
        {
            throw new AuditReportException("unsupported or missing report version");
        }
        if (
            !root.TryGetProperty("parameters", out var parameters)
            || parameters.ValueKind != JsonValueKind.String
        )
        {
            throw new AuditReportException("report does not cover transitive vulnerability scanning");
        }
        var tokens = parameters.GetString()!.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (!tokens.Contains("--vulnerable") || !tokens.Contains("--include-transitive"))
        {
            throw new AuditReportException("report does not cover transitive vulnerability scanning");
        }
        if (
            !root.TryGetProperty("sources", out var sources)
            || sources.ValueKind != JsonValueKind.Array
            || sources.GetArrayLength() == 0
            || sources.EnumerateArray().Any(s => s.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(s.GetString()))
        )
        {
            throw new AuditReportException("missing advisory sources");
        }
        RequireEmptyLogs(root);
        if (
            !root.TryGetProperty("projects", out var projects)
            || projects.ValueKind != JsonValueKind.Array
            || projects.GetArrayLength() != 1
        )
        {
            throw new AuditReportException("expected exactly one audited project");
        }
        var entry = projects[0];
        if (
            entry.ValueKind != JsonValueKind.Object
            || !entry.TryGetProperty("path", out var path)
            || path.ValueKind != JsonValueKind.String
            || Path.GetFullPath(path.GetString()!) != Path.GetFullPath(project)
        )
        {
            throw new AuditReportException("audited project does not match requested project");
        }
        RequireEmptyLogs(entry);
        // NuGet omits frameworks entirely when this project has no findings.
        if (!entry.TryGetProperty("frameworks", out var frameworks))
        {
            frameworks = default;
        }
        if (frameworks.ValueKind != JsonValueKind.Array && frameworks.ValueKind != JsonValueKind.Undefined)
        {
            throw new AuditReportException("invalid framework list");
        }
        var findings = new List<JsonElement>();
        if (frameworks.ValueKind == JsonValueKind.Undefined)
        {
            return findings;
        }
        foreach (var framework in frameworks.EnumerateArray())
        {
            if (
                framework.ValueKind != JsonValueKind.Object
                || !framework.TryGetProperty("framework", out var frameworkName)
                || frameworkName.ValueKind != JsonValueKind.String
                || string.IsNullOrWhiteSpace(frameworkName.GetString())
            )
            {
                throw new AuditReportException("invalid framework identity");
            }
            RequireEmptyLogs(framework);
            foreach (var kind in (string[])["topLevelPackages", "transitivePackages"])
            {
                if (!framework.TryGetProperty(kind, out var packages))
                {
                    packages = default;
                }
                if (packages.ValueKind != JsonValueKind.Array && packages.ValueKind != JsonValueKind.Undefined)
                {
                    throw new AuditReportException("invalid package list");
                }
                if (packages.ValueKind == JsonValueKind.Undefined)
                {
                    continue;
                }
                foreach (var package in packages.EnumerateArray())
                {
                    if (
                        package.ValueKind != JsonValueKind.Object
                        || !package.TryGetProperty("id", out var id)
                        || id.ValueKind != JsonValueKind.String
                        || string.IsNullOrWhiteSpace(id.GetString())
                        || !package.TryGetProperty("resolvedVersion", out var resolvedVersion)
                        || resolvedVersion.ValueKind != JsonValueKind.String
                        || string.IsNullOrWhiteSpace(resolvedVersion.GetString())
                    )
                    {
                        throw new AuditReportException("invalid package identity");
                    }
                    if (
                        !package.TryGetProperty("vulnerabilities", out var vulnerabilities)
                        || vulnerabilities.ValueKind != JsonValueKind.Array
                        || vulnerabilities.GetArrayLength() == 0
                    )
                    {
                        throw new AuditReportException("vulnerable package is missing advisory details");
                    }
                    foreach (var advisory in vulnerabilities.EnumerateArray())
                    {
                        if (
                            advisory.ValueKind != JsonValueKind.Object
                            || !advisory.TryGetProperty("severity", out var severity)
                            || severity.ValueKind != JsonValueKind.String
                            || severity.GetString() is not ("Low" or "Moderate" or "High" or "Critical")
                            || !advisory.TryGetProperty("advisoryurl", out var advisoryUrl)
                            || advisoryUrl.ValueKind != JsonValueKind.String
                            || string.IsNullOrWhiteSpace(advisoryUrl.GetString())
                        )
                        {
                            throw new AuditReportException("invalid vulnerability advisory");
                        }
                    }
                    findings.Add(package);
                }
            }
        }
        return findings;
    }

    /// <summary>Missing logs default to empty; anything present must be an empty array.</summary>
    private static void RequireEmptyLogs(JsonElement element)
    {
        if (!element.TryGetProperty("logs", out var logs))
        {
            return;
        }
        if (logs.ValueKind != JsonValueKind.Array || logs.GetArrayLength() != 0)
        {
            throw new AuditReportException("scanner reported diagnostics; audit completeness is unverified");
        }
    }

    public static int Run(IReadOnlyList<string> projects, AuditRunner? runAudit = null)
    {
        if (projects.Count == 0)
        {
            Console.Error.WriteLine("usage: check-nuget-vulnerabilities.cs <project> [...]");
            return 2;
        }
        runAudit ??= RunDotnetList;
        var vulnerable = 0;
        foreach (var project in projects)
        {
            var (exitCode, stdOut, stdErr) = runAudit(project);
            if (exitCode != 0)
            {
                Console.Error.WriteLine($"NuGet audit failed for {project}: {stdErr.Trim()}");
                return 1;
            }
            JsonDocument report;
            try
            {
                report = JsonDocument.Parse(stdOut);
            }
            catch (JsonException)
            {
                Console.Error.WriteLine($"NuGet audit returned invalid JSON for {project}");
                return 1;
            }
            List<JsonElement> findings;
            try
            {
                findings = ValidateReport(report, project);
            }
            catch (AuditReportException exception)
            {
                Console.Error.WriteLine(
                    $"NuGet audit returned incomplete or malformed output for {project}: {exception.Message}");
                return 1;
            }
            foreach (var package in findings)
            {
                vulnerable++;
                Console.Error.WriteLine(
                    $"vulnerable NuGet package in {project}: {package.GetProperty("id").GetString()} " +
                    $"{package.GetProperty("resolvedVersion").GetString()}");
            }
        }
        if (vulnerable > 0)
        {
            Console.Error.WriteLine($"{vulnerable} vulnerable NuGet package(s) require documented disposition.");
            return 1;
        }
        Console.WriteLine($"NuGet vulnerability audit: {projects.Count} projects, 0 vulnerable packages.");
        return 0;
    }

    private static (int, string, string) RunDotnetList(string project)
    {
        var start = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("list");
        start.ArgumentList.Add(project);
        start.ArgumentList.Add("package");
        start.ArgumentList.Add("--vulnerable");
        start.ArgumentList.Add("--include-transitive");
        start.ArgumentList.Add("--format");
        start.ArgumentList.Add("json");
        using var process = Process.Start(start)!;
        var stdOut = process.StandardOutput.ReadToEnd();
        var stdErr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, stdOut, stdErr);
    }
}
