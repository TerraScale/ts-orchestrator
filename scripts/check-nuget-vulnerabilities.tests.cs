#!/usr/bin/env dotnet run
#:package TUnit
#:include check-nuget-vulnerabilities.lib.cs

// Port of the former scripts/test_check_nuget_vulnerabilities.py unittest suite.

using System.Text.Json;

public sealed class AuditTests
{
    private const string Project = "service.csproj";

    private static string CleanReport(string frameworks = "") =>
        "{\"version\": 1, \"parameters\": \"--vulnerable --include-transitive\", " +
        "\"sources\": [\"https://api.nuget.org/v3/index.json\"], " +
        $"\"projects\": [{{\"path\": \"{Path.GetFullPath(Project)}\"{(frameworks.Length > 0 ? ", \"frameworks\": " + frameworks : "")}}}]}}";

    private static JsonDocument Parse(string json) => JsonDocument.Parse(json);

    private static string? ExpectRejection(string json)
    {
        try
        {
            TerraScale.Ci.CheckNugetVulnerabilities.ValidateReport(Parse(json), Project);
            return "expected AuditReportException";
        }
        catch (TerraScale.Ci.AuditReportException)
        {
            return null;
        }
    }

    [Test]
    public async Task Real_clean_shape_without_frameworks_yields_no_findings()
    {
        var findings = TerraScale.Ci.CheckNugetVulnerabilities.ValidateReport(Parse(CleanReport()), Project);
        await Assert.That(findings.Count).IsEqualTo(0);
    }

    public static string[] RejectedReports() =>
    [
        CleanReport().Replace("\"version\": 1", "\"version\": true"),
        CleanReport().Replace("\"version\": 1", "\"version\": 2"),
        CleanReport().Replace("\"sources\": [\"https://api.nuget.org/v3/index.json\"]", "\"sources\": []"),
        CleanReport().Replace($"\"projects\": [{{\"path\": \"{Path.GetFullPath(Project)}\"}}]",
            "\"projects\": [{\"path\": \"other.csproj\"}]"),
        CleanReport().Replace("--vulnerable --include-transitive", "--vulnerable"),
        CleanReport().Replace("\"projects\":",
            "\"logs\": [{\"level\": \"Warning\", \"message\": \"source unavailable\"}], \"projects\":"),
        CleanReport().Replace($"\"path\": \"{Path.GetFullPath(Project)}\"",
            $"\"path\": \"{Path.GetFullPath(Project)}\", \"frameworks\": null"),
        "{}",
    ];

    [Test]
    [MethodDataSource(nameof(RejectedReports))]
    public async Task Incomplete_reports_are_rejected(string report)
    {
        await Assert.That(ExpectRejection(report)).IsNull();
    }

    [Test]
    [Arguments("topLevelPackages")]
    [Arguments("transitivePackages")]
    public async Task Direct_and_transitive_advisories_are_reported(string kind)
    {
        var report = CleanReport(
            "[{\"framework\": \"net11.0\", \"" + kind + "\": [{\"id\": \"Example\", \"resolvedVersion\": \"1.0\", " +
            "\"vulnerabilities\": [{\"severity\": \"High\", \"advisoryurl\": \"https://example.test/advisory\"}]}]}]");
        var findings = TerraScale.Ci.CheckNugetVulnerabilities.ValidateReport(Parse(report), Project);
        await Assert.That(findings.Count).IsEqualTo(1);
        await Assert.That(findings[0].GetProperty("id").GetString()).IsEqualTo("Example");

        // main() exits 1 when the seam returns a vulnerable report.
        var exitCode = TerraScale.Ci.CheckNugetVulnerabilities.Run([Project],
            _ => (0, report, ""));
        await Assert.That(exitCode).IsEqualTo(1);

        // vulnerabilities: null is a malformed report, not a clean one.
        await Assert.That(ExpectRejection(report.Replace("\"vulnerabilities\": [{",
                "\"vulnerabilities\": null, \"_\": [{")))
            .IsNull();
    }

    [Test]
    public async Task Cli_exit_status_matches_the_python_tool()
    {
        // (stdout, runner exit code) -> expected exit: clean 0; malformed/`{}`/not-json/nonzero -> 1.
        var cases = new (string Output, int RunnerExit, int Expected)[]
        {
            (CleanReport(), 0, 0),
            ("{}", 0, 1),
            ("not json", 0, 1),
            (CleanReport(), 1, 1),
        };
        foreach (var (output, runnerExit, expected) in cases)
        {
            var rc = TerraScale.Ci.CheckNugetVulnerabilities.Run([Project],
                _ => (runnerExit, output, ""));
            await Assert.That(rc).IsEqualTo(expected);
        }
    }

    [Test]
    public async Task No_projects_prints_usage_and_exits_2()
    {
        var rc = TerraScale.Ci.CheckNugetVulnerabilities.Run([]);
        await Assert.That(rc).IsEqualTo(2);
    }
}
