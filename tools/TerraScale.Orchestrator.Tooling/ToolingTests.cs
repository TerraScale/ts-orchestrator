using System.Text.Json.Nodes;
using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tooling;

internal static class ToolingTests
{
    public static int Run(string[] arguments)
    {
        if (arguments.Length != 0 && arguments is not ["--repository-only"])
            throw new ToolValidationException(["test accepts only --repository-only"]);

        var tests = new List<(string Name, Action Body)>
        {
            ("adr baseline", () => AssertValid(AdrReadinessCommand.Validate(ToolingSupport.ReadObject("docs/adr/readiness-index.yaml")))),
            ("adr duplicate id", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["entries", 1, "id"], 1), AdrReadinessCommand.Validate)),
            ("adr accepted status", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["entries", 0, "status"], "accepted"), AdrReadinessCommand.Validate)),
            ("adr accepted field", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["entries", 0, "accepted"], true), AdrReadinessCommand.Validate)),
            ("adr invalid lane", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["entries", 0, "ownerLane"], "unknown"), AdrReadinessCommand.Validate)),
            ("adr missing field", () => AssertInvalid(Delete("docs/adr/readiness-index.yaml", ["entries", 0, "title"]), AdrReadinessCommand.Validate)),
            ("adr unknown controlling input", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["entries", 0, "controllingInputs", 0], "unknown-input"), AdrReadinessCommand.Validate)),
            ("adr ownership expansion drift", () => AssertInvalid(Delete("docs/adr/readiness-index.yaml", ["entries", 0, "openInputOwnershipReferences", 0]), AdrReadinessCommand.Validate)),
            ("adr executable self dependency", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["entries", 0, "executableDependencies"], new[] { 1 }), AdrReadinessCommand.Validate)),
            ("adr malformed anchor", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["entries", 0, "sourceAnchors", 0], "https://example.test/a:1-2"), AdrReadinessCommand.Validate)),
            ("adr traversal anchor", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["entries", 0, "sourceAnchors", 0], "../ORCHESTRATOR.md:1-2"), AdrReadinessCommand.Validate)),
            ("adr canonical lane substitution", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["canonicalOwnerLanes", 0], "other"), AdrReadinessCommand.Validate)),
            ("adr normalization provenance", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["normalizationEvidence"], "GOAL.md:1-1"), AdrReadinessCommand.Validate)),
            ("adr Goal anchor bounds", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["normalizationEvidence"], "../GOAL.md:999-999"), AdrReadinessCommand.Validate)),
            ("adr open-input provenance", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["openInputs", "source"], "README.md:1-1"), AdrReadinessCommand.Validate)),
            ("packet alias unknown target", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["controllingInputAliases", "storage-slo", 0], "unknown-input"), OwnerDecisionCommand.Validate)),
            ("packet alias duplicate expansion", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["controllingInputAliases", "storage-slo", 1], "storage-minimum-iops-per-member"), OwnerDecisionCommand.Validate)),
            ("packet empty alias", () => AssertInvalid(AddAlias("", ["regional-rpo"]), OwnerDecisionCommand.Validate)),
            ("packet self alias", () => AssertInvalid(AddAlias("self-alias", ["self-alias"]), OwnerDecisionCommand.Validate)),
            ("packet indirect alias cycle", () => AssertInvalid(AddAliases(("alias-a", new[] { "alias-b" }), ("alias-b", new[] { "alias-a" })), OwnerDecisionCommand.Validate)),
            ("packet alias atomic collision", () => AssertInvalid(AddAlias("regional-rpo", ["regional-rpo"]), OwnerDecisionCommand.Validate)),
            ("packet ownership record missing", () => AssertInvalid(Delete("docs/decisions/owner-decision-packet.json", ["openInputOwnershipRegister", "records", 0]), OwnerDecisionCommand.Validate)),
            ("packet ownership status", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["openInputOwnershipRegister", "records", 0, "assignmentStatus"], "pending"), OwnerDecisionCommand.Validate)),
            ("packet later selection missing id", () => AssertInvalid(Delete("docs/decisions/owner-decision-packet.json", ["laterImplementationSelections", 0, "id"]), OwnerDecisionCommand.Validate)),
            ("packet later selection missing selection", () => AssertInvalid(Delete("docs/decisions/owner-decision-packet.json", ["laterImplementationSelections", 0, "selection"]), OwnerDecisionCommand.Validate)),
            ("packet later selection schema", () => AssertInvalid(Delete("docs/decisions/owner-decision-packet.json", ["laterImplementationSelections", 0, "readinessStage"]), OwnerDecisionCommand.Validate)),
            ("packet later selection missing contract freeze", () => AssertInvalid(Delete("docs/decisions/owner-decision-packet.json", ["laterImplementationSelections", 0, "requiredBeforeContractFreeze"]), OwnerDecisionCommand.Validate)),
            ("packet later selection malformed readiness stage", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["laterImplementationSelections", 0, "readinessStage"], "deployment-qualification"), OwnerDecisionCommand.Validate)),
            ("packet later selection malformed contract freeze", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["laterImplementationSelections", 0, "requiredBeforeContractFreeze"], "false"), OwnerDecisionCommand.Validate)),
            ("packet later selection nonobject member", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["laterImplementationSelections", 0], "invalid"), OwnerDecisionCommand.Validate)),
            ("packet policy anchors", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["atomicPolicyRecords", 0, "sourceAnchors"], Array.Empty<string>()), OwnerDecisionCommand.Validate)),
            ("packet policy canonical anchor substitution", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["atomicPolicyRecords", 0, "sourceAnchors", 0], "ORCHESTRATOR.md:89-98"), OwnerDecisionCommand.Validate)),
            ("packet accepted register anchors", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["acceptedDecisionRegister", "sourceAnchors"], Array.Empty<string>()), OwnerDecisionCommand.Validate)),
            ("packet accepted canonical anchor substitution", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["acceptedDecisionRegister", "sourceAnchors", 0], "ORCHESTRATOR.md:89-98"), OwnerDecisionCommand.Validate)),
            ("owner baseline", () => AssertValid(OwnerDecisionCommand.Validate(ToolingSupport.ReadObject("docs/decisions/owner-decision-packet.json")))),
            ("owner decision drift", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["questions", 0, "answer"], "B"), OwnerDecisionCommand.Validate)),
            ("owner invalid option", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["questions", 1, "answer"], "C"), OwnerDecisionCommand.Validate)),
            ("owner invalid unit", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["inputs", 2, "unit"], "USD/month"), OwnerDecisionCommand.Validate)),
            ("owner later selection default", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["laterImplementationSelections", 0, "selection"], "cosign"), OwnerDecisionCommand.Validate)),
            ("owner missing question", () => AssertInvalid(Delete("docs/decisions/owner-decision-packet.json", ["questions", 4]), OwnerDecisionCommand.Validate)),
            ("owner semantic drift", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["questions", 0, "question"], "drift"), OwnerDecisionCommand.Validate)),
            ("no python sources", NoPythonSources),
            ("CI result manifest", CiResultManifest),
            ("development evidence profile authorization", DevelopmentEvidenceProfiles),
            ("development evidence bounded execution", DevelopmentEvidenceBounds),
            ("development bounded process observation", DevelopmentBoundedProcessObservation),
            ("development validation lease", DevelopmentValidationLease),
        };

        var failures = new List<string>();
        foreach (var test in tests)
        {
            try
            {
                test.Body();
                Console.WriteLine($"PASS {test.Name}");
            }
            catch (Exception exception)
            {
                failures.Add($"FAIL {test.Name}: {exception.Message}");
            }
        }

        if (failures.Count != 0) throw new ToolValidationException(failures);
        Console.WriteLine($"Passed {tests.Count} C# tooling tests.");
        return 0;
    }

    private static void NoPythonSources()
    {
        var python = Directory.EnumerateFiles(ToolingSupport.Root, "*" + ".p" + "y", SearchOption.AllDirectories)
            .Where(path => !path.Split(Path.DirectorySeparatorChar).Any(part => part is "bin" or "obj" or ".git"))
            .ToArray();
        if (python.Length != 0)
            throw new InvalidOperationException($"Python sources remain: {string.Join(',', python)}");
    }

    private static void CiResultManifest()
    {
        var root = Path.Combine(Path.GetTempPath(), $"ci-result-manifest-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var trx = Path.Combine(root, "tests.trx");
            var invalid = Path.Combine(root, "invalid.trx");
            var output = Path.Combine(root, "terrascale-ci-result-v2.json");
            File.WriteAllText(trx, Trx("Passed", "NotExecuted", failed: 0, notExecuted: 1));
            File.WriteAllText(invalid, Trx("Passed", "Failed", failed: 1, notExecuted: 0));
            var digest = new string('a', 64);

            AssertEqual(0, CiResultManifestCommand.Run([
                "--job", "pipeline:job", "--plan-digest", digest, "--trx", trx,
                "--artifact", "TerraScale/Orchestrator|LinuxX64|linux-x64|bin/app", "--output", output]));
            var document = JsonNode.Parse(File.ReadAllText(output))!.AsObject();
            AssertEqual(2, document["schemaVersion"]!.GetValue<int>());
            AssertEqual("pipeline:job", document["job"]!.GetValue<string>());
            AssertEqual(digest, document["planDigest"]!.GetValue<string>());
            AssertEqual(true, document["succeeded"]!.GetValue<bool>());
            AssertEqual(1, document["requiredTestSkips"]!.GetValue<int>());
            AssertEqual("TerraScale/Orchestrator",
                document["artifacts"]![0]!["artifact"]!.GetValue<string>());
            AssertEqual("LinuxX64", document["artifacts"]![0]!["architecture"]!.GetValue<string>());
            AssertEqual("linux-x64", document["artifacts"]![0]!["path"]!.GetValue<string>());
            AssertEqual("bin/app", document["artifacts"]![0]!["entrypoints"]![0]!.GetValue<string>());
            AssertThrows<ToolValidationException>(() => CiResultManifestCommand.ReadTrx(invalid));
            AssertThrows<ToolValidationException>(() => CiResultManifestCommand.Parse([
                "--job", "pipeline:job", "--plan-digest", new string('A', 64), "--output", output]));
            AssertThrows<ToolValidationException>(() => CiResultManifestCommand.Parse([
                "--job", "pipeline:job", "--plan-digest", digest,
                "--artifact", "artifact|LinuxX64|linux|app",
                "--artifact", "artifact|LinuxArm64|linux/arm64|app", "--output", output]));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string Trx(string first, string second, int failed, int notExecuted) => $$"""
        <?xml version="1.0" encoding="utf-8"?>
        <TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
          <Results>
            <UnitTestResult executionId="11111111-1111-1111-1111-111111111111" testName="first" outcome="{{first}}" />
            <UnitTestResult executionId="22222222-2222-2222-2222-222222222222" testName="second" outcome="{{second}}" />
          </Results>
          <ResultSummary outcome="Completed">
            <Counters total="2" executed="{{2 - notExecuted}}" passed="1" failed="{{failed}}" error="0"
              timeout="0" aborted="0" inconclusive="0" passedButRunAborted="0" notRunnable="0"
              notExecuted="{{notExecuted}}" disconnected="0" warning="0" completed="0" inProgress="0" pending="0" />
          </ResultSummary>
        </TestRun>
        """;

    private static void DevelopmentEvidenceProfiles()
    {
        var lean = DevelopmentEvidenceCommand.Parse(["--output", "/tmp/evidence.json"]);
        var control = DevelopmentEvidenceCommand.Parse([
            "--output", "/tmp/evidence.json",
            "--profile", "control"]);
        AssertEqual("quick", lean.Profile);
        AssertEqual("control", control.Profile);
        var retiredProfile = string.Concat("dev-", "smol", "vm", "-three-cell-r3");
        AssertThrows<ToolValidationException>(() => DevelopmentEvidenceCommand.Parse([
            "--output", "/tmp/evidence.json",
            "--profile", retiredProfile]));
    }

    private static void DevelopmentEvidenceBounds()
    {
        AssertEqual(1, DevelopmentEvidenceCommand.MaximumParallelTestModules);
        AssertEqual(2, DevelopmentEvidenceCommand.EvidenceSchemaVersion);
        AssertEqual(4, DevelopmentEvidenceCommand.MaximumParallelTests);
        AssertEqual(5, DevelopmentEvidenceCommand.TestModules.Count);
        AssertEqual(24L * 1024 * 1024 * 1024, DevelopmentEvidenceCommand.AggregateMemoryLimitBytes);
        AssertEqual(20L * 1024 * 1024 * 1024, DevelopmentEvidenceCommand.ExecutionMemoryLimitBytes);
        AssertEqual(4L * 1024 * 1024 * 1024, DevelopmentEvidenceCommand.ReservedHeadroomBytes);
        AssertEqual(46, DevelopmentEvidenceCommand.ParseTestTotal("sample", "total: 46\n"));
    }

    private static void DevelopmentValidationLease()
    {
        var scope = $"tooling-test-{Guid.NewGuid():N}";
        using var lease = LocalValidationLease.Acquire(scope);
        AssertThrows<InvalidOperationException>(() => LocalValidationLease.Acquire(scope));
    }

    private static void DevelopmentBoundedProcessObservation()
    {
        var result = BoundedProcessRunner.Run(
            "dotnet",
            ["--version"],
            ToolingSupport.Root,
            TimeSpan.FromSeconds(30),
            256L * 1024 * 1024,
            4);
        AssertEqual(0, result.ExitCode);
        if (result.Observation.PeakMemoryBytes <= 0 || result.Observation.PeakProcessCount <= 0)
            throw new InvalidOperationException("bounded process observation did not capture resource use");
    }

    private static JsonObject Mutate(string path, object[] segments, object? value)
    {
        var document = Clone(ToolingSupport.ReadObject(path));
        Set(document, segments, value);
        return document;
    }

    private static JsonObject Delete(string path, object[] segments)
    {
        var document = Clone(ToolingSupport.ReadObject(path));
        var parent = Resolve(document, segments[..^1]);
        if (parent is JsonObject objectParent) objectParent.Remove((string)segments[^1]);
        else if (parent is JsonArray arrayParent) arrayParent.RemoveAt((int)segments[^1]);
        return document;
    }

    private static JsonObject AddAlias(string alias, string[] values) => AddAliases((alias, values));

    private static JsonObject AddAliases(params (string Alias, string[] Values)[] aliases)
    {
        var document = Clone(ToolingSupport.ReadObject("docs/decisions/owner-decision-packet.json"));
        var target = document["controllingInputAliases"]!.AsObject();
        foreach (var (alias, values) in aliases)
            target[alias] = new JsonArray(values.Select(value => JsonValue.Create(value)).ToArray());
        return document;
    }

    private static void Set(JsonObject document, object[] segments, object? value)
    {
        var parent = Resolve(document, segments[..^1]);
        var node = JsonValue.Create(value);
        if (parent is JsonObject objectParent) objectParent[(string)segments[^1]] = node;
        else if (parent is JsonArray arrayParent) arrayParent[(int)segments[^1]] = node;
    }

    private static JsonNode Resolve(JsonNode current, object[] segments)
    {
        foreach (var segment in segments)
            current = segment is string key ? current[key]! : current[(int)segment]!;
        return current;
    }

    private static JsonObject Clone(JsonObject value) => JsonNode.Parse(value.ToJsonString())!.AsObject();

    private static void AssertValid(IReadOnlyCollection<string> errors)
    {
        if (errors.Count != 0) throw new InvalidOperationException(string.Join("; ", errors));
    }

    private static void AssertInvalid(IReadOnlyCollection<string> errors)
    {
        if (errors.Count == 0) throw new InvalidOperationException("validator accepted an invalid document");
    }

    private static void AssertInvalid(JsonObject document, Func<JsonObject, List<string>> validate) =>
        AssertInvalid(validate(document));

    private static void AssertEqual<T>(T expected, T actual) where T : notnull
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new InvalidOperationException($"expected {expected}, observed {actual}");
    }

    private static void AssertThrows<TException>(Action action) where TException : Exception
    {
        try { action(); }
        catch (TException) { return; }
        throw new InvalidOperationException($"expected {typeof(TException).Name}");
    }
}
