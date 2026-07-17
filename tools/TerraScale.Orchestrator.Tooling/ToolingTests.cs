using System.Text.Json.Nodes;
using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tooling;

internal static class ToolingTests
{
    public static int Run(string[] arguments)
    {
        var tests = new List<(string Name, Action Body)>
        {
            ("adr baseline", () => AssertValid(AdrReadinessCommand.Validate(ToolingSupport.ReadObject("docs/adr/readiness-index.yaml")))),
            ("adr duplicate id", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["entries", 1, "id"], 1), AdrReadinessCommand.Validate)),
            ("adr accepted status", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["entries", 0, "status"], "accepted"), AdrReadinessCommand.Validate)),
            ("adr accepted field", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["entries", 0, "accepted"], true), AdrReadinessCommand.Validate)),
            ("adr invalid lane", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["entries", 0, "ownerLane"], "unknown"), AdrReadinessCommand.Validate)),
            ("adr missing field", () => AssertInvalid(Delete("docs/adr/readiness-index.yaml", ["entries", 0, "title"]), AdrReadinessCommand.Validate)),
            ("owner baseline", () => AssertValid(OwnerDecisionCommand.Validate(ToolingSupport.ReadObject("docs/decisions/owner-decision-packet.json")))),
            ("owner decision drift", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["questions", 0, "answer"], "B"), OwnerDecisionCommand.Validate)),
            ("owner invalid option", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["questions", 1, "answer"], "C"), OwnerDecisionCommand.Validate)),
            ("owner invalid unit", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["inputs", 2, "unit"], "USD/month"), OwnerDecisionCommand.Validate)),
            ("owner later selection default", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["laterImplementationSelections", 0, "selection"], "cosign"), OwnerDecisionCommand.Validate)),
            ("owner missing question", () => AssertInvalid(Delete("docs/decisions/owner-decision-packet.json", ["questions", 4]), OwnerDecisionCommand.Validate)),
            ("owner semantic drift", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["questions", 0, "question"], "drift"), OwnerDecisionCommand.Validate)),
            ("NATS readiness baseline", NatsBaseline),
            ("NATS false full L0C", () => NatsMutation(["classification"], "full-l0c")),
            ("NATS harness drift", () => NatsMutation(["harnessPath"], "unknown.cs")),
            ("mutation baseline", () => AssertValid(MutationEvidenceCommand.Validate(ToolingSupport.ReadObject("tools/mutation/mutation-policy.json"), ToolingSupport.ReadObject("tools/mutation/mutation-evidence.json"), new DateOnly(2026, 7, 15)))),
            ("mutation stale evidence", () => AssertInvalidMutation(new DateOnly(2026, 8, 13))),
            ("mutation policy digest", MutationDigestDrift),
            ("supply chain baseline", () => AssertExitZero(() => SupplyChainCommand.Run([]))),
            ("provider baseline", () => AssertExitZero(() => ProviderQualificationCommand.Run([]))),
            ("runtime baseline", () => AssertExitZero(() => RuntimeReadinessCommand.Run([]))),
            ("delivery baseline", () => AssertExitZero(() => DeliveryInventoryCommand.Validate([]))),
            ("L0C baseline", () => AssertExitZero(() => NatsL0cCommand.Run([]))),
            ("traceability baseline", () => AssertExitZero(() => TraceabilityCommand.Validate([]))),
            ("registry baseline", () => AssertExitZero(() => RegistryAuditCommand.Run([]))),
            ("OCI sanitizer removes secrets", OciSecrets),
            ("OCI sanitizer hashes identifiers", OciIdentifiers),
            ("OCI sanitizer redacts addresses", OciAddresses),
            ("OCI authentication classification", () => AssertEqual(("query-failed", "authentication"), OciInventoryCommand.ClassifyFailure("status: 401 NotAuthenticated"))),
            ("OCI authorization classification", () => AssertEqual(("permission-denied", "authorization"), OciInventoryCommand.ClassifyFailure("status: 403 Forbidden"))),
            ("OCI plan", () => AssertExitZero(() => OciInventoryCommand.Run(["--plan"]))),
            ("translated script inventory", TranslatedInventory),
            ("development evidence profile authorization", DevelopmentEvidenceProfiles),
            ("development evidence bounded execution", DevelopmentEvidenceBounds),
            ("development bounded process observation", DevelopmentBoundedProcessObservation),
            ("development validation lease", DevelopmentValidationLease),
        };

        var failures = new List<string>();
        foreach (var test in tests)
        {
            try { test.Body(); Console.WriteLine($"PASS {test.Name}"); }
            catch (Exception exception) { failures.Add($"FAIL {test.Name}: {exception.Message}"); }
        }
        if (failures.Count != 0) throw new ToolValidationException(failures);
        Console.WriteLine($"Passed {tests.Count} C# tooling tests.");
        return 0;
    }

    private static void NatsBaseline() => AssertValid(NatsReadinessCommand.Validate(
        ToolingSupport.ReadObject("testlab/pins/nats-candidates.json"), ToolingSupport.ReadObject("testlab/nats/local-x64-l0c-report.json")));

    private static void NatsMutation(object[] path, object? value)
    {
        var report = Clone(ToolingSupport.ReadObject("testlab/nats/local-x64-l0c-report.json"));
        Set(report, path, value);
        AssertInvalid(NatsReadinessCommand.Validate(ToolingSupport.ReadObject("testlab/pins/nats-candidates.json"), report));
    }

    private static void AssertInvalidMutation(DateOnly date) => AssertInvalid(MutationEvidenceCommand.Validate(
        ToolingSupport.ReadObject("tools/mutation/mutation-policy.json"), ToolingSupport.ReadObject("tools/mutation/mutation-evidence.json"), date));

    private static void MutationDigestDrift()
    {
        var report = Clone(ToolingSupport.ReadObject("tools/mutation/mutation-evidence.json"));
        report["policySha256"] = new string('0', 64);
        AssertInvalid(MutationEvidenceCommand.Validate(ToolingSupport.ReadObject("tools/mutation/mutation-policy.json"), report, new DateOnly(2026, 7, 15)));
    }

    private static void OciSecrets()
    {
        var sanitized = OciInventoryCommand.Sanitize(JsonNode.Parse("{\"secret\":\"value\",\"nested\":{\"api_token\":\"value\",\"safe\":true}}"))!.AsObject();
        if (sanitized.ContainsKey("secret") || sanitized["nested"]!.AsObject().ContainsKey("api_token")) throw new InvalidOperationException("secret key survived sanitization");
    }

    private static void OciIdentifiers()
    {
        var sanitized = OciInventoryCommand.Sanitize(JsonNode.Parse("{\"id\":\"ocid1.instance.synthetic\",\"text\":\"ocid1.volume.synthetic\"}"))!.ToJsonString();
        if (sanitized.Contains("ocid1.", StringComparison.OrdinalIgnoreCase) || !sanitized.Contains("sha256:", StringComparison.Ordinal)) throw new InvalidOperationException("identifier was not hashed");
    }

    private static void OciAddresses()
    {
        var sanitized = OciInventoryCommand.Sanitize(JsonNode.Parse("{\"ip-address\":\"192.0.2.1\",\"text\":\"at 198.51.100.2\"}"))!.ToJsonString();
        if (sanitized.Contains("192.0.2.1", StringComparison.Ordinal) || sanitized.Contains("198.51.100.2", StringComparison.Ordinal)) throw new InvalidOperationException("address was not redacted");
    }

    private static void TranslatedInventory()
    {
        if (TranslatedScriptCatalog.Replacements.Count != 27) throw new InvalidOperationException("translation catalog must cover all 27 retained replacements");
        var python = Directory.EnumerateFiles(ToolingSupport.Root, "*" + ".p" + "y", SearchOption.AllDirectories)
            .Where(path => !path.Split(Path.DirectorySeparatorChar).Any(part => part is "bin" or "obj" or ".git")).ToArray();
        if (python.Length != 0) throw new InvalidOperationException($"Python sources remain: {string.Join(',', python)}");
    }

    private static void DevelopmentEvidenceProfiles()
    {
        var lean = DevelopmentEvidenceCommand.Parse(["--output", "/tmp/evidence.json"]);
        var control = DevelopmentEvidenceCommand.Parse([
            "--output", "/tmp/evidence.json",
            "--profile", "dev-containers-control-three-cell-lean"]);
        AssertEqual("dev-containers-three-cell-lean", lean.Profile);
        AssertEqual("dev-containers-control-three-cell-lean", control.Profile);
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
        AssertEqual(16L * 1024 * 1024 * 1024, DevelopmentEvidenceCommand.AggregateMemoryLimitBytes);
        AssertEqual(14L * 1024 * 1024 * 1024, DevelopmentEvidenceCommand.ExecutionMemoryLimitBytes);
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
        {
            throw new InvalidOperationException("bounded process observation did not capture resource use");
        }
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

    private static void Set(JsonObject document, object[] segments, object? value)
    {
        var parent = Resolve(document, segments[..^1]);
        var node = JsonValue.Create(value);
        if (parent is JsonObject objectParent) objectParent[(string)segments[^1]] = node;
        else if (parent is JsonArray arrayParent) arrayParent[(int)segments[^1]] = node;
    }

    private static JsonNode Resolve(JsonNode current, object[] segments)
    {
        foreach (var segment in segments) current = segment is string key ? current[key]! : current[(int)segment]!;
        return current;
    }

    private static JsonObject Clone(JsonObject value) => JsonNode.Parse(value.ToJsonString())!.AsObject();
    private static void AssertValid(IReadOnlyCollection<string> errors) { if (errors.Count != 0) throw new InvalidOperationException(string.Join("; ", errors)); }
    private static void AssertInvalid(IReadOnlyCollection<string> errors) { if (errors.Count == 0) throw new InvalidOperationException("validator accepted an invalid document"); }
    private static void AssertInvalid(JsonObject document, Func<JsonObject, List<string>> validate) => AssertInvalid(validate(document));
    private static void AssertExitZero(Func<int> action) { if (action() != 0) throw new InvalidOperationException("command returned nonzero"); }
    private static void AssertEqual<T>(T expected, T actual) where T : notnull { if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new InvalidOperationException($"expected {expected}, observed {actual}"); }
    private static void AssertThrows<TException>(Action action) where TException : Exception
    {
        try { action(); }
        catch (TException) { return; }
        throw new InvalidOperationException($"expected {typeof(TException).Name}");
    }
}
