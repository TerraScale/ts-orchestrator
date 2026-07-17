using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.Tooling;

internal static class Validation
{
    private static readonly Regex SecretName = new("secret|token|password|private.?key|credential", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static List<string> JsonDocument(JsonObject document, string name, params string[] requiredKeys)
    {
        var errors = new List<string>();
        foreach (var key in requiredKeys)
        {
            if (!document.ContainsKey(key))
            {
                errors.Add($"{name}: missing key {key}");
            }
        }

        return errors;
    }

    public static void ScanSecrets(JsonNode? node, string path, List<string> errors)
    {
        if (node is JsonObject objectNode)
        {
            foreach (var (key, value) in objectNode)
            {
                if (SecretName.IsMatch(key))
                {
                    errors.Add($"{path}.{key}: secret-bearing fields are prohibited");
                }
                ScanSecrets(value, $"{path}.{key}", errors);
            }
        }
        else if (node is JsonArray array)
        {
            for (var index = 0; index < array.Count; index++)
            {
                ScanSecrets(array[index], $"{path}[{index}]", errors);
            }
        }
    }

    public static void ValidateLocalAnchors(JsonArray? anchors, string where, List<string> errors)
    {
        if (anchors is null)
        {
            errors.Add($"{where}: expected anchor list");
            return;
        }

        foreach (var value in anchors)
        {
            var anchor = value?.GetValue<string>();
            if (anchor is null)
            {
                errors.Add($"{where}: anchor must be a string");
                continue;
            }

            var match = Regex.Match(anchor, @"^(?<path>[^:]+):(?<start>[1-9]\d*)-(?<end>[1-9]\d*)$");
            if (!match.Success || anchor.StartsWith("http", StringComparison.Ordinal))
            {
                continue;
            }

            var path = Path.Combine(ToolingSupport.Root, match.Groups["path"].Value);
            if (!File.Exists(path))
            {
                errors.Add($"{where}: evidence target is missing: {anchor}");
                continue;
            }

            var lines = File.ReadAllLines(path);
            var start = int.Parse(match.Groups["start"].Value, System.Globalization.CultureInfo.InvariantCulture);
            var end = int.Parse(match.Groups["end"].Value, System.Globalization.CultureInfo.InvariantCulture);
            if (end < start || end > lines.Length)
            {
                errors.Add($"{where}: evidence anchor is out of bounds: {anchor} (file has {lines.Length} lines)");
            }
            else if (!lines[(start - 1)..end].Any(line => !string.IsNullOrWhiteSpace(line)))
            {
                errors.Add($"{where}: evidence anchor contains no evidence: {anchor}");
            }
        }
    }
}

internal static class AdrReadinessCommand
{
    private static readonly HashSet<string> Lanes = ["Integration/contract steward", "Core", "Messaging/security", "Runtime", "Cloud", "Storage", "TerraBase", "Delivery", "Operations", "Cross-repository cleanup", "Verification"];
    private static readonly HashSet<string> Statuses = ["draft-ready", "owner-input-required", "evidence-required", "accepted"];
    private static readonly string[] RequiredFields = ["id", "slug", "title", "status", "ownerLane", "controllingInputs", "availableEvidence", "missingEvidence", "dependencies", "exitEvidence"];
    public static int Run(string[] arguments)
    {
        var document = ToolingSupport.ReadObject(Option(arguments, "--document") ?? "docs/adr/readiness-index.yaml");
        var errors = Validate(document);
        ToolingSupport.RequireNoErrors(errors);
        Console.WriteLine("ADR readiness index valid: 24 unique fail-closed records");
        return 0;
    }

    public static List<string> Validate(JsonObject document)
    {
        var errors = Validation.JsonDocument(document, "readiness", "schemaVersion", "status", "openOwnerQuestions", "entries");
        if (document["schemaVersion"]?.GetValue<int>() != 1) errors.Add("schemaVersion: expected 1");
        if (document["status"]?.GetValue<string>() != "readiness-map-not-decision-record") errors.Add("status: readiness map cannot claim a decision");
        var entries = document["entries"] as JsonArray;
        if (entries is null || entries.Count != 24) errors.Add("entries: IDs 1 through 24 must occur exactly once");
        else
        {
            var ids = entries.Select(item => item?["id"]?.GetValue<int>() ?? 0).ToArray();
            if (!ids.SequenceEqual(Enumerable.Range(1, 24))) errors.Add("entries: IDs 1 through 24 must be ordered and unique");
            foreach (var item in entries.OfType<JsonObject>())
            {
                var id = item["id"]?.GetValue<int>() ?? 0;
                foreach (var field in RequiredFields) if (!item.ContainsKey(field)) errors.Add($"ADR {id}: missing field {field}");
                if (item["ownerLane"] is JsonValue lane && !Lanes.Contains(lane.GetValue<string>())) errors.Add($"ADR {id}: non-canonical owner lane");
                if (item["status"] is JsonValue status && !Statuses.Contains(status.GetValue<string>())) errors.Add($"ADR {id}: invalid status");
                Validation.ValidateLocalAnchors(item["availableEvidence"] as JsonArray, $"ADR {id}", errors);
                if (item.ContainsKey("accepted")) errors.Add($"ADR {id}: accepted is forbidden while owner inputs remain open");
                if (item["status"]?.GetValue<string>() == "accepted") errors.Add($"ADR {id}: accepted is forbidden while owner/SLO inputs remain open");
                if (item["status"]?.GetValue<string>() == "draft-ready")
                {
                    var evidence = item["availableEvidence"] as JsonArray;
                    if (evidence is null || !evidence.Any(value => value?.GetValue<string>().StartsWith("ORCHESTRATOR.md:", StringComparison.Ordinal) == true)) errors.Add($"ADR {id}: draft-ready requires a precise ORCHESTRATOR.md anchor");
                    if (evidence is null || !evidence.Any(value => value?.GetValue<string>().StartsWith("docs/audits/", StringComparison.Ordinal) == true || value?.GetValue<string>().StartsWith("docs/retirement/", StringComparison.Ordinal) == true)) errors.Add($"ADR {id}: draft-ready requires a checked-in audit or ledger anchor");
                }
            }
        }
        return errors;
    }

    private static string? Option(string[] arguments, string name) =>
        Array.IndexOf(arguments, name) is var index && index >= 0 && index + 1 < arguments.Length ? arguments[index + 1] : null;
}

internal static class OwnerDecisionCommand
{
    private static readonly IReadOnlyDictionary<string, string> Units = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["team-size"] = "people",
        ["first-production-date"] = "ISO-8601-date-or-quarter",
        ["maximum-three-region-pre-user-cost"] = "BRL/day",
        ["storage-minimum-iops-per-member"] = "IOPS",
        ["storage-minimum-throughput-per-member"] = "MiB/s",
        ["storage-p95-read-latency"] = "ms",
        ["storage-p99-read-latency"] = "ms",
        ["storage-p95-write-latency"] = "ms",
        ["storage-p99-write-latency"] = "ms",
        ["regional-rpo"] = "seconds",
        ["regional-rto"] = "minutes",
        ["security-credential-revocation"] = "seconds",
        ["security-workload-certificate-ttl"] = "hours",
        ["security-certificate-renewal-lead"] = "hours",
        ["security-break-glass-session-ttl"] = "minutes",
        ["security-critical-remediation"] = "hours",
        ["memory-orchestrator-rss-per-host"] = "MiB",
        ["density-compact-post-failure-utilization-ceiling"] = "percent",
        ["audit-hot-retention"] = "days",
        ["audit-immutable-retention"] = "days",
        ["maximum-regional-survival-window"] = "hours",
    };
    public static int Run(string[] arguments)
    {
        var path = arguments.Length > 0 ? arguments[0] : "docs/decisions/owner-decision-packet.json";
        ToolingSupport.RequireNoErrors(Validate(ToolingSupport.ReadObject(path)));
        Console.WriteLine("owner decision packet valid: decisions 1A-10A accepted; measurable qualification targets remain unset");
        return 0;
    }

    public static List<string> Validate(JsonObject document)
    {
        var errors = Validation.JsonDocument(document, "packet", "schemaVersion", "status", "recordedResponse", "questions");
        if (document["status"]?.GetValue<string>() != "owner-choices-accepted-measurable-targets-pending")
            errors.Add("status: owner choices must be accepted while measurable targets remain pending");
        if (document["recordedResponse"] is not JsonObject response
            || response["answer"]?.GetValue<string>() != "all A"
            || response["priority"]?.GetValue<string>() != "reliability-first")
            errors.Add("recordedResponse: explicit all-A reliability-first response is required");
        var questions = document["questions"] as JsonArray;
        if (questions is null || questions.Count != 10) errors.Add("questions: exactly ten owner questions are required");
        else
        {
            var ids = questions.Select(q => q?["id"]?.GetValue<int>() ?? 0).ToArray();
            if (!ids.SequenceEqual(Enumerable.Range(1, 10))) errors.Add("questions: IDs 1 through 10 must be ordered and complete");
            var specification = File.ReadAllLines(Path.Combine(ToolingSupport.Root, "ORCHESTRATOR.md"));
            foreach (var question in questions.OfType<JsonObject>())
            {
                var id = question["id"]?.GetValue<int>() ?? 0;
                var answer = question["answer"]?.GetValue<string>();
                if (answer is not "A") errors.Add($"question {id}: answer must match the explicit owner selection A");
                if (question["optionA"] is null || question["optionB"] is null) errors.Add($"question {question["id"]}: exactly two options required");
                var sourceLine = question["sourceLine"]?.GetValue<int>() ?? 0;
                if (sourceLine <= 0 || sourceLine > specification.Length) { errors.Add($"question {id}: invalid source line"); continue; }
                var cells = specification[sourceLine - 1].Trim().Trim('|').Split('|').Select(cell => cell.Trim()).ToArray();
                if (cells.Length < 4 || cells[0] != id.ToString(System.Globalization.CultureInfo.InvariantCulture)) { errors.Add($"question {id}: question differs from ORCHESTRATOR.md:{sourceLine}"); continue; }
                if (question["question"]?.GetValue<string>() != cells[1]) errors.Add($"question {id}: question differs from ORCHESTRATOR.md:{sourceLine}");
                if (question["optionA"]?.GetValue<string>() != cells[2]) errors.Add($"question {id}: optionA differs from ORCHESTRATOR.md:{sourceLine}");
                if (question["optionB"]?.GetValue<string>() != cells[3]) errors.Add($"question {id}: optionB differs from ORCHESTRATOR.md:{sourceLine}");
                if (question["semanticSha256"]?.GetValue<string>() != ToolingSupport.Sha256Text(string.Join('\u001f', cells))) errors.Add($"question {id}: source line/checksum mismatch");
            }
        }
        var inputs = document["inputs"] as JsonArray;
        if (inputs is null || inputs.Count != Units.Count) errors.Add("required inputs must occur exactly once");
        else foreach (var input in inputs.OfType<JsonObject>())
        {
            var id = input["id"]?.GetValue<string>() ?? string.Empty;
            if (!Units.TryGetValue(id, out var unit) || input["unit"]?.GetValue<string>() != unit) errors.Add($"input {id}: unit must be {unit}");
            if (input["value"] is not null) errors.Add($"input {id}: unmeasured value must remain null");
            var isPlanningInput = id is "team-size" or "first-production-date";
            var expectedStage = isPlanningInput ? "phase-0-planning" : "deployment-qualification";
            if (input["readinessStage"]?.GetValue<string>() != expectedStage)
                errors.Add($"input {id}: readiness stage must be {expectedStage}");
            if (input["requiredBeforeContractFreeze"]?.GetValue<bool>() is not false)
                errors.Add($"input {id}: unmeasured qualification values cannot block pure contract freeze");
        }
        if (document["laterImplementationSelections"] is not JsonArray selections || selections.Count != 7) errors.Add("later implementation selections must occur exactly once");
        else foreach (var selection in selections.OfType<JsonObject>()) if (selection["selection"] is not null) errors.Add($"selection {selection["id"]}: checked-in selection must remain null");
        return errors;
    }
}

internal static class JsonEvidenceValidator
{
    public static List<string> Validate(string path, params string[] requiredKeys)
    {
        var document = ToolingSupport.ReadObject(path);
        return Validation.JsonDocument(document, path, requiredKeys);
    }

    public static void ExactFile(List<string> errors, string path, string expectedSha256)
    {
        var full = Path.Combine(ToolingSupport.Root, path);
        if (!File.Exists(full) || ToolingSupport.Sha256(full) != expectedSha256) errors.Add($"{path}: exact translated baseline digest drift");
    }
}

internal static class RegistryAuditCommand
{
    public static int Run(string[] arguments)
    {
        var errors = JsonEvidenceValidator.Validate("docs/audits/registry/registry-audit.json", "schemaVersion", "summary", "findings");
        JsonEvidenceValidator.ExactFile(errors, "requirements/registry.yaml", "3c4b514adb6e5d7285dae9735057bf848affe137c158f7479162abe829a84b31");
        JsonEvidenceValidator.ExactFile(errors, "docs/audits/registry/registry-audit.json", "f7057fb8a86fbb4f379a07a28567cbf682590216176d8867a42afc67e9f8b3d5");
        JsonEvidenceValidator.ExactFile(errors, "docs/audits/registry/owner-mapping.json", "754e37b4081b262ae338a852543bc14946eec6e1bf4dd355819698b5cb339931");
        JsonEvidenceValidator.ExactFile(errors, "docs/audits/registry/fixtures/negative-cases.json", "de9b1b3132d54d3840cdc678980f18ef05a0c0f34e9eb9b59ce7f0132c4ef10a");
        var audit = ToolingSupport.ReadObject("docs/audits/registry/registry-audit.json");
        if (audit["summary"]?["registryEntries"]?.GetValue<int>() != 43) errors.Add("registry audit must contain 43 entries");
        if (audit["findings"] is not JsonArray findings || findings.Count != 86) errors.Add("registry audit must contain 86 findings");
        ToolingSupport.RequireNoErrors(errors);
        Console.WriteLine("registry audit valid: 43 entries and 86 findings");
        return 0;
    }
}

internal static class NatsReadinessCommand
{
    public static int Run(string[] arguments)
    {
        var errors = Validate(ToolingSupport.ReadObject("testlab/pins/nats-candidates.json"), ToolingSupport.ReadObject("testlab/nats/local-x64-l0c-report.json"));
        JsonEvidenceValidator.ExactFile(errors, "testlab/pins/nats-candidates.json", "4ec095aba92c008e8df4540865fed1766c5d11339bd65cbe7d9201953537e138");
        JsonEvidenceValidator.ExactFile(errors, "testlab/nats/local-x64-l0c-report.json", "96bf8577cebb2dba52c4ce90c43ea677d7e6b4d9347e79d6d9565f5625e6c58f");
        ToolingSupport.RequireNoErrors(errors);
        Console.WriteLine("NATS readiness evidence valid: candidate remains unselected; bounded local smoke is not full L0C");
        return 0;
    }

    public static List<string> Validate(JsonObject candidates, JsonObject report)
    {
        var errors = Validation.JsonDocument(candidates, "candidates", "schemaVersion", "status", "serverCandidates", "clientCandidates", "readiness");
        errors.AddRange(Validation.JsonDocument(report, "report", "schemaVersion", "classification", "harnessPath", "checks", "notTested"));
        if (report["classification"]?.GetValue<string>() != "bounded-local-x64-l0c-smoke-not-production-qualification") errors.Add("report: false full-L0C claim");
        if (report["harnessPath"]?.GetValue<string>() != "testlab/nats/run_local_l0c_smoke.cs") errors.Add("report.harnessPath: C# harness path drift");
        if (report["checks"] is JsonObject checks && checks.Any(pair => pair.Value?.GetValue<bool>() != true)) errors.Add("report.checks: every bounded smoke check must pass");
        if (candidates["status"]?.GetValue<string>() != "candidate-evidence-not-selected") errors.Add("pin status must remain candidate-evidence-not-selected");
        if (candidates["nMinusOnePolicy"] is not null || candidates["candidatePairStatus"]?.GetValue<string>() != "unselected-unexecuted") errors.Add("owner-controlled N/N-1 policy and candidate pair must remain unset/unexecuted");
        foreach (var (group, count) in new[] { ("serverCandidates", 2), ("clientCandidates", 2), ("cliCandidates", 1) })
        {
            if (candidates[group] is not JsonArray rows || rows.Count != count) { errors.Add($"{group} must contain exactly {count} candidates"); continue; }
            foreach (var row in rows.OfType<JsonObject>()) if (row["selected"]?.GetValue<bool>() != false) errors.Add($"{group}: selected must remain false");
        }
        var expectedChecks = new HashSet<string>(["corePubSub", "coreRequestReply", "jetStreamCreatePublishGet", "monitoringLoopback", "processCleanup", "temporaryStoreCleanup"], StringComparer.Ordinal);
        if (report["checks"] is not JsonObject reportChecks || !expectedChecks.SetEquals(reportChecks.Select(pair => pair.Key))) errors.Add("report checks must be complete and exact");
        if (report["harnessPath"]?.GetValue<string>() == "testlab/nats/run_local_l0c_smoke.cs")
        {
            var harness = Path.Combine(ToolingSupport.Root, "testlab/nats/run_local_l0c_smoke.cs");
            if (!File.Exists(harness) || report["harnessSha256"]?.GetValue<string>() != ToolingSupport.Sha256(harness)) errors.Add("report harness digest differs from current C# smoke procedure");
        }
        return errors;
    }
}

internal static class MutationEvidenceCommand
{
    public static int Run(string[] arguments)
    {
        var asOf = DateOnly.FromDateTime(DateTime.UtcNow);
        var option = Array.IndexOf(arguments, "--as-of");
        if (option >= 0 && option + 1 < arguments.Length) asOf = DateOnly.Parse(arguments[option + 1], System.Globalization.CultureInfo.InvariantCulture);
        var errors = Validate(ToolingSupport.ReadObject("tools/mutation/mutation-policy.json"), ToolingSupport.ReadObject("tools/mutation/mutation-evidence.json"), asOf);
        ToolingSupport.RequireNoErrors(errors);
        Console.WriteLine("mutation evidence valid: tool selection unresolved; no mutation result or deployment claim");
        return 0;
    }

    public static List<string> Validate(JsonObject policy, JsonObject report, DateOnly asOf)
    {
        var errors = Validation.JsonDocument(policy, "policy", "schemaVersion", "projects", "exclusions");
        errors.AddRange(Validation.JsonDocument(report, "report", "schemaVersion", "validUntil", "policySha256", "claims"));
        var actualProjects = Directory.EnumerateFiles(Path.Combine(ToolingSupport.Root, "src"), "*.csproj", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(ToolingSupport.Root, path).Replace('\\', '/')).Order(StringComparer.Ordinal).ToArray();
        var recorded = (policy["projects"] as JsonArray)?.Select(row => row?["path"]?.GetValue<string>() ?? string.Empty).Order(StringComparer.Ordinal).ToArray() ?? [];
        if (!actualProjects.SequenceEqual(recorded)) errors.Add("policy.projects: inventory drift from src project set");
        if (policy["exclusions"] is JsonArray exclusions && exclusions.Count != 0) errors.Add("policy.exclusions: runtime sources cannot be excluded");
        var policyPath = Path.Combine(ToolingSupport.Root, "tools/mutation/mutation-policy.json");
        if (report["policySha256"]?.GetValue<string>() != ToolingSupport.Sha256(policyPath)) errors.Add("report.policySha256: policy digest is missing or stale");
        if (DateOnly.TryParse(report["validUntil"]?.GetValue<string>(), out var validUntil) && asOf > validUntil) errors.Add("report.validUntil: mutation readiness evidence is stale");
        return errors;
    }
}

internal static class NatsL0cCommand
{
    public static int Run(string[] arguments)
    {
        var errors = JsonEvidenceValidator.Validate("tools/nats-l0c/l0c-cases.json", "schemaVersion", "cases");
        errors.AddRange(JsonEvidenceValidator.Validate("tools/nats-l0c/l0c-report.json", "schemaVersion", "classification", "caseResults", "fullL0CComplete"));
        JsonEvidenceValidator.ExactFile(errors, "tools/nats-l0c/l0c-cases.json", "67f4e13479db6ef29697f1e81e91fb13e82e40f77a9d86ebdd02ce723fcc8b97");
        JsonEvidenceValidator.ExactFile(errors, "tools/nats-l0c/l0c-report.json", "ea6854c8be1b57708346079e70ded45965f56118658568884700faeb29f68a77");
        JsonEvidenceValidator.ExactFile(errors, "tools/nats-l0c/negative-cases.json", "8ee942e484c7155ded7ae7d576bf67bca6fbd8babb628fa9805866f0326caba2");
        ToolingSupport.RequireNoErrors(errors);
        Console.WriteLine("NATS L0C foundation evidence valid");
        return 0;
    }
}

internal static class RuntimeReadinessCommand
{
    public static int Run(string[] arguments)
    {
        var errors = JsonEvidenceValidator.Validate("testlab/pins/arm64-runtime-candidates.json", "schemaVersion", "status", "hostImageCandidates", "filesystemCandidates", "qualification");
        JsonEvidenceValidator.ExactFile(errors, "testlab/pins/arm64-runtime-candidates.json", "19e734dc0e71b49e25432e88b211ac2f32ec57a5cd8f52df3423b2448bd5ff00");
        var document = ToolingSupport.ReadObject("testlab/pins/arm64-runtime-candidates.json");
        if (document["status"]?.GetValue<string>() != "proposal-unqualified") errors.Add("runtime candidates cannot claim production qualification");
        if (document["selection"] is JsonObject selection && selection.Any(pair => pair.Value is not null)) errors.Add("runtime selection must remain unset");
        ToolingSupport.RequireNoErrors(errors);
        Console.WriteLine("ARM64 runtime readiness evidence valid: selection remains unresolved");
        return 0;
    }
}

internal static class ProviderQualificationCommand
{
    public static int Run(string[] arguments)
    {
        var errors = JsonEvidenceValidator.Validate("testlab/pins/provider-qualification-schema.json", "schemaVersion", "requiredProviders", "sourceCatalogRequiredTopics");
        errors.AddRange(JsonEvidenceValidator.Validate("testlab/pins/provider-qualification-blank.json", "schemaVersion", "status", "providers"));
        errors.AddRange(JsonEvidenceValidator.Validate("testlab/pins/provider-source-catalog.json", "schemaVersion", "sources"));
        JsonEvidenceValidator.ExactFile(errors, "testlab/pins/provider-qualification-schema.json", "9b2e60665f4089f7c678a4fa605ef0ae67df0959c8b4c3848da1af24b9ab60fe");
        JsonEvidenceValidator.ExactFile(errors, "testlab/pins/provider-qualification-blank.json", "b5b5b4b3d59fed094b68e8fda01188a931cc172ed9cd97504253cda8863b881e");
        JsonEvidenceValidator.ExactFile(errors, "testlab/pins/provider-source-catalog.json", "bda72287a1222eb536d73f58f36a0b9a7c437c8b6106936d2522370bdc2849ff");
        JsonEvidenceValidator.ExactFile(errors, "tools/phase0/provider-qualification/fixtures/negative-cases.json", "b196470ee60b80376a850e9eda5e31c773df6a53e894e42fac3efcfc2b3a410d");
        ToolingSupport.RequireNoErrors(errors);
        Console.WriteLine("provider qualification schema and blank evidence valid");
        return 0;
    }
}

internal static class SupplyChainCommand
{
    public static int Run(string[] arguments)
    {
        var document = ToolingSupport.ReadObject("testlab/pins/supply-chain-candidates.json");
        var errors = Validation.JsonDocument(document, "manifest", "schemaVersion", "productionQualified", "existingBaselinePins", "entries", "gaps");
        JsonEvidenceValidator.ExactFile(errors, "testlab/pins/supply-chain-candidates.json", "0174d82224b0203f7bb9a9e0aded9419e3d84a8e3219ad444dbe6b3ea08883ea");
        JsonEvidenceValidator.ExactFile(errors, "tools/phase0/supply-chain/fixtures/negative-cases.json", "fdc1175fd4b257cca88b32bc3503febb24c61ffb81ae642e9fb82f3e1f3ef845");
        if (document["productionQualified"]?.GetValue<bool>() != false) errors.Add("manifest.productionQualified: must be false");
        if (document["existingBaselinePins"]?["lockProvenance"] is JsonArray provenance)
        {
            var recorded = provenance.OfType<JsonObject>().Select(row => row["path"]?.GetValue<string>() ?? string.Empty).Order(StringComparer.Ordinal).ToArray();
            var actual = Directory.EnumerateFiles(ToolingSupport.Root, "packages.lock.json", SearchOption.AllDirectories)
                .Where(path => !path.Split(Path.DirectorySeparatorChar).Any(part => part is "bin" or "obj"))
                .Select(path => Path.GetRelativePath(ToolingSupport.Root, path).Replace('\\', '/')).Order(StringComparer.Ordinal).ToArray();
            if (!recorded.SequenceEqual(actual)) errors.Add("lock provenance path set drift");
            foreach (var row in provenance.OfType<JsonObject>())
            {
                var relative = row["path"]?.GetValue<string>() ?? string.Empty;
                var full = Path.Combine(ToolingSupport.Root, relative);
                if (!File.Exists(full) || row["sha256"]?.GetValue<string>() != ToolingSupport.Sha256(full)) errors.Add($"lock provenance SHA-256 drift: {relative}");
            }
        }
        ToolingSupport.RequireNoErrors(errors);
        Console.WriteLine("supply-chain candidate evidence valid");
        return 0;
    }
}

internal static class TraceabilityCommand
{
    public static int Generate(string[] arguments)
    {
        var path = Path.Combine(ToolingSupport.Root, "docs/audits/traceability/phase1-traceability.json");
        if (arguments.Contains("--check", StringComparer.Ordinal) && !File.Exists(path)) throw new ToolValidationException(["generated traceability artifact is missing"]);
        Console.Write(File.ReadAllText(path, Encoding.UTF8));
        return 0;
    }

    public static int Validate(string[] arguments)
    {
        var errors = JsonEvidenceValidator.Validate("requirements/trace-links.yaml", "schemaVersion", "claimsAcceptanceEvidence", "entries");
        errors.AddRange(JsonEvidenceValidator.Validate("docs/audits/traceability/phase1-structured-traceability.json", "schemaVersion", "entries"));
        JsonEvidenceValidator.ExactFile(errors, "requirements/trace-links.yaml", "0cc952af2dd3a53a6ae88c9b973ef66928bd9f88d773b98d3947f9b69a92e304");
        JsonEvidenceValidator.ExactFile(errors, "docs/audits/traceability/phase1-traceability.json", "b528d69907739c31dd0b90c61bd330ec2ee4fe3b1a2daf566122a454b6acde1b");
        JsonEvidenceValidator.ExactFile(errors, "docs/audits/traceability/phase1-structured-traceability.json", "cb0d078378fd85ec4345ae22f1e57e5a101e75e5d4c535977fe6ba53f052d4d7");
        ToolingSupport.RequireNoErrors(errors);
        Console.WriteLine("structured traceability valid");
        return 0;
    }
}

internal static class DeliveryInventoryCommand
{
    private static readonly HashSet<string> RetiredRepositories = new(StringComparer.Ordinal)
    {
        "Terrabase.Operator",
        "TerraScale.Deploy"
    };

    public static int Generate(string[] arguments)
    {
        Console.Write(File.ReadAllText(Path.Combine(ToolingSupport.Root, "docs/audits/delivery/descriptor-inventory.json"), Encoding.UTF8));
        return 0;
    }

    public static int Validate(string[] arguments)
    {
        var document = ToolingSupport.ReadObject("docs/audits/delivery/descriptor-inventory.json");
        var errors = Validation.JsonDocument(document, "inventory", "schemaVersion", "repositories", "deploymentDescriptors", "productionRoles", "policyConflicts", "coverageGaps");
        JsonEvidenceValidator.ExactFile(errors, "docs/audits/delivery/descriptor-inventory.json", "b750b7f2bda6b1657713b8120ae30d94187c7f525a3f6def879e01c031ab9b0b");
        if (document["repositories"] is not JsonArray repositories || repositories.Count != 10) errors.Add("all ten canonical sibling repositories must occur exactly once");
        else foreach (var repository in repositories.OfType<JsonObject>())
        {
            var name = repository["name"]?.GetValue<string>() ?? string.Empty;
            var commit = repository["commit"]?.GetValue<string>() ?? string.Empty;
            var directory = Path.Combine(Directory.GetParent(ToolingSupport.Root)!.FullName, name);
            if (RetiredRepositories.Contains(name) && !Directory.Exists(directory))
            {
                continue;
            }

            try { _ = ToolingSupport.Git(directory, "cat-file", "-e", $"{commit}^{{commit}}"); }
            catch { errors.Add($"{name}: pinned commit is unavailable"); }
        }
        ToolingSupport.RequireNoErrors(errors);
        Console.WriteLine("validated 10 pinned repositories and delivery inventory boundaries");
        return 0;
    }
}
