using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.Tooling;

internal static class Validation
{
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
    private static readonly HashSet<string> Lanes =
    [
        "Integration/contract steward", "Core", "Messaging/security", "Runtime", "Cloud", "Storage",
        "TerraBase", "Delivery", "Operations", "Cross-repository cleanup", "Verification"
    ];

    private static readonly HashSet<string> Statuses =
        ["draft-ready", "owner-input-required", "evidence-required", "accepted"];

    private static readonly string[] RequiredFields =
    [
        "id", "slug", "title", "status", "ownerLane", "controllingInputs", "availableEvidence",
        "missingEvidence", "dependencies", "exitEvidence"
    ];

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
        if (document["status"]?.GetValue<string>() != "readiness-map-not-decision-record")
            errors.Add("status: readiness map cannot claim a decision");
        var entries = document["entries"] as JsonArray;
        if (entries is null || entries.Count != 24) errors.Add("entries: IDs 1 through 24 must occur exactly once");
        else
        {
            var ids = entries.Select(item => item?["id"]?.GetValue<int>() ?? 0).ToArray();
            if (!ids.SequenceEqual(Enumerable.Range(1, 24))) errors.Add("entries: IDs 1 through 24 must be ordered and unique");
            foreach (var item in entries.OfType<JsonObject>())
            {
                var id = item["id"]?.GetValue<int>() ?? 0;
                foreach (var field in RequiredFields)
                {
                    if (!item.ContainsKey(field)) errors.Add($"ADR {id}: missing field {field}");
                }

                if (item["ownerLane"] is JsonValue lane && !Lanes.Contains(lane.GetValue<string>()))
                    errors.Add($"ADR {id}: non-canonical owner lane");
                if (item["status"] is JsonValue status && !Statuses.Contains(status.GetValue<string>()))
                    errors.Add($"ADR {id}: invalid status");
                Validation.ValidateLocalAnchors(item["availableEvidence"] as JsonArray, $"ADR {id}", errors);
                if (item.ContainsKey("accepted")) errors.Add($"ADR {id}: accepted is forbidden while owner inputs remain open");
                if (item["status"]?.GetValue<string>() == "accepted")
                    errors.Add($"ADR {id}: accepted is forbidden while owner/SLO inputs remain open");
                if (item["status"]?.GetValue<string>() == "draft-ready")
                {
                    var evidence = item["availableEvidence"] as JsonArray;
                    if (evidence is null
                        || !evidence.Any(value =>
                            value?.GetValue<string>().StartsWith("ORCHESTRATOR.md:", StringComparison.Ordinal) == true))
                    {
                        errors.Add($"ADR {id}: draft-ready requires a precise ORCHESTRATOR.md anchor");
                    }
                }
            }
        }

        return errors;
    }

    private static string? Option(string[] arguments, string name) =>
        Array.IndexOf(arguments, name) is var index && index >= 0 && index + 1 < arguments.Length
            ? arguments[index + 1]
            : null;
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
                if (question["optionA"] is null || question["optionB"] is null)
                    errors.Add($"question {question["id"]}: exactly two options required");
                var sourceLine = question["sourceLine"]?.GetValue<int>() ?? 0;
                if (sourceLine <= 0 || sourceLine > specification.Length)
                {
                    errors.Add($"question {id}: invalid source line");
                    continue;
                }

                var cells = specification[sourceLine - 1].Trim().Trim('|').Split('|').Select(cell => cell.Trim()).ToArray();
                if (cells.Length < 4 || cells[0] != id.ToString(System.Globalization.CultureInfo.InvariantCulture))
                {
                    errors.Add($"question {id}: question differs from ORCHESTRATOR.md:{sourceLine}");
                    continue;
                }

                if (question["question"]?.GetValue<string>() != cells[1])
                    errors.Add($"question {id}: question differs from ORCHESTRATOR.md:{sourceLine}");
                if (question["optionA"]?.GetValue<string>() != cells[2])
                    errors.Add($"question {id}: optionA differs from ORCHESTRATOR.md:{sourceLine}");
                if (question["optionB"]?.GetValue<string>() != cells[3])
                    errors.Add($"question {id}: optionB differs from ORCHESTRATOR.md:{sourceLine}");
                if (question["semanticSha256"]?.GetValue<string>() != ToolingSupport.Sha256Text(string.Join('\u001f', cells)))
                    errors.Add($"question {id}: source line/checksum mismatch");
            }
        }

        var inputs = document["inputs"] as JsonArray;
        if (inputs is null || inputs.Count != Units.Count) errors.Add("required inputs must occur exactly once");
        else
        {
            foreach (var input in inputs.OfType<JsonObject>())
            {
                var id = input["id"]?.GetValue<string>() ?? string.Empty;
                if (!Units.TryGetValue(id, out var unit) || input["unit"]?.GetValue<string>() != unit)
                    errors.Add($"input {id}: unit must be {unit}");
                if (input["value"] is not null) errors.Add($"input {id}: unmeasured value must remain null");
                var isPlanningInput = id is "team-size" or "first-production-date";
                var expectedStage = isPlanningInput ? "phase-0-planning" : "deployment-qualification";
                if (input["readinessStage"]?.GetValue<string>() != expectedStage)
                    errors.Add($"input {id}: readiness stage must be {expectedStage}");
                if (input["requiredBeforeContractFreeze"]?.GetValue<bool>() is not false)
                    errors.Add($"input {id}: unmeasured qualification values cannot block pure contract freeze");
            }
        }

        if (document["laterImplementationSelections"] is not JsonArray selections || selections.Count != 7)
            errors.Add("later implementation selections must occur exactly once");
        else
        {
            foreach (var selection in selections.OfType<JsonObject>())
            {
                if (selection["selection"] is not null)
                    errors.Add($"selection {selection["id"]}: checked-in selection must remain null");
            }
        }

        return errors;
    }
}
