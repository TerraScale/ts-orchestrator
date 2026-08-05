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
            if (value is not JsonValue scalar || !scalar.TryGetValue<string>(out var anchor) || string.IsNullOrWhiteSpace(anchor))
            {
                errors.Add($"{where}: anchor must be a non-empty string");
                continue;
            }

            var match = Regex.Match(anchor, @"^(?<path>[^:]+):(?<start>[1-9]\d*)-(?<end>[1-9]\d*)$");
            var relative = match.Success ? match.Groups["path"].Value : string.Empty;
            var isWorkspaceGoal = relative == "../GOAL.md";
            if (!match.Success || anchor.Contains("://", StringComparison.Ordinal) || Path.IsPathRooted(relative)
                || relative.Contains('\\') || (!isWorkspaceGoal && relative.Split('/').Any(part => part is "" or "." or "..")))
            {
                errors.Add($"{where}: invalid local evidence anchor: {anchor}");
                continue;
            }

            var path = isWorkspaceGoal
                ? Path.Combine(Directory.GetParent(ToolingSupport.Root)!.FullName, "GOAL.md")
                : Path.Combine(ToolingSupport.Root, relative);
            if (!File.Exists(path))
            {
                errors.Add($"{where}: evidence target is missing: {anchor}");
                continue;
            }

            var resolvedPath = ResolveExistingPath(path);
            var resolvedWorkspaceGoal = ResolveExistingPath(Path.Combine(Directory.GetParent(ToolingSupport.Root)!.FullName, "GOAL.md"));
            if (isWorkspaceGoal
                ? !string.Equals(resolvedPath, resolvedWorkspaceGoal, StringComparison.Ordinal)
                : !IsWithin(ResolveExistingPath(ToolingSupport.Root), resolvedPath))
            {
                errors.Add($"{where}: evidence target escapes the repository: {anchor}");
                continue;
            }

            var lines = File.ReadAllLines(resolvedPath);
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

    private static string ResolveExistingPath(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var root = Path.GetPathRoot(fullPath)!;
        foreach (var segment in fullPath[root.Length..].Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            var current = Path.Combine(root, segment);
            FileSystemInfo entry = Directory.Exists(current) ? new DirectoryInfo(current) : new FileInfo(current);
            root = entry.ResolveLinkTarget(returnFinalTarget: true)?.FullName ?? current;
        }

        return root;
    }

    private static bool IsWithin(string root, string path)
    {
        var relative = Path.GetRelativePath(root, path);
        return relative is not ".."
            && !relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            && !Path.IsPathRooted(relative);
    }
}

internal static class AdrReadinessCommand
{
    internal static readonly HashSet<string> Lanes =
    [
        "Integration/contract steward", "Core", "Messaging/security", "Runtime", "Cloud", "Storage",
        "TerraBase", "Delivery", "Operations", "Cross-repository cleanup", "Verification"
    ];

    private static readonly HashSet<string> Statuses =
        ["draft-ready", "owner-input-required", "evidence-required", "accepted"];

    private static readonly string[] RequiredFields =
    [
        "id", "slug", "title", "status", "ownerLane", "controllingInputs", "availableEvidence",
        "missingEvidence", "executableDependencies", "closureEvidence", "exitEvidence"
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

        errors.AddRange(DecisionReadinessValidator.Validate(ToolingSupport.ReadObject("docs/decisions/owner-decision-packet.json"), document));
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

        errors.AddRange(DecisionReadinessValidator.Validate(document, ToolingSupport.ReadObject("docs/adr/readiness-index.yaml")));
        return errors;
    }
}

internal static class DecisionReadinessValidator
{
    private static readonly HashSet<string> AcceptedPolicyProvenance =
    ["../GOAL.md:70-77", "docs/decisions/owner-decision-packet.json:13-49"];
    private static readonly HashSet<string> LaterSelectionIds = ["artifact-and-evidence-signing", "dns-implementation", "vpn-implementation", "operator-identity-provider", "regional-artifact-mirror", "arm64-host-image", "nats-n-minus-one-policy"];
    private static readonly string[] AtomicPolicyFields = ["id", "status", "kind", "sourceAnchors"];
    private static readonly string[] OwnershipFields = ["id", "stableOwnerId", "accountableApprovalRole", "assignmentStatus", "decisionScope", "authorityDependency"];
    private static readonly string[] EntryFields = ["id", "slug", "title", "status", "ownerLane", "decisionAdrReferences", "sourceAnchors", "evidenceLocations", "controllingInputs", "openInputOwnershipReferences", "availableEvidence", "missingEvidence", "executableDependencies", "closureEvidence", "exitEvidence"];

    public static List<string> Validate(JsonObject packet, JsonObject readiness)
    {
        var errors = new List<string>();
        var inputs = Ids(packet["inputs"], "packet inputs", 21, errors);
        var selections = Ids(packet["laterImplementationSelections"], "later selections", 7, errors);
        if (!selections.SetEquals(LaterSelectionIds)) errors.Add("later selections: canonical ID set required");
        if (packet["laterImplementationSelections"] is JsonArray later) foreach (var node in later)
        {
            if (node is not JsonObject selection) continue;
            Require(selection, "later selection", ["id", "selection", "readinessStage", "requiredBeforeContractFreeze"], errors);
            if (Text(selection["readinessStage"], "later selection readinessStage", errors) != "later-phase0-selection") errors.Add("later selection: invalid readiness stage");
            if (selection["selection"] is not null) errors.Add("later selection: selection must remain null");
            if (selection["requiredBeforeContractFreeze"] is not JsonValue freeze || !freeze.TryGetValue<bool>(out var required) || required) errors.Add("later selection: must not block contract freeze");
        }
        var atomic = new HashSet<string>(inputs, StringComparer.Ordinal);
        atomic.UnionWith(selections);

        var policies = packet["atomicPolicyRecords"] as JsonArray;
        if (policies is null || policies.Count != 1) errors.Add("atomicPolicyRecords: exactly one accepted policy record is required");
        else foreach (var node in policies)
        {
            if (node is not JsonObject policy) { errors.Add("atomicPolicyRecords: records must be objects"); continue; }
            Require(policy, "accepted policy", AtomicPolicyFields, errors);
            if (Text(policy["id"], "accepted policy id", errors) is { } id) atomic.Add(id);
            if (Text(policy["status"], "accepted policy status", errors) != "accepted") errors.Add("accepted policy: status must be accepted");
            if (Text(policy["kind"], "accepted policy kind", errors) != "owner-policy") errors.Add("accepted policy: kind must be owner-policy");
            ValidateAcceptedPolicyProvenance(policy["sourceAnchors"], "accepted policy", errors);
        }

        var aliases = packet["controllingInputAliases"] as JsonObject;
        if (aliases is null) errors.Add("controllingInputAliases: required object");
        if (aliases is not null)
            foreach (var alias in aliases.Select(pair => pair.Key).Where(atomic.Contains))
                errors.Add($"controllingInputAliases: alias {alias} collides with an atomic ID");
        var expanded = aliases is null ? new Dictionary<string, HashSet<string>>(StringComparer.Ordinal) : ExpandAliases(aliases, atomic, errors);
        ValidateRegisters(packet, inputs, selections, errors);
        ValidateReadinessContext(packet, readiness, errors);
        ValidateAcceptedRegister(packet, readiness, errors);

        var owners = packet["openInputOwnershipRegister"]?["records"] as JsonArray;
        var ownershipRegister = packet["openInputOwnershipRegister"] as JsonObject;
        if (ownershipRegister is null || Text(ownershipRegister["status"], "ownership register status", errors) != "unassigned-owner-gaps"
            || Text(ownershipRegister["assignmentPrerequisite"], "ownership register assignmentPrerequisite", errors) is null) errors.Add("ownership register: invalid status or prerequisite");
        var ownerIds = ObjectIds(owners, "ownership records", errors, OwnershipFields);
        if (!ownerIds.SetEquals(inputs.Concat(selections))) errors.Add("ownership records: must exactly cover every unresolved atomic input");
        if (owners is not null) foreach (var owner in owners.OfType<JsonObject>())
        {
            foreach (var field in OwnershipFields.Skip(1)) Text(owner[field], $"ownership {owner["id"]} {field}", errors);
            var assigned = Text(owner["assignmentStatus"], $"ownership {owner["id"]} assignmentStatus", errors);
            var stable = Text(owner["stableOwnerId"], $"ownership {owner["id"]} stableOwnerId", errors);
            if (assigned is not "unassigned" and not "assigned") errors.Add($"ownership {owner["id"]}: invalid assignment status");
            if (assigned == "unassigned" && stable != "unassigned") errors.Add($"ownership {owner["id"]}: unassigned requires stableOwnerId unassigned");
            if (assigned == "assigned" && (stable == "unassigned" || stable is null)) errors.Add($"ownership {owner["id"]}: assigned requires named stable owner");
        }

        var entries = readiness["entries"] as JsonArray;
        if (entries is null || entries.Count != 24) return errors;
        var graph = new Dictionary<int, HashSet<int>>();
        foreach (var node in entries)
        {
            if (node is not JsonObject entry) { errors.Add("entries: every ADR record must be an object"); continue; }
            var id = entry["id"] is JsonValue v && v.TryGetValue<int>(out var number) ? number : 0;
            Require(entry, $"ADR {id}", EntryFields, errors);
            foreach (var field in new[] { "slug", "title", "ownerLane" }) Text(entry[field], $"ADR {id} {field}", errors);
            var status = Text(entry["status"], $"ADR {id} status", errors);
            if (status is not "draft-ready" and not "owner-input-required" and not "evidence-required") errors.Add($"ADR {id}: status is not an open readiness state");
            var refs = Strings(entry["decisionAdrReferences"], $"ADR {id} decisionAdrReferences", errors);
            if (refs.Count != 1 || refs[0] != $"ADR-{id:0000}") errors.Add($"ADR {id}: decision ADR reference must be its canonical ADR id");
            var sources = Strings(entry["sourceAnchors"], $"ADR {id} sourceAnchors", errors);
            var locations = Strings(entry["evidenceLocations"], $"ADR {id} evidenceLocations", errors);
            if (!sources.Intersect(locations, StringComparer.Ordinal).Any()) errors.Add($"ADR {id}: source anchor must be an evidence location");
            Validation.ValidateLocalAnchors(entry["sourceAnchors"] as JsonArray, $"ADR {id} source anchor", errors);
            Validation.ValidateLocalAnchors(entry["evidenceLocations"] as JsonArray, $"ADR {id} evidence location", errors);
            foreach (var field in new[] { "availableEvidence", "missingEvidence", "exitEvidence" }) Strings(entry[field], $"ADR {id} {field}", errors);

            var controls = Strings(entry["controllingInputs"], $"ADR {id} controllingInputs", errors);
            var expected = new HashSet<string>(StringComparer.Ordinal);
            foreach (var control in controls)
            {
                if (expanded.TryGetValue(control, out var values)) expected.UnionWith(values.Where(ownerIds.Contains));
                else if (atomic.Contains(control) && ownerIds.Contains(control)) expected.Add(control);
                else errors.Add($"ADR {id}: unknown controlling input {control}");
            }
            var ownership = Strings(entry["openInputOwnershipReferences"], $"ADR {id} openInputOwnershipReferences", errors);
            if (!new HashSet<string>(ownership, StringComparer.Ordinal).SetEquals(expected)) errors.Add($"ADR {id}: ownership references must equal controlling-input expansion");
            if (ownership.Any(value => !ownerIds.Contains(value))) errors.Add($"ADR {id}: ownership reference has no accountable record");
            if (status == "owner-input-required" && expected.Count == 0) errors.Add($"ADR {id}: owner-input-required needs unresolved controlling inputs");
            if (status == "draft-ready" && expected.Count != 0) errors.Add($"ADR {id}: draft-ready cannot retain unresolved inputs");

            var executable = IntegerValues(entry["executableDependencies"], $"ADR {id} executableDependencies", errors);
            if (executable.Any(target => target is < 1 or > 24) || executable.Contains(id) || executable.Count != executable.Distinct().Count()) errors.Add($"ADR {id}: executable dependencies must be unique existing non-self ADR ids");
            graph[id] = executable.ToHashSet();
            var closure = IntegerValues(entry["closureEvidence"], $"ADR {id} closureEvidence", errors);
            if (closure.Any(target => target is < 1 or > 24) || closure.Count != closure.Distinct().Count()) errors.Add($"ADR {id}: closure evidence must be unique ADR evidence ids, never executable edges");
            if (closure.Intersect(executable).Any()) errors.Add($"ADR {id}: closure evidence cannot also be executable dependency");
        }
        if (HasCycle(graph)) errors.Add("executableDependencies: graph must be acyclic");
        return errors;
    }

    private static Dictionary<string, HashSet<string>> ExpandAliases(JsonObject aliases, HashSet<string> atomic, List<string> errors)
    {
        var result = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal); var visiting = new HashSet<string>(StringComparer.Ordinal);
        HashSet<string> Expand(string name)
        {
            if (result.TryGetValue(name, out var cached)) return cached;
            if (!visiting.Add(name)) { errors.Add($"controllingInputAliases: cyclic alias {name}"); return new HashSet<string>(StringComparer.Ordinal); }
            if (aliases[name] is not JsonArray values || values.Count == 0) { errors.Add($"controllingInputAliases: {name} must have a non-empty array"); visiting.Remove(name); return new HashSet<string>(StringComparer.Ordinal); }
            var resolved = new HashSet<string>(StringComparer.Ordinal);
            foreach (var value in Strings(values, $"controllingInputAliases {name}", errors))
            {
                if (value == name) errors.Add($"controllingInputAliases: {name} cannot reference itself");
                else if (atomic.Contains(value)) { if (!resolved.Add(value)) errors.Add($"controllingInputAliases: {name} expands duplicate {value}"); }
                else if (aliases.ContainsKey(value)) foreach (var item in Expand(value)) if (!resolved.Add(item)) errors.Add($"controllingInputAliases: {name} expands duplicate {item}");
                else errors.Add($"controllingInputAliases: {name} references unknown {value}");
            }
            visiting.Remove(name); return result[name] = resolved;
        }
        foreach (var alias in aliases.Select(pair => pair.Key)) if (string.IsNullOrWhiteSpace(alias)) errors.Add("controllingInputAliases: alias names must be non-empty"); else Expand(alias);
        return result;
    }

    private static void ValidateRegisters(JsonObject packet, HashSet<string> inputs, HashSet<string> selections, List<string> errors)
    {
        var register = packet["openInputRegister"] as JsonObject;
        if (register is null) { errors.Add("openInputRegister: required object"); return; }
        if (Text(register["status"], "openInputRegister status", errors) != "open-no-defaults") errors.Add("openInputRegister: invalid status");
        Validation.ValidateLocalAnchors(register["sourceAnchors"] as JsonArray, "openInputRegister", errors);
        if (!new HashSet<string>(Strings(register["planning"], "openInputRegister planning", errors)).SetEquals(inputs.Where(id => id is "team-size" or "first-production-date"))) errors.Add("openInputRegister: planning parity failure");
        if (!new HashSet<string>(Strings(register["measurableQualification"], "openInputRegister measurableQualification", errors)).SetEquals(inputs.Where(id => id is not "team-size" and not "first-production-date"))) errors.Add("openInputRegister: measurable parity failure");
        if (!new HashSet<string>(Strings(register["laterSelections"], "openInputRegister laterSelections", errors)).SetEquals(selections)) errors.Add("openInputRegister: later selections parity failure");
    }

    private static void ValidateReadinessContext(JsonObject packet, JsonObject readiness, List<string> errors)
    {
        if (Text(readiness["normalizationEvidence"], "readiness normalizationEvidence", errors) is { } evidence)
        {
            var anchors = new JsonArray(evidence); Validation.ValidateLocalAnchors(anchors, "readiness normalizationEvidence", errors);
        }
        var lanes = Strings(readiness["canonicalOwnerLanes"], "readiness canonicalOwnerLanes", errors);
        if (!new HashSet<string>(lanes, StringComparer.Ordinal).SetEquals(AdrReadinessCommand.Lanes)) errors.Add("readiness canonicalOwnerLanes: exact canonical set required");
        if (Text(readiness["normalizationEvidence"], "readiness normalizationEvidence", errors) != "../GOAL.md:70-77") errors.Add("readiness normalizationEvidence: mandated Goal anchor required");
        var left = readiness["openInputs"] as JsonObject; var right = packet["openInputRegister"] as JsonObject;
        if (left is null || right is null || Text(left["status"], "readiness openInputs status", errors) != Text(right["status"], "packet openInputRegister status", errors)
            || !new HashSet<string>(Strings(left?["planning"], "readiness openInputs planning", errors)).SetEquals(Strings(right?["planning"], "packet openInputRegister planning", errors))
            || !new HashSet<string>(Strings(left?["measurableQualification"], "readiness openInputs measurableQualification", errors)).SetEquals(Strings(right?["measurableQualification"], "packet openInputRegister measurableQualification", errors))
            || !new HashSet<string>(Strings(left?["laterSelections"], "readiness openInputs laterSelections", errors)).SetEquals(Strings(right?["laterSelections"], "packet openInputRegister laterSelections", errors))) errors.Add("readiness openInputs: packet parity failure");
        if (left is null || Text(left["source"], "readiness openInputs source", errors) != "docs/decisions/owner-decision-packet.json:51-122"
            || Text(left["ownershipRegister"], "readiness openInputs ownershipRegister", errors) != "docs/decisions/owner-decision-packet.json:91-123"
            || Text(left["unvalidatedInvariantGap"], "readiness openInputs unvalidatedInvariantGap", errors) != "docs/decisions/owner-decision-packet.json:125-127") errors.Add("readiness openInputs: mandated provenance paths required");
    }

    private static void ValidateAcceptedRegister(JsonObject packet, JsonObject readiness, List<string> errors)
    {
        var left = packet["acceptedDecisionRegister"] as JsonObject; var right = readiness["acceptedDecisionRegister"] as JsonObject;
        if (left is null || right is null || Text(left["status"], "packet acceptedDecisionRegister status", errors) != Text(right["status"], "readiness acceptedDecisionRegister status", errors)
            || Text(left["acceptedOn"], "packet acceptedDecisionRegister acceptedOn", errors) != Text(right["acceptedOn"], "readiness acceptedDecisionRegister acceptedOn", errors)
            || Text(left["authority"], "packet acceptedDecisionRegister authority", errors) != Text(right["authority"], "readiness acceptedDecisionRegister authority", errors)
            || !new HashSet<string>(Strings(left?["sourceAnchors"], "packet acceptedDecisionRegister sourceAnchors", errors)).SetEquals(Strings(right?["sourceAnchors"], "readiness acceptedDecisionRegister sourceAnchors", errors))) errors.Add("acceptedDecisionRegister: packet/readiness parity failure");
        if (left is not null)
        {
            if (Text(left["status"], "acceptedDecisionRegister status", errors) != "accepted-owner-policy") errors.Add("acceptedDecisionRegister: invalid status");
            ValidateAcceptedPolicyProvenance(left["sourceAnchors"], "packet acceptedDecisionRegister", errors);
        }
        if (right is not null) ValidateAcceptedPolicyProvenance(right["sourceAnchors"], "readiness acceptedDecisionRegister", errors);
    }

    private static void ValidateAcceptedPolicyProvenance(JsonNode? node, string where, List<string> errors)
    {
        var anchors = Strings(node, $"{where} sourceAnchors", errors);
        if (!new HashSet<string>(anchors, StringComparer.Ordinal).SetEquals(AcceptedPolicyProvenance))
            errors.Add($"{where}: canonical accepted-policy provenance required");
        Validation.ValidateLocalAnchors(node as JsonArray, where, errors);
    }

    private static HashSet<string> Ids(JsonNode? node, string name, int count, List<string> errors) => ObjectIds(node as JsonArray, name, errors, ["id"], count);
    private static HashSet<int> IntegerIds(JsonNode? node, string name, int count, List<string> errors)
    { var values = IntegerValues(node, name, errors); if (values.Count != count || !values.OrderBy(x => x).SequenceEqual(Enumerable.Range(1, count))) errors.Add($"{name}: exact ordered IDs required"); return values.ToHashSet(); }
    private static HashSet<string> ObjectIds(JsonArray? array, string name, List<string> errors, string[] required, int? count = null)
    { var result = new HashSet<string>(StringComparer.Ordinal); if (array is null) { errors.Add($"{name}: required array"); return result; } if (count is not null && array.Count != count) errors.Add($"{name}: expected {count}"); foreach (var node in array) { if (node is not JsonObject obj) { errors.Add($"{name}: every item must be an object"); continue; } Require(obj, name, required, errors); if (Text(obj["id"], $"{name} id", errors) is { } id && !result.Add(id)) errors.Add($"{name}: duplicate id {id}"); } return result; }
    private static void Require(JsonObject value, string where, IEnumerable<string> fields, List<string> errors) { foreach (var field in fields) if (!value.ContainsKey(field)) errors.Add($"{where}: missing {field}"); }
    private static string? Text(JsonNode? value, string where, List<string> errors) { if (value is JsonValue scalar && scalar.TryGetValue<string>(out var text) && !string.IsNullOrWhiteSpace(text)) return text; errors.Add($"{where}: non-empty string required"); return null; }
    private static List<string> Strings(JsonNode? node, string where, List<string> errors) { if (node is not JsonArray array) { errors.Add($"{where}: array required"); return []; } var values = new List<string>(); foreach (var value in array) if (value is JsonValue scalar && scalar.TryGetValue<string>(out var text) && !string.IsNullOrWhiteSpace(text)) values.Add(text); else errors.Add($"{where}: non-empty strings required"); if (values.Distinct(StringComparer.Ordinal).Count() != values.Count) errors.Add($"{where}: duplicate values"); return values; }
    private static List<int> IntegerValues(JsonNode? node, string where, List<string> errors) { if (node is not JsonArray array) { errors.Add($"{where}: array required"); return []; } var values = new List<int>(); foreach (var value in array) if (value is JsonValue scalar && scalar.TryGetValue<int>(out var number)) values.Add(number); else errors.Add($"{where}: integer values required"); return values; }
    private static bool HasCycle(Dictionary<int, HashSet<int>> graph) { var state = new Dictionary<int, int>(); bool Visit(int value) { if (state.GetValueOrDefault(value) == 1) return true; if (state.GetValueOrDefault(value) == 2) return false; state[value] = 1; var cycle = graph.GetValueOrDefault(value, []).Any(Visit); state[value] = 2; return cycle; } return graph.Keys.Any(Visit); }
}
