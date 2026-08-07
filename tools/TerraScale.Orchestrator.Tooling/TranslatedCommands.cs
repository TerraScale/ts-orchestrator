using System.Text;
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
        => ValidateLocalAnchors(anchors, where, errors, ToolingSupport.Root);

    internal static void ValidateLocalAnchors(JsonArray? anchors, string where, List<string> errors, string root)
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

            var workspaceGoal = Path.Combine(Directory.GetParent(root)!.FullName, "GOAL.md");
            var path = isWorkspaceGoal ? workspaceGoal : Path.Combine(root, relative);
            if (!File.Exists(path))
            {
                errors.Add($"{where}: evidence target is missing: {anchor}");
                continue;
            }

            var resolvedPath = ResolveExistingPath(path);
            if (isWorkspaceGoal
                ? new FileInfo(workspaceGoal).LinkTarget is not null
                    || !string.Equals(resolvedPath, Path.GetFullPath(workspaceGoal), StringComparison.Ordinal)
                : !IsWithin(ResolveExistingPath(root), resolvedPath))
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

internal static class Phase0EvidenceCommand
{
    private static readonly string[] Repositories =
    [
        "TerraBase", "TerraBase.Benchmark", "TerraScale.Deploy", "TerraScale.DotNet", "TerraScale.TypeScript",
        "TerraScale.Internals", "TerraScale.DevHost", "Terrascale.Documentation", "Terrascale.Landingpage",
        "TerraScale.Infrastructure"
    ];
    private static readonly string[] WorkaroundFields =
    [
        "id", "status", "disposition", "source_anchors", "original_constraint", "retained_semantic_behavior",
        "native_replacement_requirement", "native_replacement_gate", "owner_workstream", "phase_removal_task",
        "regression_scenario", "real_boundary_needed", "recovery_rollback_boundary", "external_authority_dependency",
        "evidence_claim_status"
    ];
    private static readonly string[] ClosureFields =
        ["workaround_id", "native_replacement_gate", "removal_assertion", "approved_cleanup_authority", "affected_safe_paths", "approval_identity", "repository", "commit", "path", "sha256", "timestamp"];
    private static readonly string[] InventoryFields = ["repository", "branch", "source_commit", "checkout_state", "ownership", "descriptors"];
    private static readonly string[] DescriptorFields = ["path", "type", "purpose", "classification", "production_relevance", "confidence", "source_sha256"];
    private static readonly string[] ArchiveFields = ["repository", "commit", "path", "sha256", "anchor_sha256"];
    private static readonly Dictionary<string, string[]> ArchivalReceiptIdentities = new(StringComparer.Ordinal)
    {
        ["WRK-001"] = ["TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|AGENTS.md|08d99c7181085edc0678715ac7f3973577bbcbb8a7bc06214c7d9b9fa7d46bd5|archive:TerraScale.Infrastructure/AGENTS.md:66|5255536e3df2504021a4062ba63796e604b30e637c48b9995886cf6999854591", "TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|src/TerraScale.Infrastructure/Program.cs|f3e4bcaa12717c06f2d54e98089c34effcb032d458e259ca425c2fa2fa381be4|archive:TerraScale.Infrastructure/src/TerraScale.Infrastructure/Program.cs:13|14355c61e5cd5a2ab933ae49bb9fecfb1aad66b1c1d63755f47135c217c61b8a"],
        ["WRK-002"] = ["TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|gitops/clusters/production-gru/reconciliation.yaml|5471818590e70e54874e76593e0fbd251022d12ffed56e72574f5b18473b6205|archive:TerraScale.Infrastructure/gitops/clusters/production-gru/reconciliation.yaml:70|1597fd2d8689c55dd63efd4a920f3ccb7fa7d4d98e63c6ec09337de7e4b7da5a"],
        ["WRK-003"] = ["TerraScale.Deploy|bd5ecec12efa857d098dfe12584c9a548eb3d06b|src/TerraScale.Deploy.Cli/Services/ServiceReleasePipeline.cs|5d6a669fed73fcb7f1946057fc19708b5d1fae572c8efa329247827278b1327a|archive:TerraScale.Deploy/src/TerraScale.Deploy.Cli/Services/ServiceReleasePipeline.cs:959|7022c405edaa049877f7d1d305111dc17e8f13872fb6ba5e87c2a91380d0b914"],
        ["WRK-004"] = ["TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|gitops/controllers/flux-image-automation/production-gru/image-update-automation.yaml|17ad31816802f0276645546f3bfe3202304114b3e236c74bc10a378e11d31633|archive:TerraScale.Infrastructure/gitops/controllers/flux-image-automation/production-gru/image-update-automation.yaml:45|9d66be2cf5a9426a19d3b4df69caa8fc62c098a39da7d3416977fe01ee37f969"],
        ["WRK-005"] = ["TerraScale.Deploy|bd5ecec12efa857d098dfe12584c9a548eb3d06b|src/TerraScale.Deploy.Cli/Services/ServiceReleasePipeline.cs|5d6a669fed73fcb7f1946057fc19708b5d1fae572c8efa329247827278b1327a|archive:TerraScale.Deploy/src/TerraScale.Deploy.Cli/Services/ServiceReleasePipeline.cs:280|2a44168318e224e1f830fe9ab620aa00dd4f7b3fb19ef4399abf59593cf0756d"],
        ["WRK-007"] = ["TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|src/TerraScale.Infrastructure/ObservabilityIngestTls.cs|0f4c9137ce89e21508a7e90b877a3cf05d87a06960b1b3758364f51ffe4a5837|archive:TerraScale.Infrastructure/src/TerraScale.Infrastructure/ObservabilityIngestTls.cs:101|d36b85c97864094a1cae0e705bb5cf196629561bf01393e1cd4f6a6ba09947a4"],
        ["WRK-008"] = ["TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|gitops/observability/runtime-secrets/production/external-secrets.yaml|6e80f0e86dbed4228040597b6a2a283874f1140f9f23a48547e92c8f71a8ee5f|archive:TerraScale.Infrastructure/gitops/observability/runtime-secrets/production/external-secrets.yaml:2|aed02990c9edd8692808020fb476cc0ab417a493681bc5bbab67def5908aefb2"],
        ["WRK-009"] = ["TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|gitops/observability/resources/production/prometheus-rules.yaml|efac7ead84a30bb5b53725de3b23d5ff082739dd95f900be6be091bfcbe02215|archive:TerraScale.Infrastructure/gitops/observability/resources/production/prometheus-rules.yaml:124|5ec0e8548a47dd15a659db626a84fe9116a1512490d882d29800fcf36d1c535d"],
        ["WRK-011"] = ["TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|AGENTS.md|08d99c7181085edc0678715ac7f3973577bbcbb8a7bc06214c7d9b9fa7d46bd5|archive:TerraScale.Infrastructure/AGENTS.md:69|8f8f7f6150ce721a043902faa349c1149cea6ec9f3495887b3a8cdd140bd6597"],
        ["WRK-012"] = ["TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|gitops/observability/resources/production/prometheus-rules.yaml|efac7ead84a30bb5b53725de3b23d5ff082739dd95f900be6be091bfcbe02215|archive:TerraScale.Infrastructure/gitops/observability/resources/production/prometheus-rules.yaml:253|091723c95dca86a1170f997ac62fe5cd28de11e9aaab1cff67018fd39575ea57"],
        ["WRK-013"] = ["TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|gitops/observability/resources/production/terrascale-service-dashboards.yaml|5f5ed9947f09663166c4abf6585cdef1cdc00157f224758af505fc9277d3b834|archive:TerraScale.Infrastructure/gitops/observability/resources/production/terrascale-service-dashboards.yaml:7|f9c44d76011cbbc7757e8aa1118166d7b9616225f671725d653e6c4bf52f6138"],
        ["WRK-014"] = ["TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|Pulumi.production-sfo.yaml|c2372cc5bcdf9f2950fa43bcd472fb0d4ceb9bfc93946fdaceee4dc5d8d22dc8|archive:TerraScale.Infrastructure/Pulumi.production-sfo.yaml:20|18fedfa76062642c684e536ad9d256cb01d4e1c2abe33ea756472782e1dcba46"],
        ["WRK-015"] = ["TerraScale.TypeScript|cd7da11eac891ea2a39eb12014b3abc35d45a412|src/regions.ts|f9e518460351b571659996851a7fd2bd62ca4045eb34cc9a14b861a71bffdc57|archive:TerraScale.TypeScript/src/regions.ts:15|7c34f2c8ad226806e74ad057dec21eca12952b9224a2be6c244cc74a06eaf83c"],
        ["WRK-016"] = ["TerraScale.Internals|88cc11fa9562b8c71dadfa6b0515a3d6ec32aacf|.terrascale/deploy.json|aab0bf12783784e19ae95df2c2513cf818001413b85e9e15e5c02f32a6a3e048|current+archive:TerraScale.Internals/.terrascale/deploy.json:17|360d386fc6ff18dfc06eb82163666bd0db260d7417133c3d94a157ccc61499ed"],
        ["WRK-017"] = ["Terrascale.Documentation|03287808a23cadad5dd83309df8cc63b5d5c46d7|src/content/docs/en/reference/regions.svx|2c95e7cb4b8c730fab5e24b15d51787212dea0fc27a28634476e1179f858066f|archive:Terrascale.Documentation/src/content/docs/en/reference/regions.svx:74|f3c66a5bdf719d4576668876917c0bc982c6ae8cd9d2a5e37c8b713406bf18cf"],
        ["WRK-018"] = ["TerraScale.Infrastructure|d924f26b5ceb2759e6143f3e90b78a019d79e73b|src/TerraScale.Infrastructure/Program.cs|f3e4bcaa12717c06f2d54e98089c34effcb032d458e259ca425c2fa2fa381be4|archive:TerraScale.Infrastructure/src/TerraScale.Infrastructure/Program.cs:366|0096393fdcae599d1fae6fa7111b6ff51c3ef89bb999e718eba6a7bff4a41ca7"],
        ["WRK-019"] = ["TerraScale.Deploy|6d56564e16308e2334f76a8635c01f7a621e76da|src/TerraScale.Deploy.Cli/Kubernetes/KubectlRetry.cs|e71cc30d0b673fbbcf72055f6f41c70b4c6e700fe470f8d4dda4abd3db531b58|archive:TerraScale.Deploy/src/TerraScale.Deploy.Cli/Kubernetes/KubectlRetry.cs:7|54e16f538e3fc0a9c4d4e7ed920ecd82de96e3dc49aeec49e5c453cbac6f49d9"],
        ["WRK-021"] = ["Terrascale.Documentation|03287808a23cadad5dd83309df8cc63b5d5c46d7|src/content/docs/en/reference/api/index.svx|e1826ed2b231365074c633ccc5d9e69de037946abad43efa0bb2181661287462|archive:Terrascale.Documentation/src/content/docs/en/reference/api/index.svx:20|a122d239d7e365b369572a5e2064c0abc3f2fce7f3dffb310c6c1a45a4686f8e"],
        ["WRK-022"] = ["TerraScale.TypeScript|cd7da11eac891ea2a39eb12014b3abc35d45a412|src/regions.ts|f9e518460351b571659996851a7fd2bd62ca4045eb34cc9a14b861a71bffdc57|archive:TerraScale.TypeScript/src/regions.ts:81|3e94bb98c794d747ecb1ad9a02ab88aab87c254b1e99afcc4fd98e213df7e476"],
    };
    private static readonly string[] WorkaroundIds =
    [
        "WRK-001", "WRK-002", "WRK-003", "WRK-004", "WRK-005", "WRK-007", "WRK-008", "WRK-009",
        "WRK-011", "WRK-012", "WRK-013", "WRK-014", "WRK-015", "WRK-016", "WRK-017", "WRK-018",
        "WRK-019", "WRK-021", "WRK-022"
    ];

    public static int Run(string[] arguments)
    {
        if (arguments.Length != 0) throw new ToolValidationException(["phase0-evidence accepts no arguments"]);
        var errors = ValidateInventory(ToolingSupport.ReadObject("docs/evidence/phase0/runtime-build-descriptor-inventory.yaml"));
        errors.AddRange(ValidateWorkaroundLedger(ToolingSupport.ReadObject("docs/retirement/workaround-ledger.yaml")));
        ToolingSupport.RequireNoErrors(errors);
        Console.WriteLine("Phase 0 descriptor inventory and workaround ledger valid; evidence remains unclosed.");
        return 0;
    }

    public static List<string> ValidateInventory(JsonObject document)
    {
        var errors = Validation.JsonDocument(document, "descriptor inventory", "schema_version", "inventory_id", "evidence_title", "captured_at", "scope", "repositories", "gaps");
        if (document["schema_version"]?.GetValue<int>() != 1) errors.Add("descriptor inventory: expected schema_version 1");
        if (string.IsNullOrWhiteSpace(document["inventory_id"]?.GetValue<string>())) errors.Add("descriptor inventory: inventory_id is required");
        if (string.IsNullOrWhiteSpace(document["evidence_title"]?.GetValue<string>())) errors.Add("descriptor inventory: evidence_title is required");
        if (!DateOnly.TryParse(document["captured_at"]?.GetValue<string>(), out _)) errors.Add("descriptor inventory: captured_at must be an ISO-8601 date");
        if (document["scope"] is not JsonObject scope || Validation.JsonDocument(scope, "descriptor inventory scope", "method", "production_contract_rule", "sensitive_data").Count != 0)
            errors.Add("descriptor inventory: scope must contain required evidence metadata");
        var entries = document["repositories"] as JsonArray;
        if (entries is null) return errors;
        var names = entries.Select(entry => entry?["repository"]?.GetValue<string>() ?? string.Empty).ToArray();
        if (!names.SequenceEqual(Repositories, StringComparer.Ordinal)) errors.Add("descriptor inventory: repository entries must be stable and ordered");
        for (var entryIndex = 0; entryIndex < entries.Count; entryIndex++)
        {
            if (entries[entryIndex] is not JsonObject entry)
            {
                errors.Add($"descriptor inventory: repository {entryIndex + 1} must be an object");
                continue;
            }

            var repository = entry["repository"]?.GetValue<string>() ?? string.Empty;
            foreach (var field in InventoryFields)
                if (!entry.ContainsKey(field)) errors.Add($"{repository}: missing field {field}");
            var commit = entry["source_commit"]?.GetValue<string>() ?? string.Empty;
            if (!IsCommit(commit)) errors.Add($"{repository}: source_commit must be a lower-case immutable commit ID");
            else VerifyCommit(repository, commit, "repository source_commit", errors);
            var state = entry["checkout_state"]?.GetValue<string>();
            if (state is not "clean" and not "dirty") errors.Add($"{repository}: checkout_state must be clean or dirty");
            if (entry["descriptors"] is not JsonArray descriptors || descriptors.Count == 0)
            {
                errors.Add($"{repository}: descriptors are required");
                continue;
            }

            for (var descriptorIndex = 0; descriptorIndex < descriptors.Count; descriptorIndex++)
            {
                if (descriptors[descriptorIndex] is not JsonObject descriptor)
                {
                    errors.Add($"{repository}: descriptor {descriptorIndex + 1} must be an object");
                    continue;
                }

                foreach (var field in DescriptorFields)
                    if (!descriptor.ContainsKey(field)) errors.Add($"{repository}: descriptor {descriptorIndex + 1} missing field {field}");
                var path = descriptor["path"]?.GetValue<string>() ?? string.Empty;
                var sourceCommit = descriptor["source_commit"]?.GetValue<string>() ?? commit;
                var hash = descriptor["source_sha256"]?.GetValue<string>() ?? string.Empty;
                if (!IsPath(path)) errors.Add($"{repository}: descriptor path must be a fixed repository-relative source path");
                if (!IsCommit(sourceCommit)) errors.Add($"{repository}:{path}: source_commit must be a lower-case immutable commit ID");
                if (!IsHash(hash)) errors.Add($"{repository}:{path}: source_sha256 must be a lower-case SHA-256");
                if (IsPath(path) && IsCommit(sourceCommit) && IsHash(hash))
                    VerifySource(repository, sourceCommit, path, hash, errors);
            }
        }

        return errors;
    }

    public static List<string> ValidateWorkaroundLedger(JsonObject document)
    {
        var errors = Validation.JsonDocument(document, "workaround ledger", "schema_version", "required_entry_fields", "closureEvidence", "archivalSourceEvidence", "entries", "gaps");
        if (document["schema_version"]?.GetValue<int>() != 2) errors.Add("workaround ledger: expected schema_version 2");
        var required = document["required_entry_fields"] as JsonArray;
        if (required is null || !required.Select(value => value?.GetValue<string>()).SequenceEqual(WorkaroundFields))
            errors.Add("workaround ledger: required_entry_fields are incomplete");
        var closures = document["closureEvidence"] as JsonObject;
        if (closures is null) errors.Add("workaround ledger: closureEvidence must be a record map");
        else
        {
            var expected = WorkaroundIds.ToHashSet(StringComparer.Ordinal);
            if (closures.Count != expected.Count || closures.Any(pair => !expected.Contains(pair.Key)))
                errors.Add("workaround ledger: closureEvidence must have exactly the active workaround keys");
        }
        var archives = document["archivalSourceEvidence"] as JsonObject;
        if (archives is null) errors.Add("workaround ledger: archivalSourceEvidence must be a record map");
        else
        {
            var expected = WorkaroundIds.ToHashSet(StringComparer.Ordinal);
            if (archives.Count != expected.Count || archives.Any(pair => !expected.Contains(pair.Key)))
                errors.Add("workaround ledger: archivalSourceEvidence must have exactly the active workaround keys");
        }
        var entries = document["entries"] as JsonArray;
        if (entries is null || entries.Count != WorkaroundIds.Length) return errors;
        for (var index = 0; index < entries.Count; index++)
        {
            if (entries[index] is not JsonObject entry)
            {
                errors.Add($"workaround {index + 1}: record must be an object");
                continue;
            }

            var id = WorkaroundIds[index];
            if (entry["id"]?.GetValue<string>() != id) errors.Add($"workaround {index + 1}: IDs must be stable and ordered");
            foreach (var field in WorkaroundFields)
                if (!entry.ContainsKey(field)) errors.Add($"{id}: missing field {field}");
            var status = entry["status"]?.GetValue<string>();
            var closure = closures?[id];
            ValidateArchiveSources(id, entry["source_anchors"] as JsonArray, archives?[id] as JsonArray, errors);
            if (status == "identified")
            {
                if (closure is not null) errors.Add($"{id}: identified work must have empty closureEvidence");
            }
            else if (status is "retired" or "closed")
            {
                ValidateClosure(id, StringValue(entry["native_replacement_gate"]) ?? string.Empty, closure as JsonObject, errors);
            }
            else errors.Add($"{id}: status must be identified, retired, or closed");
        }

        return errors;
    }

    private static void VerifySource(string repository, string commit, string path, string hash, List<string> errors)
    {
        if (!IsKnownRepository(repository))
        {
            errors.Add($"{repository}:{path}: repository is not a known workspace product");
            return;
        }

        try
        {
            var source = ToolingSupport.GitBytes(RepositoryPath(repository), "show", $"{commit}:{path}");
            if (!string.Equals(ToolingSupport.Sha256Bytes(source), hash, StringComparison.Ordinal))
                errors.Add($"{repository}:{path}: source_sha256 does not match git show {commit}:{path}");
        }
        catch (Exception exception)
        {
            errors.Add($"{repository}:{path}: pinned source is unavailable ({exception.Message})");
        }
    }

    private static void ValidateClosure(string id, string nativeReplacementGate, JsonObject? closure, List<string> errors)
    {
        if (closure is null)
        {
            errors.Add($"{id}: retired/closed work requires complete closureEvidence");
            return;
        }

        foreach (var field in ClosureFields)
            if (field == "affected_safe_paths"
                ? closure[field] is not JsonArray paths || paths.Count == 0 || paths.Any(pathNode => !IsPath(StringValue(pathNode) ?? string.Empty))
                : string.IsNullOrWhiteSpace(StringValue(closure[field])))
                errors.Add($"{id}: closureEvidence requires {field}");
        var repository = closure["repository"]?.GetValue<string>() ?? string.Empty;
        var commit = closure["commit"]?.GetValue<string>() ?? string.Empty;
        var path = closure["path"]?.GetValue<string>() ?? string.Empty;
        var hash = closure["sha256"]?.GetValue<string>() ?? string.Empty;
        if (!string.Equals(StringValue(closure["workaround_id"]), id, StringComparison.Ordinal))
            errors.Add($"{id}: closureEvidence workaround_id must match the current work record");
        if (!string.Equals(StringValue(closure["native_replacement_gate"]), nativeReplacementGate, StringComparison.Ordinal))
            errors.Add($"{id}: closureEvidence native_replacement_gate must match the current work record");
        if (!IsKnownRepository(repository)) errors.Add($"{id}: closureEvidence repository must be a known workspace product");
        if (!IsCommit(commit)) errors.Add($"{id}: closureEvidence commit must be immutable");
        if (!IsPath(path)) errors.Add($"{id}: closureEvidence path must be repository-relative");
        if (!IsHash(hash)) errors.Add($"{id}: closureEvidence sha256 must be lower-case");
        if (!DateTimeOffset.TryParse(closure["timestamp"]?.GetValue<string>(), out _)) errors.Add($"{id}: closureEvidence timestamp must be ISO-8601");
        if (IsKnownRepository(repository) && IsCommit(commit) && IsPath(path) && IsHash(hash))
        {
            VerifyCommit(repository, commit, $"{id}: closureEvidence commit", errors);
            VerifySource(repository, commit, path, hash, errors);
            VerifyClosureReceipt(id, closure, repository, commit, path, errors);
        }
    }

    private static void VerifyClosureReceipt(string id, JsonObject closure, string repository, string commit, string path, List<string> errors)
    {
        try
        {
            var receipt = JsonNode.Parse(new UTF8Encoding(false, true).GetString(
                ToolingSupport.GitBytes(RepositoryPath(repository), "show", $"{commit}:{path}"))) as JsonObject;
            if (receipt is null || StringValue(receipt["receipt_type"]) != "terrascale.workaround-closure-receipt/v1")
            {
                errors.Add($"{id}: closureEvidence immutable artifact must be a dedicated structured receipt");
                return;
            }

            foreach (var field in ClosureFields.TakeWhile(field => field is not "repository"))
            {
                if (field == "affected_safe_paths")
                {
                    if (receipt[field] is not JsonArray paths || paths.Count == 0 || paths.Any(pathNode => !IsPath(StringValue(pathNode) ?? string.Empty))
                        || !JsonNode.DeepEquals(paths, closure[field]))
                        errors.Add($"{id}: closureEvidence affected_safe_paths must match the immutable receipt");
                }
                else if (!string.Equals(StringValue(receipt[field]), StringValue(closure[field]), StringComparison.Ordinal))
                {
                    errors.Add($"{id}: closureEvidence {field} must match the immutable receipt");
                }
            }
            if (!string.Equals(StringValue(receipt["timestamp"]), StringValue(closure["timestamp"]), StringComparison.Ordinal))
                errors.Add($"{id}: closureEvidence timestamp must match the immutable receipt");
        }
        catch (Exception exception)
        {
            errors.Add($"{id}: closureEvidence immutable artifact is not valid receipt JSON ({exception.Message})");
        }
    }

    private static void ValidateArchiveSources(string id, JsonArray? anchors, JsonArray? sources, List<string> errors)
    {
        if (anchors is null || anchors.Count == 0 || sources is null || sources.Count == 0)
        {
            errors.Add($"{id}: archivalSourceEvidence requires an immutable source record");
            return;
        }

        var declared = anchors.Select(anchor => StringValue(anchor) ?? string.Empty).ToArray();
        for (var index = 0; index < declared.Length; index++)
            if (ParseArchiveAnchor(declared[index]) is null)
                errors.Add($"{id}: source_anchors[{index}] must be a known archival repository path and positive line");

        var recorded = sources.Select(source => source is JsonObject receipt ? StringValue(receipt["anchor"]) ?? string.Empty : string.Empty).ToArray();
        if (!recorded.SequenceEqual(declared, StringComparer.Ordinal))
            errors.Add($"{id}: archivalSourceEvidence must exactly match declared source_anchors");
        var identities = sources.Select(source => source is JsonObject receipt
            ? $"{StringValue(receipt["repository"])}|{StringValue(receipt["commit"])}|{StringValue(receipt["path"])}|{StringValue(receipt["sha256"])}|{StringValue(receipt["anchor"])}|{StringValue(receipt["anchor_sha256"])}"
            : string.Empty).ToArray();
        if (!ArchivalReceiptIdentities.TryGetValue(id, out var expected) || !identities.SequenceEqual(expected, StringComparer.Ordinal))
            errors.Add($"{id}: archivalSourceEvidence must match its canonical immutable anchor receipts");
        foreach (var source in sources)
        {
            if (source is not JsonObject receipt)
            {
                errors.Add($"{id}: archivalSourceEvidence records must be objects");
                continue;
            }

            ValidateArchiveSource(id, receipt, errors);
        }
    }

    private static void ValidateArchiveSource(string id, JsonObject? source, List<string> errors)
    {
        if (source is null) return;

        foreach (var field in ArchiveFields.Append("anchor"))
            if (string.IsNullOrWhiteSpace(source[field]?.GetValue<string>())) errors.Add($"{id}: archivalSourceEvidence requires {field}");
        var repository = source["repository"]?.GetValue<string>() ?? string.Empty;
        var commit = source["commit"]?.GetValue<string>() ?? string.Empty;
        var path = source["path"]?.GetValue<string>() ?? string.Empty;
        var hash = source["sha256"]?.GetValue<string>() ?? string.Empty;
        var anchor = source["anchor"]?.GetValue<string>() ?? string.Empty;
        var anchorHash = source["anchor_sha256"]?.GetValue<string>() ?? string.Empty;
        var parsedAnchor = ParseArchiveAnchor(anchor);
        if (parsedAnchor is null) errors.Add($"{id}: archivalSourceEvidence anchor is malformed");
        else if (parsedAnchor.Value.Repository != repository || parsedAnchor.Value.Path != path)
            errors.Add($"{id}: archivalSourceEvidence repository/path must match its anchor");
        if (!IsKnownRepository(repository)) errors.Add($"{id}: archivalSourceEvidence repository must be a known workspace product");
        if (!IsCommit(commit)) errors.Add($"{id}: archivalSourceEvidence commit must be immutable");
        if (!IsPath(path)) errors.Add($"{id}: archivalSourceEvidence path must be repository-relative");
        if (!IsHash(hash)) errors.Add($"{id}: archivalSourceEvidence sha256 must be lower-case");
        if (!IsHash(anchorHash)) errors.Add($"{id}: archivalSourceEvidence anchor_sha256 must be lower-case");
        if (IsKnownRepository(repository) && IsCommit(commit) && IsPath(path) && IsHash(hash) && IsHash(anchorHash))
        {
            VerifyCommit(repository, commit, $"{id}: archivalSourceEvidence commit", errors);
            VerifySource(repository, commit, path, hash, errors);
            if (parsedAnchor is not null) VerifyAnchorLine(id, repository, commit, path, parsedAnchor.Value.Start, parsedAnchor.Value.End, anchorHash, errors);
        }
    }

    private static void VerifyAnchorLine(string id, string repository, string commit, string path, int start, int end, string hash, List<string> errors)
    {
        try
        {
            var bytes = ToolingSupport.GitBytes(RepositoryPath(repository), "show", $"{commit}:{path}");
            var rawLines = GetRawLines(bytes, start, end);
            if (rawLines is null || string.IsNullOrWhiteSpace(new UTF8Encoding(false, true).GetString(rawLines)))
                errors.Add($"{id}: archivalSourceEvidence anchor line is out of bounds or blank");
            else if (!string.Equals(ToolingSupport.Sha256Bytes(rawLines), hash, StringComparison.Ordinal))
                errors.Add($"{id}: archivalSourceEvidence anchor_sha256 does not match raw pinned line/range bytes");
        }
        catch (Exception exception)
        {
            errors.Add($"{id}: archivalSourceEvidence anchor is not valid UTF-8 text ({exception.Message})");
        }
    }

    private static byte[]? GetRawLines(byte[] bytes, int startLine, int endLine)
    {
        var start = 0;
        for (var current = 1; current < startLine; current++)
        {
            start = Array.IndexOf(bytes, (byte)'\n', start);
            if (start < 0) return null;
            start++;
        }

        var end = start;
        for (var current = startLine; current <= endLine; current++)
        {
            end = Array.IndexOf(bytes, (byte)'\n', end);
            if (end < 0) return current == endLine ? bytes[start..] : null;
            if (current == endLine) return bytes[start..end];
            end++;
        }

        return null;
    }

    private static (string Repository, string Path, int Start, int End)? ParseArchiveAnchor(string anchor)
    {
        var match = Regex.Match(anchor, "^(?:archive|current\\+archive):(?<repository>[A-Za-z0-9.]+)/(?<path>[A-Za-z0-9._/-]+):(?<start>[1-9]\\d*)(?:-(?<end>[1-9]\\d*))?$");
        if (!match.Success || !IsKnownRepository(match.Groups["repository"].Value) || !IsPath(match.Groups["path"].Value)
            || !int.TryParse(match.Groups["start"].Value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var start)) return null;
        var end = start;
        if (match.Groups["end"].Success
            && !int.TryParse(match.Groups["end"].Value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out end)) return null;
        return end < start ? null : (match.Groups["repository"].Value, match.Groups["path"].Value, start, end);
    }

    private static string? StringValue(JsonNode? node) => node is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;

    private static void VerifyCommit(string repository, string commit, string where, List<string> errors)
    {
        if (!IsKnownRepository(repository))
        {
            errors.Add($"{where}: repository is not a known workspace product");
            return;
        }

        try
        {
            ToolingSupport.Git(RepositoryPath(repository), "cat-file", "-e", $"{commit}^{{commit}}");
        }
        catch (Exception exception)
        {
            errors.Add($"{repository}: {where} is unavailable ({exception.Message})");
        }
    }

    private static string RepositoryPath(string repository) => Path.Combine(
        Directory.GetParent(ToolingSupport.Root)?.FullName
            ?? throw new DirectoryNotFoundException("workspace root is unavailable"),
        repository);

    private static bool IsKnownRepository(string repository) => Repositories.Contains(repository, StringComparer.Ordinal);

    private static bool IsCommit(string value) => Regex.IsMatch(value, "^[0-9a-f]{40}$");
    private static bool IsHash(string value) => Regex.IsMatch(value, "^[0-9a-f]{64}$");
    private static bool IsPath(string value) => Regex.IsMatch(value, "^(?!/)(?!.*(?:^|/)\\.{1,2}(?:/|$))[A-Za-z0-9._/-]+$");
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
    ["ORCHESTRATOR.md:83-98", "docs/decisions/owner-decision-packet.json:13-49"];
    private static readonly HashSet<string> OpenInputProvenance =
    ["ORCHESTRATOR.md:100-105", "docs/decisions/owner-decision-packet.json:51-122"];
    private static readonly HashSet<string> LaterSelectionIds = ["artifact-and-evidence-signing", "dns-implementation", "vpn-implementation", "operator-identity-provider", "regional-artifact-mirror", "arm64-host-image", "nats-n-minus-one-policy"];
    private static readonly IReadOnlyDictionary<int, (int[] Adrs, string[] Gates)> QuestionMappings = new Dictionary<int, (int[], string[])>
    {
        [1] = ([1, 2], ["contract-freeze", "phase-0-exit", "L0", "L0C", "L3S"]), [2] = ([1, 21], ["contract-freeze", "phase-0-exit", "L0", "L3S", "L4", "L5"]),
        [3] = ([12, 21], ["contract-freeze", "phase-0-exit", "L0", "L0C", "L3S", "L4"]), [4] = ([6, 10], ["contract-freeze", "phase-0-exit", "L0", "L1R", "L3S", "L4"]),
        [5] = ([9, 10], ["contract-freeze", "phase-0-exit", "L0", "L3S", "L4", "L5"]), [6] = ([16, 19], ["contract-freeze", "phase-0-exit", "L0", "L4", "L5"]),
        [7] = ([14], ["contract-freeze", "phase-0-exit", "L0", "L3S"]), [8] = ([2, 8], ["contract-freeze", "phase-0-exit", "L0C", "L3S", "L4", "L5"]),
        [9] = ([17], ["contract-freeze", "phase-0-exit", "L0", "L3S", "L5"]), [10] = ([10], ["contract-freeze", "phase-0-exit", "L0", "L3S"])
    };
    private static readonly IReadOnlyDictionary<string, (string Validation, int[] Adrs, string[] Gates)> InputMappings = new Dictionary<string, (string, int[], string[])>(StringComparer.Ordinal)
    {
        ["team-size"] = ("{\"type\":\"integer\",\"minimum\":1}", [19], ["phase-0-planning"]), ["first-production-date"] = ("{\"type\":\"string\",\"pattern\":\"^(\\\\d{4}-\\\\d{2}-\\\\d{2}|\\\\d{4}-Q[1-4])$\"}", [19], ["phase-0-planning"]),
        ["maximum-three-region-pre-user-cost"] = ("{\"type\":\"number\",\"exclusiveMinimum\":0}", [5, 8, 19, 24], ["contract-freeze", "phase-0-exit", "L5"]),
        ["storage-minimum-iops-per-member"] = ("{\"type\":\"integer\",\"minimum\":1}", [2, 3, 5, 8, 9, 10, 19], ["contract-freeze", "phase-0-exit", "L1R", "L3S", "L4", "L5"]), ["storage-minimum-throughput-per-member"] = ("{\"type\":\"number\",\"exclusiveMinimum\":0}", [2, 3, 5, 8, 9, 10, 19], ["contract-freeze", "phase-0-exit", "L1R", "L3S", "L4", "L5"]),
        ["storage-p95-read-latency"] = ("{\"type\":\"number\",\"minimum\":0}", [2, 3, 5, 8, 9, 10, 19], ["contract-freeze", "phase-0-exit", "L1R", "L3S", "L4", "L5"]), ["storage-p99-read-latency"] = ("{\"type\":\"number\",\"minimum\":0}", [2, 3, 5, 8, 9, 10, 19], ["contract-freeze", "phase-0-exit", "L1R", "L3S", "L4", "L5"]),
        ["storage-p95-write-latency"] = ("{\"type\":\"number\",\"minimum\":0}", [2, 3, 5, 8, 9, 10, 19], ["contract-freeze", "phase-0-exit", "L1R", "L3S", "L4", "L5"]), ["storage-p99-write-latency"] = ("{\"type\":\"number\",\"minimum\":0}", [2, 3, 5, 8, 9, 10, 19], ["contract-freeze", "phase-0-exit", "L1R", "L3S", "L4", "L5"]),
        ["regional-rpo"] = ("{\"type\":\"integer\",\"minimum\":0}", [1, 3, 9, 10, 12, 19, 21, 24], ["contract-freeze", "phase-0-exit", "L0", "L0C", "L3S", "L4", "L5"]), ["regional-rto"] = ("{\"type\":\"integer\",\"minimum\":0}", [1, 3, 9, 10, 12, 19, 21, 24], ["contract-freeze", "phase-0-exit", "L0", "L3S", "L4", "L5"]),
        ["security-credential-revocation"] = ("{\"type\":\"integer\",\"minimum\":0}", [11, 17], ["contract-freeze", "phase-0-exit", "L0", "L0C", "L3S", "L4"]), ["security-workload-certificate-ttl"] = ("{\"type\":\"integer\",\"minimum\":1}", [11], ["contract-freeze", "phase-0-exit", "L0", "L0C", "L3S", "L4"]),
        ["security-certificate-renewal-lead"] = ("{\"type\":\"integer\",\"minimum\":1}", [11], ["contract-freeze", "phase-0-exit", "L0", "L0C", "L3S", "L4"]), ["security-break-glass-session-ttl"] = ("{\"type\":\"integer\",\"minimum\":1}", [17], ["contract-freeze", "phase-0-exit", "L0", "L3S", "L5"]),
        ["security-critical-remediation"] = ("{\"type\":\"integer\",\"minimum\":0}", [11, 17], ["contract-freeze", "phase-0-exit"]), ["memory-orchestrator-rss-per-host"] = ("{\"type\":\"integer\",\"minimum\":1}", [7, 8], ["contract-freeze", "phase-0-exit", "L3S", "L4"]),
        ["density-compact-post-failure-utilization-ceiling"] = ("{\"type\":\"number\",\"exclusiveMinimum\":0,\"maximum\":100}", [7, 8], ["contract-freeze", "phase-0-exit", "L3S", "L4", "L5"]), ["audit-hot-retention"] = ("{\"type\":\"integer\",\"minimum\":1}", [3], ["contract-freeze", "phase-0-exit", "L0C", "L3S"]),
        ["audit-immutable-retention"] = ("{\"type\":\"integer\",\"minimum\":1}", [3], ["contract-freeze", "phase-0-exit", "L3S", "L4", "L5"]), ["maximum-regional-survival-window"] = ("{\"type\":\"integer\",\"minimum\":1}", [11, 12, 21], ["contract-freeze", "phase-0-exit", "L0", "L3S", "L4", "L5"])
    };
    private static readonly IReadOnlyDictionary<string, (int[] Adrs, string[] Gates)> LaterSelectionMappings = new Dictionary<string, (int[], string[])>(StringComparer.Ordinal)
    {
        ["artifact-and-evidence-signing"] = ([14, 23], ["phase-0-exit", "L0"]), ["dns-implementation"] = ([15], ["phase-0-exit", "L3S", "L4"]), ["vpn-implementation"] = ([16], ["phase-0-exit", "L3S", "L4"]), ["operator-identity-provider"] = ([17], ["phase-0-exit", "L3S", "L5"]), ["regional-artifact-mirror"] = ([21], ["phase-0-exit", "L3S", "L4"]), ["arm64-host-image"] = ([22], ["phase-0-exit", "L1R", "L4"]), ["nats-n-minus-one-policy"] = ([22], ["phase-0-exit", "L0C", "L3S"])
    };
    private const string InvariantGapId = "P1-DECISION-REGISTER-TOOLING-ENFORCEMENT";
    private const string InvariantGapStatus = "open-independent-review-required";
    private const string InvariantGapInvariant = "P0-01V enforces accepted-policy provenance, alias expansion, ownership-reference coverage, required ADR record fields, and acyclic executable dependencies.";
    private const string InvariantGapEvidenceLimit = "Validator success proves only checked-in schema consistency; it does not establish external owner assignment or approval, measured evidence, ADR acceptance, or independent P0-01/P0-01V review.";
    private const string InvariantGapPrerequisite = "Independent P0-01/P0-01V review remains required before any acceptance claim.";
    private static readonly string[] AtomicPolicyFields = ["id", "status", "kind", "sourceAnchors"];
    private static readonly string[] OwnershipFields = ["id", "stableOwnerId", "accountableApprovalRole", "assignmentStatus", "decisionScope", "authorityDependency"];
    private static readonly string[] EntryFields = ["id", "slug", "title", "status", "ownerLane", "decisionAdrReferences", "sourceAnchors", "evidenceLocations", "controllingInputs", "openInputOwnershipReferences", "availableEvidence", "missingEvidence", "executableDependencies", "closureEvidence", "exitEvidence"];

    public static List<string> Validate(JsonObject packet, JsonObject readiness)
    {
        var errors = new List<string>();
        var inputs = Ids(packet["inputs"], "packet inputs", 21, errors);
        ValidateQuestions(packet["questions"] as JsonArray, errors);
        ValidateInputs(packet["inputs"] as JsonArray, InputMappings, errors);
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
        ValidateInputs(packet["laterImplementationSelections"] as JsonArray, LaterSelectionMappings, errors);
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
        ValidateInvariantGap(packet["unvalidatedInvariantGaps"] as JsonArray, errors);
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
        ValidateInputReadinessMappings(entries, expanded, errors);
        return errors;
    }

    private static void ValidateQuestions(JsonArray? questions, List<string> errors)
    {
        if (questions is null) return;
        foreach (var question in questions.OfType<JsonObject>())
        {
            var id = question["id"]?.GetValue<int>() ?? 0;
            if (!QuestionMappings.TryGetValue(id, out var expected)) { errors.Add($"question {id}: canonical impact mapping required"); continue; }
            ValidateImpactMapping(question, $"question {id}", expected.Adrs, expected.Gates, errors);
        }
    }

    private static void ValidateInputs<T>(JsonArray? records, IReadOnlyDictionary<string, T> mappings, List<string> errors) where T : notnull
    {
        if (records is null) return;
        foreach (var record in records.OfType<JsonObject>())
        {
            var id = Text(record["id"], "input id", errors);
            if (id is null || !mappings.ContainsKey(id)) { errors.Add($"input {id}: canonical impact mapping required"); continue; }
            switch (mappings[id])
            {
                case ValueTuple<string, int[], string[]> input:
                    if (!JsonNode.DeepEquals(record["validation"], JsonNode.Parse(input.Item1))) errors.Add($"input {id}: canonical validation shape required");
                    ValidateImpactMapping(record, $"input {id}", input.Item2, input.Item3, errors);
                    break;
                case ValueTuple<int[], string[]> selection:
                    ValidateImpactMapping(record, $"input {id}", selection.Item1, selection.Item2, errors);
                    break;
            }
        }
    }

    private static void ValidateImpactMapping(JsonObject record, string where, int[] adrs, string[] gates, List<string> errors)
    {
        if (!IntegerValues(record["impactedAdrs"], $"{where} impactedAdrs", errors).SequenceEqual(adrs)) errors.Add($"{where}: canonical impactedAdrs required");
        if (!Strings(record["impactedGates"], $"{where} impactedGates", errors).SequenceEqual(gates)) errors.Add($"{where}: canonical impactedGates required");
    }

    private static void ValidateInvariantGap(JsonArray? gaps, List<string> errors)
    {
        if (gaps is null || gaps.Count != 1 || gaps[0] is not JsonObject gap || gap.Count != 6) { errors.Add("unvalidatedInvariantGaps: exact required record missing"); return; }
        Require(gap, "unvalidatedInvariantGaps", ["id", "status", "invariant", "currentEvidenceLimit", "requiredFutureExactPaths", "prerequisite"], errors);
        if (Text(gap["id"], "unvalidatedInvariantGaps id", errors) != InvariantGapId || Text(gap["status"], "unvalidatedInvariantGaps status", errors) != InvariantGapStatus
            || Text(gap["invariant"], "unvalidatedInvariantGaps invariant", errors) != InvariantGapInvariant || Text(gap["currentEvidenceLimit"], "unvalidatedInvariantGaps currentEvidenceLimit", errors) != InvariantGapEvidenceLimit
            || gap["requiredFutureExactPaths"] is not JsonArray paths || paths.Count != 0 || Text(gap["prerequisite"], "unvalidatedInvariantGaps prerequisite", errors) != InvariantGapPrerequisite)
            errors.Add("unvalidatedInvariantGaps: independent-review provenance required");
    }

    private static void ValidateInputReadinessMappings(JsonArray entries, Dictionary<string, HashSet<string>> expanded, List<string> errors)
    {
        foreach (var (input, expected) in InputMappings)
        {
            var actual = entries.OfType<JsonObject>().Where(entry => Strings(entry["controllingInputs"], $"input {input} readiness mapping", errors).Any(control => control == input || expanded.GetValueOrDefault(control, []).Contains(input))).Select(entry => entry["id"]?.GetValue<int>() ?? 0);
            if (expected.Adrs.Except(actual).Any()) errors.Add($"input {input}: impacted ADR lacks readiness mapping");
        }
        foreach (var (input, expected) in LaterSelectionMappings)
        {
            var actual = entries.OfType<JsonObject>().Where(entry => Strings(entry["controllingInputs"], $"input {input} readiness mapping", errors).Any(control => control == input || expanded.GetValueOrDefault(control, []).Contains(input))).Select(entry => entry["id"]?.GetValue<int>() ?? 0);
            if (expected.Adrs.Except(actual).Any()) errors.Add($"input {input}: impacted ADR lacks readiness mapping");
        }
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
        if (!new HashSet<string>(Strings(register["sourceAnchors"], "openInputRegister sourceAnchors", errors), StringComparer.Ordinal).SetEquals(OpenInputProvenance)) errors.Add("openInputRegister: canonical source anchors required");
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
        if (Text(readiness["normalizationEvidence"], "readiness normalizationEvidence", errors) != "ORCHESTRATOR.md:83-105") errors.Add("readiness normalizationEvidence: canonical decision context required");
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
