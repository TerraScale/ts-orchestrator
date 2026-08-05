using System.Diagnostics;
using System.Text;
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
            ("adr executable dependency cycle", AdrExecutableDependencyCycle),
            ("adr malformed anchor", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["entries", 0, "sourceAnchors", 0], "https://example.test/a:1-2"), AdrReadinessCommand.Validate)),
            ("adr traversal anchor", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["entries", 0, "sourceAnchors", 0], "../ORCHESTRATOR.md:1-2"), AdrReadinessCommand.Validate)),
            ("adr absolute source anchor", AbsoluteSourceAnchor),
            ("adr source anchor bounds", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["entries", 0, "sourceAnchors", 0], "README.md:999999-999999"), AdrReadinessCommand.Validate)),
            ("adr evidence location bounds", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["entries", 0, "evidenceLocations", 0], "README.md:999999-999999"), AdrReadinessCommand.Validate)),
            ("adr invalid closure reference", AdrInvalidClosureReference),
            ("adr whitespace source anchor", WhitespaceSourceAnchor),
            ("adr symlink escape anchor", SymlinkEscapeAnchor),
            ("adr symlinked workspace Goal", SymlinkedWorkspaceGoal),
            ("adr canonical lane substitution", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["canonicalOwnerLanes", 0], "other"), AdrReadinessCommand.Validate)),
            ("adr normalization provenance", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["normalizationEvidence"], "GOAL.md:1-1"), AdrReadinessCommand.Validate)),
            ("adr Goal anchor bounds", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["normalizationEvidence"], "../GOAL.md:999-999"), AdrReadinessCommand.Validate)),
            ("adr canonical Goal anchor range", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["normalizationEvidence"], "../GOAL.md:70-76"), AdrReadinessCommand.Validate)),
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
            ("packet open input anchors", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["openInputRegister", "sourceAnchors"], Array.Empty<string>()), OwnerDecisionCommand.Validate)),
            ("packet open input in-bounds anchor substitution", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["openInputRegister", "sourceAnchors", 0], "ORCHESTRATOR.md:1-1"), OwnerDecisionCommand.Validate)),
            ("packet invariant gap deletion", () => AssertInvalid(Delete("docs/decisions/owner-decision-packet.json", ["unvalidatedInvariantGaps", 0]), OwnerDecisionCommand.Validate)),
            ("packet invariant gap status", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["unvalidatedInvariantGaps", 0, "status"], "accepted"), OwnerDecisionCommand.Validate)),
            ("packet invariant gap review prerequisite", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["unvalidatedInvariantGaps", 0, "prerequisite"], "review complete"), OwnerDecisionCommand.Validate)),
            ("packet invariant gap source", () => AssertInvalid(Mutate("docs/adr/readiness-index.yaml", ["openInputs", "unvalidatedInvariantGap"], "docs/decisions/owner-decision-packet.json:124-126"), AdrReadinessCommand.Validate)),
            ("owner baseline", () => AssertValid(OwnerDecisionCommand.Validate(ToolingSupport.ReadObject("docs/decisions/owner-decision-packet.json")))),
            ("owner decision drift", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["questions", 0, "answer"], "B"), OwnerDecisionCommand.Validate)),
            ("owner invalid option", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["questions", 1, "answer"], "C"), OwnerDecisionCommand.Validate)),
            ("owner invalid unit", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["inputs", 2, "unit"], "USD/month"), OwnerDecisionCommand.Validate)),
            ("owner missing input impacts", () => AssertInvalid(Delete("docs/decisions/owner-decision-packet.json", ["inputs", 0, "impactedAdrs"]), OwnerDecisionCommand.Validate)),
            ("owner arbitrary input gate", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["inputs", 0, "impactedGates", 0], "L9"), OwnerDecisionCommand.Validate)),
            ("owner malformed input validation", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["inputs", 0, "validation", "minimum"], "1"), OwnerDecisionCommand.Validate)),
            ("owner question impact substitution", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["questions", 0, "impactedAdrs", 0], 24), OwnerDecisionCommand.Validate)),
            ("owner later selection gate substitution", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["laterImplementationSelections", 0, "impactedGates", 0], "L5"), OwnerDecisionCommand.Validate)),
            ("owner later selection default", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["laterImplementationSelections", 0, "selection"], "cosign"), OwnerDecisionCommand.Validate)),
            ("owner missing question", () => AssertInvalid(Delete("docs/decisions/owner-decision-packet.json", ["questions", 4]), OwnerDecisionCommand.Validate)),
            ("owner semantic drift", () => AssertInvalid(Mutate("docs/decisions/owner-decision-packet.json", ["questions", 0, "question"], "drift"), OwnerDecisionCommand.Validate)),
            ("phase 0 evidence baseline", () => AssertPhase0Valid()),
            ("phase 0 invalid schema version", () => AssertInvalid(Mutate("docs/evidence/phase0/runtime-build-descriptor-inventory.yaml", ["schema_version"], 2), Phase0EvidenceCommand.ValidateInventory)),
            ("phase 0 scalar descriptor", () => AssertInvalid(Mutate("docs/evidence/phase0/runtime-build-descriptor-inventory.yaml", ["repositories", 0, "descriptors", 0], "invalid"), Phase0EvidenceCommand.ValidateInventory)),
            ("phase 0 malformed descriptor hash", () => AssertInvalid(Mutate("docs/evidence/phase0/runtime-build-descriptor-inventory.yaml", ["repositories", 0, "descriptors", 0, "source_sha256"], new string('A', 64)), Phase0EvidenceCommand.ValidateInventory)),
            ("phase 0 unavailable repository commit", () => AssertInvalid(Mutate("docs/evidence/phase0/runtime-build-descriptor-inventory.yaml", ["repositories", 0, "source_commit"], new string('0', 40)), Phase0EvidenceCommand.ValidateInventory)),
            ("workaround illicit closure", () => AssertInvalid(Mutate("docs/retirement/workaround-ledger.yaml", ["entries", 0, "status"], "retired"), Phase0EvidenceCommand.ValidateWorkaroundLedger)),
            ("workaround identified receipt", WorkaroundIdentifiedReceipt),
            ("workaround missing closure key", WorkaroundMissingClosureKey),
            ("workaround extra closure key", WorkaroundExtraClosureKey),
            ("workaround unavailable closure receipt", WorkaroundUnavailableClosureReceipt),
            ("workaround mismatched closure receipt", WorkaroundMismatchedClosureReceipt),
            ("workaround unbound real closure receipt", WorkaroundUnboundRealClosureReceipt),
            ("workaround unrelated real closure receipt", WorkaroundUnrelatedRealClosureReceipt),
            ("workaround archival source mismatch", () => AssertInvalid(Mutate("docs/retirement/workaround-ledger.yaml", ["archivalSourceEvidence", "WRK-001", 0, "sha256"], new string('a', 64)), Phase0EvidenceCommand.ValidateWorkaroundLedger)),
            ("workaround missing archival source evidence", WorkaroundMissingArchivalSourceEvidence),
            ("workaround archival anchor drift", () => AssertInvalid(Mutate("docs/retirement/workaround-ledger.yaml", ["entries", 0, "source_anchors", 0], "archive:TerraScale.Infrastructure/AGENTS.md:1"), Phase0EvidenceCommand.ValidateWorkaroundLedger)),
            ("workaround malformed archival anchor", () => AssertInvalid(Mutate("docs/retirement/workaround-ledger.yaml", ["entries", 0, "source_anchors", 0], "archive:unknown/AGENTS.md:1"), Phase0EvidenceCommand.ValidateWorkaroundLedger)),
            ("workaround archival receipt swap", WorkaroundArchivalReceiptSwap),
            ("workaround archival receipt commit retarget", WorkaroundArchivalReceiptCommitRetarget),
            ("workaround archival anchor line bounds", WorkaroundArchivalAnchorLineBounds),
            ("workaround archival oversized anchor range end", WorkaroundArchivalOversizedAnchorRangeEnd),
            ("workaround archival anchor and receipt retarget", WorkaroundArchivalAnchorAndReceiptRetarget),
            ("git bytes preserve non UTF-8 blob", GitBytesPreserveNonUtf8Blob),
            ("no python sources", NoPythonSources),
            ("CI result manifest", CiResultManifest),
            ("development evidence profile authorization", DevelopmentEvidenceProfiles),
            ("development evidence bounded execution", DevelopmentEvidenceBounds),
            ("development bounded process observation", DevelopmentBoundedProcessObservation),
            ("development validation lease", DevelopmentValidationLease),
            ("workspace topology lease", DevelopmentWorkspaceTopologyLease),
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

    private static void AssertPhase0Valid()
    {
        AssertValid(Phase0EvidenceCommand.ValidateInventory(
            ToolingSupport.ReadObject("docs/evidence/phase0/runtime-build-descriptor-inventory.yaml")));
        AssertValid(Phase0EvidenceCommand.ValidateWorkaroundLedger(
            ToolingSupport.ReadObject("docs/retirement/workaround-ledger.yaml")));
    }

    private static void AdrExecutableDependencyCycle()
    {
        var document = Clone(ToolingSupport.ReadObject("docs/adr/readiness-index.yaml"));
        document["entries"]![0]!["executableDependencies"] = new JsonArray(2);
        document["entries"]![1]!["executableDependencies"] = new JsonArray(1);
        AssertInvalid(AdrReadinessCommand.Validate(document));
    }

    private static void AdrInvalidClosureReference()
    {
        var document = Clone(ToolingSupport.ReadObject("docs/adr/readiness-index.yaml"));
        document["entries"]![0]!["closureEvidence"] = new JsonArray(99);
        AssertInvalid(AdrReadinessCommand.Validate(document));
    }

    private static void WorkaroundIdentifiedReceipt()
    {
        var document = Clone(ToolingSupport.ReadObject("docs/retirement/workaround-ledger.yaml"));
        document["closureEvidence"]!["WRK-001"] = new JsonObject { ["repository"] = "TerraScale.Infrastructure" };
        AssertInvalid(Phase0EvidenceCommand.ValidateWorkaroundLedger(document));
    }

    private static void WorkaroundMissingClosureKey()
    {
        var document = Clone(ToolingSupport.ReadObject("docs/retirement/workaround-ledger.yaml"));
        document["closureEvidence"]!.AsObject().Remove("WRK-022");
        AssertInvalid(Phase0EvidenceCommand.ValidateWorkaroundLedger(document));
    }

    private static void WorkaroundExtraClosureKey()
    {
        var document = Clone(ToolingSupport.ReadObject("docs/retirement/workaround-ledger.yaml"));
        document["closureEvidence"]!["WRK-023"] = null;
        AssertInvalid(Phase0EvidenceCommand.ValidateWorkaroundLedger(document));
    }

    private static void WorkaroundUnavailableClosureReceipt() => AssertInvalidClosureReceipt(new string('0', 40), new string('a', 64));

    private static void WorkaroundMismatchedClosureReceipt() => AssertInvalidClosureReceipt(
        "9653c0a337fb252602899b594b315639d32c8b20", new string('a', 64));

    private static void AssertInvalidClosureReceipt(string commit, string hash)
    {
        var document = Clone(ToolingSupport.ReadObject("docs/retirement/workaround-ledger.yaml"));
        document["entries"]![0]!["status"] = "retired";
        document["closureEvidence"]!["WRK-001"] = new JsonObject
        {
            ["repository"] = "TerraBase",
            ["commit"] = commit,
            ["path"] = "TerraBase.slnx",
            ["sha256"] = hash,
            ["gate"] = "L1",
            ["timestamp"] = "2026-08-05T00:00:00Z",
            ["authority"] = "test"
        };
        AssertInvalid(Phase0EvidenceCommand.ValidateWorkaroundLedger(document));
    }

    private static void WorkaroundUnboundRealClosureReceipt()
    {
        var document = Clone(ToolingSupport.ReadObject("docs/retirement/workaround-ledger.yaml"));
        var unrelated = document["archivalSourceEvidence"]!["WRK-002"]![0]!.AsObject();
        document["entries"]![0]!["status"] = "retired";
        document["closureEvidence"]!["WRK-001"] = new JsonObject
        {
            ["workaround_id"] = "WRK-002",
            ["native_replacement_gate"] = document["entries"]![1]!["native_replacement_gate"]!.DeepClone(),
            ["removal_assertion"] = "The retired implementation and its authority were removed.",
            ["approved_cleanup_authority"] = "approved test authority",
            ["repository"] = unrelated["repository"]!.DeepClone(),
            ["commit"] = unrelated["commit"]!.DeepClone(),
            ["path"] = unrelated["path"]!.DeepClone(),
            ["sha256"] = unrelated["sha256"]!.DeepClone(),
            ["timestamp"] = "2026-08-05T00:00:00Z"
        };
        AssertInvalid(Phase0EvidenceCommand.ValidateWorkaroundLedger(document));
    }

    private static void WorkaroundUnrelatedRealClosureReceipt()
    {
        var document = Clone(ToolingSupport.ReadObject("docs/retirement/workaround-ledger.yaml"));
        var unrelated = document["archivalSourceEvidence"]!["WRK-002"]![0]!.AsObject();
        document["entries"]![0]!["status"] = "retired";
        document["closureEvidence"]!["WRK-001"] = new JsonObject
        {
            ["workaround_id"] = "WRK-001",
            ["native_replacement_gate"] = document["entries"]![0]!["native_replacement_gate"]!.DeepClone(),
            ["removal_assertion"] = "The retired implementation and its authority were removed.",
            ["approved_cleanup_authority"] = "approved test authority",
            ["affected_safe_paths"] = new JsonArray("safe/path"),
            ["approval_identity"] = "test approver",
            ["repository"] = unrelated["repository"]!.DeepClone(),
            ["commit"] = unrelated["commit"]!.DeepClone(),
            ["path"] = unrelated["path"]!.DeepClone(),
            ["sha256"] = unrelated["sha256"]!.DeepClone(),
            ["timestamp"] = "2026-08-05T00:00:00Z"
        };
        AssertInvalid(Phase0EvidenceCommand.ValidateWorkaroundLedger(document));
    }

    private static void WorkaroundMissingArchivalSourceEvidence()
    {
        var document = Clone(ToolingSupport.ReadObject("docs/retirement/workaround-ledger.yaml"));
        document["entries"]![0]!["source_anchors"] = new JsonArray();
        document["archivalSourceEvidence"]!["WRK-001"] = new JsonArray();
        AssertInvalid(Phase0EvidenceCommand.ValidateWorkaroundLedger(document));
    }

    private static void GitBytesPreserveNonUtf8Blob()
    {
        var root = Path.Combine(Path.GetTempPath(), $"tooling-git-bytes-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "blob.bin");
        var expected = new byte[] { 0xff, 0x00, 0x80, 0x0a };
        File.WriteAllBytes(path, expected);
        try
        {
            AssertEqual(0, ToolingSupport.RunProcess("git", ["init", "--quiet", root]).ExitCode);
            var hash = ToolingSupport.Git(root, "hash-object", "-w", path).Trim();
            var actual = ToolingSupport.GitBytes(root, "cat-file", "blob", hash);
            if (!actual.SequenceEqual(expected)) throw new InvalidOperationException("git raw bytes changed a non-UTF-8 blob");
            AssertEqual(ToolingSupport.Sha256Bytes(expected), ToolingSupport.Sha256Bytes(actual));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static void WorkaroundArchivalReceiptSwap()
    {
        var document = Clone(ToolingSupport.ReadObject("docs/retirement/workaround-ledger.yaml"));
        var receipt = document["archivalSourceEvidence"]!["WRK-001"]![0]!.AsObject();
        receipt["path"] = "src/TerraScale.Infrastructure/Program.cs";
        receipt["sha256"] = "f3e4bcaa12717c06f2d54e98089c34effcb032d458e259ca425c2fa2fa381be4";
        AssertInvalid(Phase0EvidenceCommand.ValidateWorkaroundLedger(document));
    }

    private static void WorkaroundArchivalReceiptCommitRetarget()
    {
        var document = Clone(ToolingSupport.ReadObject("docs/retirement/workaround-ledger.yaml"));
        var receipt = document["archivalSourceEvidence"]!["WRK-001"]![0]!.AsObject();
        receipt["commit"] = "3bfdb4ee0124fbcce43e7db57cf00045f374fbcb";
        receipt["sha256"] = "f6b47e51a041bda7633dcc5a8f24e840604c1c85c98c8b742289c1c32868c462";
        AssertInvalid(Phase0EvidenceCommand.ValidateWorkaroundLedger(document));
    }

    private static void WorkaroundArchivalAnchorLineBounds()
    {
        var document = Clone(ToolingSupport.ReadObject("docs/retirement/workaround-ledger.yaml"));
        const string anchor = "archive:TerraScale.Infrastructure/AGENTS.md:999999";
        document["entries"]![0]!["source_anchors"]![0] = anchor;
        document["archivalSourceEvidence"]!["WRK-001"]![0]!["anchor"] = anchor;
        AssertInvalid(Phase0EvidenceCommand.ValidateWorkaroundLedger(document));
    }

    private static void WorkaroundArchivalOversizedAnchorRangeEnd()
    {
        var document = Clone(ToolingSupport.ReadObject("docs/retirement/workaround-ledger.yaml"));
        const string anchor = "archive:TerraScale.Infrastructure/AGENTS.md:66-2147483648";
        document["entries"]![0]!["source_anchors"]![0] = anchor;
        document["archivalSourceEvidence"]!["WRK-001"]![0]!["anchor"] = anchor;
        AssertInvalid(Phase0EvidenceCommand.ValidateWorkaroundLedger(document));
    }

    private static void WorkaroundArchivalAnchorAndReceiptRetarget()
    {
        var document = Clone(ToolingSupport.ReadObject("docs/retirement/workaround-ledger.yaml"));
        const string anchor = "archive:TerraScale.Infrastructure/AGENTS.md:65";
        document["entries"]![0]!["source_anchors"]![0] = anchor;
        var receipt = document["archivalSourceEvidence"]!["WRK-001"]![0]!.AsObject();
        receipt["anchor"] = anchor;
        receipt["anchor_sha256"] = "f288db607b8e7372ebff2a7dd7d8e39700ba65451d1445b2063fa300177ca7ab";
        AssertInvalid(Phase0EvidenceCommand.ValidateWorkaroundLedger(document));
    }

    private static void NoPythonSources()
    {
        var python = Directory.EnumerateFiles(ToolingSupport.Root, "*" + ".p" + "y", SearchOption.AllDirectories)
            .Where(path => !path.Split(Path.DirectorySeparatorChar).Any(part => part is "bin" or "obj" or ".git"))
            .ToArray();
        if (python.Length != 0)
            throw new InvalidOperationException($"Python sources remain: {string.Join(',', python)}");
    }

    private static void AbsoluteSourceAnchor()
    {
        var errors = new List<string>();
        Validation.ValidateLocalAnchors(new JsonArray(JsonValue.Create("/tmp/tooling-anchor.md:1-1")), "source", errors);
        AssertInvalid(errors);
    }

    private static void WhitespaceSourceAnchor()
    {
        var name = $"tooling-anchor-whitespace-{Guid.NewGuid():N}.md";
        var path = Path.Combine(ToolingSupport.Root, name);
        File.WriteAllText(path, " \n\t\n");
        try
        {
            var errors = new List<string>();
            Validation.ValidateLocalAnchors(new JsonArray(JsonValue.Create($"{name}:1-2")), "source", errors);
            AssertInvalid(errors);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static void SymlinkEscapeAnchor()
    {
        var target = Path.Combine(Path.GetTempPath(), $"tooling-symlink-target-{Guid.NewGuid():N}");
        var linkName = $"tooling-symlink-escape-{Guid.NewGuid():N}";
        var link = Path.Combine(ToolingSupport.Root, linkName);
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "evidence.md"), "outside repository");
        try
        {
            try
            {
                Directory.CreateSymbolicLink(link, target);
            }
            catch (PlatformNotSupportedException)
            {
                Console.WriteLine("SKIP adr symlink escape anchor: symbolic links are unavailable on this platform");
                return;
            }

            if (new DirectoryInfo(link).LinkTarget is null)
                throw new InvalidOperationException("symbolic link creation did not produce a symbolic link");
            var errors = new List<string>();
            Validation.ValidateLocalAnchors(new JsonArray(JsonValue.Create($"{linkName}/evidence.md:1-1")), "symlink", errors);
            if (!errors.Any(error => error.Contains("escapes the repository", StringComparison.Ordinal)))
                throw new InvalidOperationException("validator accepted a symlink escape anchor");
        }
        finally
        {
            if (Directory.Exists(link)) Directory.Delete(link);
            Directory.Delete(target, recursive: true);
        }
    }

    private static void SymlinkedWorkspaceGoal()
    {
        var workspace = Path.Combine(Path.GetTempPath(), $"tooling-workspace-{Guid.NewGuid():N}");
        var root = Path.Combine(workspace, "repository");
        var target = Path.Combine(Path.GetTempPath(), $"tooling-goal-target-{Guid.NewGuid():N}.md");
        var goal = Path.Combine(workspace, "GOAL.md");
        Directory.CreateDirectory(root);
        File.WriteAllText(target, "outside workspace");
        try
        {
            try
            {
                File.CreateSymbolicLink(goal, target);
            }
            catch (PlatformNotSupportedException)
            {
                Console.WriteLine("SKIP adr symlinked workspace Goal: symbolic links are unavailable on this platform");
                return;
            }

            var errors = new List<string>();
            Validation.ValidateLocalAnchors(new JsonArray(JsonValue.Create("../GOAL.md:1-1")), "Goal", errors, root);
            if (!errors.Any(error => error.Contains("escapes the repository", StringComparison.Ordinal)))
                throw new InvalidOperationException("validator accepted a symlinked workspace Goal");
        }
        finally
        {
            if (File.Exists(goal)) File.Delete(goal);
            Directory.Delete(workspace, recursive: true);
            File.Delete(target);
        }
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

    private static void DevelopmentWorkspaceTopologyLease()
    {
        const string namespaceVariable = "TERRASCALE_VALIDATION_LEASE_NAMESPACE";
        var previousNamespace = Environment.GetEnvironmentVariable(namespaceVariable);
        var leaseNamespace = $"tooling-{Guid.NewGuid():N}";
        try
        {
            Environment.SetEnvironmentVariable(namespaceVariable, null);
            AssertEqual($"terrascale-workspace-topology-{Environment.UserName}", WorkspaceTopologyLease.GetMutexName());
            Environment.SetEnvironmentVariable(namespaceVariable, leaseNamespace);
            AssertEqual($"terrascale-workspace-topology-{leaseNamespace}", WorkspaceTopologyLease.GetMutexName());
            AssertThrows<InvalidOperationException>(() =>
            {
                Environment.SetEnvironmentVariable(namespaceVariable, "invalid namespace");
                _ = WorkspaceTopologyLease.GetMutexName();
            });
            Environment.SetEnvironmentVariable(namespaceVariable, leaseNamespace);

            var first = WorkspaceTopologyLease.AcquireAsync(
                "development-lab", TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
            try
            {
                AssertThrows<InvalidOperationException>(() =>
                    WorkspaceTopologyLease.AcquireAsync(
                        "development-lab", TimeSpan.FromMilliseconds(50)).GetAwaiter().GetResult());

                using var cancellation = new CancellationTokenSource();
                var cancelled = WorkspaceTopologyLease.AcquireAsync(
                    "development-lab", TimeSpan.FromSeconds(2), cancellation.Token);
                cancellation.Cancel();
                AssertThrows<OperationCanceledException>(() => cancelled.GetAwaiter().GetResult());
            }
            finally
            {
                first.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }

            var second = WorkspaceTopologyLease.AcquireAsync(
                "development-lab", TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
            second.DisposeAsync().AsTask().GetAwaiter().GetResult();

            using var holder = StartWorkspaceTopologyLeaseHolder(
                leaseNamespace, noisyStderr: false, ignoreStandardInput: false, out var holderStandardError);
            try
            {
                var status = ReadWorkspaceTopologyLeaseHolderReady(holder, holderStandardError);
                AssertEqual("held", status);
                try
                {
                    WorkspaceTopologyLease.AcquireAsync(
                        "development-lab", TimeSpan.FromMilliseconds(50)).GetAwaiter().GetResult();
                    throw new InvalidOperationException("The child process did not hold the workspace topology lease.");
                }
                catch (InvalidOperationException exception)
                {
                    AssertEqual("Timed out acquiring the workspace topology lease.", exception.Message);
                }
            }
            finally
            {
                StopWorkspaceTopologyLeaseHolder(holder, holderStandardError);
            }
            AssertEqual(0, holder.ExitCode);

            using var hostileHolder = StartWorkspaceTopologyLeaseHolder(
                leaseNamespace, noisyStderr: true, ignoreStandardInput: true, out var hostileStandardError);
            try
            {
                AssertEqual("held", ReadWorkspaceTopologyLeaseHolderReady(hostileHolder, hostileStandardError));
            }
            finally
            {
                StopWorkspaceTopologyLeaseHolder(
                    hostileHolder, hostileStandardError, TimeSpan.FromMilliseconds(50));
            }
            AssertEqual(256, ReadBoundedStandardError(hostileStandardError).Length);

            var afterChildExit = WorkspaceTopologyLease.AcquireAsync(
                "development-lab", TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
            afterChildExit.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
        finally
        {
            Environment.SetEnvironmentVariable(namespaceVariable, previousNamespace);
        }
    }

    private static Process StartWorkspaceTopologyLeaseHolder(
        string leaseNamespace,
        bool noisyStderr,
        bool ignoreStandardInput,
        out Task<string> standardError)
    {
        var processPath = Environment.ProcessPath
            ?? throw new InvalidOperationException("The tooling test host path is unavailable.");
        var holder = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = processPath,
                WorkingDirectory = ToolingSupport.Root,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            }
        };
        holder.StartInfo.ArgumentList.Add("workspace-topology-lease-holder");
        holder.StartInfo.ArgumentList.Add("--namespace");
        holder.StartInfo.ArgumentList.Add(leaseNamespace);
        if (noisyStderr)
        {
            holder.StartInfo.ArgumentList.Add("--noisy-stderr");
            holder.StartInfo.ArgumentList.Add("--ignore-stdin");
        }
        holder.Start();
        standardError = CaptureBoundedStandardErrorAsync(holder.StandardError);
        return holder;
    }

    private static string ReadWorkspaceTopologyLeaseHolderReady(Process holder, Task<string> standardError)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            return holder.StandardOutput.ReadLineAsync(timeout.Token).AsTask().GetAwaiter().GetResult()
                ?? throw new InvalidOperationException("The workspace topology lease holder exited before admission.");
        }
        catch (Exception exception) when (exception is OperationCanceledException or IOException or InvalidOperationException)
        {
            StopWorkspaceTopologyLeaseHolder(holder, standardError);
            throw new InvalidOperationException(
                $"The workspace topology lease holder did not become ready (exit {holder.ExitCode}): {ReadBoundedStandardError(standardError)}",
                exception);
        }
    }

    private static void StopWorkspaceTopologyLeaseHolder(
        Process holder,
        Task<string> standardError,
        TimeSpan? gracefulTimeout = null)
    {
        if (holder.HasExited)
        {
            return;
        }

        holder.StandardInput.Close();
        var timeout = gracefulTimeout ?? TimeSpan.FromSeconds(5);
        if (!holder.WaitForExit(timeout))
        {
            holder.Kill(entireProcessTree: true);
            if (!holder.WaitForExit(TimeSpan.FromSeconds(5)))
            {
                throw new InvalidOperationException(
                    $"The workspace topology lease holder did not exit after termination: {ReadBoundedStandardError(standardError)}");
            }
        }
    }

    private static async Task<string> CaptureBoundedStandardErrorAsync(StreamReader standardError)
    {
        const int maximumLength = 256;
        var captured = new StringBuilder(maximumLength);
        var buffer = new char[maximumLength];
        while (true)
        {
            var read = await standardError.ReadAsync(buffer);
            if (read == 0)
            {
                return captured.ToString();
            }

            var remaining = maximumLength - captured.Length;
            if (remaining > 0)
            {
                captured.Append(buffer, 0, Math.Min(remaining, read));
            }
        }
    }

    private static string ReadBoundedStandardError(Task<string> standardError)
    {
        try
        {
            return standardError.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult()
                .Replace(Environment.NewLine, " ", StringComparison.Ordinal)
                .Trim();
        }
        catch (Exception exception) when (exception is TimeoutException or IOException)
        {
            return "stderr unavailable";
        }
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
