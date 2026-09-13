namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Source-scan proof that no live Public Alpha, candidate, readiness, approval, activation,
/// promotion, or release-stage delivery path exists in production sources, and that no
/// production path uses <see cref="TerraScale.Orchestrator.ControlPlane.Delivery.InMemoryDeliveryJournal"/>.
/// The scan matches retired delivery-path identifiers, not English words: consensus candidates,
/// NATS stream retention, health readiness dimensions, and control-plane approval evidence are
/// retained safety behavior, not release ceremony.
/// </summary>
public sealed class DirectDeliveryRetiredPathScanTests
{
    /// <summary>
    /// Retired delivery-path identifiers. A hit outside the residue allow-list means a removed
    /// stage returned under its own name.
    /// </summary>
    private static readonly string[] RetiredIdentifiers =
    [
        "PublicAlpha",
        "LaunchCandidate",
        "ReadinessCoordinator",
        "ReadinessRecord",
        "ReadinessStage",
        "ApprovalHandoff",
        "ApprovalCoordinator",
        "ActivationHandoff",
        "ActivationCoordinator",
        "QualificationCoordinator",
        "PromotionCoordinator",
        "PromotionJournal",
        "RetentionCoordinator",
        "SecondRollout",
        "ReleaseStage",
        "CandidateStore",
        "CandidateArtifacts",
        "JobKind.Promotion",
        "ProductionPromotion",
    ];

    /// <summary>
    /// Recorded residue (mission record for TerraScale.Orchestrator#3). These are retired-stage
    /// VOCABULARY on CI runner/decision surfaces, not live delivery stages: nothing constructs a
    /// promotion job or a promotion credential profile anymore, and <c>CandidateArtifacts</c> is
    /// merely the runner's name for ordinary artifact-build output. Renaming any of them changes
    /// serialized plan/attestation digest inputs, which permanently fails every persisted record
    /// (RepositoryCiPipelineJournal schema-2 precedent), so they are durable-format decisions
    /// owned by the CI decision domain and are recorded here instead of silently retired.
    /// </summary>
    private static readonly Dictionary<string, string[]> ResidueAllowList = new(StringComparer.Ordinal)
    {
        ["TerraScale.Orchestrator/ControlPlane/Delivery/DeliveryEngine.cs"] = ["JobKind.Promotion"],
        ["TerraScale.Orchestrator/Delivery/CiRunnerExecutionPlan.cs"] = ["CandidateArtifacts"],
        ["TerraScale.Orchestrator/Delivery/CiRunnerBuildKitInvocation.cs"] = ["CandidateArtifacts"],
        ["TerraScale.Orchestrator/Delivery/CiRunnerDurableResultSink.cs"] = ["CandidateArtifacts"],
        ["TerraScale.Orchestrator/Delivery/CiRunnerIsolationPolicy.cs"] = ["ProductionPromotion"],
    };

    /// <summary>The one file that may contain the in-memory journal: its own definition.</summary>
    private const string InMemoryJournalDefinition = "TerraScale.Orchestrator/ControlPlane/Delivery/DirectDeliveryCoordinator.cs";

    [Test]
    public async Task Production_sources_have_no_live_retired_delivery_path()
    {
        var root = FindRepositoryRoot();
        var violations = new List<string>();
        foreach (var (relativePath, text) in ReadProductionSources(root))
        {
            foreach (var identifier in RetiredIdentifiers)
            {
                if (!text.Contains(identifier, StringComparison.Ordinal))
                    continue;
                var allowed = ResidueAllowList.TryGetValue(relativePath, out var tokens) &&
                    tokens.Contains(identifier, StringComparer.Ordinal);
                if (!allowed)
                    violations.Add($"{relativePath}: {identifier}");
            }
        }
        await Assert.That(string.Join("; ", violations)).IsEmpty();
    }

    [Test]
    public async Task No_production_path_uses_the_in_memory_delivery_journal()
    {
        var root = FindRepositoryRoot();
        var violations = new List<string>();
        foreach (var (relativePath, text) in ReadProductionSources(root))
        {
            if (relativePath == InMemoryJournalDefinition)
                continue;
            if (text.Contains("InMemoryDeliveryJournal", StringComparison.Ordinal))
                violations.Add(relativePath);
        }
        await Assert.That(string.Join("; ", violations)).IsEmpty();
    }

    /// <summary>
    /// Every production source under <c>src/</c> is scanned, so a retired path cannot hide in a
    /// sibling project.
    /// </summary>
    private static IEnumerable<(string RelativePath, string Text)> ReadProductionSources(string root)
    {
        var sourceRoot = Path.Combine(root, "src");
        foreach (var path in Directory.EnumerateFiles(sourceRoot, "*.cs", SearchOption.AllDirectories)
                     .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}") &&
                         !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
                     .Order(StringComparer.Ordinal))
            yield return (
                Path.GetRelativePath(sourceRoot, path),
                File.ReadAllText(path));
    }

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null;
             directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "TerraScale.Orchestrator.slnx")))
                return directory.FullName;
        }
        throw new InvalidOperationException(
            "The repository root was not found; the retired-path scan must run from the repository.");
    }
}
