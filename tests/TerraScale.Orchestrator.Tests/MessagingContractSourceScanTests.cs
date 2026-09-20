using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Source-scan proof that production sources define NATS control subjects exclusively through
/// the canonical taxonomy (<c>Protocol/Messaging/NatsSubjectTaxonomy.cs</c>) instead of private
/// string copies. The scan matches the control-plane root <c>ts.orch</c> and the reserved
/// product-plane root <c>ts.product</c> case-insensitively, and additionally flags composition
/// lines (string concatenation, <c>string.Concat</c>, or <c>StringBuilder.Append</c>) that
/// assemble a <c>ts.</c> fragment together with an <c>orch</c> or <c>product</c> fragment on
/// one line outside the canonical contract directory.
/// <para>
/// Residual limits, stated honestly: this is a line-based text scan, not literal analysis.
/// It cannot see across lines (a <c>ts.</c> fragment and its <c>orch</c> suffix composed on
/// separate lines), interpolated assembly (<c>$"ts.{plane}.v1"</c>), char/byte assembly,
/// constants defined outside the scanned sources, or subjects arriving from configuration or
/// payloads. The <c>orch</c>/<c>product</c> fragments also match inside unrelated words (for
/// example <c>orchestrator</c>), so a legitimate composition line can be flagged; the
/// allow-list is intentionally empty today and must stay minimal. Roslyn literal-flow
/// analysis is the future fix for these blind spots.
/// </para>
/// </summary>
public sealed class MessagingContractSourceScanTests
{
    private const string CanonicalContractsDirectory = "TerraScale.Orchestrator/Protocol/Messaging";
    private const string CanonicalTaxonomyPath = CanonicalContractsDirectory + "/NatsSubjectTaxonomy.cs";
    private const string ControlRootLiteral = "ts.orch";
    private const string CurrentControlRootLiteral = "ts.orch.v2";
    private const string SupersededControlRootLiteral = "ts.orch.v1";
    private const string ProductRootLiteral = "ts.product";
    private const string SubjectFragmentLiteral = "ts.";

    [Test]
    public async Task Production_sources_have_no_private_subject_namespace_copies()
    {
        var root = FindRepositoryRoot();
        var violations = new List<string>();
        foreach (var (relativePath, text) in ReadProductionSources(root))
        {
            if (relativePath.StartsWith(CanonicalContractsDirectory, StringComparison.Ordinal))
            {
                continue;
            }

            foreach (var line in text.Split('\n'))
            {
                if (ContainsRootLiteral(line))
                {
                    violations.Add($"{relativePath}: root literal in \"{Truncate(line)}\"");
                }
                else if (ComposesSubjectFragment(line))
                {
                    violations.Add($"{relativePath}: composed subject fragment in \"{Truncate(line)}\"");
                }
            }
        }

        await Assert.That(string.Join("; ", violations)).IsEmpty();
    }

    [Test]
    public async Task Production_sources_define_each_control_root_only_in_the_canonical_taxonomy()
    {
        var root = FindRepositoryRoot();
        var current = ProductionLinesContaining(root, $"\"{CurrentControlRootLiteral}\"");
        var superseded = ProductionLinesContaining(root, $"\"{SupersededControlRootLiteral}\"");

        await Assert.That(current.Count).IsEqualTo(1);
        await Assert.That(current.Single())
            .Contains(CanonicalTaxonomyPath + ": public const string Root");
        await Assert.That(superseded.Count).IsEqualTo(1);
        await Assert.That(superseded.Single())
            .Contains(CanonicalTaxonomyPath + ": public const string SupersededRoot");
    }

    [Test]
    public async Task Production_sources_contain_no_active_legacy_subject_family_fragments()
    {
        var retiredFragments = new[]
        {
            ".event.",
            ".internal.operation-journal",
            ".global.ci.",
            "orchestrator-protocol-v1",
        };
        var violations = new List<string>();
        foreach (var (relativePath, text) in ReadProductionSources(FindRepositoryRoot()))
        {
            foreach (var line in text.Split('\n'))
            {
                foreach (var fragment in retiredFragments)
                {
                    if (line.Contains(fragment, StringComparison.Ordinal))
                    {
                        violations.Add($"{relativePath}: retired fragment {fragment} in \"{Truncate(line)}\"");
                    }
                }
            }
        }

        await Assert.That(string.Join("; ", violations)).IsEmpty();
    }

    [Test]
    public async Task Runtime_topology_and_inventory_subjects_stay_inside_the_closed_v2_taxonomy()
    {
        var regional = new NatsTopology("gru", 3, "controller-1");
        var global = new GlobalNatsTopology(3);
        var patterns = regional.Streams.SelectMany(static stream => stream.Subjects!)
            .Concat(global.Streams.SelectMany(static stream => stream.Subjects!))
            .Concat(DurableWorkInventory.Streams.SelectMany(static plan => plan.SubjectFor("gru")))
            .Concat(DurableWorkInventory.Consumers.Select(static plan => plan.FilterSubjectFor("gru")));
        var concreteSubjects = new[]
        {
            regional.HealthSubject,
            regional.InstanceHealthSubject,
            regional.StatusSubject,
            regional.MembersSubject,
            regional.StatsSubject,
            regional.OperatorStatusSubject,
            regional.DirectDeliverySubject,
            regional.OperationJournalCreateSubject,
            regional.OperationJournalUpdateSubject,
            regional.OperationJournalReplySubject("controller-1", new string('a', 32)),
            regional.CellSpecSubject,
            regional.StartupSubject,
            global.CiConsumer.FilterSubject!,
            global.CiRuntimeProofConsumer.FilterSubject!,
            global.CellSpecConsumer("gru").FilterSubject!,
            global.CiJobConsumer("untrusted-product", "runner-1").FilterSubject!,
        }.Concat(patterns.Select(RepresentativeSubject));

        var violations = concreteSubjects
            .Where(subject => !subject.StartsWith(NatsSubjectTaxonomy.Root + ".", StringComparison.Ordinal) ||
                !NatsSubjectTaxonomy.IsControlNamespace(NatsSubjectTaxonomy.Classify(subject)))
            .ToArray();

        await Assert.That(violations).IsEmpty();
    }

    [Test]
    public async Task Regional_protocol_package_identity_tracks_the_v2_messaging_contract()
    {
        await Assert.That(new NatsTopology("gru", 3).ProtocolObject)
            .IsEqualTo("orchestrator-protocol-v2");

        var package = System.Text.Encoding.UTF8.GetString(NatsProtocolPackage.Bytes);
        await Assert.That(package).Contains("\"protocol\":2");
        await Assert.That(package).DoesNotContain("\"protocol\":1");
    }

    [Test]
    public async Task Root_literals_are_matched_case_insensitively()
    {
        await Assert.That(ContainsRootLiteral("var subject = \"TS.orch.v1.gru.query.health\";")).IsTrue();
        await Assert.That(ContainsRootLiteral("var subject = \"ts.Product.v1.queue\";")).IsTrue();
        await Assert.That(ContainsRootLiteral("var subject = \"ts.control.v1.gru\";")).IsFalse();
    }

    [Test]
    public async Task Composition_lines_assembling_subject_fragments_are_flagged()
    {
        await Assert.That(ComposesSubjectFragment("var root = \"ts.\" + \"orch.v1\";")).IsTrue();
        await Assert.That(ComposesSubjectFragment("var root = \"ts.\" + plane + \".v1\"; // plane = orch")).IsTrue();
        await Assert.That(ComposesSubjectFragment("var root = string.Concat(\"ts.\", \"product\");")).IsTrue();
        await Assert.That(ComposesSubjectFragment("builder.Append(\"ts.\").Append(\"orch.v1\");")).IsTrue();
        await Assert.That(ComposesSubjectFragment("var s = new StringBuilder().Append(\"ts.orch\").ToString();")).IsTrue();

        // Composition without a ts. fragment does not define a control-plane subject root.
        await Assert.That(ComposesSubjectFragment("var log = string.Concat(prefix, \"orchestrator-log\");")).IsFalse();
        // The orchestrator word alone, even with concatenation, is not a subject fragment.
        await Assert.That(ComposesSubjectFragment("var ns = \"TerraScale.Orchestrator\" + suffix;")).IsFalse();
    }

    /// <summary>Matches a full root literal anywhere in the line, ignoring case.</summary>
    private static bool ContainsRootLiteral(string line) =>
        line.Contains(ControlRootLiteral, StringComparison.OrdinalIgnoreCase) ||
        line.Contains(ProductRootLiteral, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Matches a line that composes a subject from parts: a <c>ts.</c> fragment and an
    /// <c>orch</c> or <c>product</c> fragment joined on the same line by concatenation,
    /// <c>string.Concat</c>, or <c>StringBuilder.Append</c>.
    /// </summary>
    private static bool ComposesSubjectFragment(string line) =>
        line.Contains(SubjectFragmentLiteral, StringComparison.OrdinalIgnoreCase) &&
        (line.Contains("orch", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("product", StringComparison.OrdinalIgnoreCase)) &&
        (line.Contains("string.concat", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("stringbuilder", StringComparison.OrdinalIgnoreCase) ||
            line.Contains(".append(", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("+ \"", StringComparison.Ordinal) ||
            line.Contains("\" +", StringComparison.Ordinal));

    private static string Truncate(string line)
    {
        var trimmed = line.Trim();
        return trimmed.Length <= 120 ? trimmed : trimmed[..120];
    }

    private static List<string> ProductionLinesContaining(string root, string literal) =>
        [.. ReadProductionSources(root)
            .SelectMany(source => source.Text.Split('\n')
                .Where(line => line.Contains(literal, StringComparison.Ordinal))
                .Select(line => $"{source.RelativePath}: {line.Trim()}"))];

    private static string RepresentativeSubject(string pattern) => pattern
        .Replace("{cell}", "gru", StringComparison.Ordinal)
        .Replace("{zone}", "untrusted-product", StringComparison.Ordinal)
        .Replace("{runner}", new string('b', NatsSubjectTaxonomy.AgentHashTokenLength), StringComparison.Ordinal)
        .Replace(">", "sample", StringComparison.Ordinal);

    /// <summary>
    /// Every production source under <c>src/</c> is scanned, so a private subject copy cannot
    /// hide in a sibling project.
    /// </summary>
    private static IEnumerable<(string RelativePath, string Text)> ReadProductionSources(string root)
    {
        var sourceRoot = Path.Combine(root, "src");
        foreach (var path in Directory.EnumerateFiles(sourceRoot, "*.cs", SearchOption.AllDirectories)
                     .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}") &&
                         !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
                     .Order(StringComparer.Ordinal))
        {
            yield return (
                Path.GetRelativePath(sourceRoot, path).Replace(Path.DirectorySeparatorChar, '/'),
                File.ReadAllText(path));
        }
    }

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null;
             directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "TerraScale.Orchestrator.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException(
            "The repository root was not found; the messaging-contract scan must run from the repository.");
    }
}
