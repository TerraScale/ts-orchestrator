using TerraScale.Orchestrator.Protocol;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Protocol.Tests;

public sealed class ProtocolManifestTests
{
    /// <summary>The exact closed family set of the GOAL subject model; the manifest may not add or drop one.</summary>
    private static readonly string[] GoalFamilies =
    [
        "ts.orch.v2.global.desired.>",
        "ts.orch.v2.global.release.>",
        "ts.orch.v2.global.query.>",
        "ts.orch.v2.<region>.desired.>",
        "ts.orch.v2.<region>.command.>",
        "ts.orch.v2.<region>.observation.>",
        "ts.orch.v2.<region>.operation.>",
        "ts.orch.v2.<region>.query.>",
        "ts.orch.v2.<region>.audit.>",
        "ts.orch.v2.<region>.agent.<agent-hash>.>",
    ];

    [Test]
    public async Task The_manifest_pins_exactly_the_fresh_v2_root()
    {
        var manifest = ProtocolManifest.Loaded;

        await Assert.That(manifest.Root).IsEqualTo("ts.orch.v2");
        await Assert.That(manifest.Root).IsEqualTo(NatsSubjectTaxonomy.Root);
        await Assert.That(manifest.Version).IsEqualTo("v2");
        await Assert.That(manifest.ReservedRegionTokens).IsEquivalentTo(["global"]);
    }

    [Test]
    public async Task The_taxonomy_and_the_manifest_agree_in_both_directions()
    {
        await Assert.That(NatsSubjectTaxonomy.ManifestValidationViolations()).IsEmpty();
        await Assert.That(NatsSubjectTaxonomy.Families.Count).IsEqualTo(10);

        var manifestPatterns = ProtocolManifest.Loaded.SubjectFamilies
            .Select(static family => family.Pattern)
            .ToArray();
        foreach (var pattern in manifestPatterns)
        {
            await Assert.That(GoalFamilies).Contains(pattern);
        }

        foreach (var pattern in GoalFamilies)
        {
            await Assert.That(manifestPatterns).Contains(pattern);
        }
    }

    [Test]
    public async Task Every_goal_family_is_present_and_the_set_is_closed()
    {
        var families = NatsSubjectTaxonomy.Families;
        await Assert.That(families.Select(static family => family.Pattern)).IsEquivalentTo(GoalFamilies);

        var globalFamilies = families.Where(static family => family.Scope == ProtocolSubjectFamilyScope.Global)
            .Select(static family => family.Family)
            .ToArray();
        await Assert.That(globalFamilies).IsEquivalentTo(["desired", "release", "query"]);

        var regionalFamilies = families.Where(static family => family.Scope == ProtocolSubjectFamilyScope.Regional)
            .Select(static family => family.Family)
            .ToArray();
        await Assert.That(regionalFamilies)
            .IsEquivalentTo(["desired", "command", "observation", "operation", "query", "audit", "agent"]);

        foreach (var family in families.Where(static family => family.Scope == ProtocolSubjectFamilyScope.Regional))
        {
            await Assert.That(family.Pattern.StartsWith("ts.orch.v2.<region>.", StringComparison.Ordinal))
                .IsTrue()
                .Because($"the regional family '{family.Family}' must carry the region placeholder");
        }
    }

    [Test]
    public async Task Every_materialized_manifest_family_is_a_closed_v2_permission()
    {
        var agentHash = NatsSubjectTaxonomy.HostAgentSubjectToken("host/gru/agent-07");
        foreach (var family in NatsSubjectTaxonomy.Families)
        {
            var pattern = family.Pattern
                .Replace(NatsSubjectTaxonomy.RegionPlaceholderToken, "gru", StringComparison.Ordinal)
                .Replace(NatsSubjectTaxonomy.AgentHashPlaceholderToken, agentHash, StringComparison.Ordinal);

            await Assert.That(NatsSubjectTaxonomy.TryValidatePermissionPattern(pattern, out var error) &&
                    error == NatsSubjectPermissionError.None)
                .IsTrue()
                .Because($"the materialized family pattern '{pattern}' must be a closed v2 permission");
        }
    }

    [Test]
    public async Task No_manifest_surface_shares_the_superseded_v1_root()
    {
        var manifest = ProtocolManifest.Loaded;

        foreach (var family in manifest.SubjectFamilies)
        {
            await Assert.That(family.Pattern.StartsWith(NatsSubjectTaxonomy.SupersededRoot + ".", StringComparison.Ordinal))
                .IsFalse();
            await Assert.That(family.Pattern.StartsWith(NatsSubjectTaxonomy.Root + ".", StringComparison.Ordinal))
                .IsTrue();
        }

        foreach (var grants in manifest.AccountKinds)
        {
            foreach (var pattern in grants.Publish.Concat(grants.Subscribe))
            {
                await Assert.That(pattern.StartsWith(NatsSubjectTaxonomy.SupersededRoot + ".", StringComparison.Ordinal))
                    .IsFalse()
                    .Because($"the account kind '{grants.Kind}' must not hold a v1 permission");
            }
        }
    }
}

