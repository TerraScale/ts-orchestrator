using TerraScale.Orchestrator.Protocol.Messaging;
using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Protocol.Tests;

public sealed class NatsControlAccountModelTests
{
    private static readonly string[] Regions = ["gru", "sfo", "fra"];

    private const string GruAgent = "host/gru/agent-07";

    [Test]
    public async Task The_account_model_is_complete_against_the_manifest()
    {
        await Assert.That(NatsControlAccountModel.IsComplete).IsTrue();
        await Assert.That(NatsControlAccountModel.CompletenessViolations()).IsEmpty();
    }

    [Test]
    public async Task The_closed_account_kinds_are_exactly_the_goal_kinds_in_both_directions()
    {
        await Assert.That(NatsControlAccountModel.Kinds).IsEquivalentTo(
        [
            NatsControlAccountKind.InfrastructureAdministration,
            NatsControlAccountKind.GlobalAuthority,
            NatsControlAccountKind.GlobalDirectoryReadService,
            NatsControlAccountKind.RegionalController,
            NatsControlAccountKind.HostAgent,
            NatsControlAccountKind.CiCoordinator,
            NatsControlAccountKind.CiIsolatedRunner,
            NatsControlAccountKind.ReadOnlyMonitoring,
            NatsControlAccountKind.BreakGlassRecovery,
        ]);

        var manifestKinds = ProtocolManifest.Loaded.AccountKinds
            .Select(static grants => grants.Kind)
            .ToArray();
        await Assert.That(manifestKinds).IsEquivalentTo(
        [
            "infrastructure-administration",
            "global-authority",
            "global-directory-read-service",
            "regional-controller",
            "host-agent",
            "ci-coordinator",
            "ci-isolated-runner",
            "read-only-monitoring",
            "break-glass-recovery",
        ]);
    }

    [Test]
    public async Task Every_standing_grant_is_a_closed_permission_of_its_own_surface()
    {
        foreach (var scope in AllScopes())
        {
            foreach (var pattern in scope.Publish.Concat(scope.Subscribe))
            {
                if (scope.Kind == NatsControlAccountKind.InfrastructureAdministration)
                {
                    await Assert.That(pattern.StartsWith("$", StringComparison.Ordinal))
                        .IsTrue()
                        .Because("the infrastructure kind only ever touches platform-reserved surface");
                }
                else
                {
                    await Assert.That(
                            NatsSubjectTaxonomy.TryValidatePermissionPattern(pattern, out var error) &&
                            error == NatsSubjectPermissionError.None)
                        .IsTrue()
                        .Because($"the account kind '{scope.Kind}' must only hold closed v2 permissions");
                }
            }
        }
    }

    [Test]
    public async Task Write_authority_over_the_closed_subject_corpus_is_disjoint_across_kinds()
    {
        foreach (var subject in ControlSubjectCorpus())
        {
            var publisherKinds = AllScopes()
                .Where(scope => scope.Publish.Any(pattern => Matches(pattern, subject)))
                .Select(static scope => scope.Kind)
                .Distinct()
                .ToArray();

            await Assert.That(publisherKinds.Length).IsEqualTo(1)
                .Because(
                    $"exactly one account kind may publish '{subject}', but {publisherKinds.Length} do " +
                    $"({string.Join(", ", publisherKinds.Select(static kind => kind.ToString()))})");
        }
    }

    [Test]
    public async Task Read_only_and_break_glass_kinds_hold_no_write_grants()
    {
        foreach (var scope in AllScopes().Where(static scope => scope.Kind
                     is NatsControlAccountKind.GlobalDirectoryReadService
                     or NatsControlAccountKind.ReadOnlyMonitoring
                     or NatsControlAccountKind.BreakGlassRecovery))
        {
            await Assert.That(scope.Publish).IsEmpty();
        }

        var breakGlass = NatsControlAccountScope.Create(NatsControlAccountKind.BreakGlassRecovery);
        await Assert.That(breakGlass.Publish).IsEmpty();
        await Assert.That(breakGlass.Subscribe).IsEmpty();
    }

    [Test]
    public async Task Regional_scopes_are_pinned_to_exactly_one_region()
    {
        var gru = NatsControlAccountScope.Create(NatsControlAccountKind.RegionalController, "gru", "host/gru/agent-07");
        var sfo = NatsControlAccountScope.Create(NatsControlAccountKind.RegionalController, "sfo", "host/sfo/agent-07");

        foreach (var pattern in gru.Publish.Concat(gru.Subscribe))
        {
            var pinned = pattern.StartsWith("ts.orch.v2.gru.", StringComparison.Ordinal) ||
                pattern.StartsWith("ts.orch.v2.global.", StringComparison.Ordinal);
            await Assert.That(pinned)
                .IsTrue()
                .Because($"the GRU controller scope must stay pinned to GRU or the global scope: '{pattern}'");
        }

        foreach (var subject in ControlSubjectCorpus().Where(static subject =>
                     subject.StartsWith("ts.orch.v2.sfo.", StringComparison.Ordinal)))
        {
            await Assert.That(gru.Publish.Any(pattern => Matches(pattern, subject))).IsFalse()
                .Because($"the GRU controller must not be able to write the SFO subject '{subject}'");
        }

        await Assert.That(sfo.Publish.Any(pattern => Matches(pattern, "ts.orch.v2.sfo.desired.gitops"))).IsTrue();
    }

    [Test]
    public async Task Host_agent_scopes_use_the_fixed_agent_hash_never_the_raw_identity()
    {
        var agent = NatsControlAccountScope.Create(NatsControlAccountKind.HostAgent, "gru", GruAgent);
        var token = NatsSubjectTaxonomy.HostAgentSubjectToken(GruAgent);

        await Assert.That(agent.AgentHash).IsEqualTo(token);
        await Assert.That(agent.RegionToken).IsEqualTo("gru");
        foreach (var pattern in agent.Publish.Concat(agent.Subscribe))
        {
            await Assert.That(pattern.Contains(token, StringComparison.Ordinal)).IsTrue();
            await Assert.That(pattern.Contains(GruAgent, StringComparison.Ordinal)).IsFalse();
        }

        await Assert.That(agent.Publish).IsEquivalentTo(
        [
            "ts.orch.v2.gru.agent." + token + ".observation.>",
            "ts.orch.v2.gru.agent." + token + ".ack.>",
        ]);
        await Assert.That(agent.Subscribe).IsEquivalentTo(
        [
            "ts.orch.v2.gru.agent." + token + ".command.>",
        ]);

        // The regional controller commands the agent; the agent answers on its own hashed branch.
        var controller = NatsControlAccountScope.Create(
            NatsControlAccountKind.RegionalController, "gru", GruAgent);
        await Assert.That(controller.Publish).Contains(
            "ts.orch.v2.gru.agent." + token + ".command.>");
        await Assert.That(controller.Subscribe).Contains(
            "ts.orch.v2.gru.agent." + token + ".observation.>");
    }

    [Test]
    public async Task Scope_creation_fails_closed_on_mismatched_scope_inputs()
    {
        await Assert.That(() => NatsControlAccountScope.Create(NatsControlAccountKind.RegionalController))
            .Throws<ArgumentException>();
        await Assert.That(() => NatsControlAccountScope.Create(NatsControlAccountKind.RegionalController, "GRU"))
            .Throws<ArgumentException>();
        await Assert.That(() => NatsControlAccountScope.Create(NatsControlAccountKind.RegionalController, "global"))
            .Throws<ArgumentException>();
        await Assert.That(() => NatsControlAccountScope.Create(NatsControlAccountKind.HostAgent, "gru"))
            .Throws<ArgumentException>();
        await Assert.That(() => NatsControlAccountScope.Create(NatsControlAccountKind.GlobalAuthority, "gru"))
            .Throws<ArgumentException>();
        await Assert.That(() => NatsControlAccountScope.Create(
                NatsControlAccountKind.InfrastructureAdministration, agentIdentity: "host/gru/agent-07"))
            .Throws<ArgumentException>();
        await Assert.That(() => NatsControlAccountScope.Create(NatsControlAccountKind.Unspecified))
            .Throws<ArgumentOutOfRangeException>();
    }

    private static IEnumerable<NatsControlAccountScope> AllScopes()
    {
        yield return NatsControlAccountScope.Create(NatsControlAccountKind.InfrastructureAdministration);
        yield return NatsControlAccountScope.Create(NatsControlAccountKind.GlobalAuthority);
        yield return NatsControlAccountScope.Create(NatsControlAccountKind.GlobalDirectoryReadService);
        yield return NatsControlAccountScope.Create(NatsControlAccountKind.CiCoordinator);
        yield return NatsControlAccountScope.Create(NatsControlAccountKind.CiIsolatedRunner);
        yield return NatsControlAccountScope.Create(NatsControlAccountKind.BreakGlassRecovery);
        foreach (var region in Regions)
        {
            yield return NatsControlAccountScope.Create(
                NatsControlAccountKind.RegionalController, region, "host/" + region + "/agent-07");
            yield return NatsControlAccountScope.Create(
                NatsControlAccountKind.HostAgent, region, "host/" + region + "/agent-07");
            yield return NatsControlAccountScope.Create(NatsControlAccountKind.ReadOnlyMonitoring, region);
        }
    }

    private static IEnumerable<string> ControlSubjectCorpus()
    {
        foreach (var region in Regions)
        {
            yield return "ts.orch.v2." + region + ".desired.gitops";
            yield return "ts.orch.v2." + region + ".command.delivery";
            yield return "ts.orch.v2." + region + ".operation.journal.create";
            yield return "ts.orch.v2." + region + ".query.health";
            yield return "ts.orch.v2." + region + ".audit.event.7";
            yield return "ts.orch.v2." + region + ".observation.runtime.started.controller-1";

            var token = NatsSubjectTaxonomy.HostAgentSubjectToken("host/" + region + "/agent-07");
            yield return "ts.orch.v2." + region + ".agent." + token + ".command.start";
            yield return "ts.orch.v2." + region + ".agent." + token + ".observation.heartbeat";
            yield return "ts.orch.v2." + region + ".agent." + token + ".ack.42";
        }

        yield return "ts.orch.v2.global.desired.gitops.gru";
        yield return "ts.orch.v2.global.release.accepted.r7";
        yield return "ts.orch.v2.global.release.ci.forgejo";
        yield return "ts.orch.v2.global.release.ci.job.zone-1." +
            NatsSubjectTaxonomy.HostAgentSubjectToken("runner-7")[..NatsSubjectTaxonomy.AgentHashTokenLength];
        yield return "ts.orch.v2.global.release.ci.runtime-proof.build-9";
        yield return "ts.orch.v2.global.query.cells";
        yield return "$SYS.REQ.SERVER.PING";
    }

    private static bool Matches(string pattern, string subject)
    {
        if (!ConcreteSubject.TryParse(subject, NatsSubjectTaxonomy.GrammarLimits, out var concrete, out _) ||
            concrete is null)
        {
            throw new InvalidOperationException($"The corpus subject '{subject}' is not bounded grammar.");
        }

        return SubjectPermissionPattern.TryParse(pattern, NatsSubjectTaxonomy.GrammarLimits, out var compiled, out _) &&
            compiled is not null &&
            compiled.Matches(concrete);
    }
}
