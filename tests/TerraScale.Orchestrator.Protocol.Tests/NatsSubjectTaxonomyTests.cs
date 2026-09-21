using System.Reflection;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;
using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Protocol.Tests;

public sealed class NatsSubjectTaxonomyTests
{
    private const string Agent = "host/gru/agent-07";

    [Test]
    public async Task The_control_root_is_exactly_the_fresh_v2_protocol_root()
    {
        await Assert.That(NatsSubjectTaxonomy.Root).IsEqualTo("ts.orch.v2");
        await Assert.That(NatsSubjectTaxonomy.SupersededRoot).IsEqualTo("ts.orch.v1");
        await Assert.That(NatsSubjectTaxonomy.GlobalRoot).IsEqualTo("ts.orch.v2.global");
        await Assert.That(NatsSubjectTaxonomy.RegionalRoot("gru")).IsEqualTo("ts.orch.v2.gru");
        await Assert.That(NatsSubjectTaxonomy.RegionalRootForRegionCode("GRU")).IsEqualTo("ts.orch.v2.gru");
    }

    [Test]
    public async Task Canonical_definitions_match_the_landed_regional_topology()
    {
        var topology = new NatsTopology("gru", 3, "controller-1");

        await Assert.That(NatsSubjectTaxonomy.CellSpecSubject("gru")).IsEqualTo(topology.CellSpecSubject);
        await Assert.That(NatsSubjectTaxonomy.ControllerHealthSubject("gru")).IsEqualTo(topology.HealthSubject);
        await Assert.That(NatsSubjectTaxonomy.ControllerInstanceHealthSubject("gru", "controller-1"))
            .IsEqualTo(topology.InstanceHealthSubject);
        await Assert.That(NatsSubjectTaxonomy.ControllerStatusSubject("gru")).IsEqualTo(topology.StatusSubject);
        await Assert.That(NatsSubjectTaxonomy.ControllerMembersSubject("gru")).IsEqualTo(topology.MembersSubject);
        await Assert.That(NatsSubjectTaxonomy.ControllerStatsSubject("gru")).IsEqualTo(topology.StatsSubject);
        await Assert.That(NatsSubjectTaxonomy.ControllerOperatorStatusSubject("gru"))
            .IsEqualTo(topology.OperatorStatusSubject);
        await Assert.That(NatsSubjectTaxonomy.DirectDeliverySubject("gru")).IsEqualTo(topology.DirectDeliverySubject);

        // Every regional topology subject the taxonomy still shares a shape with stays under v2.
        foreach (var subject in new[]
                 {
                     topology.CellSpecSubject,
                     topology.HealthSubject,
                     topology.InstanceHealthSubject,
                     topology.StatusSubject,
                     topology.MembersSubject,
                     topology.StatsSubject,
                     topology.OperatorStatusSubject,
                     topology.DirectDeliverySubject,
                 })
        {
            await Assert.That(subject.StartsWith(NatsSubjectTaxonomy.Root + ".", StringComparison.Ordinal))
                .IsTrue()
                .Because($"the landed subject '{subject}' must follow the fresh v2 root");
        }
    }

    [Test]
    public async Task Canonical_definitions_match_the_landed_global_topology()
    {
        await Assert.That(NatsSubjectTaxonomy.GlobalDirectoryQuerySubject).IsEqualTo(GlobalNatsTopology.CellDirectorySubject);
        await Assert.That(NatsSubjectTaxonomy.GlobalCellSpecSubject("sfo"))
            .IsEqualTo(GlobalNatsTopology.CellSpecSubject("sfo"));
        var ciJob = NatsSubjectTaxonomy.CiJobSubjectPrefix + ".untrusted-product."
            + GlobalNatsTopology.CiRunnerIdentityHash("runner-1")[..24];
        await Assert.That(ciJob).StartsWith(NatsSubjectTaxonomy.CiJobSubjectPrefix);
        await Assert.That(NatsSubjectTaxonomy.Classify(ciJob)).IsEqualTo(NatsSubjectNamespace.ContinuousIntegration);
    }

    [Test]
    public async Task Canonical_definitions_match_the_landed_private_journal_protocol()
    {
        var subject = TerraScale.Orchestrator.ControlPlane.Runtime.RuntimeLifecycleNatsProtocol.Subject("gru", "read");
        await Assert.That(subject)
            .IsEqualTo(NatsSubjectTaxonomy.RuntimeLifecycleJournalSubject("gru", "read"));

        var reply = TerraScale.Orchestrator.ControlPlane.Runtime.RuntimeLifecycleNatsProtocol.ReplySubject(
            "gru", "UABC", new string('1', 32));
        await Assert.That(reply).IsEqualTo(
            NatsSubjectTaxonomy.RuntimeLifecycleJournalReplySubject("gru", "UABC", new string('1', 32)));
    }

    [Test]
    public async Task Rehomed_bridge_subjects_land_inside_the_closed_v2_families()
    {
        await Assert.That(NatsSubjectTaxonomy.OperationJournalCreateSubject("gru"))
            .IsEqualTo("ts.orch.v2.gru.command.journal.create");
        await Assert.That(NatsSubjectTaxonomy.OperationJournalUpdateSubject("gru"))
            .IsEqualTo("ts.orch.v2.gru.command.journal.update");
        await Assert.That(NatsSubjectTaxonomy.OperationJournalReplySubject("gru", "UABC", new string('a', 32)))
            .IsEqualTo("ts.orch.v2.gru.command.journal.reply.UABC." + new string('a', 32));
        await Assert.That(NatsSubjectTaxonomy.ControllerInboxPrefix("gru", "UABC"))
            .IsEqualTo("ts.orch.v2.gru.command.reply.UABC");
        await Assert.That(NatsSubjectTaxonomy.RuntimeStartupSubject("gru", "controller-1"))
            .IsEqualTo("ts.orch.v2.gru.observation.runtime.started.controller-1");
        await Assert.That(NatsSubjectTaxonomy.RuntimeLifecycleJournalSubject("gru", "read"))
            .IsEqualTo("ts.orch.v2.gru.command.runtime-lifecycle.read");

        foreach (var (subject, expected) in new[]
                 {
                     (NatsSubjectTaxonomy.OperationJournalCreateSubject("gru"), NatsSubjectNamespace.RegionalControl),
                     (NatsSubjectTaxonomy.RuntimeLifecycleJournalSubject("gru", "read"), NatsSubjectNamespace.RegionalControl),
                     (NatsSubjectTaxonomy.RuntimeStartupSubject("gru", "controller-1"), NatsSubjectNamespace.RegionalControl),
                     (NatsSubjectTaxonomy.ControllerInboxPrefix("gru", "UABC"), NatsSubjectNamespace.RegionalControl),
                 })
        {
            await Assert.That(NatsSubjectTaxonomy.Classify(subject)).IsEqualTo(expected);
            await Assert.That(NatsSubjectTaxonomy.TryAdmitSubject(subject, out var error) && error == NatsSubjectAdmissionError.None)
                .IsTrue()
                .Because($"the rehomed subject '{subject}' must be admissible");
        }
    }

    [Test]
    public async Task Host_agent_subjects_use_the_fixed_hash_of_the_admitted_identity()
    {
        var token = NatsSubjectTaxonomy.HostAgentSubjectToken(Agent);
        await Assert.That(token.Length).IsEqualTo(NatsSubjectTaxonomy.AgentHashTokenLength);
        await Assert.That(token.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f')).IsTrue();
        await Assert.That(NatsSubjectTaxonomy.HostAgentSubjectToken("host/gru/agent-08")).IsNotEqualTo(token);

        var root = NatsSubjectTaxonomy.HostAgentSubjectRoot("gru", Agent);
        await Assert.That(root).IsEqualTo("ts.orch.v2.gru.agent." + token);
        await Assert.That(root.Contains(Agent, StringComparison.Ordinal)).IsFalse();
        await Assert.That(NatsSubjectTaxonomy.HostAgentCommandSubject("gru", Agent, "start"))
            .IsEqualTo(root + ".command.start");
        await Assert.That(NatsSubjectTaxonomy.HostAgentObservationSubject("gru", Agent, "heartbeat"))
            .IsEqualTo(root + ".observation.heartbeat");
        await Assert.That(NatsSubjectTaxonomy.HostAgentAcknowledgementSubject("gru", Agent, "42"))
            .IsEqualTo(root + ".ack.42");
        await Assert.That(NatsSubjectTaxonomy.Classify(root)).IsEqualTo(NatsSubjectNamespace.Agent);
        await Assert.That(() => NatsSubjectTaxonomy.HostAgentIdentityHash("agent with space"))
            .Throws<ArgumentException>();
        await Assert.That(() => NatsSubjectTaxonomy.HostAgentIdentityHash(new string('a', 513)))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task Registered_region_codes_and_subject_tokens_are_bijective_and_exact()
    {
        foreach (var (code, token) in new[] { ("GRU", "gru"), ("SFO", "sfo"), ("FRA", "fra") })
        {
            await Assert.That(NatsSubjectTaxonomy.TryMapRegionCodeToSubjectToken(code, out var mapped)).IsTrue();
            await Assert.That(mapped).IsEqualTo(token);
            await Assert.That(NatsSubjectTaxonomy.TryMapSubjectTokenToRegionCode(token, out var roundTrip)).IsTrue();
            await Assert.That(roundTrip).IsEqualTo(code);
            await Assert.That(NatsSubjectTaxonomy.SubjectTokenForRegion(code)).IsEqualTo(token);
            await Assert.That(NatsSubjectTaxonomy.RegionCodeFromSubjectToken(token)).IsEqualTo(code);
        }

        foreach (var value in new string?[]
                 {
                     null, "", "gru", "Gru", " GRU", "GRU ", "GR", "GRUU", "IAD", "US1", "G-U", "G.U",
                     "GRÜ", "GLOBAL", "G\0U",
                 })
        {
            await Assert.That(NatsSubjectTaxonomy.TryMapRegionCodeToSubjectToken(value, out var refused)).IsFalse();
            await Assert.That(refused).IsEqualTo("");
        }

        foreach (var value in new string?[]
                 {
                     null, "", "GRU", "Gru", " gru", "gru ", "gr", "gruu", "iad", "us1", "g-u", "g.u",
                     "grü", "global", "g\0u",
                 })
        {
            await Assert.That(NatsSubjectTaxonomy.TryMapSubjectTokenToRegionCode(value, out var refused)).IsFalse();
            await Assert.That(refused).IsEqualTo("");
        }

        await Assert.That(() => NatsSubjectTaxonomy.SubjectTokenForRegion("IAD")).Throws<ArgumentException>();
        await Assert.That(() => NatsSubjectTaxonomy.RegionCodeFromSubjectToken("global")).Throws<ArgumentException>();
        await Assert.That(() => NatsSubjectTaxonomy.RegionalRootForRegionCode("US1")).Throws<ArgumentException>();

        // Raw subject-token APIs preserve established NATS identifiers. They do not admit RegionCode values.
        await Assert.That(NatsSubjectTaxonomy.RegionalRoot("us1")).IsEqualTo("ts.orch.v2.us1");
        await Assert.That(() => NatsSubjectTaxonomy.RegionalRoot("global")).Throws<ArgumentException>();
        await Assert.That(() => NatsSubjectTaxonomy.GlobalCellSpecSubject("global")).Throws<ArgumentException>();
    }

    [Test]
    public async Task Classification_separates_every_namespace_of_the_closed_taxonomy()
    {
        var cases = new[]
        {
            (NatsSubjectTaxonomy.GlobalCellSpecSubject("gru"), NatsSubjectNamespace.GlobalAuthority),
            (NatsSubjectTaxonomy.GlobalRoot + ".release.accepted.r7", NatsSubjectNamespace.GlobalAuthority),
            (NatsSubjectTaxonomy.GlobalRoot + ".query.health", NatsSubjectNamespace.GlobalAuthority),
            (NatsSubjectTaxonomy.GlobalDirectoryQuerySubject, NatsSubjectNamespace.GlobalDirectory),
            (NatsSubjectTaxonomy.CellSpecSubject("gru"), NatsSubjectNamespace.RegionalControl),
            (NatsSubjectTaxonomy.ControllerStatusSubject("sfo"), NatsSubjectNamespace.RegionalControl),
            (NatsSubjectTaxonomy.DirectDeliverySubject("fra"), NatsSubjectNamespace.RegionalControl),
            (NatsSubjectTaxonomy.RuntimeStartupSubject("gru", "controller-1"), NatsSubjectNamespace.RegionalControl),
            (NatsSubjectTaxonomy.RegionalRoot("gru") + ".observation.host.pressure", NatsSubjectNamespace.RegionalControl),
            (NatsSubjectTaxonomy.OperationJournalCreateSubject("gru"), NatsSubjectNamespace.RegionalControl),
            (NatsSubjectTaxonomy.RuntimeLifecycleJournalSubject("gru", "read"), NatsSubjectNamespace.RegionalControl),
            (NatsSubjectTaxonomy.RegionalRoot("gru") + ".operation.created", NatsSubjectNamespace.Operations),
            (NatsSubjectTaxonomy.CiForgejoTriggerSubject, NatsSubjectNamespace.ContinuousIntegration),
            (NatsSubjectTaxonomy.CiRuntimeProofSubject, NatsSubjectNamespace.ContinuousIntegration),
            (NatsSubjectTaxonomy.CiJobSubjectPrefix + ".trusted-build.abcd", NatsSubjectNamespace.ContinuousIntegration),
            (NatsSubjectTaxonomy.HostAgentSubjectRoot("gru", Agent), NatsSubjectNamespace.Agent),
            (NatsSubjectTaxonomy.RegionalRoot("gru") + ".audit.event.7", NatsSubjectNamespace.Audit),
            ("ts.product.v1.queue.default", NatsSubjectNamespace.ProductPlane),
            ("$JS.API.STREAM.INFO.CELL_SPEC", NatsSubjectNamespace.PlatformReserved),
            ("_INBOX.abcd.1234", NatsSubjectNamespace.PlatformReserved),
            ("$SRV.INFO.terrascale_orchestrator_gru", NatsSubjectNamespace.PlatformReserved),
        };

        foreach (var (subject, expected) in cases)
        {
            await Assert.That(NatsSubjectTaxonomy.Classify(subject)).IsEqualTo(expected);
        }
    }

    [Test]
    public async Task Classification_fails_closed_on_unknown_and_superseded_shapes()
    {
        string[] unknown =
        [
            "ts.orch.v1.gru.desired.gitops",
            "ts.orch.v1.global.query.cells",
            "ts.orch.v1.gru.unknown.channel",
            "ts.orch.v2.gru.unknown.channel",
            "ts.orch.v2.gru.event.runtime.started.controller-1",
            "ts.orch.v2.gru.internal.operation-journal.create",
            "ts.orch.v2.global.ci.forgejo",
            "ts.orch.v2.global.journal.ledger",
            "ts.orch.v2.global",
            "ts.other.v1.gru.query.health",
            "",
        ];

        foreach (var subject in unknown)
        {
            await Assert.That(NatsSubjectTaxonomy.Classify(subject))
                .IsEqualTo(NatsSubjectNamespace.Unknown)
                .Because($"the subject '{subject}' must not classify into the v2 taxonomy");
        }

        await Assert.That(NatsSubjectTaxonomy.Classify(null)).IsEqualTo(NatsSubjectNamespace.Unknown);
    }

    [Test]
    public async Task Product_plane_and_unknown_namespaces_are_not_control_namespaces()
    {
        await Assert.That(NatsSubjectTaxonomy.IsControlNamespace(NatsSubjectNamespace.ProductPlane)).IsFalse();
        await Assert.That(NatsSubjectTaxonomy.IsControlNamespace(NatsSubjectNamespace.Unknown)).IsFalse();
        await Assert.That(NatsSubjectTaxonomy.IsControlNamespace(NatsSubjectNamespace.PlatformReserved)).IsFalse();
        foreach (var ns in new[]
                 {
                     NatsSubjectNamespace.GlobalAuthority,
                     NatsSubjectNamespace.GlobalDirectory,
                     NatsSubjectNamespace.RegionalControl,
                     NatsSubjectNamespace.Agent,
                     NatsSubjectNamespace.ContinuousIntegration,
                     NatsSubjectNamespace.Operations,
                     NatsSubjectNamespace.Audit,
                 })
        {
            await Assert.That(NatsSubjectTaxonomy.IsControlNamespace(ns)).IsTrue();
        }
    }

    [Test]
    public async Task Subject_builders_fail_closed_on_invalid_input()
    {
        await Assert.That(() => NatsSubjectTaxonomy.RegionalRoot("GRU")).Throws<ArgumentException>();
        await Assert.That(() => NatsSubjectTaxonomy.RegionalRoot("-gru-")).Throws<ArgumentException>();
        await Assert.That(() => NatsSubjectTaxonomy.GlobalCellSpecSubject("gru cell")).Throws<ArgumentException>();
        await Assert.That(() => NatsSubjectTaxonomy.RuntimeLifecycleJournalSubject("gru", "bad operation"))
            .Throws<ArgumentException>();
        await Assert.That(() => NatsSubjectTaxonomy.RuntimeLifecycleJournalReplySubject("gru", "id", "not-a-nonce"))
            .Throws<ArgumentException>();
        await Assert.That(() => NatsSubjectTaxonomy.ControllerInboxPrefix("gru", "")).Throws<ArgumentException>();
    }

    [Test]
    public async Task No_wildcard_permission_may_cross_a_region_boundary()
    {
        var rejected = new[]
        {
            ("ts.orch.v2.*.desired.>", NatsSubjectPermissionError.WildcardInScopeToken),
            ("ts.orch.v2.*.query.>", NatsSubjectPermissionError.WildcardInScopeToken),
            ("ts.orch.v2.>", NatsSubjectPermissionError.WildcardInScopeToken),
            ("ts.orch.v2.*.agent.>", NatsSubjectPermissionError.WildcardInScopeToken),
            ("ts.orch.v2.gru.>", NatsSubjectPermissionError.WildcardInFamilyToken),
            ("ts.orch.v2.gru.*.>", NatsSubjectPermissionError.WildcardInFamilyToken),
            ("ts.orch.v2.global.>", NatsSubjectPermissionError.WildcardInFamilyToken),
            ("ts.orch.v2.gru.event.>", NatsSubjectPermissionError.UnknownFamily),
            ("ts.orch.v2.gru.internal.>", NatsSubjectPermissionError.UnknownFamily),
            ("ts.orch.v2.global.ci.>", NatsSubjectPermissionError.UnknownFamily),
            ("ts.orch.v2.GRU.desired.>", NatsSubjectPermissionError.InvalidRegionToken),
            ("ts.orch.v2.gru.agent.*.>", NatsSubjectPermissionError.InvalidAgentHashToken),
            ("ts.orch.v2.gru.agent.*.*.>", NatsSubjectPermissionError.InvalidAgentHashToken),
            ("ts.orch.v2.gru.agent.*.unknown.>", NatsSubjectPermissionError.InvalidAgentHashToken),
            ("ts.orch.v2.gru.agent.>", NatsSubjectPermissionError.InvalidAgentHashToken),
            ("ts.orch.v2.gru.agent.not-a-fixed-hash.command.>", NatsSubjectPermissionError.InvalidAgentHashToken),
            ("ts.orch.v1.gru.desired.>", NatsSubjectPermissionError.SupersededRoot),
            ("ts.orch.>", NatsSubjectPermissionError.OutsideControlRoot),
            ("$SYS.>", NatsSubjectPermissionError.PlatformReserved),
            ("ts.product.v1.>", NatsSubjectPermissionError.OutsideControlRoot),
        };

        foreach (var (pattern, expected) in rejected)
        {
            await Assert.That(NatsSubjectTaxonomy.TryValidatePermissionPattern(pattern, out var error))
                .IsFalse()
                .Because($"the permission pattern '{pattern}' must be rejected");
            await Assert.That(error).IsEqualTo(expected);
        }

        foreach (var pattern in new[]
                 {
                     "ts.orch.v2.gru.desired.>",
                     "ts.orch.v2.gru.command.>",
                     "ts.orch.v2.gru.observation.>",
                     "ts.orch.v2.gru.operation.>",
                     "ts.orch.v2.gru.query.>",
                     "ts.orch.v2.gru.audit.>",
                     "ts.orch.v2.gru.agent.*.command.>",
                     "ts.orch.v2.gru.agent.*.observation.>",
                     "ts.orch.v2.gru.agent.*.ack.>",
                     "ts.orch.v2.gru.agent." + NatsSubjectTaxonomy.HostAgentSubjectToken(Agent) + ".command.>",
                     "ts.orch.v2.global.desired.>",
                     "ts.orch.v2.global.release.ci.job.>",
                     "ts.orch.v2.global.query.cells",
                 })
        {
            await Assert.That(NatsSubjectTaxonomy.TryValidatePermissionPattern(pattern, out var error) && error == NatsSubjectPermissionError.None)
                .IsTrue()
                .Because($"the closed permission pattern '{pattern}' must be accepted");
        }

        // A pinned regional permission never matches another Region's subjects.
        SubjectPermissionPattern.TryParse(
            NatsSubjectTaxonomy.RegionalFamilyPattern("gru", NatsSubjectTaxonomy.DesiredFamilySegment),
            NatsSubjectTaxonomy.GrammarLimits,
            out var pinned,
            out _);
        await Assert.That(pinned!.Matches(Concrete("ts.orch.v2.sfo.desired.gitops"))).IsFalse();
        await Assert.That(pinned.Matches(Concrete(NatsSubjectTaxonomy.CellSpecSubject("gru")))).IsTrue();
    }

    private static ConcreteSubject Concrete(string value)
    {
        ConcreteSubject.TryParse(value, NatsSubjectTaxonomy.GrammarLimits, out var subject, out _);
        return subject!;
    }

    [Test]
    public async Task Customer_provided_text_never_becomes_a_subject_token()
    {
        var admitted = new[]
        {
            NatsSubjectTaxonomy.CellSpecSubject("gru"),
            NatsSubjectTaxonomy.GlobalDirectoryQuerySubject,
            NatsSubjectTaxonomy.HostAgentCommandSubject("gru", Agent, "start"),
            NatsSubjectTaxonomy.RuntimeStartupSubject("gru", "controller-1"),
        };
        foreach (var subject in admitted)
        {
            await Assert.That(NatsSubjectTaxonomy.TryAdmitSubject(subject, out var error) && error == NatsSubjectAdmissionError.None)
                .IsTrue()
                .Because($"the closed subject '{subject}' must be admissible");
        }

        var rejected = new[]
        {
            ("ts.orch.v2.gru.desired.café", NatsSubjectAdmissionError.CustomerTextInSubject),
            ("ts.orch.v2.gru.query.user@example.com", NatsSubjectAdmissionError.CustomerTextInSubject),
            ("ts.orch.v2.gru.query.héllo", NatsSubjectAdmissionError.CustomerTextInSubject),
            ("ts.orch.v2.gru. query.health", NatsSubjectAdmissionError.MalformedSubject),
            ("ts.orch.v2.gru.agent.enroll", NatsSubjectAdmissionError.InvalidAgentHashToken),
            ("ts.orch.v1.gru.desired.gitops", NatsSubjectAdmissionError.SupersededRoot),
            ("ts.product.v1.queue.default", NatsSubjectAdmissionError.OutsideControlRoot),
            ("$JS.API.STREAM.INFO", NatsSubjectAdmissionError.PlatformReserved),
            ("ts.orch.v2.gru.unknown.channel", NatsSubjectAdmissionError.UnknownNamespace),
        };

        foreach (var (subject, expected) in rejected)
        {
            await Assert.That(NatsSubjectTaxonomy.TryAdmitSubject(subject, out var error))
                .IsFalse()
                .Because($"the subject '{subject}' must not be admissible");
            await Assert.That(error).IsEqualTo(expected);
        }
    }

    [Test]
    public async Task No_v1_prefixed_subject_appears_in_any_v2_taxonomy_surface()
    {
        var constants = typeof(NatsSubjectTaxonomy)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(static field => field.IsLiteral && field.FieldType == typeof(string))
            .Select(static field => (Name: field.Name, Value: (string)field.GetRawConstantValue()!))
            .ToArray();

        await Assert.That(constants.Length).IsGreaterThanOrEqualTo(8);
        await Assert.That(constants.Single(static field => field.Name == nameof(NatsSubjectTaxonomy.Root)).Value)
            .IsEqualTo("ts.orch.v2");
        foreach (var constant in constants.Where(static field =>
                     field.Name != nameof(NatsSubjectTaxonomy.SupersededRoot) &&
                     field.Name != nameof(NatsSubjectTaxonomy.RegionPlaceholderToken) &&
                     field.Name != nameof(NatsSubjectTaxonomy.AgentHashPlaceholderToken)))
        {
            await Assert.That(constant.Value.StartsWith(NatsSubjectTaxonomy.SupersededRoot + ".", StringComparison.Ordinal))
                .IsFalse()
                .Because($"the constant {constant.Name}='{constant.Value}' must not live under the superseded v1 root");
        }

        var composed = new[]
        {
            NatsSubjectTaxonomy.GlobalDirectoryQuerySubject,
            NatsSubjectTaxonomy.GlobalCellSpecSubject("sfo"),
            NatsSubjectTaxonomy.CiForgejoTriggerSubject,
            NatsSubjectTaxonomy.CiRuntimeProofSubject,
            NatsSubjectTaxonomy.CiJobSubjectPrefix,
            NatsSubjectTaxonomy.CellSpecSubject("gru"),
            NatsSubjectTaxonomy.DirectDeliverySubject("gru"),
            NatsSubjectTaxonomy.OperationJournalCreateSubject("gru"),
            NatsSubjectTaxonomy.RuntimeStartupSubject("gru", "controller-1"),
            NatsSubjectTaxonomy.HostAgentSubjectRoot("gru", Agent),
            NatsSubjectTaxonomy.RegionalFamilyPattern("fra", NatsSubjectTaxonomy.RegionalAuditPrefixSegment),
            NatsSubjectTaxonomy.GlobalFamilyPattern(NatsSubjectTaxonomy.ReleaseFamilySegment),
        };
        foreach (var subject in composed)
        {
            await Assert.That(subject.StartsWith(NatsSubjectTaxonomy.Root + ".", StringComparison.Ordinal)).IsTrue();
            await Assert.That(NatsSubjectTaxonomy.Classify(subject)).IsNotEqualTo(NatsSubjectNamespace.Unknown);
        }

        foreach (var prefix in new[] { NatsSubjectTaxonomy.GlobalRoot, NatsSubjectTaxonomy.RegionalRoot("gru") })
        {
            await Assert.That(prefix.StartsWith(NatsSubjectTaxonomy.Root + ".", StringComparison.Ordinal)).IsTrue();
            await Assert.That(prefix.StartsWith(NatsSubjectTaxonomy.SupersededRoot + ".", StringComparison.Ordinal))
                .IsFalse();
        }

        foreach (var family in NatsSubjectTaxonomy.Families)
        {
            await Assert.That(family.Pattern.StartsWith(NatsSubjectTaxonomy.SupersededRoot + ".", StringComparison.Ordinal))
                .IsFalse();
        }

        foreach (var grants in ProtocolManifest.Loaded.AccountKinds)
        {
            foreach (var pattern in grants.Publish.Concat(grants.Subscribe))
            {
                await Assert.That(pattern.StartsWith(NatsSubjectTaxonomy.SupersededRoot + ".", StringComparison.Ordinal))
                    .IsFalse()
                    .Because($"the account kind '{grants.Kind}' must not hold v1 permissions");
            }
        }
    }
}
