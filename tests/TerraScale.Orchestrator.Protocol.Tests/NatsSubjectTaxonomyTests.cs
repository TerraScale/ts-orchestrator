using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Protocol.Tests;

public sealed class NatsSubjectTaxonomyTests
{
    [Test]
    public async Task Canonical_definitions_match_the_landed_regional_topology()
    {
        var topology = new NatsTopology("gru", 3, "controller-1");

        await Assert.That(NatsSubjectTaxonomy.RegionalRoot("gru")).IsEqualTo("ts.orch.v1.gru");
        await Assert.That(NatsSubjectTaxonomy.CellSpecSubject("gru")).IsEqualTo(topology.CellSpecSubject);
        await Assert.That(NatsSubjectTaxonomy.ControllerHealthSubject("gru")).IsEqualTo(topology.HealthSubject);
        await Assert.That(NatsSubjectTaxonomy.ControllerInstanceHealthSubject("gru", "controller-1"))
            .IsEqualTo(topology.InstanceHealthSubject);
        await Assert.That(NatsSubjectTaxonomy.ControllerStatusSubject("gru")).IsEqualTo(topology.StatusSubject);
        await Assert.That(NatsSubjectTaxonomy.ControllerMembersSubject("gru")).IsEqualTo(topology.MembersSubject);
        await Assert.That(NatsSubjectTaxonomy.DirectDeliverySubject("gru")).IsEqualTo(topology.DirectDeliverySubject);
        await Assert.That(NatsSubjectTaxonomy.OperationJournalCreateSubject("gru"))
            .IsEqualTo(topology.OperationJournalCreateSubject);
        await Assert.That(NatsSubjectTaxonomy.OperationJournalUpdateSubject("gru"))
            .IsEqualTo(topology.OperationJournalUpdateSubject);
        await Assert.That(NatsSubjectTaxonomy.OperationJournalReplySubject("gru", "UABC", new string('a', 32)))
            .IsEqualTo(topology.OperationJournalReplySubject("UABC", new string('a', 32)));
        await Assert.That(NatsSubjectTaxonomy.RuntimeStartupSubject("gru", "controller-1"))
            .IsEqualTo(topology.StartupSubject);
    }

    [Test]
    public async Task Canonical_definitions_match_the_landed_global_topology()
    {
        await Assert.That(NatsSubjectTaxonomy.GlobalRoot).IsEqualTo("ts.orch.v1.global");
        await Assert.That(NatsSubjectTaxonomy.GlobalDirectoryQuerySubject).IsEqualTo(GlobalNatsTopology.CellDirectorySubject);
        await Assert.That(NatsSubjectTaxonomy.CiForgejoTriggerSubject).IsEqualTo(GlobalNatsTopology.CiSubject);
        await Assert.That(NatsSubjectTaxonomy.CiRuntimeProofSubject).IsEqualTo(GlobalNatsTopology.CiRuntimeProofSubject);
        await Assert.That(NatsSubjectTaxonomy.CiJobSubjectPrefix).IsEqualTo(GlobalNatsTopology.CiJobSubjectPrefix);
        await Assert.That(NatsSubjectTaxonomy.GlobalCellSpecSubject("sfo"))
            .IsEqualTo(GlobalNatsTopology.CellSpecSubject("sfo"));
        await Assert.That(NatsSubjectTaxonomy.CiJobSubjectPrefix + ".untrusted-product."
                + GlobalNatsTopology.CiRunnerIdentityHash("runner-1")[..24])
            .IsEqualTo(GlobalNatsTopology.CiJobSubject("untrusted-product", "runner-1"));
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
    public async Task Classification_separates_every_namespace_of_the_closed_taxonomy()
    {
        var cases = new[]
        {
            (NatsSubjectTaxonomy.GlobalCellSpecSubject("gru"), NatsSubjectNamespace.GlobalAuthority),
            (NatsSubjectTaxonomy.GlobalRoot + ".journal.ledger", NatsSubjectNamespace.GlobalAuthority),
            (NatsSubjectTaxonomy.GlobalDirectoryQuerySubject, NatsSubjectNamespace.GlobalDirectory),
            (NatsSubjectTaxonomy.CellSpecSubject("gru"), NatsSubjectNamespace.RegionalControl),
            (NatsSubjectTaxonomy.ControllerStatusSubject("sfo"), NatsSubjectNamespace.RegionalControl),
            (NatsSubjectTaxonomy.DirectDeliverySubject("fra"), NatsSubjectNamespace.RegionalControl),
            (NatsSubjectTaxonomy.RuntimeStartupSubject("gru", "controller-1"), NatsSubjectNamespace.RegionalControl),
            (NatsSubjectTaxonomy.OperationJournalCreateSubject("gru"), NatsSubjectNamespace.Operations),
            (NatsSubjectTaxonomy.RuntimeLifecycleJournalSubject("gru", "read"), NatsSubjectNamespace.Operations),
            (NatsSubjectTaxonomy.RegionalRoot("gru") + ".operation.created", NatsSubjectNamespace.Operations),
            (NatsSubjectTaxonomy.CiForgejoTriggerSubject, NatsSubjectNamespace.ContinuousIntegration),
            (NatsSubjectTaxonomy.CiRuntimeProofSubject, NatsSubjectNamespace.ContinuousIntegration),
            (NatsSubjectTaxonomy.CiJobSubjectPrefix + ".trusted-build.abcd", NatsSubjectNamespace.ContinuousIntegration),
            (NatsSubjectTaxonomy.RegionalRoot("gru") + ".agent.enroll", NatsSubjectNamespace.Agent),
            (NatsSubjectTaxonomy.RegionalRoot("gru") + ".audit.event", NatsSubjectNamespace.Audit),
            (NatsSubjectTaxonomy.GlobalRoot + ".audit.event", NatsSubjectNamespace.Audit),
            ("ts.product.v1.queue.default", NatsSubjectNamespace.ProductPlane),
            ("$JS.API.STREAM.INFO.CELL_SPEC", NatsSubjectNamespace.PlatformReserved),
            ("_INBOX.abcd.1234", NatsSubjectNamespace.PlatformReserved),
            ("$SRV.INFO.terrascale_orchestrator_gru", NatsSubjectNamespace.PlatformReserved),
        };

        foreach (var (subject, expected) in cases)
        {
            await Assert.That(NatsSubjectTaxonomy.Classify(subject)).IsEqualTo(expected);
        }

        await Assert.That(NatsSubjectTaxonomy.Classify("ts.orch.v1.gru.unknown.channel"))
            .IsEqualTo(NatsSubjectNamespace.Unknown);
        await Assert.That(NatsSubjectTaxonomy.Classify("ts.other.v1.gru.query.health"))
            .IsEqualTo(NatsSubjectNamespace.Unknown);
        await Assert.That(NatsSubjectTaxonomy.Classify("")).IsEqualTo(NatsSubjectNamespace.Unknown);
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
}
