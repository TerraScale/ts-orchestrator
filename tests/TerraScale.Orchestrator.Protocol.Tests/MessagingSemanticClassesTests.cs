using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Protocol.Tests;

public sealed class MessagingSemanticClassesTests
{
    [Test]
    public async Task Every_landed_subject_maps_to_exactly_one_declared_semantic_class()
    {
        var topology = new NatsTopology("gru", 3, "controller-1");
        var cases = new (string Subject, MessagingSemanticClass Expected)[]
        {
            (topology.CellSpecSubject, MessagingSemanticClass.AuthoritativeJournal),
            (topology.HealthSubject, MessagingSemanticClass.Lossy),
            (topology.InstanceHealthSubject, MessagingSemanticClass.Lossy),
            (topology.StatusSubject, MessagingSemanticClass.Lossy),
            (topology.MembersSubject, MessagingSemanticClass.Lossy),
            (topology.DirectDeliverySubject, MessagingSemanticClass.Lossy),
            (NatsSubjectTaxonomy.OperationJournalCreateSubject("gru"), MessagingSemanticClass.Lossy),
            (NatsSubjectTaxonomy.OperationJournalUpdateSubject("gru"), MessagingSemanticClass.Lossy),
            (NatsSubjectTaxonomy.OperationJournalReplySubject("gru", "UABC", new string('a', 32)),
                MessagingSemanticClass.Lossy),
            (NatsSubjectTaxonomy.RuntimeLifecycleJournalReplySubject("gru", "UABC", new string('b', 32)),
                MessagingSemanticClass.Lossy),
            (NatsSubjectTaxonomy.RuntimeStartupSubject("gru", "controller-1"),
                MessagingSemanticClass.Replayable),
            (GlobalNatsTopology.CellDirectorySubject, MessagingSemanticClass.Lossy),
            (NatsSubjectTaxonomy.CiForgejoTriggerSubject, MessagingSemanticClass.WorkQueue),
            (NatsSubjectTaxonomy.CiRuntimeProofSubject, MessagingSemanticClass.Replayable),
            (NatsSubjectTaxonomy.CiJobSubjectPrefix + ".trusted-build."
                + GlobalNatsTopology.CiRunnerIdentityHash("runner-7")[..24], MessagingSemanticClass.WorkQueue),
            (GlobalNatsTopology.CellSpecSubject("sfo"), MessagingSemanticClass.AuthoritativeJournal),
            (TerraScale.Orchestrator.ControlPlane.Runtime.RuntimeLifecycleNatsProtocol.Subject("gru", "read"),
                MessagingSemanticClass.Lossy),
        };

        foreach (var (subject, expected) in cases)
        {
            var classified = MessagingSemanticClasses.TryClassifySubject(subject, out var semanticClass, out _);
            await Assert.That(classified).IsTrue().Because($"the subject '{subject}' must be classified");
            await Assert.That(semanticClass).IsEqualTo(expected);
        }
    }

    [Test]
    public async Task Unknown_and_foreign_subjects_fail_closed_instead_of_guessing_a_class()
    {
        await Assert.That(MessagingSemanticClasses.TryClassifySubject(
            "ts.orch.v1.gru.unknown.channel.x", out _, out _)).IsFalse();
        await Assert.That(MessagingSemanticClasses.TryClassifySubject(
            "ts.orch.v1.gru.desired.gitops", out _, out _)).IsFalse();
        await Assert.That(MessagingSemanticClasses.TryClassifySubject(
            "ts.orch.v2.gru.unknown.channel", out _, out _)).IsFalse();
        await Assert.That(MessagingSemanticClasses.TryClassifySubject("ts.product.v1.queue", out _, out _)).IsFalse();
        await Assert.That(MessagingSemanticClasses.TryClassifySubject("$JS.API.STREAM.INFO", out _, out _)).IsFalse();
        await Assert.That(MessagingSemanticClasses.TryClassifySubject(null, out _, out _)).IsFalse();
    }

    [Test]
    public async Task Reserved_namespaces_carry_their_intended_semantic_class()
    {
        await Assert.That(MessagingSemanticClasses.TryClassifySubject(
            NatsSubjectTaxonomy.HostAgentCommandSubject("gru", "host/gru/agent-07", "start"), out var agent, out _))
            .IsTrue();
        await Assert.That(agent).IsEqualTo(MessagingSemanticClass.WorkQueue);

        await Assert.That(MessagingSemanticClasses.TryClassifySubject(
            NatsSubjectTaxonomy.RegionalRoot("gru") + ".audit.entry", out var audit, out _)).IsTrue();
        await Assert.That(audit).IsEqualTo(MessagingSemanticClass.AuthoritativeJournal);
    }

    [Test]
    public async Task Every_landed_store_is_classified_by_the_declarative_store_table()
    {
        var topology = new NatsTopology("gru", 3);
        var global = new GlobalNatsTopology(3);
        var landedStores = new[]
        {
            topology.Leaders.Bucket!,
            topology.Runtime.Bucket!,
            topology.Delivery.Bucket!,
            topology.Operations.Bucket!,
            topology.OperationProofConsumptions.Bucket!,
            topology.Bundles.Bucket!,
            topology.ProtocolPackage.Bucket!,
            global.Leaders.Bucket!,
            global.Cells.Bucket!,
            global.Releases.Bucket!,
            global.RunnerJobs.Bucket!,
            global.Bundles.Bucket!,
            global.RunnerBundles.Bucket!,
        };

        var classified = MessagingSemanticClasses.StoreRules.Select(static rule => rule.StoreIdentity).ToHashSet(StringComparer.Ordinal);
        foreach (var store in landedStores)
        {
            await Assert.That(classified.Contains(store)).IsTrue()
                .Because($"the landed store '{store}' must have a declared semantic class");
        }
    }

    [Test]
    public async Task Authoritative_journal_stores_are_never_classified_as_lossy_or_snapshot()
    {
        foreach (var rule in MessagingSemanticClasses.StoreRules.Where(
                     static rule => rule.SemanticClass == MessagingSemanticClass.AuthoritativeJournal))
        {
            await Assert.That(rule.LossMeaning).DoesNotContain("rebuild from hints");
        }

        var operations = MessagingSemanticClasses.StoreRules.Single(
            static rule => rule.StoreIdentity == "ORCH_OPERATIONS");
        await Assert.That(operations.SemanticClass).IsEqualTo(MessagingSemanticClass.AuthoritativeJournal);
    }

    [Test]
    public async Task Subject_patterns_compile_and_agree_with_the_namespace_taxonomy()
    {
        foreach (var rule in MessagingSemanticClasses.SubjectRules)
        {
            await Assert.That(rule.Compiled).IsNotNull();

            // An exact-subject rule must classify to its own declared namespace; wildcard rules
            // are exercised by the landed-subject mapping test above.
            if (!rule.SubjectPattern.Contains('*', StringComparison.Ordinal) &&
                !rule.SubjectPattern.EndsWith('>'))
            {
                await Assert.That(NatsSubjectTaxonomy.Classify(rule.SubjectPattern)).IsEqualTo(rule.Namespace);
            }
        }
    }
}

