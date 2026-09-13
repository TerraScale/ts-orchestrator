using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Protocol.Tests;

public sealed class NatsCapabilityMatrixTests
{
    /// <summary>The exact dispositions frozen by the contract; a change is an owner decision, not a refactor.</summary>
    private static readonly (NatsCapability Capability, NatsCapabilityDisposition Disposition)[] ExpectedDispositions =
    [
        (NatsCapability.CorePubSub, NatsCapabilityDisposition.Accept),
        (NatsCapability.RequestReply, NatsCapabilityDisposition.Accept),
        (NatsCapability.ServicesAndDiscovery, NatsCapabilityDisposition.Accept),
        (NatsCapability.QueueGroups, NatsCapabilityDisposition.Accept),
        (NatsCapability.Headers, NatsCapabilityDisposition.Accept),
        (NatsCapability.MessageIds, NatsCapabilityDisposition.Accept),
        (NatsCapability.JetStreamStreams, NatsCapabilityDisposition.Accept),
        (NatsCapability.DurableConsumers, NatsCapabilityDisposition.Accept),
        (NatsCapability.Acknowledgement, NatsCapabilityDisposition.Accept),
        (NatsCapability.RedeliveryAndBackoff, NatsCapabilityDisposition.Accept),
        (NatsCapability.FlowControl, NatsCapabilityDisposition.Accept),
        (NatsCapability.KeyValueCasAndWatch, NatsCapabilityDisposition.Accept),
        (NatsCapability.ObjectStore, NatsCapabilityDisposition.Accept),
        (NatsCapability.Accounts, NatsCapabilityDisposition.Accept),
        (NatsCapability.Jwts, NatsCapabilityDisposition.Defer),
        (NatsCapability.NKeys, NatsCapabilityDisposition.Accept),
        (NatsCapability.Mtls, NatsCapabilityDisposition.Accept),
        (NatsCapability.ImportsAndExports, NatsCapabilityDisposition.Accept),
        (NatsCapability.Gateways, NatsCapabilityDisposition.Accept),
        (NatsCapability.Advisories, NatsCapabilityDisposition.Accept),
        (NatsCapability.SystemMonitoring, NatsCapabilityDisposition.Accept),
        (NatsCapability.Snapshots, NatsCapabilityDisposition.Accept),
        (NatsCapability.RollingCompatibility, NatsCapabilityDisposition.Accept),
    ];

    [Test]
    public async Task Matrix_is_complete_and_every_entry_is_well_formed()
    {
        await Assert.That(NatsCapabilityMatrix.IsComplete).IsTrue();
        await Assert.That(string.Join("; ", NatsCapabilityMatrix.CompletenessViolations())).IsEmpty();
        await Assert.That(NatsCapabilityMatrix.Entries.Count).IsEqualTo(23);
    }

    [Test]
    public async Task Every_capability_named_by_the_contract_has_the_frozen_disposition()
    {
        foreach (var (capability, disposition) in ExpectedDispositions)
        {
            var entry = NatsCapabilityMatrix.Find(capability);
            await Assert.That(entry).IsNotNull();
            await Assert.That(entry!.Disposition).IsEqualTo(disposition);
        }
    }

    [Test]
    public async Task Accepted_entries_carry_owner_data_class_durability_ordering_boundary_failure_and_observability()
    {
        foreach (var entry in NatsCapabilityMatrix.Entries.Where(
                     static entry => entry.Disposition == NatsCapabilityDisposition.Accept))
        {
            await Assert.That(entry.Owner).IsNotEqualTo(NatsCapabilityOwner.Unspecified);
            await Assert.That(entry.DataClass).IsNotEqualTo(NatsDataClass.Unspecified);
            await Assert.That(entry.Durability).IsNotEqualTo(NatsDurabilityClass.Unspecified);
            await Assert.That(entry.Ordering).IsNotEqualTo(NatsOrderingClass.Unspecified);
            await Assert.That(entry.SecurityBoundary.Trim()).IsNotEmpty();
            await Assert.That(entry.FailureMode.Trim()).IsNotEmpty();
            await Assert.That(entry.ObservabilityRequirement.Trim()).IsNotEmpty();
            await Assert.That(entry.LandedEvidence!.Trim()).IsNotEmpty();
        }
    }

    [Test]
    public async Task Deferred_and_rejected_entries_record_a_trigger_or_rationale_and_no_attributes()
    {
        foreach (var entry in NatsCapabilityMatrix.Entries.Where(
                     static entry => entry.Disposition != NatsCapabilityDisposition.Accept))
        {
            await Assert.That(entry.RevisitTriggerOrRejectionRationale!.Trim()).IsNotEmpty();
            await Assert.That(entry.Owner).IsNotEqualTo(NatsCapabilityOwner.Unspecified);
            await Assert.That(entry.DataClass).IsEqualTo(NatsDataClass.Unspecified);
        }
    }

    [Test]
    public async Task Every_owner_is_one_of_the_known_responsibility_roles()
    {
        var owners = NatsCapabilityMatrix.Entries.Select(static entry => entry.Owner).Distinct().ToArray();
        foreach (var owner in owners)
        {
            await Assert.That(Enum.IsDefined(owner)).IsTrue();
        }

        await Assert.That(owners.Length).IsGreaterThan(1);
    }

    [Test]
    public async Task Canonical_contract_document_dispositions_every_capability_identically()
    {
        var document = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "docs", "contracts", "nats-capability-matrix.md"));
        foreach (var (capability, disposition) in ExpectedDispositions)
        {
            var row = $"| `{capability}` | {disposition.ToString().ToUpperInvariant()} |";
            await Assert.That(document.Contains(row, StringComparison.Ordinal))
                .IsTrue()
                .Because($"the canonical document must carry the row '{row}'");
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
            "The repository root was not found; the capability-matrix drift test must run from the repository.");
    }
}

