using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Guards the hand-built advertisement shape the mesh-health tests rely on: a
/// well-formed regional advertisement with a healthy membership projection is
/// accepted by the global directory contract, so a mesh state of missing can only
/// ever come from a genuinely absent advertisement, never from an invalid one.
/// </summary>
public sealed class GlobalCellDirectoryContractTests
{
    [Test]
    public async Task A_well_formed_advertisement_is_accepted_into_the_directory()
    {
        var now = DateTimeOffset.UtcNow;
        var membership = new RegionalRuntimeMembershipHealth(
            1, 1, 0, 0, 0, 0, 0, 1, true, 0, RegionalRuntimeMembershipCondition.Healthy, now);
        membership.Validate();
        var advertisement = new GlobalCellAdvertisement(
            1,
            "gru",
            "orchestrator-control-gru",
            "gru-regional",
            12,
            34,
            1,
            ["authority", "regional-membership", "service-discovery"],
            membership,
            now,
            now + GlobalCellAdvertisement.SemanticLease,
            ["https://gru.terrascale.invalid:18670"]);

        await Assert.That(advertisement.IsValid(now)).IsTrue();
        var directory = new GlobalCellDirectory();
        await Assert.That(directory.Apply(advertisement, now))
            .IsEqualTo(GlobalCellAdvertisementDisposition.Accepted);
    }
}
