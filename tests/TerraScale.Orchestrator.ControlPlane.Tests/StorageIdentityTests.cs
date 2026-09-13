using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Storage;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class StorageIdentityTests
{
    [Test]
    public async Task Identities_are_bounded_scalar_valid_and_quantities_checked()
    {
        foreach (var invalid in new string?[] { null, "", "two words", "nul\0x", "\uD800", "\uDC00" })
            await Assert.That(VolumeClaimId.TryCreate(invalid, 64, out _)).IsFalse();
        await Assert.That(ProviderVolumeId.TryCreate("ab", 1, out _)).IsFalse();
        await Assert.That(StorageAttachmentId.TryCreate("attachment", 10, out _)).IsTrue();
        await Assert.That(StorageNodeId.TryCreate("node", 4, out _)).IsTrue();
        await Assert.That(StorageWorkloadId.TryCreate("workload", 8, out _)).IsTrue();
        await Assert.That(StorageMemberId.TryCreate("member", 6, out _)).IsTrue();
        await Assert.That(FilesystemId.TryCreate("fs", 2, out _)).IsTrue();
        await Assert.That(StorageOperationId.TryCreate("op", 2, out _)).IsTrue();
        await Assert.That(StorageBackupId.TryCreate("backup", 6, out _)).IsTrue();
        await Assert.That(StorageFenceId.TryCreate("fence", 5, out _)).IsTrue();
        await Assert.That(StorageBytes.TryCreate(-1, out _)).IsFalse();
        await Assert.That(StorageBytes.TryCreate(long.MaxValue, out var max)).IsTrue();
        await Assert.That(max.Value).IsEqualTo(long.MaxValue);
        await Assert.That(StorageGeneration.TryCreate(0, out _)).IsFalse();
        await Assert.That(StorageWriterEpoch.TryCreate(0, out _)).IsFalse();
    }

    [Test]
    public async Task Volume_record_binds_complete_identity_and_redacts_secret_references()
    {
        var volume = StorageTestData.Volume();
        await Assert.That(volume.Claim).IsEqualTo(StorageTestData.Claim());
        await Assert.That(volume.ProviderVolume).IsEqualTo(StorageTestData.Provider());
        await Assert.That(volume.Domain).IsEqualTo(StorageDomain.TerraBase);
        await Assert.That(volume.FilesystemType).IsEqualTo(StorageFilesystemType.Xfs);
        await Assert.That(volume.Layout).IsEqualTo(StorageLayout.Lvm);
        await Assert.That(volume.ToString()).DoesNotContain("filesystem-secret");
        await Assert.That(volume.ToString()).DoesNotContain("key-secret");
    }

    [Test]
    public async Task Default_decision_never_authorizes_mutation()
    {
        var decision = default(StorageDecision);
        await Assert.That(decision.IsMutationAuthorized).IsFalse();
        await Assert.That(decision.Action).IsEqualTo(StorageAction.Uninitialized);
    }

    [Test]
    public async Task Numeric_trace_is_culture_invariant_and_secret_safe()
    {
        var decision = StorageExpansionPlanner.Plan(StorageTestData.Volume(), StorageTestData.Context(), StorageTestData.Expansion());
        var original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
            var arabic = decision.ToString();
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("fr-FR");
            var french = decision.ToString();
            await Assert.That(arabic).IsEqualTo(french);
            await Assert.That(arabic).DoesNotContain("filesystem-secret");
            await Assert.That(arabic).DoesNotContain("key-secret");
            await Assert.That(arabic).DoesNotContain("provider-volume-a");
        }
        finally { CultureInfo.CurrentCulture = original; }
    }
}

