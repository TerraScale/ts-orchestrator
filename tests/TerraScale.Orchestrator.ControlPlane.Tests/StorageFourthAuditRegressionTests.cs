using TerraScale.Orchestrator.ControlPlane.Storage;
using System.Reflection;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class StorageFourthAuditRegressionTests
{
    [Test]
    public async Task Accepted_create_output_distinguishes_every_omitted_create_and_mount_field()
    {
        var key = StorageTestData.Key("key-a");
        var placement = StorageTestData.Placement("ad-a/fd-a");
        var baseline = Create(key, placement, StorageDomain.TerraBase, StorageMountPurpose.DatabaseData);
        var variants = new[]
        {
            Create(StorageTestData.Key("key-b"), placement, StorageDomain.TerraBase, StorageMountPurpose.DatabaseData),
            Create(key, StorageTestData.Placement("ad-b/fd-b"), StorageDomain.TerraBase, StorageMountPurpose.DatabaseData),
            Create(key, placement, StorageDomain.ProductJetStream, StorageMountPurpose.DatabaseData),
            Create(key, placement, StorageDomain.TerraBase, StorageMountPurpose.MessagingStore),
        };

        await Assert.That(baseline.Action).IsEqualTo(StorageAction.Create);
        await Assert.That(ReferenceEquals(baseline.Scope!.EncryptionKey, key)).IsTrue();
        await Assert.That(ReferenceEquals(baseline.Scope.Placement, placement)).IsTrue();
        await Assert.That(baseline.Scope.Domain).IsEqualTo(StorageDomain.TerraBase);
        await Assert.That(baseline.Scope.MountPurpose).IsEqualTo(StorageMountPurpose.DatabaseData);
        foreach (var variant in variants)
        {
            await Assert.That(variant.Action).IsEqualTo(StorageAction.Create);
            await Assert.That(variant).IsNotEqualTo(baseline);
        }
    }

    [Test]
    public async Task Complete_storage_subject_remains_opaque_and_construction_closed()
    {
        var decision = Create(StorageTestData.Key("secret-key"), StorageTestData.Placement("secret-placement"),
            StorageDomain.TerraBase, StorageMountPurpose.DatabaseData);
        var protectedTypes = new[] { typeof(StorageDecision), typeof(StorageNumericTrace), typeof(StorageIntentScope) };
        var exportedMethods = typeof(StorageDecision).Assembly.GetExportedTypes()
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Static |
                BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .ToArray();
        var decisionRoutes = exportedMethods
            .Where(method => !method.IsSpecialName && method.ReturnType == typeof(StorageDecision))
            .Select(method => $"{method.DeclaringType!.Name}.{method.Name}")
            .Order(StringComparer.Ordinal)
            .ToArray();
        var projectedRoutes = exportedMethods
            .Where(method => method.ReturnType == typeof(StorageNumericTrace) || method.ReturnType == typeof(StorageIntentScope))
            .Select(method => $"{method.DeclaringType!.Name}.{method.Name}")
            .Order(StringComparer.Ordinal)
            .ToArray();

        foreach (var type in protectedTypes)
        {
            await Assert.That(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
            await Assert.That(type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Any(property => property.SetMethod?.IsPublic == true)).IsFalse();
            await Assert.That(type.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .Any(method => method.Name == "Deconstruct")).IsFalse();
        }
        await Assert.That(decisionRoutes).IsEquivalentTo(new[]
        {
            "StorageAttachmentPlanner.Plan", "StorageCreatePlanner.Plan", "StorageDeletionPlanner.Plan",
            "StorageExpansionPlanner.Plan", "StorageFormatPlanner.Plan",
        });
        await Assert.That(projectedRoutes).IsEquivalentTo(new[]
        {
            "StorageDecision.get_Scope", "StorageDecision.get_Trace", "StorageIntentScope.<Clone>$",
            "StorageNumericTrace.<Clone>$", "StorageNumericTrace.get_Scope",
        });
        foreach (var value in new object[] { decision.Trace!, decision.Scope! })
        {
            var cloneMethod = value.GetType().GetMethods(BindingFlags.Public | BindingFlags.Instance |
                BindingFlags.DeclaredOnly).Single(method => method.Name == "<Clone>$");
            var clone = cloneMethod.Invoke(value, null)!;
            await Assert.That(clone).IsEqualTo(value);
            await Assert.That(ReferenceEquals(clone, value)).IsFalse();
        }
        await Assert.That(decision.ToString()).DoesNotContain("secret-key");
        await Assert.That(decision.ToString()).DoesNotContain("secret-placement");
        await Assert.That(decision.Scope!.ToString()).IsEqualTo("<storage-intent-scope>");
    }

    private static StorageDecision Create(EncryptionKeyReference key, StoragePlacementId placement,
        StorageDomain domain, StorageMountPurpose mountPurpose)
    {
        var volume = new StorageVolumeRecord(StorageTestData.Claim(), StorageTestData.Provider(), StorageTestData.Attachment(),
            StorageTestData.Cell(), StorageTestData.Node(), StorageTestData.Workload(), StorageTestData.Member(),
            domain, key, placement, StorageTestData.Device(), StorageTestData.Filesystem(),
            StorageFilesystemType.Xfs, StorageLayout.Lvm, mountPurpose,
            StorageTestData.B(100), StorageTestData.B(200), StorageTestData.B(100), StorageTestData.B(100),
            StorageTestData.B(100), StorageTestData.B(60), StorageTestData.B(40),
            new(StoragePerformanceTier.Balanced, StorageTestData.B(10), StorageTestData.B(1_000),
                StorageTestData.B(200), StorageTestData.B(5), StorageTestData.B(900), StorageTestData.B(180),
                StorageTestData.B(10)), StorageTestData.B(3_600), StorageRetention.ElasticQuarantine,
            StorageTestData.Backup(), StorageTestData.Generation(), StorageTestData.Fence(), StorageTestData.Epoch(),
            StorageTestData.Operation());
        return StorageCreatePlanner.Plan(volume, StorageTestData.Context(),
            StorageCreateCheckpoint.CapacityAndBudgetChecked, StorageTestData.Format(scope: volume.EvidenceScope));
    }
}
