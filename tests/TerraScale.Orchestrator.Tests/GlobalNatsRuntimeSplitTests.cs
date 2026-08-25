using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class GlobalNatsRuntimeSplitTests
{
    [Test]
    public async Task DirectoryConfigurationSelectsOnlyTheGlobalCellsCapability()
    {
        var configuration = new GlobalDirectoryNatsConfiguration(
            "tls://global.internal:4222",
            "directory.nk",
            new("ca.pem", "directory-cert.pem", "directory-key.pem"),
            "sfo");

        await Assert.That(configuration.AccessPlan.Account.Kind)
            .IsEqualTo(GlobalNatsAccountKind.GlobalDirectory);
        await Assert.That(typeof(GlobalDirectoryNatsConfiguration)
                .GetProperty("DirectoryStore", System.Reflection.BindingFlags.Instance |
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Public))
            .IsNull();
        await Assert.That(typeof(GlobalDirectoryNatsConfiguration)
                .GetProperty("AuthorityStore", System.Reflection.BindingFlags.Instance |
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Public))
            .IsNull();
        await Assert.That(configuration.AccessPlan.Publish)
            .DoesNotContain("$KV.GLOBAL_RELEASES.>");
        await Assert.That(configuration.AccessPlan.Publish)
            .DoesNotContain("$JS.API.STREAM");
    }

    [Test]
    public async Task AuthorityConfigurationCannotBeCreatedForANonGruCell()
    {
        await Assert.That(() => new GlobalAuthorityNatsConfiguration(
                "tls://global.internal:4222",
                "authority.nk",
                new("ca.pem", "authority-cert.pem", "authority-key.pem"),
                3,
                "sfo"))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task DirectoryServiceConfigurationCannotBeCreatedForANonGruCell()
    {
        await Assert.That(() => new GlobalDirectoryServiceNatsConfiguration(
                "tls://global.internal:4222",
                "service.nk",
                new("ca.pem", "service-cert.pem", "service-key.pem"),
                3,
                "sfo"))
            .Throws<ArgumentException>();
        await Assert.That(() => GlobalDirectoryServiceNatsConfiguration.Resolve(
                null,
                null,
                null,
                null,
                null,
                3,
                "fra"))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task AuthorityRuntimeConstructionHasNoDirectoryConfigurationOverload()
    {
        var authorityStartMethods = typeof(GlobalNatsRuntime)
            .GetMethods(System.Reflection.BindingFlags.Static |
                System.Reflection.BindingFlags.Public |
                System.Reflection.BindingFlags.NonPublic)
            .Where(static method => method.Name == "StartAsync");

        foreach (var method in authorityStartMethods)
        foreach (var parameter in method.GetParameters())
            await Assert.That(parameter.ParameterType)
                .IsNotEqualTo(typeof(GlobalDirectoryNatsConfiguration));
    }

    [Test]
    public async Task DirectoryStoreSeamAcceptsOnlyAnExistingBucketLookup()
    {
        var method = typeof(GlobalCellDirectoryRuntime).GetMethod(
            "OpenExistingStoreAsync",
            System.Reflection.BindingFlags.Static |
                System.Reflection.BindingFlags.NonPublic);

        await Assert.That(method).IsNotNull();
        await Assert.That(method!.GetParameters().Select(static parameter => parameter.ParameterType))
            .IsEquivalentTo([
                typeof(NATS.Client.KeyValueStore.INatsKVContext),
                typeof(CancellationToken)]);
        await Assert.That(method.ReturnType)
            .IsEqualTo(typeof(Task<NATS.Client.KeyValueStore.INatsKVStore>));
    }

    [Test]
    public async Task DirectoryRuntimeExposesHealthAlongsideSnapshotAndCompletion()
    {
        await Assert.That(typeof(GlobalCellDirectoryRuntime)
                .GetProperty("Health", System.Reflection.BindingFlags.Instance |
                    System.Reflection.BindingFlags.NonPublic))
            .IsNotNull();
        await Assert.That(typeof(GlobalCellDirectoryRuntime)
                .GetProperty("Snapshot", System.Reflection.BindingFlags.Instance |
                    System.Reflection.BindingFlags.NonPublic))
            .IsNotNull();
        await Assert.That(typeof(GlobalCellDirectoryRuntime)
                .GetProperty("Completion", System.Reflection.BindingFlags.Instance |
                    System.Reflection.BindingFlags.NonPublic))
            .IsNotNull();
    }
}
