using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class GlobalNatsAccessContractTests
{
    [Test]
    public async Task DirectoryPublisherAndServiceUseTheGlobalDirectoryAccount()
    {
        var publisher = GlobalNatsAccessContract.Create(
            "sfo",
            GlobalNatsCapability.CellDirectoryPublisher);
        var service = GlobalNatsAccessContract.Create(
            "gru",
            GlobalNatsCapability.CellDirectoryService);

        await Assert.That(publisher.Account.Kind)
            .IsEqualTo(GlobalNatsAccountKind.GlobalDirectory);
        await Assert.That(service.Account.Kind)
            .IsEqualTo(GlobalNatsAccountKind.GlobalDirectory);
        await Assert.That(publisher.Account.Name)
            .IsEqualTo(service.Account.Name);
    }

    [Test]
    public async Task RegionalReaderUsesItsCellAccountAndImportsOnlyTheDirectoryService()
    {
        var access = GlobalNatsAccessContract.Create(
            "iad",
            GlobalNatsCapability.CellDirectoryReader);

        await Assert.That(access.Account.Kind)
            .IsEqualTo(GlobalNatsAccountKind.RegionalControl);
        await Assert.That(access.Account.Name)
            .IsEqualTo("ts-orch-regional-control-iad");
        await Assert.That(access.Imports.Select(static item => item.Subject))
            .IsEquivalentTo([GlobalNatsTopology.CellDirectorySubject]);
        await Assert.That(access.Imports.Single().SourceAccount)
            .IsEqualTo(GlobalNatsAccountNames.GlobalDirectory);
    }

    [Test]
    public async Task DirectoryAccountExportsExactlyTheReadOnlyQueryService()
    {
        var access = GlobalNatsAccessContract.Create(
            "gru",
            GlobalNatsCapability.CellDirectoryService);

        await Assert.That(access.Exports.Select(static item => item.Subject))
            .IsEquivalentTo([GlobalNatsTopology.CellDirectorySubject]);
        await Assert.That(access.Imports).IsEmpty();
        await Assert.That(access.Exports.Single().Subject)
            .IsEqualTo(NatsSubjectTaxonomy.GlobalDirectoryQuerySubject);
    }

    [Test]
    public async Task OnlyGruMaySelectTheGlobalAuthorityCapability()
    {
        var gru = GlobalNatsAccessContract.Create(
            "gru",
            GlobalNatsCapability.GlobalAuthority);

        await Assert.That(gru.Account.Kind)
            .IsEqualTo(GlobalNatsAccountKind.GlobalAuthority);
        await Assert.That(gru.Account.Name)
            .IsEqualTo(GlobalNatsAccountNames.GlobalAuthority);
        await Assert.That(() => GlobalNatsAccessContract.Create(
                "sfo",
                GlobalNatsCapability.GlobalAuthority))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task OnlyGruMaySelectTheGlobalDirectoryServiceCapability()
    {
        await Assert.That(() => GlobalNatsAccessContract.Create(
                "sfo",
                GlobalNatsCapability.CellDirectoryService))
            .Throws<ArgumentException>();
        await Assert.That(() => GlobalNatsAccessContract.Create(
                "fra",
                GlobalNatsRole.CellDirectoryService))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task CellAccountNamesRemainDynamicAndInvalidCellsFailBeforeAccessIsBuilt()
    {
        foreach (var cell in new[] { "fra", "iad", "region-17" })
        {
            var access = GlobalNatsAccessContract.Create(
                cell,
                GlobalNatsCapability.CellDirectoryReader);

            await Assert.That(access.Account.Name)
                .IsEqualTo($"ts-orch-regional-control-{cell}");
        }

        foreach (var cell in new[] { "", "SFO", "sfo.us", "-sfo", "sfo-" })
        {
            await Assert.That(() => GlobalNatsAccessContract.Create(
                    cell,
                    GlobalNatsCapability.CellDirectoryReader))
                .Throws<ArgumentException>();
        }
    }

    [Test]
    public async Task CrossAccountImportsAndExportsContainNoGlobalStateOrMutationSubjects()
    {
        var plans = new[]
        {
            GlobalNatsAccessContract.Create("gru", GlobalNatsCapability.CellDirectoryService),
            GlobalNatsAccessContract.Create("sfo", GlobalNatsCapability.CellDirectoryReader),
            GlobalNatsAccessContract.Create("sfo", GlobalNatsCapability.CellDirectoryPublisher),
        };
        var subjects = plans
            .SelectMany(static plan => plan.Imports.Select(static item => item.Subject)
                .Concat(plan.Exports.Select(static item => item.Subject)))
            .ToArray();
        var forbiddenFragments = new[]
        {
            "$KV", "GLOBAL_SPEC", "GLOBAL_RELEASES", "GLOBAL_CI", "CI_",
            "$O.", "OBJ_", "LEADER", "$JS.API.STREAM", "$JS.API.CONSUMER",
            ".>", ">"
        };

        foreach (var subject in subjects)
        foreach (var fragment in forbiddenFragments)
            await Assert.That(subject).DoesNotContain(fragment);
    }

    [Test]
    public async Task LegacyGlobalNatsAuthorityAliasIsAllowedOnlyForGru()
    {
        await Assert.That(GlobalNatsConfiguration.IsLegacyAuthorityAliasAllowed("gru"))
            .IsTrue();
        await Assert.That(GlobalNatsConfiguration.IsLegacyAuthorityAliasAllowed("sfo"))
            .IsFalse();
        await Assert.That(GlobalNatsConfiguration.IsLegacyAuthorityAliasAllowed("SFO"))
            .IsFalse();
        await Assert.That(() => GlobalNatsConfiguration.ValidateLegacyAuthorityAlias("fra"))
            .Throws<ArgumentException>();
        await Assert.That(() => GlobalNatsConfiguration.Resolve(
                "tls://global.internal:4222",
                null,
                null,
                null,
                null,
                3,
                "sfo"))
            .Throws<ArgumentException>();
        await Assert.That(GlobalNatsConfiguration.Resolve(
                null,
                null,
                null,
                null,
                null,
                3,
                "sfo"))
            .IsNull();
    }
}
