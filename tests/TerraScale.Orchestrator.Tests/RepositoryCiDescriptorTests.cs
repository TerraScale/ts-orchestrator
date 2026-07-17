using System.Text;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiDescriptorTests
{
    [Test]
    public async Task V2PolicyCompilesIntoAClosedDeterministicDag()
    {
        var descriptor = Parse(ValidDescriptor());

        await Assert.That(descriptor.ApiVersion).IsEqualTo(RepositoryCiDescriptor.ApiVersion);
        await Assert.That(descriptor.Repository).IsEqualTo("TerraScale/TerraScale.Internals");
        await Assert.That(descriptor.CandidateRetentionDays).IsEqualTo(7);
        await Assert.That(descriptor.Promotion).IsEqualTo(RepositoryCiPromotionStrategy.NativeBlueGreen);
        await Assert.That(descriptor.Digest.Length).IsEqualTo(64);
        await Assert.That(string.Join(',', descriptor.RepositoryDependencies.Select(static value => value.Repository)))
            .IsEqualTo("TerraScale/TerraBase,TerraScale/TerraScale.TypeScript");
        await Assert.That(string.Join(',', descriptor.Nodes.Select(static value => value.Id)))
            .IsEqualTo("static,build,release-tests,candidate");
        await Assert.That(descriptor.Nodes.Single(static value => value.Id == "static").Paths)
            .IsEquivalentTo(["src/", "tests/"]);
        await Assert.That(descriptor.Nodes.Single(static value => value.Id == "candidate").Architectures)
            .IsEquivalentTo([RepositoryCiArchitecture.LinuxX64, RepositoryCiArchitecture.LinuxArm64]);
    }

    [Test]
    public async Task CanonicalDigestIgnoresJsonAndSetOrdering()
    {
        var first = Parse(ValidDescriptor());
        var second = Parse("""
            {
              "nodes":[
                {"dependsOn":["release-tests","build"],"paths":[],"profiles":["Release"],"resourceWeight":"Heavy","kind":"Artifact","id":"candidate"},
                {"dependsOn":["build"],"profiles":["Release"],"resourceWeight":"Heavy","kind":"Test","id":"release-tests"},
                {"dependsOn":["static"],"paths":["src/"],"profiles":["Release","Feature"],"resourceWeight":"Heavy","kind":"Build","id":"build"},
                {"paths":["tests/","src/"],"profiles":["Release","Feature"],"resourceWeight":"Light","kind":"Static","id":"static"}
              ],
              "repositoryDependencies":[
                {"reason":"SDK changes affect the Dashboard","repository":"TerraScale/TerraScale.TypeScript"},
                {"reason":"Runtime changes affect API consumers","repository":"TerraScale/TerraBase"}
              ],
              "promotion":"NativeBlueGreen",
              "candidateRetentionDays":7,
              "repository":"TerraScale/TerraScale.Internals",
              "apiVersion":"terrascale.ci/v2"
            }
            """);

        await Assert.That(second.Digest).IsEqualTo(first.Digest);
        await Assert.That(second.Nodes).IsEquivalentTo(first.Nodes);
    }

    [Test]
    public async Task FreeFormExecutionAndUnsafePathsFailClosed()
    {
        var cases = new[]
        {
            ValidDescriptor().Replace("\"paths\":[\"src/\",\"tests/\"]", "\"paths\":[\"../src\"]", StringComparison.Ordinal),
            ValidDescriptor().Replace("\"paths\":[\"src/\",\"tests/\"]", "\"paths\":[\"src/**\"]", StringComparison.Ordinal),
            ValidDescriptor().Replace("\"paths\":[\"src/\",\"tests/\"]", "\"paths\":[\"/etc\"]", StringComparison.Ordinal),
            ValidDescriptor().Replace("\"id\":\"static\"", "\"id\":\"static\",\"command\":\"/bin/sh\"", StringComparison.Ordinal),
            ValidDescriptor().Replace("\"repository\":\"TerraScale/TerraScale.Internals\"", "\"repository\":\"not-a-repository\"", StringComparison.Ordinal),
        };

        foreach (var value in cases)
            await Assert.That(() => Parse(value)).Throws<InvalidDataException>();
    }

    [Test]
    public async Task SchemaVersionsDuplicatesAndBoundsAreStrict()
    {
        var cases = new[]
        {
            ValidDescriptor().Replace("terrascale.ci/v2", "terrascale.ci/v3", StringComparison.Ordinal),
            ValidDescriptor().Replace("\"candidateRetentionDays\":7", "\"candidateRetentionDays\":31", StringComparison.Ordinal),
            ValidDescriptor().Replace("\"apiVersion\":\"terrascale.ci/v2\"", "\"apiVersion\":\"terrascale.ci/v2\",\"apiVersion\":\"terrascale.ci/v2\"", StringComparison.Ordinal),
            ValidDescriptor().Replace("\"promotion\":\"NativeBlueGreen\"", "\"promotion\":\"FluxBlueGreen\"", StringComparison.Ordinal),
            ValidDescriptor().Replace("\"profiles\":[\"Release\"]", "\"profiles\":[\"Release\"],\"architectures\":[\"Any\"]", StringComparison.Ordinal),
            ValidDescriptor().Replace("\"profiles\":[\"Release\"]", "\"profiles\":[\"Feature\"]", StringComparison.Ordinal),
        };

        foreach (var value in cases)
            await Assert.That(() => Parse(value)).Throws<InvalidDataException>();
    }

    [Test]
    public async Task MissingSelfAndCyclicDependenciesAreRejected()
    {
        var missing = ValidDescriptor().Replace("\"dependsOn\":[\"static\"]", "\"dependsOn\":[\"missing\"]", StringComparison.Ordinal);
        var self = ValidDescriptor().Replace("\"dependsOn\":[\"static\"]", "\"dependsOn\":[\"build\"]", StringComparison.Ordinal);
        var cycle = ValidDescriptor().Replace("\"id\":\"static\",\"kind\":\"Static\"", "\"id\":\"static\",\"kind\":\"Static\",\"dependsOn\":[\"candidate\"]", StringComparison.Ordinal);
        var repositorySelf = ValidDescriptor().Replace("TerraScale/TerraBase", "TerraScale/TerraScale.Internals", StringComparison.Ordinal);
        var narrowedProfile = ValidDescriptor().Replace(
            "\"id\":\"static\",\"kind\":\"Static\",\"resourceWeight\":\"Light\",\"profiles\":[\"Feature\",\"Release\"]",
            "\"id\":\"static\",\"kind\":\"Static\",\"resourceWeight\":\"Light\",\"profiles\":[\"Release\"]",
            StringComparison.Ordinal);

        foreach (var value in new[] { missing, self, cycle, repositorySelf, narrowedProfile })
            await Assert.That(() => Parse(value)).Throws<InvalidDataException>();
    }

    private static RepositoryCiDescriptorV2 Parse(string value) =>
        RepositoryCiDescriptor.Parse(Encoding.UTF8.GetBytes(value));

    private static string ValidDescriptor() => """
        {
          "apiVersion":"terrascale.ci/v2",
          "repository":"TerraScale/TerraScale.Internals",
          "candidateRetentionDays":7,
          "promotion":"NativeBlueGreen",
          "repositoryDependencies":[
            {"repository":"TerraScale/TerraBase","reason":"Runtime changes affect API consumers"},
            {"repository":"TerraScale/TerraScale.TypeScript","reason":"SDK changes affect the Dashboard"}
          ],
          "nodes":[
            {"id":"candidate","kind":"Artifact","resourceWeight":"Heavy","profiles":["Release"],"paths":[],"dependsOn":["build","release-tests"]},
            {"id":"release-tests","kind":"Test","resourceWeight":"Heavy","profiles":["Release"],"dependsOn":["build"]},
            {"id":"build","kind":"Build","resourceWeight":"Heavy","profiles":["Feature","Release"],"paths":["src/"],"dependsOn":["static"]},
            {"id":"static","kind":"Static","resourceWeight":"Light","profiles":["Feature","Release"],"paths":["src/","tests/"]}
          ]
        }
        """;
}
