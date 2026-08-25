using System.Text;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiDescriptorTests
{
    [Test]
    public async Task CheckedInPolicyHasOneClosedPinnedRecipeTargetPerNode()
    {
        var root = FindRepositoryRoot();
        var descriptor = RepositoryCiDescriptor.Parse(
            await File.ReadAllBytesAsync(Path.Combine(root, RepositoryCiImpactPlanner.DescriptorPath)));
        var recipe = await File.ReadAllTextAsync(Path.Combine(root, CiRunnerExecutionPlanner.RecipePath));

        await Assert.That(descriptor.Repository).IsEqualTo("TerraScale/TerraScale.Orchestrator");
        await Assert.That(descriptor.Nodes.Select(static node => node.Id))
            .IsEquivalentTo(["static", "build", "test", "artifact"]);
        await Assert.That(descriptor.Nodes.Single(static node => node.Id == "artifact").Architectures)
            .IsEquivalentTo([RepositoryCiArchitecture.LinuxX64, RepositoryCiArchitecture.LinuxArm64]);
        await Assert.That(recipe.Split('\n', StringSplitOptions.RemoveEmptyEntries)[0])
            .IsEqualTo("FROM mcr.microsoft.com/dotnet/sdk@sha256:b8cc28b501af233e51be59583a41bf3ebde7fc8656418a7dd305b90b21a7f3f9 AS source");
        await Assert.That(recipe).DoesNotContain("net10.0");
        await Assert.That(recipe).Contains("/net11.0/");
        await Assert.That(recipe.Split("/net11.0/", StringSplitOptions.None).Length - 1)
            .IsEqualTo(3);
        await Assert.That(recipe.Split("--results-directory /evidence/tests/", StringSplitOptions.None).Length - 1)
            .IsEqualTo(5);
        await Assert.That(recipe).DoesNotContain("COPY --from=test /source/tests/");
        foreach (var node in descriptor.Nodes)
            await Assert.That(recipe).Contains($"AS ci-{node.Id}");
    }

    [Test]
    public async Task V3PolicyCompilesIntoAClosedDeterministicDag()
    {
        var descriptor = Parse(ValidDescriptor());

        await Assert.That(descriptor.ApiVersion).IsEqualTo(RepositoryCiDescriptor.ApiVersion);
        await Assert.That(descriptor.Repository).IsEqualTo("TerraScale/TerraScale.Internals");
        await Assert.That(descriptor.Digest.Length).IsEqualTo(64);
        await Assert.That(string.Join(',', descriptor.RepositoryDependencies.Select(static value => value.Repository)))
            .IsEqualTo("TerraScale/TerraBase,TerraScale/TerraScale.TypeScript");
        await Assert.That(string.Join(',', descriptor.Nodes.Select(static value => value.Id)))
            .IsEqualTo("static,build,test,artifact");
        await Assert.That(descriptor.Nodes.Single(static value => value.Id == "static").Paths)
            .IsEquivalentTo(["src/", "tests/"]);
        await Assert.That(descriptor.Nodes.Single(static value => value.Id == "artifact").Architectures)
            .IsEquivalentTo([RepositoryCiArchitecture.LinuxX64, RepositoryCiArchitecture.LinuxArm64]);
    }

    [Test]
    public async Task AnyArchitecturePolicyIsClosedToExactlyOneArtifactNodeArchitecture()
    {
        var descriptor = Parse(ValidDescriptor().Replace(
            "\"architectures\":[\"LinuxX64\",\"LinuxArm64\"]",
            "\"architectures\":[\"Any\"]",
            StringComparison.Ordinal));

        await Assert.That(descriptor.Nodes.Single(static value => value.Id == "artifact").Architectures)
            .IsEquivalentTo([RepositoryCiArchitecture.Any]);
    }

    [Test]
    public async Task CanonicalDigestIgnoresJsonAndSetOrdering()
    {
        var first = Parse(ValidDescriptor());
        var second = Parse("""
            {
              "nodes":[
                {"dependsOn":["test","build"],"paths":[],"profiles":["Build"],"resourceWeight":"Heavy","kind":"Artifact","id":"artifact","architectures":["LinuxArm64","LinuxX64"]},
                {"dependsOn":["build"],"profiles":["Build"],"resourceWeight":"Heavy","kind":"Test","id":"test"},
                {"dependsOn":["static"],"paths":["src/"],"profiles":["Build","Feature"],"resourceWeight":"Heavy","kind":"Build","id":"build"},
                {"paths":["tests/","src/"],"profiles":["Build","Feature"],"resourceWeight":"Light","kind":"Static","id":"static"}
              ],
              "repositoryDependencies":[
                {"reason":"SDK changes affect the Dashboard","repository":"TerraScale/TerraScale.TypeScript"},
                {"reason":"Runtime changes affect API consumers","repository":"TerraScale/TerraBase"}
              ],
              "repository":"TerraScale/TerraScale.Internals",
              "apiVersion":"terrascale.ci/v3"
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
    public async Task SchemaVersionsDuplicatesBoundsAndRetiredStageFieldsAreStrict()
    {
        var cases = new[]
        {
            ValidDescriptor().Replace("terrascale.ci/v3", "terrascale.ci/v9", StringComparison.Ordinal),
            // Retired release-stage fields must fail closed as unknown descriptor fields.
            ValidDescriptor().Replace("\"apiVersion\":\"terrascale.ci/v3\"", "\"apiVersion\":\"terrascale.ci/v3\",\"candidateRetentionDays\":7", StringComparison.Ordinal),
            ValidDescriptor().Replace("\"apiVersion\":\"terrascale.ci/v3\"", "\"apiVersion\":\"terrascale.ci/v3\",\"promotion\":\"NativeBlueGreen\"", StringComparison.Ordinal),
            ValidDescriptor().Replace("\"apiVersion\":\"terrascale.ci/v3\"", "\"apiVersion\":\"terrascale.ci/v3\",\"apiVersion\":\"terrascale.ci/v3\"", StringComparison.Ordinal),
            // The retired release-stage profile vocabulary is no longer a valid profile.
            ValidDescriptor().Replace("\"profiles\":[\"Build\"]", "\"profiles\":[\"Release\"]", StringComparison.Ordinal),
            ValidDescriptor().Replace(
                "\"id\":\"test\",\"kind\":\"Test\",\"resourceWeight\":\"Heavy\",\"profiles\":[\"Build\"]",
                "\"id\":\"test\",\"kind\":\"Test\",\"resourceWeight\":\"Heavy\",\"profiles\":[\"Build\"],\"architectures\":[\"Any\",\"LinuxX64\"]",
                StringComparison.Ordinal),
            ValidDescriptor().Replace(
                "\"id\":\"static\",\"kind\":\"Static\",\"resourceWeight\":\"Light\",\"profiles\":[\"Feature\",\"Build\"]",
                "\"id\":\"static\",\"kind\":\"Static\",\"resourceWeight\":\"Light\",\"profiles\":[\"Release\"]",
                StringComparison.Ordinal),
        };

        foreach (var value in cases)
            await Assert.That(() => Parse(value)).Throws<InvalidDataException>();
    }

    [Test]
    public async Task RetiredV2DescriptorsFailWithOneActionableMigrationError()
    {
        // The full retired shape sibling repositories still carry: v2 apiVersion, retention,
        // promotion policy, and 'Release' profiles.
        var exception = Failure(RetiredV2Descriptor());

        await Assert.That(exception).IsNotNull();
        await Assert.That(exception!.Message).Contains("terrascale.ci/v2");
        await Assert.That(exception.Message).Contains("candidateRetentionDays");
        await Assert.That(exception.Message).Contains("promotion");
        await Assert.That(exception.Message).Contains("Release");
        await Assert.That(exception.Message).Contains("'Build'");
        await Assert.That(exception.Message).Contains("terrascale.ci/v3");
    }

    [Test]
    public async Task RetiredFieldsUnderTheCurrentVersionStillNameTheOffendingFields()
    {
        var currentVersionWithRetiredFields = RetiredV2Descriptor().Replace(
            "\"apiVersion\":\"terrascale.ci/v2\"",
            "\"apiVersion\":\"terrascale.ci/v3\"",
            StringComparison.Ordinal);

        var exception = Failure(currentVersionWithRetiredFields);

        await Assert.That(exception).IsNotNull();
        await Assert.That(exception!.Message).Contains("candidateRetentionDays");
        await Assert.That(exception.Message).Contains("promotion");
        await Assert.That(exception.Message).Contains("unknown fields");
    }

    [Test]
    public async Task UnsupportedVersionsAreRejectedWithTheExpectedVersion()
    {
        var unknownVersion = Failure(ValidDescriptor().Replace(
            "terrascale.ci/v3",
            "terrascale.ci/v9",
            StringComparison.Ordinal));

        await Assert.That(unknownVersion).IsNotNull();
        await Assert.That(unknownVersion!.Message).Contains("terrascale.ci/v9");
        await Assert.That(unknownVersion.Message).Contains("terrascale.ci/v3");
    }

    private static InvalidDataException? Failure(string value)
    {
        try
        {
            Parse(value);
            return null;
        }
        catch (InvalidDataException exception)
        {
            return exception;
        }
    }

    private static string RetiredV2Descriptor() => """
        {
          "apiVersion":"terrascale.ci/v2",
          "repository":"TerraScale/TerraScale.Internals",
          "candidateRetentionDays":7,
          "promotion":"NativeOrdered",
          "repositoryDependencies":[],
          "nodes":[
            {"id":"candidate","kind":"Artifact","resourceWeight":"Heavy","profiles":["Release"],"architectures":["LinuxX64","LinuxArm64"],"dependsOn":["build","release-tests"]},
            {"id":"release-tests","kind":"Test","resourceWeight":"Heavy","profiles":["Release"],"dependsOn":["build"]},
            {"id":"build","kind":"Build","resourceWeight":"Heavy","profiles":["Feature","Release"],"paths":["src/"],"dependsOn":["static"]},
            {"id":"static","kind":"Static","resourceWeight":"Light","profiles":["Feature","Release"],"paths":["src/","tests/"]}
          ]
        }
        """;

    [Test]
    public async Task MissingSelfAndCyclicDependenciesAreRejected()
    {
        var missing = ValidDescriptor().Replace("\"dependsOn\":[\"static\"]", "\"dependsOn\":[\"missing\"]", StringComparison.Ordinal);
        var self = ValidDescriptor().Replace("\"dependsOn\":[\"static\"]", "\"dependsOn\":[\"build\"]", StringComparison.Ordinal);
        var cycle = ValidDescriptor().Replace("\"id\":\"static\",\"kind\":\"Static\"", "\"id\":\"static\",\"kind\":\"Static\",\"dependsOn\":[\"artifact\"]", StringComparison.Ordinal);
        var repositorySelf = ValidDescriptor().Replace("TerraScale/TerraBase", "TerraScale/TerraScale.Internals", StringComparison.Ordinal);
        var narrowedProfile = ValidDescriptor().Replace(
            "\"id\":\"static\",\"kind\":\"Static\",\"resourceWeight\":\"Light\",\"profiles\":[\"Feature\",\"Build\"]",
            "\"id\":\"static\",\"kind\":\"Static\",\"resourceWeight\":\"Light\",\"profiles\":[\"Build\"]",
            StringComparison.Ordinal);

        foreach (var value in new[] { missing, self, cycle, repositorySelf, narrowedProfile })
            await Assert.That(() => Parse(value)).Throws<InvalidDataException>();
    }

    private static RepositoryCiDescriptorV2 Parse(string value) =>
        RepositoryCiDescriptor.Parse(Encoding.UTF8.GetBytes(value));

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "ORCHESTRATOR.md")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("Could not locate the repository root.");
    }

    private static string ValidDescriptor() => """
        {
          "apiVersion":"terrascale.ci/v3",
          "repository":"TerraScale/TerraScale.Internals",
          "repositoryDependencies":[
            {"repository":"TerraScale/TerraBase","reason":"Runtime changes affect API consumers"},
            {"repository":"TerraScale/TerraScale.TypeScript","reason":"SDK changes affect the Dashboard"}
          ],
          "nodes":[
            {"id":"artifact","kind":"Artifact","resourceWeight":"Heavy","profiles":["Build"],"architectures":["LinuxX64","LinuxArm64"],"paths":[],"dependsOn":["build","test"]},
            {"id":"test","kind":"Test","resourceWeight":"Heavy","profiles":["Build"],"dependsOn":["build"]},
            {"id":"build","kind":"Build","resourceWeight":"Heavy","profiles":["Feature","Build"],"paths":["src/"],"dependsOn":["static"]},
            {"id":"static","kind":"Static","resourceWeight":"Light","profiles":["Feature","Build"],"paths":["src/","tests/"]}
          ]
        }
        """;
}
