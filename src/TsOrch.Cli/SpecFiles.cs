namespace TsOrch.Cli;

internal sealed record class FleetDefinitionInvalid(string Path, string Detail);

internal sealed record class ServiceDefinitionInvalid(string Path, string Detail);

internal sealed record class DuplicateServiceDefinition(string Directory, string Service);

internal sealed record class ServiceDefinitionsMissing(string Directory);

internal readonly union FleetDefinitionLoad(FleetConfig, CliFileReadProblem, FleetDefinitionInvalid);

internal readonly union ServiceDefinitionsLoad(
    IReadOnlyList<ServiceSpec>, CliFileReadProblem, ServiceDefinitionInvalid, DuplicateServiceDefinition, ServiceDefinitionsMissing);

internal static class SpecFiles
{
    public const string DefaultServicesPath = "deploy/services";
    public const string DefaultFleetPath = "deploy/fleet.json";

    public static async Task<FleetDefinitionLoad> LoadFleetAsync(string path, CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        var read = await CliFiles.ReadTextAsync(fullPath, cancellationToken);
        return read switch
        {
            string content => DecodeFleet(fullPath, content),
            CliFileReadProblem failure => failure,
        };
    }

    private static FleetDefinitionLoad DecodeFleet(string path, string content) =>
        OrchHttp.Decode(content, FleetJsonContext.Default.FleetConfig, out var error) is { } fleet
            ? fleet
            : new FleetDefinitionInvalid(path, error ?? "Missing fleet definition.");

    public static async Task<ServiceDefinitionsLoad> LoadServicesAsync(string path, CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        var listed = ListFiles(fullPath);
        return listed switch
        {
            IReadOnlyList<string> files => await LoadServicesAsync(fullPath, files, cancellationToken),
            CliFileReadProblem failure => failure,
        };
    }

    private static ServiceFileListing ListFiles(string path)
    {
        try
        {
            return Directory.Exists(path)
                ? (IReadOnlyList<string>)[.. Directory.EnumerateFiles(path, "*.json").Order(StringComparer.Ordinal)]
                : (IReadOnlyList<string>)[path];
        }
        catch (IOException exception)
        {
            return new CliFileReadInterrupted(path, exception.Message);
        }
        catch (UnauthorizedAccessException exception)
        {
            return new CliFileReadDenied(path, exception.Message);
        }
    }

    private static async Task<ServiceDefinitionsLoad> LoadServicesAsync(string path, IReadOnlyList<string> files, CancellationToken cancellationToken)
    {
        if (files.Count == 0)
        {
            return new ServiceDefinitionsMissing(path);
        }

        List<ServiceSpec> loaded = [];
        HashSet<string> names = [with(StringComparer.Ordinal)];
        foreach (var file in files)
        {
            var read = await CliFiles.ReadTextAsync(file, cancellationToken);
            var decoded = read switch
            {
                string content => DecodeServiceFile(file, content),
                CliFileReadProblem readFailure => (ServiceFileLoad)readFailure,
            };
            var failure = decoded switch
            {
                IReadOnlyList<ServiceSpec> services => AddServices(services, names, loaded, path),
                CliFileReadProblem readFailure => (ServiceDefinitionsLoad?)readFailure,
                ServiceDefinitionInvalid invalid => (ServiceDefinitionsLoad?)invalid,
            };
            if (failure is { } finished)
            {
                return finished;
            }
        }

        return loaded;
    }

    private static ServiceDefinitionsLoad? AddServices(IReadOnlyList<ServiceSpec> services, HashSet<string> names, List<ServiceSpec> loaded, string path)
    {
        foreach (var service in services)
        {
            if (!names.Add(service.Name))
            {
                return new DuplicateServiceDefinition(path, service.Name);
            }

            loaded.Add(service);
        }

        return null;
    }

    private static ServiceFileLoad DecodeServiceFile(string path, string content)
    {
        if (content.TrimStart().StartsWith('['))
        {
            return OrchHttp.Decode(content, FleetJsonContext.Default.IReadOnlyListServiceSpec, out var error) is { } list
                ? list
                : new ServiceDefinitionInvalid(path, error ?? "Missing service definitions.");
        }

        return OrchHttp.Decode(content, FleetJsonContext.Default.ServiceSpec, out var detail) is { } service
            ? (IReadOnlyList<ServiceSpec>)[service]
            : new ServiceDefinitionInvalid(path, detail ?? "Missing service definition.");
    }

    public static CliDiagnostic Describe(FleetDefinitionInvalid invalid) => CliDiagnostic.Usage($"{invalid.Path} is not valid: {invalid.Detail}");

    public static CliDiagnostic Describe(ServiceDefinitionInvalid invalid) => CliDiagnostic.Usage($"{invalid.Path} is not valid: {invalid.Detail}");

    public static CliDiagnostic Describe(DuplicateServiceDefinition duplicate) => CliDiagnostic.Usage($"Service '{duplicate.Service}' is defined more than once under {duplicate.Directory}.");

    public static CliDiagnostic Describe(ServiceDefinitionsMissing missing) => CliDiagnostic.Missing($"{missing.Directory} holds no *.json service definitions.");

    private readonly union ServiceFileListing(IReadOnlyList<string>, CliFileReadProblem);

    private readonly union ServiceFileLoad(IReadOnlyList<ServiceSpec>, CliFileReadProblem, ServiceDefinitionInvalid);
}
