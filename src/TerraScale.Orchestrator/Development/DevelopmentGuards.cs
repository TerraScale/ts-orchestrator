namespace TerraScale.Orchestrator.Development;

internal static class DevelopmentGuards
{
    internal static string RequireDirectory(string path, string description)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var directory = Path.GetDirectoryName(path);
        return !string.IsNullOrWhiteSpace(directory)
            ? directory
            : throw new InvalidOperationException($"{description} '{path}' has no parent directory.");
    }

    internal static string RequireLabOption(string? value, string optionName) =>
        !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidOperationException(
                $"The development lab option '{optionName}' is required for this command.");

    internal static int RequireSecondaryPort(DevelopmentResourcePlan resource)
    {
        ArgumentNullException.ThrowIfNull(resource);
        if (resource.SecondaryPort is not { } port || port <= 0)
        {
            throw new InvalidOperationException(
                $"Development resource '{resource.Name}' is missing a valid secondary port.");
        }

        return port;
    }

    internal static string RequireEndpoint(DevelopmentResourceObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);
        return observation.Endpoint
            ?? throw new InvalidOperationException(
                $"Development resource '{observation.Name}' has no endpoint to publish.");
    }

    internal static DevelopmentTlsIdentity RequireTlsIdentity(
        DevelopmentTlsIdentity? identity,
        string description) =>
        identity ?? throw new InvalidOperationException($"The {description} TLS identity is unavailable.");
}
