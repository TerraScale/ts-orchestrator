using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TsOrch.Agent;

internal sealed record class InvalidConfigFileTarget(string Service, string Target)
{
    public string Message => $"Config file target '{Target}' of {Service} must be a unique absolute container file path.";
}

internal sealed record class ConfigFileSecretMissing(string Service, string Target, string Name)
{
    public string Message => $"Config file '{Target}' of {Service} references undefined secret '{Name}'.";
}

internal sealed record class RenderedConfigFile(string Target, ReadOnlyMemory<byte> Content);

internal readonly union ConfigFileRendering(IReadOnlyList<RenderedConfigFile>, InvalidConfigFileTarget, ConfigFileSecretMissing);

internal static partial class ServiceConfigFiles
{
    public static ConfigFileRendering Render(ServiceSpec service, ResolvedServiceSecrets secrets)
    {
        if (service.ConfigFiles is not { Count: > 0 } files)
        {
            return (IReadOnlyList<RenderedConfigFile>)[];
        }

        var targets = service.Mounts.Select(static mount => mount.Target).ToHashSet(StringComparer.Ordinal);
        List<RenderedConfigFile> rendered = [];
        foreach (var file in files)
        {
            if (IsValidTarget(file.Target) is false || targets.Add(file.Target) is false)
            {
                return new InvalidConfigFileTarget(service.Name, file.Target);
            }

            var content = new StringBuilder();
            var offset = 0;
            foreach (Match placeholder in SecretPlaceholder().Matches(file.Template))
            {
                var name = placeholder.Groups[1].Value;
                if (secrets.Values.TryGetValue(name, out var secret) is false)
                {
                    return new ConfigFileSecretMissing(service.Name, file.Target, name);
                }

                content.Append(file.Template, offset, placeholder.Index - offset);
                content.Append(JsonSerializer.Serialize(secret.Value, AgentJsonContext.Default.String));
                offset = placeholder.Index + placeholder.Length;
            }

            content.Append(file.Template, offset, file.Template.Length - offset);
            rendered.Add(new RenderedConfigFile(file.Target, Encoding.UTF8.GetBytes(content.ToString())));
        }

        return (IReadOnlyList<RenderedConfigFile>)rendered;
    }

    private static bool IsValidTarget(string target) =>
        target.Length > 1 && target.StartsWith('/') && target.EndsWith('/') is false
        && target.Contains("..", StringComparison.Ordinal) is false
        && target.Contains('\0') is false && target.Contains(':') is false
        && target.Split('/').Skip(1).All(static segment => segment is not ("" or "."))
        && target.Equals(SecretStore.ContainerSecretsDirectory, StringComparison.Ordinal) is false
        && target.StartsWith(SecretStore.ContainerSecretsDirectory + "/", StringComparison.Ordinal) is false;

    [GeneratedRegex(@"\{\{([^{}]*)\}\}")]
    private static partial Regex SecretPlaceholder();
}
