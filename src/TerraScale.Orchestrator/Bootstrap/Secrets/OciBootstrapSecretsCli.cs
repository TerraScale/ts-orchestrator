using System.Text.Json;

namespace TerraScale.Orchestrator.Bootstrap.Secrets;

internal static class OciBootstrapSecretsCli
{
    internal static async Task<int> ExecuteAsync(string[] arguments, CancellationToken cancellationToken,
        Func<string, IOciVaultSecretSource>? sourceFactory = null, TextWriter? output = null, TextWriter? error = null)
    {
        output ??= Console.Out;
        error ??= Console.Error;
        try
        {
            if (arguments.Length != 6)
                throw new ArgumentException("Expected manifest, region intent and output directory.");
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            for (var index = 0; index < arguments.Length; index += 2)
                if (arguments[index] is not ("--manifest" or "--region-intent" or "--output") ||
                    string.IsNullOrWhiteSpace(arguments[index + 1]) ||
                    !values.TryAdd(arguments[index], arguments[index + 1]))
                    throw new ArgumentException("Invalid OCI bootstrap arguments.");

            var manifest = OciSecretManifest.Load(values["--manifest"]);
            OciRegionIntent.Load(values["--region-intent"]).RequireCell(manifest.Region);
            using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            bounded.CancelAfter(TimeSpan.FromMinutes(3));
            await OciSecretBundleInstaller.InstallAsync(manifest, values["--output"],
                sourceFactory ?? OciVaultSecretSource.Create, bounded.Token).ConfigureAwait(false);
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                state = "verified",
                region = manifest.Region,
                files = manifest.Files.Length
            })).ConfigureAwait(false);
            return 0;
        }
        catch (Exception exception)
        {
            // SDK and filesystem errors may contain response bodies or paths.
            // Do not send those through Program's generic exception printer.
            await error.WriteLineAsync($"OCI secret bootstrap failed ({exception.GetType().Name}); no bundle was replaced.")
                .ConfigureAwait(false);
            return 1;
        }
    }
}
