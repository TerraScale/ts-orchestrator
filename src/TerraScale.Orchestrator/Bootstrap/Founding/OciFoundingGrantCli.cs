using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Bootstrap.Founding;

/// <summary>Offline CI operation. Its signing key must never be installed on a controller.</summary>
internal static class OciFoundingGrantCli
{
    internal static async Task<int> ExecuteAsync(string[] arguments, CancellationToken cancellationToken,
        TimeProvider? timeProvider = null, TextWriter? output = null, TextWriter? error = null)
    {
        output ??= Console.Out;
        error ??= Console.Error;
        string? temporary = null;
        try
        {
            if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Founding signing requires private Linux key files.");
            if (arguments.Length != 8) throw new ArgumentException("Expected plan, signing key, region intent and output.");
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            for (var i = 0; i < arguments.Length; i += 2)
                if (arguments[i] is not ("--plan" or "--signing-key" or "--region-intent" or "--output") ||
                    string.IsNullOrWhiteSpace(arguments[i + 1]) || !values.TryAdd(arguments[i], arguments[i + 1]))
                    throw new ArgumentException("The founding signing arguments are invalid.");
            cancellationToken.ThrowIfCancellationRequested();
            var bytes = OciFoundingPlan.ReadFile(values["--plan"], "unsigned founding plan", 96 * 1024);
            var plan = JsonSerializer.Deserialize<OciFoundingPlan>(bytes, OciFoundingPlan.JsonOptions)
                ?? throw new InvalidDataException("The founding plan is empty.");
            plan.Validate(OciRegionIntent.Load(values["--region-intent"]));
            plan.RequireCreateWindow((timeProvider ?? TimeProvider.System).GetUtcNow());
            var keyPath = NatsFileResolver.Resolve(values["--signing-key"], "founding signing key", 8 * 1024, ownerPrivate: true);
            var privateBytes = OciFoundingPlan.ReadFile(keyPath, "founding signing key", 8 * 1024);
            byte[] signature;
            try
            {
                using var key = ECDsa.Create();
                var pem = new char[Encoding.UTF8.GetCharCount(privateBytes)];
                try
                {
                    Encoding.UTF8.GetChars(privateBytes, pem);
                    key.ImportFromPem(pem);
                }
                finally { Array.Clear(pem); }
                BootstrapTrustBundleKey.RequireP256(key);
                signature = key.SignData(OciFoundingPlan.SigningBytes(bytes), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            finally { CryptographicOperations.ZeroMemory(privateBytes); }
            var envelope = JsonSerializer.SerializeToUtf8Bytes(
                new OciFoundingPlan.SignedPlan(Convert.ToBase64String(bytes), Convert.ToBase64String(signature)),
                OciFoundingPlan.JsonOptions);
            if (envelope.Length > OciFoundingPlan.MaximumDocumentBytes)
                throw new InvalidDataException("The signed founding envelope exceeds its delivery bound.");
            var target = Path.GetFullPath(values["--output"]);
            var parent = Directory.GetParent(target) ?? throw new InvalidDataException("A signing output parent is required.");
            if (!parent.Exists) throw new InvalidDataException("The signing output parent must exist.");
            for (DirectoryInfo? part = parent; part is not null; part = part.Parent)
                if (part.LinkTarget is not null || part.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    throw new InvalidDataException("The signing output must not traverse links.");
            temporary = target + "." + Guid.NewGuid().ToString("N");
            await using (var stream = new FileStream(temporary, new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite, Options = FileOptions.Asynchronous
            }))
            {
                await stream.WriteAsync(envelope, cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temporary, target); // Never replace a previously signed generation.
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                state = "signed",
                bootstrapId = plan.BootstrapId,
                planSha256 = Convert.ToHexStringLower(SHA256.HashData(bytes))
            }, OciFoundingPlan.JsonOptions)).ConfigureAwait(false);
            return 0;
        }
        catch (Exception exception)
        {
            await error.WriteLineAsync($"OCI founding signing failed ({exception.GetType().Name}); no grant was replaced.").ConfigureAwait(false);
            return 1;
        }
        finally
        {
            if (temporary is not null && File.Exists(temporary)) File.Delete(temporary);
        }
    }
}
