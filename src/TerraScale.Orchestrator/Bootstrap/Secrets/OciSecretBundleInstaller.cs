using System.Security.Cryptography;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Bootstrap.Secrets;

/// <summary>
/// Materializes a complete verified generation before publishing it with one
/// directory rename. Existing generations are verified, never overwritten.
/// A caller must keep the parent directory under its exclusive control.
/// </summary>
internal static class OciSecretBundleInstaller
{
    private const UnixFileMode FileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode DirectoryMode = FileMode | UnixFileMode.UserExecute;

    internal static async Task InstallAsync(OciSecretManifest manifest, string outputDirectory,
        Func<string, IOciVaultSecretSource> sourceFactory, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("OCI secret bootstrap requires Linux file permissions.");
        cancellationToken.ThrowIfCancellationRequested();
        var output = Path.GetFullPath(outputDirectory);
        var parent = Directory.GetParent(output)
            ?? throw new InvalidDataException("A private bundle parent directory is required.");
        ValidateDirectory(parent);
        if (Path.Exists(output))
        {
            VerifyExisting(manifest, output);
            return;
        }
        var staging = Path.Combine(parent.FullName, $".oci-secrets-{Guid.NewGuid():N}");
        Directory.CreateDirectory(staging, DirectoryMode);
        File.SetUnixFileMode(staging, DirectoryMode);
        try
        {
            using var source = sourceFactory(manifest.Region);
            foreach (var file in manifest.Files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var bytes = await source.ReadAsync(file, cancellationToken).ConfigureAwait(false);
                try
                {
                    OciSecretManifest.VerifyContent(file, bytes);
                    await using var stream = new FileStream(Path.Combine(staging, file.Name), new FileStreamOptions
                    {
                        Mode = System.IO.FileMode.CreateNew,
                        Access = FileAccess.Write,
                        Share = FileShare.None,
                        UnixCreateMode = FileMode,
                        Options = FileOptions.Asynchronous
                    });
                    File.SetUnixFileMode(Path.Combine(staging, file.Name), FileMode);
                    await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                    stream.Flush(flushToDisk: true);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }
            cancellationToken.ThrowIfCancellationRequested();
            // If another invocation won, fail closed; a subsequent run can
            // verify its complete bundle. No overwrite is permitted.
            Directory.Move(staging, output);
        }
        finally
        {
            if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true);
        }
    }

    private static void VerifyExisting(OciSecretManifest manifest, string output)
    {
        ValidateDirectory(new(output));
        var entries = Directory.GetFileSystemEntries(output);
        if (entries.Length != manifest.Files.Length)
            throw new InvalidDataException("The existing OCI secret bundle has unexpected files.");
        foreach (var file in manifest.Files)
        {
            var path = NatsFileResolver.Resolve(Path.Combine(output, file.Name), "OCI secret file",
                OciSecretManifest.MaximumSecretBytes, ownerPrivate: true);
            var bytes = File.ReadAllBytes(path);
            try { OciSecretManifest.VerifyContent(file, bytes); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }

    private static void ValidateDirectory(DirectoryInfo directory)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("OCI secret bootstrap requires Linux file permissions.");
        if (!directory.Exists || File.GetUnixFileMode(directory.FullName) != DirectoryMode)
            throw new InvalidDataException("OCI secret bundles require an existing owner-private parent and generation directory.");
        for (DirectoryInfo? part = directory; part is not null; part = part.Parent)
            if (part.LinkTarget is not null || part.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new InvalidDataException("OCI secret bundle directories must not traverse symlinks.");
    }
}
