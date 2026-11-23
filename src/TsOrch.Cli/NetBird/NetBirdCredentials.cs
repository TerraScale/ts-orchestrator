using System.Buffers.Text;
using System.Text;
using TsOrch.Oci;

namespace TsOrch.Cli;

internal sealed class NetBirdCredential(string value)
{
    public string Value { get; } = value;

    public override string ToString() => nameof(NetBirdCredential);
}

internal sealed record class NetBirdCredentialUnavailable(CliDiagnostic Diagnostic);

internal readonly union NetBirdCredentialRead(NetBirdCredential, NetBirdCredentialUnavailable);

internal sealed record class NetBirdExportDirectory(string Path);

internal sealed record class NetBirdExportDirectoryUnavailable(CliDiagnostic Diagnostic);

internal readonly union NetBirdExportPreparation(NetBirdExportDirectory, NetBirdExportDirectoryUnavailable);

internal static class NetBirdCredentials
{
    private const UnixFileMode PrivateDirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    public static async Task<NetBirdCredentialRead> ReadAsync(
        string? path, VaultConfig vault, string secretName, TimeProvider timeProvider, CancellationToken cancellationToken)
    {
        if (path is not null)
        {
            return await ReadFileAsync(path, cancellationToken);
        }

        using var deadline = new CancellationTokenSource(OrchHttp.DefaultTimeout, timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        return await ReadOperatorVaultAsync(vault, secretName, linked.Token, cancellationToken);
    }

    private static async Task<NetBirdCredentialRead> ReadOperatorVaultAsync(
        VaultConfig vault, string secretName, CancellationToken operationToken, CancellationToken cancellationToken)
    {
        try
        {
            var outcome = await ExternalProcess.RunAsync("oci",
                [
                    "secrets", "secret-bundle", "get-secret-bundle-by-name",
                    "--vault-id", vault.VaultId, "--secret-name", secretName, "--region", vault.Region,
                    "--query", "data.\"secret-bundle-content\".content", "--raw-output",
                ],
                inheritInput: false,
                operationToken);
            return outcome switch
            {
                ProcessResult { ExitCode: 0 } result when Base64.IsValid(result.Stdout.Trim())
                    => FromText(Encoding.UTF8.GetString(Convert.FromBase64String(result.Stdout)), secretName),
                ProcessResult => new NetBirdCredentialUnavailable(CliDiagnostic.Unavailable($"OCI CLI could not read Vault secret '{secretName}'.")),
                ProcessLaunchFailed => new NetBirdCredentialUnavailable(CliDiagnostic.Unavailable("Install and configure the OCI CLI, or supply a credential file.")),
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested is false)
        {
            return new NetBirdCredentialUnavailable(CliDiagnostic.Unavailable("OCI CLI timed out while reading a NetBird Vault secret."));
        }
    }

    public static async Task<NetBirdCredentialRead> ReadFileAsync(string path, CancellationToken cancellationToken)
    {
        var outcome = await CliFiles.ReadTextAsync(path, cancellationToken);
        return outcome switch
        {
            string content => FromText(content, path),
            CliFileReadProblem failure => new NetBirdCredentialUnavailable(CliFiles.Describe(failure)),
        };
    }

    public static async Task<NetBirdCredentialRead> ReadInstanceVaultAsync(
        OciVaultClient vault, string vaultId, string secretName, CancellationToken cancellationToken)
    {
        var outcome = await vault.GetSecretAsync(vaultId, secretName, cancellationToken);
        return outcome switch
        {
            VaultSecretBundle bundle => FromText(bundle.Value, secretName),
            VaultRegionMissing => new NetBirdCredentialUnavailable(CliDiagnostic.Usage("NetBird enrollment needs a Vault OCID with a region.")),
            VaultSecretMissing => new NetBirdCredentialUnavailable(CliDiagnostic.Missing($"Vault secret '{secretName}' does not exist.")),
            VaultAccessDenied => new NetBirdCredentialUnavailable(CliDiagnostic.Permission($"Instance Principal cannot read Vault secret '{secretName}'.")),
            VaultUnavailable or VaultBundleInvalid or ImdsRequestRejected or ImdsUnavailable or ImdsDocumentInvalid or InvalidFederationCredentials
                or FederationRejected or FederationUnavailable or FederationTokenInvalid
                => new NetBirdCredentialUnavailable(CliDiagnostic.Unavailable($"Instance Principal could not read Vault secret '{secretName}'.")),
        };
    }

    private static NetBirdCredentialRead FromText(string content, string source) =>
        content.TrimEnd('\r', '\n') is { Length: > 0 } value && string.IsNullOrWhiteSpace(value) is false
            ? new NetBirdCredential(value)
            : new NetBirdCredentialUnavailable(CliDiagnostic.Usage($"NetBird credential from '{source}' is empty."));

    public static bool IsToken(string value) =>
        value.Length > 0 && value.All(static character => character is > ' ' and <= '~');

    public static NetBirdExportPreparation PrepareDirectory(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return new NetBirdExportDirectoryUnavailable(CliDiagnostic.Usage("NetBird credential export requires Unix permissions."));
        }

        try
        {
            var fullPath = Path.GetFullPath(path);
            var directory = Directory.CreateDirectory(fullPath, PrivateDirectoryMode);
            if (directory.Attributes.HasFlag(FileAttributes.ReparsePoint) || (File.GetUnixFileMode(fullPath) == PrivateDirectoryMode) is false)
            {
                return new NetBirdExportDirectoryUnavailable(CliDiagnostic.Permission($"NetBird credential directory '{fullPath}' must be a real directory with mode 0700."));
            }

            return new NetBirdExportDirectory(fullPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return new NetBirdExportDirectoryUnavailable(CliDiagnostic.Unavailable($"Could not prepare NetBird credential directory '{path}'."));
        }
    }
}
