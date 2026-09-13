using System.Security.Cryptography;
using System.Text;

namespace TerraScale.Orchestrator.Security;

internal static class InfisicalCli
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private const UnixFileMode ForbiddenMode =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
    private static readonly UnixFileMode PrivateFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    internal static async Task<int> ExecuteAsync(
        string[] arguments,
        Func<string, string?> environment,
        CancellationToken cancellationToken)
    {
        var command = Parse(arguments);
        var configuration = InfisicalConfiguration.Resolve(environment)
            ?? throw new ArgumentException("Infisical is not configured.");
        await using var store = InfisicalSecretStore.Create(configuration);
        switch (command)
        {
            case { Action: InfisicalCliAction.List, Name: null, File: null }:
                foreach (var secret in await store.ListAsync(cancellationToken))
                    Console.WriteLine($"{secret.Path}\t{secret.Name}\tversion {secret.Version}");
                break;
            case { Action: InfisicalCliAction.Get, Name: { } name, File: { } file }:
                {
                    var secret = await store.GetAsync(name, cancellationToken);
                    WriteSecret(file, secret.Value);
                    Console.WriteLine($"wrote {secret.Path}:{secret.Name}@{secret.Version} to {Path.GetFullPath(file)}");
                    break;
                }
            case { Action: InfisicalCliAction.Create, Name: { } name, File: { } file }:
                {
                    var secret = await store.CreateAsync(
                        name,
                        ReadSecret(file),
                        cancellationToken);
                    Console.WriteLine($"created {secret.Path}:{secret.Name}@{secret.Version}");
                    break;
                }
            case { Action: InfisicalCliAction.Update, Name: { } name, File: { } file }:
                {
                    var secret = await store.UpdateAsync(
                        name,
                        ReadSecret(file),
                        cancellationToken);
                    Console.WriteLine($"updated {secret.Path}:{secret.Name}@{secret.Version}");
                    break;
                }
            case { Action: InfisicalCliAction.Delete, Name: { } name, File: null }:
                {
                    var secret = await store.DeleteAsync(name, cancellationToken);
                    Console.WriteLine($"deleted {secret.Path}:{secret.Name}@{secret.Version}");
                    break;
                }
            default:
                throw new ArgumentOutOfRangeException();
        }
        return 0;
    }

    internal static InfisicalCliCommand Parse(string[] arguments)
    {
        if (arguments is ["list"])
            return new(InfisicalCliAction.List, null, null);
        if (arguments is ["get", var getName, "--output", var output])
            return new(InfisicalCliAction.Get, RequireName(getName), RequireFile(output));
        if (arguments is ["create", var createName, "--value-file", var createFile])
            return new(InfisicalCliAction.Create, RequireName(createName), RequireFile(createFile));
        if (arguments is ["update", var updateName, "--value-file", var updateFile])
            return new(InfisicalCliAction.Update, RequireName(updateName), RequireFile(updateFile));
        if (arguments is ["delete", var deleteName, "--confirm", var confirmation] &&
            deleteName == confirmation)
            return new(InfisicalCliAction.Delete, RequireName(deleteName), null);
        throw Usage();
    }

    private static string ReadSecret(string value)
    {
        var path = RequirePrivateFile(value, mustExist: true);
        var bytes = File.ReadAllBytes(path);
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            throw new InvalidDataException("The Infisical value file must contain UTF-8 text.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void WriteSecret(string value, string secret)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Infisical secret files require Linux file permissions.");
        var path = Path.GetFullPath(value);
        var parent = Path.GetDirectoryName(path);
        if (parent is null || !Directory.Exists(parent))
            throw new ArgumentException("The Infisical output directory does not exist.");
        if (File.Exists(path)) RequirePrivateFile(path, mustExist: true);
        var temporary = Path.Combine(parent, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        var bytes = Encoding.UTF8.GetBytes(secret);
        try
        {
            using (var file = new FileStream(temporary, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = FileOptions.WriteThrough,
                UnixCreateMode = PrivateFileMode,
            }))
            {
                file.Write(bytes);
                file.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            File.Delete(temporary);
        }
    }

    private static string RequirePrivateFile(string value, bool mustExist)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Infisical secret files require Linux file permissions.");
        var path = Path.GetFullPath(value);
        var file = new FileInfo(path);
        if (mustExist && (!file.Exists || file.LinkTarget is not null || file.Length > 1024 * 1024 ||
                (File.GetUnixFileMode(path) & ForbiddenMode) != 0))
            throw new ArgumentException("The Infisical secret file must be bounded, regular, and owner-private.");
        return path;
    }

    private static string RequireName(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 256 ||
            value.Any(static character => char.IsControl(character)))
            throw Usage();
        return value;
    }

    private static string RequireFile(string value) =>
        string.IsNullOrWhiteSpace(value) ? throw Usage() : value;

    private static ArgumentException Usage() => new(
        "Usage: infisical list | get <name> --output <file> | create|update <name> --value-file <file> | delete <name> --confirm <name>.");
}

internal enum InfisicalCliAction
{
    List,
    Get,
    Create,
    Update,
    Delete,
}

internal sealed record InfisicalCliCommand(InfisicalCliAction Action, string? Name, string? File);

