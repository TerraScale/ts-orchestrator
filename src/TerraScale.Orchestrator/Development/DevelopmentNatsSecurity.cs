using System.Security.Cryptography;
using System.Text.Json;
using NATS.Client.Core;

namespace TerraScale.Orchestrator.Development;

internal sealed record DevelopmentNKeyIdentity(string PublicKey, string SeedFile);

internal sealed record DevelopmentProductNatsIdentity(string Username, string Password);

internal sealed record DevelopmentTlsIdentity(
    string CertificateFile,
    string KeyFile,
    string CaFile,
    string SpiffeId);

internal sealed record DevelopmentNatsServerTlsIdentity(
    DevelopmentTlsIdentity Client,
    DevelopmentTlsIdentity Route);

internal sealed record DevelopmentNatsTlsPlane(
    IReadOnlyDictionary<string, DevelopmentNatsServerTlsIdentity> Servers,
    IReadOnlyDictionary<string, DevelopmentTlsIdentity> Clients);

internal sealed record DevelopmentNatsTlsSecurity(
    DevelopmentNatsTlsPlane Control,
    DevelopmentNatsTlsPlane Product);

internal sealed record DevelopmentNatsCellSecurity(
    string Cell,
    IReadOnlyDictionary<int, DevelopmentNKeyIdentity> Controllers,
    DevelopmentNKeyIdentity JournalWriter,
    DevelopmentNKeyIdentity Infrastructure,
    DevelopmentNKeyIdentity Operator,
    DevelopmentProductNatsIdentity Product,
    DevelopmentNatsTlsSecurity Tls);

internal sealed class DevelopmentNatsSecurity
{
    private const UnixFileMode DirectoryMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode SecretFileMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private readonly IReadOnlyDictionary<string, DevelopmentNatsCellSecurity> cells;

    private DevelopmentNatsSecurity(IReadOnlyDictionary<string, DevelopmentNatsCellSecurity> cells) =>
        this.cells = cells;

    public DevelopmentNatsCellSecurity Cell(string cell) =>
        cells.TryGetValue(cell, out var security)
            ? security
            : throw new InvalidOperationException($"NATS security for cell '{cell}' is unavailable.");

    public static DevelopmentNatsSecurity Create(
        DevelopmentTopology topology,
        string dataDirectory)
    {
        var root = Path.Combine(dataDirectory, "credentials", "nats");
        EnsurePrivateDirectory(root);
        var tls = DevelopmentPki.Create(topology, dataDirectory);
        var cells = new Dictionary<string, DevelopmentNatsCellSecurity>(StringComparer.Ordinal);
        foreach (var cell in topology.Cells)
        {
            var cellRoot = Path.Combine(root, cell.Cell);
            EnsurePrivateDirectory(cellRoot);
            var controllers = cell.OfKind(DevelopmentResourceKind.ControllerAgent)
                .ToDictionary(
                    controller => controller.Replica,
                    controller => EnsureNKey(
                        Path.Combine(cellRoot, $"controller-{controller.Replica}.nk")));
            var security = new DevelopmentNatsCellSecurity(
                cell.Cell,
                controllers,
                EnsureNKey(Path.Combine(cellRoot, "journal-writer.nk")),
                EnsureNKey(Path.Combine(cellRoot, "infrastructure.nk")),
                EnsureNKey(Path.Combine(cellRoot, "operator-read.nk")),
                EnsureProductIdentity(Path.Combine(cellRoot, "product.json"), cell.Cell),
                tls[cell.Cell]);
            cells.Add(cell.Cell, security);
        }
        return new DevelopmentNatsSecurity(cells);
    }

    internal static DevelopmentNKeyIdentity EnsureNKey(string path)
    {
        string seed;
        string? storedPublicKey = null;
        if (File.Exists(path))
        {
            RequirePrivateFile(path);
            var lines = File.ReadAllLines(path)
                .Select(line => line.Trim())
                .Where(line => line.Length > 0)
                .ToArray();
            seed = lines.FirstOrDefault()
                ?? throw new InvalidOperationException("A development NATS NKey file is empty.");
            storedPublicKey = lines.Skip(1).FirstOrDefault();
        }
        else
        {
            seed = NKeys.CreateUserSeed();
        }

        try
        {
            var publicKey = NKeys.PublicKeyFromSeed(seed);
            if (storedPublicKey is not null && storedPublicKey != publicKey)
            {
                throw new InvalidOperationException(
                    "A development NATS NKey file contains a mismatched public key.");
            }
            if (storedPublicKey is null)
            {
                WriteSecret(path, $"{seed}{Environment.NewLine}{publicKey}{Environment.NewLine}", overwrite: true);
            }
            return new DevelopmentNKeyIdentity(publicKey, path);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            throw new InvalidOperationException("A development NATS NKey file is invalid.", exception);
        }
    }

    private static DevelopmentProductNatsIdentity EnsureProductIdentity(string path, string cell)
    {
        if (File.Exists(path))
        {
            RequirePrivateFile(path);
            var existing = JsonSerializer.Deserialize<DevelopmentProductNatsIdentity>(File.ReadAllText(path))
                ?? throw new InvalidOperationException("A development product NATS identity is empty.");
            ValidateProduct(existing, cell);
            return existing;
        }

        var identity = new DevelopmentProductNatsIdentity(
            $"product-{cell}",
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant());
        WriteSecret(path, JsonSerializer.Serialize(identity));
        return identity;
    }

    private static void ValidateProduct(DevelopmentProductNatsIdentity identity, string cell)
    {
        if (identity.Username != $"product-{cell}" || identity.Password.Length != 64 ||
            identity.Password.Any(character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new InvalidOperationException("A development product NATS identity is invalid.");
        }
    }

    private static void WriteSecret(string path, string contents, bool overwrite = false)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("The Orchestrator development runtime requires Linux.");
        }
        EnsurePrivateDirectory(Path.GetDirectoryName(path)!);
        var temporary = $"{path}.{Guid.NewGuid():N}.tmp";
        File.WriteAllText(temporary, contents);
        File.SetUnixFileMode(temporary, SecretFileMode);
        File.Move(temporary, path, overwrite);
        RequirePrivateFile(path);
    }

    private static void EnsurePrivateDirectory(string path)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("The Orchestrator development runtime requires Linux.");
        }
        Directory.CreateDirectory(path);
        File.SetUnixFileMode(path, DirectoryMode);
    }

    private static void RequirePrivateFile(string path)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("The Orchestrator development runtime requires Linux.");
        }
        var mode = File.GetUnixFileMode(path);
        if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                     UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
        {
            throw new InvalidOperationException("Development NATS credential files must be private to the owner.");
        }
    }

}
