using System.Buffers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.Development;

public sealed record DevelopmentReconcileRequest(
    string SchemaVersion,
    string RequestId,
    string Repository,
    string PreviousCommit,
    string CurrentCommit,
    IReadOnlyList<string> ChangedPaths);

public sealed record DevelopmentReconcileResponse(
    string SchemaVersion,
    string RequestId,
    bool Accepted,
    string? ReconciliationId,
    string? Error);

internal sealed record DevelopmentReconcilePlan(
    DevelopmentReconcileRequest Request,
    string ReconciliationId,
    IReadOnlyList<DevelopmentResourcePlan> Resources);

internal static partial class DevelopmentReconcilePlanner
{
    public const string SchemaVersion = "terrascale.orchestrator.development/v1";
    // Large refactors (e.g. ZString migrations across tests/bench) routinely exceed 128
    // paths; TerraBase impact mapping does not use the path list for kind selection.
    internal const int MaximumChangedPaths = 1024;
    private const int MaximumPathLength = 512;

    public static DevelopmentReconcilePlan Plan(
        DevelopmentTopology topology,
        DevelopmentReconcileRequest request)
    {
        ArgumentNullException.ThrowIfNull(topology);
        ArgumentNullException.ThrowIfNull(request);
        if (request.SchemaVersion != SchemaVersion)
        {
            throw new InvalidDataException("Unsupported reconciliation schema.");
        }
        if (string.IsNullOrEmpty(request.RequestId) || !TokenPattern().IsMatch(request.RequestId))
        {
            throw new InvalidDataException("The request ID is invalid.");
        }
        if (string.IsNullOrEmpty(request.PreviousCommit) ||
            string.IsNullOrEmpty(request.CurrentCommit) ||
            !CommitPattern().IsMatch(request.PreviousCommit) ||
            !CommitPattern().IsMatch(request.CurrentCommit) ||
            request.PreviousCommit == request.CurrentCommit)
        {
            throw new InvalidDataException("The commit range is invalid.");
        }
        if (request.ChangedPaths is null || request.ChangedPaths.Count < 1)
        {
            throw new InvalidDataException("Changed paths must be a non-empty list of relative repository paths.");
        }
        if (request.ChangedPaths.Count > MaximumChangedPaths)
        {
            throw new InvalidDataException(
                $"Changed paths exceed the maximum of {MaximumChangedPaths} entries.");
        }
        if (request.ChangedPaths.Any(path => !SafePath(path)))
        {
            throw new InvalidDataException("Changed paths must be bounded relative repository paths.");
        }

        var kinds = Impact(request.Repository, request.ChangedPaths);
        var resources = topology.Cells.SelectMany(cell => cell.Resources)
            .Where(resource => kinds.Contains(resource.Kind))
            .OrderBy(resource => Order(resource.Kind))
            .ThenBy(resource => resource.Cell, StringComparer.Ordinal)
            .ThenBy(resource => resource.Name, StringComparer.Ordinal)
            .ToArray();
        if (resources.Length == 0)
        {
            // Docs/test/CI-only content has no runtime mapping and must not fail closed.
            if (!SupportsNoRuntimeUpdates(request.Repository) ||
                !request.ChangedPaths.All(path => IsNonRuntimePath(request.Repository, path)))
            {
                throw new InvalidDataException(
                    "The repository update has no safe workload mapping in this topology.");
            }
        }

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(
            '\u001f',
            request.RequestId,
            request.Repository,
            request.PreviousCommit,
            request.CurrentCommit,
            string.Join('\u001e', request.ChangedPaths))));
        return new(request, $"dev-{Convert.ToHexStringLower(digest)[..24]}", resources);
    }

    /// <summary>
    /// Repositories whose updates may resolve to a zero-resource no-op plan when
    /// every changed path is non-runtime content (docs, tests, CI, agent rules).
    /// </summary>
    internal static bool SupportsNoRuntimeUpdates(string repository) =>
        repository is "TerraScale.Internals" or "TerraBase" or "TerraScale.Dashboard";

    internal static bool IsNonRuntimePath(string repository, string path) => repository switch
    {
        "TerraScale.Internals" => IsNonRuntimeInternalsPath(path),
        "TerraBase" => IsNonRuntimeTerraBasePath(path),
        "TerraScale.Dashboard" => IsNonRuntimeDashboardPath(path),
        _ => false
    };

    /// <summary>
    /// Paths that never map to a development workload for TerraBase. Docs, tests,
    /// benchmarks, helper scripts, and agent/CI rules may pull without replacing
    /// the TerraBase/Authentication/Platform/Dashboard graph.
    /// </summary>
    internal static bool IsNonRuntimeTerraBasePath(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return false;
        }

        if (path.StartsWith("docs/", StringComparison.Ordinal) ||
            path.StartsWith("test/", StringComparison.Ordinal) ||
            path.StartsWith("bench/", StringComparison.Ordinal) ||
            path.StartsWith("scripts/", StringComparison.Ordinal) ||
            path.StartsWith(".forgejo/", StringComparison.Ordinal) ||
            path.StartsWith(".github/", StringComparison.Ordinal) ||
            path.StartsWith(".agents/", StringComparison.Ordinal) ||
            path.StartsWith(".codex/", StringComparison.Ordinal) ||
            path.StartsWith(".terrascale/", StringComparison.Ordinal))
        {
            return true;
        }

        if (path is "BannedSymbols.txt" or "NuGet.Config" or "PLAN.md" or "AGENTS.md" or "CLAUDE.md")
        {
            return true;
        }

        // Root-level markdown only (readme.md, CONTEXT.md, etc.).
        return !path.Contains('/') && path.EndsWith(".md", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Paths that never map to a development workload for TerraScale.Internals.
    /// Docs, agent rules, CI/tooling config, root markdown, and the Aspire-only
    /// local emulators may pull without restart.
    /// </summary>
    internal static bool IsNonRuntimeInternalsPath(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return false;
        }

        if (path.StartsWith("docs/", StringComparison.Ordinal) ||
            path.StartsWith("eng/", StringComparison.Ordinal) ||
            path.StartsWith(".forgejo/", StringComparison.Ordinal) ||
            path.StartsWith(".github/", StringComparison.Ordinal) ||
            path.StartsWith(".agents/", StringComparison.Ordinal) ||
            path.StartsWith(".codex/", StringComparison.Ordinal) ||
            path.StartsWith(".terrascale/", StringComparison.Ordinal) ||
            path.StartsWith("src/Hosting/TerraScale.LocalEmulators/", StringComparison.Ordinal))
        {
            return true;
        }

        if (path is "BannedSymbols.txt" or "NuGet.config" or "PLAN.md" or "AGENTS.md" or "CLAUDE.md")
        {
            return true;
        }

        // Root-level markdown only (README.md, CONTRIBUTING.md, etc.).
        return !path.Contains('/') && path.EndsWith(".md", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Paths that never map to a development workload for the standalone
    /// TerraScale.Dashboard repository. Docs, browser/e2e tests, and agent/CI
    /// rules may pull without replacing the dashboard workload. Unknown root
    /// paths stay runtime (fail toward replacement, not silence), matching the
    /// TerraBase policy: app/, src/, public/, types/, scripts/, and every build
    /// config file rebuild the dashboard.
    /// </summary>
    internal static bool IsNonRuntimeDashboardPath(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return false;
        }

        if (path.StartsWith("docs/", StringComparison.Ordinal) ||
            path.StartsWith("e2e/", StringComparison.Ordinal) ||
            path.StartsWith("tests/", StringComparison.Ordinal) ||
            path.StartsWith(".forgejo/", StringComparison.Ordinal) ||
            path.StartsWith(".github/", StringComparison.Ordinal) ||
            path.StartsWith(".agents/", StringComparison.Ordinal) ||
            path.StartsWith(".codex/", StringComparison.Ordinal) ||
            path.StartsWith(".terrascale/", StringComparison.Ordinal))
        {
            return true;
        }

        if (path is "playwright.config.ts" or "AGENTS.md" or "CLAUDE.md" or "PLAN.md")
        {
            return true;
        }

        // Root-level markdown only (README.md, DESIGN_SYSTEM.md, etc.).
        return !path.Contains('/') && path.EndsWith(".md", StringComparison.OrdinalIgnoreCase);
    }

    private static HashSet<DevelopmentResourceKind> Impact(
        string repository,
        IReadOnlyList<string> paths)
    {
        if (repository == "TerraBase")
        {
            return paths.All(path => IsNonRuntimeTerraBasePath(path))
                ? []
                :
                [
                    DevelopmentResourceKind.TerraBase,
                    DevelopmentResourceKind.Authentication,
                    DevelopmentResourceKind.Platform,
                    DevelopmentResourceKind.Dashboard
                ];
        }
        if (repository == "TerraScale.Dashboard")
        {
            return paths.All(path => IsNonRuntimeDashboardPath(path))
                ? []
                : [DevelopmentResourceKind.Dashboard];
        }
        if (repository != "TerraScale.Internals")
        {
            throw new InvalidDataException("The repository has no safe development workload mapping.");
        }

        var kinds = new HashSet<DevelopmentResourceKind>();
        foreach (var path in paths)
        {
            if (path.StartsWith("src/Platform/", StringComparison.Ordinal))
            {
                kinds.Add(DevelopmentResourceKind.Platform);
                kinds.Add(DevelopmentResourceKind.Dashboard);
            }
            else if (path.StartsWith("src/Auth/", StringComparison.Ordinal))
            {
                kinds.Add(DevelopmentResourceKind.Authentication);
                kinds.Add(DevelopmentResourceKind.Platform);
                kinds.Add(DevelopmentResourceKind.Dashboard);
            }
            else if (path is "Directory.Build.props" or "Directory.Packages.props" or
                     "global.json" or "TerraScale.Internals.slnx")
            {
                kinds.UnionWith([
                    DevelopmentResourceKind.Authentication,
                    DevelopmentResourceKind.Platform,
                    DevelopmentResourceKind.Dashboard
                ]);
            }
        }
        return kinds;
    }

    private static bool SafePath(string path) =>
        !string.IsNullOrEmpty(path) &&
        path.Length <= MaximumPathLength &&
        !Path.IsPathRooted(path) &&
        !path.StartsWith('/') &&
        !path.EndsWith('/') &&
        !path.Contains("//", StringComparison.Ordinal) &&
        path.Split('/').All(segment => segment is not "." and not "..") &&
        !path.Contains('\\');

    private static int Order(DevelopmentResourceKind kind) => kind switch
    {
        DevelopmentResourceKind.TerraBase => 0,
        DevelopmentResourceKind.Authentication => 1,
        DevelopmentResourceKind.Platform => 2,
        DevelopmentResourceKind.Dashboard => 3,
        _ => 5
    };

    [GeneratedRegex(@"^[A-Za-z0-9._-]{1,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex TokenPattern();

    [GeneratedRegex(@"^[0-9a-f]{7,64}$", RegexOptions.CultureInvariant)]
    private static partial Regex CommitPattern();
}

internal sealed class DevelopmentControlSocket : IAsyncDisposable
{
    private const int MaximumRequestBytes = 128 * 1024;
    private static readonly TimeSpan ClientTimeout = TimeSpan.FromSeconds(2);
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    private readonly Socket listener;
    private readonly CancellationTokenSource stopping = new();
    private readonly Func<DevelopmentReconcileRequest, DevelopmentReconcileResponse> handle;
    private readonly Dictionary<string, (string Digest, DevelopmentReconcileResponse Response)> requests =
        new(StringComparer.Ordinal);
    private readonly string path;
    private readonly Task loop;

    private DevelopmentControlSocket(
        string path,
        Func<DevelopmentReconcileRequest, DevelopmentReconcileResponse> handle)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("The development control socket requires Linux.");
        }
        this.path = Path.GetFullPath(path);
        this.handle = handle;
        Directory.CreateDirectory(
            DevelopmentGuards.RequireDirectory(this.path, "Development control socket"));
        File.SetUnixFileMode(
            DevelopmentGuards.RequireDirectory(this.path, "Development control socket"),
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        File.Delete(this.path);
        listener = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(this.path));
        File.SetUnixFileMode(this.path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        listener.Listen(8);
        loop = AcceptAsync(stopping.Token);
    }

    public static DevelopmentControlSocket Start(
        string path,
        Func<DevelopmentReconcileRequest, DevelopmentReconcileResponse> handle) =>
        new(path, handle);

    public async ValueTask DisposeAsync()
    {
        await stopping.CancelAsync();
        listener.Dispose();
        try
        {
            await loop;
        }
        catch (OperationCanceledException)
        {
        }
        File.Delete(path);
        stopping.Dispose();
    }

    private async Task AcceptAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            using var client = await listener.AcceptAsync(cancellationToken);
            using var clientTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            clientTimeout.CancelAfter(ClientTimeout);
            try
            {
                await ProcessAsync(client, clientTimeout.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
            }
            catch (Exception exception) when (
                exception is IOException or SocketException or ObjectDisposedException)
            {
            }
        }
    }

    private async Task ProcessAsync(Socket client, CancellationToken cancellationToken)
    {
        await using var stream = new NetworkStream(client, ownsSocket: false);
        DevelopmentReconcileResponse response;
        try
        {
            var bytes = await ReadRequestAsync(stream, cancellationToken);
            ValidateDocument(bytes.Span);
            var request = JsonSerializer.Deserialize<DevelopmentReconcileRequest>(
                bytes.Span,
                SerializerOptions) ?? throw new InvalidDataException("The reconciliation request is empty.");
            var digest = Convert.ToHexStringLower(SHA256.HashData(bytes.Span));
            if (requests.TryGetValue(request.RequestId, out var previous))
            {
                response = previous.Digest == digest
                    ? previous.Response
                    : Rejected(request.RequestId, "The request ID was reused with different content.");
            }
            else
            {
                response = handle(request);
                requests.Add(request.RequestId, (digest, response));
                if (requests.Count > 1024)
                {
                    requests.Remove(requests.Keys.First());
                }
            }
        }
        catch (Exception exception) when (exception is JsonException or InvalidDataException)
        {
            response = Rejected(string.Empty, exception.Message);
        }

        await JsonSerializer.SerializeAsync(stream, response, SerializerOptions, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static async Task<ReadOnlyMemory<byte>> ReadRequestAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        using var content = new MemoryStream();
        var buffer = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer, cancellationToken);
                if (read == 0)
                {
                    break;
                }
                if (content.Length + read > MaximumRequestBytes)
                {
                    throw new InvalidDataException("The reconciliation request exceeds the size limit.");
                }
                content.Write(buffer, 0, read);
                if (buffer.AsSpan(0, read).Contains((byte)'\n'))
                {
                    break;
                }
            }
            return content.ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static void ValidateDocument(ReadOnlySpan<byte> bytes)
    {
        var root = JsonElement.Parse(bytes);
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("The reconciliation request must be a JSON object.");
        }
        var names = root.EnumerateObject()
            .Select(property => property.Name)
            .ToArray();
        var expected = new[]
        {
            "schemaVersion",
            "requestId",
            "repository",
            "previousCommit",
            "currentCommit",
            "changedPaths"
        };
        if (names.Length != expected.Length ||
            names.Distinct(StringComparer.Ordinal).Count() != names.Length ||
            names.Except(expected, StringComparer.Ordinal).Any())
        {
            throw new InvalidDataException("The reconciliation request schema is invalid.");
        }
    }

    private static DevelopmentReconcileResponse Rejected(string requestId, string error) =>
        new(DevelopmentReconcilePlanner.SchemaVersion, requestId, false, null, error);
}
