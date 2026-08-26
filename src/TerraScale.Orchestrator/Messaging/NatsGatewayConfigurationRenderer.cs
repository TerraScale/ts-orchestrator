using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// One account's preloaded resolver entry: its name, public key, and the
/// signed account JWT the resolver preloads. Account JWTs are public signed
/// tokens; they carry no key material and no user credentials.
/// </summary>
internal sealed record NatsGatewayRenderAccount
{
    internal NatsGatewayRenderAccount(string accountName, string publicKey, string jwt)
    {
        if (!GlobalNatsAccountNames.IsValid(accountName))
            throw new ArgumentException("The render account name is invalid.", nameof(accountName));
        // The public key is emitted unquoted as a resolver_preload map key, so
        // only the exact NKey public-key shape is accepted: a type-letter
        // prefix (account A, server N, user U, operator O, cluster C) followed
        // by base32 characters. Quotes, whitespace, lowercase, and injection
        // payloads fail here, before any rendering.
        if (publicKey is not { Length: >= 40 and <= 64 } ||
            publicKey[0] is not ('A' or 'N' or 'U' or 'O' or 'C') ||
            publicKey.Skip(1).Any(static character =>
                character is not ((>= 'A' and <= 'Z') or (>= '2' and <= '7'))))
            throw new ArgumentException(
                "The render account public key is not a bounded base32 NKey public key.", nameof(publicKey));
        // The JWT is emitted inside a double-quoted value, but its shape is
        // still validated exactly: three non-empty base64url segments. Any
        // quote, newline, or other character outside the token alphabet fails
        // here, before any rendering.
        var segments = jwt.Split('.');
        if (segments.Length != 3 ||
            segments.Any(static segment => segment.Length == 0 || segment.Any(static character =>
                character is not ((>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or
                                  (>= '0' and <= '9') or '-' or '_'))))
            throw new ArgumentException(
                "The render account JWT is not a signed three-segment base64url token.", nameof(jwt));
        AccountName = accountName;
        PublicKey = publicKey;
        Jwt = jwt;
    }

    internal string AccountName { get; }
    internal string PublicKey { get; }
    internal string Jwt { get; }
}

/// <summary>
/// Everything the renderer needs beyond the typed plan: the operator JWT file
/// and the preloaded account set. File references only — the renderer never
/// receives or emits private key material, seeds, or passwords.
/// </summary>
internal sealed record NatsGatewayRenderContext
{
    internal NatsGatewayRenderContext(
        string operatorJwtFile,
        IReadOnlyList<NatsGatewayRenderAccount> accounts)
    {
        // The operator JWT file is emitted inside a double-quoted value, so it
        // must be an absolute .jwt path without quotes, control characters, or
        // path traversal; anything else fails here, before any rendering.
        if (!Path.IsPathRooted(operatorJwtFile) ||
            !operatorJwtFile.EndsWith(".jwt", StringComparison.Ordinal) ||
            operatorJwtFile.Contains("..", StringComparison.Ordinal) ||
            operatorJwtFile.Any(static character =>
                character is '"' or '\'' || char.IsControl(character)))
            throw new ArgumentException(
                "The operator JWT file must be an absolute .jwt path without quotes or control characters.",
                nameof(operatorJwtFile));
        if (accounts.Count == 0)
            throw new ArgumentException("At least one account must be preloaded.", nameof(accounts));
        foreach (var duplicate in accounts
                     .GroupBy(static account => account.AccountName, StringComparer.Ordinal)
                     .Where(group => group.Count() > 1))
            throw new ArgumentException($"The account '{duplicate.Key}' is preloaded twice.", nameof(accounts));
        OperatorJwtFile = operatorJwtFile;
        Accounts = Array.AsReadOnly(accounts.ToArray());
    }

    internal string OperatorJwtFile { get; }
    internal IReadOnlyList<NatsGatewayRenderAccount> Accounts { get; }
}

/// <summary>
/// Renders nats-server configuration text deterministically from a validated
/// typed plan. This is the only production composition path for gateway
/// configuration: it refuses to render an inadmissible plan, emits every
/// field in a fixed order with sorted collections, includes no timestamp or
/// environment input, and never emits secrets — certificate profiles are file
/// references and account JWTs are public signed tokens.
/// </summary>
internal static partial class NatsGatewayConfigurationRenderer
{
    /// <summary>
    /// Renders one server's configuration from the typed plan. The plan is
    /// re-validated first — against production admission unless the caller
    /// explicitly passes the local conformance profile — so invalid cell
    /// tokens, unqualified endpoints, shared identities, shared store paths,
    /// cross-plane credentials, wildcard imports, and incomplete meshes fail
    /// before any text is produced.
    /// </summary>
    internal static string Render(
        NatsGatewayPlan plan,
        string cell,
        string serverName,
        NatsGatewayRenderContext context,
        NatsGatewayValidationOptions? options = null)
    {
        NatsGatewayPlanValidation.EnsureValid(
            plan,
            options ?? NatsGatewayValidationOptions.Production);
        var cluster = plan.Cluster(cell)
            ?? throw new ArgumentException($"The plan has no cluster for cell '{cell}'.", nameof(cell));
        var server = cluster.Server(serverName);

        var builder = new StringBuilder();
        // The generation header binds the rendered artifact to the typed plan's
        // trust and configuration generations: a rotation changes it, and the
        // digest of the configuration changes with it.
        builder.Append("# terrascale-nats-gateway-plan")
            .Append(" plane=").Append(plan.Plane.ToString().ToLowerInvariant())
            .Append(" cell=").Append(cluster.Cell)
            .Append(" server=").Append(server.ServerName)
            .Append(" trust=").Append(cluster.TrustGeneration.ToString(CultureInfo.InvariantCulture))
            .Append(" config=").Append(cluster.ConfigurationGeneration.ToString(CultureInfo.InvariantCulture))
            .AppendLine();
        AppendLine(builder, "server_name", server.ServerName);
        AppendLine(builder, "host", server.Client.Host);
        builder.Append("port: ").AppendLine(server.Client.Port.ToString(CultureInfo.InvariantCulture));
        builder.Append("max_control_line: 65536").AppendLine();
        AppendLine(builder, "operator", context.OperatorJwtFile);
        builder.Append("resolver: MEMORY").AppendLine();
        builder.Append("resolver_preload: {").AppendLine();
        foreach (var account in context.Accounts.OrderBy(static account => account.AccountName, StringComparer.Ordinal))
        {
            builder.Append("  ").Append(account.PublicKey).Append(": \"").Append(account.Jwt).Append('"').AppendLine();
        }
        builder.Append('}').AppendLine();
        AppendTls(builder, server.Profile(NatsGatewayTransport.Client), indent: 0);
        builder.Append("jetstream {").AppendLine();
        builder.Append("  domain: \"").Append(cluster.JetStreamDomain).Append('"').AppendLine();
        builder.Append("  store_dir: \"").Append(server.StoreDirectory).Append('"').AppendLine();
        builder.Append('}').AppendLine();
        // Every cluster renders a cluster block, including single-server
        // clusters, which solicit their own route endpoint — the upstream
        // single-node shape. The load-bearing case is a server with a
        // gateway listener: the pinned server treats it as never
        // JetStream-standalone, starts clustered JetStream, and refuses to
        // start without a configured route. For a single-server cluster
        // without a gateway listener the self-route is a harmless change of
        // label — standalone JetStream becomes a one-node JetStream cluster
        // with itself as meta leader — and no landed plan declares that
        // shape today.
        AppendCluster(builder, cluster, server);
        if (server.Gateway is not null)
            AppendGateway(builder, plan, cluster, server);
        return builder.ToString();
    }

    /// <summary>The stable content digest of one rendered configuration.</summary>
    internal static string Digest(string rendered) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(rendered)));

    /// <summary>
    /// A short, stable identity of a rendered configuration for evidence:
    /// cell, server, generation, and digest, with no configuration body.
    /// </summary>
    internal static string RenderEvidenceIdentity(
        NatsGatewayPlan plan,
        string cell,
        string serverName,
        string rendered)
    {
        var cluster = plan.Cluster(cell)
            ?? throw new ArgumentException($"The plan has no cluster for cell '{cell}'.", nameof(cell));
        var server = cluster.Server(serverName);
        return string.Create(
            CultureInfo.InvariantCulture,
            $"{cluster.ClusterName}/{server.ServerName} trust={cluster.TrustGeneration} config={cluster.ConfigurationGeneration} digest={Digest(rendered)}");
    }

    /// <summary>
    /// Redacts everything unsuitable for evidence copies of rendered
    /// configuration: private-key PEM blocks, NKey seeds, JWT tokens, and
    /// password assignments.
    /// </summary>
    internal static string RedactForEvidence(string rendered)
    {
        var text = rendered.ReplaceLineEndings("\n");
        text = PrivateKeyBlock().Replace(text, "[redacted-private-key]");
        text = JwtToken().Replace(text, "<redacted-jwt>");
        text = NKeySeed().Replace(text, "[redacted-nkey-seed]");
        return PasswordAssignment().Replace(text, "password: [redacted-password]");
    }

    /// <summary>
    /// Scans text for material that must never appear in rendered
    /// configuration: private-key PEM blocks, NKey seeds, and password
    /// assignments. Public account JWTs are intentionally not flagged — they
    /// are the resolver's public signed tokens — but they are still redacted
    /// from evidence copies.
    /// </summary>
    internal static IReadOnlyList<string> ScanForSecrets(string rendered)
    {
        var findings = new List<string>();
        if (PrivateKeyBlock().IsMatch(rendered))
            findings.Add("private-key-pem-block");
        if (NKeySeed().IsMatch(rendered))
            findings.Add("nkey-seed");
        if (PasswordAssignment().IsMatch(rendered))
            findings.Add("password-assignment");
        return findings;
    }

    [GeneratedRegex(@"-----BEGIN[A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z0-9 ]*PRIVATE KEY-----")]
    private static partial Regex PrivateKeyBlock();

    // NKey seeds are base32 with a two-letter type prefix. Any S-prefixed
    // uppercase token of seed length is treated as a seed: server (SN),
    // account (SA), user (SU), operator (SO), cluster (SC), and any future
    // type letter. The public-key prefixes (A/N/U/O/C) never start with S, so
    // public keys are not flagged.
    [GeneratedRegex(@"\bS[A-Z][A-Z0-9]{20,}\b")]
    private static partial Regex NKeySeed();

    [GeneratedRegex(@"\b[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b")]
    private static partial Regex JwtToken();

    [GeneratedRegex(@"(?i)\bpassword\s*[:=]\s*\S+")]
    private static partial Regex PasswordAssignment();

    private static void AppendCluster(
        StringBuilder builder,
        NatsGatewayCluster cluster,
        NatsGatewayServerIdentity server)
    {
        builder.Append("cluster {").AppendLine();
        builder.Append("  name: \"").Append(cluster.ClusterName).Append('"').AppendLine();
        builder.Append("  host: \"").Append(server.Route.Host).Append('"').AppendLine();
        builder.Append("  port: ").Append(server.Route.Port.ToString(CultureInfo.InvariantCulture)).AppendLine();
        AppendTls(builder, server.Profile(NatsGatewayTransport.Route), indent: 2);
        var routes = cluster.Servers
            .Where(peer => peer.ServerName != server.ServerName)
            .Select(peer => $"nats-route://{peer.Route.Qualified}")
            .Order(StringComparer.Ordinal)
            // A single-server cluster solicits its own route endpoint. The
            // server ignores the self-connection at runtime, but the pinned
            // server requires a configured route before clustered JetStream
            // may start — and a gateway listener always implies clustered
            // JetStream. Gateway-less single-server clusters render the same
            // self-route; for them it is harmless (see Render).
            .DefaultIfEmpty($"nats-route://{server.Route.Qualified}")
            .ToArray();
        if (routes.Length > 0)
        {
            builder.Append("  routes: [")
                .Append(string.Join(", ", routes.Select(static route => $"\"{route}\"")))
                .Append(']')
                .AppendLine();
        }
        builder.Append('}').AppendLine();
    }

    private static void AppendGateway(
        StringBuilder builder,
        NatsGatewayPlan plan,
        NatsGatewayCluster cluster,
        NatsGatewayServerIdentity server)
    {
        builder.Append("gateway {").AppendLine();
        builder.Append("  name: \"").Append(cluster.ClusterName).Append('"').AppendLine();
        builder.Append("  host: \"").Append(server.Gateway!.Host).Append('"').AppendLine();
        builder.Append("  port: ").Append(server.Gateway.Port.ToString(CultureInfo.InvariantCulture)).AppendLine();
        AppendTls(builder, server.Profile(NatsGatewayTransport.Gateway), indent: 2);
        var remotes = plan.Clusters
            .Where(other => other.Cell != cluster.Cell)
            .SelectMany(other => other.Servers.Select(peer => (
                other.ClusterName,
                Url: $"nats-gateway://{peer.Gateway!.Qualified}")))
            .GroupBy(static entry => entry.ClusterName, StringComparer.Ordinal)
            .Select(group => (
                group.Key,
                Urls: group.Select(static entry => entry.Url).Order(StringComparer.Ordinal).ToArray()))
            .OrderBy(static entry => entry.Key, StringComparer.Ordinal)
            .ToArray();
        builder.Append("  gateways: [").AppendLine();
        foreach (var remote in remotes)
        {
            builder.Append("    { name: \"").Append(remote.Key).Append("\", urls: [")
                .Append(string.Join(", ", remote.Urls.Select(static url => $"\"{url}\"")))
                .Append("] }")
                .AppendLine();
        }
        builder.Append("  ]").AppendLine();
        builder.Append('}').AppendLine();
    }

    private static void AppendTls(
        StringBuilder builder,
        NatsGatewayCertificateProfile profile,
        int indent)
    {
        var padding = new string(' ', indent);
        builder.Append(padding).Append("tls {").AppendLine();
        builder.Append(padding).Append("  cert_file: \"").Append(profile.CertificateFile).Append('"').AppendLine();
        builder.Append(padding).Append("  key_file: \"").Append(profile.KeyFile).Append('"').AppendLine();
        builder.Append(padding).Append("  ca_file: \"").Append(profile.CaFile).Append('"').AppendLine();
        builder.Append(padding).Append("  verify: true").AppendLine();
        builder.Append(padding).Append("  timeout: 3").AppendLine();
        builder.Append(padding).Append('}').AppendLine();
    }

    private static void AppendLine(StringBuilder builder, string key, string value)
    {
        builder.Append(key).Append(": \"").Append(value).Append('"').AppendLine();
    }
}
