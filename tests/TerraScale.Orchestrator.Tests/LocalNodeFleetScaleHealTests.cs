using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TerraScale.Orchestrator.Nodes;
using TerraScale.Orchestrator.Scheduler;
using TerraScale.Orchestrator.Scheduler.Autoscaling;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// The live local-fleet lane: real TerraBase member processes started from
/// environment configuration, driven through the deterministic autoscaler by
/// the orchestrator's node fleet. Proves scale-up (a provisioned node boots a
/// healthy member), scale-down (cordon + drain + retire under the replica
/// drain-safety gate), and auto-heal (member loss triggers a replacement).
/// Gated by <c>TS_ORCH_LIVE_FLEET=1</c> because it builds the TerraBase host.
/// </summary>
public sealed class LocalNodeFleetScaleHealTests
{
    private static readonly ResourceVector NodeCapacity = LocalNodeFleet.DefaultNodeCapacity;

    [Test]
    public async Task FleetScalesUpDrainsDownAndHeals()
    {
        Skip.Unless(
            Environment.GetEnvironmentVariable("TS_ORCH_LIVE_FLEET") == "1" &&
                !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("TS_ORCH_TERRABASE_HOST_DIR")),
            "Set TS_ORCH_LIVE_FLEET=1 and TS_ORCH_TERRABASE_HOST_DIR=<published TerraBase.Host output> to run the live fleet lane.");
        var root = Path.Combine(Path.GetTempPath(), "orchestrator-fleet-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        using var certificates = ClusterCertificates.Create(root, memberCount: 4);
        var databaseId = CanonicalUlid.New();
        var tenantId = CanonicalUlid.New();
        await using var fleet = new LocalNodeFleet(request => Launch(request, root, certificates, databaseId, tenantId));
        var engine = new AutoscalerEngine(
            new AutoscalerConfig(
                minNodes: 1,
                maxNodes: 4,
                scaleUpHeadroomPercent: 30,
                scaleDownHeadroomPercent: 40,
                scaleUpConfirmTicks: 2,
                scaleDownConfirmTicks: 2,
                maxConcurrentProvisions: 2,
                flapSuppressionTicks: 0),
            new ReplicaDrainSafetyEvaluator(new DrainPolicy(maxLagBytes: 1_000_000)));
        var runtime = new AutoscalerRuntime(engine, fleet);

        try
        {
            // --- bootstrap: one real member under orchestrator control.
            await fleet.ProvisionAsync(ProvisionRequest("node-1"));
            await Assert.That(fleet.IsMemberAlive("node-1")).IsTrue();

            // --- scale up: sustained member demand breaches headroom and a
            // second node's real member must boot healthy.
            var demand = MemberDemand();
            await runtime.StepAsync([demand]);
            var scaleUp = await runtime.StepAsync([demand]);
            await Assert.That(scaleUp.OfType<AutoscalerAction.ProvisionNode>().Count()).IsEqualTo(1);
            await Assert.That(fleet.IsMemberAlive("as-node-1")).IsTrue();

            // --- auto-heal: hard member loss must not silently pass; the
            // surviving fleet stays drain-safe (the dead replica blocks
            // draining other nodes) and the sustained demand provisions a
            // replacement member.
            fleet.KillMember("node-1");
            await Assert.That(fleet.IsMemberAlive("node-1")).IsFalse();
            var healTicks = new List<IReadOnlyList<AutoscalerAction>>();
            for (var step = 0; step < 4; step++)
            {
                healTicks.Add(await runtime.StepAsync([demand]));
            }

            await Assert.That(fleet.IsMemberAlive("as-node-2")).IsTrue();
            // While node-1's replica is down, no node is drained.
            await Assert.That(healTicks.SelectMany(actions => actions).OfType<AutoscalerAction.DrainNode>()).IsEmpty();

            // --- scale down: demand disappears; after confirmation the
            // lowest-utilization node is cordoned, drained, and retired.
            await runtime.StepAsync([]);
            var scaleDown = await runtime.StepAsync([]);
            var cordon = scaleDown.OfType<AutoscalerAction.CordonNode>().SingleOrDefault();
            var drain = scaleDown.OfType<AutoscalerAction.DrainNode>().SingleOrDefault();
            await Assert.That(cordon).IsNotNull();
            await Assert.That(drain).IsNotNull();

            var retire = await runtime.StepAsync([]);
            var retired = retire.OfType<AutoscalerAction.RetireNode>().SingleOrDefault();
            await Assert.That(retired).IsNotNull();
            await Assert.That(fleet.IsMemberAlive(retired.NodeId)).IsFalse();
        }
        finally
        {
            await fleet.DisposeAsync();
            Directory.Delete(root, recursive: true);
        }
    }

    private static NodeProvisionRequest ProvisionRequest(string nodeId) =>
        new(nodeId, "greenfield", NodeCapacity, "test bootstrap provision");

    private static AllocationDemand MemberDemand() =>
        new("terrabase-member", "terrabase-member", true, new ResourceVector(
            cpu: 20, memory: 6_500_000_000, blockIo: 0, ephemeralDisk: 0, bandwidth: 0, pids: 2, fileDescriptors: 0, hugePages: 0));

    /// <summary>
    /// A canonical 26-character Crockford base32 ULID, matching the identity
    /// text TerraBase requires for database ids without taking a dependency.
    /// </summary>
    internal static class CanonicalUlid
    {
        private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

        public static string New()
        {
            Span<char> text = stackalloc char[26];
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            for (var index = 9; index >= 0; index--)
            {
                text[index] = Alphabet[(int)(timestamp & 31)];
                timestamp >>= 5;
            }

            Span<byte> randomness = stackalloc byte[8];
            RandomNumberGenerator.Fill(randomness);
            var value = BitConverter.ToUInt64(randomness);
            for (var index = 25; index >= 10; index--)
            {
                text[index] = Alphabet[(int)(value & 31)];
                value >>= 5;
            }

            return new string(text);
        }
    }

    private static MemberLaunchDescription Launch(
        NodeProvisionRequest request,
        string root,
        ClusterCertificates certificates,
        string databaseId,
        string tenantId)
    {
        var member = certificates.Member(request.NodeId);
        var dataPath = Path.Combine(root, request.NodeId, "data");
        Directory.CreateDirectory(dataPath);
        var (peerPort, observabilityPort) = ReservePorts();
        return new MemberLaunchDescription(
            request.NodeId,
            Environment.GetEnvironmentVariable("DOTNET_ROOT") is { Length: > 0 } dotnetRoot
                ? Path.Combine(dotnetRoot, "dotnet")
                : "dotnet",
            Path.Combine(Environment.GetEnvironmentVariable("TS_ORCH_TERRABASE_HOST_DIR")
                ?? throw new InvalidOperationException("TS_ORCH_TERRABASE_HOST_DIR must point at the published TerraBase.Host output."),
                "TerraBase.Host.dll"),
            dataPath,
            peerPort,
            observabilityPort,
            new Dictionary<string, string>
            {
                ["TERRABASE_REGION"] = "GRU",
                ["TERRABASE_NODE_ID"] = request.NodeId,
                ["TERRABASE_REPLICA_EPOCH"] = "1",
                ["TERRABASE_MEMBER_CERT_FILE"] = member.CertificatePath,
                ["TERRABASE_MEMBER_KEY_FILE"] = member.KeyPath,
                ["TERRABASE_CLUSTER_CA_FILE"] = certificates.AuthorityPath,
                ["TERRABASE_PEER_ALLOWLIST"] = certificates.Allowlist(databaseId, tenantId, except: request.NodeId),
                ["TERRABASE_INTERNAL_DATABASE_ID"] = databaseId,
                ["TERRABASE_DATABASE_ROUTE"] = "fleet-db",
                ["TERRABASE_DATABASE_TENANT"] = tenantId,
                ["TERRABASE_DATABASE_ULID"] = databaseId,
                ["TERRABASE_DATABASE_MODE"] = "explicit",
                ["TERRABASE_DATABASE_PATH"] = dataPath,
                ["TERRABASE_DATABASE_BACKEND"] = "storage-engine",
                ["TERRABASE_DATABASE_HOME_REGION"] = "GRU",
                ["TERRABASE_DATABASE_SELECTED_REGIONS"] = "GRU",
            });
    }

    private static (int PeerPort, int ObservabilityPort) ReservePorts()
    {
        using var peer = new TcpListener(IPAddress.Loopback, 0);
        peer.Start();
        using var observability = new TcpListener(IPAddress.Loopback, 0);
        observability.Start();
        var peerPort = ((IPEndPoint)peer.LocalEndpoint).Port;
        var observabilityPort = ((IPEndPoint)observability.LocalEndpoint).Port;
        peer.Stop();
        observability.Stop();
        return (peerPort, observabilityPort);
    }

    private sealed class ClusterCertificates : IDisposable
    {
        private readonly Dictionary<string, MemberCertificate> members = new(StringComparer.Ordinal);
        private readonly X509Certificate2 authority;

        private ClusterCertificates(X509Certificate2 authority, string authorityPath)
        {
            this.authority = authority;
            AuthorityPath = authorityPath;
        }

        public string AuthorityPath { get; }

        public static ClusterCertificates Create(string root, int memberCount)
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest(
                new X500DistinguishedName("CN=fleet-test-ca"),
                key,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            using var authority = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddHours(2));
            var cluster = new ClusterCertificates(
                authority,
                Path.Combine(root, "ca.crt"));
            File.WriteAllText(cluster.AuthorityPath, authority.ExportCertificatePem());

            for (var index = 1; index <= memberCount; index++)
            {
                var nodeId = index == 1 ? "node-1" : $"as-node-{index - 1}";
                using var memberKey = RSA.Create(2048);
                var memberRequest = new CertificateRequest(
                    new X500DistinguishedName($"CN={nodeId}"),
                    memberKey,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
                // One certificate plays both roles in this fleet: the member
                // presents it as the peer-listener server certificate and as
                // its client certificate to the other members' listeners.
                var usages = new OidCollection
                {
                    new("1.3.6.1.5.5.7.3.1"),
                    new("1.3.6.1.5.5.7.3.2"),
                };
                memberRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, false));
                var names = new SubjectAlternativeNameBuilder();
                names.AddIpAddress(IPAddress.Loopback);
                memberRequest.CertificateExtensions.Add(names.Build());
                using var issued = memberRequest.Create(
                    authority,
                    DateTimeOffset.UtcNow.AddMinutes(-5),
                    authority.NotAfter.AddMinutes(-1),
                    RandomNumberGenerator.GetBytes(16));
                using var member = issued.CopyWithPrivateKey(memberKey);
                var directory = Path.Combine(root, nodeId);
                Directory.CreateDirectory(directory);
                var certificatePath = Path.Combine(directory, "member.crt");
                var keyPath = Path.Combine(directory, "member.key");
                File.WriteAllText(certificatePath, member.ExportCertificatePem());
                File.WriteAllText(keyPath, PemEncoding.WriteString("PRIVATE KEY", member.GetRSAPrivateKey()!.ExportPkcs8PrivateKey()));
                cluster.members[nodeId] = new MemberCertificate(
                    nodeId,
                    certificatePath,
                    keyPath,
                    member.GetCertHashString(HashAlgorithmName.SHA256).Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant());
            }

            return cluster;
        }

        public MemberCertificate Member(string nodeId) =>
            members.TryGetValue(nodeId, out var member)
                ? member
                : throw new InvalidOperationException($"No certificate was prepared for member {nodeId}.");

        public string Allowlist(string databaseId, string tenantId, string except) =>
            "[" + string.Join(",", members.Values
                .Where(member => member.NodeId != except)
                .Select(member =>
                    $$"""{"fingerprint":"{{member.Fingerprint}}","memberId":"{{member.NodeId}}","epoch":1,"databases":["{{databaseId}}"],"tenants":["{{tenantId}}"]}""")) + "]";

        public void Dispose()
        {
            authority.Dispose();
        }
    }

    private sealed record MemberCertificate(string NodeId, string CertificatePath, string KeyPath, string Fingerprint);
}
