using System.Security.Cryptography;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Oci.CoreService.Models;
using Oci.CoreService.Requests;
using Oci.CoreService.Responses;
using Oci.Common;
using Oci.Common.Auth;
using Oci.CoreService;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.Bootstrap.Founding;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.Tests;

public sealed class OciFoundingPeersTests
{
    [Test]
    public async Task Real_sdk_signs_the_bounded_launch_and_decodes_the_compute_wire_response()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var fixture = new Fixture();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var key = RSA.Create(2048);
        var keyFile = Path.Combine(fixture.StateDirectory, "synthetic-api-key.pem");
        await File.WriteAllTextAsync(keyFile, key.ExportRSAPrivateKeyPem());
        File.SetUnixFileMode(keyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var configFile = Path.Combine(fixture.StateDirectory, "synthetic-oci-config");
        await File.WriteAllTextAsync(configFile, $"""
            [DEFAULT]
            user=ocid1.user.oc1..synthetic
            tenancy=ocid1.tenancy.oc1..synthetic
            fingerprint=00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
            region=sa-saopaulo-1
            key_file={keyFile}
            """);
        var authentication = new ConfigFileAuthenticationDetailsProvider(configFile, "DEFAULT");
        var endpoint = $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}";
        var compute = new ComputeClient(authentication, new ClientConfiguration { TimeoutMillis = 5000 }, endpoint);
        compute.SetRealmSpecificEndpointTemplate("http://127.0.0.1:1/{ignored}");
        using var transport = new OciCiRunnerSdkTransport(
            OciSdkEndpoint.Pin(compute),
            OciSdkEndpoint.Pin(new VirtualNetworkClient(authentication, new ClientConfiguration { TimeoutMillis = 5000 }, endpoint)));
        var verified = OciFoundingPlan.Load(fixture.PlanPath, fixture.TrustPath, OciRegionIntent.Load(fixture.IntentPath));
        var peer = fixture.Plan.Peers[0];
        var launch = OciFoundingPeerReconciler.CompileLaunch(verified, peer);
        var server = ServeComputeAsync(listener, timeout.Token);
        var response = await transport.LaunchInstanceAsync(launch, timeout.Token);
        var wire = await server.WaitAsync(timeout.Token);
        await Assert.That(wire.Headers).Contains("POST /20160918/instances HTTP/1.1");
        await Assert.That(wire.Headers.ToLowerInvariant()).Contains("authorization: signature ");
        await Assert.That(wire.Headers.ToLowerInvariant()).Contains($"opc-retry-token: {launch.OpcRetryToken}");
        await Assert.That(wire.Headers.ToLowerInvariant()).Contains("x-content-sha256: " +
            Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(wire.Body))).ToLowerInvariant());
        using var document = JsonDocument.Parse(wire.Body);
        var request = document.RootElement;
        await Assert.That(request.GetProperty("sourceDetails").GetProperty("sourceType").GetString()).IsEqualTo("image");
        await Assert.That(request.GetProperty("sourceDetails").GetProperty("bootVolumeSizeInGBs").GetInt32()).IsEqualTo(50);
        await Assert.That(request.GetProperty("metadata").GetProperty("user_data").GetString()).IsEqualTo(peer.BootstrapBase64);
        await Assert.That(request.GetProperty("createVnicDetails").GetProperty("assignPublicIp").GetBoolean()).IsFalse();
        await Assert.That(request.GetProperty("createVnicDetails").GetProperty("assignIpv6Ip").GetBoolean()).IsFalse();
        await Assert.That(request.GetProperty("createVnicDetails").GetProperty("privateIp").GetString()).IsEqualTo(peer.PrivateIp);
        await Assert.That(request.GetProperty("instanceOptions").GetProperty("areLegacyImdsEndpointsDisabled").GetBoolean()).IsTrue();
        await Assert.That(request.GetProperty("isPvEncryptionInTransitEnabled").GetBoolean()).IsTrue();
        await Assert.That(response.Instance.Id).IsEqualTo("ocid1.instance.oc1.sa-saopaulo-1.synthetic-peer");
        await Assert.That(response.Instance.LifecycleState).IsEqualTo(Instance.LifecycleStateEnum.Provisioning);
        await Assert.That(response.Instance.SourceDetails is InstanceSourceViaImageDetails { BootVolumeSizeInGBs: 50 }).IsTrue();
    }

    private static async Task<(string Headers, string Body)> ServeComputeAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        using var socket = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = socket.GetStream();
        using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
        var headers = new StringBuilder();
        var length = 0;
        while (await reader.ReadLineAsync(cancellationToken) is { Length: > 0 } line)
        {
            headers.AppendLine(line);
            if (headers.Length > 16 * 1024) throw new InvalidDataException("Oversized local SDK test headers.");
            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                length = int.Parse(line[15..].Trim(), System.Globalization.CultureInfo.InvariantCulture);
        }
        if (length is < 1 or > 96 * 1024) throw new InvalidDataException("Oversized local SDK test body.");
        // The fixture uses ASCII-only JSON; byte and character lengths agree.
        var chars = new char[length];
        if (await reader.ReadBlockAsync(chars.AsMemory(), cancellationToken) != length)
            throw new InvalidDataException("Incomplete local SDK test body.");
        var response = Encoding.UTF8.GetBytes("""
            {"id":"ocid1.instance.oc1.sa-saopaulo-1.synthetic-peer","lifecycleState":"PROVISIONING",
             "sourceDetails":{"sourceType":"image","imageId":"ocid1.image.oc1.sa-saopaulo-1.pinned","bootVolumeSizeInGBs":50,"bootVolumeVpusPerGB":10}}
            """);
        await stream.WriteAsync(Encoding.ASCII.GetBytes(
            $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"), cancellationToken);
        await stream.WriteAsync(response, cancellationToken);
        return (headers.ToString(), new string(chars));
    }

    [Test]
    public async Task Offline_signer_produces_a_verifiable_grant_without_overwriting_a_generation()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var fixture = new Fixture();
        var unsigned = Path.Combine(fixture.StateDirectory, "unsigned.json");
        var privateKey = Path.Combine(fixture.StateDirectory, "signer.pem");
        var signed = Path.Combine(fixture.StateDirectory, "signed.json");
        File.WriteAllBytes(unsigned, JsonSerializer.SerializeToUtf8Bytes(fixture.Plan, OciFoundingPlan.JsonOptions));
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(privateKey, key.ExportECPrivateKeyPem());
        File.SetUnixFileMode(privateKey, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.WriteAllText(fixture.TrustPath, key.ExportSubjectPublicKeyInfoPem());
        string[] arguments = ["--plan", unsigned, "--signing-key", privateKey, "--region-intent", fixture.IntentPath, "--output", signed];
        await Assert.That(await OciFoundingGrantCli.ExecuteAsync(arguments, CancellationToken.None, fixture.Clock, TextWriter.Null, TextWriter.Null)).IsEqualTo(0);
        var accepted = OciFoundingPlan.Load(signed, fixture.TrustPath, OciRegionIntent.Load(fixture.IntentPath));
        await Assert.That(accepted.Plan.BootstrapId).IsEqualTo(fixture.Plan.BootstrapId);
        var original = File.ReadAllBytes(signed);
        await Assert.That(await OciFoundingGrantCli.ExecuteAsync(arguments, CancellationToken.None, fixture.Clock, TextWriter.Null, TextWriter.Null)).IsEqualTo(1);
        await Assert.That(File.ReadAllBytes(signed)).IsEquivalentTo(original);
        File.SetUnixFileMode(privateKey, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead);
        arguments[7] = Path.Combine(fixture.StateDirectory, "unsafe-key-output.json");
        await Assert.That(await OciFoundingGrantCli.ExecuteAsync(arguments, CancellationToken.None, fixture.Clock, TextWriter.Null, TextWriter.Null)).IsEqualTo(1);
        await Assert.That(File.Exists(arguments[7])).IsFalse();
        File.SetUnixFileMode(privateKey, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var unsignedBytes = File.ReadAllBytes(unsigned);
        File.WriteAllText(unsigned, Encoding.UTF8.GetString(unsignedBytes) + new string(' ', 96 * 1024 - unsignedBytes.Length));
        // The maximum payload can exceed the envelope bound after base64 encoding.
        await Assert.That(await OciFoundingGrantCli.ExecuteAsync(arguments, CancellationToken.None, fixture.Clock, TextWriter.Null, TextWriter.Null)).IsEqualTo(1);
        await Assert.That(File.Exists(arguments[7])).IsFalse();
        await Assert.That(fixture.Transport.Reads).IsEqualTo(0);
    }

    [Test]
    [Arguments("extra-peer")]
    [Arguments("same-address")]
    [Arguments("same-fault-domain")]
    [Arguments("excessive-lifetime")]
    [Arguments("excessive-capacity")]
    [Arguments("wrong-region")]
    [Arguments("wrong-purpose")]
    public async Task A_valid_signature_cannot_expand_the_fixed_founding_contract(string change)
    {
        if (!OperatingSystem.IsLinux()) return;
        using var fixture = new Fixture();
        var plan = change switch
        {
            "extra-peer" => fixture.Plan with { Peers = [.. fixture.Plan.Peers, fixture.Plan.Peers[0] with { Slot = "peer-3" }] },
            "same-address" => fixture.Plan with { Peers = [fixture.Plan.Peers[0], fixture.Plan.Peers[1] with { PrivateIp = fixture.Plan.Peers[0].PrivateIp }] },
            "same-fault-domain" => fixture.Plan with { Peers = [fixture.Plan.Peers[0], fixture.Plan.Peers[1] with { FaultDomain = fixture.Plan.Peers[0].FaultDomain }] },
            "excessive-lifetime" => fixture.Plan with { ExpiresAt = fixture.Plan.NotBefore.AddHours(2) },
            "excessive-capacity" => fixture.Plan with { Ocpus = 80 },
            "wrong-region" => fixture.Plan with { Region = "SFO" },
            _ => fixture.Plan with { Purpose = "general-oci-administration" }
        };
        fixture.WritePlan(plan);
        await Assert.That(await fixture.Execute()).IsEqualTo(1);
        await Assert.That(fixture.Transport.Reads).IsEqualTo(0);
        await Assert.That(fixture.Transport.Launches.Count).IsEqualTo(0);
    }

    [Test]
    public async Task Signed_command_creates_exactly_two_private_peers_then_only_observes_on_restart()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var fixture = new Fixture();
        using var output = new StringWriter();
        await Assert.That(await fixture.Execute(output)).IsEqualTo(2);
        await Assert.That(fixture.Transport.Launches.Count).IsEqualTo(2);
        foreach (var request in fixture.Transport.Launches)
        {
            var launch = request.LaunchInstanceDetails;
            await Assert.That(launch.CreateVnicDetails.AssignPublicIp).IsFalse();
            await Assert.That(launch.InstanceOptions.AreLegacyImdsEndpointsDisabled).IsTrue();
            await Assert.That(launch.CompartmentId).IsEqualTo(fixture.Plan.CompartmentId);
            await Assert.That(launch.FreeformTags["terrascale-owner"]).IsEqualTo("orchestrator");
            await Assert.That(launch.CreateVnicDetails.PrivateIp).IsNotEqualTo("10.20.0.10");
        }
        output.GetStringBuilder().Clear();
        await Assert.That(await fixture.Execute(output)).IsEqualTo(0);
        using var status = JsonDocument.Parse(output.ToString());
        await Assert.That(status.RootElement.GetProperty("state").GetString()).IsEqualTo("peers-running");
        await Assert.That(status.RootElement.GetProperty("needs").EnumerateArray().Select(item => item.GetString()!))
            .IsEquivalentTo(["regional-nats-quorum", "controller-admission", "seed-ownership-handoff"]);
        fixture.Clock.Now = fixture.Plan.ExpiresAt.AddDays(1);
        await Assert.That(await fixture.Execute()).IsEqualTo(0); // Observing completed peers needs no fresh create grant.
        await Assert.That(fixture.Transport.Launches.Count).IsEqualTo(2);
        await Assert.That(fixture.Transport.Terminations).IsEqualTo(0);
    }

    [Test]
    public async Task Lost_launch_response_and_missing_listing_reuse_the_exact_retry_token_after_restart()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var fixture = new Fixture();
        fixture.Transport.LoseFirstResponse = true;
        fixture.Transport.HideListing = true;
        await Assert.That(await fixture.Execute()).IsEqualTo(1);
        await Assert.That(await fixture.Execute()).IsEqualTo(2);
        await Assert.That(fixture.Transport.Launches[0].OpcRetryToken).IsEqualTo(fixture.Transport.Launches[1].OpcRetryToken);
        await Assert.That(fixture.Transport.Peers.Count).IsEqualTo(2);
        await Assert.That(await fixture.Execute()).IsEqualTo(0);
        await Assert.That(fixture.Transport.Launches.Count).IsEqualTo(3);
    }

    [Test]
    public async Task Loss_of_local_receipt_recovers_exact_provider_peers_without_another_launch()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var fixture = new Fixture();
        await Assert.That(await fixture.Execute()).IsEqualTo(2);
        File.Delete(Path.Combine(fixture.StateDirectory, "founding.json"));
        await Assert.That(await fixture.Execute()).IsEqualTo(0);
        await Assert.That(fixture.Transport.Launches.Count).IsEqualTo(2);
    }

    [Test]
    [Arguments("expired")]
    [Arguments("not-yet-valid")]
    [Arguments("wrong-node")]
    [Arguments("wrong-seed-owner")]
    [Arguments("public-seed")]
    public async Task Invalid_authority_or_seed_binding_never_launches(string condition)
    {
        if (!OperatingSystem.IsLinux()) return;
        using var fixture = new Fixture();
        if (condition == "expired") fixture.Clock.Now = fixture.Plan.ExpiresAt;
        if (condition == "not-yet-valid") fixture.Clock.Now = fixture.Plan.NotBefore.AddSeconds(-1);
        if (condition == "wrong-seed-owner") fixture.Transport.Seed.FreeformTags["ManagedBy"] = "orchestrator";
        if (condition == "public-seed") fixture.Transport.PublicSeed = true;
        await Assert.That(await fixture.Execute(localId: condition == "wrong-node" ? "other-node" : null)).IsEqualTo(1);
        await Assert.That(fixture.Transport.Launches.Count).IsEqualTo(0);
    }

    [Test]
    public async Task Expiration_after_a_lost_response_does_not_issue_a_new_create()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var fixture = new Fixture();
        fixture.Transport.LoseFirstResponse = true;
        fixture.Transport.HideListing = true;
        await Assert.That(await fixture.Execute()).IsEqualTo(1);
        fixture.Clock.Now = fixture.Plan.ExpiresAt;
        await Assert.That(await fixture.Execute()).IsEqualTo(1);
        await Assert.That(fixture.Transport.Launches.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("wrong-image")]
    [Arguments("wrong-address")]
    [Arguments("wrong-owner")]
    [Arguments("wrong-bootstrap")]
    [Arguments("terminated")]
    [Arguments("public-peer")]
    public async Task Peer_drift_never_becomes_readiness_or_authority_to_replace(string drift)
    {
        if (!OperatingSystem.IsLinux()) return;
        using var fixture = new Fixture();
        await Assert.That(await fixture.Execute()).IsEqualTo(2);
        var peer = fixture.Transport.Peers.Values.First();
        if (drift == "wrong-image") peer.ImageId = "other-image";
        if (drift == "wrong-owner") peer.FreeformTags["terrascale-owner"] = "ts-infra";
        if (drift == "wrong-bootstrap") peer.Metadata["user_data"] = "different";
        if (drift == "terminated") peer.LifecycleState = Instance.LifecycleStateEnum.Terminated;
        if (drift == "wrong-address") fixture.Transport.WrongPeerAddress = true;
        if (drift == "public-peer") fixture.Transport.PublicPeer = true;
        await Assert.That(await fixture.Execute()).IsEqualTo(1);
        await Assert.That(fixture.Transport.Launches.Count).IsEqualTo(2);
        await Assert.That(fixture.Transport.Terminations).IsEqualTo(0);
    }

    [Test]
    public async Task Tampering_generation_rollback_and_a_different_grant_are_rejected_before_provider_calls()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var fixture = new Fixture();
        var original = File.ReadAllText(fixture.PlanPath);
        var envelope = JsonSerializer.Deserialize<OciFoundingPlan.SignedPlan>(original, OciFoundingPlan.JsonOptions)!;
        File.WriteAllText(fixture.PlanPath, JsonSerializer.Serialize(envelope with { Signature = Convert.ToBase64String(new byte[64]) }, OciFoundingPlan.JsonOptions));
        await Assert.That(await fixture.Execute()).IsEqualTo(1);
        File.WriteAllText(fixture.PlanPath, original);
        fixture.WritePlan(fixture.Plan with { RegionIntentGeneration = 2 });
        await Assert.That(await fixture.Execute()).IsEqualTo(1);
        await Assert.That(fixture.Transport.Reads).IsEqualTo(0);
        fixture.WritePlan(fixture.Plan);
        await Assert.That(await fixture.Execute()).IsEqualTo(2);
        var reads = fixture.Transport.Reads;
        fixture.WritePlan(fixture.Plan with { BootstrapId = new string('b', 32) });
        await Assert.That(await fixture.Execute()).IsEqualTo(1);
        await Assert.That(fixture.Transport.Reads).IsEqualTo(reads);
    }

    [Test]
    public async Task Concurrent_invocation_cannot_acquire_the_same_state_receipt()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var fixture = new Fixture();
        var plan = OciFoundingPlan.Load(fixture.PlanPath, fixture.TrustPath, OciRegionIntent.Load(fixture.IntentPath));
        using var first = OciFoundingState.Open(fixture.StateDirectory, plan);
        await Assert.That(await fixture.Execute()).IsEqualTo(1);
        await Assert.That(fixture.Transport.Reads).IsEqualTo(0);
    }

    [Test]
    public async Task Provider_error_bodies_are_not_written_to_operator_output()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var fixture = new Fixture();
        fixture.Transport.LoseFirstResponse = true;
        using var error = new StringWriter();
        await Assert.That(await fixture.Execute(error: error)).IsEqualTo(1);
        await Assert.That(error.ToString()).DoesNotContain("synthetic-sensitive-provider-body");
    }

    private sealed class Fixture : IDisposable
    {
        private const UnixFileMode PrivateDirectory = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        private readonly DirectoryInfo root;
        private readonly ECDsa signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        internal Fixture()
        {
            if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
            root = Directory.CreateTempSubdirectory("ts-orch-founding-");
            File.SetUnixFileMode(root.FullName, PrivateDirectory);
            StateDirectory = Path.Combine(root.FullName, "state");
            Directory.CreateDirectory(StateDirectory, PrivateDirectory);
            IntentPath = Path.Combine(root.FullName, "intent.json");
            PlanPath = Path.Combine(root.FullName, "plan.json");
            TrustPath = Path.Combine(root.FullName, "trust.pem");
            File.WriteAllText(IntentPath, """{"schemaVersion":1,"generation":1,"bootstrapRegion":"GRU","regions":[{"cell":"GRU","ociRegion":"sa-saopaulo-1"}]}""");
            File.SetUnixFileMode(IntentPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.WriteAllText(TrustPath, signer.ExportSubjectPublicKeyInfoPem());
            Clock = new() { Now = new(2026, 9, 20, 0, 0, 0, TimeSpan.Zero) };
            var bootstrap = Encoding.UTF8.GetBytes("#cloud-config\nruncmd: []\n");
            OciFoundingPeer Peer(int slot) => new($"peer-{slot}", $"10.20.0.{10 + slot}", $"FAULT-DOMAIN-{slot + 1}",
                Convert.ToBase64String(bootstrap), Convert.ToHexStringLower(SHA256.HashData(bootstrap)));
            Plan = new(1, OciFoundingPlan.GrantPurpose, new string('a', 32), 1, "GRU",
                "ocid1.instance.oc1.sa-saopaulo-1.seed", "ocid1.compartment.oc1..control", "TEST:SA-SAOPAULO-1-AD-1", "FAULT-DOMAIN-1",
                "ocid1.subnet.oc1.sa-saopaulo-1.control", ["ocid1.networksecuritygroup.oc1.sa-saopaulo-1.control"],
                "ocid1.image.oc1.sa-saopaulo-1.pinned", 1, 8, Clock.Now.AddMinutes(-1), Clock.Now.AddMinutes(30), [Peer(1), Peer(2)]);
            WritePlan(Plan);
            Transport = new(Plan);
        }

        internal string StateDirectory { get; }
        internal string IntentPath { get; }
        internal string PlanPath { get; }
        internal string TrustPath { get; }
        internal OciFoundingPlan Plan { get; }
        internal Clock Clock { get; }
        internal Transport Transport { get; }
        internal void WritePlan(OciFoundingPlan plan)
        {
            var payload = JsonSerializer.SerializeToUtf8Bytes(plan, OciFoundingPlan.JsonOptions);
            var signature = signer.SignData(OciFoundingPlan.SigningBytes(payload), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            File.WriteAllText(PlanPath, JsonSerializer.Serialize(new OciFoundingPlan.SignedPlan(Convert.ToBase64String(payload), Convert.ToBase64String(signature)), OciFoundingPlan.JsonOptions));
        }
        internal Task<int> Execute(TextWriter? output = null, string? localId = null, TextWriter? error = null) =>
            OciFoundingPeersCli.ExecuteAsync(["--plan", PlanPath, "--trust-key", TrustPath, "--region-intent", IntentPath, "--state-dir", StateDirectory],
                CancellationToken.None, _ => Task.FromResult(localId ?? Plan.SeedInstanceId), () => Transport, Clock, output ?? TextWriter.Null, error ?? TextWriter.Null);
        public void Dispose() { signer.Dispose(); root.Delete(recursive: true); }
    }

    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now { get; set; }
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class Transport : IOciCiRunnerComputeTransport
    {
        private readonly OciFoundingPlan plan;
        private readonly Dictionary<string, string> tokens = new(StringComparer.Ordinal);
        internal Transport(OciFoundingPlan plan)
        {
            this.plan = plan;
            Seed = new()
            {
                Id = plan.SeedInstanceId,
                CompartmentId = plan.CompartmentId,
                AvailabilityDomain = plan.AvailabilityDomain,
                FaultDomain = plan.SeedFaultDomain,
                LifecycleState = Instance.LifecycleStateEnum.Running,
                FreeformTags = new() { ["ManagedBy"] = "ts-infra", ["Role"] = "initial-controller", ["Region"] = "GRU" }
            };
        }
        internal Instance Seed { get; }
        internal Dictionary<string, Instance> Peers { get; } = new(StringComparer.Ordinal);
        internal List<LaunchInstanceRequest> Launches { get; } = [];
        internal int Reads { get; private set; }
        internal int Terminations { get; private set; }
        internal bool LoseFirstResponse { get; set; }
        internal bool HideListing { get; set; }
        internal bool PublicSeed { get; set; }
        internal bool PublicPeer { get; set; }
        internal bool WrongPeerAddress { get; set; }

        public Task<ListInstancesResponse> ListInstancesAsync(ListInstancesRequest request, CancellationToken cancellationToken)
        {
            Reads++;
            return Task.FromResult(new ListInstancesResponse { Items = HideListing ? [] : Peers.Values.Where(peer => peer.DisplayName == request.DisplayName).ToList() });
        }
        public Task<GetInstanceResponse> GetInstanceAsync(GetInstanceRequest request, CancellationToken cancellationToken)
        {
            Reads++;
            return Task.FromResult(new GetInstanceResponse { Instance = request.InstanceId == Seed.Id ? Seed : Peers[request.InstanceId] });
        }
        public Task<ListVnicAttachmentsResponse> ListVnicAttachmentsAsync(ListVnicAttachmentsRequest request, CancellationToken cancellationToken) =>
            Task.FromResult(new ListVnicAttachmentsResponse
            {
                Items = [new() { InstanceId = request.InstanceId, CompartmentId = plan.CompartmentId, AvailabilityDomain = plan.AvailabilityDomain,
                    SubnetId = plan.SubnetId, NicIndex = 0, LifecycleState = VnicAttachment.LifecycleStateEnum.Attached, VnicId = request.InstanceId + "-vnic" }]
            });
        public Task<GetVnicResponse> GetVnicAsync(GetVnicRequest request, CancellationToken cancellationToken)
        {
            var seed = request.VnicId == Seed.Id + "-vnic";
            var instance = seed ? Seed : Peers[request.VnicId[..^5]];
            var slot = seed ? null : instance.FreeformTags["terrascale-founding-slot"];
            return Task.FromResult(new GetVnicResponse
            {
                Vnic = new()
                {
                    Id = request.VnicId,
                    CompartmentId = plan.CompartmentId,
                    AvailabilityDomain = plan.AvailabilityDomain,
                    SubnetId = plan.SubnetId,
                    IsPrimary = true,
                    LifecycleState = Vnic.LifecycleStateEnum.Available,
                    NsgIds = plan.NetworkSecurityGroupIds.ToList(),
                    PrivateIp = seed ? "10.20.0.10" : WrongPeerAddress ? "10.20.0.99" : plan.Peers.Single(peer => peer.Slot == slot).PrivateIp,
                    PublicIp = seed ? PublicSeed ? "203.0.113.1" : null : PublicPeer ? "203.0.113.2" : null
                }
            });
        }
        public Task<LaunchInstanceResponse> LaunchInstanceAsync(LaunchInstanceRequest request, CancellationToken cancellationToken)
        {
            Launches.Add(request);
            if (!tokens.TryGetValue(request.OpcRetryToken, out var id))
            {
                var launch = request.LaunchInstanceDetails;
                id = $"ocid1.instance.oc1.sa-saopaulo-1.peer-{Peers.Count + 1}";
                tokens.Add(request.OpcRetryToken, id);
                Peers.Add(id, new()
                {
                    Id = id,
                    DisplayName = launch.DisplayName,
                    CompartmentId = launch.CompartmentId,
                    AvailabilityDomain = launch.AvailabilityDomain,
                    FaultDomain = launch.FaultDomain,
                    Shape = launch.Shape,
                    ShapeConfig = new() { Ocpus = launch.ShapeConfig.Ocpus, MemoryInGBs = launch.ShapeConfig.MemoryInGBs },
                    ImageId = plan.ImageId,
                    SourceDetails = launch.SourceDetails,
                    Metadata = launch.Metadata,
                    FreeformTags = launch.FreeformTags,
                    InstanceOptions = new() { AreLegacyImdsEndpointsDisabled = true },
                    LaunchOptions = new() { IsPvEncryptionInTransitEnabled = true },
                    LifecycleState = Instance.LifecycleStateEnum.Running
                });
            }
            if (LoseFirstResponse)
            {
                LoseFirstResponse = false;
                throw new IOException("synthetic-sensitive-provider-body");
            }
            return Task.FromResult(new LaunchInstanceResponse { Instance = Peers[id] });
        }
        public Task<TerminateInstanceResponse> TerminateInstanceAsync(TerminateInstanceRequest request, CancellationToken cancellationToken)
        {
            Terminations++;
            throw new InvalidOperationException("Founding must never terminate a resource.");
        }
        public void Dispose() { }
    }
}
