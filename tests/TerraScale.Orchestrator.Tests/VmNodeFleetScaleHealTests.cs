using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TerraScale.Orchestrator.Nodes;
using TerraScale.Orchestrator.Scheduler;
using TerraScale.Orchestrator.Scheduler.Autoscaling;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// The live Firecracker lane: nodes are microVMs booting the pinned kernel
/// and prepared Ubuntu guest, each running a real TerraBase member from an
/// injected systemd unit, observed by the host over the mTLS peer listener.
/// Provisions a VM under autoscaler control, heals VM loss with a replacement
/// member, and drains plus retires under the replica drain-safety gate.
/// Gated by <c>TS_ORCH_LIVE_VM=1</c>: requires KVM, sudo for tap devices, and
/// the prepared guest inputs under <c>TS_ORCH_VM_INPUTS</c>.
/// </summary>
[NotInParallel("FirecrackerLive")]
public sealed class VmNodeFleetScaleHealTests
{
    [Test]
    public async Task VmFleetBootsHealsAndDrains()
    {
        Skip.Unless(
            Environment.GetEnvironmentVariable("TS_ORCH_LIVE_VM") == "1",
            "Set TS_ORCH_LIVE_VM=1 and TS_ORCH_VM_INPUTS=<prepared vm inputs directory> to run the Firecracker lane.");
        var inputs = RequirePreparedInputs();
        await using var lane = await VmLane.PrepareAsync(inputs, "GRU", subnetThirdOctet: 77);
        await using var fleet = new VmNodeFleet(lane.Options, lane.DescribeMember);
        var engine = new AutoscalerEngine(
            new AutoscalerConfig(
                minNodes: 1,
                maxNodes: 3,
                scaleUpHeadroomPercent: 30,
                scaleDownHeadroomPercent: 40,
                scaleUpConfirmTicks: 2,
                scaleDownConfirmTicks: 2,
                maxConcurrentProvisions: 2,
                flapSuppressionTicks: 0),
            new ReplicaDrainSafetyEvaluator(new DrainPolicy(maxLagBytes: 1_000_000)));
        var runtime = new AutoscalerRuntime(engine, fleet);

        // --- scale up: a provisioned node boots a microVM whose member is
        // healthy and observable from the host over mTLS.
        await fleet.ProvisionAsync(new NodeProvisionRequest(
            "vm-node-1", "greenfield", lane.Options.NodeCapacity, "vm lane bootstrap"));
        await Assert.That(fleet.IsMemberAlive("vm-node-1")).IsTrue();

        // --- auto-heal: VM power loss provisions a replacement member in a
        // fresh microVM and no node drains while the replica is down.
        fleet.KillMember("vm-node-1");
        await Assert.That(fleet.IsMemberAlive("vm-node-1")).IsFalse();
        var demand = new AllocationDemand("terrabase-member", "terrabase-member", true, new ResourceVector(
            cpu: 20, memory: 6_500_000_000, blockIo: 0, ephemeralDisk: 0, bandwidth: 0, pids: 2, fileDescriptors: 0, hugePages: 0));
        var healTicks = new List<IReadOnlyList<AutoscalerAction>>();
        for (var step = 0; step < 4; step++)
        {
            healTicks.Add(await runtime.StepAsync([demand]));
        }

        await Assert.That(fleet.IsMemberAlive("as-node-1")).IsTrue();
        await Assert.That(healTicks.SelectMany(actions => actions).OfType<AutoscalerAction.DrainNode>()).IsEmpty();

        // --- power-loss recovery: the killed VM's member must restart
        // healthy on its retained rootfs — recovery truncates the possibly
        // torn write-ahead log to the last committed frame instead of
        // failing every reopen.
        await fleet.RestartAsync("vm-node-1");
        await Assert.That(fleet.IsMemberAlive("vm-node-1")).IsTrue();

        // --- scale down: confirmed idle cordons, drains, and retires a node.
        await runtime.StepAsync([]);
        var scaleDown = await runtime.StepAsync([]);
        await Assert.That(scaleDown.OfType<AutoscalerAction.CordonNode>().SingleOrDefault()).IsNotNull();
        var drain = scaleDown.OfType<AutoscalerAction.DrainNode>().SingleOrDefault();
        await Assert.That(drain).IsNotNull();
        // The drain reached inside the guest: systemd stopped the member
        // cleanly before the microVM exited, not a hard power-off.
        await Assert.That(fleet.WasDrainedGracefully(drain!.NodeId)).IsTrue();
        var retire = await runtime.StepAsync([]);
        var retired = retire.OfType<AutoscalerAction.RetireNode>().SingleOrDefault();
        await Assert.That(retired).IsNotNull();
        await Assert.That(fleet.IsMemberAlive(retired.NodeId)).IsFalse();
        lane.Succeeded = true;
    }

    [Test]
    public async Task VmFleetRunsAuthAgainstTerraBaseAndRecoversDurableState()
    {
        Skip.Unless(
            Environment.GetEnvironmentVariable("TS_ORCH_LIVE_VM") == "1",
            "Set TS_ORCH_LIVE_VM=1 and TS_ORCH_VM_INPUTS=<prepared vm inputs directory> to run the Firecracker auth lane.");
        var inputs = RequirePreparedInputs();
        var authBinary = Path.Combine(inputs, "auth", "TerraScale.Auth");
        if (!File.Exists(authBinary))
        {
            throw new InvalidOperationException(
                $"The Firecracker auth lane requires a published ts-auth payload at {authBinary}.");
        }

        await using var lane = await VmLane.PrepareAsync(inputs, "GRU", subnetThirdOctet: 80, includeAuth: true);
        await using var fleet = new VmNodeFleet(lane.Options, lane.DescribeMember);
        await fleet.ProvisionAsync(new NodeProvisionRequest(
            "vm-node-1", "auth-with-terrabase", lane.Options.NodeCapacity, "combined service qualification"));

        using var auth = new HttpClient
        {
            BaseAddress = new Uri($"http://{lane.Options.AddressFor(1)}:8080"),
            Timeout = TimeSpan.FromSeconds(5),
        };
        await WaitForAuthReadinessAsync(auth);

        using (var create = CreateAuthInstanceRequest())
        using (var created = await auth.SendAsync(create))
        {
            await Assert.That(created.StatusCode).IsEqualTo(HttpStatusCode.Created);
        }

        // A hard VM stop takes both processes down without giving either
        // systemd unit a shutdown opportunity. The retained rootfs and
        // TerraBase WAL must recover before ts-auth can become ready again.
        fleet.KillMember("vm-node-1");
        await Assert.That(fleet.IsMemberAlive("vm-node-1")).IsFalse();
        await fleet.RestartAsync("vm-node-1");
        await Assert.That(fleet.IsMemberAlive("vm-node-1")).IsTrue();
        await WaitForAuthReadinessAsync(auth);

        using (var duplicate = CreateAuthInstanceRequest())
        using (var conflict = await auth.SendAsync(duplicate))
        {
            await Assert.That(conflict.StatusCode).IsEqualTo(HttpStatusCode.Conflict);
        }

        await fleet.DrainAsync("vm-node-1");
        await Assert.That(fleet.WasDrainedGracefully("vm-node-1")).IsTrue();
        await fleet.RetireAsync("vm-node-1");
        lane.Succeeded = true;
    }

    private static HttpRequestMessage CreateAuthInstanceRequest()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/v1/instances")
        {
            Content = JsonContent.Create(new { slug = "vm-auth", name = "Firecracker Auth" }),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "vm-auth-operator-key");
        return request;
    }

    private static async Task WaitForAuthReadinessAsync(HttpClient auth)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(3);
        HttpStatusCode? lastStatus = null;
        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                using var response = await auth.GetAsync("/readyz");
                lastStatus = response.StatusCode;
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    return;
                }
            }
            catch (HttpRequestException)
            {
            }
            catch (TaskCanceledException)
            {
            }

            await Task.Delay(500);
        }

        throw new TimeoutException($"ts-auth did not become ready in the Firecracker guest; last HTTP status was {lastStatus}.");
    }

    private static string RequirePreparedInputs() =>
        Environment.GetEnvironmentVariable("TS_ORCH_VM_INPUTS")
            ?? throw new InvalidOperationException("TS_ORCH_VM_INPUTS must point at the prepared vm lane inputs.");

    /// <summary>
    /// The multi-region Firecracker lane: three isolated region fleets, each on its own
    /// subnet and bridge with its own regional database and member cluster. A full region
    /// loss must not disturb the other regions, and the lost region heals itself with a
    /// replacement member — the multi-cluster, multi-region topology this control plane
    /// deploys, emulated on one host with real microVMs.
    /// </summary>
    [Test]
    public async Task VmFleetBootsThreeRegionsAndHealsRegionLoss()
    {
        Skip.Unless(
            Environment.GetEnvironmentVariable("TS_ORCH_LIVE_VM") == "1",
            "Set TS_ORCH_LIVE_VM=1 and TS_ORCH_VM_INPUTS=<prepared vm inputs directory> to run the Firecracker multi-region lane.");
        var inputs = RequirePreparedInputs();
        await using var gru = await VmLane.PrepareAsync(inputs, "GRU", subnetThirdOctet: 77);
        await using var sfo = await VmLane.PrepareAsync(inputs, "SFO", subnetThirdOctet: 78);
        await using var fra = await VmLane.PrepareAsync(inputs, "FRA", subnetThirdOctet: 79);
        await using var gruFleet = new VmNodeFleet(gru.Options, gru.DescribeMember);
        await using var sfoFleet = new VmNodeFleet(sfo.Options, sfo.DescribeMember);
        await using var fraFleet = new VmNodeFleet(fra.Options, fra.DescribeMember);

        // Each region boots one real member on its own isolated network. The prepared
        // guest inputs carry one fixed member identity set; each fleet gets its own copy,
        // so the same member names repeat inside isolated regional clusters.
        await gruFleet.ProvisionAsync(new NodeProvisionRequest(
            "vm-node-1", "gru", gru.Options.NodeCapacity, "multi-region bootstrap"));
        await sfoFleet.ProvisionAsync(new NodeProvisionRequest(
            "vm-node-1", "sfo", sfo.Options.NodeCapacity, "multi-region bootstrap"));
        await fraFleet.ProvisionAsync(new NodeProvisionRequest(
            "vm-node-1", "fra", fra.Options.NodeCapacity, "multi-region bootstrap"));
        await Assert.That(gruFleet.IsMemberAlive("vm-node-1")).IsTrue();
        await Assert.That(sfoFleet.IsMemberAlive("vm-node-1")).IsTrue();
        await Assert.That(fraFleet.IsMemberAlive("vm-node-1")).IsTrue();

        // Region loss: SFO's member dies hard; GRU and FRA never notice.
        sfoFleet.KillMember("vm-node-1");
        await Assert.That(sfoFleet.IsMemberAlive("vm-node-1")).IsFalse();
        await Assert.That(gruFleet.IsMemberAlive("vm-node-1")).IsTrue();
        await Assert.That(fraFleet.IsMemberAlive("vm-node-1")).IsTrue();

        // The lost region heals itself with a replacement member in a fresh microVM.
        var demand = new AllocationDemand("terrabase-member", "terrabase-member", true, new ResourceVector(
            cpu: 20, memory: 6_500_000_000, blockIo: 0, ephemeralDisk: 0, bandwidth: 0, pids: 2, fileDescriptors: 0, hugePages: 0));
        var engine = new AutoscalerEngine(
            new AutoscalerConfig(
                minNodes: 1,
                maxNodes: 3,
                scaleUpHeadroomPercent: 30,
                scaleDownHeadroomPercent: 40,
                scaleUpConfirmTicks: 2,
                scaleDownConfirmTicks: 2,
                maxConcurrentProvisions: 2,
                flapSuppressionTicks: 0),
            new ReplicaDrainSafetyEvaluator(new DrainPolicy(maxLagBytes: 1_000_000)));
        var sfoRuntime = new AutoscalerRuntime(engine, sfoFleet);
        for (var step = 0; step < 4; step++)
            await sfoRuntime.StepAsync([demand]);
        await Assert.That(sfoFleet.IsMemberAlive("as-node-1")).IsTrue();
        await Assert.That(gruFleet.IsMemberAlive("vm-node-1")).IsTrue();
        await Assert.That(fraFleet.IsMemberAlive("vm-node-1")).IsTrue();

        gru.Succeeded = true;
        sfo.Succeeded = true;
        fra.Succeeded = true;
    }

    private sealed class VmLane : IAsyncDisposable
    {
        private VmLane(string root, string region, VmFleetOptions options, string databaseId, string tenantId, string observerCertificate, string observerKey, string observerAuthority)
        {
            Root = root;
            Region = region;
            Options = options;
            DatabaseId = databaseId;
            TenantId = tenantId;
            ObserverCertificate = observerCertificate;
            ObserverKey = observerKey;
            ObserverAuthority = observerAuthority;
        }

        public string Root { get; }

        public string Region { get; }

        public VmFleetOptions Options { get; }

        public string DatabaseId { get; }

        public string TenantId { get; }

        public string ObserverCertificate { get; }

        public string ObserverKey { get; }

        public string ObserverAuthority { get; }

        public VmMemberDescription DescribeMember(NodeProvisionRequest request) => new(
            8422,
            new Dictionary<string, string>
            {
                ["TERRABASE_NODE_ID"] = request.NodeId,
                ["TERRABASE_REPLICA_EPOCH"] = "1",
                ["TERRABASE_REGION"] = Region,
                ["TERRABASE_MEMBER_CERT_FILE"] = $"/opt/payload/certs/{request.NodeId}.crt",
                ["TERRABASE_MEMBER_KEY_FILE"] = $"/opt/payload/certs/{request.NodeId}.key",
                ["TERRABASE_CLUSTER_CA_FILE"] = "/opt/payload/certs/ca.crt",
                // The other members plus the host-side observer identity, so
                // the fleet can probe every member over mTLS.
                ["TERRABASE_PEER_ALLOWLIST"] = "[" +
                    string.Join(",", new[] { "vm-node-1", "as-node-1", "as-node-2", "observer" }
                        .Where(member => member != request.NodeId)
                        .Select(member => $$"""{"fingerprint":"{{FingerprintOf(member)}}","memberId":"{{member}}","epoch":1,{{PeerUrlProperty(member)}}"databases":["{{DatabaseId}}"],"tenants":["{{TenantId}}"]}""")) +
                    "]",
                ["TERRABASE_INTERNAL_DATABASE_ID"] = DatabaseId,
                ["TERRABASE_DATABASE_ROUTE"] = "vm-lane-db",
                ["TERRABASE_DATABASE_TENANT"] = TenantId,
                ["TERRABASE_DATABASE_ULID"] = DatabaseId,
                ["TERRABASE_DATABASE_MODE"] = "explicit",
                ["TERRABASE_DATABASE_PATH"] = "/var/lib/terrabase",
                ["TERRABASE_DATABASE_BACKEND"] = "storage-engine",
                ["TERRABASE_DATABASE_HOME_REGION"] = Region,
                ["TERRABASE_DATABASE_SELECTED_REGIONS"] = Region,
            });

        private string PeerUrlProperty(string member) => member switch
        {
            "vm-node-1" => $"\"url\":\"https://{Options.AddressFor(1)}:8422\",",
            "as-node-1" => $"\"url\":\"https://{Options.AddressFor(2)}:8422\",",
            "as-node-2" => $"\"url\":\"https://{Options.AddressFor(3)}:8422\",",
            _ => string.Empty,
        };

        private string FingerprintOf(string member)
        {
            using var certificate = X509Certificate2.CreateFromPem(
                File.ReadAllText(Path.Combine(Root, "payload", "certs", $"{member}.crt")));
            return certificate.GetCertHashString(HashAlgorithmName.SHA256);
        }

        public static async Task<VmLane> PrepareAsync(
            string inputs,
            string region,
            int subnetThirdOctet,
            bool includeAuth = false)
        {
            var root = Path.Combine(Path.GetTempPath(), "orchestrator-vm-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            var host = Path.Combine(root, "payload", "host");
            CopyDirectory(Path.Combine(inputs, "host"), host);
            if (includeAuth)
            {
                CopyDirectory(Path.Combine(inputs, "auth"), Path.Combine(root, "payload", "auth"));
            }

            var certs = Path.Combine(root, "payload", "certs");
            VmFleetCertificates.Create(certs, subnetThirdOctet);

            var databaseId = LocalNodeFleetScaleHealTests.CanonicalUlid.New();
            var tenantId = LocalNodeFleetScaleHealTests.CanonicalUlid.New();
            var units = new List<(string UnitPath, string GuestName)>();
            var payloadUnit = Path.Combine(root, "terrabase-payload.service");
            await File.WriteAllTextAsync(payloadUnit, """
                [Unit]
                Description=Mount the TerraBase member payload disk
                After=local-fs.target
                Before=terrabase-member.service ts-auth.service

                [Service]
                Type=oneshot
                ExecStartPre=/bin/mkdir -p /opt/payload
                ExecStart=/bin/mount -t ext4 -o ro /dev/vdb /opt/payload
                RemainAfterExit=yes

                [Install]
                WantedBy=multi-user.target
                """);
            units.Add((payloadUnit, "terrabase-payload.service"));
            var memberUnit = Path.Combine(root, "terrabase-member.service");
            await File.WriteAllTextAsync(memberUnit, """
                [Unit]
                Description=TerraBase cluster member
                After=terrabase-payload.service systemd-networkd.service
                Requires=terrabase-payload.service
                Wants=systemd-networkd.service

                [Service]
                Type=simple
                EnvironmentFile=/opt/member.env
                # The peer listener binds the static eth0 address, so wait for
                # networkd to configure it before the member starts.
                ExecStartPre=/bin/sh -c 'for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do ip -4 addr show eth0 | grep -q " inet " && exec /bin/mkdir -p /var/lib/terrabase; sleep 1; done; exit 1'
                ExecStart=/opt/payload/host/TerraBase.Host
                StandardOutput=journal+console
                StandardError=journal+console
                Restart=on-failure
                RestartSec=2
                StartLimitIntervalSec=0

                [Install]
                WantedBy=multi-user.target
                """);
            units.Add((memberUnit, "terrabase-member.service"));
            if (includeAuth)
            {
                var authUnit = Path.Combine(root, "ts-auth.service");
                await File.WriteAllTextAsync(authUnit, $$"""
                    [Unit]
                    Description=TerraScale authentication service
                    After=terrabase-member.service
                    Requires=terrabase-member.service terrabase-payload.service

                    [Service]
                    Type=simple
                    Environment=DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
                    Environment=DOTNET_BUNDLE_EXTRACT_BASE_DIR=/var/tmp/ts-auth-bundle
                    Environment=ASPNETCORE_ENVIRONMENT=Production
                    Environment=TS_AUTH_LISTEN=http://0.0.0.0:8080
                    Environment=TS_AUTH_PUBLIC_ORIGIN=http://10.{{subnetThirdOctet}}.0.10:8080
                    Environment=TS_AUTH_TERRASCALE_API_URL=http://127.0.0.1:8420
                    Environment=TS_AUTH_TERRASCALE_API_KEY=vm-auth-api-key
                    Environment=TS_AUTH_DATABASE=vm-lane-db
                    Environment=TS_AUTH_MASTER_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
                    Environment=TS_AUTH_AUDIT_SIGNING_KEY=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
                    Environment=TS_AUTH_OPERATOR_KEY=vm-auth-operator-key
                    Environment=TS_AUTH_METRICS_KEY=vm-auth-metrics-key
                    ExecStart=/opt/payload/auth/TerraScale.Auth
                    StandardOutput=journal+console
                    StandardError=journal+console
                    Restart=on-failure
                    RestartSec=2
                    StartLimitIntervalSec=0

                    [Install]
                    WantedBy=multi-user.target
                    """);
                units.Add((authUnit, "ts-auth.service"));
            }

            var disabledMarker = Path.Combine(root, "cloud-init.disabled");
            await File.WriteAllTextAsync(disabledMarker, string.Empty);

            var payloadDisk = Path.Combine(root, "payload.ext4");
            var payloadBytes = Directory.EnumerateFiles(Path.Combine(root, "payload"), "*", SearchOption.AllDirectories)
                .Sum(file => new FileInfo(file).Length);
            var payloadSizeMib = Math.Max(420, checked((int)(payloadBytes / (1024 * 1024)) + 96));
            await RunAsync("truncate", $"-s {payloadSizeMib}M {payloadDisk}");
            await RunAsync("mkfs.ext4", $"-q -F -d {Path.Combine(root, "payload")} {payloadDisk}");

            var options = new VmFleetOptions
            {
                RootDirectory = root,
                KernelPath = Path.Combine(inputs, "vmlinux"),
                BaseRootfsPath = Path.Combine(inputs, "rootfs.ext4"),
                PayloadDiskPath = payloadDisk,
                FirecrackerPath = "/run/current-system/sw/bin/firecracker",
                DisabledMarkerPath = disabledMarker,
                GuestUnits = units,
                ObserverCertificatePath = Path.Combine(certs, "observer.crt"),
                ObserverKeyPath = Path.Combine(certs, "observer.key"),
                ObserverAuthorityPath = Path.Combine(certs, "ca.crt"),
                ReadinessTimeout = TimeSpan.FromSeconds(180),
            };
            return new VmLane(root, region, options with { SubnetThirdOctet = subnetThirdOctet }, databaseId, tenantId,
                Path.Combine(certs, "observer.crt"), Path.Combine(certs, "observer.key"), Path.Combine(certs, "ca.crt"));
        }

        public bool Succeeded { get; set; }

        public async ValueTask DisposeAsync()
        {
            // A failed lane keeps its working directory for diagnosis.
            if (Succeeded)
            {
                try
                {
                    Directory.Delete(Root, recursive: true);
                }
                catch (IOException)
                {
                }
            }

            await ValueTask.CompletedTask;
        }

        private static void CopyDirectory(string source, string destination)
        {
            Directory.CreateDirectory(destination);
            foreach (var directory in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories))
            {
                Directory.CreateDirectory(Path.Combine(destination, Path.GetRelativePath(source, directory)));
            }

            foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
            {
                var target = Path.Combine(destination, Path.GetRelativePath(source, file));
                File.Copy(file, target);
            }
        }

        private static async Task RunAsync(string fileName, string arguments)
        {
            using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardError = true,
            }) ?? throw new InvalidOperationException($"Could not run {fileName} {arguments}.");
            var exited = await Task.Run(() => process.WaitForExit(300_000), CancellationToken.None);
            if (!exited || process.ExitCode != 0)
            {
                throw new InvalidOperationException($"{fileName} {arguments} failed with {process.ExitCode}.");
            }
        }
    }
}
