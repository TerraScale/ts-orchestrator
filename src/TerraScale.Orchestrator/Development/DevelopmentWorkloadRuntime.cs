using System.Collections;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace TerraScale.Orchestrator.Development;

internal static class DevelopmentWorkloadRuntime
{
    private const string ProductProjectId = "01C00000000000000000000002";

    public static async Task StartAsync(
        DevelopmentProcessSupervisor supervisor,
        DevelopmentTopology topology,
        string workspaceRoot,
        string dataDirectory,
        DevelopmentNatsSecurity natsSecurity,
        CancellationToken cancellationToken)
    {
        var internalsRoot = Path.Combine(workspaceRoot, "TerraScale.Internals");
        var dashboardRoot = Path.Combine(workspaceRoot, "TerraScale.Dashboard");
        var terraBaseRoot = Path.Combine(workspaceRoot, "TerraBase");
        RequireDirectory(internalsRoot, "TerraScale.Internals repository");
        RequireDirectory(dashboardRoot, "TerraScale.Dashboard repository");
        RequireDirectory(terraBaseRoot, "TerraBase repository");

        var paymentEnvironment = ReadPaymentEnvironment();

        foreach (var cell in topology.Cells)
        {
            foreach (var member in cell.OfKind(DevelopmentResourceKind.TerraBase))
            {
                StartTerraBase(supervisor, member, terraBaseRoot, dataDirectory);
            }
        }
        foreach (var cell in topology.Cells)
        {
            await BootstrapTerraBaseAsync(cell.OfKind(DevelopmentResourceKind.TerraBase), supervisor, cancellationToken);
        }

        foreach (var cell in topology.Cells)
        {
            var authentication = cell.OfKind(DevelopmentResourceKind.Authentication).Single();
            StartDotNetService(
                supervisor,
                authentication,
                Path.Combine(internalsRoot, "src", "Auth", "TerraScale.Authentication", "TerraScale.Authentication.csproj"),
                CreateServiceEnvironment(
                    topology, cell, authentication, isPlatform: false, dataDirectory, natsSecurity, paymentEnvironment),
                dataDirectory);
            await WaitHttpAsync(authentication.Port, "/health/ready", supervisor, cancellationToken);

            var dashboard = cell.OfKind(DevelopmentResourceKind.Dashboard).Single();
            StartDashboard(supervisor, topology, cell, dashboard, dataDirectory, natsSecurity);
            await WaitHttpAsync(dashboard.Port, "/health/ready", supervisor, cancellationToken);
        }
    }


    private static void StartTerraBase(
        DevelopmentProcessSupervisor supervisor,
        DevelopmentResourcePlan resource,
        string terraBaseRoot,
        string dataDirectory)
    {
        var project = Path.Combine(terraBaseRoot, "src", "TerraBase.Server", "TerraBase.Server.csproj");
        RequireFile(project, "TerraBase server project");
        var projectDirectory = DevelopmentGuards.RequireDirectory(project, "TerraBase project");
        var resourceData = Path.Combine(dataDirectory, "workloads", resource.Name);
        Directory.CreateDirectory(resourceData);
        var tag = ((char)('A' + resource.Replica - 1)).ToString();
        var serverArguments = CreateTerraBaseServerArguments(resource, resourceData);
        var assembly = Path.Combine(
            DevelopmentArtifactBuilder.DotNetOutputDirectory(dataDirectory, "TerraBase.Server"),
            "TerraBase.Server.dll");
        RequireFile(assembly, "published TerraBase assembly");
        var arguments = new[] { "dotnet", assembly }.Concat(serverArguments).ToArray();
        supervisor.Start(
            resource.Name,
            DevelopmentContainerImages.For(resource.Kind),
            arguments,
            projectDirectory,
            new Dictionary<string, string?> { ["TERRABASE_NODE_TAG"] = tag });
    }

    /// <summary>
    /// TerraBase launch flags for the rootless DevHost lab. Cluster timeouts are
    /// raised above production defaults so cold restarts under pasta + multi-DB
    /// load do not demote the sole RF=1 member before maintenance samples recover.
    /// </summary>
    internal static IReadOnlyList<string> CreateTerraBaseServerArguments(
        DevelopmentResourcePlan resource,
        string resourceData) =>
    [
        $"--ServerUrl=http://0.0.0.0:{resource.Port}",
        $"--ServerUrl.Tcp=tcp://127.0.0.1:{resource.SecondaryPort}",
        $"--PublicServerUrl=http://127.0.0.1:{resource.Port}",
        $"--PublicServerUrl.Tcp=tcp://127.0.0.1:{resource.SecondaryPort}",
        $"--PublicServerUrl.Tcp.Cluster=tcp://127.0.0.1:{resource.SecondaryPort}",
        $"--PublicServerUrl.Tcp.External=tcp://127.0.0.1:{resource.SecondaryPort}",
        $"--DataDir={resourceData}",
        $"--Logs.NuGet.PackagesPath={Path.Combine(resourceData, "packages", "logging")}",
        $"--Indexing.NuGetPackagesPath={Path.Combine(resourceData, "packages", "indexing")}",
        "--Security.UnsecuredAccessAllowed=PublicNetwork",
        "--Features.Availability=Experimental",
        // Defaults are 5s receive / 60s rehab grace — too tight for lab cold start.
        "--Cluster.ReceiveFromWorkerTimeoutInMs=30000",
        "--Cluster.OnErrorDelayTimeInMs=2000",
        "--Cluster.TcpTimeoutInMs=30000",
        "--Cluster.TimeBeforeMovingToRehabInSec=300"
    ];

    private static void StartDotNetService(
        DevelopmentProcessSupervisor supervisor,
        DevelopmentResourcePlan resource,
        string project,
        IReadOnlyDictionary<string, string?> environment,
        string dataDirectory)
    {
        RequireFile(project, $"{resource.Kind} project");
        var directory = DevelopmentGuards.RequireDirectory(project, $"{resource.Kind} project");
        var projectName = Path.GetFileNameWithoutExtension(project);
        var assembly = Path.Combine(
            DevelopmentArtifactBuilder.DotNetOutputDirectory(dataDirectory, projectName),
            projectName + ".dll");
        RequireFile(assembly, $"published {resource.Kind} assembly");
        supervisor.Start(
            resource.Name,
            DevelopmentContainerImages.AspNet,
            ["dotnet", assembly],
            directory,
            environment);
    }

    private static void StartDashboard(
        DevelopmentProcessSupervisor supervisor,
        DevelopmentTopology topology,
        DevelopmentCellPlan cell,
        DevelopmentResourcePlan dashboard,
        string dataDirectory,
        DevelopmentNatsSecurity natsSecurity)
    {
        var directory = DevelopmentDashboardArtifact.Resolve(dataDirectory);
        var authentication = cell.OfKind(DevelopmentResourceKind.Authentication).Single();
        var certificateBundle = natsSecurity.Cell(cell.Cell).Tls.Product.Clients[
            ProductWorkloadClientName(cell)].CaFile;
        var cache = Path.Combine(dataDirectory, "workloads", dashboard.Name, "vite-task-cache");
        Directory.CreateDirectory(cache);
        supervisor.Start(
            dashboard.Name,
            DevelopmentContainerImages.Node,
            ["node", .. CreateDashboardArguments(dashboard)],
            directory,
            CreateDashboardEnvironment(topology, dashboard, authentication, dashboard, certificateBundle, cache));
    }

    internal static string ProductWorkloadClientName(DevelopmentCellPlan cell)
    {
        var dashboard = cell.OfKind(DevelopmentResourceKind.Dashboard).SingleOrDefault();
        return dashboard?.Name ?? cell.OfKind(DevelopmentResourceKind.Platform).Single().Name;
    }

    internal static IReadOnlyDictionary<string, string?> CreateDashboardEnvironment(
        DevelopmentTopology topology,
        DevelopmentResourcePlan dashboardApi,
        DevelopmentResourcePlan authentication,
        DevelopmentResourcePlan dashboard,
        string certificateBundle,
        string cache,
        Func<string, string?>? getEnvironmentVariable = null) =>
        new Dictionary<string, string?>
        {
            ["HOST"] = "127.0.0.1",
            ["PORT"] = dashboard.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["NODE_ENV"] = "production",
            ["SSL_CERT_FILE"] = certificateBundle,
            ["VITE_CACHE_PATH"] = cache,
            ["OTEL_EXPORTER_OTLP_ENDPOINT"] = string.Empty,
            ["OpenTelemetry__OtlpEndpoint"] = string.Empty,
            // Server-side Dashboard/Auth stay on pod loopback; only the browser-facing
            // public origin uses DevHost Tailscale MagicDNS when injected.
            // A tailnet URL is injected when DevHost publishes one; otherwise
            // retain the in-pod loopback contract used by focused tests.
            ["TERRASCALE_API_BASE_URL"] = DevelopmentPublicSurfaces.PublicDashboardApiUrl(
                getEnvironmentVariable) ?? Http(dashboardApi.Port),
            ["TERRASCALE_AUTH_API_BASE_URL"] = DevelopmentPublicSurfaces.PublicAuthenticationUrl(
                getEnvironmentVariable) ?? Http(authentication.Port),
            ["TERRASCALE_DASHBOARD_PUBLIC_URL"] = DevelopmentPublicSurfaces.ResolveDashboardPublicUrl(
                dashboard.Port,
                getEnvironmentVariable),
            ["TERRASCALE_DEVELOPMENT_PAYMENT_BYPASS"] = "true",
            ["TERRASCALE_REGIONS"] = string.Join(',', topology.Cells.Select(candidate => candidate.Cell))
        };

    internal static IReadOnlyList<string> CreateDashboardArguments(DevelopmentResourcePlan dashboard) =>
    [
        "server.js"
    ];

    internal static Dictionary<string, string?> CreateServiceEnvironment(
        DevelopmentTopology topology,
        DevelopmentCellPlan cell,
        DevelopmentResourcePlan resource,
        bool isPlatform,
        string dataDirectory,
        DevelopmentNatsSecurity? natsSecurity = null,
        IReadOnlyDictionary<string, string?>? paymentEnvironment = null)
    {
        var dashboard = cell.OfKind(DevelopmentResourceKind.Dashboard).Single();
        var productNats = cell.OfKind(DevelopmentResourceKind.ProductNats)[0];
        var productIdentity = natsSecurity?.Cell(cell.Cell).Product;
        var productTls = isPlatform
            ? natsSecurity?.Cell(cell.Cell).Tls.Product.Clients[resource.Name]
            : null;
        var serviceHome = Path.Combine(dataDirectory, "workloads", resource.Name, "home");
        var environment = new Dictionary<string, string?>
        {
            ["ASPNETCORE_HTTP_PORTS"] = string.Empty,
            ["HOME"] = serviceHome,
            ["DOTNET_CLI_HOME"] = serviceHome,
            ["ASPNETCORE_ENVIRONMENT"] = "Development",
            ["DOTNET_ENVIRONMENT"] = "Development",
            ["Kestrel__EndpointDefaults__Protocols"] = "Http1AndHttp2",
            ["Jwt__Secret"] = "dev-only-terrascale-jwt-secret-key-minimum-32-bytes!",
            ["Jwt__Issuer"] = "https://api.terrascale.tech",
            ["Jwt__Audience"] = "terrascale",
            ["ProjectAuthStorage__CredentialDerivationKey"] = "dev-only-project-auth-credential-derivation-key-v1!",
            ["ProjectAuthStorage__CredentialDerivationKeyVersion"] = "1",
            ["ProjectAuthStorage__Mode"] = "Project",
            ["Logging__LogLevel__Default"] = "Warning",
            ["Logging__LogLevel__Microsoft.AspNetCore"] = "Warning",
            // Readiness is polled while the product bootstrap is still converging.
            // DefaultHealthCheckService logs every expected Unhealthy response at
            // Error, even though the Orchestrator correctly treats it as pending.
            ["Logging__LogLevel__Microsoft.Extensions.Diagnostics.HealthChecks.DefaultHealthCheckService"] = "Critical",
            ["OTEL_EXPORTER_OTLP_ENDPOINT"] = string.Empty,
            ["OpenTelemetry__OtlpEndpoint"] = string.Empty,
            // No email server runs in the lab: delivery renders and logs instead of
            // sending, and Auth__AutoVerifyEmail keeps signup/login free of the
            // email-verification challenge flow.
            ["Email__Provider"] = "Disabled",
            ["Routing__CurrentRegion"] = cell.Cell,
            ["TerraScale__Kestrel__Urls"] = $"http://0.0.0.0:{resource.Port}",
            // Keep the persisted logical database name stable while the owning
            // implementation is now hosted by the full-stack Dashboard.
            ["TerraScale__ServiceDatabases__Platform"] = "TerraScale.Platform",
            ["TerraScale__ServiceDatabases__Authentication"] = "TerraScale.Authentication",
            ["TerraScale__ServiceDatabases__Payments"] = "TerraScale.Payments",
            ["TerraScale__ServiceDatabases__Queue"] = "TerraScale.Queue",
            ["TerraScale__ServiceDatabases__OwnerEmail"] = "mariogk@terrascale.tech",
            ["TerraScale__ServiceDatabases__OrganizationName"] = "TerraScale",
            ["TerraScale__ServiceDatabases__ProjectName"] = "TerraScale",
            ["TerraScale__ServiceDatabases__ProjectId"] = ProductProjectId,
            ["TerraScale__ServiceDatabases__AllowReducedDevelopmentTopology"] = "true",
            ["TerraScale__ServiceDatabases__ShardCount"] = "1",
            ["TerraScale__ServiceDatabases__ReplicationFactor"] = "1",
            ["TerraScale__ServiceDatabases__DynamicNodesDistribution"] = "true"
        };
        // Private MagicOnion HTTP/2 listener (SecondaryPort) remains available for
        // Authentication's existing internal service contract. The Vinext Dashboard
        // has no private listener and is addressed through its public loopback URL.
        if (resource.SecondaryPort is int secondaryPort && secondaryPort > 0)
        {
            environment["TerraScale__Kestrel__InternalRpcPort"] =
                secondaryPort.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        var members = cell.OfKind(DevelopmentResourceKind.TerraBase);
        for (var index = 0; index < members.Count; index++)
        {
            environment[$"TerraBase__Urls__{index}"] = Http(members[index].Port);
        }
        for (var index = 0; index < topology.Cells.Count; index++)
        {
            environment[$"Routing__AllowedRegions__{index}"] = topology.Cells[index].Cell;
            environment[$"TerraScale__ServiceDatabases__Regions__{index}"] = topology.Cells[index].Cell;
            var regionalApi = topology.Cells[index].OfKind(DevelopmentResourceKind.Platform).SingleOrDefault()
                ?? topology.Cells[index].OfKind(DevelopmentResourceKind.Dashboard).Single();
            environment[$"Routing__RegionApiBaseUrls__{topology.Cells[index].Cell}"] =
                Http(regionalApi.Port);
        }
        // Authentication requires its own region's InternalRpc endpoint at
        // startup (live error: "InternalRpc:RegionalEndpoints:{region} is
        // required by Authentication."), so it needs the current cell's
        // Dashboard endpoint before the early return — exactly that one
        // endpoint, never every regional endpoint. Platform adds the full
        // regional map itself in its own branch below.
        var currentPlatform = cell.OfKind(DevelopmentResourceKind.Platform).SingleOrDefault();
        var currentDashboard = cell.OfKind(DevelopmentResourceKind.Dashboard).Single();
        var currentPlatformPort = currentPlatform?.SecondaryPort ?? currentDashboard.Port;
        environment[$"InternalRpc__RegionalEndpoints__{cell.Cell}"] = Http(currentPlatformPort);

        if (!isPlatform)
        {
            environment["OpenIddict__Issuer"] = $"https://{cell.Cell}-auth.terrascale.local";
            environment["Auth__UseRealProviders"] = "true";
            environment["Auth__TestOAuthProvider__Enabled"] = "true";
            environment["Auth__AutoVerifyEmail"] = "true";
            environment["ExternalLogins__Providers__google__ClientId"] = "google-client-id";
            environment["ExternalLogins__Providers__google__ClientSecret"] = "google-client-secret";
            return environment;
        }

        environment["TERRASCALE_DASHBOARD_TESTS"] = "true";
        environment["TerraScale__Billing__BillingManagementUrl"] = "https://dashboard.terrascale.test/settings/billing";
        environment["InternalAuth__ApiKey"] = "test_internal_auth_api_key";
        environment["Fido2__ServerDomain"] = "localhost";
        environment["Fido2__Origins__0"] = "http://localhost";
        environment["Fido2__Origins__1"] = Http(resource.Port);
        environment["Fido2__Origins__2"] = Http(dashboard.Port);
        environment["Cors__AllowedOrigins__0"] = "http://localhost";
        environment["Cors__AllowedOrigins__1"] = Http(dashboard.Port);
        // When DevHost publishes the product dashboard on MagicDNS HTTPS, browsers
        // present that origin to Platform. Accept it alongside loopback so cookie
        // and CORS checks succeed for tailnet clients.
        var publicDashboardOrigin = DevelopmentPublicSurfaces.PublicDashboardUrl();
        var dashboardOrigin = publicDashboardOrigin ?? Http(dashboard.Port);
        if (publicDashboardOrigin is not null)
        {
            environment["Fido2__Origins__3"] = publicDashboardOrigin;
            environment["Cors__AllowedOrigins__2"] = publicDashboardOrigin;
            // Prefer the public host for WebAuthn rpId when available (hostname only).
            if (Uri.TryCreate(publicDashboardOrigin, UriKind.Absolute, out var publicUri) &&
                !string.IsNullOrWhiteSpace(publicUri.Host) &&
                !string.Equals(publicUri.Host, "localhost", StringComparison.OrdinalIgnoreCase) &&
                publicUri.Host is not "127.0.0.1")
            {
                environment["Fido2__ServerDomain"] = publicUri.Host;
            }
        }
        environment["Routing__ForwardUnplacedRequests"] = "true";
        environment["QueueReplication__SharedSecret"] = "test_project_queue_replication_key";
        environment["QueueReplication__RequestTimeoutMilliseconds"] = "900";
        environment["Payments__Provider"] = "polar";
        environment["Payments__Polar__ApiBaseUrl"] = "https://sandbox-api.polar.sh";
        environment["Payments__Polar__CheckoutSuccessUrl"] =
            $"{dashboardOrigin}/onboarding?payment=success";
        environment["Payments__Polar__CheckoutReturnUrl"] = $"{dashboardOrigin}/onboarding";
        environment["Payments__Polar__PortalReturnUrl"] =
            $"{dashboardOrigin}/onboarding?payment=success";
        environment["Payments__Development__Enabled"] = "true";
        if (paymentEnvironment is not null)
        {
            foreach (var (key, value) in paymentEnvironment)
            {
                environment[key] = value;
            }
        }
        if (environment["Payments__Provider"] is { } selectedPaymentProvider)
        {
            if (selectedPaymentProvider.Equals("polar", StringComparison.OrdinalIgnoreCase))
            {
                var hasPolarCredential = HasNonEmptySetting(
                    paymentEnvironment,
                    "Payments__Polar__AccessToken") ||
                    HasNonEmptySetting(paymentEnvironment, "Payments__Polar__AccessTokenFile");
                var polarExplicitlyDisabled = TryGetSetting(
                    paymentEnvironment,
                    "Payments__Polar__Enabled",
                    out var polarEnabledSetting) &&
                    bool.TryParse(polarEnabledSetting, out var polarEnabled) &&
                    !polarEnabled;
                environment["Payments__Polar__Enabled"] =
                    hasPolarCredential && !polarExplicitlyDisabled ? "true" : "false";
                if (hasPolarCredential)
                {
                    environment.TryAdd("Payments__Polar__WebhookSecret", "devhost-local-webhook-secret");
                }
            }
            else
            {
                environment[$"Payments__{selectedPaymentProvider}__Enabled"] = "true";
            }
        }
        environment["Idempotency__RequireForInternalCalls"] = "true";
        // The legacy Platform branch is retained for callers constructing a
        // compatibility topology; the regional production Dashboard is Vinext and
        // has no MagicOnion endpoint.
        // AuthenticationEndpoint is required at startup (ValidateOnStart); RegionalEndpoints
        // cover queue replication and regional request streaming.
        var authentication = cell.OfKind(DevelopmentResourceKind.Authentication).Single();
        if (authentication.SecondaryPort is not int authenticationPort || authenticationPort <= 0)
        {
            throw new InvalidOperationException(
                $"Authentication resource '{authentication.Name}' is missing SecondaryPort for InternalRpc.");
        }
        environment["InternalRpc__AuthenticationEndpoint"] = Http(authenticationPort);
        environment["InternalRpc__LocalPublicEndpoint"] = Http(resource.Port);
        foreach (var regionalCell in topology.Cells)
        {
            var regionalPlatform = regionalCell.OfKind(DevelopmentResourceKind.Platform).SingleOrDefault();
            var regionalDashboard = regionalCell.OfKind(DevelopmentResourceKind.Dashboard).Single();
            var regionalPlatformPort = regionalPlatform?.SecondaryPort ?? regionalDashboard.Port;
            environment[$"InternalRpc__RegionalEndpoints__{regionalCell.Cell}"] =
                Http(regionalPlatformPort);
        }
        environment["TerraScale__Queue__Provider"] = "Nats";
        environment["TerraScale__Queue__NatsUrl"] = $"nats://127.0.0.1:{productNats.Port}";
        environment["TerraScale__Queue__NatsUsername"] = productIdentity?.Username;
        environment["TerraScale__Queue__NatsPassword"] = productIdentity?.Password;
        environment["TerraScale__Queue__RequireTls"] = productTls is null ? null : "true";
        environment["TerraScale__Queue__TlsCaFile"] = productTls?.CaFile;
        environment["TerraScale__Queue__TlsCertificateFile"] = productTls?.CertificateFile;
        environment["TerraScale__Queue__TlsKeyFile"] = productTls?.KeyFile;
        environment["TerraScale__Queue__SubjectPrefix"] = $"terrascale.devhost.{cell.Cell}";
        environment["TerraScale__Queue__StreamReplicas"] = "1";
        environment["TerraScale__Queue__ConsumerReplicas"] = "1";
        // Internals defaults operation-metering PublishTimeout to 100ms. The product
        // NATS client reconnect floor is 250ms and a cold TLS JetStream publish after
        // connect is commonly 50-80ms here; under reconnect or lab contention the
        // 100ms budget cancels the PubAck wait (TaskCanceledException), falls back
        // to the TerraBase outbox, and emits a Warning even though NATS is healthy.
        // Two seconds still bounds the post-response metering path while surviving
        // one reconnect + publish cycle on the regional product plane.
        environment["TerraScale__Billing__OperationMetering__PublishTimeout"] = "00:00:02";
        environment["TerraScale__Backups__Provider"] = "LocalFolder";
        environment["TerraScale__Backups__LocalFolderPath"] = Path.Combine(dataDirectory, "backups", cell.Cell);
        environment["TerraScale__Backups__OperationPollSeconds"] = "1";
        return environment;
    }

    private static IReadOnlyDictionary<string, string?> ReadPaymentEnvironment()
    {
        var values = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            if (entry.Key is string key &&
                key.StartsWith("Payments__", StringComparison.OrdinalIgnoreCase))
            {
                values[key] = entry.Value?.ToString();
            }
        }

        return values;
    }

    private static bool HasNonEmptySetting(
        IReadOnlyDictionary<string, string?>? settings,
        string name) =>
        TryGetSetting(settings, name, out var value) && !string.IsNullOrWhiteSpace(value);

    private static bool TryGetSetting(
        IReadOnlyDictionary<string, string?>? settings,
        string name,
        out string? value)
    {
        if (settings is not null)
        {
            foreach (var setting in settings)
            {
                if (setting.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    value = setting.Value;
                    return true;
                }
            }
        }

        value = null;
        return false;
    }

    private static async Task BootstrapTerraBaseAsync(
        IReadOnlyList<DevelopmentResourcePlan> members,
        DevelopmentProcessSupervisor supervisor,
        CancellationToken cancellationToken)
    {
        foreach (var member in members)
        {
            await WaitHttpAsync(
                member.Port,
                $"/info/tcp?tag={(char)('A' + member.Replica - 1)}",
                supervisor,
                cancellationToken);
        }

        using var client = new HttpClient
        {
            BaseAddress = new Uri(Http(members[0].Port)),
            Timeout = TimeSpan.FromSeconds(15)
        };
        var topology = await ReadTopologyAsync(client, cancellationToken);
        if (!members.All(member => topology.ContainsKey(((char)('A' + member.Replica - 1)).ToString())))
        {
            await SendUntilAppliedAsync(
                client,
                HttpMethod.Post,
                "/admin/cluster/bootstrap?tag=A",
                members[0],
                cancellationToken);
            foreach (var member in members.Skip(1))
            {
                var tag = ((char)('A' + member.Replica - 1)).ToString();
                var path = $"/admin/cluster/node?url={Uri.EscapeDataString(Http(member.Port))}&tag={tag}";
                await SendUntilAppliedAsync(client, HttpMethod.Put, path, member, cancellationToken);
            }
        }

        await WaitForPlacementSupportAsync(client, supervisor, cancellationToken);
    }

    private static async Task WaitForPlacementSupportAsync(
        HttpClient client,
        DevelopmentProcessSupervisor supervisor,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(5));
        while (true)
        {
            supervisor.ThrowIfAnyExited();
            try
            {
                using var response = await client.GetAsync(
                    "/databases?start=0&pageSize=1&placementOnly=true",
                    timeout.Token);
                if (response.IsSuccessStatusCode)
                {
                    await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
                    using var document = await JsonDocument.ParseAsync(stream, cancellationToken: timeout.Token);
                    if (TryGetProperty(document.RootElement, "DatabasePlacementSupported", out var supported) &&
                        supported.ValueKind == JsonValueKind.True)
                    {
                        return;
                    }
                }
            }
            catch (Exception exception) when (
                exception is HttpRequestException or JsonException or TaskCanceledException &&
                !timeout.IsCancellationRequested)
            {
            }
            await Task.Delay(TimeSpan.FromMilliseconds(500), timeout.Token);
        }
    }

    private static async Task SendUntilAppliedAsync(
        HttpClient client,
        HttpMethod method,
        string path,
        DevelopmentResourcePlan member,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(5));
        var tag = ((char)('A' + member.Replica - 1)).ToString();
        while (true)
        {
            try
            {
                using var request = new HttpRequestMessage(method, path);
                using var response = await client.SendAsync(request, timeout.Token);
                var topology = await ReadTopologyAsync(client, timeout.Token);
                if (response.IsSuccessStatusCode || topology.ContainsKey(tag))
                {
                    return;
                }
            }
            catch (HttpRequestException)
            {
            }
            await Task.Delay(TimeSpan.FromSeconds(1), timeout.Token);
        }
    }

    private static async Task<IReadOnlyDictionary<string, string>> ReadTopologyAsync(
        HttpClient client,
        CancellationToken cancellationToken)
    {
        try
        {
            using var response = await client.GetAsync("/cluster/topology?clientIndependent=true", cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return new Dictionary<string, string>();
            }
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            if (!TryGetProperty(document.RootElement, "Topology", out var topology) ||
                !TryGetProperty(topology, "Members", out var members) ||
                members.ValueKind != JsonValueKind.Object)
            {
                return new Dictionary<string, string>();
            }
            return members.EnumerateObject().ToDictionary(
                property => property.Name,
                property => property.Value.GetString() ?? string.Empty,
                StringComparer.OrdinalIgnoreCase);
        }
        catch (HttpRequestException)
        {
            return new Dictionary<string, string>();
        }
    }

    private static bool TryGetProperty(JsonElement element, string name, out JsonElement value)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (property.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    value = property.Value;
                    return true;
                }
            }
        }
        value = default;
        return false;
    }

    private static async Task WaitHttpAsync(
        int port,
        string path,
        DevelopmentProcessSupervisor supervisor,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(10));
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        while (true)
        {
            supervisor.ThrowIfAnyExited();
            try
            {
                using var response = await client.GetAsync(Http(port, path), timeout.Token);
                if (response.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (Exception exception) when (
                exception is HttpRequestException or TaskCanceledException &&
                !timeout.IsCancellationRequested)
            {
            }
            await Task.Delay(TimeSpan.FromMilliseconds(500), timeout.Token);
        }
    }

    private static string Http(int port, string suffix = "") => $"http://127.0.0.1:{port}{suffix}";

    private static void RequireFile(string path, string description)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Could not find {description} at {path}.", path);
        }
    }

    private static void RequireDirectory(string path, string description)
    {
        if (!Directory.Exists(path))
        {
            throw new DirectoryNotFoundException($"Could not find {description} at {path}.");
        }
    }
}
