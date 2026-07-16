using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace TerraScale.Orchestrator.Development;

internal static class DevelopmentWorkloadRuntime
{
    private const string ProductProjectId = "01C00000000000000000000002";
    private const string DashboardClientId = "terrascale-dashboard";

    public static async Task StartAsync(
        DevelopmentProcessSupervisor supervisor,
        DevelopmentTopology topology,
        string workspaceRoot,
        string dataDirectory,
        bool watch,
        CancellationToken cancellationToken)
    {
        var internalsRoot = Path.Combine(workspaceRoot, "TerraScale.Internals");
        var terraBaseRoot = Path.Combine(workspaceRoot, "TerraBase");
        RequireDirectory(internalsRoot, "TerraScale.Internals repository");
        RequireDirectory(terraBaseRoot, "TerraBase repository");

        StartEmulators(supervisor, topology, internalsRoot);
        await WaitHttpAsync(topology.GlobalResources.Single(resource =>
            resource.Kind == DevelopmentResourceKind.EmailEmulator).Port, "/health/ready", supervisor, cancellationToken);
        await WaitHttpAsync(topology.GlobalResources.Single(resource =>
            resource.Kind == DevelopmentResourceKind.StripeEmulator).Port, "/health/ready", supervisor, cancellationToken);

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
                watch,
                CreateServiceEnvironment(topology, cell, authentication, isApi: false, dataDirectory));
            await WaitHttpAsync(authentication.Port, "/health/ready", supervisor, cancellationToken);

            var api = cell.OfKind(DevelopmentResourceKind.Api).Single();
            StartDotNetService(
                supervisor,
                api,
                Path.Combine(internalsRoot, "src", "API", "TerraScale.API", "TerraScale.API.csproj"),
                watch,
                CreateServiceEnvironment(topology, cell, api, isApi: true, dataDirectory));
            await WaitHttpAsync(api.Port, "/health/ready", supervisor, cancellationToken);

            var dashboard = cell.OfKind(DevelopmentResourceKind.Dashboard).Single();
            StartDashboard(supervisor, topology, cell, dashboard, internalsRoot, watch);
            await WaitHttpAsync(dashboard.Port, "/api/stack", supervisor, cancellationToken);
        }
    }

    private static void StartEmulators(
        DevelopmentProcessSupervisor supervisor,
        DevelopmentTopology topology,
        string internalsRoot)
    {
        var project = Path.Combine(
            internalsRoot,
            "src",
            "Hosting",
            "TerraScale.LocalEmulators",
            "TerraScale.LocalEmulators.csproj");
        RequireFile(project, "local emulator project");
        foreach (var resource in topology.GlobalResources)
        {
            var mode = resource.Kind switch
            {
                DevelopmentResourceKind.EmailEmulator => "email",
                DevelopmentResourceKind.StripeEmulator => "stripe",
                _ => throw new InvalidOperationException($"Unsupported global development role {resource.Kind}.")
            };
            supervisor.Start(
                resource.Name,
                "dotnet",
                ["run", "--no-launch-profile", "--project", project, "--", mode],
                Path.GetDirectoryName(project)!,
                new Dictionary<string, string?>
                {
                    ["PORT"] = resource.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["Logging__LogLevel__Default"] = "Warning",
                    ["Logging__LogLevel__Microsoft.AspNetCore"] = "Warning"
                });
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
        var projectDirectory = Path.GetDirectoryName(project)!;
        var resourceData = Path.Combine(dataDirectory, "workloads", resource.Name);
        Directory.CreateDirectory(resourceData);
        var tag = ((char)('A' + resource.Replica - 1)).ToString();
        var serverArguments = new[]
        {
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
            "--Features.Availability=Experimental"
        };
        var assembly = new[]
        {
            Path.Combine(projectDirectory, "bin", "Debug", "net10.0", "TerraBase.Server.dll"),
            Path.Combine(projectDirectory, "bin", "Release", "net10.0", "TerraBase.Server.dll")
        }.FirstOrDefault(File.Exists);
        var arguments = assembly is null
            ? new[] { "run", "--no-launch-profile", "--project", project, "--" }.Concat(serverArguments).ToArray()
            : new[] { "exec", assembly }.Concat(serverArguments).ToArray();
        supervisor.Start(
            resource.Name,
            "dotnet",
            arguments,
            projectDirectory,
            new Dictionary<string, string?> { ["TERRABASE_NODE_TAG"] = tag });
    }

    private static void StartDotNetService(
        DevelopmentProcessSupervisor supervisor,
        DevelopmentResourcePlan resource,
        string project,
        bool watch,
        IReadOnlyDictionary<string, string?> environment)
    {
        RequireFile(project, $"{resource.Kind} project");
        var arguments = watch
            ? new[] { "watch", "--quiet", "--non-interactive", "run", "--no-launch-profile", "--project", project }
            : new[] { "run", "--no-launch-profile", "--project", project };
        supervisor.Start(resource.Name, "dotnet", arguments, Path.GetDirectoryName(project)!, environment);
    }

    private static void StartDashboard(
        DevelopmentProcessSupervisor supervisor,
        DevelopmentTopology topology,
        DevelopmentCellPlan cell,
        DevelopmentResourcePlan dashboard,
        string internalsRoot,
        bool watch)
    {
        var directory = Path.Combine(internalsRoot, "src", "Dashboard", "TerraScale.Dashboard.Next");
        RequireDirectory(directory, "Dashboard project");
        var vp = Path.Combine(directory, "node_modules", ".bin", "vp");
        if (!File.Exists(vp))
        {
            vp = "vp";
        }
        var api = cell.OfKind(DevelopmentResourceKind.Api).Single();
        var authentication = cell.OfKind(DevelopmentResourceKind.Authentication).Single();
        supervisor.Start(
            dashboard.Name,
            vp,
            watch ? ["run", "vinext:dev"] : ["run", "vinext:start"],
            directory,
            new Dictionary<string, string?>
            {
                ["HOST"] = "127.0.0.1",
                ["PORT"] = dashboard.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["NODE_ENV"] = watch ? "development" : "production",
                ["OTEL_EXPORTER_OTLP_ENDPOINT"] = string.Empty,
                ["OpenTelemetry__OtlpEndpoint"] = string.Empty,
                ["TERRASCALE_API_BASE_URL"] = Http(api.Port),
                ["TERRASCALE_AUTH_API_BASE_URL"] = Http(authentication.Port),
                ["TERRASCALE_DASHBOARD_PUBLIC_URL"] = Http(dashboard.Port),
                ["TERRASCALE_DASHBOARD_CLIENT_ID"] = DashboardClientId,
                ["TERRASCALE_DASHBOARD_PROJECT_ID"] = ProductProjectId,
                ["TERRASCALE_DASHBOARD_TENANT_ID"] = string.Empty,
                ["TERRASCALE_DASHBOARD_DATABASE_IDS"] = string.Empty,
                ["TERRASCALE_REGIONS"] = string.Join(',', topology.Cells.Select(candidate => candidate.Cell))
            });
    }

    internal static Dictionary<string, string?> CreateServiceEnvironment(
        DevelopmentTopology topology,
        DevelopmentCellPlan cell,
        DevelopmentResourcePlan resource,
        bool isApi,
        string dataDirectory)
    {
        var email = topology.GlobalResources.Single(candidate => candidate.Kind == DevelopmentResourceKind.EmailEmulator);
        var stripe = topology.GlobalResources.Single(candidate => candidate.Kind == DevelopmentResourceKind.StripeEmulator);
        var authentication = cell.OfKind(DevelopmentResourceKind.Authentication).Single();
        var dashboard = cell.OfKind(DevelopmentResourceKind.Dashboard).Single();
        var productNats = cell.OfKind(DevelopmentResourceKind.ProductNats).First();
        var environment = new Dictionary<string, string?>
        {
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
            ["OTEL_EXPORTER_OTLP_ENDPOINT"] = string.Empty,
            ["OpenTelemetry__OtlpEndpoint"] = string.Empty,
            ["Email__Cloudflare__AccountId"] = "test-account",
            ["Email__Cloudflare__ApiToken"] = "test-token",
            ["Email__Cloudflare__FromAddress"] = "auth@terrascale.local",
            ["Email__DefaultFromAddress"] = "noreply@terrascale.local",
            ["Email__DefaultFromName"] = "TerraScale",
            ["Email__Cloudflare__BaseUrl"] = Http(email.Port, "/client/v4/"),
            ["Routing__CurrentRegion"] = cell.Cell,
            ["TerraScale__Kestrel__Urls"] = $"http://0.0.0.0:{resource.Port}",
            ["TerraScale__ServiceDatabases__Dashboard"] = "TerraScale.Dashboard",
            ["TerraScale__ServiceDatabases__Authentication"] = "TerraScale.Authentication",
            ["TerraScale__ServiceDatabases__Payments"] = "TerraScale.Payments",
            ["TerraScale__ServiceDatabases__Queue"] = "TerraScale.Queue",
            ["TerraScale__ServiceDatabases__OwnerEmail"] = "mariogk@terrascale.tech",
            ["TerraScale__ServiceDatabases__OrganizationName"] = "TerraScale",
            ["TerraScale__ServiceDatabases__ProjectName"] = "TerraScale",
            ["TerraScale__ServiceDatabases__ProjectId"] = ProductProjectId,
            ["TerraScale__ServiceDatabases__AllowReducedDevelopmentTopology"] = "false",
            ["TerraScale__ServiceDatabases__ShardCount"] = "3",
            ["TerraScale__ServiceDatabases__ReplicationFactor"] = "3",
            ["TerraScale__ServiceDatabases__DynamicNodesDistribution"] = "true"
        };
        var members = cell.OfKind(DevelopmentResourceKind.TerraBase);
        for (var index = 0; index < members.Count; index++)
        {
            environment[$"TerraBase__Urls__{index}"] = Http(members[index].Port);
        }
        for (var index = 0; index < topology.Cells.Count; index++)
        {
            environment[$"Routing__AllowedRegions__{index}"] = topology.Cells[index].Cell;
            environment[$"TerraScale__ServiceDatabases__Regions__{index}"] = topology.Cells[index].Cell;
            environment[$"Routing__RegionApiBaseUrls__{topology.Cells[index].Cell}"] =
                Http(topology.Cells[index].OfKind(DevelopmentResourceKind.Api).Single().Port);
        }

        if (!isApi)
        {
            environment["OpenIddict__Issuer"] = $"https://{cell.Cell}-auth.terrascale.local";
            environment["Auth__UseRealProviders"] = "true";
            environment["Auth__TestOAuthProvider__Enabled"] = "true";
            environment["Auth__AutoVerifyEmail"] = "true";
            environment["DashboardExternalLogins__Providers__google__ClientId"] = "google-client-id";
            environment["DashboardExternalLogins__Providers__google__ClientSecret"] = "google-client-secret";
            return environment;
        }

        environment["TERRASCALE_DASHBOARD_TESTS"] = "true";
        environment["TerraScale__Billing__DashboardBillingUrl"] = "https://dashboard.terrascale.test/settings/billing";
        environment["InternalAuth__ApiKey"] = "test_internal_auth_api_key";
        environment["Fido2__ServerDomain"] = "localhost";
        environment["Fido2__Origins__0"] = "http://localhost";
        environment["Fido2__Origins__1"] = Http(resource.Port);
        environment["Fido2__Origins__2"] = Http(dashboard.Port);
        environment["Cors__DashboardOrigins__0"] = "http://localhost";
        environment["Cors__DashboardOrigins__1"] = Http(dashboard.Port);
        environment["Services__Dashboard__BaseUrl"] = Http(dashboard.Port);
        environment["Routing__ForwardUnplacedRequests"] = "true";
        environment["QueueReplication__SharedSecret"] = "test_project_queue_replication_key";
        environment["QueueReplication__RequestTimeoutMilliseconds"] = "900";
        environment["Payments__Stripe__WebhookSecret"] = "whsec_devhost_local";
        environment["Payments__Stripe__SecretKey"] = "sk_test_devhost_local";
        environment["Payments__Stripe__ApiBaseUrl"] = Http(stripe.Port);
        environment["Idempotency__RequireForInternalCalls"] = "true";
        environment["AuthenticationService__BaseUrl"] = Http(authentication.Port);
        environment["TerraScale__Queue__Provider"] = "Nats";
        environment["TerraScale__Queue__NatsUrl"] = $"nats://127.0.0.1:{productNats.Port}";
        environment["TerraScale__Queue__SubjectPrefix"] = $"terrascale.devhost.{cell.Cell}";
        environment["TerraScale__Queue__StreamReplicas"] = "3";
        environment["TerraScale__Queue__ConsumerReplicas"] = "3";
        environment["TerraScale__Backups__Provider"] = "LocalFolder";
        environment["TerraScale__Backups__LocalFolderPath"] = Path.Combine(dataDirectory, "backups", cell.Cell);
        environment["TerraScale__Backups__OperationPollSeconds"] = "1";
        environment["DashboardAdmin__OwnerEmails__0"] = "mariogk@terrascale.tech";
        return environment;
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
        if (members.All(member => topology.ContainsKey(((char)('A' + member.Replica - 1)).ToString())))
        {
            return;
        }

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
