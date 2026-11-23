using Microsoft.Extensions.DependencyInjection;
using TsOrch.Oci;

namespace TsOrch.Agent;

public static class AgentServiceCollectionExtensions
{
    public const string OciClientName = "ts-orch-oci";

    extension(IServiceCollection services)
    {
        public IServiceCollection AddTsOrchAgent(AgentOptions options, OciEnvironment ociEnvironment, TimeProvider timeProvider)
        {
            ArgumentNullException.ThrowIfNull(options);
            ArgumentNullException.ThrowIfNull(ociEnvironment);
            ArgumentNullException.ThrowIfNull(timeProvider);
            services.AddSingleton(options);
            services.AddSingleton(ociEnvironment);
            services.AddSingleton(timeProvider);
            services.AddHttpClient(OciClientName, static client => client.Timeout = TimeSpan.FromSeconds(30));
            services.AddHttpClient(NodeEnrollment.BackplaneClientName, static client => client.Timeout = TimeSpan.FromSeconds(30));
            services.AddHttpClient(ContainerSwapper.ProbeClientName, static client => client.Timeout = TimeSpan.FromSeconds(5));
            services.AddHttpClient(NodeMaintenance.DownloadClientName, static client => client.Timeout = Timeout.InfiniteTimeSpan);
            services.AddSingleton(static provider => new OciImdsClient(OciHttpClient(provider), provider.GetRequiredService<OciEnvironment>()));
            services.AddSingleton<OciRequestSigner>();
            services.AddSingleton(static provider => new OciInstancePrincipal(
                OciHttpClient(provider),
                provider.GetRequiredService<OciEnvironment>(),
                provider.GetRequiredService<OciImdsClient>(),
                provider.GetRequiredService<OciRequestSigner>(),
                provider.GetRequiredService<TimeProvider>()));
            services.AddSingleton(static provider => new OciVaultClient(
                OciHttpClient(provider),
                provider.GetRequiredService<OciEnvironment>(),
                provider.GetRequiredService<OciImdsClient>(),
                provider.GetRequiredService<OciInstancePrincipal>()));
            services.AddSingleton<DockerEngineClient>();
            services.AddSingleton<AgentOutbox>();
            services.AddSingleton<PlacementTracker>();
            services.AddSingleton<RouteObserver>();
            services.AddSingleton<SecretStore>();
            services.AddSingleton<ImageHistoryStore>();
            services.AddSingleton<ContainerSwapper>();
            services.AddSingleton<ContainerReconciler>();
            services.AddSingleton<ImageGarbageCollector>();
            services.AddSingleton<HostMetricsCollector>();
            services.AddSingleton<NodeMaintenance>();
            services.AddSingleton<NodeEnrollment>();
            services.AddSingleton<EdgeConfigWriter>();
            services.AddSingleton<ContainerSessions>();
            services.AddSingleton<NodeReportComposer>();
            services.AddSingleton<BackplaneDispatcher>();
            services.AddSingleton<NodeAgentRunner>();
            services.AddHostedService(static provider => provider.GetRequiredService<ContainerReconciler>());
            services.AddHostedService(static provider => provider.GetRequiredService<ImageGarbageCollector>());
            services.AddHostedService(static provider => provider.GetRequiredService<NodeMaintenance>());
            services.AddHostedService(static provider => provider.GetRequiredService<NodeAgentRunner>());
            return services;
        }
    }

    private static HttpClient OciHttpClient(IServiceProvider provider) =>
        provider.GetRequiredService<IHttpClientFactory>().CreateClient(OciClientName);
}
