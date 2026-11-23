using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace TsOrch.Agent;

public static class AgentServiceCollectionExtensions
{
    extension(IServiceCollection services)
    {
        public IServiceCollection AddTsOrchAgent(Action<AgentOptions> configure)
        {
            ArgumentNullException.ThrowIfNull(configure);
            services.AddOptions<AgentOptions>().Configure(configure).ValidateOnStart();
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<AgentOptions>, AgentOptionsValidator>());
            services.TryAddSingleton(TimeProvider.System);
            services.AddHttpClient(NodeEnrollment.BackplaneClientName, static client => client.Timeout = TimeSpan.FromSeconds(30));
            services.AddHttpClient(ContainerSwapper.ProbeClientName, static client => client.Timeout = TimeSpan.FromSeconds(5));
            services.AddHttpClient(NodeMaintenance.DownloadClientName, static client => client.Timeout = Timeout.InfiniteTimeSpan);
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
}
