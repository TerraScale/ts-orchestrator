namespace TsOrch.Edge;

public static class EdgeServiceCollectionExtensions
{
    extension(IServiceCollection services)
    {
        public IServiceCollection AddTsOrchEdge(EdgeServerOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);
            services.AddSingleton(options);
            services.AddSingleton(TimeProvider.System);
            services.AddHttpForwarder();
            services.AddSingleton<UpstreamCircuitBreaker>();
            services.AddSingleton<EdgeRouteTable>();
            services.AddSingleton<TlsCertificateStore>();
            services.AddSingleton<EdgeMetricsCollector>();
            services.AddSingleton<EdgeDrainCoordinator>();
            services.AddSingleton<EdgeProxy>();
            services.AddSingleton<PostgresSniConnectionHandler>();
            services.AddHostedService(static provider => provider.GetRequiredService<EdgeRouteTable>());
            services.AddHostedService(static provider => provider.GetRequiredService<TlsCertificateStore>());
            services.AddHostedService(static provider => provider.GetRequiredService<EdgeMetricsCollector>());
            services.AddHostedService(static provider => provider.GetRequiredService<EdgeDrainCoordinator>());
            return services;
        }
    }
}
