namespace TsOrch.Edge;

public static class EdgeServiceCollectionExtensions
{
    extension(IServiceCollection services)
    {
        public IServiceCollection AddTsOrchEdge()
        {
            services.AddHttpForwarder();
            services.AddSingleton(TimeProvider.System);
            return services;
        }
    }
}
