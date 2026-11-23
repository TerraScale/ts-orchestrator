using Microsoft.Extensions.DependencyInjection;

namespace TsOrch.Agent;

public static class AgentServiceCollectionExtensions
{
    extension(IServiceCollection services)
    {
        public IServiceCollection AddTsOrchAgent()
        {
            services.AddSingleton(TimeProvider.System);
            return services;
        }
    }
}
