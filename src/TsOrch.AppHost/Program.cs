using Aspire.Hosting;

var builder = DistributedApplication.CreateBuilder(args);

await using var app = builder.Build();
await app.RunAsync();
