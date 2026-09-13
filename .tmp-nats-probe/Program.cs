using System.Reflection;
using TerraScale.Orchestrator.Messaging;

try
{
    var method = typeof(NatsRuntime).GetMethod(
        "VerifyAnonymousDeniedAsync",
        BindingFlags.Static | BindingFlags.NonPublic)!;
    await (Task)method.Invoke(null, [args[0], null, CancellationToken.None])!;
    Console.WriteLine("denied");
}
catch (Exception exception)
{
    Console.WriteLine($"{exception.GetType().Name}: {exception.Message}");
    for (var inner = exception.InnerException; inner is not null; inner = inner.InnerException)
        Console.WriteLine($"inner={inner.GetType().Name}: {inner.Message}");
}
