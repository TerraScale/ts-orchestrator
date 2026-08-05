namespace TerraScale.Orchestrator.Messaging;

internal static class NatsProtocolPackage
{
    internal static readonly byte[] Bytes = """
        {"name":"terrascale-orchestrator","protocol":1}
        """u8.ToArray();
}
