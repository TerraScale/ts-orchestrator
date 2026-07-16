namespace TerraScale.Orchestrator.Protocol;

internal static class ProtocolExceptionPolicy
{
    internal static bool IsFatal(Exception? exception) =>
        exception is OutOfMemoryException or StackOverflowException or AccessViolationException;
}
