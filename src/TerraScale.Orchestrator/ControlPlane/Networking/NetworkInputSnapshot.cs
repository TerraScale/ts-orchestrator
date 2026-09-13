namespace TerraScale.Orchestrator.ControlPlane.Networking;

/// <summary>Technical denial-of-service safety limits; these are not route, topology, or exposure policy.</summary>
public static class NetworkTechnicalLimits
{
    public const int MaximumCapturedItems = 4096;
}

internal static class NetworkInputSnapshot
{
    internal static T[] Copy<T>(IEnumerable<T> source, int maximum, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(source, parameterName);
        var result = new List<T>(Math.Min(maximum, 16));
        try
        {
            using var iterator = source.GetEnumerator();
            while (iterator.MoveNext())
            {
                if (result.Count == maximum)
                    throw new ArgumentException("Network input exceeds the technical item limit.", parameterName);
                result.Add(iterator.Current);
            }
        }
        catch (Exception exception) when (!IsFatal(exception))
        {
            throw new ArgumentException("Network input could not be captured safely.", parameterName);
        }
        return result.ToArray();
    }

    private static bool IsFatal(Exception exception) =>
        exception is OutOfMemoryException or StackOverflowException or AccessViolationException;
}

