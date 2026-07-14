namespace TerraScale.Orchestrator.ControlPlane.Security;

/// <summary>Technical denial-of-service safety limits; these are not identity, PKI, or retention policy.</summary>
public static class SecurityTechnicalLimits
{
    public const int MaximumCapturedItems = 4096;
}

internal static class SecurityInputSnapshot
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
                    throw new ArgumentException("Security input exceeds the technical item limit.", parameterName);
                result.Add(iterator.Current);
            }
        }
        catch (Exception exception) when (!IsFatal(exception))
        {
            throw new ArgumentException("Security input could not be captured safely.", parameterName);
        }
        return result.ToArray();
    }

    private static bool IsFatal(Exception exception) =>
        exception is OutOfMemoryException or StackOverflowException or AccessViolationException;
}
