using System.Text;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Classifies fixture output while the server is alive. Only fixed event names
/// and counters leave this collector; neither credentials nor raw log lines do.
/// </summary>
internal sealed class NatsFixtureDiagnostics
{
    private const int MaximumLineLength = 4096;
    private static readonly (string Name, string[] Markers)[] Categories =
    [
        ("tls-handshake-error", ["TLS handshake error", "TLS handshake failure"]),
        ("certificate-error", ["x509:", "bad certificate", "unknown certificate", "certificate expired"]),
        ("authentication-error", ["Authentication Error", "Authentication Violation", "Authorization Violation", "authentication failed"]),
        ("authentication-timeout", ["Authentication Timeout", "authentication timed out"]),
        ("listen-ready", ["Listening for client connections"]),
        ("server-ready", ["Server is ready"]),
        ("address-in-use", ["address already in use"]),
        ("route-error", ["Error trying to connect to route", "Route Error", "Route connection closed"]),
        ("route-established", ["Route connection created", "Route connection established"]),
        ("jetstream", ["JetStream"]),
        ("process-error", ["[ERR]", "[FTL]", "Error:", "panic:"]),
    ];
    private readonly object sync = new();
    private readonly int[] counts = new int[Categories.Length];
    private int discardedLines;

    internal async Task DrainAsync(StreamReader reader)
    {
        var buffer = new char[1024];
        var line = new StringBuilder(MaximumLineLength);
        var oversized = false;
        while (await reader.ReadAsync(buffer.AsMemory()) is var length && length > 0)
        {
            for (var index = 0; index < length; index++)
            {
                var character = buffer[index];
                if (character == '\n')
                {
                    Record(line.ToString(), oversized);
                    line.Clear();
                    oversized = false;
                }
                else if (!oversized)
                {
                    if (line.Length < MaximumLineLength)
                        line.Append(character);
                    else
                        oversized = true;
                }
            }
        }
        if (line.Length > 0 || oversized) Record(line.ToString(), oversized);
    }

    internal string Snapshot()
    {
        lock (sync)
        {
            var events = Categories
                .Select((category, index) => (category.Name, Count: counts[index]))
                .Where(static category => category.Count > 0)
                .Select(static category => $"{category.Name}={category.Count}")
                .ToList();
            if (discardedLines > 0) events.Add($"oversized-lines={discardedLines}");
            return events.Count == 0 ? "no-classified-events" : string.Join(",", events);
        }
    }

    private void Record(string line, bool oversized)
    {
        lock (sync)
        {
            if (oversized)
            {
                if (discardedLines < int.MaxValue) discardedLines++;
                return;
            }
            for (var index = 0; index < Categories.Length; index++)
            {
                if (counts[index] < int.MaxValue && Categories[index].Markers.Any(
                        marker => line.Contains(marker, StringComparison.OrdinalIgnoreCase)))
                    counts[index]++;
            }
        }
    }
}
