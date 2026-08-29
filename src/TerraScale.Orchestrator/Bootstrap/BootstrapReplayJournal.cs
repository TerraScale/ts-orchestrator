using System.Text.Json;
using TerraScale.Orchestrator.Security.SystemProjectBootstrap;

namespace TerraScale.Orchestrator.Bootstrap;

/// <summary>
/// The replay journal a bootstrap grant must consume exactly once. Journal
/// keys are the exact-case grant identity and nonce strings, so each caller
/// path must use one consistent spelling of the same grant.
/// </summary>
public interface IBootstrapGrantReplayJournal
{
    BootstrapReplayConsumeResult TryConsume(string grantId, string nonce, DateTimeOffset expiresAt);
}

/// <summary>
/// In-memory replay journal. Correct within one process lifetime; used for
/// tests and for callers that layer durability on top.
/// </summary>
public sealed class InMemoryBootstrapReplayJournal : IBootstrapGrantReplayJournal, IBootstrapGrantReplayConsumer
{
    private readonly HashSet<string> consumed = new(StringComparer.Ordinal);
    private readonly Lock gate = new();

    public BootstrapReplayConsumeResult TryConsume(string grantId, string nonce, DateTimeOffset expiresAt)
    {
        ArgumentException.ThrowIfNullOrEmpty(grantId);
        ArgumentException.ThrowIfNullOrEmpty(nonce);
        lock (gate)
        {
            return consumed.Add(JournalKey(grantId, nonce)) ? BootstrapReplayConsumeResult.Consumed : BootstrapReplayConsumeResult.AlreadyConsumed;
        }
    }

    BootstrapReplayConsumeResult IBootstrapGrantReplayConsumer.TryConsume(BootstrapGrantReplayKey key, DateTimeOffset expiresAt) =>
        TryConsume(key.GrantId.Value, key.Nonce.Value, expiresAt);

    internal static string JournalKey(string grantId, string nonce) => string.Concat(grantId, "\u001f", nonce);
}

/// <summary>
/// Durable file-backed replay journal: the consume is appended to an append-only
/// JSONL file before it is acknowledged, so the replay decision survives a
/// process restart. Loading prunes entries whose grant has already expired (an
/// expired grant can never verify again) and skips malformed trailing lines,
/// which is the crash-during-append shape in which no answer was returned.
/// </summary>
public sealed class FileBootstrapGrantReplayJournal : IBootstrapGrantReplayJournal, IBootstrapGrantReplayConsumer, IDisposable
{
    private readonly string filePath;
    private readonly HashSet<string> consumed = new(StringComparer.Ordinal);
    private readonly Lock gate = new();

    public FileBootstrapGrantReplayJournal(string filePath, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        this.filePath = filePath;
        if (!File.Exists(filePath)) return;
        foreach (var line in File.ReadLines(filePath))
        {
            Entry? entry;
            try
            {
                entry = JsonSerializer.Deserialize<Entry>(line);
            }
            catch (JsonException)
            {
                continue;
            }

            if (entry is null) continue;
            if (entry.GrantId is null || entry.Nonce is null) continue;
            if (entry.ExpiresAtUnixSeconds <= now.ToUnixTimeSeconds()) continue;
            consumed.Add(InMemoryBootstrapReplayJournal.JournalKey(entry.GrantId, entry.Nonce));
        }
    }

    public BootstrapReplayConsumeResult TryConsume(string grantId, string nonce, DateTimeOffset expiresAt)
    {
        ArgumentException.ThrowIfNullOrEmpty(grantId);
        ArgumentException.ThrowIfNullOrEmpty(nonce);
        lock (gate)
        {
            if (consumed.Contains(InMemoryBootstrapReplayJournal.JournalKey(grantId, nonce)))
                return BootstrapReplayConsumeResult.AlreadyConsumed;
            var line = JsonSerializer.Serialize(new Entry(grantId, nonce, expiresAt.ToUnixTimeSeconds()));
            File.AppendAllText(filePath, line + Environment.NewLine);
            consumed.Add(InMemoryBootstrapReplayJournal.JournalKey(grantId, nonce));
            return BootstrapReplayConsumeResult.Consumed;
        }
    }

    BootstrapReplayConsumeResult IBootstrapGrantReplayConsumer.TryConsume(BootstrapGrantReplayKey key, DateTimeOffset expiresAt) =>
        TryConsume(key.GrantId.Value, key.Nonce.Value, expiresAt);

    public void Dispose()
    {
    }

    private sealed record Entry(string? GrantId, string? Nonce, long ExpiresAtUnixSeconds);
}
