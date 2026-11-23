using System.Threading.Channels;

namespace TsOrch.Edge;

internal sealed class FileChangeMonitor : IDisposable
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);

    private readonly Channel<bool> _signals = Channel.CreateBounded<bool>(
        new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropWrite, SingleReader = true });
    private readonly FileSystemWatcher _watcher;
    private readonly ITimer _poll;

    public FileChangeMonitor(string directory, TimeProvider timeProvider)
    {
        Directory.CreateDirectory(directory);
        _watcher = new FileSystemWatcher(directory)
        {
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
            IncludeSubdirectories = false,
        };
        _watcher.Changed += OnFileSystemEvent;
        _watcher.Created += OnFileSystemEvent;
        _watcher.Deleted += OnFileSystemEvent;
        _watcher.Renamed += OnFileSystemEvent;
        _watcher.EnableRaisingEvents = true;
        _poll = timeProvider.CreateTimer(_ => Signal(), null, PollInterval, PollInterval);
    }

    public IAsyncEnumerable<bool> ReadAllAsync(CancellationToken cancellationToken) => _signals.Reader.ReadAllAsync(cancellationToken);

    public void Dispose()
    {
        _poll.Dispose();
        _watcher.Dispose();
        _signals.Writer.TryComplete();
    }

    private void OnFileSystemEvent(object sender, FileSystemEventArgs e) => Signal();

    private void Signal() => _signals.Writer.TryWrite(true);
}

internal readonly record struct FileStamp(bool Exists, DateTime LastWriteUtc, long Length)
{
    public static FileStamp Read(string path)
    {
        var info = new FileInfo(path);
        return info.Exists ? new FileStamp(true, info.LastWriteTimeUtc, info.Length) : default;
    }
}
