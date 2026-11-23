using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace TsOrch.Agent;

public sealed class ImageHistoryStore(IOptions<AgentOptions> options) : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _path = options.Value.ImageStateFile;
    private ImageState? _state;

    public void Dispose() => _gate.Dispose();

    public async Task<ImageState> SnapshotAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            return await LoadAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public Task RecordPulledAsync(string image, CancellationToken cancellationToken) =>
        UpdateAsync(state => state.Pulled.Contains(image, StringComparer.Ordinal) ? state : state with { Pulled = [.. state.Pulled, image] }, cancellationToken);

    public Task RecordActiveAsync(string serviceName, string image, CancellationToken cancellationToken) =>
        UpdateAsync(
            state =>
            {
                var current = state.Services.GetValueOrDefault(serviceName);
                if (current is not null && current.Active == image)
                {
                    return state;
                }

                var services = new Dictionary<string, ServiceImageHistory>(state.Services, StringComparer.Ordinal)
                {
                    [serviceName] = new ServiceImageHistory(image, current?.Active),
                };
                return state with { Services = services };
            },
            cancellationToken);

    public Task ForgetPulledAsync(string image, CancellationToken cancellationToken) =>
        UpdateAsync(state => state with { Pulled = [.. state.Pulled.Where(pulled => pulled != image)] }, cancellationToken);

    private async Task UpdateAsync(Func<ImageState, ImageState> update, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var current = await LoadAsync(cancellationToken);
            var next = update(current);
            if (ReferenceEquals(next, current))
            {
                return;
            }

            await UnixFiles.WriteAtomicAsync(_path, JsonSerializer.SerializeToUtf8Bytes(next, AgentJsonContext.Default.ImageState), UnixFiles.WorldReadable, cancellationToken);
            _state = next;
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<ImageState> LoadAsync(CancellationToken cancellationToken)
    {
        if (_state is not null)
        {
            return _state;
        }

        if (!File.Exists(_path))
        {
            _state = new ImageState(new Dictionary<string, ServiceImageHistory>(StringComparer.Ordinal), []);
            return _state;
        }

        await using var stream = File.OpenRead(_path);
        _state = await JsonSerializer.DeserializeAsync(stream, AgentJsonContext.Default.ImageState, cancellationToken)
            ?? throw new InvalidDataException($"{_path} is empty.");
        return _state;
    }
}

public sealed class ImageGarbageCollector(
    DockerEngineClient docker,
    ImageHistoryStore history,
    IOptions<AgentOptions> options,
    TimeProvider timeProvider,
    ILogger<ImageGarbageCollector> logger) : BackgroundService
{
    private readonly AgentOptions _options = options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(_options.ImageGcInterval, timeProvider);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            await CollectAsync(stoppingToken);
        }
    }

    public async Task<OrchResult<int>> CollectAsync(CancellationToken cancellationToken)
    {
        var state = await history.SnapshotAsync(cancellationToken);
        var imagesResult = await docker.ListImagesAsync(cancellationToken);
        if (!imagesResult.TryGetValue(out var images, out var listError))
        {
            logger.ImageGcFailed(listError.Message);
            return listError;
        }

        var usedResult = await docker.ListContainerImageIdsAsync(cancellationToken);
        if (!usedResult.TryGetValue(out var usedImageIds, out var usedError))
        {
            logger.ImageGcFailed(usedError.Message);
            return usedError;
        }

        HashSet<string> retained = new(StringComparer.Ordinal);
        foreach (var service in state.Services.Values)
        {
            retained.Add(service.Active);
            if (service.Previous is { } previous)
            {
                retained.Add(previous);
            }
        }

        var cutoff = timeProvider.GetUtcNow() - _options.ImageRetention;
        var removed = 0;
        foreach (var image in images)
        {
            var pulledReferences = state.Pulled.Where(reference => Matches(image, reference)).ToList();
            if (pulledReferences.Count == 0
                || usedImageIds.Contains(image.Id)
                || retained.Any(reference => Matches(image, reference))
                || image.Created > cutoff)
            {
                continue;
            }

            var removal = await docker.RemoveImageAsync(image.Id, cancellationToken);
            switch (removal)
            {
                case Done:
                    removed++;
                    foreach (var reference in pulledReferences)
                    {
                        await history.ForgetPulledAsync(reference, cancellationToken);
                    }

                    logger.ImageRemoved(image.Id);
                    break;
                case OrchError error:
                    logger.ImageRemovalSkipped(image.Id, error.Message);
                    break;
            }
        }

        return removed;
    }

    private static bool Matches(DockerImage image, string reference)
    {
        var normalized = ImageReference.WithDefaultTag(reference);
        return image.Id == reference
            || image.RepoTags.Contains(normalized, StringComparer.Ordinal)
            || image.RepoDigests.Contains(reference, StringComparer.Ordinal);
    }
}
