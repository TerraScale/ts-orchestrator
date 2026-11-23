using System.Text.Json;
using Microsoft.Extensions.Hosting;

namespace TsOrch.Agent;

public sealed class ImageHistoryStore(AgentOptions options) : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private ImageState? _state;

    public void Dispose() => _gate.Dispose();

    public async Task<Result<ImageState, InternalFailure>> SnapshotAsync(CancellationToken cancellationToken)
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

    public Task<Result<Done, InternalFailure>> RecordPulledAsync(string image, CancellationToken cancellationToken) =>
        UpdateAsync(state => state.Pulled.Contains(image, StringComparer.Ordinal) ? state : state with { Pulled = [.. state.Pulled, image] }, cancellationToken);

    public Task<Result<Done, InternalFailure>> RecordActiveAsync(string serviceName, string image, CancellationToken cancellationToken) =>
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

    public Task<Result<Done, InternalFailure>> ForgetPulledAsync(string image, CancellationToken cancellationToken) =>
        UpdateAsync(state => state with { Pulled = [.. state.Pulled.Where(pulled => pulled != image)] }, cancellationToken);

    private async Task<Result<Done, InternalFailure>> UpdateAsync(Func<ImageState, ImageState> update, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            return await LoadAsync(cancellationToken) switch
            {
                ImageState current => await SaveAsync(current, update(current), cancellationToken),
                InternalFailure failure => failure,
            };
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<Result<Done, InternalFailure>> SaveAsync(ImageState current, ImageState next, CancellationToken cancellationToken)
    {
        if (ReferenceEquals(next, current))
        {
            return new Done();
        }

        return await UnixFiles.WriteAtomicAsync(options.ImageStateFile, JsonSerializer.SerializeToUtf8Bytes(next, AgentJsonContext.Default.ImageState), UnixFiles.WorldReadable, cancellationToken) switch
        {
            Done done => Remember(next, done),
            InternalFailure failure => failure,
        };
    }

    private Done Remember(ImageState state, Done done)
    {
        _state = state;
        return done;
    }

    private async Task<Result<ImageState, InternalFailure>> LoadAsync(CancellationToken cancellationToken)
    {
        if (_state is not null)
        {
            return _state;
        }

        if (!File.Exists(options.ImageStateFile))
        {
            _state = new ImageState(new Dictionary<string, ServiceImageHistory>(StringComparer.Ordinal), []);
            return _state;
        }

        try
        {
            await using var stream = File.OpenRead(options.ImageStateFile);
            if (await JsonSerializer.DeserializeAsync(stream, AgentJsonContext.Default.ImageState, cancellationToken) is not { } loaded)
            {
                return new InternalFailure($"{options.ImageStateFile} is empty.");
            }

            _state = loaded;
            return loaded;
        }
        catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException)
        {
            return new InternalFailure($"Reading {options.ImageStateFile} failed: {exception.Message}");
        }
    }
}

public sealed class ImageGarbageCollector(
    DockerEngineClient docker,
    ImageHistoryStore history,
    AgentOptions options,
    TimeProvider timeProvider,
    ILogger<ImageGarbageCollector> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(options.ImageGcInterval, timeProvider);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            await CollectAsync(stoppingToken);
        }
    }

    private async Task CollectAsync(CancellationToken cancellationToken)
    {
        var failure = await history.SnapshotAsync(cancellationToken) switch
        {
            ImageState state => await docker.ListImagesAsync(cancellationToken) switch
            {
                IReadOnlyList<DockerImage> images => await docker.ListContainerImageIdsAsync(cancellationToken) switch
                {
                    IReadOnlySet<string> usedImageIds => await RemoveUnusedAsync(state, images, usedImageIds, cancellationToken),
                    Unavailable usedFailure => usedFailure.Message,
                    InternalFailure usedFailure => usedFailure.Message,
                },
                Unavailable listFailure => listFailure.Message,
                InternalFailure listFailure => listFailure.Message,
            },
            InternalFailure stateFailure => stateFailure.Message,
        };
        if (failure is not null)
        {
            AgentLog.ImageGcFailed(logger, failure);
        }
    }

    private async Task<string?> RemoveUnusedAsync(ImageState state, IReadOnlyList<DockerImage> images, IReadOnlySet<string> usedImageIds, CancellationToken cancellationToken)
    {
        HashSet<string> retained = [with(StringComparer.Ordinal)];
        foreach (var service in state.Services.Values)
        {
            retained.Add(service.Active);
            if (service.Previous is { } previous)
            {
                retained.Add(previous);
            }
        }

        var cutoff = timeProvider.GetUtcNow() - options.ImageRetention;
        foreach (var image in images)
        {
            List<string> pulledReferences = [.. state.Pulled.Where(reference => Matches(image, reference))];
            if (pulledReferences.Count == 0
                || usedImageIds.Contains(image.Id)
                || retained.Any(reference => Matches(image, reference))
                || image.Created > cutoff)
            {
                continue;
            }

            var skipped = await docker.RemoveImageAsync(image.Id, cancellationToken) switch
            {
                Done => await ForgetAsync(image, pulledReferences, cancellationToken),
                NotFound removeFailure => removeFailure.Message,
                Conflict removeFailure => removeFailure.Message,
                Unavailable removeFailure => removeFailure.Message,
                InternalFailure removeFailure => removeFailure.Message,
            };
            if (skipped is not null)
            {
                AgentLog.ImageRemovalSkipped(logger, image.Id, skipped);
            }
        }

        return null;
    }

    private async Task<string?> ForgetAsync(DockerImage image, IReadOnlyList<string> pulledReferences, CancellationToken cancellationToken)
    {
        AgentLog.ImageRemoved(logger, image.Id);
        foreach (var reference in pulledReferences)
        {
            var failure = await history.ForgetPulledAsync(reference, cancellationToken) switch
            {
                Done => null,
                InternalFailure forgetFailure => forgetFailure.Message,
            };
            if (failure is not null)
            {
                AgentLog.ImageHistoryFailed(logger, failure);
            }
        }

        return null;
    }

    private static bool Matches(DockerImage image, string reference)
    {
        var normalized = ImageReference.WithDefaultTag(reference);
        return image.Id == reference
            || image.RepoTags.Contains(normalized, StringComparer.Ordinal)
            || image.RepoDigests.Contains(reference, StringComparer.Ordinal);
    }
}
