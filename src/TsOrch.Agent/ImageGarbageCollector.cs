using System.Text.Json;

namespace TsOrch.Agent;

public readonly record struct ImageHistoryRecorded;

public sealed record class ImageHistoryUnreadable(string Message);

public sealed record class ImageHistoryWriteFailed(string Path, string Detail)
{
    public string Message => $"Writing image history {Path} failed: {Detail}";
}

public readonly union ImageHistorySnapshot(ImageState, ImageHistoryUnreadable);

public readonly union ImageHistoryUpdate(ImageHistoryRecorded, ImageHistoryUnreadable, ImageHistoryWriteFailed);

public sealed class ImageHistoryStore(AgentOptions options, TimeProvider timeProvider) : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private ImageState? _state;

    public void Dispose() => _gate.Dispose();

    public async Task<ImageHistorySnapshot> SnapshotAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var loaded = await LoadAsync(cancellationToken);
            return loaded switch
            {
                ImageState state => await StampUntrackedAsync(state, cancellationToken),
                ImageHistoryUnreadable failure => failure,
            };
        }
        finally
        {
            _gate.Release();
        }
    }

    public Task<ImageHistoryUpdate> RecordPulledAsync(string image, CancellationToken cancellationToken) =>
        UpdateAsync(
            state =>
            {
                var timestamps = new Dictionary<string, DateTimeOffset>(state.PulledAt ?? Enumerable.Empty<KeyValuePair<string, DateTimeOffset>>(), StringComparer.Ordinal)
                {
                    [image] = timeProvider.GetUtcNow(),
                };
                return state with
                {
                    Pulled = state.Pulled.Contains(image, StringComparer.Ordinal) ? state.Pulled : [.. state.Pulled, image],
                    PulledAt = timestamps,
                };
            },
            cancellationToken);

    public Task<ImageHistoryUpdate> RecordActiveAsync(string serviceName, string image, CancellationToken cancellationToken) =>
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

    public Task<ImageHistoryUpdate> ForgetPulledAsync(string image, CancellationToken cancellationToken) =>
        UpdateAsync(
            state =>
            {
                var timestamps = new Dictionary<string, DateTimeOffset>(state.PulledAt ?? Enumerable.Empty<KeyValuePair<string, DateTimeOffset>>(), StringComparer.Ordinal);
                timestamps.Remove(image);
                return state with { Pulled = [.. state.Pulled.Where(pulled => pulled != image)], PulledAt = timestamps };
            },
            cancellationToken);

    private async Task<ImageHistorySnapshot> StampUntrackedAsync(ImageState state, CancellationToken cancellationToken)
    {
        var unknown = state.Pulled.Where(image => state.PulledAt?.ContainsKey(image) is not true).ToArray();
        if (unknown.Length == 0)
        {
            return state;
        }

        var timestamps = new Dictionary<string, DateTimeOffset>(state.PulledAt ?? Enumerable.Empty<KeyValuePair<string, DateTimeOffset>>(), StringComparer.Ordinal);
        var observedAt = timeProvider.GetUtcNow();
        foreach (var image in unknown)
        {
            timestamps[image] = observedAt;
        }

        var next = state with { PulledAt = timestamps };
        var saved = await SaveAsync(state, next, cancellationToken);
        return saved switch
        {
            ImageHistoryRecorded => next,
            ImageHistoryUnreadable failure => failure,
            ImageHistoryWriteFailed failure => new ImageHistoryUnreadable(failure.Message),
        };
    }

    private async Task<ImageHistoryUpdate> UpdateAsync(Func<ImageState, ImageState> update, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var outcome = await LoadAsync(cancellationToken);
            return outcome switch
            {
                ImageState current => await SaveAsync(current, update(current), cancellationToken),
                ImageHistoryUnreadable failure => failure,
            };
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<ImageHistoryUpdate> SaveAsync(ImageState current, ImageState next, CancellationToken cancellationToken)
    {
        if (ReferenceEquals(next, current))
        {
            return new ImageHistoryRecorded();
        }

        var outcome = await UnixFiles.WriteAtomicAsync(options.ImageStateFile, JsonSerializer.SerializeToUtf8Bytes(next, AgentJsonContext.Default.ImageState), UnixFiles.WorldReadable, cancellationToken);
        return outcome switch
        {
            AtomicWriteCompleted => Remember(next),
            AtomicWriteFailed failure => new ImageHistoryWriteFailed(failure.Path, failure.Detail),
        };
    }

    private ImageHistoryRecorded Remember(ImageState state)
    {
        _state = state;
        return new ImageHistoryRecorded();
    }

    private async Task<ImageHistorySnapshot> LoadAsync(CancellationToken cancellationToken)
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
                return new ImageHistoryUnreadable($"{options.ImageStateFile} is empty.");
            }

            _state = loaded;
            return loaded;
        }
        catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException)
        {
            return new ImageHistoryUnreadable($"Reading {options.ImageStateFile} failed: {exception.Message}");
        }
    }
}

public sealed class ImageGarbageCollector(
    DockerEngineClient docker,
    ImageHistoryStore history,
    AgentOptions options,
    TimeProvider timeProvider,
    ILogger<ImageGarbageCollector> logger)
{
    internal async Task CollectAsync(CancellationToken cancellationToken)
    {
        var outcome = await history.SnapshotAsync(cancellationToken);
        var failure = outcome switch
        {
            ImageState state => await CollectWithHistoryAsync(state, cancellationToken),
            ImageHistoryUnreadable stateFailure => stateFailure.Message,
        };
        if (failure is not null)
        {
            AgentLog.ImageGcFailed(logger, failure);
        }
    }

    private async Task<string?> CollectWithHistoryAsync(ImageState state, CancellationToken cancellationToken)
    {
        var listed = await docker.ListImagesAsync(cancellationToken);
        return listed switch
        {
            IReadOnlyList<DockerImage> images => await CollectUnusedAsync(state, images, cancellationToken),
            DockerDaemonUnavailable failure => failure.Message,
            DockerResponseInvalid failure => failure.Message,
        };
    }

    private async Task<string?> CollectUnusedAsync(ImageState state, IReadOnlyList<DockerImage> images, CancellationToken cancellationToken)
    {
        var used = await docker.ListContainerImageIdsAsync(cancellationToken);
        return used switch
        {
            IReadOnlySet<string> imageIds => await RemoveUnusedAsync(state, images, imageIds, cancellationToken),
            DockerDaemonUnavailable failure => failure.Message,
            DockerResponseInvalid failure => failure.Message,
        };
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
                || pulledReferences.Any(reference => state.PulledAt?.TryGetValue(reference, out var pulledAt) is not true || pulledAt > cutoff))
            {
                continue;
            }

            var outcome = await docker.RemoveImageAsync(image.Id, cancellationToken);
            var skipped = outcome switch
            {
                DockerRequestCompleted => await ForgetAsync(image, pulledReferences, cancellationToken),
                DockerResourceMissing removeFailure => removeFailure.Message,
                DockerResourceBusy removeFailure => removeFailure.Message,
                DockerDaemonUnavailable removeFailure => removeFailure.Message,
                DockerResponseInvalid removeFailure => removeFailure.Message,
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
            var outcome = await history.ForgetPulledAsync(reference, cancellationToken);
            var failure = outcome switch
            {
                ImageHistoryRecorded => null,
                ImageHistoryUnreadable forgetFailure => forgetFailure.Message,
                ImageHistoryWriteFailed forgetFailure => forgetFailure.Message,
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
