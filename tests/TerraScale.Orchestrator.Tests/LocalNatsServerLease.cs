namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Serializes the complete lifetime of disposable local NATS server fixtures.
/// A lease begins before a fixture starts a server and ends only after it has
/// stopped its processes and removed its private root.
/// </summary>
internal static class LocalNatsServerLease
{
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static readonly object RetentionSync = new();
    private static IAsyncDisposable? retainedOwner;

    internal static async ValueTask<Handle> AcquireAsync(CancellationToken cancellationToken = default)
    {
        await Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        return new Handle();
    }

    internal static void Retain(IAsyncDisposable owner)
    {
        ArgumentNullException.ThrowIfNull(owner);
        lock (RetentionSync)
        {
            if (retainedOwner is not null && !ReferenceEquals(retainedOwner, owner))
                throw new InvalidOperationException("A local NATS cleanup owner is already quarantined.");
            retainedOwner = owner;
        }
    }

    internal static void CompleteRetention(IAsyncDisposable owner)
    {
        lock (RetentionSync)
        {
            if (ReferenceEquals(retainedOwner, owner)) retainedOwner = null;
        }
    }

    internal static async ValueTask RetryRetainedAsync()
    {
        IAsyncDisposable? owner;
        lock (RetentionSync) owner = retainedOwner;
        if (owner is not null) await owner.DisposeAsync();
    }

    internal sealed class DirectoryCleanupOwner(string directory, Handle lease) : IAsyncDisposable
    {
        private int disposing;

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.CompareExchange(ref disposing, 1, 0) != 0) return;
            var cleanup = new Cleanup();
            try
            {
                cleanup.Attempt(() =>
                {
                    if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
                });
                if (await lease.ReleaseIfCleanAsync(cleanup))
                {
                    Volatile.Write(ref disposing, 2);
                    CompleteRetention(this);
                }
                cleanup.ThrowIfFailed();
            }
            finally
            {
                if (Volatile.Read(ref disposing) == 1)
                {
                    Retain(this);
                    Volatile.Write(ref disposing, 0);
                }
            }
        }
    }

    internal sealed class Handle : IAsyncDisposable
    {
        private int released;

        internal async ValueTask<bool> ReleaseIfCleanAsync(Cleanup cleanup)
        {
            ArgumentNullException.ThrowIfNull(cleanup);
            // A failed process/root cleanup leaves this handle held as a quarantine.
            // The owning fixture can retry its cleanup; a later fixture cannot start
            // against an unverified predecessor.
            if (cleanup.HasFailures) return false;
            await DisposeAsync();
            return true;
        }

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref released, 1) == 0)
                Gate.Release();
            return ValueTask.CompletedTask;
        }
    }

    internal sealed class Cleanup
    {
        private readonly List<Exception> failures = [];

        internal bool HasFailures => failures.Count > 0;

        internal bool Attempt(Action action)
        {
            try
            {
                action();
                return true;
            }
            catch (Exception exception)
            {
                failures.Add(exception);
                return false;
            }
        }

        internal async ValueTask<bool> AttemptAsync(Func<Task> action)
        {
            try
            {
                await action().ConfigureAwait(false);
                return true;
            }
            catch (Exception exception)
            {
                failures.Add(exception);
                return false;
            }
        }

        internal void ThrowIfFailed()
        {
            if (failures.Count > 0)
                throw new AggregateException("One or more local NATS fixture cleanup steps failed.", failures);
        }
    }
}

