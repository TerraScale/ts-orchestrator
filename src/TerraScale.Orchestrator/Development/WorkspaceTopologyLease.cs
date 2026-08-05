using System.Diagnostics;

namespace TerraScale.Orchestrator.Development;

/// <summary>
/// Serializes product development topologies only within the same operating-system named-mutex namespace.
/// It provides no cross-session, container, or host guarantee.
/// </summary>
internal sealed class WorkspaceTopologyLease : IAsyncDisposable
{
    private const string NamespaceEnvironmentVariable = "TERRASCALE_VALIDATION_LEASE_NAMESPACE";
    private const string DevelopmentLabOwner = "development-lab";
    private static readonly TimeSpan RetryDelay = TimeSpan.FromMilliseconds(250);

    private readonly ManualResetEventSlim release;
    private readonly Task released;
    private int disposed;

    private WorkspaceTopologyLease(string mutexName, ManualResetEventSlim release, Task released)
    {
        MutexName = mutexName;
        this.release = release;
        this.released = released;
    }

    internal string MutexName { get; }

    public static Task<WorkspaceTopologyLease> AcquireAsync(
        string owner,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(owner);
        if (!string.Equals(owner, DevelopmentLabOwner, StringComparison.Ordinal))
        {
            throw new ArgumentException("The topology lease owner is not supported.", nameof(owner));
        }

        if (timeout <= TimeSpan.Zero || timeout == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout), "A finite positive timeout is required.");
        }

        var mutexName = GetMutexName();
        var acquired = new TaskCompletionSource<WorkspaceTopologyLease>(TaskCreationOptions.RunContinuationsAsynchronously);
        var released = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new ManualResetEventSlim();
        var ownerThread = new Thread(() => RunOwner(mutexName, timeout, cancellationToken, release, acquired, released))
        {
            IsBackground = true,
            Name = "TerraScale topology lease",
        };

        ownerThread.Start();
        return acquired.Task;
    }

    internal static string GetMutexName()
    {
        var leaseNamespace = Environment.GetEnvironmentVariable(NamespaceEnvironmentVariable) ?? Environment.UserName;
        if (string.IsNullOrEmpty(leaseNamespace) || leaseNamespace.Length > 64 ||
            leaseNamespace.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '.' and not '_' and not '-'))
        {
            throw new InvalidOperationException("The workspace topology lease namespace is invalid.");
        }

        return $"terrascale-workspace-topology-{leaseNamespace}";
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return ValueTask.CompletedTask;
        }

        release.Set();
        return new ValueTask(ReleaseAsync());
    }

    private async Task ReleaseAsync()
    {
        try
        {
            await released.ConfigureAwait(false);
        }
        finally
        {
            release.Dispose();
        }
    }

    private static void RunOwner(
        string mutexName,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        ManualResetEventSlim release,
        TaskCompletionSource<WorkspaceTopologyLease> acquired,
        TaskCompletionSource released)
    {
        var leasePublished = false;

        try
        {
            using var mutex = new Mutex(initiallyOwned: false, mutexName);
            var stopwatch = Stopwatch.StartNew();
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var remaining = timeout - stopwatch.Elapsed;
                if (remaining <= TimeSpan.Zero)
                {
                    throw new InvalidOperationException("Timed out acquiring the workspace topology lease.");
                }

                try
                {
                    if (mutex.WaitOne(0))
                    {
                        break;
                    }
                }
                catch (AbandonedMutexException)
                {
                    break;
                }

                cancellationToken.WaitHandle.WaitOne(remaining < RetryDelay ? remaining : RetryDelay);
            }

            var lease = new WorkspaceTopologyLease(mutexName, release, released.Task);
            acquired.SetResult(lease);
            leasePublished = true;
            release.Wait();
            mutex.ReleaseMutex();
            released.SetResult();
        }
        catch (Exception exception)
        {
            acquired.TrySetException(exception);
            released.TrySetException(exception);
            if (!leasePublished)
            {
                release.Dispose();
            }
        }
    }
}
