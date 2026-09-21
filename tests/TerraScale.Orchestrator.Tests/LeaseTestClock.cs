namespace TerraScale.Orchestrator.Tests;

/// <summary>UTC can jump independently; timers and timestamps use only monotonic elapsed time.</summary>
internal sealed class LeaseTestClock(DateTimeOffset initial) : TimeProvider
{
    private readonly object gate = new();
    private readonly List<ClockTimer> timers = [];
    private DateTimeOffset utc = initial;
    private long elapsed;
    internal bool PendingOneSecondDelay { get { lock (gate) return timers.Any(timer => timer.Due == elapsed + TimeSpan.TicksPerSecond && timer.Period is null); } }
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    public override DateTimeOffset GetUtcNow() { lock (gate) return utc; }
    public override long GetTimestamp() { lock (gate) return elapsed; }
    internal void ShiftUtc(TimeSpan shift) { lock (gate) utc += shift; }
    internal void Advance(TimeSpan duration, bool advanceUtc = true)
    {
        if (duration < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(duration));
        List<(TimerCallback Callback, object? State)> ready = [];
        lock (gate)
        {
            elapsed += duration.Ticks;
            if (advanceUtc) utc += duration;
            foreach (var timer in timers)
            {
                if (timer.Due is not { } due || due > elapsed) continue;
                timer.Due = timer.Period is { } period ? elapsed + period : null;
                ready.Add((timer.Callback, timer.State));
            }
        }
        foreach (var (callback, state) in ready) callback(state);
    }
    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new ClockTimer(this, callback, state);
        lock (gate) { timers.Add(timer); timer.Change(dueTime, period); }
        return timer;
    }
    private sealed class ClockTimer(LeaseTestClock owner, TimerCallback callback, object? state) : ITimer
    {
        internal TimerCallback Callback { get; } = callback;
        internal object? State { get; } = state;
        internal long? Due { get; set; }
        internal long? Period { get; private set; }
        private bool disposed;
        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            if (dueTime < Timeout.InfiniteTimeSpan || period < Timeout.InfiniteTimeSpan)
                throw new ArgumentOutOfRangeException(nameof(dueTime));
            lock (owner.gate)
            {
                if (disposed) return false;
                Due = dueTime == Timeout.InfiniteTimeSpan ? null : owner.elapsed + dueTime.Ticks;
                Period = period <= TimeSpan.Zero ? null : period.Ticks;
                return true;
            }
        }
        public void Dispose() { lock (owner.gate) { disposed = true; Due = null; owner.timers.Remove(this); } }
        public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
    }
}
