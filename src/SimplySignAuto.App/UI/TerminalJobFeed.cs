using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.App.UI;

internal interface ITerminalJobFeed : IDisposable
{
    event EventHandler? ItemsChanged;

    IReadOnlyList<TerminalJobEventItem> Items { get; }

    bool HasCompletedInitialPoll { get; }
}

internal interface ITerminalJobFeedDelay
{
    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

internal sealed class TerminalJobFeed : ITerminalJobFeed
{
    private static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(15);
    private readonly IAgentAdministrationClient _administration;
    private readonly ITerminalJobFeedDelay _delay;
    private readonly TimeSpan _pollInterval;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _sync = new();
    private readonly Task _loop;
    private IReadOnlyList<TerminalJobEventItem> _items = [];
    private TerminalJobWatermark? _watermark;
    private TerminalJobCursor? _cursor;
    private int _initialPollCompleted;
    private int _disposed;

    public TerminalJobFeed(
        IAgentAdministrationClient administration,
        ITerminalJobFeedDelay? delay = null,
        TimeSpan? pollInterval = null)
    {
        _administration = administration ?? throw new ArgumentNullException(nameof(administration));
        _delay = delay ?? SystemTerminalJobFeedDelay.Instance;
        _pollInterval = pollInterval ?? DefaultPollInterval;
        if (_pollInterval <= TimeSpan.Zero || _pollInterval > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(nameof(pollInterval));
        }

        _loop = RunAsync();
    }

    public event EventHandler? ItemsChanged;

    public IReadOnlyList<TerminalJobEventItem> Items
    {
        get
        {
            lock (_sync)
            {
                return _items;
            }
        }
    }

    public bool HasCompletedInitialPoll => Volatile.Read(ref _initialPollCompleted) != 0;

    internal IAgentAdministrationClient AdministrationClient => _administration;

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _lifetime.Cancel();
        try
        {
            _loop.GetAwaiter().GetResult();
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
        }
        finally
        {
            _lifetime.Dispose();
        }
    }

    private async Task RunAsync()
    {
        while (!_lifetime.IsCancellationRequested)
        {
            try
            {
                await PollAsync(_lifetime.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
            {
                break;
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
            }

            await _delay.DelayAsync(_pollInterval, _lifetime.Token).ConfigureAwait(false);
        }
    }

    private async Task PollAsync(CancellationToken cancellationToken)
    {
        TerminalJobWatermark? requestWatermark;
        TerminalJobCursor? requestCursor;
        lock (_sync)
        {
            requestWatermark = _watermark;
            requestCursor = _cursor;
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(RequestTimeout);
        var page = await _administration
            .GetTerminalJobDeltaAsync(requestWatermark, requestCursor, timeout.Token)
            .ConfigureAwait(false);
        var responseWatermark = page.Watermark
            ?? throw new InvalidOperationException("terminal_delta_missing_watermark");

        var changed = false;
        var completedDelta = page.NextCursor is null;
        lock (_sync)
        {
            var snapshot = page.Items
                .Concat(_items)
                .GroupBy(static item => item.Sequence)
                .Select(static group => group.First())
                .OrderByDescending(static item => item.Sequence)
                .Take(1_000)
                .ToArray();
            if (!_items.SequenceEqual(snapshot))
            {
                _items = Array.AsReadOnly(snapshot);
                changed = true;
            }

            if (completedDelta)
            {
                _watermark = responseWatermark;
                _cursor = null;
            }
            else
            {
                _cursor = page.NextCursor;
            }
        }

        var firstPoll = completedDelta && Interlocked.Exchange(ref _initialPollCompleted, 1) == 0;
        if ((changed || firstPoll) && Volatile.Read(ref _disposed) == 0)
        {
            ItemsChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    private sealed class SystemTerminalJobFeedDelay : ITerminalJobFeedDelay
    {
        public static SystemTerminalJobFeedDelay Instance { get; } = new();

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
            Task.Delay(delay, cancellationToken);
    }
}
