namespace SimplySignAuto.Agent.SimplySign;

public sealed class SimplySignHealthMonitor : IDisposable, IAsyncDisposable
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);
    private readonly ISimplySignSessionManager _manager;
    private readonly TimeProvider _timeProvider;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _disposeSync = new();
    private readonly Task _worker;
    private Task? _disposeTask;

    public SimplySignHealthMonitor(
        ISimplySignSessionManager manager,
        TimeProvider? timeProvider = null)
    {
        _manager = manager ?? throw new ArgumentNullException(nameof(manager));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _worker = RunAsync();
    }

    public async Task<bool> TickAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _lifetime.Token);
        try
        {
            _ = await _manager.CheckAsync(
                SessionTrigger.BackgroundHealth,
                linked.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return true;
        }
    }

    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();

    public ValueTask DisposeAsync()
    {
        Task disposeTask;
        TaskCompletionSource? completion = null;
        lock (_disposeSync)
        {
            if (_disposeTask is null)
            {
                completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                _disposeTask = completion.Task;
            }

            disposeTask = _disposeTask;
        }

        if (completion is not null)
        {
            _lifetime.Cancel();
            _ = CompleteDisposeAsync(completion);
        }

        return new ValueTask(disposeTask);
    }

    private async Task RunAsync()
    {
        try
        {
            _ = await TickAsync(_lifetime.Token).ConfigureAwait(false);
            using var timer = new PeriodicTimer(Interval, _timeProvider);
            while (await timer.WaitForNextTickAsync(_lifetime.Token).ConfigureAwait(false))
            {
                _ = await TickAsync(_lifetime.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
        }
    }

    private async Task CompleteDisposeAsync(TaskCompletionSource completion)
    {
        try
        {
            await _worker.ConfigureAwait(false);
            _lifetime.Dispose();
            completion.TrySetResult();
        }
        catch (Exception error)
        {
            completion.TrySetException(error);
        }
    }
}
