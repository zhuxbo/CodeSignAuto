namespace CodeSignAuto.Service.Jobs;

public interface IUpgradeAdmissionGate
{
    bool IsDraining { get; }

    ValueTask<IAsyncDisposable?> TryEnterAsync(CancellationToken cancellationToken);

    ValueTask<IAsyncDisposable?> TryEnterExistingAsync(CancellationToken cancellationToken);

    Task<bool> DrainAsync(TimeSpan timeout, CancellationToken cancellationToken);

    Task<bool> SealAsync(TimeSpan timeout, CancellationToken cancellationToken);

    void Resume();
}

public sealed class UpgradeAdmissionGate : IUpgradeAdmissionGate
{
    private readonly object _sync = new();
    private TaskCompletionSource? _idle;
    private AdmissionState _state = AdmissionState.Accepting;
    private int _active;

    public bool IsDraining
    {
        get
        {
            lock (_sync)
            {
                return _state != AdmissionState.Accepting;
            }
        }
    }

    public ValueTask<IAsyncDisposable?> TryEnterAsync(CancellationToken cancellationToken) =>
        TryEnterCore(allowDuringDrain: false, cancellationToken);

    public ValueTask<IAsyncDisposable?> TryEnterExistingAsync(CancellationToken cancellationToken) =>
        TryEnterCore(allowDuringDrain: true, cancellationToken);

    private ValueTask<IAsyncDisposable?> TryEnterCore(
        bool allowDuringDrain,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            if (_state == AdmissionState.Sealed ||
                _state == AdmissionState.DrainingNew && !allowDuringDrain)
            {
                return ValueTask.FromResult<IAsyncDisposable?>(null);
            }

            checked
            {
                _active++;
            }

            return ValueTask.FromResult<IAsyncDisposable?>(new Admission(this));
        }
    }

    public async Task<bool> DrainAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        ValidateTimeout(timeout);
        lock (_sync)
        {
            if (_state == AdmissionState.Accepting)
            {
                _state = AdmissionState.DrainingNew;
            }
        }

        return await WaitForIdleAsync(timeout, cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> SealAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        ValidateTimeout(timeout);
        lock (_sync)
        {
            _state = AdmissionState.Sealed;
        }

        return await WaitForIdleAsync(timeout, cancellationToken).ConfigureAwait(false);
    }

    private async Task<bool> WaitForIdleAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        Task wait;
        lock (_sync)
        {
            if (_active == 0)
            {
                return true;
            }

            _idle ??= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            wait = _idle.Task;
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            await wait.WaitAsync(deadline.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            Resume();
            return false;
        }
    }

    public void Resume()
    {
        lock (_sync)
        {
            _state = AdmissionState.Accepting;
            if (_active == 0)
            {
                _idle = null;
            }
        }
    }

    private static void ValidateTimeout(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero || timeout == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }
    }

    private void Exit()
    {
        TaskCompletionSource? completed = null;
        lock (_sync)
        {
            if (_active <= 0)
            {
                return;
            }

            _active--;
            if (_active == 0)
            {
                completed = _idle;
                _idle = null;
            }
        }

        completed?.TrySetResult();
    }

    private sealed class Admission(UpgradeAdmissionGate owner) : IAsyncDisposable
    {
        private UpgradeAdmissionGate? _owner = owner;

        public ValueTask DisposeAsync()
        {
            Interlocked.Exchange(ref _owner, null)?.Exit();
            return ValueTask.CompletedTask;
        }
    }

    private enum AdmissionState
    {
        Accepting,
        DrainingNew,
        Sealed,
    }
}
