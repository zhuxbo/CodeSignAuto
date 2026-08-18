namespace SimplySignAuto.Agent.Signing;

public interface ISigningOperationLease : IAsyncDisposable
{
    CancellationToken CancellationToken { get; }
}

public interface ISigningOperationGate : IAsyncDisposable
{
    Task RunAsync(
        Func<CancellationToken, Task> operation,
        CancellationToken cancellationToken);

    Task<T> RunAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken);

    Task<bool> TryRunHealthCheckAsync(
        Func<CancellationToken, Task> operation,
        CancellationToken cancellationToken);

    ValueTask<ISigningOperationLease> AcquireAsync(CancellationToken cancellationToken);
}

public sealed class SigningOperationGate : ISigningOperationGate, IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _lifecycleSync = new();
    private TaskCompletionSource _operationsDrained = CompletedSource();
    private Task? _disposeTask;
    private int _activeOperations;

    public async Task RunAsync(
        Func<CancellationToken, Task> operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        await using var lease = await AcquireAsync(cancellationToken).ConfigureAwait(false);
        await operation(lease.CancellationToken).ConfigureAwait(false);
    }

    public async Task<T> RunAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        await using var lease = await AcquireAsync(cancellationToken).ConfigureAwait(false);
        return await operation(lease.CancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> TryRunHealthCheckAsync(
        Func<CancellationToken, Task> operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        BeginOperation();
        var acquired = false;
        var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _lifetime.Token);
        try
        {
            acquired = await _gate.WaitAsync(TimeSpan.Zero, linked.Token).ConfigureAwait(false);
            if (!acquired)
            {
                return false;
            }

            await operation(linked.Token).ConfigureAwait(false);
            return true;
        }
        finally
        {
            if (acquired)
            {
                _gate.Release();
            }

            linked.Dispose();
            EndOperation();
        }
    }

    public async ValueTask<ISigningOperationLease> AcquireAsync(
        CancellationToken cancellationToken)
    {
        BeginOperation();
        var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _lifetime.Token);
        try
        {
            await _gate.WaitAsync(linked.Token).ConfigureAwait(false);
            return new OperationLease(this, linked);
        }
        catch
        {
            linked.Dispose();
            EndOperation();
            throw;
        }
    }

    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();

    public ValueTask DisposeAsync()
    {
        Task disposeTask;
        TaskCompletionSource? completion = null;
        lock (_lifecycleSync)
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
            _ = CompleteDisposeAsync(completion);
        }

        return new ValueTask(disposeTask);
    }

    private void BeginOperation()
    {
        lock (_lifecycleSync)
        {
            ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
            if (_activeOperations++ == 0)
            {
                _operationsDrained = new TaskCompletionSource(
                    TaskCreationOptions.RunContinuationsAsynchronously);
            }
        }
    }

    private void EndOperation()
    {
        TaskCompletionSource? drained = null;
        lock (_lifecycleSync)
        {
            if (--_activeOperations == 0)
            {
                drained = _operationsDrained;
            }
        }

        drained?.TrySetResult();
    }

    private async Task CompleteDisposeAsync(TaskCompletionSource completion)
    {
        try
        {
            _lifetime.Cancel();
            Task drained;
            lock (_lifecycleSync)
            {
                drained = _operationsDrained.Task;
            }

            await drained.ConfigureAwait(false);
            _gate.Dispose();
            _lifetime.Dispose();
            completion.TrySetResult();
        }
        catch (Exception error)
        {
            completion.TrySetException(error);
        }
    }

    private static TaskCompletionSource CompletedSource()
    {
        var source = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        source.SetResult();
        return source;
    }

    private sealed class OperationLease(
        SigningOperationGate owner,
        CancellationTokenSource cancellation) : ISigningOperationLease
    {
        private SigningOperationGate? _owner = owner;
        private CancellationTokenSource? _cancellation = cancellation;

        public CancellationToken CancellationToken =>
            _cancellation?.Token ?? throw new ObjectDisposedException(nameof(OperationLease));

        public ValueTask DisposeAsync()
        {
            var owner = Interlocked.Exchange(ref _owner, null);
            var cancellation = Interlocked.Exchange(ref _cancellation, null);
            if (owner is not null)
            {
                owner._gate.Release();
                cancellation!.Dispose();
                owner.EndOperation();
            }

            return ValueTask.CompletedTask;
        }
    }
}
