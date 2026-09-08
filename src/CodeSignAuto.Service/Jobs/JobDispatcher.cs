using System.Threading.Channels;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Protocol;
using CodeSignAuto.Service.Ipc;

namespace CodeSignAuto.Service.Jobs;

public sealed class JobDispatcher : IJobDispatcherRuntime, IDisposable
{
    private static readonly HashSet<string> RetryableErrors = new(StringComparer.Ordinal)
    {
        "token_missing", "private_key_missing", "pkcs11_session_lost",
    };
    private readonly IJobStore _jobs;
    private readonly ISpoolStore _spool;
    private readonly IAgentPipeTransport _pipe;
    private readonly IJobCompletionNotifier _notifier;
    private readonly Channel<DispatcherEvent> _events = Channel.CreateUnbounded<DispatcherEvent>(
        new UnboundedChannelOptions { SingleReader = true, SingleWriter = false });
    private ActiveDispatch? _active;
    private Guid? _blockedConnectionId;
    private int _running;
    private int _disposed;

    public JobDispatcher(
        IJobStore jobs,
        ISpoolStore spool,
        IAgentPipeTransport pipe,
        IJobCompletionNotifier notifier)
    {
        _jobs = jobs ?? throw new ArgumentNullException(nameof(jobs));
        _spool = spool ?? throw new ArgumentNullException(nameof(spool));
        _pipe = pipe ?? throw new ArgumentNullException(nameof(pipe));
        _notifier = notifier ?? throw new ArgumentNullException(nameof(notifier));
        _pipe.ConnectionStateChanged += OnConnectionStateChanged;
        _pipe.MessageReceived += OnMessageReceived;
    }

    public void Enqueue(Guid jobId)
    {
        if (jobId == Guid.Empty)
        {
            throw new ArgumentException("Job ID is required.", nameof(jobId));
        }

        _events.Writer.TryWrite(WakeEvent.Instance);
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.CompareExchange(ref _running, 1, 0) != 0)
        {
            throw new InvalidOperationException("Only one dispatcher loop may run.");
        }

        try
        {
            await _jobs.RecoverActiveLeasesAsync(cancellationToken).ConfigureAwait(false);
            await ResumePendingCompletionsAsync(cancellationToken).ConfigureAwait(false);
            _events.Writer.TryWrite(WakeEvent.Instance);
            while (await _events.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                while (_events.Reader.TryRead(out var dispatcherEvent))
                {
                    await ProcessEventAsync(dispatcherEvent, cancellationToken).ConfigureAwait(false);
                }

                await DispatchNextAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            Volatile.Write(ref _running, 0);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _pipe.ConnectionStateChanged -= OnConnectionStateChanged;
        _pipe.MessageReceived -= OnMessageReceived;
        _events.Writer.TryComplete();
    }

    private async Task ProcessEventAsync(DispatcherEvent dispatcherEvent, CancellationToken cancellationToken)
    {
        switch (dispatcherEvent)
        {
            case ConnectionEvent connection:
                await ProcessConnectionAsync(connection.Change, cancellationToken).ConfigureAwait(false);
                break;
            case MessageEvent message:
                await ProcessMessageAsync(message.Message, cancellationToken).ConfigureAwait(false);
                break;
        }
    }

    private async Task ProcessConnectionAsync(
        AgentConnectionStateChangedEventArgs change,
        CancellationToken cancellationToken)
    {
        if (change.Status == AgentConnectionStatus.Connected)
        {
            if (_pipe.CurrentConnection?.ConnectionId == change.ConnectionId)
            {
                if (_blockedConnectionId != change.ConnectionId)
                {
                    _blockedConnectionId = null;
                }

                await _jobs.RequeueWaitingForAgentAsync(cancellationToken).ConfigureAwait(false);
            }

            return;
        }

        if (_active?.ConnectionId == change.ConnectionId)
        {
            await ReleaseActiveLeaseAsync("recovery_exhausted", cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ProcessMessageAsync(
        AgentMessageReceivedEventArgs received,
        CancellationToken cancellationToken)
    {
        var current = _pipe.CurrentConnection;
        var active = _active;
        if (current?.ConnectionId != received.ConnectionId ||
            active is null ||
            active.ConnectionId != received.ConnectionId)
        {
            return;
        }

        switch (received.Message)
        {
            case JobProgress progress when Matches(active, progress.JobId, progress.DispatchId):
                if (progress.Stage == "verifying")
                {
                    await _jobs.TryMarkVerifyingAsync(
                        active.Job.Id,
                        active.DispatchId,
                        active.ConnectionId,
                        cancellationToken).ConfigureAwait(false);
                }

                break;
            case JobCompleted completed when Matches(active, completed.JobId, completed.DispatchId):
                await CompleteAsync(active, completed, cancellationToken).ConfigureAwait(false);
                break;
            case JobFailed failed when Matches(active, failed.JobId, failed.DispatchId):
                await FailAsync(active, failed, cancellationToken).ConfigureAwait(false);
                break;
        }
    }

    private async Task CompleteAsync(
        ActiveDispatch active,
        JobCompleted completed,
        CancellationToken cancellationToken)
    {
        if (!await _jobs.TryRecordCompletionAsync(
                active.Job.Id,
                active.DispatchId,
                active.ConnectionId,
                completed.OutputSize,
                completed.OutputSha256,
                cancellationToken).ConfigureAwait(false))
        {
            try
            {
                var failed = await _jobs.TryFailLeaseAsync(
                    active.Job.Id,
                    active.DispatchId,
                    active.ConnectionId,
                    "internal_error",
                    "The agent completed the job before verification started.",
                    cancellationToken).ConfigureAwait(false);
                await NotifyFailedIfTransitionedAsync(
                    failed,
                    active.Job.Id,
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                if (ReferenceEquals(_active, active))
                {
                    _active = null;
                    _events.Writer.TryWrite(WakeEvent.Instance);
                }
            }

            return;
        }

        try
        {
            await _spool.PromoteResultAsync(
                active.Job.Id,
                active.Job.Extension,
                completed.OutputSha256,
                completed.OutputSize,
                cancellationToken).ConfigureAwait(false);
            if (await _jobs.TryFinishSuccessAsync(
                    active.Job.Id,
                    active.DispatchId,
                    active.ConnectionId,
                    cancellationToken).ConfigureAwait(false))
            {
                var succeeded = await _jobs.GetAsync(active.Job.Id, cancellationToken).ConfigureAwait(false);
                if (succeeded is not null)
                {
                    NotifyBestEffort(succeeded);
                }
            }
        }
        catch (SpoolException)
        {
            var failed = await _jobs.TryFailLeaseAsync(
                active.Job.Id,
                active.DispatchId,
                active.ConnectionId,
                "result_corrupt",
                "The signed result failed integrity verification.",
                cancellationToken).ConfigureAwait(false);
            await NotifyFailedIfTransitionedAsync(
                failed,
                active.Job.Id,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (ReferenceEquals(_active, active))
            {
                _active = null;
                _events.Writer.TryWrite(WakeEvent.Instance);
            }
        }
    }

    private async Task FailAsync(
        ActiveDispatch active,
        JobFailed failed,
        CancellationToken cancellationToken)
    {
        var requeued = RetryableErrors.Contains(failed.ErrorCode) &&
            active.Job.AttemptCount < 2 &&
            await _jobs.TryRequeueLeaseAsync(
                active.Job.Id,
                active.DispatchId,
                active.ConnectionId,
                cancellationToken).ConfigureAwait(false);
        if (!requeued)
        {
            var transitioned = await _jobs.TryFailLeaseAsync(
                active.Job.Id,
                active.DispatchId,
                active.ConnectionId,
                failed.ErrorCode,
                failed.ErrorMessage,
                cancellationToken).ConfigureAwait(false);
            await NotifyFailedIfTransitionedAsync(
                transitioned,
                active.Job.Id,
                cancellationToken).ConfigureAwait(false);
        }

        if (ReferenceEquals(_active, active))
        {
            _active = null;
            _events.Writer.TryWrite(WakeEvent.Instance);
        }
    }

    private async Task DispatchNextAsync(CancellationToken cancellationToken)
    {
        if (_active is not null)
        {
            return;
        }

        var connection = _pipe.CurrentConnection;
        if (connection is null)
        {
            while (await _jobs.TryMarkNextWaitingForAgentAsync(cancellationToken).ConfigureAwait(false))
            {
            }

            return;
        }

        if (_blockedConnectionId == connection.ConnectionId)
        {
            return;
        }

        await _jobs.RequeueWaitingForAgentAsync(cancellationToken).ConfigureAwait(false);
        var job = await _jobs.ClaimNextAsync(connection.ConnectionId, cancellationToken).ConfigureAwait(false);
        if (job?.DispatchId is not { } dispatchId || job.LeaseConnectionId != connection.ConnectionId)
        {
            return;
        }

        var active = new ActiveDispatch(job, connection.ConnectionId, dispatchId);
        _active = active;
        var command = new SignJobCommand(
            job.Id,
            dispatchId,
            job.AttemptCount,
            job.Extension,
            job.CanonicalParametersJson,
            job.InputSize,
            job.InputSha256);
        try
        {
            await _pipe.SendAsync(connection.ConnectionId, command, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            _blockedConnectionId = active.ConnectionId;
            await ReleaseActiveLeaseAsync("recovery_exhausted", cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ReleaseActiveLeaseAsync(string exhaustedCode, CancellationToken cancellationToken)
    {
        var active = _active;
        if (active is null)
        {
            return;
        }

        var requeued = active.Job.AttemptCount < 2 &&
            await _jobs.TryRequeueLeaseAsync(
                active.Job.Id,
                active.DispatchId,
                active.ConnectionId,
                cancellationToken).ConfigureAwait(false);
        if (!requeued)
        {
            var transitioned = await _jobs.TryFailLeaseAsync(
                active.Job.Id,
                active.DispatchId,
                active.ConnectionId,
                exhaustedCode,
                "Signing recovery was exhausted.",
                cancellationToken).ConfigureAwait(false);
            await NotifyFailedIfTransitionedAsync(
                transitioned,
                active.Job.Id,
                cancellationToken).ConfigureAwait(false);
        }

        if (ReferenceEquals(_active, active))
        {
            _active = null;
        }
    }

    private async Task ResumePendingCompletionsAsync(CancellationToken cancellationToken)
    {
        while (await _jobs.GetNextPendingCompletionAsync(cancellationToken).ConfigureAwait(false) is { } pending)
        {
            try
            {
                await _spool.PromoteResultAsync(
                    pending.Id,
                    pending.Extension,
                    pending.ResultSha256!,
                    pending.ResultSize!.Value,
                    cancellationToken).ConfigureAwait(false);
                if (await _jobs.TryFinishRecoveredSuccessAsync(
                        pending.Id,
                        pending.ResultSize.Value,
                        pending.ResultSha256!,
                        cancellationToken).ConfigureAwait(false))
                {
                    var succeeded = await _jobs.GetAsync(pending.Id, cancellationToken).ConfigureAwait(false);
                    if (succeeded is not null)
                    {
                        NotifyBestEffort(succeeded);
                    }
                }
            }
            catch (SpoolException)
            {
                var failed = await _jobs.TryFailRecoveredCompletionAsync(
                    pending.Id,
                    pending.ResultSize!.Value,
                    pending.ResultSha256!,
                    "result_corrupt",
                    "The signed result failed integrity verification.",
                    cancellationToken).ConfigureAwait(false);
                await NotifyFailedIfTransitionedAsync(
                    failed,
                    pending.Id,
                    cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task NotifyFailedIfTransitionedAsync(
        bool transitioned,
        Guid jobId,
        CancellationToken cancellationToken)
    {
        if (!transitioned)
        {
            return;
        }

        var failed = await _jobs.GetAsync(jobId, cancellationToken).ConfigureAwait(false);
        if (failed?.State == JobState.Failed)
        {
            NotifyBestEffort(failed);
        }
    }

    private void NotifyBestEffort(Job job)
    {
        try
        {
            _notifier.Notify(job);
        }
        catch (Exception)
        {
        }
    }

    private void OnConnectionStateChanged(object? sender, AgentConnectionStateChangedEventArgs change) =>
        _events.Writer.TryWrite(new ConnectionEvent(change));

    private void OnMessageReceived(object? sender, AgentMessageReceivedEventArgs message) =>
        _events.Writer.TryWrite(new MessageEvent(message));

    private static bool Matches(ActiveDispatch active, Guid jobId, Guid dispatchId) =>
        active.Job.Id == jobId && active.DispatchId == dispatchId;

    private abstract record DispatcherEvent;

    private sealed record WakeEvent : DispatcherEvent
    {
        public static WakeEvent Instance { get; } = new();
    }

    private sealed record ConnectionEvent(AgentConnectionStateChangedEventArgs Change) : DispatcherEvent;

    private sealed record MessageEvent(AgentMessageReceivedEventArgs Message) : DispatcherEvent;

    private sealed record ActiveDispatch(Job Job, Guid ConnectionId, Guid DispatchId);
}
