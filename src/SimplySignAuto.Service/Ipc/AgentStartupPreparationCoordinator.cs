using System.Threading.Channels;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.Service.Ipc;

public enum AgentStartupPreparationStatus
{
    Pending,
    Running,
    Completed,
}

public sealed record AgentStartupPreparationSnapshot(
    AgentStartupPreparationStatus Status,
    Guid? RequestId,
    PrepareSimplySignSessionResult? Result);

public interface IAgentStartupPreparationTransport
{
    event EventHandler<AgentConnectionStateChangedEventArgs>? ConnectionStateChanged;

    event EventHandler<AgentMessageReceivedEventArgs>? MessageReceived;

    AgentConnectionSnapshot? CurrentConnection { get; }

    Task SendPreparationAsync(
        Guid connectionId,
        PrepareSimplySignSessionCommand command,
        CancellationToken cancellationToken);
}

public interface IAgentStartupPreparationRuntime
{
    AgentStartupPreparationSnapshot Current { get; }

    Task RunAsync(CancellationToken cancellationToken);
}

public sealed class AgentStartupPreparationCoordinator : IAgentStartupPreparationRuntime
{
    private static readonly TimeSpan FailedResultRetryDelay = TimeSpan.FromSeconds(60);
    private readonly object _sync = new();
    private readonly IAgentStartupPreparationTransport _transport;
    private readonly Func<Guid> _requestIdFactory;
    private readonly Func<CancellationToken, Task> _retryDelayAsync;
    private readonly Channel<CoordinatorEvent> _events = Channel.CreateUnbounded<CoordinatorEvent>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false,
            AllowSynchronousContinuations = false,
        });
    private int _status = (int)AgentStartupPreparationStatus.Pending;
    private Guid? _requestId;
    private Guid? _lastSentConnectionId;
    private int? _lastSentProcessId;
    private PrepareSimplySignSessionResult? _result;
    private int _running;

    public AgentStartupPreparationCoordinator(
        IAgentStartupPreparationTransport transport,
        Func<Guid>? requestIdFactory = null)
        : this(
            transport,
            requestIdFactory,
            cancellationToken => Task.Delay(FailedResultRetryDelay, cancellationToken))
    {
    }

    internal AgentStartupPreparationCoordinator(
        IAgentStartupPreparationTransport transport,
        Func<Guid>? requestIdFactory,
        Func<CancellationToken, Task> retryDelayAsync)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        _requestIdFactory = requestIdFactory ?? Guid.NewGuid;
        _retryDelayAsync = retryDelayAsync ?? throw new ArgumentNullException(nameof(retryDelayAsync));
    }

    public AgentStartupPreparationSnapshot Current
    {
        get
        {
            lock (_sync)
            {
                return new AgentStartupPreparationSnapshot(
                    (AgentStartupPreparationStatus)_status,
                    _requestId,
                    _result);
            }
        }
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _running, 1) != 0)
        {
            throw new InvalidOperationException("startup_preparation_already_running");
        }

        _transport.ConnectionStateChanged += OnConnectionStateChanged;
        _transport.MessageReceived += OnMessageReceived;
        try
        {
            if (_transport.CurrentConnection is { } current)
            {
                _events.Writer.TryWrite(new Connected(current.ConnectionId, current.ProcessId));
            }

            await foreach (var item in _events.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                switch (item)
                {
                    case Connected connected:
                        await HandleConnectedAsync(
                            connected.ConnectionId,
                            connected.ProcessId,
                            cancellationToken).ConfigureAwait(false);
                        break;
                    case Disconnected disconnected:
                        lock (_sync)
                        {
                            if (_lastSentConnectionId == disconnected.ConnectionId)
                            {
                                _lastSentConnectionId = null;
                            }
                        }
                        break;
                    case ResultReceived received:
                        if (Complete(received.ConnectionId, received.Result))
                        {
                            await RetryAfterFailureAsync(cancellationToken).ConfigureAwait(false);
                        }
                        break;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            _transport.ConnectionStateChanged -= OnConnectionStateChanged;
            _transport.MessageReceived -= OnMessageReceived;
            Volatile.Write(ref _running, 0);
        }
    }

    private async Task HandleConnectedAsync(
        Guid connectionId,
        int processId,
        CancellationToken cancellationToken)
    {
        Guid requestId;
        lock (_sync)
        {
            if (_status == (int)AgentStartupPreparationStatus.Completed)
            {
                if (_lastSentProcessId == processId)
                {
                    return;
                }

                _status = (int)AgentStartupPreparationStatus.Pending;
                _requestId = null;
                _result = null;
                _lastSentConnectionId = null;
            }

            if (_lastSentConnectionId == connectionId)
            {
                return;
            }

            if (Interlocked.CompareExchange(
                    ref _status,
                    (int)AgentStartupPreparationStatus.Running,
                    (int)AgentStartupPreparationStatus.Pending) ==
                (int)AgentStartupPreparationStatus.Pending)
            {
                _requestId = _requestIdFactory();
                if (_requestId == Guid.Empty)
                {
                    throw new InvalidOperationException("startup_preparation_request_id_invalid");
                }

                _result = null;
            }

            requestId = _requestId
                ?? throw new InvalidOperationException("startup_preparation_request_id_missing");
            _lastSentConnectionId = connectionId;
            _lastSentProcessId = processId;
        }

        try
        {
            await _transport.SendPreparationAsync(
                connectionId,
                new PrepareSimplySignSessionCommand(requestId),
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error) when (
            error is IOException or ObjectDisposedException or ProtocolException or OperationCanceledException)
        {
            lock (_sync)
            {
                if (_lastSentConnectionId == connectionId)
                {
                    _lastSentConnectionId = null;
                }
            }
        }
    }

    private bool Complete(Guid connectionId, PrepareSimplySignSessionResult result)
    {
        lock (_sync)
        {
            if (_status != (int)AgentStartupPreparationStatus.Running ||
                result.RequestId != _requestId ||
                _lastSentConnectionId != connectionId ||
                _transport.CurrentConnection?.ConnectionId != connectionId)
            {
                return false;
            }

            _result = result;
            if (result.State == SimplySignSessionState.Ready)
            {
                Volatile.Write(ref _status, (int)AgentStartupPreparationStatus.Completed);
                return false;
            }

            _requestId = null;
            Volatile.Write(ref _status, (int)AgentStartupPreparationStatus.Pending);
            return true;
        }
    }

    private async Task RetryAfterFailureAsync(CancellationToken cancellationToken)
    {
        await _retryDelayAsync(cancellationToken).ConfigureAwait(false);
        var current = _transport.CurrentConnection;
        if (current is null)
        {
            return;
        }

        lock (_sync)
        {
            if (_status != (int)AgentStartupPreparationStatus.Pending)
            {
                return;
            }

            if (_lastSentConnectionId == current.ConnectionId)
            {
                _lastSentConnectionId = null;
            }
        }

        await HandleConnectedAsync(
            current.ConnectionId,
            current.ProcessId,
            cancellationToken).ConfigureAwait(false);
    }

    private void OnConnectionStateChanged(object? sender, AgentConnectionStateChangedEventArgs args) =>
        _events.Writer.TryWrite(args.Status == AgentConnectionStatus.Connected
            ? new Connected(args.ConnectionId, args.ProcessId)
            : new Disconnected(args.ConnectionId));

    private void OnMessageReceived(object? sender, AgentMessageReceivedEventArgs args)
    {
        if (args.Message is PrepareSimplySignSessionResult result)
        {
            _events.Writer.TryWrite(new ResultReceived(args.ConnectionId, result));
        }
    }

    private abstract record CoordinatorEvent;
    private sealed record Connected(Guid ConnectionId, int ProcessId) : CoordinatorEvent;
    private sealed record Disconnected(Guid ConnectionId) : CoordinatorEvent;
    private sealed record ResultReceived(
        Guid ConnectionId,
        PrepareSimplySignSessionResult Result) : CoordinatorEvent;
}
