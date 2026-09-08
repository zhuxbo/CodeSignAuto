using System.IO.Pipes;
using System.Runtime.ExceptionServices;
using System.Security.Principal;
using CodeSignAuto.Agent.LocalJobs;
using CodeSignAuto.Agent.Diagnostics;
using CodeSignAuto.Protocol;

namespace CodeSignAuto.Agent.Ipc;

public sealed class ManagementUnavailableException : Exception
{
    public ManagementUnavailableException(Guid correlationId)
        : base("management_unavailable")
    {
        CorrelationId = correlationId == Guid.Empty ? throw new ArgumentException("Correlation ID is required.", nameof(correlationId)) : correlationId;
    }

    public string Code => "management_unavailable";

    public Guid CorrelationId { get; }
}

public interface IAgentDelay
{
    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

public sealed class SystemAgentDelay : IAgentDelay
{
    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) => Task.Delay(delay, cancellationToken);
}

public delegate Task JobProgressReporter(int percent, string stage, CancellationToken cancellationToken);

public delegate Task<JobTerminalMessage> SignJobCommandHandler(
    SignJobCommand command,
    JobProgressReporter progress,
    CancellationToken cancellationToken);

public delegate Task<JobTerminalPublication> PrepareSignJobCommandHandler(
    SignJobCommand command,
    JobProgressReporter progress,
    CancellationToken cancellationToken);

public delegate Task<PrepareSimplySignSessionResult> PrepareSimplySignSessionCommandHandler(
    PrepareSimplySignSessionCommand command,
    CancellationToken cancellationToken);

public interface IAgentControlCommandHandler
{
    Task<AgentControlResponse> ExecuteAsync(
        AgentControlRequest request,
        CancellationToken cancellationToken);
}

public sealed class AgentStartupPreparationCache : IDisposable
{
    private const int MaximumCompleted = 16;
    private readonly object _sync = new();
    private readonly PrepareSimplySignSessionCommandHandler _handler;
    private readonly IAgentDiagnosticSink _diagnostics;
    private readonly Dictionary<Guid, Lazy<Task<PrepareSimplySignSessionResult>>> _entries = [];
    private readonly Queue<Guid> _completed = [];
    private readonly CancellationTokenSource _lifetime = new();
    private int _disposed;

    public AgentStartupPreparationCache(
        PrepareSimplySignSessionCommandHandler handler,
        IAgentDiagnosticSink? diagnostics = null)
    {
        _handler = handler ?? throw new ArgumentNullException(nameof(handler));
        _diagnostics = diagnostics.Safe();
    }

    public Task<PrepareSimplySignSessionResult> ExecuteAsync(
        PrepareSimplySignSessionCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        Lazy<Task<PrepareSimplySignSessionResult>> entry;
        lock (_sync)
        {
            if (!_entries.TryGetValue(command.RequestId, out entry!))
            {
                entry = new Lazy<Task<PrepareSimplySignSessionResult>>(
                    () => ExecuteOwnedAsync(command),
                    LazyThreadSafetyMode.ExecutionAndPublication);
                _entries.Add(command.RequestId, entry);
            }
        }

        var operation = entry.Value;

        return cancellationToken.CanBeCanceled
            ? operation.WaitAsync(cancellationToken)
            : operation;
    }

    private async Task<PrepareSimplySignSessionResult> ExecuteOwnedAsync(
        PrepareSimplySignSessionCommand command)
    {
        PrepareSimplySignSessionResult result;
        try
        {
            result = await _handler(command, _lifetime.Token).ConfigureAwait(false);
            if (result.RequestId != command.RequestId)
            {
                _diagnostics.Report(new AgentDiagnostic(
                    "startup_preparation",
                    "internal_error",
                    new InvalidOperationException("startup_preparation_request_id_mismatch")));
                result = new PrepareSimplySignSessionResult(
                    command.RequestId,
                    SimplySignSessionState.Failed,
                    "internal_error");
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception error)
        {
            _diagnostics.Report(new AgentDiagnostic("startup_preparation", "internal_error", error));
            result = new PrepareSimplySignSessionResult(
                command.RequestId,
                SimplySignSessionState.Failed,
                "internal_error");
        }

        lock (_sync)
        {
            _completed.Enqueue(command.RequestId);
            while (_completed.Count > MaximumCompleted)
            {
                _entries.Remove(_completed.Dequeue());
            }
        }
        return result;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _lifetime.Cancel();
            _lifetime.Dispose();
        }
    }
}

public interface IAgentManagementTransport
{
    Guid? CurrentJobId { get; }

    Task PublishHeartbeatAsync(AgentHeartbeat heartbeat, CancellationToken cancellationToken);

    Task<ManagementSnapshot> GetManagementSnapshotAsync(CancellationToken cancellationToken);

    Task<JobPageResponse> GetJobPageAsync(JobPageCursor? cursor, CancellationToken cancellationToken) =>
        Task.FromException<JobPageResponse>(new ManagementUnavailableException(Guid.NewGuid()));

    Task<TerminalJobDeltaResponse> GetTerminalJobDeltaAsync(
        TerminalJobWatermark? watermark,
        TerminalJobCursor? cursor,
        CancellationToken cancellationToken) =>
        Task.FromException<TerminalJobDeltaResponse>(new ManagementUnavailableException(Guid.NewGuid()));

    Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken) =>
        Task.FromException<ServiceSettingsSummary>(new ManagementUnavailableException(Guid.NewGuid()));
}

public sealed class AgentPipeClient : IAgentManagementTransport, ILocalJobTransport
{
    public const string PipeName = "CodeSignAuto.Agent.v2";
    public static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(5);

    private readonly Func<CancellationToken, ValueTask<Stream>> _connector;
    private readonly IAgentDelay _delay;
    private readonly object _jobSync = new();
    private readonly Action? _admissionLocked;
    private readonly Func<Guid> _requestIdFactory;
    private readonly TimeSpan _managementTimeout;
    private readonly TimeSpan _localCreateTimeout;
    private readonly TimeSpan _localCompleteTimeout;
    private readonly TimeSpan _localResultTimeout;
    private readonly Func<JobTerminalMessage, IReadOnlyList<AgentMessage>>? _postTerminalMessages;
    private readonly Action? _localReconnectWaitStarted;
    private readonly object _managementSync = new();
    private readonly Dictionary<Guid, PendingResponse> _pendingManagement = [];
    private readonly Dictionary<Guid, PendingResponse> _pendingLocal = [];
    private TaskCompletionSource _currentJobCompletion = CompletedSource();
    private TaskCompletionSource<ActiveManagementConnection> _managementConnectionAvailable =
        NewConnectionSource();
    private Guid? _currentJobId;
    private bool _acceptingNewJobs = true;
    private bool _connectionMayReconnect;
    private ActiveManagementConnection? _managementConnection;

    public AgentPipeClient()
        : this(ConnectNamedPipeAsync, new SystemAgentDelay())
    {
    }

    public AgentPipeClient(
        Func<CancellationToken, ValueTask<Stream>> connector,
        IAgentDelay delay)
        : this(connector, delay, admissionLocked: null)
    {
    }

    internal AgentPipeClient(
        Func<CancellationToken, ValueTask<Stream>> connector,
        IAgentDelay delay,
        Action? admissionLocked,
        Func<Guid>? requestIdFactory = null,
        TimeSpan? managementTimeout = null,
        TimeSpan? localCreateTimeout = null,
        TimeSpan? localCompleteTimeout = null,
        TimeSpan? localResultTimeout = null,
        Func<JobTerminalMessage, IReadOnlyList<AgentMessage>>? postTerminalMessages = null,
        Action? localReconnectWaitStarted = null)
    {
        _connector = connector ?? throw new ArgumentNullException(nameof(connector));
        _delay = delay ?? throw new ArgumentNullException(nameof(delay));
        _admissionLocked = admissionLocked;
        _requestIdFactory = requestIdFactory ?? Guid.NewGuid;
        _managementTimeout = managementTimeout ?? TimeSpan.FromSeconds(15);
        _localCreateTimeout = localCreateTimeout ?? TimeSpan.FromSeconds(15);
        _localCompleteTimeout = localCompleteTimeout ?? TimeSpan.FromMinutes(10);
        _localResultTimeout = localResultTimeout ?? TimeSpan.FromSeconds(30);
        _postTerminalMessages = postTerminalMessages;
        _localReconnectWaitStarted = localReconnectWaitStarted;
        if (_managementTimeout <= TimeSpan.Zero || _managementTimeout > TimeSpan.FromSeconds(15))
        {
            throw new ArgumentOutOfRangeException(nameof(managementTimeout));
        }

        if (_localCreateTimeout <= TimeSpan.Zero || _localCreateTimeout > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(localCreateTimeout));
        }

        if (_localCompleteTimeout <= TimeSpan.Zero || _localCompleteTimeout > TimeSpan.FromMinutes(30))
        {
            throw new ArgumentOutOfRangeException(nameof(localCompleteTimeout));
        }

        if (_localResultTimeout <= TimeSpan.Zero || _localResultTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(nameof(localResultTimeout));
        }
    }

    internal int PendingManagementRequestCount
    {
        get
        {
            lock (_managementSync)
            {
                return _pendingManagement.Count;
            }
        }
    }

    public Guid? CurrentJobId
    {
        get
        {
            lock (_jobSync)
            {
                return _currentJobId;
            }
        }
    }

    public Task CurrentJobCompletion
    {
        get
        {
            lock (_jobSync)
            {
                return _currentJobCompletion.Task;
            }
        }
    }

    public void StopAcceptingNewJobs()
    {
        lock (_jobSync)
        {
            _acceptingNewJobs = false;
        }
    }

    public Task RunAsync(
        AgentHello hello,
        Func<AgentHeartbeat> heartbeatFactory,
        SignJobCommandHandler commandHandler,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(commandHandler);
        return RunWithPublicationAsync(
            hello,
            heartbeatFactory,
            async (command, progress, token) => new JobTerminalPublication(
                await commandHandler(command, progress, token).ConfigureAwait(false)),
            cancellationToken);
    }

    internal async Task RunWithPublicationAsync(
        AgentHello hello,
        Func<AgentHeartbeat> heartbeatFactory,
        PrepareSignJobCommandHandler commandHandler,
        CancellationToken cancellationToken,
        AgentStartupPreparationCache? startupPreparation = null,
        IAgentControlCommandHandler? controlCommands = null)
    {
        ArgumentNullException.ThrowIfNull(hello);
        ArgumentNullException.ThrowIfNull(heartbeatFactory);
        ArgumentNullException.ThrowIfNull(commandHandler);
        if (hello.ProtocolVersion != LengthPrefixedJsonProtocol.ProtocolVersion)
        {
            throw new ArgumentException("The agent protocol version is not supported.", nameof(hello));
        }

        lock (_jobSync)
        {
            if (_currentJobId is not null)
            {
                throw new InvalidOperationException("agent_pipe_already_running");
            }

            if (_connectionMayReconnect)
            {
                _acceptingNewJobs = true;
                _connectionMayReconnect = false;
            }
        }

        await using var connection = await _connector(cancellationToken).ConfigureAwait(false);
        var writer = LengthPrefixedJsonProtocol.GetWriter(connection);
        await writer.WriteAsync(hello, cancellationToken).ConfigureAwait(false);

        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var activeManagement = RegisterManagementConnection(writer, lifetime);
        try
        {
            var heartbeatTask = SendHeartbeatsAsync(writer, hello.SessionId, heartbeatFactory, lifetime.Token);
            var receiveTask = ReceiveMessagesAsync(
                connection,
                writer,
                commandHandler,
                startupPreparation,
                controlCommands,
                lifetime.Token);
            var first = await Task.WhenAny(heartbeatTask, receiveTask).ConfigureAwait(false);
            var second = ReferenceEquals(first, heartbeatTask) ? receiveTask : heartbeatTask;
            var firstError = await CaptureErrorAsync(first, cancellationToken).ConfigureAwait(false);
            lifetime.Cancel();
            var secondError = await CaptureErrorAsync(second, cancellationToken, ignoreLinkedCancellation: true).ConfigureAwait(false);

            var error = firstError ?? secondError;
            if (error is not null)
            {
                ExceptionDispatchInfo.Capture(error).Throw();
            }
        }
        finally
        {
            ClearManagementConnection(activeManagement);
        }
    }

    public async Task<ManagementSnapshot> GetManagementSnapshotAsync(CancellationToken cancellationToken)
    {
        var response = await SendManagementRequestAsync<ManagementSnapshotResponse>(
            static requestId => new ManagementSnapshotRequest(requestId),
            cancellationToken).ConfigureAwait(false);
        if (response.Snapshot is { } snapshot)
        {
            return snapshot;
        }

        throw new ManagementUnavailableException(response.CorrelationId ?? Guid.NewGuid());
    }

    public async Task<JobPageResponse> GetJobPageAsync(
        JobPageCursor? cursor,
        CancellationToken cancellationToken)
    {
        var response = await SendManagementRequestAsync<JobPageResponse>(
            requestId => new JobPageRequest(requestId, cursor),
            cancellationToken).ConfigureAwait(false);
        if (response.ErrorCode is null)
        {
            return response;
        }

        throw new ManagementUnavailableException(response.CorrelationId ?? Guid.NewGuid());
    }

    public async Task<TerminalJobDeltaResponse> GetTerminalJobDeltaAsync(
        TerminalJobWatermark? watermark,
        TerminalJobCursor? cursor,
        CancellationToken cancellationToken)
    {
        var response = await SendManagementRequestAsync<TerminalJobDeltaResponse>(
            requestId => new TerminalJobDeltaRequest(requestId, watermark, cursor),
            cancellationToken).ConfigureAwait(false);
        if (response.ErrorCode is null)
        {
            return response;
        }

        throw new ManagementUnavailableException(response.CorrelationId ?? Guid.NewGuid());
    }

    public async Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken)
    {
        var response = await SendManagementRequestAsync<ServiceSettingsResponse>(
            static requestId => new ServiceSettingsRequest(requestId),
            cancellationToken).ConfigureAwait(false);
        if (response.Summary is { } summary)
        {
            return summary;
        }

        throw new ManagementUnavailableException(response.CorrelationId ?? Guid.NewGuid());
    }

    private async Task<TResponse> SendManagementRequestAsync<TResponse>(
        Func<Guid, AgentMessage> requestFactory,
        CancellationToken cancellationToken)
        where TResponse : AgentMessage
    {
        ArgumentNullException.ThrowIfNull(requestFactory);
        cancellationToken.ThrowIfCancellationRequested();
        ActiveManagementConnection connection;
        Guid requestId;
        TaskCompletionSource<AgentMessage> completion;
        lock (_managementSync)
        {
            connection = _managementConnection
                ?? throw new ManagementUnavailableException(Guid.NewGuid());
            requestId = _requestIdFactory();
            if (requestId == Guid.Empty ||
                _pendingManagement.ContainsKey(requestId) ||
                _pendingLocal.ContainsKey(requestId))
            {
                throw new ManagementUnavailableException(Guid.NewGuid());
            }

            completion = new TaskCompletionSource<AgentMessage>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            _pendingManagement.Add(
                requestId,
                new PendingResponse(completion, static response => response is TResponse));
        }

        var frameStarted = false;
        using var requestCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            connection.Lifetime.Token);
        requestCancellation.CancelAfter(_managementTimeout);
        try
        {
            try
            {
                await connection.Writer
                    .WriteAsync(
                        requestFactory(requestId),
                        requestCancellation.Token,
                        () => frameStarted = true)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                if (frameStarted)
                {
                    connection.Lifetime.Cancel();
                }

                cancellationToken.ThrowIfCancellationRequested();
                throw new ManagementUnavailableException(Guid.NewGuid());
            }
            catch (Exception error) when (error is IOException or ObjectDisposedException or ProtocolException)
            {
                connection.Lifetime.Cancel();
                throw new ManagementUnavailableException(Guid.NewGuid());
            }

            try
            {
                return (TResponse)await completion.Task
                    .WaitAsync(requestCancellation.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                cancellationToken.ThrowIfCancellationRequested();
                throw new ManagementUnavailableException(Guid.NewGuid());
            }
        }
        finally
        {
            lock (_managementSync)
            {
                _pendingManagement.Remove(requestId);
            }
        }
    }

    public async Task PublishHeartbeatAsync(
        AgentHeartbeat heartbeat,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(heartbeat);
        cancellationToken.ThrowIfCancellationRequested();
        ActiveManagementConnection connection;
        lock (_managementSync)
        {
            connection = _managementConnection
                ?? throw new ManagementUnavailableException(Guid.NewGuid());
        }

        try
        {
            await connection.Writer.WriteAsync(heartbeat, connection.Lifetime.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (connection.Lifetime.IsCancellationRequested)
        {
            throw new ManagementUnavailableException(Guid.NewGuid());
        }
        catch (Exception error) when (error is IOException or ObjectDisposedException or ProtocolException)
        {
            connection.Lifetime.Cancel();
            throw new ManagementUnavailableException(Guid.NewGuid());
        }
    }

    public async Task<LocalJobCreateOutcome> CreateLocalJobAsync(
        LocalJobCreateRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        AgentMessage response;
        for (var reconnectAttempt = 0; ; reconnectAttempt++)
        {
            try
            {
                response = await SendLocalRequestAsync(
                    request.RequestId,
                    request,
                    _localCreateTimeout,
                    cancellationToken).ConfigureAwait(false);
                break;
            }
            catch (LocalConnectionLostException error) when (reconnectAttempt == 0)
            {
                await WaitForReconnectAsync(error.Connection, _localCreateTimeout, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception error) when (
                error is LocalRequestTimedOutException or LocalConnectionLostException)
            {
                throw new LocalJobException("local_job_unavailable");
            }
        }

        return response switch
        {
            LocalJobUploadLease lease when lease.RequestId == request.RequestId =>
                LocalJobCreateOutcome.FromLease(lease),
            LocalJobAccepted accepted when accepted.RequestId == request.RequestId =>
                LocalJobCreateOutcome.FromAccepted(accepted),
            LocalJobRejected rejected when rejected.RequestId == request.RequestId =>
                throw new LocalJobException(
                    rejected.ErrorCode,
                    rejected.CorrelationId,
                    rejected.GetDisposition()),
            _ => throw new LocalJobException("local_response_mismatch"),
        };
    }

    public async Task<LocalJobAccepted> CompleteLocalJobAsync(
        LocalJobUploadCompleted completed,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(completed);
        AgentMessage? response = null;
        var timeoutAttempts = 0;
        var reconnectAttempts = 0;
        while (response is null)
        {
            try
            {
                response = await SendLocalRequestAsync(
                    completed.RequestId,
                    completed,
                    _localCompleteTimeout,
                    cancellationToken).ConfigureAwait(false);
                break;
            }
            catch (LocalRequestTimedOutException) when (timeoutAttempts++ == 0)
            {
            }
            catch (LocalConnectionLostException error) when (reconnectAttempts++ == 0)
            {
                await WaitForReconnectAsync(error.Connection, _localCompleteTimeout, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception error) when (
                error is LocalRequestTimedOutException or LocalConnectionLostException)
            {
                throw new LocalJobException("local_job_unavailable");
            }
        }

        return response switch
        {
            LocalJobAccepted accepted when accepted.RequestId == completed.RequestId => accepted,
            LocalJobRejected rejected when rejected.RequestId == completed.RequestId =>
                throw new LocalJobException(
                    rejected.ErrorCode,
                    rejected.CorrelationId,
                    rejected.GetDisposition()),
            _ => throw new LocalJobException("local_response_mismatch"),
        };
    }

    public async Task<LocalJobResultMetadata> GetLocalResultAsync(
        LocalJobResultRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        AgentMessage response;
        try
        {
            response = await SendLocalRequestAsync(
                request.RequestId,
                request,
                _localResultTimeout,
                cancellationToken).ConfigureAwait(false);
        }
        catch (LocalRequestTimedOutException)
        {
            throw new LocalJobException("local_job_unavailable");
        }
        return response switch
        {
            LocalJobResultMetadata metadata when metadata.RequestId == request.RequestId => metadata,
            LocalJobRejected rejected when rejected.RequestId == request.RequestId =>
                throw new LocalJobException(
                    rejected.ErrorCode,
                    rejected.CorrelationId,
                    rejected.GetDisposition()),
            _ => throw new LocalJobException("local_response_mismatch"),
        };
    }

    private async Task<AgentMessage> SendLocalRequestAsync(
        Guid requestId,
        AgentMessage request,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (requestId == Guid.Empty)
        {
            throw new LocalJobException("local_response_mismatch");
        }

        ActiveManagementConnection connection;
        TaskCompletionSource<AgentMessage> completion;
        lock (_managementSync)
        {
            connection = _managementConnection
                ?? throw new LocalConnectionLostException(null);
            if (_pendingLocal.ContainsKey(requestId) || _pendingManagement.ContainsKey(requestId))
            {
                throw new LocalJobException("local_response_mismatch");
            }

            completion = new TaskCompletionSource<AgentMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
            _pendingLocal.Add(
                requestId,
                new PendingResponse(completion, response => IsExpectedLocalResponse(request, response)));
        }

        var frameStarted = false;
        var frameCompleted = false;
        using var requestCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            connection.Lifetime.Token);
        requestCancellation.CancelAfter(timeout);
        try
        {
            try
            {
                await connection.Writer.WriteAsync(
                    request,
                    requestCancellation.Token,
                    () => frameStarted = true).ConfigureAwait(false);
                frameCompleted = true;
            }
            catch (OperationCanceledException)
            {
                if (frameStarted && !frameCompleted)
                {
                    connection.Lifetime.Cancel();
                }

                cancellationToken.ThrowIfCancellationRequested();
                throw new LocalConnectionLostException(connection);
            }
            catch (Exception error) when (error is IOException or ObjectDisposedException or ProtocolException)
            {
                connection.Lifetime.Cancel();
                throw new LocalConnectionLostException(connection);
            }

            try
            {
                return await completion.Task.WaitAsync(requestCancellation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (connection.Lifetime.IsCancellationRequested)
                {
                    throw new LocalConnectionLostException(connection);
                }

                throw new LocalRequestTimedOutException();
            }
        }
        finally
        {
            lock (_managementSync)
            {
                _pendingLocal.Remove(requestId);
            }
        }
    }

    private async Task SendHeartbeatsAsync(
        LengthPrefixedJsonWriter writer,
        int verifiedSessionId,
        Func<AgentHeartbeat> heartbeatFactory,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await _delay.DelayAsync(HeartbeatInterval, cancellationToken).ConfigureAwait(false);
            var heartbeat = heartbeatFactory();
            if (heartbeat.SessionId != verifiedSessionId)
            {
                throw new ProtocolException("agent_identity_mismatch", "The heartbeat session does not match the agent hello.");
            }

            await writer.WriteAsync(heartbeat, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ReceiveMessagesAsync(
        Stream connection,
        LengthPrefixedJsonWriter writer,
        PrepareSignJobCommandHandler commandHandler,
        AgentStartupPreparationCache? startupPreparation,
        IAgentControlCommandHandler? controlCommands,
        CancellationToken cancellationToken)
    {
        using var commandCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task<AgentMessage?>? readTask = null;
        Task? commandTask = null;
        var startupTasks = new List<Task>();
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                startupTasks.RemoveAll(static task => task.IsCompletedSuccessfully);
                readTask ??= ReadNextAsync(connection, commandCancellation.Token);
                if (commandTask is not null)
                {
                    var completed = await Task.WhenAny(readTask, commandTask).ConfigureAwait(false);
                    if (ReferenceEquals(completed, commandTask))
                    {
                        await commandTask.ConfigureAwait(false);
                        commandTask = null;
                        continue;
                    }
                }

                var message = await readTask.ConfigureAwait(false);
                readTask = null;
                if (message is null)
                {
                    if (commandTask is not null)
                    {
                        await commandTask.ConfigureAwait(false);
                    }

                    return;
                }

                switch (message)
                {
                    case SignJobCommand command when commandTask is null:
                        BeginJob(command.JobId);
                        commandTask = ExecuteCommandAsync(
                            command,
                            writer,
                            commandHandler,
                            commandCancellation.Token);
                        break;
                    case PrepareSimplySignSessionCommand command when startupPreparation is not null:
                        startupTasks.Add(ExecuteStartupPreparationAsync(
                            command,
                            writer,
                            startupPreparation,
                            cancellationToken));
                        break;
                    case AgentControlRequest request when controlCommands is not null:
                        await ExecuteControlCommandAsync(
                            request,
                            writer,
                            controlCommands,
                            cancellationToken).ConfigureAwait(false);
                        break;
                    case ManagementSnapshotResponse response:
                        DispatchManagementResponse(response);
                        break;
                    case JobPageResponse response:
                        DispatchManagementResponse(response);
                        break;
                    case TerminalJobDeltaResponse response:
                        DispatchManagementResponse(response);
                        break;
                    case ServiceSettingsResponse response:
                        DispatchManagementResponse(response);
                        break;
                    case LocalJobUploadLease or LocalJobAccepted or LocalJobRejected or LocalJobResultMetadata:
                        DispatchLocalResponse(message);
                        break;
                    default:
                        throw new ProtocolException(
                            "invalid_message_direction",
                            "The message is not valid in this direction.");
                }
            }
        }
        finally
        {
            commandCancellation.Cancel();
            if (readTask is not null)
            {
                await IgnoreLinkedCancellationAsync(readTask, commandCancellation.Token).ConfigureAwait(false);
            }

            if (commandTask is not null)
            {
                await IgnoreLinkedCancellationAsync(commandTask, commandCancellation.Token).ConfigureAwait(false);
            }

            await ObserveAllStartupTasksAsync(startupTasks, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task ObserveAllStartupTasksAsync(
        IReadOnlyList<Task> tasks,
        CancellationToken cancellationToken)
    {
        Exception? firstError = null;
        foreach (var task in tasks)
        {
            try
            {
                await task.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
            catch (Exception error)
            {
                firstError ??= error;
            }
        }

        if (firstError is not null)
        {
            ExceptionDispatchInfo.Capture(firstError).Throw();
        }
    }

    private static async Task ExecuteStartupPreparationAsync(
        PrepareSimplySignSessionCommand command,
        LengthPrefixedJsonWriter writer,
        AgentStartupPreparationCache cache,
        CancellationToken cancellationToken)
    {
        var result = await cache.ExecuteAsync(command, cancellationToken).ConfigureAwait(false);
        await writer.WriteAsync(result, cancellationToken).ConfigureAwait(false);
    }

    private static async Task ExecuteControlCommandAsync(
        AgentControlRequest request,
        LengthPrefixedJsonWriter writer,
        IAgentControlCommandHandler handler,
        CancellationToken cancellationToken)
    {
        var response = await handler.ExecuteAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.RequestId != request.RequestId ||
            !string.Equals(response.Operation, request.Operation, StringComparison.Ordinal))
        {
            throw new ProtocolException(
                "invalid_message",
                "The agent control response does not match the request.");
        }

        await writer.WriteAsync(response, cancellationToken).ConfigureAwait(false);
    }

    private static async Task IgnoreLinkedCancellationAsync(Task task, CancellationToken cancellationToken)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private static async Task<AgentMessage?> ReadNextAsync(
        Stream connection,
        CancellationToken cancellationToken)
    {
        try
        {
            return await LengthPrefixedJsonProtocol
                .ReadAsync<AgentMessage>(connection, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (ProtocolException error) when (error.Code == "unexpected_eof")
        {
            return null;
        }
    }

    private async Task ExecuteCommandAsync(
        SignJobCommand command,
        LengthPrefixedJsonWriter writer,
        PrepareSignJobCommandHandler commandHandler,
        CancellationToken cancellationToken)
    {
        try
        {
            Task ReportProgress(int percent, string stage, CancellationToken progressCancellation) =>
                writer.WriteAsync(
                    new JobProgress(command.JobId, command.DispatchId, percent, stage),
                    progressCancellation);
            await using var publication = await commandHandler(command, ReportProgress, cancellationToken)
                .ConfigureAwait(false);
            var terminal = publication.Terminal;
            if (terminal.JobId != command.JobId || terminal.DispatchId != command.DispatchId)
            {
                throw new ProtocolException("invalid_message", "The terminal message does not match the current dispatch.");
            }

            await publication.PublishAsync(
                writer.WriteAsync,
                cancellationToken).ConfigureAwait(false);
            if (_postTerminalMessages is not null)
            {
                foreach (var extra in _postTerminalMessages(terminal))
                {
                    await writer.WriteAsync(extra, cancellationToken).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            EndJob();
        }
    }

    private ActiveManagementConnection RegisterManagementConnection(
        LengthPrefixedJsonWriter writer,
        CancellationTokenSource lifetime)
    {
        var active = new ActiveManagementConnection(writer, lifetime);
        lock (_managementSync)
        {
            if (_managementConnection is not null)
            {
                throw new InvalidOperationException("agent_pipe_already_running");
            }

            _managementConnection = active;
            _managementConnectionAvailable.TrySetResult(active);
            return active;
        }
    }

    private void ClearManagementConnection(ActiveManagementConnection active)
    {
        PendingResponse[] pending;
        PendingResponse[] localPending;
        lock (_managementSync)
        {
            if (!ReferenceEquals(_managementConnection, active))
            {
                return;
            }

            _managementConnection = null;
            if (_managementConnectionAvailable.Task.IsCompleted)
            {
                _managementConnectionAvailable = NewConnectionSource();
            }
            pending = _pendingManagement.Values.ToArray();
            _pendingManagement.Clear();
            localPending = _pendingLocal.Values.ToArray();
            _pendingLocal.Clear();
        }

        foreach (var pendingResponse in pending)
        {
            pendingResponse.Completion.TrySetException(new ManagementUnavailableException(Guid.NewGuid()));
        }


        foreach (var pendingResponse in localPending)
        {
            pendingResponse.Completion.TrySetException(new LocalConnectionLostException(active));
        }

        lock (_jobSync)
        {
            _connectionMayReconnect = true;
        }
    }

    private async Task WaitForReconnectAsync(
        ActiveManagementConnection? previous,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        Task<ActiveManagementConnection> available;
        lock (_managementSync)
        {
            if (_managementConnection is { } current && !ReferenceEquals(current, previous))
            {
                return;
            }

            if (_managementConnectionAvailable.Task.IsCompleted)
            {
                _managementConnectionAvailable = NewConnectionSource();
            }

            available = _managementConnectionAvailable.Task;
        }

        _localReconnectWaitStarted?.Invoke();

        try
        {
            using var wait = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            wait.CancelAfter(timeout);
            await available.WaitAsync(wait.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new LocalJobException("local_job_unavailable");
        }
    }

    private void DispatchManagementResponse(AgentMessage response)
    {
        var requestId = response switch
        {
            ManagementSnapshotResponse snapshot => snapshot.RequestId,
            JobPageResponse page => page.RequestId,
            TerminalJobDeltaResponse delta => delta.RequestId,
            ServiceSettingsResponse settings => settings.RequestId,
            _ => Guid.Empty,
        };
        PendingResponse? pending;
        lock (_managementSync)
        {
            if (!_pendingManagement.TryGetValue(requestId, out pending))
            {
                return;
            }

            if (!pending.Accepts(response))
            {
                throw new ProtocolException(
                    "invalid_message",
                    "The response type does not match the pending request.");
            }

            _pendingManagement.Remove(requestId);
        }

        pending.Completion.TrySetResult(response);
    }

    private void DispatchLocalResponse(AgentMessage response)
    {
        var requestId = response switch
        {
            LocalJobUploadLease lease => lease.RequestId,
            LocalJobAccepted accepted => accepted.RequestId,
            LocalJobRejected rejected => rejected.RequestId,
            LocalJobResultMetadata metadata => metadata.RequestId,
            _ => Guid.Empty,
        };
        PendingResponse? pending;
        lock (_managementSync)
        {
            if (!_pendingLocal.TryGetValue(requestId, out pending))
            {
                return;
            }

            if (!pending.Accepts(response))
            {
                throw new ProtocolException(
                    "invalid_message",
                    "The response type does not match the pending request.");
            }

            _pendingLocal.Remove(requestId);
        }

        pending.Completion.TrySetResult(response);
    }

    private static bool IsExpectedLocalResponse(AgentMessage request, AgentMessage response) =>
        request switch
        {
            LocalJobCreateRequest => response is LocalJobUploadLease or LocalJobAccepted or LocalJobRejected,
            LocalJobUploadCompleted => response is LocalJobAccepted or LocalJobRejected,
            LocalJobResultRequest => response is LocalJobResultMetadata or LocalJobRejected,
            _ => false,
        };

    private sealed record PendingResponse(
        TaskCompletionSource<AgentMessage> Completion,
        Func<AgentMessage, bool> Accepts);

    private void BeginJob(Guid jobId)
    {
        lock (_jobSync)
        {
            if (!_acceptingNewJobs)
            {
                throw new ProtocolException("agent_shutting_down", "The agent is not accepting new jobs.");
            }

            if (_currentJobId is not null)
            {
                throw new ProtocolException("invalid_message", "Only one job may be active.");
            }

            _admissionLocked?.Invoke();
            _currentJobId = jobId;
            _currentJobCompletion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }
    }

    private void EndJob()
    {
        TaskCompletionSource completion;
        lock (_jobSync)
        {
            _currentJobId = null;
            completion = _currentJobCompletion;
        }

        completion.TrySetResult();
    }

    private static TaskCompletionSource CompletedSource()
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        completion.SetResult();
        return completion;
    }

    private static TaskCompletionSource<ActiveManagementConnection> NewConnectionSource() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static async Task<Exception?> CaptureErrorAsync(
        Task task,
        CancellationToken callerCancellation,
        bool ignoreLinkedCancellation = false)
    {
        try
        {
            await task.ConfigureAwait(false);
            return null;
        }
        catch (OperationCanceledException) when (
            callerCancellation.IsCancellationRequested || ignoreLinkedCancellation || task.IsCanceled)
        {
            return null;
        }
        catch (Exception error)
        {
            return error;
        }
    }

    private static async ValueTask<Stream> ConnectNamedPipeAsync(CancellationToken cancellationToken)
    {
        var pipe = new NamedPipeClientStream(
            ".",
            PipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            TokenImpersonationLevel.Impersonation);
        try
        {
            await pipe.ConnectAsync(cancellationToken).ConfigureAwait(false);
            return pipe;
        }
        catch
        {
            pipe.Dispose();
            throw;
        }
    }

    private sealed record ActiveManagementConnection(
        LengthPrefixedJsonWriter Writer,
        CancellationTokenSource Lifetime);

    private sealed class LocalRequestTimedOutException : Exception;

    private sealed class LocalConnectionLostException(ActiveManagementConnection? connection) : Exception
    {
        public ActiveManagementConnection? Connection { get; } = connection;
    }
}
