using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.Agent.Sessions;
using SimplySignAuto.Agent.Signing;
using SimplySignAuto.Protocol;
using SimplySignAuto.Service.Ipc;
using SimplySignAuto.Service.Jobs;

namespace SimplySignAuto.App.Manual;

internal sealed class InProcessSigningTransport :
    IAgentPipeTransport,
    ILocalJobTransport,
    IAgentManagementTransport,
    IAsyncDisposable
{
    private readonly object _sync = new();
    private readonly SigningWorker _worker;
    private readonly AgentConnectionIdentity _identity;
    private readonly IReadOnlyList<string> _capabilities;
    private readonly TimeProvider _timeProvider;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Guid _connectionId = Guid.NewGuid();
    private ILocalJobRequestHandler? _localJobs;
    private IServiceManagementSnapshotProvider? _management;
    private AgentConnectionSnapshot? _connection;
    private AgentHeartbeat? _heartbeat;
    private Guid? _currentJobId;
    private Task _currentJobCompletion = Task.CompletedTask;
    private bool _acceptingJobs;
    private int _disposed;

    public InProcessSigningTransport(
        SigningWorker worker,
        InteractiveSessionInfo session,
        IReadOnlyList<string> capabilities,
        TimeProvider? timeProvider = null)
    {
        _worker = worker ?? throw new ArgumentNullException(nameof(worker));
        ArgumentNullException.ThrowIfNull(session);
        if (session.SessionId <= 0 || string.IsNullOrWhiteSpace(session.UserSid))
        {
            throw new ArgumentException("The interactive session is invalid.", nameof(session));
        }

        _identity = new AgentConnectionIdentity(
            Environment.ProcessId,
            session.SessionId,
            session.UserSid);
        _capabilities = Array.AsReadOnly(
            (capabilities ?? throw new ArgumentNullException(nameof(capabilities))).ToArray());
        if (_capabilities.Count == 0)
        {
            throw new ArgumentException("At least one signing capability is required.", nameof(capabilities));
        }

        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public event EventHandler<AgentConnectionStateChangedEventArgs>? ConnectionStateChanged;

    public event EventHandler<AgentMessageReceivedEventArgs>? MessageReceived;

    public AgentConnectionSnapshot? CurrentConnection
    {
        get
        {
            lock (_sync)
            {
                return _connection;
            }
        }
    }

    public Guid? CurrentJobId
    {
        get
        {
            lock (_sync)
            {
                return _currentJobId;
            }
        }
    }

    public void Configure(
        ILocalJobRequestHandler localJobs,
        IServiceManagementSnapshotProvider management)
    {
        ArgumentNullException.ThrowIfNull(localJobs);
        ArgumentNullException.ThrowIfNull(management);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        lock (_sync)
        {
            if (_connection is not null || _localJobs is not null || _management is not null)
            {
                throw new InvalidOperationException("manual_transport_already_configured");
            }

            _localJobs = localJobs;
            _management = management;
        }
    }

    public void Connect()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        AgentConnectionSnapshot connection;
        lock (_sync)
        {
            if (_localJobs is null || _management is null)
            {
                throw new InvalidOperationException("manual_transport_not_configured");
            }

            if (_connection is not null)
            {
                throw new InvalidOperationException("manual_transport_already_connected");
            }

            connection = new AgentConnectionSnapshot(
                _connectionId,
                _identity.ProcessId,
                _identity.SessionId,
                _timeProvider.GetUtcNow().ToUniversalTime());
            _connection = connection;
            _acceptingJobs = true;
        }

        ConnectionStateChanged?.Invoke(
            this,
            new AgentConnectionStateChangedEventArgs(
                connection.ConnectionId,
                AgentConnectionStatus.Connected,
                connection.ProcessId,
                connection.SessionId,
                "connected"));
    }

    public Task SendAsync(
        Guid connectionId,
        SignJobCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        cancellationToken.ThrowIfCancellationRequested();
        TaskCompletionSource completion;
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            if (_connection?.ConnectionId != connectionId || !_acceptingJobs)
            {
                throw new IOException("manual_transport_disconnected");
            }

            if (_currentJobId is not null)
            {
                throw new InvalidOperationException("manual_worker_busy");
            }

            completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _currentJobId = command.JobId;
            _currentJobCompletion = completion.Task;
        }

        _ = ExecuteCommandAsync(connectionId, command, cancellationToken, completion);
        return Task.CompletedTask;
    }

    public async Task PublishHeartbeatAsync(
        AgentHeartbeat heartbeat,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(heartbeat);
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            EnsureConnected();
            if (heartbeat.SessionId != _identity.SessionId)
            {
                throw new ManagementUnavailableException(Guid.NewGuid());
            }

            var receivedAt = _timeProvider.GetUtcNow().ToUniversalTime();
            _heartbeat = heartbeat;
            _connection = _connection! with { LastHeartbeatUtc = receivedAt };
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    public Task<ManagementSnapshot> GetManagementSnapshotAsync(CancellationToken cancellationToken)
    {
        var (management, health) = GetManagementState(cancellationToken);
        return management.CreateAsync(health, cancellationToken);
    }

    public async Task<JobPageResponse> GetJobPageAsync(
        JobPageCursor? cursor,
        CancellationToken cancellationToken)
    {
        var (management, _) = GetManagementState(cancellationToken);
        var page = await management.CreateJobPageAsync(cursor, cancellationToken).ConfigureAwait(false);
        return new JobPageResponse(Guid.NewGuid(), page.Items, page.NextCursor, null, null);
    }

    public async Task<TerminalJobDeltaResponse> GetTerminalJobDeltaAsync(
        TerminalJobWatermark? watermark,
        TerminalJobCursor? cursor,
        CancellationToken cancellationToken)
    {
        var (management, _) = GetManagementState(cancellationToken);
        var delta = await management
            .CreateTerminalJobDeltaAsync(watermark, cursor, cancellationToken)
            .ConfigureAwait(false);
        return new TerminalJobDeltaResponse(
            Guid.NewGuid(),
            delta.Items,
            delta.NextCursor,
            delta.Watermark,
            null,
            null);
    }

    public Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromException<ServiceSettingsSummary>(
            new ManagementUnavailableException(Guid.NewGuid()));
    }

    public async Task<LocalJobCreateOutcome> CreateLocalJobAsync(
        LocalJobCreateRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = await SendLocalAsync(request, cancellationToken).ConfigureAwait(false);
        return response switch
        {
            LocalJobUploadLease lease when lease.RequestId == request.RequestId =>
                LocalJobCreateOutcome.FromLease(lease),
            LocalJobAccepted accepted when accepted.RequestId == request.RequestId =>
                LocalJobCreateOutcome.FromAccepted(accepted),
            LocalJobRejected rejected when rejected.RequestId == request.RequestId =>
                throw Rejected(rejected),
            _ => throw new LocalJobException("local_response_mismatch"),
        };
    }

    public async Task<LocalJobAccepted> CompleteLocalJobAsync(
        LocalJobUploadCompleted completed,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(completed);
        var response = await SendLocalAsync(completed, cancellationToken).ConfigureAwait(false);
        return response switch
        {
            LocalJobAccepted accepted when accepted.RequestId == completed.RequestId => accepted,
            LocalJobRejected rejected when rejected.RequestId == completed.RequestId =>
                throw Rejected(rejected),
            _ => throw new LocalJobException("local_response_mismatch"),
        };
    }

    public async Task<LocalJobResultMetadata> GetLocalResultAsync(
        LocalJobResultRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = await SendLocalAsync(request, cancellationToken).ConfigureAwait(false);
        return response switch
        {
            LocalJobResultMetadata result when result.RequestId == request.RequestId => result,
            LocalJobRejected rejected when rejected.RequestId == request.RequestId =>
                throw Rejected(rejected),
            _ => throw new LocalJobException("local_response_mismatch"),
        };
    }

    public void StopAcceptingNewJobs()
    {
        lock (_sync)
        {
            _acceptingJobs = false;
        }
    }

    public async Task DrainAsync(CancellationToken cancellationToken)
    {
        Task current;
        lock (_sync)
        {
            current = _currentJobCompletion;
        }

        await current.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        StopAcceptingNewJobs();
        await DrainAsync(CancellationToken.None).ConfigureAwait(false);
        AgentConnectionSnapshot? disconnected;
        lock (_sync)
        {
            disconnected = _connection;
            _connection = null;
            _localJobs = null;
            _management = null;
        }

        _lifetime.Cancel();
        _lifetime.Dispose();
        if (disconnected is not null)
        {
            ConnectionStateChanged?.Invoke(
                this,
                new AgentConnectionStateChangedEventArgs(
                    disconnected.ConnectionId,
                    AgentConnectionStatus.Disconnected,
                    disconnected.ProcessId,
                    disconnected.SessionId,
                    "disconnected"));
        }
    }

    private async Task ExecuteCommandAsync(
        Guid connectionId,
        SignJobCommand command,
        CancellationToken cancellationToken,
        TaskCompletionSource completion)
    {
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            await using var publication = await _worker
                .PreparePublicationAsync(
                    command,
                    (percent, stage, token) =>
                    {
                        RaiseMessage(
                            connectionId,
                            new JobProgress(command.JobId, command.DispatchId, percent, stage));
                        return Task.CompletedTask;
                    },
                    linked.Token)
                .ConfigureAwait(false);
            await publication.PublishAsync(
                (terminal, _) =>
                {
                    RaiseMessage(connectionId, terminal);
                    return Task.CompletedTask;
                },
                linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (
            cancellationToken.IsCancellationRequested || _lifetime.IsCancellationRequested)
        {
        }
        catch (Exception)
        {
            RaiseMessage(
                connectionId,
                new JobFailed(
                    command.JobId,
                    command.DispatchId,
                    "internal_error",
                    "The signing operation failed."));
        }
        finally
        {
            lock (_sync)
            {
                if (_currentJobId == command.JobId)
                {
                    _currentJobId = null;
                }
            }

            completion.TrySetResult();
        }
    }

    private async Task<AgentMessage> SendLocalAsync(
        AgentMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ILocalJobRequestHandler localJobs;
        lock (_sync)
        {
            EnsureConnected();
            localJobs = _localJobs!;
        }

        try
        {
            return await localJobs
                .HandleAsync(request, _identity, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            throw new LocalJobException("local_job_unavailable");
        }
    }

    private (IServiceManagementSnapshotProvider Provider, AgentHealthSnapshot Health)
        GetManagementState(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            EnsureConnected();
            return (
                _management!,
                new AgentHealthSnapshot(
                    _connectionId,
                    _identity.SessionId,
                    _capabilities,
                    _connection!.LastHeartbeatUtc,
                    _heartbeat));
        }
    }

    private void RaiseMessage(Guid connectionId, AgentMessage message)
    {
        lock (_sync)
        {
            if (_connection?.ConnectionId != connectionId)
            {
                return;
            }
        }

        MessageReceived?.Invoke(
            this,
            new AgentMessageReceivedEventArgs(connectionId, message));
    }

    private void EnsureConnected()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (_connection is null || _localJobs is null || _management is null)
        {
            throw new ManagementUnavailableException(Guid.NewGuid());
        }
    }

    private static LocalJobException Rejected(LocalJobRejected rejected) =>
        new(rejected.ErrorCode, rejected.CorrelationId, rejected.GetDisposition());
}
