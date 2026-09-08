using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Channels;
using Microsoft.Win32.SafeHandles;
using CodeSignAuto.Core.Versioning;
using CodeSignAuto.Protocol;
using CodeSignAuto.Service.Jobs;

namespace CodeSignAuto.Service.Ipc;

public sealed record AgentConnectionIdentity(int ProcessId, int SessionId, string UserSid);

public sealed record AgentConnectionSnapshot(
    Guid ConnectionId,
    int ProcessId,
    int SessionId,
    DateTimeOffset? LastHeartbeatUtc);

public sealed record AgentHealthSnapshot(
    Guid ConnectionId,
    int SessionId,
    IReadOnlyList<string> Capabilities,
    DateTimeOffset? LastHeartbeatUtc,
    AgentHeartbeat? Heartbeat);

public interface IAgentHealthStatusSource
{
    AgentHealthSnapshot? CurrentHealth { get; }
}

public sealed class DisconnectedAgentHealthStatusSource : IAgentHealthStatusSource
{
    public AgentHealthSnapshot? CurrentHealth => null;
}

public enum AgentConnectionStatus
{
    Connected,
    Disconnected,
}

public sealed class AgentConnectionStateChangedEventArgs(
    Guid connectionId,
    AgentConnectionStatus status,
    int processId,
    int sessionId,
    string reason) : EventArgs
{
    public Guid ConnectionId { get; } = connectionId;
    public AgentConnectionStatus Status { get; } = status;
    public int ProcessId { get; } = processId;
    public int SessionId { get; } = sessionId;
    public string Reason { get; } = reason;
}

public sealed class AgentMessageReceivedEventArgs(Guid connectionId, AgentMessage message) : EventArgs
{
    public Guid ConnectionId { get; } = connectionId;
    public AgentMessage Message { get; } = message;
}

public interface IAgentPipeTransport
{
    event EventHandler<AgentConnectionStateChangedEventArgs>? ConnectionStateChanged;

    event EventHandler<AgentMessageReceivedEventArgs>? MessageReceived;

    AgentConnectionSnapshot? CurrentConnection { get; }

    Task SendAsync(Guid connectionId, SignJobCommand command, CancellationToken cancellationToken);
}

public interface IAgentPipeRuntime : IAgentPipeTransport
{
    Task RunAsync(CancellationToken cancellationToken);
}

public interface IAgentControlTransport
{
    Task<AgentControlResponse> SendControlAsync(
        AgentControlRequest request,
        CancellationToken cancellationToken);
}

public interface IAgentConnectionIdentityVerifier
{
    ValueTask<AgentConnectionIdentity> VerifyAsync(Stream connection, CancellationToken cancellationToken);
}

public interface IAgentClock
{
    DateTimeOffset UtcNow { get; }

    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

public sealed class SystemAgentClock : IAgentClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;

    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) => Task.Delay(delay, cancellationToken);
}

public sealed partial class WindowsAgentConnectionIdentityVerifier : IAgentConnectionIdentityVerifier
{
    public ValueTask<AgentConnectionIdentity> VerifyAsync(Stream connection, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows named-pipe identity verification is required.");
        }

        if (connection is not NamedPipeServerStream pipe)
        {
            throw new ArgumentException("A connected named-pipe server stream is required.", nameof(connection));
        }

        return ValueTask.FromResult(VerifyWindows(pipe));
    }

    [SupportedOSPlatform("windows")]
    private static AgentConnectionIdentity VerifyWindows(NamedPipeServerStream pipe)
    {
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var processId))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "Unable to determine the named-pipe client process.");
        }

        if (!ProcessIdToSessionId(processId, out var sessionId))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "Unable to determine the named-pipe client session.");
        }

        string? userSid = null;
        pipe.RunAsClient(() => userSid = WindowsIdentity.GetCurrent().User?.Value);
        if (string.IsNullOrEmpty(userSid))
        {
            throw new InvalidOperationException("Unable to determine the named-pipe client user.");
        }

        return new AgentConnectionIdentity(checked((int)processId), checked((int)sessionId), userSid);
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ProcessIdToSessionId(uint processId, out uint sessionId);
}

public sealed class AgentPipeServer :
    IAgentPipeRuntime,
    IAgentStartupPreparationTransport,
    IAgentControlTransport,
    IAgentHealthStatusSource
{
    public const string PipeName = "CodeSignAuto.Agent.v2";
    public static readonly TimeSpan HeartbeatTimeout = TimeSpan.FromSeconds(15);
    // The Agent owns a 100s relogin budget; keep transport cancellation outside it.
    public static readonly TimeSpan ControlTimeout = TimeSpan.FromSeconds(105);

    private readonly object _sync = new();
    private readonly string _signingUserSid;
    private readonly IAgentConnectionIdentityVerifier _identityVerifier;
    private readonly IAgentClock _clock;
    private readonly Func<CancellationToken, Task<Stream>> _acceptConnection;
    private readonly IServiceManagementSnapshotProvider _managementProvider;
    private readonly string _expectedProductIdentity;
    private ILocalJobRequestHandler _localJobs;
    private readonly Dictionary<Guid, PendingControlResponse> _pendingControls = [];
    private ActiveConnection? _current;
    private AgentHeartbeat? _lastHeartbeat;

    public AgentPipeServer(
        string signingUserSid,
        string expectedProductIdentity,
        IAgentConnectionIdentityVerifier? identityVerifier = null,
        IAgentClock? clock = null,
        Func<CancellationToken, Task<Stream>>? acceptConnection = null,
        IServiceManagementSnapshotProvider? managementProvider = null,
        ILocalJobRequestHandler? localJobs = null)
    {
        if (string.IsNullOrWhiteSpace(signingUserSid))
        {
            throw new ArgumentException("The signing user SID is required.", nameof(signingUserSid));
        }

        _signingUserSid = signingUserSid;
        _identityVerifier = identityVerifier ?? new WindowsAgentConnectionIdentityVerifier();
        _clock = clock ?? new SystemAgentClock();
        _acceptConnection = acceptConnection ?? (token => AcceptNamedPipeAsync(_signingUserSid, token));
        _managementProvider = managementProvider ?? UnavailableManagementSnapshotProvider.Instance;
        _localJobs = localJobs ?? UnavailableLocalJobRequestHandler.Instance;
        _expectedProductIdentity = ProductVersion.TryParse(expectedProductIdentity, out var version)
            ? version!.Identity
            : throw new ArgumentException("The expected product identity is invalid.", nameof(expectedProductIdentity));
    }

    internal ILocalJobRequestHandler LocalJobHandler => _localJobs;

    internal void ConfigureLocalJobs(ILocalJobRequestHandler localJobs)
    {
        ArgumentNullException.ThrowIfNull(localJobs);
        lock (_sync)
        {
            if (_current is not null)
            {
                throw new InvalidOperationException("local_job_handler_change_while_connected");
            }

            _localJobs = localJobs;
        }
    }

    public event EventHandler<AgentConnectionStateChangedEventArgs>? ConnectionStateChanged;

    public event EventHandler<AgentMessageReceivedEventArgs>? MessageReceived;

    public AgentConnectionSnapshot? CurrentConnection
    {
        get
        {
            lock (_sync)
            {
                return _current is null
                    ? null
                    : new AgentConnectionSnapshot(
                        _current.ConnectionId,
                        _current.Identity.ProcessId,
                        _current.Identity.SessionId,
                        _current.LastHeartbeatUtc);
            }
        }
    }

    public async Task SendAsync(
        Guid connectionId,
        SignJobCommand command,
        CancellationToken cancellationToken)
    {
        await SendMessageAsync(connectionId, command, cancellationToken).ConfigureAwait(false);
    }

    public Task SendPreparationAsync(
        Guid connectionId,
        PrepareSimplySignSessionCommand command,
        CancellationToken cancellationToken) =>
        SendMessageAsync(connectionId, command, cancellationToken);

    public async Task<AgentControlResponse> SendControlAsync(
        AgentControlRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ActiveConnection active;
        var completion = new TaskCompletionSource<AgentControlResponse>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_sync)
        {
            active = _current
                ?? throw Error("agent_not_connected", "The signing agent is not connected.");
            if (_pendingControls.ContainsKey(request.RequestId))
            {
                throw Error("invalid_message", "The agent control request is already pending.");
            }

            _pendingControls.Add(
                request.RequestId,
                new PendingControlResponse(active.ConnectionId, completion));
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            active.Lifetime.Token);
        timeout.CancelAfter(ControlTimeout);
        try
        {
            await SendMessageAsync(active.ConnectionId, request, timeout.Token).ConfigureAwait(false);
            try
            {
                return await completion.Task.WaitAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw Error("agent_control_timeout", "The signing agent control request timed out.");
            }
        }
        finally
        {
            lock (_sync)
            {
                _pendingControls.Remove(request.RequestId);
            }
        }
    }

    private async Task SendMessageAsync(
        Guid connectionId,
        AgentMessage message,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        ActiveConnection active;
        lock (_sync)
        {
            if (_current is null || _current.ConnectionId != connectionId)
            {
                throw Error("agent_not_connected", "The target agent connection is not active.");
            }

            active = _current;
        }

        try
        {
            await active.Writer.WriteAsync(message, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // A failed frame write can leave the byte stream desynchronized. Retire only
            // the connection that owned this writer; Disconnect is identity guarded so
            // an already-registered replacement is never cleared here.
            Disconnect(active, "send_failed");
            throw;
        }

        lock (_sync)
        {
            if (!ReferenceEquals(_current, active) || _current.ConnectionId != connectionId)
            {
                throw Error("agent_not_connected", "The target agent connection changed during the send.");
            }
        }
    }

    public AgentHeartbeat? LastHeartbeat
    {
        get
        {
            lock (_sync)
            {
                return _lastHeartbeat;
            }
        }
    }

    public AgentHealthSnapshot? CurrentHealth
    {
        get
        {
            lock (_sync)
            {
                return _current is null
                    ? null
                    : new AgentHealthSnapshot(
                        _current.ConnectionId,
                        _current.Identity.SessionId,
                        _current.Capabilities,
                        _current.LastHeartbeatUtc,
                        _current.Heartbeat);
            }
        }
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using var runCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var handlers = new List<Task>();
        try
        {
            while (!runCancellation.IsCancellationRequested)
            {
                var connection = await _acceptConnection(runCancellation.Token).ConfigureAwait(false);
                handlers.RemoveAll(task => task.IsCompletedSuccessfully);
                var handler = ProcessAcceptedConnectionAsync(connection, runCancellation.Token);
                handlers.Add(handler);
                _ = handler.ContinueWith(
                    static (_, state) => ((CancellationTokenSource)state!).Cancel(),
                    runCancellation,
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously | TaskContinuationOptions.OnlyOnFaulted,
                    TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) when (runCancellation.IsCancellationRequested)
        {
        }
        finally
        {
            runCancellation.Cancel();
            ActiveConnection? current;
            lock (_sync)
            {
                current = _current;
            }

            current?.Close();
            await Task.WhenAll(handlers).ConfigureAwait(false);
        }
    }

    private static async Task<Stream> AcceptNamedPipeAsync(
        string signingUserSid,
        CancellationToken cancellationToken)
    {
        var pipe = CreateNamedPipeServer(signingUserSid);
        try
        {
            await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
            return pipe;
        }
        catch
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async Task ProcessConnectionAsync(Stream connection, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ActiveConnection? active = null;
        Task? monitor = null;
        try
        {
            var initial = await LengthPrefixedJsonProtocol
                .ReadAsync<AgentMessage>(connection, cancellationToken)
                .ConfigureAwait(false);
            if (initial is not AgentHello hello)
            {
                throw Error("invalid_initial_message", "The first agent message must be a hello message.");
            }

            var identity = await _identityVerifier.VerifyAsync(connection, cancellationToken).ConfigureAwait(false);
            ValidateIdentity(hello, identity);
            active = Register(connection, identity, hello.Capabilities, cancellationToken);
            active.StartManagementPump(() => RunManagementPumpAsync(active));
            active.StartLocalJobPump(() => RunLocalJobPumpAsync(active));
            monitor = MonitorHeartbeatAsync(active);
            await ReadMessagesAsync(active).ConfigureAwait(false);
        }
        catch (ProtocolException error) when (error.Code == "unexpected_eof" && active is not null)
        {
        }
        catch (OperationCanceledException) when (active?.Lifetime.IsCancellationRequested == true)
        {
        }
        catch (IOException) when (active?.Lifetime.IsCancellationRequested == true)
        {
        }
        catch (ObjectDisposedException) when (active?.Lifetime.IsCancellationRequested == true)
        {
        }
        finally
        {
            if (active is not null)
            {
                Disconnect(active, "connection_closed");
                await active.JoinPumpsAsync().ConfigureAwait(false);
                if (monitor is not null)
                {
                    await IgnoreCancellationAsync(monitor).ConfigureAwait(false);
                }

                active.Dispose();
            }

            await connection.DisposeAsync().ConfigureAwait(false);
        }
    }

    [SupportedOSPlatform("windows")]
    public static NamedPipeServerStream CreateNamedPipeServer(string signingUserSid) =>
        CreateNamedPipeServer(
            signingUserSid,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));

    [SupportedOSPlatform("windows")]
    internal static NamedPipeServerStream CreateNamedPipeServer(
        string signingUserSid,
        SecurityIdentifier serverSid) =>
        CreateNamedPipeServer(PipeName, signingUserSid, serverSid);

    [SupportedOSPlatform("windows")]
    internal static NamedPipeServerStream CreateNamedPipeServer(
        string pipeName,
        string signingUserSid,
        SecurityIdentifier serverSid)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows named-pipe ACLs are required.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);

        var pipeSecurity = new PipeSecurity();
        pipeSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        AddRule(
            pipeSecurity,
            serverSid,
            PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance);
        AddRule(pipeSecurity, new SecurityIdentifier(signingUserSid), PipeAccessRights.ReadWrite);
        return NamedPipeServerStreamAcl.Create(
            pipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            LengthPrefixedJsonProtocol.MaximumPayloadLength + sizeof(int),
            LengthPrefixedJsonProtocol.MaximumPayloadLength + sizeof(int),
            pipeSecurity,
            HandleInheritability.None);
    }

    private static void AddRule(PipeSecurity security, SecurityIdentifier sid, PipeAccessRights rights) =>
        security.AddAccessRule(new PipeAccessRule(sid, rights, AccessControlType.Allow));

    private async Task ProcessAcceptedConnectionAsync(Stream pipe, CancellationToken cancellationToken)
    {
        try
        {
            await ProcessConnectionAsync(pipe, cancellationToken).ConfigureAwait(false);
        }
        catch (ProtocolException)
        {
        }
        catch (IOException) when (!cancellationToken.IsCancellationRequested)
        {
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private void ValidateIdentity(AgentHello hello, AgentConnectionIdentity identity)
    {
        if (hello.ProtocolVersion != LengthPrefixedJsonProtocol.ProtocolVersion)
        {
            throw Error("unsupported_protocol_version", "The agent protocol version is not supported.");
        }

        if (identity.SessionId <= 0)
        {
            throw Error("non_interactive_session", "An interactive agent session is required.");
        }

        if (identity.ProcessId <= 0 ||
            identity.ProcessId != hello.ProcessId ||
            identity.SessionId != hello.SessionId ||
            !string.Equals(identity.UserSid, hello.UserSid, StringComparison.Ordinal) ||
            !string.Equals(identity.UserSid, _signingUserSid, StringComparison.Ordinal))
        {
            throw Error("agent_identity_mismatch", "The agent identity could not be verified.");
        }

        if (!string.Equals(hello.AgentVersion, _expectedProductIdentity, StringComparison.Ordinal))
        {
            throw Error("product_version_mismatch", "The agent product version does not match the service.");
        }
    }

    private ActiveConnection Register(
        Stream connection,
        AgentConnectionIdentity identity,
        IReadOnlyList<string> capabilities,
        CancellationToken cancellationToken)
    {
        if (!AgentCapabilityPolicy.IsValid(capabilities))
        {
            throw Error("invalid_message", "The agent capabilities are invalid.");
        }

        ActiveConnection? stale = null;
        ActiveConnection active;
        lock (_sync)
        {
            if (_current is not null)
            {
                if (_clock.UtcNow - _current.LastActivityUtc < HeartbeatTimeout)
                {
                    throw Error("agent_already_connected", "An agent is already connected.");
                }

                stale = _current;
            }

            active = new ActiveConnection(connection, identity, capabilities, _clock.UtcNow, cancellationToken);
            _current = active;
            _lastHeartbeat = null;
        }

        if (stale is not null)
        {
            stale.Close();
            RaiseConnectionState(stale, AgentConnectionStatus.Disconnected, "heartbeat_timeout");
        }

        RaiseConnectionState(active, AgentConnectionStatus.Connected, "connected");
        return active;
    }

    private async Task ReadMessagesAsync(ActiveConnection active)
    {
        while (!active.Lifetime.IsCancellationRequested)
        {
            var message = await LengthPrefixedJsonProtocol
                .ReadAsync<AgentMessage>(active.Connection, active.Lifetime.Token)
                .ConfigureAwait(false);
            switch (message)
            {
                case AgentHeartbeat heartbeat:
                    RecordHeartbeat(active, heartbeat);
                    break;
                case JobProgress or JobCompleted or JobFailed:
                    EnsureCurrent(active);
                    break;
                case PrepareSimplySignSessionResult:
                    EnsureCurrent(active);
                    break;
                case AgentControlResponse response:
                    EnsureCurrent(active);
                    if (response.Heartbeat is not null)
                    {
                        RecordHeartbeat(active, response.Heartbeat);
                    }

                    DispatchControlResponse(active, response);
                    continue;
                case ManagementSnapshotRequest or JobPageRequest or TerminalJobDeltaRequest or ServiceSettingsRequest:
                    EnsureCurrent(active);
                    if (!active.TryQueueManagementRequest(message))
                    {
                        continue;
                    }

                    continue;
                case LocalJobCreateRequest or LocalJobUploadCompleted or LocalJobResultRequest:
                    EnsureCurrent(active);
                    if (!active.TryQueueLocalJobRequest(message))
                    {
                        Disconnect(active, "local_job_busy");
                        throw new OperationCanceledException(active.Lifetime.Token);
                    }

                    continue;
                default:
                    throw Error("invalid_message_direction", "The message is not valid in this direction.");
            }

            MessageReceived?.Invoke(this, new AgentMessageReceivedEventArgs(active.ConnectionId, message));
        }
    }

    private async Task RunManagementPumpAsync(ActiveConnection active)
    {
        try
        {
            await foreach (var request in active.ManagementRequests.Reader.ReadAllAsync(active.Lifetime.Token))
            {
                await RespondToManagementRequestAsync(active, request).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (active.Lifetime.IsCancellationRequested)
        {
        }
        catch (Exception)
        {
            Disconnect(active, "management_response_failed");
        }
    }

    private async Task RunLocalJobPumpAsync(ActiveConnection active)
    {
        try
        {
            await foreach (var request in active.LocalJobRequests.Reader.ReadAllAsync(active.Lifetime.Token))
            {
                await RespondToLocalJobRequestAsync(active, request).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (active.Lifetime.IsCancellationRequested)
        {
        }
        catch (Exception)
        {
            Disconnect(active, "local_job_response_failed");
        }
    }

    private async Task RespondToLocalJobRequestAsync(ActiveConnection active, AgentMessage request)
    {
        AgentMessage response;
        try
        {
            response = await _localJobs
                .HandleAsync(request, active.Identity, active.Lifetime.Token)
                .ConfigureAwait(false);
            EnsureCurrent(active);
        }
        catch (OperationCanceledException) when (active.Lifetime.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            EnsureCurrent(active);
            response = new LocalJobRejected(GetLocalRequestId(request), "local_job_unavailable", Guid.NewGuid());
        }

        try
        {
            EnsureCurrent(active);
            await active.Writer.WriteAsync(response, active.Lifetime.Token).ConfigureAwait(false);
            EnsureCurrent(active);
        }
        catch
        {
            Disconnect(active, "send_failed");
            throw;
        }
    }

    private static Guid GetLocalRequestId(AgentMessage request) => request switch
    {
        LocalJobCreateRequest create => create.RequestId,
        LocalJobUploadCompleted completed => completed.RequestId,
        LocalJobResultRequest result => result.RequestId,
        _ => throw Error("invalid_message_direction", "The message is not a local job request."),
    };

    private async Task RespondToManagementRequestAsync(
        ActiveConnection active,
        AgentMessage request)
    {
        AgentMessage response;
        try
        {
            response = request switch
            {
                ManagementSnapshotRequest snapshotRequest => new ManagementSnapshotResponse(
                    snapshotRequest.RequestId,
                    await _managementProvider.CreateAsync(
                        GetCurrentHealth(active),
                        active.Lifetime.Token).ConfigureAwait(false),
                    null,
                    null),
                JobPageRequest pageRequest => CreateJobPageResponse(
                    pageRequest.RequestId,
                    await _managementProvider.CreateJobPageAsync(
                        pageRequest.Cursor,
                        active.Lifetime.Token).ConfigureAwait(false)),
                TerminalJobDeltaRequest deltaRequest => CreateTerminalJobDeltaResponse(
                    deltaRequest.RequestId,
                    await _managementProvider.CreateTerminalJobDeltaAsync(
                        deltaRequest.Watermark,
                        deltaRequest.Cursor,
                        active.Lifetime.Token).ConfigureAwait(false)),
                ServiceSettingsRequest settingsRequest => new ServiceSettingsResponse(
                    settingsRequest.RequestId,
                    _managementProvider.GetServiceSettings(),
                    null,
                    null),
                _ => throw Error("invalid_message_direction", "The message is not a management request."),
            };
            EnsureCurrent(active);
        }
        catch (OperationCanceledException) when (active.Lifetime.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            EnsureCurrent(active);
            response = CreateManagementErrorResponse(request, Guid.NewGuid());
        }

        try
        {
            EnsureCurrent(active);
            await active.Writer.WriteAsync(response, active.Lifetime.Token).ConfigureAwait(false);
            EnsureCurrent(active);
        }
        catch
        {
            Disconnect(active, "send_failed");
            throw;
        }
    }

    private static JobPageResponse CreateJobPageResponse(Guid requestId, JobPageData page) =>
        new(requestId, page.Items, page.NextCursor, null, null);

    private static TerminalJobDeltaResponse CreateTerminalJobDeltaResponse(
        Guid requestId,
        TerminalJobDeltaData delta) =>
        new(requestId, delta.Items, delta.NextCursor, delta.Watermark, null, null);

    private static AgentMessage CreateManagementErrorResponse(AgentMessage request, Guid correlationId) =>
        request switch
        {
            ManagementSnapshotRequest snapshot => new ManagementSnapshotResponse(
                snapshot.RequestId, null, "management_unavailable", correlationId),
            JobPageRequest page => new JobPageResponse(
                page.RequestId, [], null, "management_unavailable", correlationId),
            TerminalJobDeltaRequest delta => new TerminalJobDeltaResponse(
                delta.RequestId, [], null, null, "management_unavailable", correlationId),
            ServiceSettingsRequest settings => new ServiceSettingsResponse(
                settings.RequestId, null, "management_unavailable", correlationId),
            _ => throw Error("invalid_message_direction", "The message is not a management request."),
        };

    private AgentHealthSnapshot GetCurrentHealth(ActiveConnection active)
    {
        lock (_sync)
        {
            if (!ReferenceEquals(_current, active))
            {
                throw Error("agent_not_connected", "The agent connection is no longer active.");
            }

            return new AgentHealthSnapshot(
                active.ConnectionId,
                active.Identity.SessionId,
                active.Capabilities,
                active.LastHeartbeatUtc,
                active.Heartbeat);
        }
    }

    private void RecordHeartbeat(ActiveConnection active, AgentHeartbeat heartbeat)
    {
        lock (_sync)
        {
            if (!ReferenceEquals(_current, active))
            {
                throw Error("agent_not_connected", "The agent connection is no longer active.");
            }

            if (heartbeat.SessionId != active.Identity.SessionId)
            {
                throw Error("agent_identity_mismatch", "The heartbeat session does not match the verified agent.");
            }

            active.LastHeartbeatUtc = _clock.UtcNow;
            active.Heartbeat = heartbeat;
            _lastHeartbeat = heartbeat;
        }
    }

    private void DispatchControlResponse(
        ActiveConnection active,
        AgentControlResponse response)
    {
        TaskCompletionSource<AgentControlResponse>? completion;
        lock (_sync)
        {
            if (!_pendingControls.TryGetValue(response.RequestId, out var pending))
            {
                return;
            }

            if (pending.ConnectionId != active.ConnectionId)
            {
                throw Error("agent_not_connected", "The agent control response came from a replaced connection.");
            }

            _pendingControls.Remove(response.RequestId);
            completion = pending.Completion;
        }

        completion.TrySetResult(response);
    }

    private void EnsureCurrent(ActiveConnection active)
    {
        lock (_sync)
        {
            if (!ReferenceEquals(_current, active))
            {
                throw Error("agent_not_connected", "The agent connection is no longer active.");
            }
        }
    }

    private async Task MonitorHeartbeatAsync(ActiveConnection active)
    {
        try
        {
            while (!active.Lifetime.IsCancellationRequested)
            {
                TimeSpan remaining;
                lock (_sync)
                {
                    if (!ReferenceEquals(_current, active))
                    {
                        return;
                    }

                    remaining = HeartbeatTimeout - (_clock.UtcNow - active.LastActivityUtc);
                }

                if (remaining <= TimeSpan.Zero)
                {
                    Disconnect(active, "heartbeat_timeout");
                    return;
                }

                await _clock.DelayAsync(remaining, active.Lifetime.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (active.Lifetime.IsCancellationRequested)
        {
        }
    }

    private void Disconnect(ActiveConnection active, string reason)
    {
        PendingControlResponse[] pending;
        lock (_sync)
        {
            if (!ReferenceEquals(_current, active))
            {
                return;
            }

            _current = null;
            _lastHeartbeat = null;
            pending = _pendingControls.Values
                .Where(item => item.ConnectionId == active.ConnectionId)
                .ToArray();
            foreach (var requestId in _pendingControls
                         .Where(item => item.Value.ConnectionId == active.ConnectionId)
                         .Select(static item => item.Key)
                         .ToArray())
            {
                _pendingControls.Remove(requestId);
            }
        }

        foreach (var item in pending)
        {
            item.Completion.TrySetException(
                Error("agent_not_connected", "The signing agent disconnected."));
        }

        active.Close();
        RaiseConnectionState(active, AgentConnectionStatus.Disconnected, reason);
    }

    private sealed record PendingControlResponse(
        Guid ConnectionId,
        TaskCompletionSource<AgentControlResponse> Completion);

    private void RaiseConnectionState(ActiveConnection active, AgentConnectionStatus status, string reason) =>
        ConnectionStateChanged?.Invoke(
            this,
            new AgentConnectionStateChangedEventArgs(
                active.ConnectionId,
                status,
                active.Identity.ProcessId,
                active.Identity.SessionId,
                reason));

    private static async Task IgnoreCancellationAsync(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static ProtocolException Error(string code, string message) => new(code, message);

    private sealed class ActiveConnection(
        Stream connection,
        AgentConnectionIdentity identity,
        IReadOnlyList<string> capabilities,
        DateTimeOffset connectedAt,
        CancellationToken cancellationToken)
    {
        private readonly object _pumpSync = new();
        private Task? _managementPump;
        private Task? _localJobPump;

        public Guid ConnectionId { get; } = Guid.NewGuid();
        public Stream Connection { get; } = connection;
        public LengthPrefixedJsonWriter Writer { get; } = LengthPrefixedJsonProtocol.GetWriter(connection);
        public AgentConnectionIdentity Identity { get; } = identity;
        public IReadOnlyList<string> Capabilities { get; } = capabilities.ToArray();
        public CancellationTokenSource Lifetime { get; } =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        public DateTimeOffset ConnectedAtUtc { get; } = connectedAt;
        public DateTimeOffset? LastHeartbeatUtc { get; set; }
        public AgentHeartbeat? Heartbeat { get; set; }
        public DateTimeOffset LastActivityUtc => LastHeartbeatUtc ?? ConnectedAtUtc;
        public Channel<AgentMessage> ManagementRequests { get; } =
            Channel.CreateBounded<AgentMessage>(new BoundedChannelOptions(4)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait,
                AllowSynchronousContinuations = false,
            });
        public Channel<AgentMessage> LocalJobRequests { get; } =
            Channel.CreateBounded<AgentMessage>(new BoundedChannelOptions(4)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait,
                AllowSynchronousContinuations = false,
            });

        public void StartManagementPump(Func<Task> operation)
        {
            lock (_pumpSync)
            {
                if (_managementPump is not null)
                {
                    throw new InvalidOperationException("management_pump_already_started");
                }

                _managementPump = operation();
            }
        }

        public bool TryQueueManagementRequest(AgentMessage request) =>
            ManagementRequests.Writer.TryWrite(request);

        public void StartLocalJobPump(Func<Task> operation)
        {
            lock (_pumpSync)
            {
                if (_localJobPump is not null)
                {
                    throw new InvalidOperationException("local_job_pump_already_started");
                }

                _localJobPump = operation();
            }
        }

        public bool TryQueueLocalJobRequest(AgentMessage request) =>
            LocalJobRequests.Writer.TryWrite(request);

        public async Task JoinPumpsAsync()
        {
            Task? managementPump;
            Task? localJobPump;
            lock (_pumpSync)
            {
                managementPump = _managementPump;
                localJobPump = _localJobPump;
            }

            if (managementPump is not null)
            {
                await managementPump.ConfigureAwait(false);
            }

            if (localJobPump is not null)
            {
                await localJobPump.ConfigureAwait(false);
            }
        }

        public void Close()
        {
            ManagementRequests.Writer.TryComplete();
            LocalJobRequests.Writer.TryComplete();
            Lifetime.Cancel();
            Connection.Dispose();
        }

        public void Dispose() => Lifetime.Dispose();
    }

    private sealed class UnavailableManagementSnapshotProvider : IServiceManagementSnapshotProvider
    {
        public static UnavailableManagementSnapshotProvider Instance { get; } = new();

        public Task<ManagementSnapshot> CreateAsync(
            AgentHealthSnapshot health,
            CancellationToken cancellationToken) =>
            Task.FromException<ManagementSnapshot>(new InvalidOperationException("management_unavailable"));
    }

    private sealed class UnavailableLocalJobRequestHandler : ILocalJobRequestHandler
    {
        public static UnavailableLocalJobRequestHandler Instance { get; } = new();

        public Task<AgentMessage> HandleAsync(
            AgentMessage request,
            AgentConnectionIdentity identity,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<AgentMessage>(
                new LocalJobRejected(GetLocalRequestId(request), "local_job_unavailable", Guid.NewGuid()));
        }
    }
}
