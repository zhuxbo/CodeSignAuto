using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using CodeSignAuto.Protocol;
using CodeSignAuto.Service.Jobs;

namespace CodeSignAuto.Service.Ipc;

public sealed record AdminControlIdentity(
    int ProcessId,
    int SessionId,
    string UserSid,
    bool IsAdministrator,
    bool IsLocal = false);

public interface IAdminControlIdentityVerifier
{
    ValueTask<AdminControlIdentity> VerifyAsync(
        Stream connection,
        CancellationToken cancellationToken);
}

public interface IAdminControlRuntime
{
    Task RunAsync(CancellationToken cancellationToken);
}

public sealed partial class WindowsAdminControlIdentityVerifier : IAdminControlIdentityVerifier
{
    private const int ErrorPipeLocal = 229;

    public ValueTask<AdminControlIdentity> VerifyAsync(
        Stream connection,
        CancellationToken cancellationToken)
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
    private static AdminControlIdentity VerifyWindows(NamedPipeServerStream pipe)
    {
        var clientComputerName = new StringBuilder(256);
        var isLocal = !GetNamedPipeClientComputerNameW(
                pipe.SafePipeHandle,
                clientComputerName,
                checked((uint)clientComputerName.Capacity));
        if (isLocal)
        {
            var errorCode = Marshal.GetLastWin32Error();
            if (errorCode != ErrorPipeLocal)
            {
                throw new Win32Exception(
                    errorCode,
                    $"Unable to determine the named-pipe client computer ({errorCode}).");
            }
        }

        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var processId) ||
            !ProcessIdToSessionId(processId, out var sessionId))
        {
            throw new Win32Exception(
                Marshal.GetLastPInvokeError(),
                "Unable to determine the local named-pipe client identity.");
        }

        string? userSid = null;
        var isAdministrator = false;
        pipe.RunAsClient(() =>
        {
            using var identity = WindowsIdentity.GetCurrent();
            userSid = identity.User?.Value;
            isAdministrator = new WindowsPrincipal(identity)
                .IsInRole(WindowsBuiltInRole.Administrator);
        });
        if (string.IsNullOrEmpty(userSid))
        {
            throw new UnauthorizedAccessException("admin_control_identity_invalid");
        }

        return new AdminControlIdentity(
            checked((int)processId),
            checked((int)sessionId),
            userSid,
            isAdministrator,
            isLocal);
    }

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetNamedPipeClientComputerNameW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientComputerNameW(
        SafePipeHandle pipe,
        StringBuilder clientComputerName,
        uint clientComputerNameLength);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(
        SafePipeHandle pipe,
        out uint clientProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ProcessIdToSessionId(uint processId, out uint sessionId);
}

public sealed class AdminControlPipeServer : IAdminControlRuntime
{
    public const string PipeName = "CodeSignAuto.Control.v1";
    internal static readonly TimeSpan IdentityTimeout = TimeSpan.FromSeconds(5);
    internal static readonly TimeSpan HelloTimeout = TimeSpan.FromSeconds(10);
    internal static readonly TimeSpan RequestReadTimeout = TimeSpan.FromSeconds(15);
    // Preserve a second transport margin outside AgentPipeServer.ControlTimeout.
    internal static readonly TimeSpan ManagementDispatchTimeout = TimeSpan.FromSeconds(110);
    internal static readonly TimeSpan LocalCreateDispatchTimeout = TimeSpan.FromSeconds(15);
    internal static readonly TimeSpan LocalCompleteDispatchTimeout = TimeSpan.FromMinutes(10);
    internal static readonly TimeSpan LocalResultDispatchTimeout = TimeSpan.FromSeconds(30);

    private readonly IAdminControlIdentityVerifier _identityVerifier;
    private readonly Func<CancellationToken, Task<Stream>> _acceptConnection;
    private readonly IServiceManagementSnapshotProvider _management;
    private readonly IAgentControlTransport _agentControl;
    private readonly IAgentHealthStatusSource _agentHealth;
    private readonly IAdministratorLocalJobRequestHandler _localJobs;
    private readonly IUpgradeDrainCoordinator _upgradeDrain;
    private readonly TimeSpan _identityTimeout;
    private readonly TimeSpan _helloTimeout;
    private readonly TimeSpan _requestReadTimeout;
    private int _activeConnection;

    public AdminControlPipeServer(
        IServiceManagementSnapshotProvider management,
        IAgentControlTransport agentControl,
        IAgentHealthStatusSource agentHealth,
        IAdministratorLocalJobRequestHandler localJobs,
        IAdminControlIdentityVerifier? identityVerifier = null,
        Func<CancellationToken, Task<Stream>>? acceptConnection = null,
        TimeSpan? identityTimeout = null,
        TimeSpan? helloTimeout = null,
        TimeSpan? requestReadTimeout = null,
        IUpgradeDrainCoordinator? upgradeDrain = null)
    {
        _management = management ?? throw new ArgumentNullException(nameof(management));
        _agentControl = agentControl ?? throw new ArgumentNullException(nameof(agentControl));
        _agentHealth = agentHealth ?? throw new ArgumentNullException(nameof(agentHealth));
        _localJobs = localJobs ?? throw new ArgumentNullException(nameof(localJobs));
        _upgradeDrain = upgradeDrain ?? new UnavailableUpgradeDrainCoordinator();
        _identityVerifier = identityVerifier ?? new WindowsAdminControlIdentityVerifier();
        _acceptConnection = acceptConnection ?? AcceptNamedPipeAsync;
        _identityTimeout = ValidateTimeout(identityTimeout ?? IdentityTimeout, nameof(identityTimeout));
        _helloTimeout = ValidateTimeout(helloTimeout ?? HelloTimeout, nameof(helloTimeout));
        _requestReadTimeout = ValidateTimeout(
            requestReadTimeout ?? RequestReadTimeout,
            nameof(requestReadTimeout));
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var handlers = new List<Task>();
        try
        {
            while (!lifetime.IsCancellationRequested)
            {
                var connection = await _acceptConnection(lifetime.Token).ConfigureAwait(false);
                handlers.RemoveAll(static task => task.IsCompletedSuccessfully);
                handlers.Add(ProcessAcceptedConnectionAsync(connection, lifetime.Token));
            }
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested)
        {
        }
        finally
        {
            lifetime.Cancel();
            await Task.WhenAll(handlers).ConfigureAwait(false);
        }
    }

    public async Task ProcessConnectionAsync(
        Stream connection,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        await using (connection.ConfigureAwait(false))
        {
            using var identityDeadline = CreateDeadline(cancellationToken, _identityTimeout);
            var identity = await _identityVerifier
                .VerifyAsync(connection, identityDeadline.Token)
                .ConfigureAwait(false);
            using var helloDeadline = CreateDeadline(cancellationToken, _helloTimeout);
            var hello = await LengthPrefixedJsonProtocol
                .ReadAsync<AgentMessage>(connection, helloDeadline.Token)
                .ConfigureAwait(false) as AdminControlHello
                ?? throw Error("invalid_initial_message", "The first control message must be a hello message.");
            ValidateIdentity(hello, identity);
            if (Interlocked.CompareExchange(ref _activeConnection, 1, 0) != 0)
            {
                throw new UnauthorizedAccessException("admin_control_connection_conflict");
            }

            try
            {
                var writer = LengthPrefixedJsonProtocol.GetWriter(connection);
                await writer.WriteAsync(
                    new AdminControlAccepted(AdminControlContract.ProtocolVersion),
                    cancellationToken).ConfigureAwait(false);
                using var requestDeadline = CreateDeadline(cancellationToken, _requestReadTimeout);
                var request = await LengthPrefixedJsonProtocol
                    .ReadAsync<AgentMessage>(connection, requestDeadline.Token)
                    .ConfigureAwait(false);
                using var dispatchDeadline = CreateDeadline(
                    cancellationToken,
                    GetDispatchTimeout(request));
                var response = await DispatchAsync(request, identity, dispatchDeadline.Token)
                    .ConfigureAwait(false);
                await writer.WriteAsync(response, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                Volatile.Write(ref _activeConnection, 0);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    public static NamedPipeServerStream CreateNamedPipeServer()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows named-pipe ACLs are required.");
        }

        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        AddRule(
            security,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance);
        AddRule(
            security,
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.ReadWrite);
        return NamedPipeServerStreamAcl.Create(
            PipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            LengthPrefixedJsonProtocol.MaximumPayloadLength + sizeof(int),
            LengthPrefixedJsonProtocol.MaximumPayloadLength + sizeof(int),
            security,
            HandleInheritability.None);
    }

    private static async Task<Stream> AcceptNamedPipeAsync(CancellationToken cancellationToken)
    {
        var pipe = CreateNamedPipeServer();
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

    private async Task<AgentMessage> DispatchAsync(
        AgentMessage request,
        AdminControlIdentity identity,
        CancellationToken cancellationToken)
    {
        try
        {
            return request switch
            {
                ManagementSnapshotRequest snapshot => new ManagementSnapshotResponse(
                    snapshot.RequestId,
                    await CreateSnapshotAsync(cancellationToken).ConfigureAwait(false),
                    null,
                    null),
                AgentControlRequest control => await ForwardControlAsync(control, cancellationToken)
                    .ConfigureAwait(false),
                JobPageRequest page => CreateJobPageResponse(
                    page.RequestId,
                    await _management.CreateJobPageAsync(page.Cursor, cancellationToken)
                        .ConfigureAwait(false)),
                TerminalJobDeltaRequest delta => CreateTerminalResponse(
                    delta.RequestId,
                    await _management.CreateTerminalJobDeltaAsync(
                        delta.Watermark,
                        delta.Cursor,
                        cancellationToken).ConfigureAwait(false)),
                ServiceSettingsRequest settings => new ServiceSettingsResponse(
                    settings.RequestId,
                    _management.GetServiceSettings(),
                    null,
                    null),
                UpgradeDrainRequest drain => await DrainUpgradeAsync(drain, cancellationToken)
                    .ConfigureAwait(false),
                UpgradeResumeRequest resume => ResumeUpgrade(resume),
                LocalJobCreateRequest or LocalJobUploadCompleted or LocalJobResultRequest =>
                    await _localJobs.HandleAdministratorAsync(
                        request,
                        new AgentConnectionIdentity(
                            identity.ProcessId,
                            identity.SessionId,
                            identity.UserSid),
                        cancellationToken).ConfigureAwait(false),
                _ => throw Error("invalid_message_direction", "The message is not valid on the control pipe."),
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return CreateErrorResponse(request);
        }
    }

    private async Task<ManagementSnapshot> CreateSnapshotAsync(CancellationToken cancellationToken)
    {
        var health = _agentHealth.CurrentHealth
            ?? throw new InvalidOperationException("management_unavailable");
        return await _management.CreateAsync(health, cancellationToken).ConfigureAwait(false);
    }

    private async Task<AgentControlResponse> ForwardControlAsync(
        AgentControlRequest request,
        CancellationToken cancellationToken)
    {
        var forwarded = request with { RequestId = Guid.NewGuid() };
        var response = await _agentControl
            .SendControlAsync(forwarded, cancellationToken)
            .ConfigureAwait(false);
        if (response.RequestId != forwarded.RequestId ||
            !string.Equals(response.Operation, request.Operation, StringComparison.Ordinal))
        {
            throw Error("invalid_message", "The signing agent returned a mismatched control response.");
        }

        return response with { RequestId = request.RequestId };
    }

    internal static void ValidateIdentity(
        AdminControlHello hello,
        AdminControlIdentity identity)
    {
        if (hello.ProtocolVersion != AdminControlContract.ProtocolVersion ||
            identity.ProcessId <= 0 || identity.SessionId <= 0 || !identity.IsAdministrator ||
            !identity.IsLocal ||
            hello.ProcessId != identity.ProcessId || hello.SessionId != identity.SessionId ||
            !string.Equals(hello.UserSid, identity.UserSid, StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException("admin_control_identity_mismatch");
        }
    }

    private static JobPageResponse CreateJobPageResponse(Guid requestId, JobPageData page) =>
        new(requestId, page.Items, page.NextCursor, null, null);

    private static TerminalJobDeltaResponse CreateTerminalResponse(
        Guid requestId,
        TerminalJobDeltaData delta) =>
        new(requestId, delta.Items, delta.NextCursor, delta.Watermark, null, null);

    private static AgentMessage CreateErrorResponse(AgentMessage request)
    {
        var correlationId = Guid.NewGuid();
        return request switch
        {
            ManagementSnapshotRequest snapshot => new ManagementSnapshotResponse(
                snapshot.RequestId, null, "management_unavailable", correlationId),
            AgentControlRequest control => new AgentControlResponse(
                control.RequestId,
                control.Operation,
                null,
                null,
                null,
                null,
                "management_unavailable",
                correlationId),
            JobPageRequest page => new JobPageResponse(
                page.RequestId, [], null, "management_unavailable", correlationId),
            TerminalJobDeltaRequest delta => new TerminalJobDeltaResponse(
                delta.RequestId, [], null, null, "management_unavailable", correlationId),
            ServiceSettingsRequest settings => new ServiceSettingsResponse(
                settings.RequestId, null, "management_unavailable", correlationId),
            UpgradeDrainRequest drain => new UpgradeDrainResponse(
                drain.RequestId, false, "upgrade_drain_timeout"),
            UpgradeResumeRequest resume => new UpgradeResumeResponse(
                resume.RequestId, false, "management_unavailable"),
            LocalJobCreateRequest create => new LocalJobRejected(
                create.RequestId, "local_job_unavailable", correlationId),
            LocalJobUploadCompleted complete => new LocalJobRejected(
                complete.RequestId, "local_job_unavailable", correlationId),
            LocalJobResultRequest result => new LocalJobRejected(
                result.RequestId, "local_job_unavailable", correlationId),
            _ => throw Error("invalid_message_direction", "The control request type is invalid."),
        };
    }

    private async Task ProcessAcceptedConnectionAsync(
        Stream connection,
        CancellationToken cancellationToken)
    {
        try
        {
            await ProcessConnectionAsync(connection, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (
            error is ProtocolException or IOException or UnauthorizedAccessException or Win32Exception)
        {
            await connection.DisposeAsync().ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await connection.DisposeAsync().ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            await connection.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static void AddRule(
        PipeSecurity security,
        SecurityIdentifier sid,
        PipeAccessRights rights) =>
        security.AddAccessRule(new PipeAccessRule(sid, rights, AccessControlType.Allow));

    private static ProtocolException Error(string code, string message) => new(code, message);

    private static CancellationTokenSource CreateDeadline(
        CancellationToken cancellationToken,
        TimeSpan timeout)
    {
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        return deadline;
    }

    private static TimeSpan GetDispatchTimeout(AgentMessage request) => request switch
    {
        UpgradeDrainRequest drain => TimeSpan.FromSeconds(drain.TimeoutSeconds + 5),
        LocalJobCreateRequest => LocalCreateDispatchTimeout,
        LocalJobUploadCompleted => LocalCompleteDispatchTimeout,
        LocalJobResultRequest => LocalResultDispatchTimeout,
        _ => ManagementDispatchTimeout,
    };

    private async Task<UpgradeDrainResponse> DrainUpgradeAsync(
        UpgradeDrainRequest request,
        CancellationToken cancellationToken)
    {
        var drained = await _upgradeDrain
            .DrainAsync(TimeSpan.FromSeconds(request.TimeoutSeconds), cancellationToken)
            .ConfigureAwait(false);
        return new UpgradeDrainResponse(
            request.RequestId,
            drained,
            drained ? null : "upgrade_drain_timeout");
    }

    private UpgradeResumeResponse ResumeUpgrade(UpgradeResumeRequest request)
    {
        _upgradeDrain.Resume();
        return new UpgradeResumeResponse(request.RequestId, true, null);
    }

    private sealed class UnavailableUpgradeDrainCoordinator : IUpgradeDrainCoordinator
    {
        public Task<bool> DrainAsync(TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public void Resume()
        {
        }
    }

    private static TimeSpan ValidateTimeout(TimeSpan value, string parameterName) =>
        value > TimeSpan.Zero && value != Timeout.InfiniteTimeSpan
            ? value
            : throw new ArgumentOutOfRangeException(parameterName);
}
