using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Principal;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.Agent.Security;
using SimplySignAuto.App.UI;
using SimplySignAuto.Core.Otp;
using SimplySignAuto.Protocol;
using SimplySignAuto.Service.Ipc;

namespace SimplySignAuto.App.Control;

public sealed record AdminControlClientIdentity(int ProcessId, int SessionId, string UserSid);

public interface IAdminControlClientIdentityProvider
{
    AdminControlClientIdentity GetCurrent();
}

public interface IAdminControlServerIdentityVerifier
{
    void Verify(Stream connection);
}

public sealed class WindowsAdminControlServerIdentityVerifier : IAdminControlServerIdentityVerifier
{
    private static readonly string LocalSystemSid =
        new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value;

    public void Verify(Stream connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (!OperatingSystem.IsWindows() || connection is not NamedPipeClientStream pipe)
        {
            throw new UnauthorizedAccessException("admin_control_server_identity_invalid");
        }

        ValidateEvidence(new WindowsActivationServerIdentityReader().ReadServer(pipe.SafePipeHandle));
    }

    internal static void ValidateEvidence(ActivationServerIdentityEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (!evidence.InspectionSucceeded || evidence.SessionId != 0 ||
            !string.Equals(evidence.UserSid, LocalSystemSid, StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException("admin_control_server_identity_mismatch");
        }
    }
}

public sealed class WindowsAdminControlClientIdentityProvider : IAdminControlClientIdentityProvider
{
    public AdminControlClientIdentity GetCurrent()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows administrator control is required.");
        }

        using var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User?.Value;
        if (string.IsNullOrWhiteSpace(sid))
        {
            throw new UnauthorizedAccessException("admin_control_identity_invalid");
        }

        return new AdminControlClientIdentity(
            Environment.ProcessId,
            Process.GetCurrentProcess().SessionId,
            sid);
    }
}

public sealed class AdminControlClient :
    IAgentManagementClient,
    IAgentAdministrationClient,
    ILocalTotpCodeProvider,
    ILocalJobTransport,
    IDisposable
{
    public static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(70);
    public static readonly TimeSpan LocalCreateTimeout = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan LocalCompleteTimeout = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan LocalResultTimeout = TimeSpan.FromSeconds(30);

    private readonly object _sync = new();
    private readonly Func<CancellationToken, ValueTask<Stream>> _connector;
    private readonly IAdminControlClientIdentityProvider _identityProvider;
    private readonly IAdminControlServerIdentityVerifier _serverIdentityVerifier;
    private readonly Func<Guid> _requestIdFactory;
    private readonly SemaphoreSlim _requestGate = new(1, 1);
    private ManagementSnapshot? _latest;
    private int _disposed;

    public AdminControlClient()
        : this(
            ConnectNamedPipeAsync,
            new WindowsAdminControlClientIdentityProvider(),
            new WindowsAdminControlServerIdentityVerifier())
    {
    }

    internal AdminControlClient(
        Func<CancellationToken, ValueTask<Stream>> connector,
        IAdminControlClientIdentityProvider identityProvider,
        IAdminControlServerIdentityVerifier? serverIdentityVerifier = null,
        Func<Guid>? requestIdFactory = null)
    {
        _connector = connector ?? throw new ArgumentNullException(nameof(connector));
        _identityProvider = identityProvider ?? throw new ArgumentNullException(nameof(identityProvider));
        _serverIdentityVerifier = serverIdentityVerifier
            ?? new WindowsAdminControlServerIdentityVerifier();
        _requestIdFactory = requestIdFactory ?? Guid.NewGuid;
    }

    public event EventHandler? SnapshotChanged;

    public ManagementSnapshot? LatestSnapshot
    {
        get
        {
            lock (_sync)
            {
                return _latest;
            }
        }
    }

    public async Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken)
    {
        await ExecuteControlAsync(AdminControlContract.Refresh, null, cancellationToken)
            .ConfigureAwait(false);
        return await GetSnapshotAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken)
    {
        await ExecuteControlAsync(AdminControlContract.Relogin, null, cancellationToken)
            .ConfigureAwait(false);
        return await GetSnapshotAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<ManagementSnapshot> LogoutAsync(CancellationToken cancellationToken)
    {
        await ExecuteControlAsync(AdminControlContract.Logout, null, cancellationToken)
            .ConfigureAwait(false);
        return await GetSnapshotAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<ManagementSnapshot> ClearOtpAndLogoutAsync(
        CancellationToken cancellationToken)
    {
        await ExecuteControlAsync(AdminControlContract.ClearOtp, null, cancellationToken)
            .ConfigureAwait(false);
        return await GetSnapshotAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task SaveOtpAsync(
        OtpauthProfile profile,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var uri = FormatOtpUri(profile);
        try
        {
            var response = await SendAsync<AgentControlResponse>(
                new AgentControlRequest(
                    NewRequestId(),
                    AdminControlContract.ImportOtp,
                    uri),
                cancellationToken).ConfigureAwait(false);
            ThrowControlError(response, otpOperation: true);
        }
        finally
        {
            uri = string.Empty;
        }
    }

    public async Task<LocalTotpCode> GenerateCurrentAsync(CancellationToken cancellationToken)
    {
        var response = await SendAsync<AgentControlResponse>(
            new AgentControlRequest(NewRequestId(), AdminControlContract.GenerateTotp),
            cancellationToken).ConfigureAwait(false);
        ThrowControlError(response, otpOperation: true);
        if (response.TotpCode is null || response.RemainingSeconds is null ||
            response.ExpiresAtUtc is null)
        {
            throw new ManagementUnavailableException(Guid.NewGuid());
        }

        return new LocalTotpCode(
            response.TotpCode,
            response.RemainingSeconds.Value,
            response.ExpiresAtUtc.Value);
    }

    public async Task<JobPageResponse> GetJobPageAsync(
        JobPageCursor? cursor,
        CancellationToken cancellationToken)
    {
        var response = await SendAsync<JobPageResponse>(
            new JobPageRequest(NewRequestId(), cursor),
            cancellationToken).ConfigureAwait(false);
        if (response.ErrorCode is not null)
        {
            throw new ManagementUnavailableException(response.CorrelationId ?? Guid.NewGuid());
        }

        return response;
    }

    public async Task<TerminalJobDeltaResponse> GetTerminalJobDeltaAsync(
        TerminalJobWatermark? watermark,
        TerminalJobCursor? cursor,
        CancellationToken cancellationToken)
    {
        var response = await SendAsync<TerminalJobDeltaResponse>(
            new TerminalJobDeltaRequest(NewRequestId(), watermark, cursor),
            cancellationToken).ConfigureAwait(false);
        if (response.ErrorCode is not null)
        {
            throw new ManagementUnavailableException(response.CorrelationId ?? Guid.NewGuid());
        }

        return response;
    }

    public async Task<ServiceSettingsSummary> GetServiceSettingsAsync(
        CancellationToken cancellationToken)
    {
        var response = await SendAsync<ServiceSettingsResponse>(
            new ServiceSettingsRequest(NewRequestId()),
            cancellationToken).ConfigureAwait(false);
        return response.Summary
            ?? throw new ManagementUnavailableException(response.CorrelationId ?? Guid.NewGuid());
    }

    public async Task<LocalJobCreateOutcome> CreateLocalJobAsync(
        LocalJobCreateRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = await SendAsync<AgentMessage>(
            request,
            LocalCreateTimeout,
            localJobTransport: true,
            retryTransportOnce: true,
            cancellationToken).ConfigureAwait(false);
        return response switch
        {
            LocalJobUploadLease lease when lease.RequestId == request.RequestId =>
                LocalJobCreateOutcome.FromLease(lease),
            LocalJobAccepted accepted when accepted.RequestId == request.RequestId =>
                LocalJobCreateOutcome.FromAccepted(accepted),
            LocalJobRejected rejected when rejected.RequestId == request.RequestId =>
                throw LocalError(rejected),
            _ => throw new LocalJobException("local_response_mismatch"),
        };
    }

    public async Task<LocalJobAccepted> CompleteLocalJobAsync(
        LocalJobUploadCompleted completed,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(completed);
        var response = await SendAsync<AgentMessage>(
            completed,
            LocalCompleteTimeout,
            localJobTransport: true,
            retryTransportOnce: true,
            cancellationToken).ConfigureAwait(false);
        return response switch
        {
            LocalJobAccepted accepted when accepted.RequestId == completed.RequestId => accepted,
            LocalJobRejected rejected when rejected.RequestId == completed.RequestId =>
                throw LocalError(rejected),
            _ => throw new LocalJobException("local_response_mismatch"),
        };
    }

    public async Task<LocalJobResultMetadata> GetLocalResultAsync(
        LocalJobResultRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = await SendAsync<AgentMessage>(
            request,
            LocalResultTimeout,
            localJobTransport: true,
            retryTransportOnce: false,
            cancellationToken).ConfigureAwait(false);
        return response switch
        {
            LocalJobResultMetadata result when result.RequestId == request.RequestId => result,
            LocalJobRejected rejected when rejected.RequestId == request.RequestId =>
                throw LocalError(rejected),
            _ => throw new LocalJobException("local_response_mismatch"),
        };
    }

    public void Dispose() => Volatile.Write(ref _disposed, 1);

    private async Task ExecuteControlAsync(
        string operation,
        string? otpUri,
        CancellationToken cancellationToken)
    {
        var response = await SendAsync<AgentControlResponse>(
            new AgentControlRequest(NewRequestId(), operation, otpUri),
            cancellationToken).ConfigureAwait(false);
        ThrowControlError(response, otpOperation: false);
    }

    private async Task<ManagementSnapshot> GetSnapshotAsync(CancellationToken cancellationToken)
    {
        var response = await SendAsync<ManagementSnapshotResponse>(
            new ManagementSnapshotRequest(NewRequestId()),
            cancellationToken).ConfigureAwait(false);
        var snapshot = response.Snapshot
            ?? throw new ManagementUnavailableException(response.CorrelationId ?? Guid.NewGuid());
        lock (_sync)
        {
            _latest = snapshot;
        }

        SnapshotChanged?.Invoke(this, EventArgs.Empty);
        return snapshot;
    }

    private async Task<TResponse> SendAsync<TResponse>(
        AgentMessage request,
        CancellationToken cancellationToken)
        where TResponse : AgentMessage =>
        await SendAsync<TResponse>(
            request,
            RequestTimeout,
            localJobTransport: false,
            retryTransportOnce: false,
            cancellationToken).ConfigureAwait(false);

    private async Task<TResponse> SendAsync<TResponse>(
        AgentMessage request,
        TimeSpan requestTimeout,
        bool localJobTransport,
        bool retryTransportOnce,
        CancellationToken cancellationToken)
        where TResponse : AgentMessage
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var gateEntered = false;
        try
        {
            await _requestGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            gateEntered = true;
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            for (var attempt = 0; ; attempt++)
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(requestTimeout);
                try
                {
                    await using var connection = await _connector(timeout.Token).ConfigureAwait(false);
                    _serverIdentityVerifier.Verify(connection);
                    var identity = _identityProvider.GetCurrent();
                    var writer = LengthPrefixedJsonProtocol.GetWriter(connection);
                    await writer.WriteAsync(
                        new AdminControlHello(
                            AdminControlContract.ProtocolVersion,
                            identity.ProcessId,
                            identity.SessionId,
                            identity.UserSid),
                        timeout.Token).ConfigureAwait(false);
                    var accepted = await LengthPrefixedJsonProtocol
                        .ReadAsync<AgentMessage>(connection, timeout.Token)
                        .ConfigureAwait(false);
                    if (accepted is not AdminControlAccepted)
                    {
                        throw new IOException("admin_control_not_accepted");
                    }

                    await writer.WriteAsync(request, timeout.Token).ConfigureAwait(false);
                    var response = await LengthPrefixedJsonProtocol
                        .ReadAsync<AgentMessage>(connection, timeout.Token)
                        .ConfigureAwait(false);
                    if (response is not TResponse typed || GetRequestId(typed) != GetRequestId(request))
                    {
                        throw new ProtocolException(
                            "invalid_message",
                            "The administrator control response did not match the request.");
                    }

                    return typed;
                }
                catch (OperationCanceledException)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (retryTransportOnce && attempt == 0)
                    {
                        continue;
                    }

                    throw TransportUnavailable(localJobTransport);
                }
                catch (Exception error) when (
                    error is IOException or UnauthorizedAccessException or ProtocolException or
                        ObjectDisposedException)
                {
                    if (retryTransportOnce && attempt == 0)
                    {
                        continue;
                    }

                    throw TransportUnavailable(localJobTransport);
                }
            }
        }
        finally
        {
            if (gateEntered)
            {
                _requestGate.Release();
            }
        }
    }

    private static Exception TransportUnavailable(bool localJobTransport) =>
        localJobTransport
            ? new LocalJobException("local_job_unavailable")
            : new ManagementUnavailableException(Guid.NewGuid());

    private Guid NewRequestId()
    {
        var requestId = _requestIdFactory();
        return requestId != Guid.Empty
            ? requestId
            : throw new ManagementUnavailableException(Guid.NewGuid());
    }

    private static Guid GetRequestId(AgentMessage message) => message switch
    {
        ManagementSnapshotRequest value => value.RequestId,
        ManagementSnapshotResponse value => value.RequestId,
        AgentControlRequest value => value.RequestId,
        AgentControlResponse value => value.RequestId,
        JobPageRequest value => value.RequestId,
        JobPageResponse value => value.RequestId,
        TerminalJobDeltaRequest value => value.RequestId,
        TerminalJobDeltaResponse value => value.RequestId,
        ServiceSettingsRequest value => value.RequestId,
        ServiceSettingsResponse value => value.RequestId,
        LocalJobCreateRequest value => value.RequestId,
        LocalJobUploadLease value => value.RequestId,
        LocalJobUploadCompleted value => value.RequestId,
        LocalJobAccepted value => value.RequestId,
        LocalJobRejected value => value.RequestId,
        LocalJobResultRequest value => value.RequestId,
        LocalJobResultMetadata value => value.RequestId,
        _ => Guid.Empty,
    };

    private static void ThrowControlError(AgentControlResponse response, bool otpOperation)
    {
        if (response.ErrorCode is null)
        {
            return;
        }

        if (otpOperation && response.ErrorCode.StartsWith("otp_", StringComparison.Ordinal))
        {
            throw new OtpStoreException(response.ErrorCode);
        }

        throw new ManagementUnavailableException(response.CorrelationId ?? Guid.NewGuid());
    }

    private static LocalJobException LocalError(LocalJobRejected rejected) =>
        new(rejected.ErrorCode, rejected.CorrelationId, rejected.GetDisposition());

    private static string FormatOtpUri(OtpauthProfile profile) =>
        $"otpauth://totp/{Uri.EscapeDataString(profile.Issuer)}:{Uri.EscapeDataString(profile.Account)}" +
        $"?secret={Uri.EscapeDataString(profile.Secret)}" +
        $"&algorithm={Uri.EscapeDataString(profile.Algorithm)}" +
        $"&digits={profile.Digits.ToString(System.Globalization.CultureInfo.InvariantCulture)}" +
        $"&period={profile.Period.ToString(System.Globalization.CultureInfo.InvariantCulture)}" +
        $"&issuer={Uri.EscapeDataString(profile.Issuer)}";

    private static async ValueTask<Stream> ConnectNamedPipeAsync(
        CancellationToken cancellationToken)
    {
        var pipe = new NamedPipeClientStream(
            ".",
            AdminControlPipeServer.PipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            TokenImpersonationLevel.Impersonation);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(ConnectTimeout);
            await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
            return pipe;
        }
        catch
        {
            pipe.Dispose();
            throw;
        }
    }
}
