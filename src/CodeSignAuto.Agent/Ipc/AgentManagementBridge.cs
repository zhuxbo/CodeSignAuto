using CodeSignAuto.Protocol;
using CodeSignAuto.Agent.LocalJobs;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Agent.Security;
using CodeSignAuto.Core.Otp;

namespace CodeSignAuto.Agent.Ipc;

public interface IAgentManagementSession
{
    Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken);

    Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken);

    Task<ManagementSnapshot> LogoutAsync(CancellationToken cancellationToken) =>
        Task.FromException<ManagementSnapshot>(new ManagementUnavailableException(Guid.NewGuid()));
}

public interface IAgentStartupPreparationSession
{
    Task<PrepareSimplySignSessionResult> PrepareStartupAsync(
        PrepareSimplySignSessionCommand command,
        CancellationToken cancellationToken);
}

public interface IAgentManagementClient
{
    event EventHandler? SnapshotChanged;

    ManagementSnapshot? LatestSnapshot { get; }

    Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken);

    Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken);

    Task<ManagementSnapshot> LogoutAsync(CancellationToken cancellationToken) =>
        Task.FromException<ManagementSnapshot>(new ManagementUnavailableException(Guid.NewGuid()));
}

public interface IAgentAdministrationSession : IAgentManagementSession
{
    Task<ManagementSnapshot> ClearOtpAndLogoutAsync(CancellationToken cancellationToken);

    Task<JobPageResponse> GetJobPageAsync(JobPageCursor? cursor, CancellationToken cancellationToken);

    Task<TerminalJobDeltaResponse> GetTerminalJobDeltaAsync(
        TerminalJobWatermark? watermark,
        TerminalJobCursor? cursor,
        CancellationToken cancellationToken) =>
        Task.FromException<TerminalJobDeltaResponse>(new ManagementUnavailableException(Guid.NewGuid()));

    Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken);
}

public interface IAgentAdministrationClient
{
    Task<ManagementSnapshot> ClearOtpAndLogoutAsync(CancellationToken cancellationToken) =>
        Task.FromException<ManagementSnapshot>(new ManagementUnavailableException(Guid.NewGuid()));

    Task<JobPageResponse> GetJobPageAsync(JobPageCursor? cursor, CancellationToken cancellationToken);

    Task<TerminalJobDeltaResponse> GetTerminalJobDeltaAsync(
        TerminalJobWatermark? watermark,
        TerminalJobCursor? cursor,
        CancellationToken cancellationToken) =>
        Task.FromException<TerminalJobDeltaResponse>(new ManagementUnavailableException(Guid.NewGuid()));

    Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken);

    Task SaveOtpAsync(OtpauthProfile profile, CancellationToken cancellationToken);
}

public interface ILocalTotpCodeProvider
{
    Task<LocalTotpCode> GenerateCurrentAsync(CancellationToken cancellationToken);
}

public sealed class LocalTotpCode
{
    public LocalTotpCode(string code, int remainingSeconds, DateTimeOffset expiresAtUtc)
    {
        if (code is not { Length: 6 } || code.Any(static character => character is < '0' or > '9') ||
            remainingSeconds is < 1 or > 30 ||
            expiresAtUtc == default || expiresAtUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("The local login value is invalid.");
        }

        Code = code;
        RemainingSeconds = remainingSeconds;
        ExpiresAtUtc = expiresAtUtc;
    }

    public string Code { get; }
    public int RemainingSeconds { get; }
    public DateTimeOffset ExpiresAtUtc { get; }

    public override string ToString() => string.Empty;
}

public sealed class AgentManagementBridge :
    IAgentManagementClient,
    IAgentAdministrationClient,
    ILocalTotpCodeProvider,
    ILocalJobClient,
    IDisposable
{
    // Relogin may spend 30s closing SimplySign, 30s on each of two bounded probes,
    // and up to 3s entering a safe TOTP window. The remainder is scheduling margin.
    private static readonly TimeSpan MaximumReloginTimeout = TimeSpan.FromSeconds(100);

    private readonly object _sync = new();
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private readonly TimeSpan _refreshTimeout;
    private readonly TimeSpan _reloginTimeout;
    private readonly IOtpStore? _otpStore;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _otpGate = new(1, 1);
    private ActiveSession? _active;
    private ILocalJobClient? _knownLocalJobs;
    private ManagementSnapshot? _latest;
    private int _disposed;

    public AgentManagementBridge(
        TimeSpan? refreshTimeout = null,
        TimeSpan? reloginTimeout = null,
        IOtpStore? otpStore = null,
        TimeProvider? timeProvider = null)
    {
        _refreshTimeout = refreshTimeout ?? TimeSpan.FromSeconds(15);
        _reloginTimeout = reloginTimeout ?? MaximumReloginTimeout;
        _otpStore = otpStore;
        _timeProvider = timeProvider ?? TimeProvider.System;
        if (_refreshTimeout <= TimeSpan.Zero || _refreshTimeout > TimeSpan.FromSeconds(15) ||
            _reloginTimeout <= TimeSpan.Zero || _reloginTimeout > MaximumReloginTimeout)
        {
            throw new ArgumentOutOfRangeException(nameof(refreshTimeout));
        }
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

    public IDisposable Attach(IAgentManagementSession session) => Attach(session, null);

    public IDisposable Attach(IAgentManagementSession session, ILocalJobClient? localJobs)
    {
        ArgumentNullException.ThrowIfNull(session);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var active = new ActiveSession(session, localJobs);
        lock (_sync)
        {
            _active = active;
            if (localJobs is not null)
            {
                _knownLocalJobs = localJobs;
            }

            _latest = null;
        }

        SnapshotChanged?.Invoke(this, EventArgs.Empty);
        return new SessionLease(this, active);
    }

    public Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken) =>
        ExecuteAsync(ManagementOperation.Refresh, cancellationToken);

    public Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken) =>
        ExecuteAsync(ManagementOperation.Relogin, cancellationToken);

    public Task<ManagementSnapshot> LogoutAsync(CancellationToken cancellationToken) =>
        ExecuteAsync(ManagementOperation.Logout, cancellationToken);

    public Task<ManagementSnapshot> ClearOtpAndLogoutAsync(CancellationToken cancellationToken) =>
        ExecuteClearOtpAndLogoutAsync(cancellationToken);

    public Task<PrepareSimplySignSessionResult> PrepareStartupAsync(
        PrepareSimplySignSessionCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        IAgentManagementSession session;
        lock (_sync)
        {
            session = _active?.Session
                ?? throw new ManagementUnavailableException(Guid.NewGuid());
        }

        return session is IAgentStartupPreparationSession startup
            ? startup.PrepareStartupAsync(command, cancellationToken)
            : Task.FromException<PrepareSimplySignSessionResult>(
                new ManagementUnavailableException(Guid.NewGuid()));
    }

    public Task<JobPageResponse> GetJobPageAsync(
        JobPageCursor? cursor,
        CancellationToken cancellationToken) =>
        ExecuteAdministrationAsync(
            (session, token) => session.GetJobPageAsync(cursor, token),
            cancellationToken);

    public Task<TerminalJobDeltaResponse> GetTerminalJobDeltaAsync(
        TerminalJobWatermark? watermark,
        TerminalJobCursor? cursor,
        CancellationToken cancellationToken) =>
        ExecuteAdministrationAsync(
            (session, token) => session.GetTerminalJobDeltaAsync(watermark, cursor, token),
            cancellationToken);

    public Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken) =>
        ExecuteAdministrationAsync(
            static (session, token) => session.GetServiceSettingsAsync(token),
            cancellationToken);

    public async Task SaveOtpAsync(OtpauthProfile profile, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (_otpStore is null)
        {
            throw new ManagementUnavailableException(Guid.NewGuid());
        }

        await _otpGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _otpStore.SaveAsync(profile, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _otpGate.Release();
        }
    }

    public async Task<LocalTotpCode> GenerateCurrentAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (_otpStore is null)
        {
            throw new ManagementUnavailableException(Guid.NewGuid());
        }

        await _otpGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var profile = await _otpStore.LoadAsync(cancellationToken).ConfigureAwait(false);
            if (profile.Digits != 6 || profile.Period != 30 ||
                !string.Equals(profile.Algorithm, "SHA256", StringComparison.Ordinal))
            {
                throw new OtpStoreException("otp_profile_invalid");
            }

            var now = _timeProvider.GetUtcNow().ToUniversalTime();
            var unixSeconds = now.ToUnixTimeSeconds();
            if (unixSeconds < 0)
            {
                throw new OtpStoreException("clock_not_synchronized");
            }

            var remaining = profile.Period - (int)(unixSeconds % profile.Period);
            var expiresAt = DateTimeOffset.FromUnixTimeSeconds(unixSeconds + remaining);
            return new LocalTotpCode(
                TotpGenerator.Generate(profile, now),
                remaining,
                expiresAt);
        }
        finally
        {
            _otpGate.Release();
        }
    }

    public async Task<Guid> CreateAndUploadAsync(
        string path,
        SigningParameters parameters,
        IProgress<LocalCopyProgress>? progress,
        CancellationToken cancellationToken)
    {
        var (active, localJobs) = GetLocalJobs();
        var jobId = await localJobs
            .CreateAndUploadAsync(path, parameters, progress, cancellationToken)
            .ConfigureAwait(false);
        EnsureActiveLocalJobs(active, localJobs);
        return jobId;
    }

    public async Task SaveSignedCopyAsync(
        Guid jobId,
        string destinationPath,
        bool overwrite,
        CancellationToken cancellationToken)
    {
        var (active, localJobs) = GetLocalJobs();
        await localJobs
            .SaveSignedCopyAsync(jobId, destinationPath, overwrite, cancellationToken)
            .ConfigureAwait(false);
        EnsureActiveLocalJobs(active, localJobs);
    }

    public void ReleaseAcceptedSource(Guid jobId)
    {
        ILocalJobClient? localJobs;
        lock (_sync)
        {
            localJobs = _active?.LocalJobs ?? _knownLocalJobs;
        }

        localJobs?.ReleaseAcceptedSource(jobId);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        lock (_sync)
        {
            _active = null;
            _knownLocalJobs = null;
            _latest = null;
        }

        _operationGate.Dispose();
        _otpGate.Dispose();
    }

    private async Task<ManagementSnapshot> ExecuteAsync(
        ManagementOperation operation,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ActiveSession active;
            lock (_sync)
            {
                active = _active ?? throw new ManagementUnavailableException(Guid.NewGuid());
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(operation == ManagementOperation.Refresh
                ? _refreshTimeout
                : _reloginTimeout);
            ManagementSnapshot snapshot;
            try
            {
                snapshot = operation switch
                {
                    ManagementOperation.Refresh =>
                        await active.Session.RefreshAsync(timeout.Token).ConfigureAwait(false),
                    ManagementOperation.Relogin =>
                        await active.Session.ReloginAsync(timeout.Token).ConfigureAwait(false),
                    ManagementOperation.Logout =>
                        await active.Session.LogoutAsync(timeout.Token).ConfigureAwait(false),
                    _ => throw new InvalidOperationException("management_operation_invalid"),
                };
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested)
            {
                throw new ManagementUnavailableException(Guid.NewGuid());
            }
            catch (ManagementUnavailableException)
            {
                throw;
            }
            catch (Exception error) when (
                error is IOException or ObjectDisposedException or ProtocolException or SimplySign.SimplySignException)
            {
                throw new ManagementUnavailableException(Guid.NewGuid());
            }

            lock (_sync)
            {
                if (!ReferenceEquals(_active, active))
                {
                    throw new ManagementUnavailableException(Guid.NewGuid());
                }

                _latest = snapshot;
            }

            SnapshotChanged?.Invoke(this, EventArgs.Empty);
            return snapshot;
        }
        finally
        {
            _operationGate.Release();
        }
    }

    private enum ManagementOperation
    {
        Refresh,
        Relogin,
        Logout,
    }

    private async Task<T> ExecuteAdministrationAsync<T>(
        Func<IAgentAdministrationSession, CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        ActiveSession active;
        lock (_sync)
        {
            active = _active ?? throw new ManagementUnavailableException(Guid.NewGuid());
        }

        if (active.Session is not IAgentAdministrationSession administration)
        {
            throw new ManagementUnavailableException(Guid.NewGuid());
        }

        try
        {
            var result = await operation(administration, cancellationToken).ConfigureAwait(false);
            lock (_sync)
            {
                if (!ReferenceEquals(_active, active))
                {
                    throw new ManagementUnavailableException(Guid.NewGuid());
                }
            }

            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ManagementUnavailableException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or ObjectDisposedException or ProtocolException)
        {
            throw new ManagementUnavailableException(Guid.NewGuid());
        }
    }

    private async Task<ManagementSnapshot> ExecuteClearOtpAndLogoutAsync(
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ActiveSession active;
            lock (_sync)
            {
                active = _active ?? throw new ManagementUnavailableException(Guid.NewGuid());
            }

            if (active.Session is not IAgentAdministrationSession administration)
            {
                throw new ManagementUnavailableException(Guid.NewGuid());
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_reloginTimeout);
            ManagementSnapshot snapshot;
            try
            {
                snapshot = await administration
                    .ClearOtpAndLogoutAsync(timeout.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested)
            {
                throw new ManagementUnavailableException(Guid.NewGuid());
            }
            catch (ManagementUnavailableException)
            {
                throw;
            }
            catch (Exception error) when (
                error is IOException or ObjectDisposedException or ProtocolException or SimplySign.SimplySignException)
            {
                throw new ManagementUnavailableException(Guid.NewGuid());
            }

            lock (_sync)
            {
                if (!ReferenceEquals(_active, active))
                {
                    throw new ManagementUnavailableException(Guid.NewGuid());
                }

                _latest = snapshot;
            }

            SnapshotChanged?.Invoke(this, EventArgs.Empty);
            return snapshot;
        }
        finally
        {
            _operationGate.Release();
        }
    }

    private void Detach(ActiveSession active)
    {
        var changed = false;
        lock (_sync)
        {
            if (ReferenceEquals(_active, active))
            {
                _active = null;
                _latest = null;
                changed = true;
            }
        }

        if (changed)
        {
            SnapshotChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    private (ActiveSession Active, ILocalJobClient LocalJobs) GetLocalJobs()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        lock (_sync)
        {
            if (_active is not { LocalJobs: { } localJobs } active)
            {
                throw new LocalJobException("local_job_unavailable");
            }

            return (active, localJobs);
        }
    }

    private void EnsureActiveLocalJobs(ActiveSession started, ILocalJobClient localJobs)
    {
        lock (_sync)
        {
            if (ReferenceEquals(_active, started))
            {
                return;
            }

            if (_active is not { LocalJobs: { } current } || !ReferenceEquals(current, localJobs))
            {
                throw new LocalJobException("local_job_unavailable");
            }
        }
    }

    private sealed record ActiveSession(IAgentManagementSession Session, ILocalJobClient? LocalJobs);

    private sealed class SessionLease(AgentManagementBridge owner, ActiveSession active) : IDisposable
    {
        private AgentManagementBridge? _owner = owner;

        public void Dispose() => Interlocked.Exchange(ref _owner, null)?.Detach(active);
    }
}
