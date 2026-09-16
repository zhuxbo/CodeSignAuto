using CodeSignAuto.Agent.SimplySign;
using CodeSignAuto.Agent.Security;
using CodeSignAuto.Core.Otp;
using CodeSignAuto.Protocol;

namespace CodeSignAuto.Agent.Ipc;

public sealed class LiveAgentManagementSession :
    IAgentAdministrationSession,
    IAgentStartupPreparationSession,
    IAgentControlCommandHandler,
    IDisposable,
    IAsyncDisposable
{
    private readonly IAgentManagementTransport _transport;
    private readonly CapabilityProbeCache _cache;
    private readonly IOtpStore? _otpStore;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _lifecycleSync = new();
    private TaskCompletionSource _operationsDrained = CompletedSource();
    private Task? _disposeTask;
    private int _activeOperations;

    public LiveAgentManagementSession(
        IAgentManagementTransport transport,
        CapabilityProbeCache cache,
        IOtpStore? otpStore = null,
        TimeProvider? timeProvider = null)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _otpStore = otpStore;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<AgentControlResponse> ExecuteAsync(
        AgentControlRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        try
        {
            if (_transport.CurrentJobId is not null)
            {
                return ControlError(request, "agent_busy");
            }

            if (request.Operation == AdminControlContract.GenerateTotp)
            {
                return await GenerateTotpAsync(request, cancellationToken).ConfigureAwait(false);
            }

            switch (request.Operation)
            {
                case AdminControlContract.Refresh:
                case AdminControlContract.Relogin:
                case AdminControlContract.Logout:
                case AdminControlContract.ClearOtp:
                    await ExecuteControlManagementAsync(
                        request.Operation,
                        cancellationToken).ConfigureAwait(false);
                    break;
                case AdminControlContract.ImportOtp:
                    await ImportOtpAsync(request.OtpUri!, cancellationToken).ConfigureAwait(false);
                    break;
                default:
                    return ControlError(request, "internal_error");
            }

            return new AgentControlResponse(
                request.RequestId,
                request.Operation,
                _cache.CreateHeartbeat(_transport.CurrentJobId),
                null,
                null,
                null,
                null,
                null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ManagementUnavailableException)
        {
            return ControlError(request, "management_unavailable");
        }
        catch (OtpStoreException error)
        {
            return ControlError(
                request,
                AdminControlContract.IsErrorCode(error.Code) ? error.Code : "internal_error");
        }
        catch (OtpauthException)
        {
            return ControlError(request, "otp_profile_invalid");
        }
        catch (Exception)
        {
            return ControlError(request, "internal_error");
        }
    }

    public Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken)
    {
        BeginOperation();
        return ExecuteTrackedManagementAsync(relogin: false, cancellationToken);
    }

    public Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken)
    {
        BeginOperation();
        return ExecuteTrackedManagementAsync(relogin: true, cancellationToken);
    }

    public Task<ManagementSnapshot> LogoutAsync(CancellationToken cancellationToken)
    {
        BeginOperation();
        return ExecuteTrackedLogoutAsync(cancellationToken);
    }

    public Task<ManagementSnapshot> ClearOtpAndLogoutAsync(CancellationToken cancellationToken)
    {
        BeginOperation();
        return ExecuteTrackedClearOtpAndLogoutAsync(cancellationToken);
    }

    public Task<int> ClearJobHistoryAsync(DateTimeOffset completedBeforeUtc, CancellationToken cancellationToken)
    {
        BeginOperation();
        return ExecuteAdministrationAsync(
            token => _transport.ClearJobHistoryAsync(completedBeforeUtc, token), cancellationToken);
    }

    public Task<JobPageResponse> GetJobPageAsync(
        JobPageCursor? cursor,
        CancellationToken cancellationToken)
    {
        BeginOperation();
        return ExecuteAdministrationAsync(
            token => _transport.GetJobPageAsync(cursor, token),
            cancellationToken);
    }

    public Task<TerminalJobDeltaResponse> GetTerminalJobDeltaAsync(
        TerminalJobWatermark? watermark,
        TerminalJobCursor? cursor,
        CancellationToken cancellationToken)
    {
        BeginOperation();
        return ExecuteAdministrationAsync(
            token => _transport.GetTerminalJobDeltaAsync(watermark, cursor, token),
            cancellationToken);
    }

    public Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken)
    {
        BeginOperation();
        return ExecuteAdministrationAsync(_transport.GetServiceSettingsAsync, cancellationToken);
    }

    public Task<PrepareSimplySignSessionResult> PrepareStartupAsync(
        PrepareSimplySignSessionCommand command,
        CancellationToken cancellationToken) =>
        _cache.PrepareStartupAsync(command, cancellationToken);

    public async Task<JobTerminalMessage> ExecuteSigningAsync(
        Func<CancellationToken, Task<JobTerminalMessage>> operation,
        CancellationToken cancellationToken)
    {
        return await ExecuteSigningCoreAsync(operation, cancellationToken).ConfigureAwait(false);
    }

    public async Task<JobTerminalPublication> PrepareSigningPublicationAsync(
        Func<CancellationToken, Task<JobTerminalPublication>> operation,
        CancellationToken cancellationToken)
    {
        return await ExecuteSigningCoreAsync(operation, cancellationToken).ConfigureAwait(false);
    }

    private async Task<T> ExecuteSigningCoreAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        BeginOperation();
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            await _operationGate.WaitAsync(linked.Token).ConfigureAwait(false);
            try
            {
                return await operation(linked.Token).ConfigureAwait(false);
            }
            finally
            {
                _operationGate.Release();
            }
        }
        finally
        {
            EndOperation();
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

    private async Task<ManagementSnapshot> ExecuteTrackedManagementAsync(
        bool relogin,
        CancellationToken cancellationToken)
    {
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            await _operationGate.WaitAsync(linked.Token).ConfigureAwait(false);
            try
            {
                if (relogin && _transport.CurrentJobId is not null)
                {
                    throw new ManagementUnavailableException(Guid.NewGuid());
                }

                if (relogin)
                {
                    await _cache.ReloginAsync(linked.Token).ConfigureAwait(false);
                }
                else
                {
                    await _cache.RefreshAsync(linked.Token).ConfigureAwait(false);
                }

                await _transport.PublishHeartbeatAsync(
                    _cache.CreateHeartbeat(_transport.CurrentJobId),
                    linked.Token).ConfigureAwait(false);
                return await _transport.GetManagementSnapshotAsync(linked.Token).ConfigureAwait(false);
            }
            finally
            {
                _operationGate.Release();
            }
        }
        finally
        {
            EndOperation();
        }
    }

    private async Task ExecuteControlManagementAsync(
        string operation,
        CancellationToken cancellationToken)
    {
        BeginOperation();
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            await _operationGate.WaitAsync(linked.Token).ConfigureAwait(false);
            try
            {
                if (_transport.CurrentJobId is not null)
                {
                    throw new ManagementUnavailableException(Guid.NewGuid());
                }

                switch (operation)
                {
                    case AdminControlContract.Refresh:
                        await _cache.RefreshAsync(linked.Token).ConfigureAwait(false);
                        break;
                    case AdminControlContract.Relogin:
                        await _cache.ReloginAsync(linked.Token).ConfigureAwait(false);
                        break;
                    case AdminControlContract.Logout:
                        await _cache.LogoutAsync(linked.Token).ConfigureAwait(false);
                        break;
                    case AdminControlContract.ClearOtp:
                        await _cache.ClearOtpAndLogoutAsync(linked.Token).ConfigureAwait(false);
                        break;
                    default:
                        throw new InvalidOperationException("agent_control_operation_invalid");
                }

                await _transport.PublishHeartbeatAsync(
                    _cache.CreateHeartbeat(_transport.CurrentJobId),
                    linked.Token).ConfigureAwait(false);
            }
            finally
            {
                _operationGate.Release();
            }
        }
        finally
        {
            EndOperation();
        }
    }

    private async Task<ManagementSnapshot> ExecuteTrackedLogoutAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            await _operationGate.WaitAsync(linked.Token).ConfigureAwait(false);
            try
            {
                if (_transport.CurrentJobId is not null)
                {
                    throw new ManagementUnavailableException(Guid.NewGuid());
                }

                await _cache.LogoutAsync(linked.Token).ConfigureAwait(false);
                await _transport.PublishHeartbeatAsync(
                    _cache.CreateHeartbeat(_transport.CurrentJobId),
                    linked.Token).ConfigureAwait(false);
                return await _transport.GetManagementSnapshotAsync(linked.Token).ConfigureAwait(false);
            }
            finally
            {
                _operationGate.Release();
            }
        }
        finally
        {
            EndOperation();
        }
    }

    private async Task<ManagementSnapshot> ExecuteTrackedClearOtpAndLogoutAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            await _operationGate.WaitAsync(linked.Token).ConfigureAwait(false);
            try
            {
                if (_transport.CurrentJobId is not null)
                {
                    throw new ManagementUnavailableException(Guid.NewGuid());
                }

                await _cache.ClearOtpAndLogoutAsync(linked.Token).ConfigureAwait(false);
                await _transport.PublishHeartbeatAsync(
                    _cache.CreateHeartbeat(_transport.CurrentJobId),
                    linked.Token).ConfigureAwait(false);
                return await _transport.GetManagementSnapshotAsync(linked.Token).ConfigureAwait(false);
            }
            finally
            {
                _operationGate.Release();
            }
        }
        finally
        {
            EndOperation();
        }
    }

    private async Task ImportOtpAsync(string uri, CancellationToken cancellationToken)
    {
        if (_otpStore is null)
        {
            throw new ManagementUnavailableException(Guid.NewGuid());
        }

        BeginOperation();
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            await _operationGate.WaitAsync(linked.Token).ConfigureAwait(false);
            try
            {
                if (_transport.CurrentJobId is not null)
                {
                    throw new ManagementUnavailableException(Guid.NewGuid());
                }

                var profile = OtpauthProfile.Parse(uri);
                await _otpStore.SaveAsync(profile, linked.Token).ConfigureAwait(false);
            }
            finally
            {
                _operationGate.Release();
            }
        }
        finally
        {
            EndOperation();
        }
    }

    private async Task<AgentControlResponse> GenerateTotpAsync(
        AgentControlRequest request,
        CancellationToken cancellationToken)
    {
        if (_otpStore is null)
        {
            throw new ManagementUnavailableException(Guid.NewGuid());
        }

        BeginOperation();
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            await _operationGate.WaitAsync(linked.Token).ConfigureAwait(false);
            try
            {
                if (_transport.CurrentJobId is not null)
                {
                    return ControlError(request, "agent_busy");
                }

                var profile = await _otpStore.LoadAsync(linked.Token).ConfigureAwait(false);
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
                return new AgentControlResponse(
                    request.RequestId,
                    request.Operation,
                    null,
                    TotpGenerator.Generate(profile, now),
                    remaining,
                    DateTimeOffset.FromUnixTimeSeconds(unixSeconds + remaining),
                    null,
                    null);
            }
            finally
            {
                _operationGate.Release();
            }
        }
        finally
        {
            EndOperation();
        }
    }

    private static AgentControlResponse ControlError(AgentControlRequest request, string code) =>
        new(
            request.RequestId,
            request.Operation,
            null,
            null,
            null,
            null,
            code,
            Guid.NewGuid());

    private async Task<T> ExecuteAdministrationAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            return await operation(linked.Token).ConfigureAwait(false);
        }
        finally
        {
            EndOperation();
        }
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
            _operationGate.Dispose();
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
}
