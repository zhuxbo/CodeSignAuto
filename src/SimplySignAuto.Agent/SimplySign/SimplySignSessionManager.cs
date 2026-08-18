using SimplySignAuto.Agent.Signing;
using SimplySignAuto.Core.Otp;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.Agent.SimplySign;

public enum SessionTrigger
{
    Startup,
    BeforeSign,
    BackgroundHealth,
    ManualRefresh,
    ManualRelogin,
}

public interface IReadySignLease : IAsyncDisposable
{
    SimplySignSessionSnapshot Snapshot { get; }

    CertificateCatalogSnapshot CatalogSnapshot { get; }

    CancellationToken CancellationToken { get; }

    Task<T> RunAsync<T>(Func<CancellationToken, Task<T>> operation);
}

public interface ISimplySignSessionManager : IDisposable, IAsyncDisposable
{
    event EventHandler<SimplySignSessionSnapshot>? SnapshotChanged;

    SimplySignSessionSnapshot GetSnapshot();

    SimplySignCapabilityGroup GetCapabilityGroup();

    Task<SimplySignSessionSnapshot> PrepareStartupAsync(CancellationToken cancellationToken);

    Task<SimplySignSessionSnapshot> CheckAsync(
        SessionTrigger trigger,
        CancellationToken cancellationToken);

    Task<SimplySignSessionSnapshot> EnsureReadyAsync(
        SessionTrigger trigger,
        CancellationToken cancellationToken);

    Task<IReadySignLease> AcquireReadySignLeaseAsync(CancellationToken cancellationToken);

    Task<SimplySignSessionSnapshot> LogoutAsync(CancellationToken cancellationToken) =>
        Task.FromException<SimplySignSessionSnapshot>(
            new SimplySignException("simplysign_configuration_invalid"));

    Task<SimplySignSessionSnapshot> ClearOtpAndLogoutAsync(CancellationToken cancellationToken) =>
        Task.FromException<SimplySignSessionSnapshot>(
            new SimplySignException("simplysign_configuration_invalid"));

    void Invalidate();
}

public sealed record SimplySignCapabilityGroup(
    long SessionGeneration,
    SimplySignSessionSnapshot Session,
    CertificateCatalogSnapshot? CatalogSnapshot,
    IReadOnlyList<CertificateDisplaySummary>? DisplaySummaries = null);

public sealed class SimplySignSessionManager : ISimplySignSessionManager
{
    private static readonly TimeSpan ProbeInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan LoginProbeTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan RetryCooldown = TimeSpan.FromSeconds(60);

    private readonly ISimplySignSessionDriver _driver;
    private readonly ISigningOperationGate _operationGate;
    private readonly ICertificateCatalog _catalog;
    private readonly SemaphoreSlim _loginGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _stateSync = new();
    private readonly object _lifecycleSync = new();
    private TaskCompletionSource _operationsDrained = CompletedSource();
    private SimplySignSessionSnapshot _snapshot;
    private StartupPreparation? _startupPreparation;
    private Task? _disposeTask;
    private int _activeOperations;

    public SimplySignSessionManager(
        ISimplySignSessionDriver driver,
        ISigningOperationGate operationGate,
        ICertificateCatalog catalog,
        long initialSessionGeneration = 1)
    {
        _driver = driver ?? throw new ArgumentNullException(nameof(driver));
        _operationGate = operationGate ?? throw new ArgumentNullException(nameof(operationGate));
        _catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
        if (driver.VerifiedSessionId <= 0 || initialSessionGeneration <= 0)
        {
            throw new SimplySignException("simplysign_configuration_invalid");
        }

        var now = NormalizeNow(driver.UtcNow);
        _snapshot = EmptySnapshot(
            SimplySignSessionState.Unknown,
            initialSessionGeneration,
            now,
            "unknown",
            attempt: 0,
            nextRetryAtUtc: null,
            processState: null);
    }

    public event EventHandler<SimplySignSessionSnapshot>? SnapshotChanged;

    public SimplySignSessionSnapshot GetSnapshot()
    {
        lock (_stateSync)
        {
            return _snapshot;
        }
    }

    public SimplySignCapabilityGroup GetCapabilityGroup()
    {
        lock (_stateSync)
        {
            return new SimplySignCapabilityGroup(
                _snapshot.SessionGeneration,
                _snapshot,
                _catalog.Current,
                _catalog.DisplaySummaries);
        }
    }

    public async Task<SimplySignSessionSnapshot> PrepareStartupAsync(
        CancellationToken cancellationToken)
    {
        Task<SimplySignSessionSnapshot> preparation;
        lock (_stateSync)
        {
            ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
            var owner = _startupPreparation;
            if (owner is null)
            {
                owner = new StartupPreparation();
                _startupPreparation = owner;
                owner.Task = ExecuteStartupPreparationAsync(owner);
            }

            preparation = owner.Task;
        }

        return await preparation.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<SimplySignSessionSnapshot> ExecuteStartupPreparationAsync(
        StartupPreparation owner)
    {
        try
        {
            return await EnsureReadyAsync(SessionTrigger.Startup, _lifetime.Token).ConfigureAwait(false);
        }
        finally
        {
            lock (_stateSync)
            {
                if (ReferenceEquals(_startupPreparation, owner))
                {
                    _startupPreparation = null;
                }
            }
        }
    }

    public Task<SimplySignSessionSnapshot> CheckAsync(
        SessionTrigger trigger,
        CancellationToken cancellationToken)
    {
        ValidateTrigger(trigger);
        BeginOperation();
        return ExecuteCheckTrackedAsync(trigger, cancellationToken);
    }

    public Task<SimplySignSessionSnapshot> EnsureReadyAsync(
        SessionTrigger trigger,
        CancellationToken cancellationToken)
    {
        ValidateTrigger(trigger);
        if (trigger == SessionTrigger.BackgroundHealth)
        {
            throw new ArgumentException("Background health is read-only.", nameof(trigger));
        }

        BeginOperation();
        return ExecuteEnsureTrackedAsync(trigger, cancellationToken);
    }

    public async Task<IReadySignLease> AcquireReadySignLeaseAsync(
        CancellationToken cancellationToken)
    {
        BeginOperation();
        var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _lifetime.Token);
        ISigningOperationLease? operationLease = null;
        try
        {
            operationLease = await _operationGate.AcquireAsync(linked.Token).ConfigureAwait(false);
            var snapshot = await EnsureReadyInsideOperationAsync(
                SessionTrigger.BeforeSign,
                operationLease.CancellationToken).ConfigureAwait(false);
            var catalog = _catalog.Current;
            if (catalog is null)
            {
                throw new SigningException("certificate_catalog_unavailable");
            }

            if (!snapshot.Ready)
            {
                throw new SimplySignException(NormalizeSigningFailure(snapshot));
            }

            return new ReadySignLease(this, snapshot, catalog, operationLease, linked);
        }
        catch
        {
            if (operationLease is not null)
            {
                await operationLease.DisposeAsync().ConfigureAwait(false);
            }

            linked.Dispose();
            EndOperation();
            throw;
        }
    }

    public Task<SimplySignSessionSnapshot> ClearOtpAndLogoutAsync(
        CancellationToken cancellationToken)
    {
        BeginOperation();
        return ExecuteClearOtpAndLogoutTrackedAsync(cancellationToken);
    }

    public Task<SimplySignSessionSnapshot> LogoutAsync(CancellationToken cancellationToken)
    {
        BeginOperation();
        return ExecuteLogoutTrackedAsync(cancellationToken);
    }

    public void Invalidate()
    {
        SimplySignSessionSnapshot invalidated;
        lock (_stateSync)
        {
            ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
            _catalog.Invalidate();
            var now = NormalizeNow(_driver.UtcNow);
            invalidated = EmptySnapshot(
                SimplySignSessionState.Unknown,
                checked(_snapshot.SessionGeneration + 1),
                TransitionTime(_snapshot, now),
                "invalidated",
                attempt: 0,
                nextRetryAtUtc: null,
                ProcessState(_snapshot));
            _snapshot = invalidated;
        }

        SnapshotChanged?.Invoke(this, invalidated);
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

    private async Task<SimplySignSessionSnapshot> ExecuteCheckTrackedAsync(
        SessionTrigger trigger,
        CancellationToken cancellationToken)
    {
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            if (trigger == SessionTrigger.BackgroundHealth)
            {
                SimplySignSessionSnapshot? checkedSnapshot = null;
                var ran = await _operationGate.TryRunHealthCheckAsync(
                    token =>
                    {
                        token.ThrowIfCancellationRequested();
                        checkedSnapshot = CheckProcessOnlyInsideOperation();
                        return Task.CompletedTask;
                    },
                    linked.Token).ConfigureAwait(false);
                return ran ? checkedSnapshot! : GetSnapshot();
            }

            return await _operationGate.RunAsync(
                CheckCatalogInsideOperationAsync,
                linked.Token).ConfigureAwait(false);
        }
        finally
        {
            EndOperation();
        }
    }

    private async Task<SimplySignSessionSnapshot> ExecuteClearOtpAndLogoutTrackedAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            return await _operationGate.RunAsync(
                ClearOtpAndLogoutInsideOperationAsync,
                linked.Token).ConfigureAwait(false);
        }
        finally
        {
            EndOperation();
        }
    }

    private async Task<SimplySignSessionSnapshot> ExecuteLogoutTrackedAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            return await _operationGate.RunAsync(
                LogoutInsideOperationAsync,
                linked.Token).ConfigureAwait(false);
        }
        finally
        {
            EndOperation();
        }
    }

    private async Task<SimplySignSessionSnapshot> LogoutInsideOperationAsync(
        CancellationToken cancellationToken)
    {
        await _driver.CloseAsync(cancellationToken).ConfigureAwait(false);
        InvalidateAfterLogout();
        return GetSnapshot();
    }

    private async Task<SimplySignSessionSnapshot> ClearOtpAndLogoutInsideOperationAsync(
        CancellationToken cancellationToken)
    {
        await _driver.CloseAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _driver.DeleteOtpAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            InvalidateAfterLogout();
        }

        return GetSnapshot();
    }

    private void InvalidateAfterLogout()
    {
        SimplySignSessionSnapshot invalidated;
        lock (_stateSync)
        {
            _catalog.Clear();
            var now = NormalizeNow(_driver.UtcNow);
            invalidated = EmptySnapshot(
                SimplySignSessionState.Unknown,
                checked(_snapshot.SessionGeneration + 1),
                TransitionTime(_snapshot, now),
                "invalidated",
                attempt: 0,
                nextRetryAtUtc: null,
                new SimplySignProcessState(false, null));
            _snapshot = invalidated;
        }

        SnapshotChanged?.Invoke(this, invalidated);
    }

    private async Task<SimplySignSessionSnapshot> ExecuteEnsureTrackedAsync(
        SessionTrigger trigger,
        CancellationToken cancellationToken)
    {
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            return await _operationGate.RunAsync(
                token => EnsureReadyInsideOperationAsync(trigger, token),
                linked.Token).ConfigureAwait(false);
        }
        finally
        {
            EndOperation();
        }
    }

    private async Task<SimplySignSessionSnapshot> EnsureReadyInsideOperationAsync(
        SessionTrigger trigger,
        CancellationToken cancellationToken)
    {
        var current = GetSnapshot();
        if (trigger != SessionTrigger.ManualRelogin &&
            current.State == SimplySignSessionState.Failed &&
            current.NextRetryAtUtc is { } retry && retry > _driver.UtcNow)
        {
            return current;
        }

        if (trigger != SessionTrigger.ManualRelogin)
        {
            current = await CheckCatalogInsideOperationAsync(cancellationToken).ConfigureAwait(false);
            if (current.Ready)
            {
                return current;
            }
        }

        await _loginGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (trigger != SessionTrigger.ManualRelogin && GetSnapshot().Ready && _catalog.Current is not null)
            {
                return GetSnapshot();
            }

            return await ReloginInsideOperationAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _loginGate.Release();
        }
    }

    private async Task<SimplySignSessionSnapshot> CheckCatalogInsideOperationAsync(
        CancellationToken cancellationToken)
    {
        var current = GetSnapshot();
        var generation = current.SessionGeneration;
        Publish(
            SimplySignSessionState.Checking,
            "checking",
            current.Attempt,
            nextRetryAtUtc: null,
            generation,
            ProcessState(current));
        try
        {
            _ = await _catalog.RefreshAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsCurrentGeneration(generation) || _catalog.Current is null)
            {
                return GetSnapshot();
            }

            return PublishReady(generation, current.Attempt);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (SigningException)
        {
            _catalog.Invalidate();
            return Publish(
                SimplySignSessionState.LoginRequired,
                "login_required",
                current.Attempt,
                nextRetryAtUtc: null,
                generation,
                ProcessState(current));
        }
    }

    private SimplySignSessionSnapshot CheckProcessOnlyInsideOperation()
    {
        var process = _driver.CheckProcessOnly();
        var current = GetSnapshot();
        return Publish(
            current.State,
            current.ReasonCode,
            current.Attempt,
            current.NextRetryAtUtc,
            current.SessionGeneration,
            process);
    }

    private async Task<SimplySignSessionSnapshot> ReloginInsideOperationAsync(
        CancellationToken cancellationToken)
    {
        var generation = BeginLoginGeneration();
        try
        {
            await _driver.CloseAsync(cancellationToken).ConfigureAwait(false);
            var profile = await _driver.LoadOtpAsync(cancellationToken).ConfigureAwait(false);

            var firstCounter = await StartLoginAttemptAsync(profile, generation, 1, cancellationToken)
                .ConfigureAwait(false);
            var ready = await PollUntilReadyAsync(generation, 1, cancellationToken).ConfigureAwait(false);
            if (ready is not null)
            {
                return ready;
            }

            Publish(
                SimplySignSessionState.LoginRequired,
                "login_required",
                attempt: 1,
                nextRetryAtUtc: null,
                generation,
                processState: null);
            await _driver.WaitForCounterAfterAsync(profile, firstCounter, cancellationToken)
                .ConfigureAwait(false);
            _ = await StartLoginAttemptAsync(profile, generation, 2, cancellationToken)
                .ConfigureAwait(false);
            ready = await PollUntilReadyAsync(generation, 2, cancellationToken).ConfigureAwait(false);
            if (ready is not null)
            {
                return ready;
            }

            var nextRetry = NormalizeNow(_driver.UtcNow) + RetryCooldown;
            return Publish(
                SimplySignSessionState.Failed,
                "retry_scheduled",
                attempt: 2,
                nextRetry,
                generation,
                processState: null);
        }
        catch
        {
            InvalidateFailedGeneration(generation);
            throw;
        }
    }

    private async Task<long> StartLoginAttemptAsync(
        OtpauthProfile profile,
        long generation,
        int attempt,
        CancellationToken cancellationToken)
    {
        if (!IsCurrentGeneration(generation))
        {
            throw new OperationCanceledException("session_generation_invalidated", cancellationToken);
        }

        Publish(
            SimplySignSessionState.Loginning,
            "loginning",
            attempt,
            nextRetryAtUtc: null,
            generation,
            processState: null);
        var counter = await _driver.StartLoginAsync(profile, cancellationToken).ConfigureAwait(false);
        Publish(
            SimplySignSessionState.WaitToken,
            "wait_token",
            attempt,
            nextRetryAtUtc: null,
            generation,
            processState: null);
        return counter;
    }

    private async Task<SimplySignSessionSnapshot?> PollUntilReadyAsync(
        long generation,
        int attempt,
        CancellationToken cancellationToken)
    {
        var deadline = _driver.UtcNow + LoginProbeTimeout;
        while (_driver.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsCurrentGeneration(generation))
            {
                return null;
            }

            var remaining = deadline - _driver.UtcNow;
            await _driver.DelayAsync(
                remaining < ProbeInterval ? remaining : ProbeInterval,
                cancellationToken).ConfigureAwait(false);
            try
            {
                _ = await _catalog.RefreshAsync(cancellationToken).ConfigureAwait(false);
                if (_catalog.Current is not null && IsCurrentGeneration(generation))
                {
                    return PublishReady(generation, attempt);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (SigningException)
            {
                _catalog.Invalidate();
            }
        }

        return null;
    }

    private long BeginLoginGeneration()
    {
        SimplySignSessionSnapshot invalidated;
        lock (_stateSync)
        {
            _catalog.Invalidate();
            var now = NormalizeNow(_driver.UtcNow);
            invalidated = EmptySnapshot(
                SimplySignSessionState.Unknown,
                checked(_snapshot.SessionGeneration + 1),
                TransitionTime(_snapshot, now),
                "invalidated",
                attempt: 0,
                nextRetryAtUtc: null,
                ProcessState(_snapshot));
            _snapshot = invalidated;
        }

        SnapshotChanged?.Invoke(this, invalidated);
        Publish(
            SimplySignSessionState.Checking,
            "checking",
            attempt: 0,
            nextRetryAtUtc: null,
            invalidated.SessionGeneration,
            processState: null);
        Publish(
            SimplySignSessionState.LoginRequired,
            "login_required",
            attempt: 0,
            nextRetryAtUtc: null,
            invalidated.SessionGeneration,
            processState: null);
        return invalidated.SessionGeneration;
    }

    private SimplySignSessionSnapshot PublishReady(long generation, int attempt) =>
        Publish(
            SimplySignSessionState.Ready,
            "ready",
            attempt,
            nextRetryAtUtc: null,
            generation,
            _driver.CheckProcessOnly());

    private SimplySignSessionSnapshot Publish(
        SimplySignSessionState state,
        string reasonCode,
        int attempt,
        DateTimeOffset? nextRetryAtUtc,
        long generation,
        SimplySignProcessState? processState)
    {
        SimplySignSessionSnapshot candidate;
        lock (_stateSync)
        {
            if (_snapshot.SessionGeneration != generation)
            {
                return _snapshot;
            }

            var now = NormalizeNow(_driver.UtcNow);
            var transitioned = state == _snapshot.State
                ? _snapshot.TransitionedAtUtc
                : TransitionTime(_snapshot, now);
            var probedAt = now < transitioned ? transitioned : now;
            candidate = state == SimplySignSessionState.Ready
                ? ReadySnapshot(
                    generation,
                    probedAt,
                    transitioned,
                    attempt,
                    _driver.VerifiedSessionId,
                    processState)
                : EmptySnapshot(
                    state,
                    generation,
                    probedAt,
                    reasonCode,
                    attempt,
                    nextRetryAtUtc,
                    processState ?? ProcessState(_snapshot),
                    transitioned);
            if (!SimplySignSessionTransitionPolicy.IsAllowed(
                    _snapshot,
                    candidate,
                    TransitionCause.Normal))
            {
                return _snapshot;
            }

            _snapshot = candidate;
        }

        SnapshotChanged?.Invoke(this, candidate);
        return candidate;
    }

    private void InvalidateFailedGeneration(long generation)
    {
        lock (_stateSync)
        {
            if (_snapshot.SessionGeneration != generation)
            {
                return;
            }
        }

        Invalidate();
    }

    private bool IsCurrentGeneration(long generation)
    {
        lock (_stateSync)
        {
            return _snapshot.SessionGeneration == generation;
        }
    }

    private static SimplySignSessionSnapshot ReadySnapshot(
        long generation,
        DateTimeOffset now,
        DateTimeOffset transitioned,
        int attempt,
        int verifiedSessionId,
        SimplySignProcessState? processState) =>
        new(
            SimplySignSessionState.Ready,
            generation,
            now,
            transitioned,
            sessionId: verifiedSessionId,
            tokenPresent: true,
            tokenMatches: true,
            certificatePresent: true,
            certificateMatches: true,
            privateKeyPresent: true,
            privateKeyMatches: true,
            ready: true,
            "ready",
            attempt,
            nextRetryAtUtc: null,
            simplySignProcessRunning: processState?.ProcessRunning,
            simplySignProcessSessionId: processState?.ProcessRunning == true ? processState.SessionId : null);

    private static SimplySignSessionSnapshot EmptySnapshot(
        SimplySignSessionState state,
        long generation,
        DateTimeOffset now,
        string reasonCode,
        int attempt,
        DateTimeOffset? nextRetryAtUtc,
        SimplySignProcessState? processState,
        DateTimeOffset? transitionedAtUtc = null) =>
        new(
            state,
            generation,
            now,
            transitionedAtUtc ?? now,
            sessionId: null,
            tokenPresent: false,
            tokenMatches: false,
            certificatePresent: false,
            certificateMatches: false,
            privateKeyPresent: false,
            privateKeyMatches: false,
            ready: false,
            reasonCode,
            attempt,
            nextRetryAtUtc,
            simplySignProcessRunning: processState?.ProcessRunning,
            simplySignProcessSessionId: processState?.ProcessRunning == true ? processState.SessionId : null);

    private static SimplySignProcessState? ProcessState(SimplySignSessionSnapshot snapshot) =>
        snapshot.SimplySignProcessRunning is { } running
            ? new SimplySignProcessState(running, snapshot.SimplySignProcessSessionId)
            : null;

    private static DateTimeOffset TransitionTime(
        SimplySignSessionSnapshot previous,
        DateTimeOffset now) =>
        now > previous.TransitionedAtUtc ? now : previous.TransitionedAtUtc.AddTicks(1);

    private static DateTimeOffset NormalizeNow(DateTimeOffset value) =>
        value == default ? DateTimeOffset.UnixEpoch : value.ToUniversalTime();

    private static string NormalizeSigningFailure(SimplySignSessionSnapshot snapshot) =>
        snapshot.ReasonCode switch
        {
            "token_missing" => "token_missing",
            "certificate_missing" => "certificate_missing",
            "private_key_missing" => "private_key_missing",
            _ => "simplysign_login_failed",
        };

    private static void ValidateTrigger(SessionTrigger trigger)
    {
        if (!Enum.IsDefined(trigger))
        {
            throw new ArgumentOutOfRangeException(nameof(trigger));
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
            _loginGate.Dispose();
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

    private sealed class StartupPreparation
    {
        public Task<SimplySignSessionSnapshot> Task { get; set; } = null!;
    }

    private sealed class ReadySignLease(
        SimplySignSessionManager owner,
        SimplySignSessionSnapshot snapshot,
        CertificateCatalogSnapshot catalogSnapshot,
        ISigningOperationLease operationLease,
        CancellationTokenSource cancellation) : IReadySignLease
    {
        private SimplySignSessionManager? _owner = owner;
        private ISigningOperationLease? _operationLease = operationLease;
        private CancellationTokenSource? _cancellation = cancellation;

        public SimplySignSessionSnapshot Snapshot { get; } = snapshot;

        public CertificateCatalogSnapshot CatalogSnapshot { get; } = catalogSnapshot;

        public CancellationToken CancellationToken =>
            _operationLease?.CancellationToken ?? throw new ObjectDisposedException(nameof(ReadySignLease));

        public Task<T> RunAsync<T>(Func<CancellationToken, Task<T>> operation)
        {
            ArgumentNullException.ThrowIfNull(operation);
            return operation(CancellationToken);
        }

        public async ValueTask DisposeAsync()
        {
            var owner = Interlocked.Exchange(ref _owner, null);
            var operationLease = Interlocked.Exchange(ref _operationLease, null);
            var cancellation = Interlocked.Exchange(ref _cancellation, null);
            if (owner is not null)
            {
                await operationLease!.DisposeAsync().ConfigureAwait(false);
                cancellation!.Dispose();
                owner.EndOperation();
            }
        }
    }
}
