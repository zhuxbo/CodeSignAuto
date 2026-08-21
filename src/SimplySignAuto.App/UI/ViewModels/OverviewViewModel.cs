using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.App.UI;
using SimplySignAuto.App.UI.Localization;
using SimplySignAuto.App.UI.Status;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.App.UI.ViewModels;

public interface IReloginConfirmation
{
    Task<bool> ConfirmAsync(CancellationToken cancellationToken);
}

public sealed class OverviewViewModel : INotifyPropertyChanged, IDisposable
{
    private static readonly IReadOnlyDictionary<string, string> ReasonResourceKeys =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["not_configured"] = "ReasonNotConfigured",
            ["process_missing"] = "ReasonProcessMissing",
            ["process_session_mismatch"] = "ReasonProcessSessionMismatch",
            ["process_probe_failed"] = "ReasonProcessProbeFailed",
            ["token_missing"] = "ReasonTokenMissing",
            ["token_identifier_mismatch"] = "ReasonTokenIdentifierMismatch",
            ["certificate_missing"] = "ReasonCertificateMissing",
            ["certificate_identifier_mismatch"] = "ReasonCertificateIdentifierMismatch",
            ["not_yet_valid"] = "ReasonNotYetValid",
            ["expired"] = "ReasonExpired",
            ["private_key_ambiguous"] = "ReasonPrivateKeyAmbiguous",
            ["certificate_serial_ambiguous"] = "ReasonCertificateSerialAmbiguous",
            ["unsupported_purpose"] = "ReasonUnsupportedPurpose",
            ["catalog_stale"] = "ReasonCatalogStale",
            ["private_key_missing"] = "ReasonPrivateKeyMissing",
            ["private_key_identifier_mismatch"] = "ReasonPrivateKeyIdentifierMismatch",
            ["probe_output_invalid"] = "ReasonProbeOutputInvalid",
            ["probe_request_invalid"] = "ReasonProbeRequestInvalid",
            ["probe_request_cleanup_failed"] = "ReasonProbeRequestCleanupFailed",
            ["probe_token_unavailable"] = "ReasonProbeTokenUnavailable",
            ["probe_process_failed"] = "ReasonProbeProcessFailed",
            ["probe_failed"] = "ReasonProbeFailed",
            ["management_unavailable"] = "ReasonManagementUnavailable",
            ["service_unavailable"] = "ReasonServiceUnavailable",
            ["agent_unavailable"] = "ReasonAgentUnavailable",
            ["agent_session_invalid"] = "ReasonAgentSessionInvalid",
            ["heartbeat_missing"] = "ReasonHeartbeatMissing",
            ["heartbeat_invalid"] = "ReasonHeartbeatInvalid",
            ["heartbeat_stale"] = "ReasonHeartbeatStale",
        };

    private readonly IAgentManagementClient _management;
    private readonly IReloginConfirmation _confirmation;
    private readonly IUiDispatcher _dispatcher;
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private ManagementSnapshot? _snapshot;
    private OverallStatus? _status;
    private long _nextSnapshotVersion;
    private long _appliedSnapshotVersion;
    private int _refreshingOperations;
    private int _disposed;

    public OverviewViewModel(
        IAgentManagementClient management,
        IReloginConfirmation confirmation,
        Action openJobs,
        IUiDispatcher? dispatcher = null)
    {
        _management = management ?? throw new ArgumentNullException(nameof(management));
        _confirmation = confirmation ?? throw new ArgumentNullException(nameof(confirmation));
        _dispatcher = dispatcher ?? InlineUiDispatcher.Instance;
        ArgumentNullException.ThrowIfNull(openJobs);
        OpenJobsCommand = new DelegateCommand(openJobs);
        LoginCommand = new AsyncDelegateCommand(ExecuteLoginCommandAsync, () => CanLogin && !IsRefreshing);
        _management.SnapshotChanged += HandleSnapshotChanged;
        if (_management.LatestSnapshot is { } snapshot)
        {
            _ = ApplySnapshotAsync(snapshot);
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    internal IAgentManagementClient ManagementClient => _management;

    public ManagementSnapshot? Snapshot
    {
        get => _snapshot;
        private set
        {
            if (!Equals(_snapshot, value))
            {
                _snapshot = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(CanLogin));
                OnPropertyChanged(nameof(CanRelogin));
                OnPropertyChanged(nameof(IsLoggedIn));
                OnPropertyChanged(nameof(LoginButtonText));
                OnPropertyChanged(nameof(CurrentJob));
                OnPropertyChanged(nameof(RecentJobs));
                OnPropertyChanged(nameof(SimplySignStatusText));
                OnPropertyChanged(nameof(SimplySignStatusIcon));
                OnPropertyChanged(nameof(AuthenticodeStatusText));
                OnPropertyChanged(nameof(AuthenticodeStatusIcon));
                OnPropertyChanged(nameof(PdfStatusText));
                OnPropertyChanged(nameof(PdfStatusIcon));
                OnPropertyChanged(nameof(PdfExtensionVisible));
                OnPropertyChanged(nameof(QueueStatusText));
                OnPropertyChanged(nameof(CurrentJobText));
                OnPropertyChanged(nameof(ReasonMessages));
                OnPropertyChanged(nameof(CorrelationText));
                OnPropertyChanged(nameof(HasDiagnostics));
                RaiseCommandStates();
            }
        }
    }

    public OverallStatus? Status
    {
        get => _status;
        private set
        {
            if (!Equals(_status, value))
            {
                _status = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(ReasonMessages));
                OnPropertyChanged(nameof(CorrelationText));
                OnPropertyChanged(nameof(HasDiagnostics));
                OnPropertyChanged(nameof(AuthenticodeStatusText));
                OnPropertyChanged(nameof(AuthenticodeStatusIcon));
                OnPropertyChanged(nameof(PdfStatusText));
                OnPropertyChanged(nameof(PdfStatusIcon));
            }
        }
    }

    public bool IsRefreshing => Volatile.Read(ref _refreshingOperations) != 0;

    public bool CanRelogin => Snapshot is { ActiveJobCount: 0, CurrentJob: null };

    public bool CanLogin => Snapshot is null || CanRelogin;

    public bool IsLoggedIn => Snapshot is not null && IsLoginReady(Snapshot);

    public string LoginButtonText => IsLoggedIn
        ? UiCulture.Text("OverviewLogout")
        : UiCulture.Text("OverviewLogin");

    public CurrentJobSnapshot? CurrentJob => Snapshot?.CurrentJob;

    public IReadOnlyList<RecentJobSnapshot> RecentJobs => Snapshot?.RecentJobs ?? [];

    public ICommand OpenJobsCommand { get; }

    public ICommand LoginCommand { get; }

    public string SimplySignStatusText => Snapshot switch
    {
        null => UiCulture.Text("OverallNotChecked"),
        { SimplySignProcessRunning: true, SimplySignProcessSessionId: not null } snapshot
            when snapshot.SimplySignProcessSessionId == snapshot.AgentSessionId =>
                UiCulture.Format("OverviewProcessRunning", snapshot.AgentSessionId),
        _ => UiCulture.Text("OverviewProcessNotRunning"),
    };

    public string SimplySignStatusIcon => Snapshot is
    {
        SimplySignProcessRunning: true,
        SimplySignProcessSessionId: not null
    } snapshot &&
        snapshot.SimplySignProcessSessionId == snapshot.AgentSessionId
        ? "✓"
        : Snapshot is null ? "○" : "×";

    public string AuthenticodeStatusText => CapabilityText(_status?.AuthenticodeReady == true);

    public string AuthenticodeStatusIcon => CapabilityIcon(_status?.AuthenticodeReady == true);

    public string PdfStatusText => CapabilityText(_status?.PdfReady == true);

    public string PdfStatusIcon => CapabilityIcon(_status?.PdfReady == true);

    public bool PdfExtensionVisible => Snapshot?.Pdf is { Configured: true } pdf &&
        !string.Equals(
            pdf.ReasonCode,
            "pdf_support_not_installed",
            StringComparison.Ordinal);

    public string QueueStatusText => Snapshot is null
        ? UiCulture.Text("OverviewQueueNotChecked")
        : UiCulture.Format("OverviewQueueStatus", Snapshot.QueuedJobCount, Snapshot.ActiveJobCount);

    public string CurrentJobText => Snapshot?.CurrentJob is { } job
        ? UiCulture.Format("OverviewCurrentJob", JobKindText(job.Kind), JobStageText(job.Stage), job.ElapsedSeconds)
        : UiCulture.Text("OverviewNoCurrentJob");

    public IReadOnlyList<string> ReasonMessages =>
        Status?.Reasons
            .Where(reason => Snapshot?.SimplySignProcessRunning == true ||
                !string.Equals(reason, "certificate_missing", StringComparison.Ordinal))
            .Select(MapReason)
            .ToArray() ?? [];

    public string CorrelationText => Status?.CorrelationId is { } correlation
        ? UiCulture.Format("CorrelationFormat", correlation.ToString("D", UiCulture.Current))
        : string.Empty;

    public bool HasDiagnostics => ReasonMessages.Count > 0 || CorrelationText.Length > 0;

    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        await InvokeUiAsync(BeginRefreshing).ConfigureAwait(false);
        try
        {
            await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await ApplySnapshotAsync(
                    await _management.RefreshAsync(cancellationToken).ConfigureAwait(false))
                    .ConfigureAwait(false);
            }
            catch (ManagementUnavailableException unavailable)
            {
                await ApplyUnavailableAsync(unavailable.CorrelationId).ConfigureAwait(false);
            }
            finally
            {
                _operationGate.Release();
            }
        }
        finally
        {
            await InvokeUiAsync(EndRefreshing).ConfigureAwait(false);
        }
    }

    public async Task<bool> ReloginAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (!CanRelogin || !await _confirmation.ConfirmAsync(cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        await InvokeUiAsync(BeginRefreshing).ConfigureAwait(false);
        try
        {
            await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (!await ReadCanReloginAsync().ConfigureAwait(false))
                {
                    return false;
                }

                await ApplySnapshotAsync(
                    await _management.ReloginAsync(cancellationToken).ConfigureAwait(false))
                    .ConfigureAwait(false);
                return true;
            }
            catch (ManagementUnavailableException unavailable)
            {
                await ApplyUnavailableAsync(unavailable.CorrelationId).ConfigureAwait(false);
                return false;
            }
            finally
            {
                _operationGate.Release();
            }
        }
        finally
        {
            await InvokeUiAsync(EndRefreshing).ConfigureAwait(false);
        }
    }

    public async Task<bool> LoginAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (!CanLogin)
        {
            return false;
        }

        await InvokeUiAsync(BeginRefreshing).ConfigureAwait(false);
        try
        {
            await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var refreshed = await _management.RefreshAsync(cancellationToken).ConfigureAwait(false);
                await ApplySnapshotAsync(refreshed).ConfigureAwait(false);
                if (IsLoginReady(refreshed))
                {
                    return true;
                }

                if (!await ReadCanReloginAsync().ConfigureAwait(false) ||
                    (NeedsCleanupConfirmation(refreshed) &&
                        !await _confirmation.ConfirmAsync(cancellationToken).ConfigureAwait(false)) ||
                    !await ReadCanReloginAsync().ConfigureAwait(false))
                {
                    return false;
                }

                var loggedIn = await _management.ReloginAsync(cancellationToken).ConfigureAwait(false);
                await ApplySnapshotAsync(loggedIn).ConfigureAwait(false);
                return IsLoginReady(loggedIn);
            }
            catch (ManagementUnavailableException unavailable)
            {
                await ApplyUnavailableAsync(unavailable.CorrelationId).ConfigureAwait(false);
                return false;
            }
            finally
            {
                _operationGate.Release();
            }
        }
        finally
        {
            await InvokeUiAsync(EndRefreshing).ConfigureAwait(false);
        }
    }

    public async Task<bool> LogoutAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (!IsLoggedIn || !CanRelogin)
        {
            return false;
        }

        await InvokeUiAsync(BeginRefreshing).ConfigureAwait(false);
        try
        {
            await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (!await ReadCanReloginAsync().ConfigureAwait(false) || !IsLoggedIn)
                {
                    return false;
                }

                var loggedOut = await _management.LogoutAsync(cancellationToken).ConfigureAwait(false);
                await ApplySnapshotAsync(loggedOut).ConfigureAwait(false);
                return !IsLoginReady(loggedOut);
            }
            catch (ManagementUnavailableException unavailable)
            {
                await ApplyUnavailableAsync(unavailable.CorrelationId).ConfigureAwait(false);
                return false;
            }
            finally
            {
                _operationGate.Release();
            }
        }
        finally
        {
            await InvokeUiAsync(EndRefreshing).ConfigureAwait(false);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _management.SnapshotChanged -= HandleSnapshotChanged;
        _lifetime.Cancel();
    }

    private void HandleSnapshotChanged(object? sender, EventArgs eventArgs)
    {
        var latest = _management.LatestSnapshot;
        _ = ApplySnapshotAsync(latest);
    }

    private Task ApplySnapshotAsync(ManagementSnapshot? snapshot)
    {
        var version = Interlocked.Increment(ref _nextSnapshotVersion);
        return InvokeUiAsync(() =>
        {
            if (version < _appliedSnapshotVersion)
            {
                return;
            }

            _appliedSnapshotVersion = version;
            Snapshot = snapshot;
            Status = snapshot is null ? null : ReadinessStatusMapper.Map(snapshot);
        });
    }

    private Task ApplyUnavailableAsync(Guid correlationId)
    {
        var version = Interlocked.Increment(ref _nextSnapshotVersion);
        return InvokeUiAsync(() =>
        {
            if (version < _appliedSnapshotVersion)
            {
                return;
            }

            _appliedSnapshotVersion = version;
            Snapshot = null;
            Status = ReadinessStatusMapper.ServiceUnavailable(correlationId);
        });
    }

    private async Task<bool> ReadCanReloginAsync()
    {
        var result = false;
        await InvokeUiAsync(() => result = CanRelogin).ConfigureAwait(false);
        return result;
    }

    private async Task InvokeUiAsync(Action action)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        try
        {
            await _dispatcher.InvokeAsync(() =>
            {
                if (Volatile.Read(ref _disposed) == 0)
                {
                    action();
                }
            }, _lifetime.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
        }
        catch (ObjectDisposedException) when (Volatile.Read(ref _disposed) != 0)
        {
        }
        catch (InvalidOperationException) when (Volatile.Read(ref _disposed) != 0)
        {
        }
    }

    private void BeginRefreshing()
    {
        if (Interlocked.Increment(ref _refreshingOperations) == 1)
        {
            OnPropertyChanged(nameof(IsRefreshing));
            RaiseCommandStates();
        }
    }

    private void EndRefreshing()
    {
        if (Interlocked.Decrement(ref _refreshingOperations) == 0)
        {
            OnPropertyChanged(nameof(IsRefreshing));
            RaiseCommandStates();
        }
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    private async Task ExecuteLoginCommandAsync()
    {
        try
        {
            if (IsLoggedIn)
            {
                await LogoutAsync(CancellationToken.None).ConfigureAwait(false);
            }
            else
            {
                await LoginAsync(CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            await ApplyUnavailableAsync(Guid.NewGuid()).ConfigureAwait(false);
        }
    }

    private void RaiseCommandStates()
    {
        ((AsyncDelegateCommand)LoginCommand).RaiseCanExecuteChanged();
    }

    private static bool IsLoginReady(ManagementSnapshot snapshot) =>
        snapshot.SimplySignProcessRunning &&
        snapshot.SimplySignProcessSessionId == snapshot.AgentSessionId &&
        (ReadinessStatusMapper.IsCurrentReady(snapshot.SessionGeneration, snapshot.Authenticode) ||
            ReadinessStatusMapper.IsCurrentReady(snapshot.SessionGeneration, snapshot.Pdf));

    private static bool NeedsCleanupConfirmation(ManagementSnapshot snapshot) =>
        snapshot.SimplySignProcessRunning &&
        snapshot.SimplySignProcessSessionId != snapshot.AgentSessionId;

    private string CapabilityText(bool ready) => Snapshot is null
        ? UiCulture.Text("OverallNotChecked")
        : ready ? UiCulture.Text("SessionReady") : UiCulture.Text("StatusUnavailable");

    private string CapabilityIcon(bool ready) => Snapshot is null ? "○" : ready ? "✓" : "×";

    private static string MapReason(string reason) =>
        ReasonResourceKeys.TryGetValue(reason, out var key)
            ? UiCulture.Text(key)
            : UiCulture.Text("ReasonInternalUnavailable");

    private static string JobKindText(string kind) => kind switch
    {
        "authenticode" => UiCulture.Text("AuthenticodeTitle"),
        "pdf" => UiCulture.Text("PdfSigningTitle"),
        _ => UiCulture.Text("JobKindGeneric"),
    };

    private static string JobStageText(string stage) => stage switch
    {
        "waiting_for_agent" => UiCulture.Text("JobStageWaitingForAgent"),
        "signing" => UiCulture.Text("JobStageSigning"),
        "verifying" => UiCulture.Text("JobStageVerifying"),
        _ => UiCulture.Text("JobStageProcessing"),
    };

    private sealed class DelegateCommand(Action execute) : ICommand
    {
        public event EventHandler? CanExecuteChanged { add { } remove { } }

        public bool CanExecute(object? parameter) => true;

        public void Execute(object? parameter) => execute();
    }

    private sealed class AsyncDelegateCommand(
        Func<Task> execute,
        Func<bool> canExecute) : ICommand
    {
        public event EventHandler? CanExecuteChanged;

        public bool CanExecute(object? parameter) => canExecute();

        public async void Execute(object? parameter) => await execute().ConfigureAwait(false);

        public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
    }

    private sealed class InlineUiDispatcher : IUiDispatcher
    {
        public static InlineUiDispatcher Instance { get; } = new();

        public Task InvokeAsync(Action action, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            action();
            return Task.CompletedTask;
        }
    }
}
