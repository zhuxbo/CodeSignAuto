using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.App.UI;
using SimplySignAuto.App.UI.Status;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.App.UI.ViewModels;

public interface IReloginConfirmation
{
    Task<bool> ConfirmAsync(CancellationToken cancellationToken);
}

public sealed class OverviewViewModel : INotifyPropertyChanged, IDisposable
{
    private static readonly IReadOnlyDictionary<string, string> ReasonText =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["not_configured"] = "未配置",
            ["process_missing"] = "SimplySign 未运行",
            ["process_session_mismatch"] = "SimplySign 不在当前登录会话",
            ["process_probe_failed"] = "无法检查 SimplySign 进程",
            ["token_missing"] = "未找到令牌",
            ["token_identifier_mismatch"] = "令牌标识不匹配",
            ["certificate_missing"] = "未找到证书",
            ["certificate_identifier_mismatch"] = "证书标识不匹配",
            ["not_yet_valid"] = "证书尚未生效",
            ["expired"] = "证书已过期",
            ["private_key_ambiguous"] = "证书私钥不唯一",
            ["certificate_serial_ambiguous"] = "证书序列号不唯一",
            ["unsupported_purpose"] = "证书不支持该签名用途",
            ["catalog_stale"] = "证书目录已失效",
            ["private_key_missing"] = "未找到私钥",
            ["private_key_identifier_mismatch"] = "私钥标识不匹配",
            ["probe_output_invalid"] = "签名能力检查结果无效",
            ["probe_request_invalid"] = "签名能力检查请求无效",
            ["probe_request_cleanup_failed"] = "签名能力检查清理失败",
            ["probe_token_unavailable"] = "签名令牌不可用",
            ["probe_process_failed"] = "签名能力检查进程失败",
            ["probe_failed"] = "签名能力检查失败",
            ["management_unavailable"] = "管理通道不可用",
            ["service_unavailable"] = "本机签名服务不可用",
            ["agent_unavailable"] = "签名代理未连接",
            ["agent_session_invalid"] = "签名代理会话无效",
            ["heartbeat_missing"] = "尚未收到代理状态",
            ["heartbeat_invalid"] = "代理状态与当前会话不一致",
            ["heartbeat_stale"] = "代理状态已过期",
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

    public string LoginButtonText => IsLoggedIn ? "退出" : "登录";

    public CurrentJobSnapshot? CurrentJob => Snapshot?.CurrentJob;

    public IReadOnlyList<RecentJobSnapshot> RecentJobs => Snapshot?.RecentJobs ?? [];

    public ICommand OpenJobsCommand { get; }

    public ICommand LoginCommand { get; }

    public string SimplySignStatusText => Snapshot switch
    {
        null => "尚未检查",
        { SimplySignProcessRunning: true, SimplySignProcessSessionId: not null } snapshot
            when snapshot.SimplySignProcessSessionId == snapshot.AgentSessionId =>
                $"进程诊断：运行中（会话 {snapshot.AgentSessionId}）",
        _ => "进程诊断：未运行",
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
        ? "队列尚未检查"
        : $"排队 {Snapshot.QueuedJobCount} · 执行中 {Snapshot.ActiveJobCount}";

    public string CurrentJobText => Snapshot?.CurrentJob is { } job
        ? $"{JobKindText(job.Kind)} · {JobStageText(job.Stage)} · 已运行 {job.ElapsedSeconds} 秒"
        : "当前没有签名任务";

    public IReadOnlyList<string> ReasonMessages =>
        Status?.Reasons
            .Where(reason => Snapshot?.SimplySignProcessRunning == true ||
                !string.Equals(reason, "certificate_missing", StringComparison.Ordinal))
            .Select(MapReason)
            .ToArray() ?? [];

    public string CorrelationText => Status?.CorrelationId is { } correlation
        ? $"关联编号：{correlation:D}"
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

    private string CapabilityText(bool ready) => Snapshot is null ? "尚未检查" : ready ? "已就绪" : "不可用";

    private string CapabilityIcon(bool ready) => Snapshot is null ? "○" : ready ? "✓" : "×";

    private static string MapReason(string reason) =>
        ReasonText.TryGetValue(reason, out var text) ? text : "内部状态不可用";

    private static string JobKindText(string kind) => kind switch
    {
        "authenticode" => "代码签名",
        "pdf" => "PDF 文档签名",
        _ => "签名任务",
    };

    private static string JobStageText(string stage) => stage switch
    {
        "waiting_for_agent" => "等待签名代理",
        "signing" => "正在签名",
        "verifying" => "正在验证",
        _ => "处理中",
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
