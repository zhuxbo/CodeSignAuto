namespace CodeSignAuto.App.UI;

using System.ComponentModel;
using CodeSignAuto.App.UI.Localization;
using CodeSignAuto.App.UI.Status;
using CodeSignAuto.App.UI.ViewModels;

public enum TrayCommand
{
    OpenConsole,
    CurrentStatus,
    Recheck,
    OpenRecentJobs,
    Exit,
}

public sealed record TrayMenuEntry(TrayCommand Command, string Text, bool Enabled = true);

public sealed class TrayCommandEventArgs(TrayCommand command) : EventArgs
{
    public TrayCommand Command { get; } = command;
}

public interface ITrayIconPlatform : IDisposable
{
    event EventHandler<TrayCommandEventArgs>? CommandInvoked;

    void Initialize(IReadOnlyList<TrayMenuEntry> entries, string statusText);

    void SetStatus(string statusText);

    void ShowNotification(TrayNotification notification)
    {
    }
}

public sealed class TrayIconController : IDisposable
{
    private static readonly IReadOnlyList<TrayMenuEntry> FixedEntries =
    [
        new(TrayCommand.OpenConsole, UiCulture.Text("TrayOpenConsole")),
        new(TrayCommand.Exit, UiCulture.Text("TrayExit")),
    ];

    private readonly ITrayIconPlatform _platform;
    private readonly ShellViewModel _viewModel;
    private readonly IWindowController _window;
    private readonly IUiDispatcher _dispatcher;
    private readonly NotificationPolicy _notificationPolicy;
    private readonly object _notificationSync = new();
    private readonly CancellationTokenSource _lifetime = new();
    private Task? _notificationUpdateTask;
    private bool _notificationUpdatePending;
    private OverallStatus? _lastNotificationStatus;
    private int _disposed;

    public TrayIconController(
        ITrayIconPlatform platform,
        ShellViewModel viewModel,
        IWindowController window,
        IUiDispatcher? dispatcher = null,
        NotificationPolicy? notificationPolicy = null)
    {
        _platform = platform ?? throw new ArgumentNullException(nameof(platform));
        _viewModel = viewModel ?? throw new ArgumentNullException(nameof(viewModel));
        _window = window ?? throw new ArgumentNullException(nameof(window));
        _dispatcher = dispatcher ?? InlineAppUiDispatcher.Instance;
        _notificationPolicy = notificationPolicy ?? new NotificationPolicy();
        _platform.CommandInvoked += HandlePlatformCommand;
        _viewModel.PropertyChanged += HandleViewModelPropertyChanged;
        if (_viewModel.TerminalJobs is not null)
        {
            _viewModel.TerminalJobs.ItemsChanged += HandleTerminalItemsChanged;
        }
        try
        {
            _platform.Initialize(FixedEntries, $"{_viewModel.OverallStatusIcon} {_viewModel.OverallStatusText}");
            EvaluateAndDisplayNotifications();
        }
        catch
        {
            _platform.CommandInvoked -= HandlePlatformCommand;
            _viewModel.PropertyChanged -= HandleViewModelPropertyChanged;
            if (_viewModel.TerminalJobs is not null)
            {
                _viewModel.TerminalJobs.ItemsChanged -= HandleTerminalItemsChanged;
            }
            _platform.Dispose();
            throw;
        }
    }

    public async Task HandleCommandAsync(TrayCommand command, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        switch (command)
        {
            case TrayCommand.OpenConsole:
                await InvokeUiAsync(_window.ShowRestoreActivate, cancellationToken).ConfigureAwait(false);
                break;
            case TrayCommand.CurrentStatus:
                await InvokeUiAsync(
                    () => _window.ShowNotice(
                        UiCulture.Format(
                            "TrayCurrentStatus",
                            _viewModel.OverallStatusIcon,
                            _viewModel.OverallStatusText)),
                    cancellationToken).ConfigureAwait(false);
                break;
            case TrayCommand.Recheck:
                if (_viewModel.Overview is null)
                {
                    await InvokeUiAsync(
                        () => _window.ShowNotice(UiCulture.Text("TrayStatusPending")),
                        cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await _viewModel.Overview.RefreshAsync(cancellationToken).ConfigureAwait(false);
                }
                break;
            case TrayCommand.OpenRecentJobs:
                if (_viewModel.Overview is null)
                {
                    await InvokeUiAsync(
                        () => _window.ShowNotice(UiCulture.Text("TrayRecentJobsPending")),
                        cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await InvokeUiAsync(() =>
                    {
                        _viewModel.Overview.OpenJobsCommand.Execute(null);
                        _window.ShowRestoreActivate();
                    }, cancellationToken).ConfigureAwait(false);
                }
                break;
            case TrayCommand.Exit:
                await _viewModel.RequestExitAsync(cancellationToken).ConfigureAwait(false);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(command));
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _platform.CommandInvoked -= HandlePlatformCommand;
        _viewModel.PropertyChanged -= HandleViewModelPropertyChanged;
        if (_viewModel.TerminalJobs is not null)
        {
            _viewModel.TerminalJobs.ItemsChanged -= HandleTerminalItemsChanged;
        }
        _lifetime.Cancel();
        _platform.Dispose();
    }

    private void HandleViewModelPropertyChanged(object? sender, PropertyChangedEventArgs eventArgs)
    {
        if (eventArgs.PropertyName is nameof(ShellViewModel.OverallStatusText)
            or nameof(ShellViewModel.OverallStatusIcon)
            or null)
        {
            _ = UpdateStatusAsync();
            ScheduleNotificationUpdate();
        }
    }

    private void HandleTerminalItemsChanged(object? sender, EventArgs eventArgs)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        try
        {
            // Backpressure the bounded feed until this page has been consumed. Otherwise a
            // stalled dispatcher could coalesce more than ten pages and evict unseen events.
            InvokeUiAsync(EvaluateAndDisplayNotifications, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
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

    private async void HandlePlatformCommand(object? sender, TrayCommandEventArgs args)
    {
        try
        {
            await HandleCommandAsync(args.Command, CancellationToken.None).ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
        }
        catch (Exception)
        {
            await InvokeUiAsync(
                () => _window.ShowNotice(UiCulture.Text("TrayCommandFailed")),
                CancellationToken.None).ConfigureAwait(false);
        }
    }

    private Task UpdateStatusAsync() => InvokeUiAsync(
        () => _platform.SetStatus($"{_viewModel.OverallStatusIcon} {_viewModel.OverallStatusText}"),
        CancellationToken.None);

    private void ScheduleNotificationUpdate()
    {
        lock (_notificationSync)
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                return;
            }

            _notificationUpdatePending = true;
            if (_notificationUpdateTask is null or { IsCompleted: true })
            {
                _notificationUpdateTask = DrainNotificationUpdatesAsync();
            }
        }
    }

    private async Task DrainNotificationUpdatesAsync()
    {
        while (true)
        {
            lock (_notificationSync)
            {
                if (!_notificationUpdatePending || Volatile.Read(ref _disposed) != 0)
                {
                    return;
                }

                _notificationUpdatePending = false;
            }

            await InvokeUiAsync(EvaluateAndDisplayNotifications, CancellationToken.None).ConfigureAwait(false);
        }
    }

    private void EvaluateAndDisplayNotifications()
    {
        var current = _viewModel.Overview?.Status;
        if (current is null)
        {
            return;
        }

        IReadOnlyList<CodeSignAuto.Protocol.TerminalJobEventItem>? terminalJobs =
            _viewModel.TerminalJobs is { HasCompletedInitialPoll: true } feed
                ? feed.Items
                : null;
        var notifications = _notificationPolicy.Evaluate(
            _lastNotificationStatus,
            current,
            terminalJobs);
        _lastNotificationStatus = current;
        foreach (var notification in notifications)
        {
            _platform.ShowNotification(notification);
        }
    }

    private async Task InvokeUiAsync(Action action, CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _lifetime.Token);
        try
        {
            await _dispatcher.InvokeAsync(() =>
            {
                if (Volatile.Read(ref _disposed) == 0)
                {
                    action();
                }
            }, linked.Token).ConfigureAwait(false);
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
}

#if CODESIGNAUTO_WPF
internal sealed class WindowsNotifyIconPlatform : ITrayIconPlatform
{
    private readonly string? _uiTestIdentity;
    private readonly List<System.Windows.Forms.ToolStripMenuItem> _items = [];
    private System.IO.Stream? _iconStream;
    private System.Drawing.Icon? _icon;
    private System.Windows.Forms.ContextMenuStrip? _menu;
    private System.Windows.Forms.NotifyIcon? _notifyIcon;
    private bool _initialized;
    private bool _disposed;

    public WindowsNotifyIconPlatform(string? uiTestIdentity = null)
    {
        if (uiTestIdentity is not null && !Testing.UiTestTrayIdentity.IsValid(uiTestIdentity))
        {
            throw new ArgumentException("ui_test_tray_identity_invalid", nameof(uiTestIdentity));
        }

        _uiTestIdentity = uiTestIdentity;
    }

    public event EventHandler<TrayCommandEventArgs>? CommandInvoked;

    public void Initialize(IReadOnlyList<TrayMenuEntry> entries, string statusText)
    {
        ArgumentNullException.ThrowIfNull(entries);
        if (_disposed || _initialized)
        {
            throw new InvalidOperationException("tray_lifecycle_invalid");
        }

        try
        {
            var resource = System.Windows.Application.GetResourceStream(
                new Uri("pack://application:,,,/CodeSignAuto;component/UI/Resources/app.ico", UriKind.Absolute))
                ?? throw new InvalidOperationException("tray_icon_missing");
            _iconStream = resource.Stream;
            _icon = new System.Drawing.Icon(_iconStream);
            _menu = new System.Windows.Forms.ContextMenuStrip();
            foreach (var entry in entries)
            {
                var item = new System.Windows.Forms.ToolStripMenuItem(entry.Text)
                {
                    Enabled = entry.Enabled,
                    Tag = entry.Command,
                };
                item.Click += HandleMenuClick;
                _items.Add(item);
                _menu.Items.Add(item);
            }

            _notifyIcon = new System.Windows.Forms.NotifyIcon
            {
                ContextMenuStrip = _menu,
                Icon = _icon,
                Visible = true,
            };
            _notifyIcon.DoubleClick += HandleDoubleClick;
            SetStatus(statusText);
            _initialized = true;
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    public void SetStatus(string statusText)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statusText);
        if (_notifyIcon is null)
        {
            return;
        }

        var text = _uiTestIdentity ?? $"CodeSignAuto - {statusText}";
        _notifyIcon.Text = text[..Math.Min(text.Length, 63)];
    }

    public void ShowNotification(TrayNotification notification)
    {
        ArgumentNullException.ThrowIfNull(notification);
        if (_notifyIcon is null)
        {
            return;
        }

        _notifyIcon.ShowBalloonTip(
            5_000,
            notification.Title,
            notification.Message,
            notification.Kind == TrayNotificationKind.LocalJobSucceeded
                ? System.Windows.Forms.ToolTipIcon.Info
                : System.Windows.Forms.ToolTipIcon.Warning);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_notifyIcon is not null)
        {
            _notifyIcon.DoubleClick -= HandleDoubleClick;
            _notifyIcon.Visible = false;
            _notifyIcon.Dispose();
            _notifyIcon = null;
        }

        foreach (var item in _items)
        {
            item.Click -= HandleMenuClick;
            item.Dispose();
        }

        _items.Clear();
        _menu?.Dispose();
        _menu = null;
        _icon?.Dispose();
        _icon = null;
        _iconStream?.Dispose();
        _iconStream = null;
    }

    private void HandleMenuClick(object? sender, EventArgs args)
    {
        if (sender is System.Windows.Forms.ToolStripMenuItem { Tag: TrayCommand command })
        {
            CommandInvoked?.Invoke(this, new TrayCommandEventArgs(command));
        }
    }

    private void HandleDoubleClick(object? sender, EventArgs args) =>
        CommandInvoked?.Invoke(this, new TrayCommandEventArgs(TrayCommand.OpenConsole));
}
#endif
