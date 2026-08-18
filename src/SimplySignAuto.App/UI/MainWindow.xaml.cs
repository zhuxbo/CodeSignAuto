#if SIMPLYSIGN_WPF
using System.ComponentModel;
using System.Windows;
using System.Windows.Threading;

namespace SimplySignAuto.App.UI;

public partial class MainWindow : Window, IWindowController
{
    private readonly WindowPlacementStore _placementStore;
    private ShellViewModel? _viewModel;
    private bool _allowClose;
    private bool _placementApplied;

    public MainWindow()
        : this(new WindowPlacementStore(
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SimplySignAuto",
                "window.json"),
            new WindowsScreenWorkAreaSource()))
    {
    }

    internal MainWindow(WindowPlacementStore placementStore)
    {
        InitializeComponent();
        _placementStore = placementStore ?? throw new ArgumentNullException(nameof(placementStore));
    }

    public void Initialize(ShellViewModel viewModel)
    {
        _viewModel = viewModel ?? throw new ArgumentNullException(nameof(viewModel));
        DataContext = viewModel;
    }

    public void ShowRestoreActivate() => InvokeOnDispatcher(() =>
    {
        EnsurePlacement();
        if (WindowState == WindowState.Minimized)
        {
            WindowState = WindowState.Normal;
        }

        if (!IsVisible)
        {
            Show();
        }

        Activate();
        Topmost = true;
        Topmost = false;
        Focus();
    });

    public new void Hide() => InvokeOnDispatcher(() =>
    {
        SavePlacementSafely();
        base.Hide();
    });

    public void CloseForExit() => InvokeOnDispatcher(() =>
    {
        _allowClose = true;
        SavePlacementSafely();
        Close();
        System.Windows.Application.Current?.Shutdown();
    });

    public void ShowNotice(string message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(message);
        InvokeOnDispatcher(() => System.Windows.MessageBox.Show(
            this,
            message,
            "SimplySign Auto",
            System.Windows.MessageBoxButton.OK,
            System.Windows.MessageBoxImage.Information));
    }

    public bool ConfirmRelogin() => Dispatcher.CheckAccess()
        ? ShowReloginConfirmation()
        : Dispatcher.Invoke(ShowReloginConfirmation, DispatcherPriority.Send);

    public bool ConfirmClearOtp() => Dispatcher.CheckAccess()
        ? ShowClearOtpConfirmation()
        : Dispatcher.Invoke(ShowClearOtpConfirmation, DispatcherPriority.Send);

    public void PrepareForShutdown() => InvokeOnDispatcher(() => _allowClose = true);

    private void OnClosing(object? sender, CancelEventArgs args)
    {
        if (_allowClose)
        {
            SavePlacementSafely();
            return;
        }

        args.Cancel = true;
        _viewModel?.HandleCloseRequested(isSystemShutdown: false);
    }

    private void EnsurePlacement()
    {
        if (!_placementApplied)
        {
            var restored = _placementStore.LoadAsync(CancellationToken.None).GetAwaiter().GetResult();
            Apply(restored);
            _placementApplied = true;
            return;
        }

        var normalized = _placementStore.Normalize(new WindowPlacement(Left, Top, Width, Height));
        if (normalized.CenterOnScreen)
        {
            Apply(normalized);
        }
    }

    private void Apply(RestoredWindowPlacement restored)
    {
        Width = restored.Placement.Width;
        Height = restored.Placement.Height;
        if (restored.CenterOnScreen)
        {
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            return;
        }

        WindowStartupLocation = WindowStartupLocation.Manual;
        Left = restored.Placement.Left;
        Top = restored.Placement.Top;
    }

    private void SavePlacementSafely()
    {
        try
        {
            var bounds = WindowState == WindowState.Normal ? new Rect(Left, Top, Width, Height) : RestoreBounds;
            _placementStore.SaveAsync(
                new WindowPlacement(bounds.Left, bounds.Top, bounds.Width, bounds.Height),
                CancellationToken.None).GetAwaiter().GetResult();
        }
        catch (Exception error) when (
            error is IOException
                or UnauthorizedAccessException
                or InvalidOperationException
                or NotSupportedException)
        {
        }
    }

    private bool ShowReloginConfirmation() => System.Windows.MessageBox.Show(
        this,
        "检测到 SimplySign 正在其他 Windows 会话运行。将关闭该会话并在当前会话登录，是否继续？",
        "SimplySign Auto",
        System.Windows.MessageBoxButton.YesNo,
        System.Windows.MessageBoxImage.Warning) == System.Windows.MessageBoxResult.Yes;

    private bool ShowClearOtpConfirmation() => System.Windows.MessageBox.Show(
        this,
        "此操作会退出当前 SimplySign 登录并永久删除本机保存的 TOTP 激活内容。确定继续吗？",
        "SimplySign Auto",
        System.Windows.MessageBoxButton.YesNo,
        System.Windows.MessageBoxImage.Warning) == System.Windows.MessageBoxResult.Yes;

    private void InvokeOnDispatcher(Action action)
    {
        if (Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished)
        {
            return;
        }

        if (Dispatcher.CheckAccess())
        {
            action();
        }
        else
        {
            try
            {
                Dispatcher.Invoke(action, DispatcherPriority.Send);
            }
            catch (Exception error) when (
                (error is InvalidOperationException or TaskCanceledException) &&
                (Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished))
            {
            }
        }
    }
}

internal sealed class WindowsScreenWorkAreaSource : IScreenWorkAreaSource
{
    public IReadOnlyList<ScreenWorkArea> GetWorkAreas() =>
        System.Windows.Forms.Screen.AllScreens
            .Select(screen => new ScreenWorkArea(
                screen.WorkingArea.Left,
                screen.WorkingArea.Top,
                screen.WorkingArea.Width,
                screen.WorkingArea.Height))
            .ToArray();
}
#endif
