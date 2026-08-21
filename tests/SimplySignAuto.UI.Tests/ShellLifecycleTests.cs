using SimplySignAuto.App.UI;

namespace SimplySignAuto.UI.Tests;

public sealed class ShellLifecycleTests
{
    [Fact]
    public void Shell_exposes_the_fixed_navigation_order_and_safe_placeholder_status()
    {
        var window = new RecordingWindow();
        var viewModel = new ShellViewModel(
            new FixedActiveJobState(ActiveJobState.Unknown),
            window,
            new RecordingAgentLifetime());

        Assert.Equal(
            ["概览", "快速签名", "签名任务", "激活凭证", "服务设置"],
            viewModel.Pages.Take(5).Select(page => page.Title).ToArray());
        Assert.Equal(viewModel.ApplicationSettings.PageTitle, viewModel.Pages[5].Title);
        Assert.Same(viewModel.ApplicationSettings, viewModel.Pages[5].Content);
        Assert.Equal("尚未检查", viewModel.OverallStatusText);
    }

    [Fact]
    public void Manual_shell_uses_the_fixed_five_page_set_without_service_settings()
    {
        var viewModel = new ShellViewModel(
            new FixedActiveJobState(ActiveJobState.None),
            new RecordingWindow(),
            new RecordingAgentLifetime(),
            dispatcher: null,
            mode: SimplySignAuto.App.Commands.InstallationMode.Manual);

        Assert.Equal(
            ["概览", "手工签名", "签名任务", "激活凭证", "应用设置"],
            viewModel.Pages.Select(page => page.Title).ToArray());
        Assert.DoesNotContain(viewModel.Pages, page => page.Title == "服务设置");
    }

    [Fact]
    public void Ordinary_close_hides_the_window_and_keeps_the_agent_running()
    {
        var window = new RecordingWindow();
        var lifetime = new RecordingAgentLifetime();
        var viewModel = new ShellViewModel(
            new FixedActiveJobState(ActiveJobState.None),
            window,
            lifetime);

        var disposition = viewModel.HandleCloseRequested(isSystemShutdown: false);

        Assert.Equal(WindowCloseDisposition.Hide, disposition);
        Assert.False(window.IsVisible);
        Assert.False(lifetime.IsStopRequested);
    }

    [Theory]
    [InlineData(ActiveJobState.Active)]
    [InlineData(ActiveJobState.Unknown)]
    public async Task Admin_console_exit_is_allowed_without_stopping_background_work(
        ActiveJobState state)
    {
        var window = new RecordingWindow();
        var lifetime = new RecordingAgentLifetime();
        var viewModel = new ShellViewModel(new FixedActiveJobState(state), window, lifetime);

        var result = await viewModel.RequestExitAsync(CancellationToken.None);

        Assert.Equal(ExitRequestResult.Exiting, result);
        Assert.Null(window.LastNotice);
        Assert.False(lifetime.IsStopRequested);
    }

    [Fact]
    public async Task Concurrent_exit_requests_close_the_console_once_without_stopping_the_agent()
    {
        var window = new RecordingWindow();
        var lifetime = new RecordingAgentLifetime();
        var viewModel = new ShellViewModel(
            new FixedActiveJobState(ActiveJobState.None),
            window,
            lifetime);

        var results = await Task.WhenAll(
            viewModel.RequestExitAsync(CancellationToken.None),
            viewModel.RequestExitAsync(CancellationToken.None));

        Assert.All(results, result => Assert.Equal(ExitRequestResult.Exiting, result));
        Assert.Equal(0, lifetime.StopCalls);
        Assert.Equal(1, window.CloseForExitCalls);
    }

    [Fact]
    public async Task Manual_exit_refuses_an_active_job_without_stopping_or_closing()
    {
        var window = new RecordingWindow();
        var lifetime = new RecordingAgentLifetime();
        var viewModel = new ShellViewModel(
            new FixedActiveJobState(ActiveJobState.Active),
            window,
            lifetime,
            dispatcher: null,
            mode: SimplySignAuto.App.Commands.InstallationMode.Manual);

        var result = await viewModel.RequestExitAsync(CancellationToken.None);

        Assert.Equal(ExitRequestResult.Refused, result);
        Assert.Equal("签名任务正在进行，完成后才能退出程序。", window.LastNotice);
        Assert.Equal(0, lifetime.StopCalls);
        Assert.Equal(0, window.CloseForExitCalls);
    }

    [Fact]
    public async Task Manual_exit_stops_the_owned_runtime_before_closing_once()
    {
        var window = new RecordingWindow();
        var lifetime = new RecordingAgentLifetime();
        var viewModel = new ShellViewModel(
            new FixedActiveJobState(ActiveJobState.None),
            window,
            lifetime,
            dispatcher: null,
            mode: SimplySignAuto.App.Commands.InstallationMode.Manual);

        var results = await Task.WhenAll(
            viewModel.RequestExitAsync(CancellationToken.None),
            viewModel.RequestExitAsync(CancellationToken.None));

        Assert.All(results, result => Assert.Equal(ExitRequestResult.Exiting, result));
        Assert.Equal(1, lifetime.StopCalls);
        Assert.Equal(1, window.CloseForExitCalls);
    }

    [Fact]
    public async Task Worker_stop_completion_closes_the_window_only_inside_the_ui_dispatcher()
    {
        var dispatcher = new GuardedDispatcher();
        var window = new RecordingWindow(dispatcher);
        using var viewModel = new ShellViewModel(
            new FixedActiveJobState(ActiveJobState.None),
            window,
            new RecordingAgentLifetime(),
            dispatcher);

        Assert.Equal(
            ExitRequestResult.Exiting,
            await viewModel.RequestExitAsync(CancellationToken.None));

        Assert.True(window.CloseWasDispatched);
    }

    [Fact]
    public void System_shutdown_is_not_converted_to_hide()
    {
        var viewModel = new ShellViewModel(
            new FixedActiveJobState(ActiveJobState.Active),
            new RecordingWindow(),
            new RecordingAgentLifetime());

        Assert.Equal(
            WindowCloseDisposition.AllowSystemShutdown,
            viewModel.HandleCloseRequested(isSystemShutdown: true));
    }

    private sealed class FixedActiveJobState(ActiveJobState state) : IActiveJobStateSource
    {
        public ActiveJobState Current => state;
    }

    private sealed class RecordingAgentLifetime : IDesktopAgentLifetime
    {
        private int _stopCalls;

        public bool IsStopRequested => Volatile.Read(ref _stopCalls) > 0;

        public int StopCalls => Volatile.Read(ref _stopCalls);

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _stopCalls);
            await Task.Yield();
            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    private sealed class RecordingWindow(GuardedDispatcher? dispatcher = null) : IWindowController
    {
        public bool IsVisible { get; private set; } = true;

        public int CloseForExitCalls { get; private set; }

        public string? LastNotice { get; private set; }

        public bool CloseWasDispatched { get; private set; }

        public void ShowRestoreActivate() => IsVisible = true;

        public void Hide() => IsVisible = false;

        public void CloseForExit()
        {
            CloseWasDispatched = dispatcher?.IsDispatching ?? true;
            CloseForExitCalls++;
            IsVisible = false;
        }

        public void ShowNotice(string message) => LastNotice = message;
    }

    private sealed class GuardedDispatcher : IUiDispatcher
    {
        private readonly AsyncLocal<int> _depth = new();

        public bool IsDispatching => _depth.Value > 0;

        public Task InvokeAsync(Action action, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _depth.Value++;
            try
            {
                action();
            }
            finally
            {
                _depth.Value--;
            }

            return Task.CompletedTask;
        }
    }
}
