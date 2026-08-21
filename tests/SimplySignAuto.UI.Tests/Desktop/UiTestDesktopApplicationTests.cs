using SimplySignAuto.App.UI;
using SimplySignAuto.App.UI.Testing;

namespace SimplySignAuto.UI.Tests.Desktop;

public sealed class UiTestDesktopApplicationTests
{
    [Fact]
    public async Task Test_application_uses_only_fake_composition_and_host_exit_stops_the_runtime()
    {
        var runtime = new RecordingRuntime();
        var host = new ControlledHostConnection();
        var runtimeFactory = new FixedRuntimeFactory(runtime);
        var application = new UiTestDesktopApplication(
            runtimeFactory,
            new FixedHostFactory(host));
        var options = CreateOptions("ready");
        var run = application.ExecuteAsync(options, CancellationToken.None);
        var viewModel = await runtime.Initialized.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(6, viewModel.Pages.Count);
        Assert.All(viewModel.Pages, page => Assert.NotNull(page.Content));
        Assert.Same(viewModel.Overview!.ManagementClient, viewModel.Activation!.ManagementClient);
        Assert.Same(viewModel.Jobs!.LocalJobClient, viewModel.QuickSign!.LocalJobsClient);
        Assert.IsType<UiTestServiceConfigurationEditor>(viewModel.ServiceSettings!.ConfigurationEditor);
        Assert.IsType<UiTestClipboardService>(viewModel.Activation.ClipboardService);
        Assert.Equal(UiTestTrayIdentity.Create(options.ProcessId, options.PipeName), runtimeFactory.TrayIdentity);

        host.RequestExit();

        Assert.Equal(0, await run.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(1, runtime.ShutdownRequests);
        Assert.Equal(1, runtime.DisposeCalls);
        Assert.Equal(1, host.DisposeCalls);
    }

    [Fact]
    public async Task Unknown_initial_refresh_maps_unavailable_and_still_enters_runtime_loop()
    {
        var runtime = new RecordingRuntime();
        var host = new ControlledHostConnection();
        var application = new UiTestDesktopApplication(
            new FixedRuntimeFactory(runtime),
            new FixedHostFactory(host));
        var run = application.ExecuteAsync(CreateOptions("unknown"), CancellationToken.None);
        var viewModel = await runtime.Initialized.Task.WaitAsync(TimeSpan.FromSeconds(5));

        await runtime.RunStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Null(viewModel.Overview!.Snapshot);
        Assert.Contains("本机签名服务不可用", viewModel.Overview.ReasonMessages);
        Assert.Equal("尚未检查", viewModel.Overview.SimplySignStatusText);
        host.RequestExit();
        Assert.Equal(0, await run.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    private static UiTestLaunchOptions CreateOptions(string stateCode)
    {
        Assert.True(UiTestState.TryParse(stateCode, out var state));
        return new UiTestLaunchOptions(
            state!,
            $"SSA.UI.{Guid.NewGuid():N}",
            Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)),
            Environment.ProcessId);
    }

    private sealed class FixedRuntimeFactory(IDesktopRuntime runtime) : IDesktopRuntimeFactory
    {
        public string? TrayIdentity { get; private set; }

        public IDesktopRuntime Create(string? uiTestTrayIdentity = null)
        {
            TrayIdentity = uiTestTrayIdentity;
            return runtime;
        }
    }

    private sealed class FixedHostFactory(IUiTestHostConnection connection) : IUiTestHostConnectionFactory
    {
        public Task<IUiTestHostConnection> ConnectAsync(
            UiTestLaunchOptions options,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(connection);
        }
    }

    private sealed class ControlledHostConnection : IUiTestHostConnection
    {
        private readonly TaskCompletionSource<bool> _exit =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int DisposeCalls { get; private set; }

        public Task<bool> WaitForExitRequestAsync(CancellationToken cancellationToken) =>
            _exit.Task.WaitAsync(cancellationToken);

        public void RequestExit() => _exit.TrySetResult(true);

        public ValueTask DisposeAsync()
        {
            DisposeCalls++;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class RecordingRuntime : IDesktopRuntime
    {
        private readonly TaskCompletionSource<int> _exit =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<ShellViewModel> Initialized { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource RunStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public IWindowController Window { get; } = new NullWindow();

        public IUiDispatcher Dispatcher { get; } = new InlineDispatcher();

        public int ShutdownRequests { get; private set; }

        public int DisposeCalls { get; private set; }

        public Task InitializeAsync(ShellViewModel viewModel, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Initialized.TrySetResult(viewModel);
            return Task.CompletedTask;
        }

        public Task<int> RunAsync(bool showInitially, CancellationToken cancellationToken)
        {
            Assert.True(showInitially);
            RunStarted.TrySetResult();
            return _exit.Task;
        }

        public void RequestShutdown()
        {
            ShutdownRequests++;
            _exit.TrySetResult(0);
        }

        public ValueTask DisposeAsync()
        {
            DisposeCalls++;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class InlineDispatcher : IUiDispatcher
    {
        public Task InvokeAsync(Action action, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            action();
            return Task.CompletedTask;
        }
    }

    private sealed class NullWindow : IWindowController
    {
        public void ShowRestoreActivate() { }
        public void Hide() { }
        public void CloseForExit() { }
        public void ShowNotice(string message) { }
    }
}
