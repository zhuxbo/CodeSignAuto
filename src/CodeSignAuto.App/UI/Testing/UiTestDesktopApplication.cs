using CodeSignAuto.Agent.Ipc;
using CodeSignAuto.App.Commands;
using CodeSignAuto.App.UI.ViewModels;

namespace CodeSignAuto.App.UI.Testing;

public sealed class UiTestClipboardService : IClipboardService, IDisposable
{
    private string? _value;
    private int _disposed;

    public string? GetText()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        return _value;
    }

    public void SetText(string value)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        _value = value ?? throw new ArgumentNullException(nameof(value));
    }

    public void Clear() => _value = null;

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _value = null;
        }
    }
}

internal sealed class UiTestServiceConfigurationEditor(IAgentAdministrationClient administration)
    : IServiceConfigurationEditor
{
    public async Task<ServiceConfigurationEditResult> ApplyAsync(
        ServiceConfigurationEditRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return new ServiceConfigurationEditResult(
            await administration.GetServiceSettingsAsync(cancellationToken).ConfigureAwait(false),
            null);
    }
}

public sealed class UiTestDesktopApplication
{
    private readonly IDesktopRuntimeFactory _runtimeFactory;
    private readonly IUiTestHostConnectionFactory _hostFactory;

    public UiTestDesktopApplication()
        : this(new WpfDesktopRuntimeFactory(isolatedUiTestMode: true), new UiTestHostConnectionFactory())
    {
    }

    public UiTestDesktopApplication(
        IDesktopRuntimeFactory runtimeFactory,
        IUiTestHostConnectionFactory hostFactory)
    {
        _runtimeFactory = runtimeFactory ?? throw new ArgumentNullException(nameof(runtimeFactory));
        _hostFactory = hostFactory ?? throw new ArgumentNullException(nameof(hostFactory));
    }

    public async Task<int> ExecuteAsync(
        UiTestLaunchOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        await using var host = await _hostFactory.ConnectAsync(options, cancellationToken)
            .ConfigureAwait(false);
        await using var runtime = _runtimeFactory.Create(
            UiTestTrayIdentity.Create(options.ProcessId, options.PipeName));
        using var services = UiTestDesktopServices.Create(options.State);
        using var clipboard = new UiTestClipboardService();
        var settingsEditor = new UiTestServiceConfigurationEditor(services.Administration);
        var settingsDialogs = runtime is IServiceSettingsDialogServiceProvider provider
            ? provider.ServiceSettingsDialogs
            : UnavailableServiceSettingsDialogService.Instance;
        var lifetime = new UiTestDesktopLifetime(runtime);
        using var viewModel = new ShellViewModel(
            services.Management,
            services.LocalJobs,
            services.Configuration,
            new WindowReloginConfirmation(runtime.Window, runtime.Dispatcher),
            runtime.Window,
            lifetime,
            runtime.Dispatcher,
            terminalJobs: null,
            clipboard,
            settingsEditor,
            settingsDialogs);
        await runtime.InitializeAsync(viewModel, cancellationToken).ConfigureAwait(false);
        await (viewModel.Overview ?? throw new InvalidOperationException("ui_test_overview_missing"))
            .RefreshAsync(cancellationToken)
            .ConfigureAwait(false);

        using var hostReadCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var hostExit = host.WaitForExitRequestAsync(hostReadCancellation.Token);
        var run = runtime.RunAsync(showInitially: true, cancellationToken);
        var completed = await Task.WhenAny(run, hostExit).ConfigureAwait(false);
        if (completed == hostExit)
        {
            var requestedExit = await hostExit.ConfigureAwait(false);
            runtime.RequestShutdown();
            await run.ConfigureAwait(false);
            if (!requestedExit)
            {
                throw new UiTestHostException("ui_test_host_disconnected");
            }
        }
        else
        {
            hostReadCancellation.Cancel();
        }

        return await run.ConfigureAwait(false);
    }

    private sealed class UiTestDesktopLifetime(IDesktopRuntime runtime) : IDesktopAgentLifetime
    {
        public Task StopAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            runtime.RequestShutdown();
            return Task.CompletedTask;
        }
    }
}
