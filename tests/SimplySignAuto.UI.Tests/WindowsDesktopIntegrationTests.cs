using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.App.UI;
using SimplySignAuto.App.UI.ViewModels;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.UI.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class WindowsDesktopIntegrationCollection
{
    public const string Name = "Windows Desktop Integration";
}

[Collection(WindowsDesktopIntegrationCollection.Name)]
public sealed class WindowsDesktopIntegrationTests
{
    [WindowsFact]
    [SupportedOSPlatform("windows")]
    public async Task Activation_pipe_is_exclusive_and_accepts_only_the_current_signing_user()
    {
        var sid = WindowsIdentity.GetCurrent().User?.Value
            ?? throw new InvalidOperationException("Current Windows identity has no SID.");
        var names = ActivationNames.ForSigningUser(sid);
        var transport = new WindowsActivationTransport(
            new SessionZeroIntegrationIdentityReader(new WindowsActivationServerIdentityReader()),
            new ActivationServerIdentityVerifier());
        await using var server = await transport.TryCreateServerAsync(names, sid, CancellationToken.None)
            ?? throw new InvalidOperationException("Unable to claim the first activation server.");
        Assert.Null(await transport.TryCreateServerAsync(names, sid, CancellationToken.None));
        var window = new SignalingWindow();
        var handler = new ActivationCommandHandler(new InlineDispatcher(), window);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var serverTask = server.RunAsync(handler, cancellation.Token);

        var sent = false;
        for (var attempt = 0;
             attempt <= SingleInstanceActivator.MaximumActivationRetries && !sent;
             attempt++)
        {
            if (attempt > 0)
            {
                await Task.Delay(SingleInstanceActivator.RetryDelay, cancellation.Token);
            }

            sent = await transport.TrySendShowAsync(
                names,
                sid,
                SingleInstanceActivator.ConnectionTimeout,
                cancellation.Token);
        }

        Assert.True(sent);
        await window.Shown.Task.WaitAsync(cancellation.Token);
        cancellation.Cancel();
        await serverTask;
    }

    [WindowsFact]
    [SupportedOSPlatform("windows")]
    public async Task A_preexisting_pipe_squatter_cannot_be_claimed_and_never_starts_the_agent()
    {
        var sid = WindowsIdentity.GetCurrent().User?.Value
            ?? throw new InvalidOperationException("Current Windows identity has no SID.");
        var names = ActivationNames.ForSigningUser(sid);
        await using var squatter = new NamedPipeServerStream(
            names.PipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        var realTransport = new WindowsActivationTransport();

        Assert.Null(await realTransport.TryCreateServerAsync(names, sid, CancellationToken.None));

        var transport = new SquattedClaimTransport(realTransport);
        var activator = new SingleInstanceActivator(transport, new ImmediateDelay());
        var starts = 0;
        var failure = await Assert.ThrowsAsync<ActivationException>(() => activator.RunSingleAsync(
            sid,
            (_, _) =>
            {
                starts++;
                return Task.FromResult(0);
            },
            CancellationToken.None));

        Assert.Equal("activation_unavailable", failure.Code);
        Assert.Equal(0, starts);
        Assert.Equal(1, transport.CreateCalls);
    }

    [WindowsFact]
    public async Task Wpf_runtime_preserves_theme_icon_tray_and_opens_settings_on_its_visible_main_window()
    {
        await using var runtime = new WpfDesktopRuntimeFactory().Create();
        var management = new FixedManagementClient(ReadySnapshot());
        using var viewModel = new ShellViewModel(
            management,
            new RejectingReloginConfirmation(),
            runtime.Window,
            new NoopAgentLifetime());
        await runtime.InitializeAsync(viewModel, CancellationToken.None);
        Assert.Equal(1, management.RefreshCalls);
        Assert.Equal("退出", viewModel.Overview!.LoginButtonText);
#if SIMPLYSIGN_WPF
        await runtime.Dispatcher.InvokeAsync(() =>
        {
            var applier = new WpfThemeResourceApplier();
            foreach (var theme in new[] { ShellTheme.Light, ShellTheme.Dark })
            {
                applier.Apply(theme);
                var application = System.Windows.Application.Current
                    ?? throw new InvalidOperationException("desktop_application_missing");
                var dictionary = application.Resources.MergedDictionaries[0];
                Assert.Equal(ThemeResourceUris.For(theme), dictionary.Source);
                AssertRequiredThemeResources(dictionary, theme);
            }
        }, CancellationToken.None);

        runtime.Window.ShowRestoreActivate();
        var summary = new SimplySignAuto.Protocol.ServiceSettingsSummary(
            7080,
            SimplySignAuto.Protocol.ServiceSettingsSummary.FixedMaximumUploadBytes,
            24,
            "1.0.0");
        using var settings = new SimplySignAuto.App.UI.ViewModels.ServiceSettingsDialogViewModel(
            summary,
            new NoopSettingsEditor(summary),
            new SettingsAdministration(summary),
            new NoopClipboard(),
            new InlineDispatcher());
        var inspected = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        System.Windows.Threading.DispatcherTimer? inspectionTimer = null;
        await runtime.Dispatcher.InvokeAsync(() =>
        {
            var application = System.Windows.Application.Current
                ?? throw new InvalidOperationException("desktop_application_missing");
            var owner = application.MainWindow
                ?? throw new InvalidOperationException("desktop_main_window_missing");
            Assert.True(owner.IsVisible);
            var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
            inspectionTimer = new System.Windows.Threading.DispatcherTimer(
                TimeSpan.FromMilliseconds(25),
                System.Windows.Threading.DispatcherPriority.ApplicationIdle,
                (_, _) =>
                {
                    var dialogs = application.Windows
                        .OfType<SimplySignAuto.App.UI.Views.ServiceSettingsDialog>()
                        .ToArray();
                    if (dialogs.Length == 0 && DateTimeOffset.UtcNow < deadline)
                    {
                        return;
                    }

                    inspectionTimer?.Stop();
                    if (dialogs.Length == 0)
                    {
                        inspected.TrySetException(
                            new TimeoutException("service_settings_dialog_not_shown"));
                        return;
                    }

                    var dialog = dialogs[0];
                    try
                    {
                        Assert.Single(dialogs);
                        Assert.Same(owner, dialog.Owner);
                        Assert.Same(application.MainWindow, dialog.Owner);
                        Assert.Equal(
                            System.Windows.WindowStartupLocation.CenterOwner,
                            dialog.WindowStartupLocation);
                        Assert.False(dialog.ShowInTaskbar);
                        inspected.TrySetResult();
                    }
                    catch (Exception error)
                    {
                        inspected.TrySetException(error);
                    }
                    finally
                    {
                        dialog.Close();
                    }
                },
                application.Dispatcher);
            inspectionTimer.Start();
        }, CancellationToken.None);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var dialogs = Assert.IsAssignableFrom<
            SimplySignAuto.App.UI.ViewModels.IServiceSettingsDialogServiceProvider>(runtime)
            .ServiceSettingsDialogs;
        var showDialog = dialogs.ShowAsync(settings, timeout.Token);
        try
        {
            await inspected.Task.WaitAsync(timeout.Token);
            await showDialog.WaitAsync(timeout.Token);
        }
        finally
        {
            await runtime.Dispatcher.InvokeAsync(() =>
            {
                inspectionTimer?.Stop();
                foreach (var dialog in System.Windows.Application.Current.Windows
                    .OfType<SimplySignAuto.App.UI.Views.ServiceSettingsDialog>()
                    .ToArray())
                {
                    dialog.Close();
                }
            }, CancellationToken.None);
        }

#endif

        var runTask = runtime.RunAsync(showInitially: false, CancellationToken.None);
        runtime.RequestShutdown();
        Assert.Equal(0, await runTask.WaitAsync(TimeSpan.FromSeconds(10)));
    }

#if SIMPLYSIGN_WPF
    private static void AssertRequiredThemeResources(
        System.Windows.ResourceDictionary dictionary,
        ShellTheme theme)
    {
        string[] requiredKeys =
        [
            "ShellBackgroundBrush",
            "SurfaceBrush",
            "SidebarBackgroundBrush",
            "PrimaryBrush",
            "PrimaryForegroundBrush",
            "TextPrimaryBrush",
            "TextSecondaryBrush",
            "BorderBrush",
            "SelectionBrush",
            "SuccessBrush",
            "WarningBrush",
            "ErrorBrush",
        ];
        foreach (var key in requiredKeys)
        {
            Assert.True(dictionary.Contains(key), $"Theme {theme} is missing resource {key}.");
        }
    }
#endif

    private sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute()
        {
            if (!OperatingSystem.IsWindows())
            {
                Skip = "Requires Windows WPF, NotifyIcon, registry theme, and named-pipe ACL support.";
            }
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

    private static ManagementSnapshot ReadySnapshot() => new(
        ManagementSnapshot.CurrentVersion,
        new DateTimeOffset(2026, 8, 17, 0, 0, 0, TimeSpan.Zero),
        Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        true,
        true,
        7,
        7,
        1_000,
        true,
        7,
        ProtocolV3TestFixtures.Ready("authenticode"),
        ProtocolV3TestFixtures.Ready("pdf"),
        0,
        0,
        null,
        [],
        1,
        []);

    private sealed class FixedManagementClient(ManagementSnapshot snapshot) : IAgentManagementClient
    {
        public event EventHandler? SnapshotChanged { add { } remove { } }

        public int RefreshCalls { get; private set; }

        public ManagementSnapshot? LatestSnapshot => null;

        public Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RefreshCalls++;
            return Task.FromResult(snapshot);
        }

        public Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("relogin_not_expected");
    }

    private sealed class RejectingReloginConfirmation : IReloginConfirmation
    {
        public Task<bool> ConfirmAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("confirmation_not_expected");
    }

    private sealed class SessionZeroIntegrationIdentityReader(IActivationServerIdentityReader inner)
        : IActivationServerIdentityReader
    {
        public ActivationServerIdentityEvidence ReadServer(Microsoft.Win32.SafeHandles.SafePipeHandle pipeHandle) =>
            Normalize(inner.ReadServer(pipeHandle));

        public ActivationServerIdentityEvidence ReadCurrent() => Normalize(inner.ReadCurrent());

        private static ActivationServerIdentityEvidence Normalize(ActivationServerIdentityEvidence evidence) =>
            evidence is { InspectionSucceeded: true, SessionId: 0 }
                ? evidence with { SessionId = uint.MaxValue }
                : evidence;
    }

    private sealed class SignalingWindow : IWindowController
    {
        public TaskCompletionSource Shown { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void ShowRestoreActivate() => Shown.TrySetResult();

        public void Hide()
        {
        }

        public void CloseForExit()
        {
        }

        public void ShowNotice(string message)
        {
        }
    }

    private sealed class NoopAgentLifetime : IDesktopAgentLifetime
    {
        public Task StopAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
    }

#if SIMPLYSIGN_WPF
    private sealed class NoopSettingsEditor(SimplySignAuto.Protocol.ServiceSettingsSummary summary)
        : SimplySignAuto.App.Commands.IServiceConfigurationEditor
    {
        public Task<SimplySignAuto.App.Commands.ServiceConfigurationEditResult> ApplyAsync(
            SimplySignAuto.App.Commands.ServiceConfigurationEditRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(
                new SimplySignAuto.App.Commands.ServiceConfigurationEditResult(summary, null));
        }
    }

    private sealed class SettingsAdministration(SimplySignAuto.Protocol.ServiceSettingsSummary summary)
        : SimplySignAuto.Agent.Ipc.IAgentAdministrationClient
    {
        public Task<SimplySignAuto.Protocol.JobPageResponse> GetJobPageAsync(
            SimplySignAuto.Protocol.JobPageCursor? cursor,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<SimplySignAuto.Protocol.ServiceSettingsSummary> GetServiceSettingsAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(summary);
        }

        public Task SaveOtpAsync(
            SimplySignAuto.Core.Otp.OtpauthProfile profile,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class NoopClipboard : SimplySignAuto.App.UI.ViewModels.IClipboardService
    {
        public string? GetText() => null;
        public void SetText(string value) { }
        public void Clear() { }
    }
#endif

    private sealed class SquattedClaimTransport(WindowsActivationTransport inner) : IActivationTransport
    {
        public int CreateCalls { get; private set; }

        public Task<bool> TrySendShowAsync(
            ActivationNames names,
            string signingUserSid,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(false);
        }

        public bool AgentInstanceExists(ActivationNames names) => false;

        public ValueTask<IActivationServer?> TryCreateServerAsync(
            ActivationNames names,
            string signingUserSid,
            CancellationToken cancellationToken)
        {
            CreateCalls++;
            return inner.TryCreateServerAsync(names, signingUserSid, cancellationToken);
        }
    }

    private sealed class ImmediateDelay : IActivationRetryDelay
    {
        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
    }
}
