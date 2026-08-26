using System.Collections.Concurrent;
using SimplySignAuto.Agent;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.Agent.Signing;
using SimplySignAuto.App;
using SimplySignAuto.App.Commands;
using SimplySignAuto.App.UI;
using SimplySignAuto.App.UI.ViewModels;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.UI.Tests;

public sealed class DesktopApplicationCompositionTests
{
    [Fact]
    public async Task Admin_desktop_entry_builds_only_the_control_console_composition()
    {
        var runtime = new RecordingDesktopRuntime();
        var application = new AdminDesktopApplication(
            new FixedSigningIdentity("S-1-5-21-1000"),
            new ImmediateSingleInstanceActivator(new BlockingActivationServer([])),
            new FixedDesktopRuntimeFactory(runtime));

        var execution = application.ExecuteAsync(
            showInitially: true,
            TextWriter.Null,
            CancellationToken.None);
        await runtime.Started.Task;
        runtime.RequestShutdown();
        var exitCode = await execution;

        Assert.Equal(0, exitCode);
        Assert.True(runtime.WasShownInitially);
        Assert.Equal(1, runtime.DisposeCalls);
        Assert.IsType<ServiceConfigurationEditor>(
            runtime.ViewModel!.ServiceSettings!.ConfigurationEditor);
        Assert.Same(
            runtime.ServiceSettingsDialogs,
            runtime.ViewModel.ServiceSettings.DialogService);
    }

    [Fact]
    public void Installed_receipt_selects_the_fixed_desktop_entry_without_ui_override()
    {
        var root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "SimplySignAuto", "manual"));
        var manual = new InstallationReceipt(
            InstallationReceipt.CurrentSchemaVersion,
            InstallationMode.Manual,
            "0123456789abcdef0123456789abcdef",
            "S-1-5-21-1000-2000-3000-4000",
            Path.GetFullPath(Path.Combine(Path.GetTempPath(), "SimplySignAuto.exe")),
            root);
        var service = manual with { Mode = InstallationMode.Service, UserDataRoot = null };

        Assert.Equal(InstallationMode.Service, Program.ResolveDesktopMode(null));
        Assert.Equal(InstallationMode.Service, Program.ResolveDesktopMode(service));
        Assert.Equal(InstallationMode.Manual, Program.ResolveDesktopMode(manual));
        Assert.Same(manual, Program.ValidateManualDesktopReceipt(
            manual,
            manual.ExecutablePath,
            root));
        Assert.Equal(
            "owned_resource_mismatch",
            Assert.Throws<InstallException>(() => Program.ValidateManualDesktopReceipt(
                manual,
                Path.GetFullPath(Path.Combine(Path.GetTempPath(), "other", "SimplySignAuto.exe")),
                root)).Code);
    }

    [Fact]
    public void Explicit_entry_routing_preserves_cli_and_desktop_modes()
    {
        (string[] Arguments, ApplicationEntryKind ExpectedKind, bool ExpectedShowInitially)[] routes =
        [
            ([], ApplicationEntryKind.Desktop, true),
            (["agent", "--background"], ApplicationEntryKind.AgentConsole, false),
            (["agent", "--console"], ApplicationEntryKind.AgentConsole, false),
            (["service"], ApplicationEntryKind.Service, false),
            (["configure-otp"], ApplicationEntryKind.ConfigureOtp, false),
            (["install", "--signing-user", "DOMAIN\\user"], ApplicationEntryKind.Install, false),
            (["uninstall"], ApplicationEntryKind.Uninstall, false),
            (["purge-quarantine", "--manifest", "C:\\ProgramData\\SimplySignAuto.Purge.x\\manifest.json"], ApplicationEntryKind.PurgeQuarantine, false),
            (["--version"], ApplicationEntryKind.Version, false),
            (["agent", "--background", "extra"], ApplicationEntryKind.Invalid, false),
            (["unknown"], ApplicationEntryKind.Invalid, false),
        ];
        foreach (var (arguments, expectedKind, expectedShowInitially) in routes)
        {
            var route = ApplicationEntryRoute.Parse(arguments);

            Assert.Equal(expectedKind, route.Kind);
            Assert.Equal(expectedShowInitially, route.ShowInitially);
        }
    }

    [Fact]
    public void Only_foreground_command_entries_attach_to_the_parent_console()
    {
        Assert.False(Program.ShouldAttachParentConsole(ApplicationEntryRoute.Parse([])));
        Assert.False(Program.ShouldAttachParentConsole(
            ApplicationEntryRoute.Parse(["agent", "--background"])));
        Assert.False(Program.ShouldAttachParentConsole(
            ApplicationEntryRoute.Parse(["service"])));
        Assert.False(Program.ShouldAttachParentConsole(
            ApplicationEntryRoute.Parse(["uninstall", "--ui"])));
        Assert.True(Program.ShouldAttachParentConsole(
            ApplicationEntryRoute.Parse(["agent", "--console"])));
        Assert.True(Program.ShouldAttachParentConsole(
            ApplicationEntryRoute.Parse(["service", "--console"])));
        Assert.True(Program.ShouldAttachParentConsole(
            ApplicationEntryRoute.Parse(["--version"])));
        Assert.True(Program.ShouldAttachParentConsole(
            ApplicationEntryRoute.Parse(["uninstall"])));
    }

    [Fact]
    public void Uninstall_without_a_console_uses_UI_but_redirected_or_console_calls_stay_noninteractive()
    {
        Assert.True(Program.ShouldUseGraphicalUninstall(
            ApplicationEntryRoute.Parse(["uninstall"]),
            standardIoAvailable: false));
        Assert.False(Program.ShouldUseGraphicalUninstall(
            ApplicationEntryRoute.Parse(["uninstall"]),
            standardIoAvailable: true));
        Assert.True(Program.ShouldUseGraphicalUninstall(
            ApplicationEntryRoute.Parse(["uninstall", "--ui"]),
            standardIoAvailable: true));
        Assert.True(Program.ShouldUseGraphicalUninstall(
            ApplicationEntryRoute.Parse(["pdf-extension", "uninstall"]),
            standardIoAvailable: false));
        Assert.False(Program.ShouldUseGraphicalUninstall(
            ApplicationEntryRoute.Parse([
                "uninstall", "--purge-data", "--confirm", "PURGE"]),
            standardIoAvailable: false));
        Assert.False(Program.ShouldUseGraphicalUninstall(
            ApplicationEntryRoute.Parse([
                "pdf-extension", "install", "--media-root", @"C:\setup\pdf"]),
            standardIoAvailable: false));
    }

    [Fact]
    public void Detached_desktop_keeps_diagnostics_in_a_bounded_local_log()
    {
        var root = Path.Combine(Path.GetTempPath(), $"ssa-desktop-log-{Guid.NewGuid():N}");
        try
        {
            using (var writer = DesktopDiagnosticLog.Open(root, maximumBytes: 256))
            {
                writer.WriteLine("first diagnostic path=C:\\ProgramData\\SimplySignAuto");
                writer.WriteLine(new string('x', 220));
                writer.WriteLine("latest diagnostic hresult=0x80070005");
            }

            var log = File.ReadAllText(DesktopDiagnosticLog.GetPath(root));
            Assert.DoesNotContain("first diagnostic", log, StringComparison.Ordinal);
            Assert.Contains("latest diagnostic hresult=0x80070005", log, StringComparison.Ordinal);
            Assert.True(new FileInfo(DesktopDiagnosticLog.GetPath(root)).Length <= 256);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void Uninstall_keeps_diagnostics_in_a_separate_bounded_local_log()
    {
        var root = Path.Combine(Path.GetTempPath(), $"ssa-uninstall-log-{Guid.NewGuid():N}");
        try
        {
            using (var writer = UninstallDiagnosticLog.Open(root, maximumBytes: 256))
            {
                writer.WriteLine("stage=start product_version=0.1.1 os_build=19045");
                writer.WriteLine(new string('x', 220));
                writer.WriteLine(
                    "stage=state receipt=missing service_configuration=missing code=uninstall_installation_state_missing");
            }

            var log = File.ReadAllText(UninstallDiagnosticLog.GetPath(root));
            Assert.DoesNotContain("stage=start", log, StringComparison.Ordinal);
            Assert.Contains("code=uninstall_installation_state_missing", log, StringComparison.Ordinal);
            Assert.True(new FileInfo(UninstallDiagnosticLog.GetPath(root)).Length <= 256);
            Assert.NotEqual(
                DesktopDiagnosticLog.GetPath(root),
                UninstallDiagnosticLog.GetPath(root));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public async Task Desktop_shutdown_stops_activation_before_agent_and_is_idempotent()
    {
        var events = new List<string>();
        var activation = new BlockingActivationServer(events);
        var runner = new BlockingAgentRunner(events);
        var handler = new ActivationCommandHandler(new InlineDispatcher(), new NullWindow());
        var lifetimes = new DesktopOwnedLifetimes(activation, handler, runner, CompleteConfiguration());

        lifetimes.Start();
        await Task.WhenAll(activation.Started.Task, runner.Started.Task);
        await Task.WhenAll(
            lifetimes.StopAsync(CancellationToken.None),
            lifetimes.StopAsync(CancellationToken.None));

        Assert.True(events.IndexOf("activation.stop") < events.IndexOf("agent.stop"));
        Assert.Equal(1, events.Count(item => item == "activation.stop"));
        Assert.Equal(1, events.Count(item => item == "agent.stop"));
    }

    [Fact]
    public async Task A_stop_that_wins_the_start_race_prevents_the_agent_from_starting_later()
    {
        var events = new List<string>();
        var lifetimes = new DesktopOwnedLifetimes(
            new BlockingActivationServer(events),
            new ActivationCommandHandler(new InlineDispatcher(), new NullWindow()),
            new BlockingAgentRunner(events),
            CompleteConfiguration());

        await lifetimes.StopAsync(CancellationToken.None);

        var failure = Assert.Throws<InvalidOperationException>(lifetimes.Start);
        Assert.Equal("desktop_lifetime_stopped", failure.Message);
        Assert.Empty(events);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Shutdown_request_is_delivered_once_whether_it_wins_or_loses_runtime_attachment(bool requestFirst)
    {
        var gate = new DeferredShutdownGate();
        var calls = 0;
        if (requestFirst)
        {
            gate.Request();
        }

        gate.Attach(() => calls++);
        if (!requestFirst)
        {
            gate.Request();
        }

        gate.Request();
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Agent_failure_requests_dispatcher_shutdown_without_touching_WPF_from_worker_thread()
    {
        var runtime = new RecordingDesktopRuntime();
        var lifetime = new FakeOwnedAgentLifetime();
        var application = new DesktopApplication(
            new FixedConfigurationLoader(CompleteConfiguration()),
            new FixedSigningIdentity("S-1-5-21-1000"),
            new ImmediateSingleInstanceActivator(new BlockingActivationServer([])),
            new FailingAgentRunner(),
            new FixedDesktopRuntimeFactory(runtime),
            new UnknownActiveJobStateSource(),
            new FixedAgentLifetimeFactory(lifetime));

        var exitCode = await application.ExecuteAsync(
            showInitially: false,
            TextWriter.Null,
            CancellationToken.None);

        Assert.Equal(1, exitCode);
        Assert.False(runtime.WasShownInitially);
        Assert.Equal(1, runtime.DispatcherInvocations);
        Assert.Equal(1, runtime.ShutdownRequests);
        Assert.Equal(1, runtime.DisposeCalls);
        Assert.Equal(1, lifetime.DisposeCalls);
    }

    [Fact]
    public async Task Shared_system_lifetime_makes_agent_first_completion_a_clean_shutdown()
    {
        for (var iteration = 0; iteration < 20; iteration++)
        {
            await AssertSharedSystemLifetimeShutdownAsync();
        }
    }

    private static async Task AssertSharedSystemLifetimeShutdownAsync()
    {
        var lifetime = new FakeOwnedAgentLifetime();
        var runner = new LifetimeAwareAgentRunner();
        var runtime = new DelayedShutdownDesktopRuntime();
        var application = new DesktopApplication(
            new FixedConfigurationLoader(CompleteConfiguration()),
            new FixedSigningIdentity("S-1-5-21-1000"),
            new ImmediateSingleInstanceActivator(new BlockingActivationServer([])),
            runner,
            new FixedDesktopRuntimeFactory(runtime),
            new UnknownActiveJobStateSource(),
            new FixedAgentLifetimeFactory(lifetime));

        var execution = application.ExecuteAsync(
            showInitially: false,
            TextWriter.Null,
            CancellationToken.None);
        await Task.WhenAll(runtime.Started.Task, runner.Started.Task);

        lifetime.RequestShutdown();
        await Task.WhenAll(runner.Completed.Task, runtime.ShutdownRequested.Task);
        Assert.False(execution.IsCompleted);
        runtime.ReleaseShutdown();

        Assert.Equal(0, await execution);
        Assert.Equal(1, runner.SharedLifetimeCalls);
        Assert.Equal(1, runtime.ShutdownRequests);
        Assert.Equal(1, runtime.DisposeCalls);
        Assert.Equal(1, lifetime.DisposeCalls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Shared_system_signal_does_not_hide_an_unrelated_agent_cancellation(
        bool useDefaultCancellationToken)
    {
        var events = new List<string>();
        var lifetime = new FakeOwnedAgentLifetime();
        var runner = new UnrelatedCancellationAgentRunner(useDefaultCancellationToken);
        var runtime = new RecordingDesktopRuntime();
        var error = new StringWriter();
        var application = new DesktopApplication(
            new FixedConfigurationLoader(CompleteConfiguration()),
            new FixedSigningIdentity("S-1-5-21-1000"),
            new ImmediateSingleInstanceActivator(new BlockingActivationServer(events)),
            runner,
            new FixedDesktopRuntimeFactory(runtime),
            new UnknownActiveJobStateSource(),
            new FixedAgentLifetimeFactory(lifetime));

        var execution = application.ExecuteAsync(
            showInitially: false,
            error,
            CancellationToken.None);
        await Task.WhenAll(runtime.Started.Task, runner.Started.Task);

        lifetime.RequestShutdown();

        Assert.Equal(1, await execution);
        Assert.Contains("stable_code=desktop_start_failed", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("stage=desktop_execute", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("desktop_start_failed", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(1, runtime.ShutdownRequests);
        Assert.Equal(1, runtime.DisposeCalls);
        Assert.Equal(1, lifetime.DisposeCalls);
        Assert.Equal(1, events.Count(item => item == "activation.stop"));
    }

    [Fact]
    public async Task Desktop_unknown_failure_keeps_top_level_native_diagnostics_and_a_throwing_writer_does_not_change_exit_code()
    {
        var native = new System.ComponentModel.Win32Exception(5, "access denied path=C:\\ProgramData\\SimplySignAuto");
        var output = new StringWriter();
        var application = new DesktopApplication(
            new FixedConfigurationLoader(CompleteConfiguration()),
            new ThrowingSigningIdentity(native),
            new ImmediateSingleInstanceActivator(new BlockingActivationServer([])),
            new FailingAgentRunner(),
            new FixedDesktopRuntimeFactory(new RecordingDesktopRuntime()),
            new UnknownActiveJobStateSource());

        Assert.Equal(1, await application.ExecuteAsync(false, output, CancellationToken.None));
        var diagnostic = output.ToString();
        Assert.Contains("stable_code=desktop_start_failed", diagnostic, StringComparison.Ordinal);
        Assert.Contains("stage=desktop_execute", diagnostic, StringComparison.Ordinal);
        Assert.Contains("exception_depth=0", diagnostic, StringComparison.Ordinal);
        Assert.Contains("Win32Exception", diagnostic, StringComparison.Ordinal);
        Assert.Contains("win32_error=5", diagnostic, StringComparison.Ordinal);
        Assert.Contains("path=C:\\ProgramData\\SimplySignAuto", diagnostic, StringComparison.Ordinal);

        Assert.Equal(1, await application.ExecuteAsync(false, new ThrowingWriter(), CancellationToken.None));
    }

    [Fact]
    public async Task Shared_system_signal_requests_runtime_shutdown_without_using_a_dead_dispatcher()
    {
        var events = new List<string>();
        var lifetime = new FakeOwnedAgentLifetime();
        var runner = new LifetimeAwareAgentRunner();
        var runtime = new DeadDispatcherDelayedShutdownRuntime();
        var application = new DesktopApplication(
            new FixedConfigurationLoader(CompleteConfiguration()),
            new FixedSigningIdentity("S-1-5-21-1000"),
            new ImmediateSingleInstanceActivator(new BlockingActivationServer(events)),
            runner,
            new FixedDesktopRuntimeFactory(runtime),
            new UnknownActiveJobStateSource(),
            new FixedAgentLifetimeFactory(lifetime));

        var execution = application.ExecuteAsync(
            showInitially: false,
            TextWriter.Null,
            CancellationToken.None);
        await Task.WhenAll(runtime.Started.Task, runner.Started.Task);

        lifetime.RequestShutdown();
        var completed = await Task.WhenAny(runtime.ShutdownRequested.Task, execution);

        Assert.Same(runtime.ShutdownRequested.Task, completed);
        Assert.False(execution.IsCompleted);
        runtime.ReleaseShutdown();
        Assert.Equal(0, await execution);
        Assert.Equal(0, runtime.DispatcherCalls);
        Assert.Equal(1, runtime.ShutdownRequests);
        Assert.Equal(1, runtime.DisposeCalls);
        Assert.Equal(1, lifetime.DisposeCalls);
        Assert.Equal(1, events.Count(item => item == "activation.stop"));
    }

    [Fact]
    public async Task Shared_agent_lifetime_is_disposed_when_runtime_startup_fails()
    {
        var lifetime = new FakeOwnedAgentLifetime();
        var application = new DesktopApplication(
            new FixedConfigurationLoader(CompleteConfiguration()),
            new FixedSigningIdentity("S-1-5-21-1000"),
            new ImmediateSingleInstanceActivator(new BlockingActivationServer([])),
            new FailingAgentRunner(),
            new ThrowingDesktopRuntimeFactory(),
            new UnknownActiveJobStateSource(),
            new FixedAgentLifetimeFactory(lifetime));

        var exitCode = await application.ExecuteAsync(
            showInitially: false,
            TextWriter.Null,
            CancellationToken.None);

        Assert.Equal(1, exitCode);
        Assert.Equal(1, lifetime.DisposeCalls);
    }

    [Fact]
    public async Task Safe_tray_exit_joins_owned_lifetimes_and_returns_zero()
    {
        var events = new List<string>();
        var activation = new BlockingActivationServer(events);
        var runner = new BlockingAgentRunner(events);
        var runtime = new RecordingDesktopRuntime();
        var application = new DesktopApplication(
            new FixedConfigurationLoader(CompleteConfiguration()),
            new FixedSigningIdentity("S-1-5-21-1000"),
            new ImmediateSingleInstanceActivator(activation),
            runner,
            new FixedDesktopRuntimeFactory(runtime),
            new FixedActiveJobStateSource(ActiveJobState.None));

        var execution = application.ExecuteAsync(
            showInitially: true,
            TextWriter.Null,
            CancellationToken.None);
        await Task.WhenAll(runtime.Started.Task, activation.Started.Task, runner.Started.Task);

        var exit = await runtime.ViewModel!.RequestExitAsync(CancellationToken.None);
        var exitCode = await execution;

        Assert.Equal(ExitRequestResult.Exiting, exit);
        Assert.Equal(0, exitCode);
        Assert.Equal(1, events.Count(item => item == "activation.stop"));
        Assert.Equal(1, events.Count(item => item == "agent.stop"));
        Assert.Equal(1, runtime.CloseForExitCalls);
        Assert.Equal(1, runtime.DisposeCalls);
        AssertCancellationSourceWasDisposed(activation.Token);
        AssertCancellationSourceWasDisposed(runner.Token);
    }

    [Fact]
    public async Task Activation_fault_still_cancels_and_joins_agent_and_disposes_all_owned_resources()
    {
        var events = new List<string>();
        var activation = new FaultingActivationServer(events);
        var runner = new BlockingAgentRunner(events);
        var runtime = new RecordingDesktopRuntime();
        var application = new DesktopApplication(
            new FixedConfigurationLoader(CompleteConfiguration()),
            new FixedSigningIdentity("S-1-5-21-1000"),
            new ImmediateSingleInstanceActivator(activation),
            runner,
            new FixedDesktopRuntimeFactory(runtime),
            new FixedActiveJobStateSource(ActiveJobState.None));

        var exitCode = await application.ExecuteAsync(
            showInitially: false,
            TextWriter.Null,
            CancellationToken.None);

        Assert.Equal(1, exitCode);
        Assert.Equal(1, events.Count(item => item == "activation.fault"));
        Assert.Equal(1, events.Count(item => item == "agent.stop"));
        Assert.Equal(1, runtime.ShutdownRequests);
        Assert.Equal(1, runtime.DisposeCalls);
        AssertCancellationSourceWasDisposed(activation.Token);
        AssertCancellationSourceWasDisposed(runner.Token);
    }

    [Fact]
    public async Task System_shutdown_racing_a_delayed_tray_exit_is_idempotent_and_safe()
    {
        var events = new List<string>();
        var activation = new BlockingActivationServer(events);
        var runner = new DelayedStopAgentRunner(events);
        var runtime = new SystemShutdownDesktopRuntime();
        var application = new DesktopApplication(
            new FixedConfigurationLoader(CompleteConfiguration()),
            new FixedSigningIdentity("S-1-5-21-1000"),
            new ImmediateSingleInstanceActivator(activation),
            runner,
            new FixedDesktopRuntimeFactory(runtime),
            new FixedActiveJobStateSource(ActiveJobState.None));

        var execution = application.ExecuteAsync(
            showInitially: false,
            TextWriter.Null,
            CancellationToken.None);
        await Task.WhenAll(runtime.Started.Task, activation.Started.Task, runner.Started.Task);
        var trayPlatform = new MinimalTrayPlatform();
        using var tray = new TrayIconController(trayPlatform, runtime.ViewModel!, runtime.Window);

        runtime.CompleteSystemShutdown();
        var trayExit = tray.HandleCommandAsync(TrayCommand.Exit, CancellationToken.None);
        await trayExit;
        Assert.True(trayExit.IsCompletedSuccessfully);
        await runner.StopStarted.Task;
        Assert.False(execution.IsCompleted);
        runner.ReleaseStop.TrySetResult();

        var exitCode = await execution;

        Assert.Equal(0, exitCode);
        Assert.Equal(1, events.Count(item => item == "activation.stop"));
        Assert.Equal(1, events.Count(item => item == "agent.stop"));
        Assert.Equal(0, runtime.UnsafeWindow.CloseCalls);
        Assert.Equal(0, runtime.UnsafeWindow.NoticeCalls);
        Assert.Equal(1, runtime.DisposeCalls);
        tray.Dispose();
        Assert.Equal(1, trayPlatform.DisposeCalls);
        Assert.Equal(0, trayPlatform.SubscriberCount);
    }

    [Fact]
    public async Task Existing_instance_activation_does_not_depend_on_reloading_agent_configuration()
    {
        var loader = new NeverLoadConfigurationLoader();
        var application = new DesktopApplication(
            loader,
            new FixedSigningIdentity("S-1-5-21-1000"),
            new ExistingOnlyActivator(),
            new FailingAgentRunner(),
            new FixedDesktopRuntimeFactory(new RecordingDesktopRuntime()),
            new UnknownActiveJobStateSource());

        var exitCode = await application.ExecuteAsync(
            showInitially: true,
            TextWriter.Null,
            CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.Equal(0, loader.Calls);
    }

    [Fact]
    public async Task Real_desktop_application_composes_the_management_overview_instead_of_placeholder_state()
    {
        var events = new List<string>();
        var runtime = new RecordingDesktopRuntime();
        var runner = new ManagementBlockingAgentRunner(events, ReadyManagementClient());
        var application = new DesktopApplication(
            new FixedConfigurationLoader(CompleteConfiguration()),
            new FixedSigningIdentity("S-1-5-21-1000"),
            new ImmediateSingleInstanceActivator(new BlockingActivationServer(events)),
            runner,
            new FixedDesktopRuntimeFactory(runtime),
            new UnknownActiveJobStateSource(),
            new FixedAgentLifetimeFactory(new FakeOwnedAgentLifetime()));

        var execution = application.ExecuteAsync(
            showInitially: false,
            TextWriter.Null,
            CancellationToken.None);
        await Task.WhenAll(runtime.Started.Task, runner.Started.Task);

        Assert.NotNull(runtime.ViewModel!.Overview);
        Assert.Same(runtime.ViewModel.Overview, runtime.ViewModel.Pages[0].Content);
        Assert.Equal("签名服务已就绪", runtime.ViewModel.OverallStatusText);

        runtime.RequestShutdown();
        Assert.Equal(0, await execution);
    }

    [Fact]
    public async Task Real_desktop_application_composes_quick_sign_from_the_runner_local_bridge_and_loaded_configuration()
    {
        var events = new List<string>();
        var runtime = new RecordingDesktopRuntime();
        var localJobs = new RecordingLocalJobClient();
        var runner = new LocalManagementBlockingAgentRunner(events, ReadyManagementClient(), localJobs);
        var configuration = CompleteLocalConfiguration();
        var application = new DesktopApplication(
            new FixedConfigurationLoader(configuration),
            new FixedSigningIdentity(configuration.SigningUserSid),
            new ImmediateSingleInstanceActivator(new BlockingActivationServer(events)),
            runner,
            new FixedDesktopRuntimeFactory(runtime),
            new UnknownActiveJobStateSource(),
            new FixedAgentLifetimeFactory(new FakeOwnedAgentLifetime()));

        var execution = application.ExecuteAsync(false, TextWriter.Null, default);
        await Task.WhenAll(runtime.Started.Task, runner.Started.Task);

        Assert.NotNull(runtime.ViewModel!.QuickSign);
        Assert.Same(runtime.ViewModel.QuickSign, runtime.ViewModel.Pages[1].Content);
        Assert.Same(localJobs, runner.LocalJobs);

        runtime.RequestShutdown();
        Assert.Equal(0, await execution);
    }

    [Fact]
    public async Task Manual_desktop_application_reuses_the_local_bridge_with_the_five_page_shell()
    {
        var events = new List<string>();
        var runtime = new RecordingDesktopRuntime();
        var localJobs = new RecordingLocalJobClient();
        using var management = new AgentManagementBridge();
        var runner = new LocalManagementBlockingAgentRunner(events, management, localJobs);
        var configuration = CompleteLocalConfiguration();
        var application = new DesktopApplication(
            new FixedConfigurationLoader(configuration),
            new FixedSigningIdentity(configuration.SigningUserSid),
            new ImmediateSingleInstanceActivator(new BlockingActivationServer(events)),
            runner,
            new FixedDesktopRuntimeFactory(runtime),
            new UnknownActiveJobStateSource(),
            new FixedAgentLifetimeFactory(new FakeOwnedAgentLifetime()),
            mode: InstallationMode.Manual);

        var execution = application.ExecuteAsync(false, TextWriter.Null, default);
        await Task.WhenAll(runtime.Started.Task, runner.Started.Task);

        Assert.Equal(
            ["概览", "手工签名", "签名任务", "激活凭证", "应用设置"],
            runtime.ViewModel!.Pages.Select(page => page.Title).ToArray());
        Assert.NotNull(runtime.ViewModel.QuickSign);
        Assert.NotNull(runtime.ViewModel.Jobs);
        Assert.NotNull(runtime.ViewModel.Activation);
        Assert.Null(runtime.ViewModel.ServiceSettings);

        runtime.RequestShutdown();
        Assert.Equal(0, await execution);
    }

    [Fact]
    public async Task Real_desktop_exit_joins_a_blocking_local_complete_before_the_agent_owner_returns()
    {
        var root = Path.Combine(Path.GetTempPath(), "SimplySignAuto-desktop-local-exit-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var configuration = CompleteLocalConfiguration(root);
            Directory.CreateDirectory(configuration.SpoolPath);
            var source = Path.Combine(root, "source.exe");
            await File.WriteAllBytesAsync(source, "MZ-blocked"u8.ToArray());
            var events = new ConcurrentQueue<string>();
            var transport = new BlockingCompleteLocalTransport(configuration.SpoolPath, events);
            var runner = new AsyncLocalOwnerAgentRunner(
                new LocalJobClient(transport, configuration.SpoolPath),
                ReadyManagementClient(),
                events);
            var runtime = new RecordingDesktopRuntime();
            var application = new DesktopApplication(
                new FixedConfigurationLoader(configuration),
                new FixedSigningIdentity(configuration.SigningUserSid),
                new ImmediateSingleInstanceActivator(new BlockingActivationServer([])),
                runner,
                new FixedDesktopRuntimeFactory(runtime),
                new UnknownActiveJobStateSource(),
                new FixedAgentLifetimeFactory(new FakeOwnedAgentLifetime()));

            var execution = application.ExecuteAsync(false, TextWriter.Null, default);
            await Task.WhenAll(runtime.Started.Task, runner.Started.Task);
            await runtime.ViewModel!.QuickSign!.SelectFileAsync(source);
            var submit = runtime.ViewModel.QuickSign.SubmitAsync(default);
            await transport.CompleteStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));

            var exit = await runtime.ViewModel.RequestExitAsync(default);
            var exitCode = await execution.WaitAsync(TimeSpan.FromSeconds(1));

            Assert.Equal(ExitRequestResult.Exiting, exit);
            Assert.Equal(0, exitCode);
            Assert.Null(await submit.WaitAsync(TimeSpan.FromSeconds(1)));
            var ordered = events.ToArray();
            Assert.True(
                Array.IndexOf(ordered, "complete.stop") < Array.IndexOf(ordered, "owner.disposed"),
                string.Join(",", ordered));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static AgentConfiguration CompleteConfiguration() => new(
        "S-1-5-21-1000",
        Path.Combine(Path.GetTempPath(), "SimplySignAuto", "spool"),
        Path.Combine(Path.GetTempPath(), "SimplySignDesktop.exe"),
        Path.Combine(Path.GetTempPath(), "synthetic.dll"),
        new AgentAuthenticodeConfiguration(Path.Combine(Path.GetTempPath(), "signtool.exe")),
        null);

    private static AgentConfiguration CompleteLocalConfiguration(string? configuredRoot = null)
    {
        var root = configuredRoot ?? Path.Combine(Path.GetTempPath(), "SimplySignAuto", "local-composition");
        return new AgentConfiguration(
            "S-1-5-21-1000-2000-3000-4000",
            Path.Combine(root, "spool"),
            Path.Combine(root, "SimplySignDesktop.exe"),
            Path.Combine(root, "synthetic.dll"),
            new AgentAuthenticodeConfiguration(Path.Combine(root, "signtool.exe")),
            null);
    }

    private static IAgentManagementClient ReadyManagementClient() =>
        new FixedManagementClient(new ManagementSnapshot(
            ManagementSnapshot.CurrentVersion,
            new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero),
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
            [
                new CertificateSummary(
                    "Synthetic", "52A1B4C9",
                    DateTimeOffset.Parse("2025-01-01T00:00:00Z"),
                    DateTimeOffset.Parse("2027-01-01T00:00:00Z"),
                    true, true, true, null),
            ]));

    private static void AssertCancellationSourceWasDisposed(CancellationToken cancellationToken) =>
        Assert.Throws<ObjectDisposedException>(() => _ = cancellationToken.WaitHandle);

    private sealed class BlockingActivationServer(List<string> events) : IActivationServer
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public CancellationToken Token { get; private set; }

        public async Task RunAsync(ActivationCommandHandler handler, CancellationToken cancellationToken)
        {
            Token = cancellationToken;
            events.Add("activation.start");
            Started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            finally
            {
                events.Add("activation.stop");
            }
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FaultingActivationServer(List<string> events) : IActivationServer
    {
        public CancellationToken Token { get; private set; }

        public Task RunAsync(ActivationCommandHandler handler, CancellationToken cancellationToken)
        {
            Token = cancellationToken;
            events.Add("activation.fault");
            return Task.FromException(new InvalidOperationException("synthetic activation failure"));
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class BlockingAgentRunner(List<string> events) : IAgentRunner
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public CancellationToken Token { get; private set; }

        public async Task RunAsync(AgentConfiguration configuration, CancellationToken cancellationToken)
        {
            Token = cancellationToken;
            events.Add("agent.start");
            Started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            finally
            {
                events.Add("agent.stop");
            }
        }
    }

    private sealed class ManagementBlockingAgentRunner(
        List<string> events,
        IAgentManagementClient management) : IAgentRunner, IDesktopManagementSource
    {
        public TaskCompletionSource Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public IAgentManagementClient Management { get; } = management;

        public async Task RunAsync(
            AgentConfiguration configuration,
            CancellationToken cancellationToken)
        {
            events.Add("agent.start");
            Started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            finally
            {
                events.Add("agent.stop");
            }
        }
    }

    private sealed class LocalManagementBlockingAgentRunner(
        List<string> events,
        IAgentManagementClient management,
        ILocalJobClient localJobs) : IAgentRunner, IDesktopManagementSource, IDesktopLocalJobSource
    {
        public TaskCompletionSource Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public IAgentManagementClient Management { get; } = management;

        public ILocalJobClient LocalJobs { get; } = localJobs;

        public async Task RunAsync(AgentConfiguration configuration, CancellationToken cancellationToken)
        {
            events.Add("agent.start");
            Started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            finally
            {
                events.Add("agent.stop");
            }
        }
    }

    private sealed class AsyncLocalOwnerAgentRunner(
        LocalJobClient localJobs,
        IAgentManagementClient management,
        ConcurrentQueue<string> events)
        : IAgentRunner, IDesktopAgentRunner, IDesktopManagementSource, IDesktopLocalJobSource
    {
        public TaskCompletionSource Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public IAgentManagementClient Management { get; } = management;

        public ILocalJobClient LocalJobs => localJobs;

        public Task RunAsync(AgentConfiguration configuration, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("desktop must provide the shared agent lifetime");

        public async Task RunAsync(
            AgentConfiguration configuration,
            IAgentLifetime lifetime,
            CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
            finally
            {
                await localJobs.DisposeAsync();
                events.Enqueue("owner.disposed");
            }
        }
    }

    private sealed class BlockingCompleteLocalTransport(
        string spoolPath,
        ConcurrentQueue<string> events) : ILocalJobTransport
    {
        private readonly Guid _jobId = Guid.Parse("44444444-4444-4444-4444-444444444444");

        public TaskCompletionSource CompleteStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<LocalJobCreateOutcome> CreateLocalJobAsync(
            LocalJobCreateRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Directory.CreateDirectory(Path.Combine(spoolPath, _jobId.ToString("N")));
            return Task.FromResult(LocalJobCreateOutcome.FromLease(new LocalJobUploadLease(
                request.RequestId,
                _jobId,
                "00112233445566778899aabbccddeeff",
                $"{_jobId:N}/input.exe.part",
                DateTimeOffset.UtcNow.AddMinutes(10))));
        }

        public async Task<LocalJobAccepted> CompleteLocalJobAsync(
            LocalJobUploadCompleted completed,
            CancellationToken cancellationToken)
        {
            CompleteStarted.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                throw new InvalidOperationException("unreachable");
            }
            finally
            {
                events.Enqueue("complete.stop");
            }
        }

        public Task<LocalJobResultMetadata> GetLocalResultAsync(
            LocalJobResultRequest request,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("result not expected");
    }

    private sealed class RecordingLocalJobClient : ILocalJobClient
    {
        public Task<Guid> CreateAndUploadAsync(
            string path,
            SigningParameters parameters,
            IProgress<LocalCopyProgress>? progress,
            CancellationToken cancellationToken) => Task.FromResult(Guid.NewGuid());

        public Task SaveSignedCopyAsync(
            Guid jobId,
            string destinationPath,
            bool overwrite,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public void ReleaseAcceptedSource(Guid jobId)
        {
        }
    }

    private sealed class FixedManagementClient(ManagementSnapshot snapshot) : IAgentManagementClient
    {
        public event EventHandler? SnapshotChanged { add { } remove { } }

        public ManagementSnapshot? LatestSnapshot => snapshot;

        public Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken) =>
            Task.FromResult(snapshot);

        public Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken) =>
            Task.FromResult(snapshot);
    }

    private sealed class DelayedStopAgentRunner(List<string> events) : IAgentRunner
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource StopStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ReleaseStop { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task RunAsync(AgentConfiguration configuration, CancellationToken cancellationToken)
        {
            events.Add("agent.start");
            Started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                events.Add("agent.stop");
                StopStarted.TrySetResult();
                await ReleaseStop.Task;
            }
        }
    }

    private sealed class FailingAgentRunner : IAgentRunner
    {
        public Task RunAsync(AgentConfiguration configuration, CancellationToken cancellationToken) =>
            Task.FromException(new IOException("synthetic agent failure"));
    }

    private sealed class LifetimeAwareAgentRunner : IAgentRunner, IDesktopAgentRunner
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Completed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int SharedLifetimeCalls { get; private set; }

        public Task RunAsync(AgentConfiguration configuration, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("desktop must provide the shared agent lifetime");

        public async Task RunAsync(
            AgentConfiguration configuration,
            IAgentLifetime lifetime,
            CancellationToken cancellationToken)
        {
            SharedLifetimeCalls++;
            Started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, lifetime.ShutdownRequested);
            }
            finally
            {
                Completed.TrySetResult();
            }
        }
    }

    private sealed class UnrelatedCancellationAgentRunner(bool useDefaultCancellationToken)
        : IAgentRunner, IDesktopAgentRunner
    {
        private readonly CancellationToken _failureToken = useDefaultCancellationToken
            ? CancellationToken.None
            : new CancellationToken(canceled: true);

        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task RunAsync(AgentConfiguration configuration, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("desktop must provide the shared agent lifetime");

        public async Task RunAsync(
            AgentConfiguration configuration,
            IAgentLifetime lifetime,
            CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, lifetime.ShutdownRequested);
            }
            catch (OperationCanceledException) when (lifetime.ShutdownRequested.IsCancellationRequested)
            {
            }

            throw new OperationCanceledException(_failureToken);
        }
    }

    private sealed class FakeOwnedAgentLifetime : IOwnedAgentLifetime
    {
        private readonly CancellationTokenSource _shutdown = new();

        public CancellationToken ShutdownRequested => _shutdown.Token;

        public int DisposeCalls { get; private set; }

        public void RequestShutdown() => _shutdown.Cancel();

        public void Dispose()
        {
            DisposeCalls++;
            _shutdown.Dispose();
        }
    }

    private sealed class FixedAgentLifetimeFactory(IOwnedAgentLifetime lifetime) : IAgentLifetimeFactory
    {
        public IOwnedAgentLifetime Create() => lifetime;
    }

    private sealed class FixedConfigurationLoader(AgentConfiguration configuration) : IAgentConfigurationLoader
    {
        public Task<AgentConfiguration> LoadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(configuration);
        }
    }

    private sealed class NeverLoadConfigurationLoader : IAgentConfigurationLoader
    {
        public int Calls { get; private set; }

        public Task<AgentConfiguration> LoadAsync(CancellationToken cancellationToken)
        {
            Calls++;
            throw new InvalidOperationException("existing activation must not read configuration");
        }
    }

    private sealed class FixedSigningIdentity(string sid) : IDesktopSigningUserIdentity
    {
        public string GetCurrentSid() => sid;
    }

    private sealed class ThrowingSigningIdentity(Exception error) : IDesktopSigningUserIdentity
    {
        public string GetCurrentSid() => throw error;
    }

    private sealed class ThrowingWriter : StringWriter
    {
        public override void WriteLine(string? value) => throw new InvalidOperationException("writer_failed");

        public override Task WriteLineAsync(string? value) =>
            Task.FromException(new InvalidOperationException("writer_failed"));
    }

    private sealed class FixedActiveJobStateSource(ActiveJobState state) : IActiveJobStateSource
    {
        public ActiveJobState Current => state;
    }

    private sealed class ImmediateSingleInstanceActivator(IActivationServer server) : ISingleInstanceActivator
    {
        public async Task<int> RunSingleAsync(
            string signingUserSid,
            Func<IActivationServer, CancellationToken, Task<int>> startOwnedInstance,
            CancellationToken cancellationToken) =>
            await startOwnedInstance(server, cancellationToken);
    }

    private sealed class ExistingOnlyActivator : ISingleInstanceActivator
    {
        public Task<int> RunSingleAsync(
            string signingUserSid,
            Func<IActivationServer, CancellationToken, Task<int>> startOwnedInstance,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(0);
        }
    }

    private sealed class FixedDesktopRuntimeFactory(IDesktopRuntime runtime) : IDesktopRuntimeFactory
    {
        public IDesktopRuntime Create(string? uiTestTrayIdentity = null) => runtime;
    }

    private sealed class ThrowingDesktopRuntimeFactory : IDesktopRuntimeFactory
    {
        public IDesktopRuntime Create(string? uiTestTrayIdentity = null) =>
            throw new InvalidOperationException("synthetic runtime startup failure");
    }

    private sealed class RecordingDesktopRuntime :
        IDesktopRuntime,
        IServiceSettingsDialogServiceProvider
    {
        private readonly RecordingWindow _window;
        private readonly RecordingDispatcher _dispatcher;
        private readonly TaskCompletionSource<int> _exit = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public RecordingDesktopRuntime()
        {
            _dispatcher = new RecordingDispatcher();
            _window = new RecordingWindow(() => _exit.TrySetResult(0));
        }

        public IWindowController Window => _window;

        public IUiDispatcher Dispatcher => _dispatcher;

        public IServiceSettingsDialogService ServiceSettingsDialogs { get; } =
            new RecordingServiceSettingsDialogService();

        public int DispatcherInvocations => _dispatcher.Invocations;

        public int ShutdownRequests { get; private set; }

        public int DisposeCalls { get; private set; }

        public bool WasShownInitially { get; private set; }

        public int CloseForExitCalls => _window.CloseForExitCalls;

        public ShellViewModel? ViewModel { get; private set; }

        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task InitializeAsync(ShellViewModel viewModel, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ViewModel = viewModel;
            return Task.CompletedTask;
        }

        public Task<int> RunAsync(bool showInitially, CancellationToken cancellationToken)
        {
            WasShownInitially = showInitially;
            cancellationToken.Register(() => _exit.TrySetCanceled(cancellationToken));
            Started.TrySetResult();
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

        private sealed class RecordingDispatcher : IUiDispatcher
        {
            public int Invocations { get; private set; }

            public Task InvokeAsync(Action action, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                Invocations++;
                action();
                return Task.CompletedTask;
            }
        }

        private sealed class RecordingServiceSettingsDialogService : IServiceSettingsDialogService
        {
            public Task ShowAsync(
                ServiceSettingsDialogViewModel viewModel,
                CancellationToken cancellationToken)
            {
                ArgumentNullException.ThrowIfNull(viewModel);
                cancellationToken.ThrowIfCancellationRequested();
                return Task.CompletedTask;
            }
        }
    }

    private sealed class DelayedShutdownDesktopRuntime : IDesktopRuntime
    {
        private readonly TaskCompletionSource<int> _exit =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public IWindowController Window { get; } = new NullWindow();

        public IUiDispatcher Dispatcher { get; } = new InlineDispatcher();

        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ShutdownRequested { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int ShutdownRequests { get; private set; }

        public int DisposeCalls { get; private set; }

        public Task InitializeAsync(ShellViewModel viewModel, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }

        public Task<int> RunAsync(bool showInitially, CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            return _exit.Task;
        }

        public void RequestShutdown()
        {
            ShutdownRequests++;
            ShutdownRequested.TrySetResult();
        }

        public void ReleaseShutdown() => _exit.TrySetResult(0);

        public ValueTask DisposeAsync()
        {
            DisposeCalls++;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class DeadDispatcherDelayedShutdownRuntime : IDesktopRuntime
    {
        private readonly TaskCompletionSource<int> _exit =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly DeadDispatcher _dispatcher = new();

        public IWindowController Window { get; } = new NullWindow();

        public IUiDispatcher Dispatcher => _dispatcher;

        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ShutdownRequested { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int DispatcherCalls => _dispatcher.Calls;

        public int ShutdownRequests { get; private set; }

        public int DisposeCalls { get; private set; }

        public Task InitializeAsync(ShellViewModel viewModel, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }

        public Task<int> RunAsync(bool showInitially, CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            return _exit.Task;
        }

        public void RequestShutdown()
        {
            ShutdownRequests++;
            ShutdownRequested.TrySetResult();
        }

        public void ReleaseShutdown() => _exit.TrySetResult(0);

        public ValueTask DisposeAsync()
        {
            DisposeCalls++;
            return ValueTask.CompletedTask;
        }

        private sealed class DeadDispatcher : IUiDispatcher
        {
            public int Calls { get; private set; }

            public Task InvokeAsync(Action action, CancellationToken cancellationToken)
            {
                Calls++;
                throw new InvalidOperationException("dispatcher has shut down");
            }
        }
    }

    private sealed class SystemShutdownDesktopRuntime : IDesktopRuntime
    {
        private readonly DesktopShutdownCoordinator _shutdown = new();
        private readonly TaskCompletionSource<int> _exit = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public SystemShutdownDesktopRuntime()
        {
            UnsafeWindow = new ThrowingWindow();
            Window = new ShutdownAwareWindowController(_shutdown, UnsafeWindow);
        }

        public IWindowController Window { get; }

        public IUiDispatcher Dispatcher { get; } = new InlineDispatcher();

        public ThrowingWindow UnsafeWindow { get; }

        public ShellViewModel? ViewModel { get; private set; }

        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int DisposeCalls { get; private set; }

        public Task InitializeAsync(ShellViewModel viewModel, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ViewModel = viewModel;
            return Task.CompletedTask;
        }

        public Task<int> RunAsync(bool showInitially, CancellationToken cancellationToken)
        {
            cancellationToken.Register(RequestShutdown);
            Started.TrySetResult();
            return _exit.Task;
        }

        public void CompleteSystemShutdown()
        {
            _shutdown.TryBegin();
            _exit.TrySetResult(0);
        }

        public void RequestShutdown()
        {
            _shutdown.TryBegin();
            _exit.TrySetResult(0);
        }

        public ValueTask DisposeAsync()
        {
            DisposeCalls++;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ThrowingWindow : IWindowController
    {
        public int CloseCalls { get; private set; }

        public int NoticeCalls { get; private set; }

        public void ShowRestoreActivate() => throw new InvalidOperationException("dispatcher has shut down");

        public void Hide() => throw new InvalidOperationException("dispatcher has shut down");

        public void CloseForExit()
        {
            CloseCalls++;
            throw new InvalidOperationException("dispatcher has shut down");
        }

        public void ShowNotice(string message)
        {
            NoticeCalls++;
            throw new InvalidOperationException("dispatcher has shut down");
        }
    }

    private sealed class MinimalTrayPlatform : ITrayIconPlatform
    {
        private EventHandler<TrayCommandEventArgs>? _commandInvoked;

        public event EventHandler<TrayCommandEventArgs>? CommandInvoked
        {
            add => _commandInvoked += value;
            remove => _commandInvoked -= value;
        }

        public int DisposeCalls { get; private set; }

        public int SubscriberCount => _commandInvoked?.GetInvocationList().Length ?? 0;

        public void Initialize(IReadOnlyList<TrayMenuEntry> entries, string statusText)
        {
        }

        public void SetStatus(string statusText)
        {
        }

        public void Dispose()
        {
            DisposeCalls++;
            _commandInvoked = null;
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
        public void ShowRestoreActivate()
        {
        }

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

    private sealed class RecordingWindow(Action closeForExit) : IWindowController
    {
        public int CloseForExitCalls { get; private set; }

        public void ShowRestoreActivate()
        {
        }

        public void Hide()
        {
        }

        public void CloseForExit()
        {
            CloseForExitCalls++;
            closeForExit();
        }

        public void ShowNotice(string message)
        {
        }
    }
}
