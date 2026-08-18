using SimplySignAuto.Agent;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.App;
using SimplySignAuto.App.Commands;
using SimplySignAuto.App.UI;
using SimplySignAuto.App.UI.ViewModels;
using SimplySignAuto.Core.Otp;
using SimplySignAuto.Protocol;
using SimplySignAuto.Service;

namespace SimplySignAuto.UI.Tests;

public sealed class ServiceSettingsViewModelTests
{
    [Fact]
    public async Task Deferred_dialog_service_releases_the_target_and_can_rebind()
    {
        var inner = new RecordingDialogService();
        var deferred = new DeferredServiceSettingsDialogService();
        using var vm = DialogViewModel(Summary());

        deferred.SetTarget(inner);
        await deferred.ShowAsync(vm, default);
        Assert.Equal(1, inner.ShowCalls);

        deferred.ClearTarget();
        var unbound = await Assert.ThrowsAsync<InvalidOperationException>(
            () => deferred.ShowAsync(vm, default));
        Assert.Equal("service_settings_dialog_not_initialized", unbound.Message);

        deferred.SetTarget(inner);
        await deferred.ShowAsync(vm, default);
        Assert.Equal(2, inner.ShowCalls);
    }

    [Fact]
    public async Task Page_loads_safe_summary_and_modal_success_refreshes_the_same_page()
    {
        var original = Summary();
        var changed = Summary(port: 7080, retention: 0);
        var administration = new AdministrationFake(original, changed);
        var editor = new EditorFake(new ServiceConfigurationEditResult(changed, null));
        var dialogs = new ApplyingDialogService();
        var clipboard = new ClipboardFake();
        var vm = new ServiceSettingsViewModel(
            administration,
            editor,
            dialogs,
            clipboard,
            new InlineDispatcher());

        await vm.LoadAsync(default);
        var opened = await vm.EditAsync(default);

        Assert.True(opened);
        Assert.Equal(1, dialogs.ShowCalls);
        Assert.Equal(1, editor.ApplyCalls);
        Assert.Equivalent(changed, vm.Settings, strict: true);
        Assert.Equal("版本 1.0.0", vm.ProductVersionText);
        Assert.Equal("512 MB", vm.MaximumUploadText);
        Assert.Null(vm.ErrorCode);
    }

    [Fact]
    public async Task Product_version_text_keeps_prerelease_and_never_shows_build_metadata()
    {
        var summary = Summary(identity: "0.2.0-0.dev.17+build.7");
        var vm = PageViewModel(new AdministrationFake(summary));

        await vm.LoadAsync(default);

        Assert.Equal("版本 0.2.0-0.dev.17", vm.ProductVersionText);
        Assert.DoesNotContain("build.7", vm.ProductVersionText, StringComparison.Ordinal);
    }

    [Fact]
    public void Dialog_displays_zero_retention_as_permanent()
    {
        using var vm = DialogViewModel(Summary());
        vm.RetentionHoursText = "0";

        Assert.Equal("永久保留", vm.RetentionDisplay);

        vm.RetentionHoursText = "168";
        Assert.Equal("168 小时", vm.RetentionDisplay);
    }

    [Theory]
    [InlineData("", "24")]
    [InlineData("letters", "24")]
    [InlineData("2147483648", "24")]
    [InlineData("+1", "24")]
    [InlineData("-1", "24")]
    [InlineData("0", "24")]
    [InlineData("65536", "24")]
    [InlineData("7080", "")]
    [InlineData("7080", "letters")]
    [InlineData("7080", "2147483648")]
    [InlineData("7080", "+1")]
    [InlineData("7080", "-1")]
    [InlineData("7080", "169")]
    public async Task Dialog_rejects_invalid_raw_numeric_input_without_calling_editor(
        string listenPort,
        string retentionHours)
    {
        var editor = new EditorFake(new ServiceConfigurationEditResult(Summary(), null));
        using var vm = DialogViewModel(Summary(), editor: editor);
        vm.ListenPortText = listenPort;
        vm.RetentionHoursText = retentionHours;

        var applied = await vm.ApplyAsync(default);

        Assert.False(applied);
        Assert.Equal(ServiceSettingsDialogState.Failed, vm.State);
        Assert.Equal("configure_service_input_invalid", vm.ErrorCode);
        Assert.Equal(0, editor.ApplyCalls);
    }

    [Theory]
    [InlineData("1")]
    [InlineData("65535")]
    public async Task Dialog_accepts_listen_port_boundaries(string listenPort)
    {
        var changed = Summary(port: int.Parse(listenPort, System.Globalization.CultureInfo.InvariantCulture));
        var editor = new EditorFake(new ServiceConfigurationEditResult(changed, null));
        using var vm = DialogViewModel(
            Summary(),
            new AdministrationFake(changed),
            editor);
        vm.ListenPortText = listenPort;

        Assert.True(await vm.ApplyAsync(default));
        Assert.Equal(1, editor.ApplyCalls);
    }

    [Theory]
    [InlineData("0", "永久保留")]
    [InlineData("168", "168 小时")]
    public async Task Dialog_accepts_retention_boundaries(string retentionHours, string display)
    {
        var changed = Summary(retention: int.Parse(retentionHours, System.Globalization.CultureInfo.InvariantCulture));
        var editor = new EditorFake(new ServiceConfigurationEditResult(changed, null));
        using var vm = DialogViewModel(
            Summary(),
            new AdministrationFake(changed),
            editor);
        vm.RetentionHoursText = retentionHours;

        Assert.Equal(display, vm.RetentionDisplay);
        Assert.True(await vm.ApplyAsync(default));
        Assert.Equal(1, editor.ApplyCalls);
    }

    [Fact]
    public async Task Dialog_has_observable_apply_restart_reconnect_success_states_and_one_mutation()
    {
        var original = Summary();
        var changed = Summary(port: 7080, retention: 0);
        var editor = new EditorFake(new ServiceConfigurationEditResult(changed, null));
        var administration = new AdministrationFake(original, changed);
        using var vm = DialogViewModel(
            original,
            administration,
            editor,
            reconnectAttempts: 2);
        vm.ListenPortText = "7080";
        vm.RetentionHoursText = "0";
        var states = new List<ServiceSettingsDialogState> { vm.State };
        vm.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(ServiceSettingsDialogViewModel.State))
            {
                states.Add(vm.State);
            }
        };

        var applied = await vm.ApplyAsync(default);

        Assert.True(applied);
        Assert.Equal(
            [
                ServiceSettingsDialogState.Editing,
                ServiceSettingsDialogState.Applying,
                ServiceSettingsDialogState.Restarting,
                ServiceSettingsDialogState.Reconnecting,
                ServiceSettingsDialogState.Succeeded,
            ],
            states);
        Assert.Equal(1, editor.ApplyCalls);
        Assert.Equivalent(changed, vm.ConfirmedSummary, strict: true);
        Assert.True(vm.CanClose);
    }

    [Fact]
    public async Task Duplicate_submit_is_rejected_without_a_second_editor_call()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var editor = new EditorFake(
            new ServiceConfigurationEditResult(Summary(), null),
            beforeReturn: token => release.Task.WaitAsync(token));
        using var vm = DialogViewModel(Summary(), editor: editor);
        var first = vm.ApplyAsync(default);
        await editor.Entered.Task;

        var duplicate = await vm.ApplyAsync(default);

        Assert.False(duplicate);
        Assert.Equal(1, editor.ApplyCalls);
        release.TrySetResult();
        Assert.True(await first);
    }

    [Fact]
    public async Task Confirmed_rotation_timeout_keeps_one_time_token_until_copy_and_acknowledgement()
    {
        var original = Summary();
        var changed = Summary(port: 7444);
        var token = new string('T', 43);
        var clipboard = new ClipboardFake();
        var editor = new EditorFake(new ServiceConfigurationEditResult(changed, token));
        var administration = new AdministrationFake(original, original, original);
        using var vm = DialogViewModel(
            original,
            administration,
            editor,
            clipboard,
            reconnectAttempts: 2);
        vm.ListenPortText = "7444";
        vm.RotateToken = true;

        var applied = await vm.ApplyAsync(default);

        Assert.False(applied);
        Assert.Equal(ServiceSettingsDialogState.Failed, vm.State);
        Assert.Equal("management_unavailable", vm.ErrorCode);
        Assert.Equal(token, vm.OneTimeApiToken);
        Assert.False(vm.CanClose);
        Assert.DoesNotContain(token, vm.ToString(), StringComparison.Ordinal);

        Assert.True(vm.CopyOneTimeToken());
        Assert.Equal(token, clipboard.Text);
        vm.AcknowledgeOneTimeToken();

        Assert.Null(vm.OneTimeApiToken);
        Assert.True(vm.CanClose);
        Assert.False(vm.CopyOneTimeToken());
    }

    [Fact]
    public async Task Editor_failure_surfaces_the_stable_error()
    {
        var editor = new EditorFake(
            new ServiceConfigurationEditResult(Summary(), null),
            static _ => throw new ConfigureServiceException("configure_service_failed"));
        using var vm = DialogViewModel(Summary(), editor: editor);

        var applied = await vm.ApplyAsync(default);

        Assert.False(applied);
        Assert.Equal("configure_service_failed", vm.ErrorCode);
        Assert.Equal(1, editor.ApplyCalls);
    }

    [Fact]
    public async Task Editor_cancellation_propagates()
    {
        var editor = new EditorFake(
            new ServiceConfigurationEditResult(Summary(), null),
            static cancellationToken => Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken));
        using var vm = DialogViewModel(Summary(), editor: editor);
        using var cancellation = new CancellationTokenSource();
        var apply = vm.ApplyAsync(cancellation.Token);
        await editor.Entered.Task;

        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => apply);
        Assert.Equal(1, editor.ApplyCalls);
    }

    [Fact]
    public async Task Ui_boundary_swallows_expected_cancellation_without_changing_settings_error()
    {
        var vm = PageViewModel(new AdministrationFake(Summary()));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await UiAsyncExceptionBoundary.RunAsync(
            () => Task.FromCanceled(cancellation.Token),
            () => vm.ReportUiFailureAsync("management_unavailable"));

        Assert.Null(vm.ErrorCode);
    }

    [Fact]
    public async Task Ui_boundary_contains_shutdown_during_stable_error_reporting()
    {
        await UiAsyncExceptionBoundary.RunAsync(
            () => Task.FromException(new IOException("native failure")),
            () => Task.FromException(new ObjectDisposedException("dispatcher")));
    }

    [Fact]
    public void Service_settings_component_assemblies_share_exact_full_product_identity()
    {
        var appIdentity = ApplicationVersion.ReadIdentity(typeof(Program).Assembly);
        var agentIdentity = ApplicationVersion.ReadIdentity(typeof(AgentHost).Assembly);
        var serviceIdentity = ApplicationVersion.ReadIdentity(typeof(ServiceHost).Assembly);

        Assert.Equal(appIdentity, agentIdentity);
        Assert.Equal(appIdentity, serviceIdentity);
        var expectedIdentity = Environment.GetEnvironmentVariable(
            "SIMPLYSIGNAUTO_TEST_EXPECTED_PRODUCT_IDENTITY");
        if (!string.IsNullOrEmpty(expectedIdentity))
        {
            Assert.Equal(expectedIdentity, appIdentity);
        }
    }

    private static ServiceSettingsViewModel PageViewModel(IAgentAdministrationClient administration) =>
        new(
            administration,
            new EditorFake(new ServiceConfigurationEditResult(Summary(), null)),
            new ApplyingDialogService(),
            new ClipboardFake(),
            new InlineDispatcher());

    private static ServiceSettingsDialogViewModel DialogViewModel(
        ServiceSettingsSummary summary,
        IAgentAdministrationClient? administration = null,
        IServiceConfigurationEditor? editor = null,
        IClipboardService? clipboard = null,
        int reconnectAttempts = 1) =>
        new(
            summary,
            editor ?? new EditorFake(new ServiceConfigurationEditResult(summary, null)),
            administration ?? new AdministrationFake(summary),
            clipboard ?? new ClipboardFake(),
            new InlineDispatcher(),
            reconnectAttempts,
            static (_, cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                return Task.CompletedTask;
            });

    private static ServiceSettingsSummary Summary(
        string identity = "1.0.0",
        int port = 7080,
        int retention = 24) =>
        new(
            port,
            ServiceSettingsSummary.FixedMaximumUploadBytes,
            retention,
            identity);

    private sealed class AdministrationFake : IAgentAdministrationClient
    {
        private readonly Queue<ServiceSettingsSummary> _summaries;
        private ServiceSettingsSummary _last;

        public AdministrationFake(params ServiceSettingsSummary[] summaries)
        {
            Assert.NotEmpty(summaries);
            _summaries = new Queue<ServiceSettingsSummary>(summaries);
            _last = summaries[^1];
        }

        public Task<JobPageResponse> GetJobPageAsync(JobPageCursor? cursor, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_summaries.TryDequeue(out var summary))
            {
                _last = summary;
            }

            return Task.FromResult(_last);
        }

        public Task SaveOtpAsync(OtpauthProfile profile, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class EditorFake(
        ServiceConfigurationEditResult result,
        Func<CancellationToken, Task>? beforeReturn = null) : IServiceConfigurationEditor
    {
        public int ApplyCalls { get; private set; }
        public TaskCompletionSource Entered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<ServiceConfigurationEditResult> ApplyAsync(
            ServiceConfigurationEditRequest request,
            CancellationToken cancellationToken)
        {
            ApplyCalls++;
            Entered.TrySetResult();
            if (beforeReturn is not null)
            {
                await beforeReturn(cancellationToken);
            }

            return result;
        }
    }

    private sealed class ApplyingDialogService : IServiceSettingsDialogService
    {
        public int ShowCalls { get; private set; }

        public async Task ShowAsync(
            ServiceSettingsDialogViewModel viewModel,
            CancellationToken cancellationToken)
        {
            ShowCalls++;
            _ = await viewModel.ApplyAsync(cancellationToken);
        }
    }

    private sealed class RecordingDialogService : IServiceSettingsDialogService
    {
        public int ShowCalls { get; private set; }

        public Task ShowAsync(
            ServiceSettingsDialogViewModel viewModel,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(viewModel);
            cancellationToken.ThrowIfCancellationRequested();
            ShowCalls++;
            return Task.CompletedTask;
        }
    }

    private sealed class ClipboardFake : IClipboardService
    {
        public string? Text { get; private set; }
        public string? GetText() => Text;
        public void SetText(string value) => Text = value;
        public void Clear() => Text = null;
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
}
