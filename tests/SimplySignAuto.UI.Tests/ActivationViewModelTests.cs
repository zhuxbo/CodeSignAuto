using System.Security.Cryptography;
using System.Text;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.App.UI;
using SimplySignAuto.App.UI.Status;
using SimplySignAuto.App.UI.ViewModels;
using SimplySignAuto.Core.Otp;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.UI.Tests;

public sealed class ActivationViewModelTests
{
    private const string Uri = "otpauth://totp/Certum:user%40example.test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30&issuer=Certum";

    [Fact]
    public async Task Activation_shows_all_discovered_certificates_in_three_lines()
    {
        var backend = new BackendFake
        {
            Snapshot = Snapshot(active: false, certificates:
            [
                Summary("Code Signing", "52A1B4C9", true, false, true, null),
                Summary("Expired", "6F09D233", false, false, true, "expired"),
                Summary("Stale", "7A10E344", false, false, false, "catalog_stale"),
            ]),
        };
        using var vm = new ActivationViewModel(backend, backend, backend);

        Assert.Equal(3, vm.Certificates.Count);
        Assert.All(vm.Certificates, card => Assert.Equal(3, card.LogicalRows.Count));
        Assert.Equal("CN: Expired", vm.Certificates[1].LogicalRows[0]);
        Assert.Equal("序列号: 6F09D233", vm.Certificates[1].LogicalRows[1]);
        Assert.Equal("已过期", vm.Certificates[1].StatusText);
    }

    [Fact]
    public async Task Activation_serial_supports_selection_ctrl_c_and_double_click_full_copy()
    {
        var backend = new BackendFake
        {
            Snapshot = Snapshot(active: false, certificates:
            [
                Summary("Code Signing", "52A1B4C9", true, false, true, null),
            ]),
        };
        using var vm = new ActivationViewModel(backend, backend, backend);

        Assert.True(await vm.CopyCertificateSerialAsync(vm.Certificates[0], default));
        Assert.Equal("52A1B4C9", backend.ClipboardText);
    }

    [Fact]
    public async Task Success_saves_strict_profile_clears_input_and_exact_clipboard_only()
    {
        var backend = new BackendFake { ClipboardText = Uri };
        var vm = new ActivationViewModel(backend, backend, backend);
        vm.OtpauthInput = Uri;

        var saved = await vm.ValidateAndSaveAsync(Uri, default);

        Assert.True(saved);
        Assert.Equal(string.Empty, vm.OtpauthInput);
        Assert.True(backend.ClipboardCleared);
        Assert.Equal("Certum · user@example.test · 6 位 / 30 秒", vm.DisplaySummary);
        var profile = Assert.Single(backend.Saved);
        Assert.Equal("SHA256", profile.Algorithm);
        Assert.DoesNotContain(profile.Secret, vm.DisplaySummary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Invalid_or_changed_clipboard_never_leaks_or_deletes_new_content()
    {
        var backend = new BackendFake { ClipboardText = "new clipboard content" };
        var vm = new ActivationViewModel(backend, backend, backend) { OtpauthInput = "invalid-secret" };

        var saved = await vm.ValidateAndSaveAsync("invalid-secret", default);

        Assert.False(saved);
        Assert.Equal(string.Empty, vm.OtpauthInput);
        Assert.Empty(backend.Saved);
        Assert.False(backend.ClipboardCleared);
        Assert.Equal("otpauth_invalid", vm.ErrorCode);
        Assert.DoesNotContain("invalid-secret", vm.DisplaySummary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Cancellation_while_waiting_for_operation_gate_still_clears_activation_input()
    {
        var backend = new BackendFake { BlockFirstSave = true };
        var vm = new ActivationViewModel(backend, backend, backend) { OtpauthInput = Uri };
        var first = vm.ValidateAndSaveAsync(Uri, default);
        await backend.SaveEntered.Task.WaitAsync(TimeSpan.FromSeconds(1));
        vm.OtpauthInput = Uri;
        using var cancellation = new CancellationTokenSource();

        var waiting = vm.ValidateAndSaveAsync(Uri, cancellation.Token);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        Assert.Equal(string.Empty, vm.OtpauthInput);
        backend.ReleaseSave.TrySetResult();
        Assert.True(await first);
    }

    [Fact]
    public async Task Login_validation_is_disabled_while_job_state_is_active_or_unknown()
    {
        var backend = new BackendFake { Snapshot = Snapshot(active: true) };
        var vm = new ActivationViewModel(backend, backend, backend);

        Assert.False(await vm.ValidateLoginAsync(default));
        backend.Snapshot = null;
        Assert.False(await vm.ValidateLoginAsync(default));

        Assert.Equal(0, backend.ReloginCalls);
    }

    [Fact]
    public async Task Login_validation_maps_management_disconnect_to_a_stable_ui_error()
    {
        var backend = new BackendFake
        {
            Snapshot = Snapshot(active: false),
            ReloginError = new ManagementUnavailableException(
                Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")),
        };
        using var vm = new ActivationViewModel(
            backend,
            backend,
            backend,
            new AllowRelogin());

        var result = await vm.ValidateLoginAsync(default);

        Assert.False(result);
        Assert.Equal(1, backend.ReloginCalls);
        Assert.Equal("management_unavailable", vm.ErrorCode);
    }

    [Fact]
    public async Task Management_disconnect_exposes_actionable_startup_guidance()
    {
        var backend = new BackendFake
        {
            Snapshot = Snapshot(active: false),
            ReloginError = new ManagementUnavailableException(
                Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")),
        };
        using var vm = new ActivationViewModel(
            backend,
            backend,
            backend,
            new AllowRelogin());

        Assert.False(await vm.ValidateLoginAsync(default));

        Assert.Equal("management_unavailable", vm.ErrorCode);
        Assert.Equal(
            "签名代理尚未就绪。首次安装后请先重启 Windows；已重启时请等待服务启动后重试。",
            vm.ErrorText);
    }

    [Fact]
    public async Task Clear_and_logout_requires_confirmation_and_clears_all_activation_display_state()
    {
        var time = new ControllableTimeProvider(DateTimeOffset.Parse("2026-08-09T00:00:01Z"));
        var backend = new BackendFake(time)
        {
            Snapshot = Snapshot(
                active: false,
                certificates:
                [
                    Summary("Document Signing", "52A1B4C9", false, true, true, null),
                ]),
        };
        using var vm = new ActivationViewModel(
            backend,
            backend,
            backend,
            clearConfirmation: new AllowClearOtp(),
            totpProvider: backend,
            timeProvider: time);
        vm.OtpauthInput = Uri;
        Assert.True(await vm.GenerateTotpAsync(default));

        var cleared = await vm.ClearOtpAndLogoutAsync(default);

        Assert.True(cleared);
        Assert.Equal(1, backend.ClearOtpAndLogoutCalls);
        Assert.Equal(string.Empty, vm.OtpauthInput);
        Assert.False(vm.HasTotpCode);
        Assert.Empty(vm.Certificates);
        Assert.Equal("激活内容已清除，SimplySign 已退出。", vm.DisplaySummary);
        Assert.Null(vm.ErrorCode);
    }

    [Fact]
    public async Task Clear_and_logout_is_disabled_for_active_jobs_and_confirmation_denial()
    {
        var backend = new BackendFake { Snapshot = Snapshot(active: true) };
        using var active = new ActivationViewModel(
            backend,
            backend,
            backend,
            clearConfirmation: new AllowClearOtp());

        Assert.False(await active.ClearOtpAndLogoutAsync(default));
        Assert.Equal(0, backend.ClearOtpAndLogoutCalls);

        backend.Snapshot = Snapshot(active: false);
        using var denied = new ActivationViewModel(backend, backend, backend);
        Assert.False(await denied.ClearOtpAndLogoutAsync(default));
        Assert.Equal(0, backend.ClearOtpAndLogoutCalls);
    }

    [Fact]
    public async Task Diagnostic_json_uses_fixed_redacted_schema()
    {
        var backend = new BackendFake { Snapshot = Snapshot(active: false) };
        var vm = new ActivationViewModel(backend, backend, backend);

        var json = await vm.CopyRedactedDiagnosticsAsync(default);

        Assert.Contains("\"schemaVersion\":1", json, StringComparison.Ordinal);
        Assert.Contains("\"agentSessionValid\":true", json, StringComparison.Ordinal);
        Assert.Contains("\"certificateNotAfterUtc\":\"2027-08-09T00:00:00+00:00\"", json, StringComparison.Ordinal);
        Assert.Contains("\"certificateThumbprintSuffix\":\"89ABCDEF\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("S-1-", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("otpauth", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("JBSWY", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("path", json, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(json, backend.ClipboardText);
    }

    [Fact]
    public async Task Ui_boundary_reduces_unexpected_activation_failure_to_stable_error()
    {
        var backend = new BackendFake();
        var vm = new ActivationViewModel(backend, backend, backend);

        await UiAsyncExceptionBoundary.RunAsync(
            () => Task.FromException(new ArgumentException("C:\\secret\\activation.txt")),
            () => vm.ReportUiFailureAsync("management_unavailable"));

        Assert.Equal("management_unavailable", vm.ErrorCode);
    }

    [Fact]
    public async Task Legacy_capability_states_cannot_hide_public_certificate_cards()
    {
        var backend = new BackendFake
        {
            Snapshot = Snapshot(
                active: false,
                StateCapability("authenticode", SimplySignSessionState.Failed),
                StateCapability("pdf", SimplySignSessionState.WaitToken),
                [Summary("Visible", "52A1B4C9", true, false, true, null)]),
        };
        using var activation = new ActivationViewModel(backend, backend, backend);
        using var overview = new OverviewViewModel(backend, new AllowRelogin(), () => { });

        await overview.RefreshAsync(default);

        Assert.Equal("已就绪", overview.AuthenticodeStatusText);
        Assert.Equal("不可用", overview.PdfStatusText);
        Assert.Equal("52A1B4C9", Assert.Single(activation.Certificates).SerialNumber);
    }

    [Fact]
    public async Task Empty_certificate_catalog_makes_both_overview_capabilities_unavailable()
    {
        var backend = new BackendFake
        {
            Snapshot = Snapshot(
                active: false,
                CapabilitySnapshot.NotConfigured(),
                CapabilitySnapshot.NotConfigured()),
        };
        using var activation = new ActivationViewModel(backend, backend, backend);
        using var overview = new OverviewViewModel(backend, new AllowRelogin(), () => { });

        await overview.RefreshAsync(default);

        Assert.Equal("不可用", overview.AuthenticodeStatusText);
        Assert.Equal("不可用", overview.PdfStatusText);
        Assert.Empty(activation.Certificates);
    }

    [Fact]
    public async Task Current_six_digit_value_is_generated_only_on_demand_with_manual_login_guidance()
    {
        var time = new ControllableTimeProvider(DateTimeOffset.Parse("2026-08-09T00:00:01Z"));
        var backend = new BackendFake(time);
        using var vm = new ActivationViewModel(
            backend,
            backend,
            backend,
            totpProvider: backend,
            timeProvider: time);

        Assert.False(vm.HasTotpCode);
        Assert.Equal(0, backend.GenerateTotpCalls);
        Assert.Equal(0, backend.ClipboardSetCalls);

        Assert.True(await vm.GenerateTotpAsync(default));

        Assert.True(vm.HasTotpCode);
        Assert.True(CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(backend.GeneratedCode),
            Encoding.UTF8.GetBytes(vm.TotpCode)));
        Assert.Equal(6, vm.TotpCode.Length);
        Assert.Equal(29, vm.TotpRemainingSeconds);
        Assert.Equal(1, backend.GenerateTotpCalls);
        Assert.Equal(0, backend.ClipboardSetCalls);
        Assert.Equal("用于其他机器人工登录；本机自动登录无需显示", vm.TotpInstruction);
    }

    [Fact]
    public async Task Crossing_the_window_clears_the_display_and_exact_matching_clipboard_only()
    {
        var time = new ControllableTimeProvider(DateTimeOffset.Parse("2026-08-09T00:00:28Z"));
        var backend = new BackendFake(time);
        using var vm = new ActivationViewModel(
            backend,
            backend,
            backend,
            totpProvider: backend,
            timeProvider: time);
        Assert.True(await vm.GenerateTotpAsync(default));
        Assert.True(await vm.CopyTotpAsync(default));

        time.Advance(TimeSpan.FromSeconds(2));
        await WaitUntilAsync(() => !vm.HasTotpCode);

        Assert.Equal(string.Empty, vm.TotpCode);
        Assert.Equal(0, vm.TotpRemainingSeconds);
        Assert.True(backend.ClipboardCleared);

        backend.ResetClipboardTracking();
        time.Advance(TimeSpan.FromSeconds(1));
        Assert.True(await vm.GenerateTotpAsync(default));
        Assert.True(await vm.CopyTotpAsync(default));
        backend.ClipboardText = "operator replacement";

        time.Advance(TimeSpan.FromSeconds(29));
        await WaitUntilAsync(() => !vm.HasTotpCode);

        Assert.False(backend.ClipboardCleared);
        Assert.Equal("operator replacement", backend.ClipboardText);
    }

    [Fact]
    public async Task Leaving_hiding_reimporting_and_dispose_clear_the_display_without_automatic_copy()
    {
        var time = new ControllableTimeProvider(DateTimeOffset.Parse("2026-08-09T00:00:01Z"));
        var backend = new BackendFake(time);
        var vm = new ActivationViewModel(
            backend,
            backend,
            backend,
            totpProvider: backend,
            timeProvider: time);

        Assert.True(await vm.GenerateTotpAsync(default));
        vm.DeactivateTotp();
        Assert.False(vm.HasTotpCode);

        Assert.True(await vm.GenerateTotpAsync(default));
        vm.BeginOtpImport();
        Assert.False(vm.HasTotpCode);

        Assert.True(await vm.GenerateTotpAsync(default));
        vm.Dispose();
        Assert.Equal(string.Empty, vm.TotpCode);
        Assert.Equal(0, backend.ClipboardSetCalls);
    }

    [Fact]
    public async Task Reimport_and_diagnostics_never_retain_or_serialize_the_displayed_value()
    {
        var time = new ControllableTimeProvider(DateTimeOffset.Parse("2026-08-09T00:00:01Z"));
        var backend = new BackendFake(time) { Snapshot = Snapshot(active: false) };
        using var vm = new ActivationViewModel(
            backend,
            backend,
            backend,
            totpProvider: backend,
            timeProvider: time);
        Assert.True(await vm.GenerateTotpAsync(default));
        var displayed = vm.TotpCode;

        var json = await vm.CopyRedactedDiagnosticsAsync(default);

        Assert.False(json.Contains(displayed, StringComparison.Ordinal));
        Assert.True(vm.HasTotpCode);

        Assert.True(await vm.ValidateAndSaveAsync(Uri, default));
        Assert.False(vm.HasTotpCode);
    }

    private static ManagementSnapshot Snapshot(
        bool active,
        CapabilitySnapshot? authenticode = null,
        CapabilitySnapshot? pdf = null,
        IReadOnlyList<CertificateSummary>? certificates = null)
    {
        authenticode ??= ProtocolV3TestFixtures.Ready("authenticode");
        pdf ??= ProtocolV3TestFixtures.Ready("pdf");
        var now = DateTimeOffset.Parse("2026-08-09T00:00:00Z");
        return new ManagementSnapshot(
            1, now, Guid.NewGuid(), true, true, 7, 7, 10, true, 7,
            authenticode, pdf, 0, active ? 1 : 0,
            active ? new CurrentJobSnapshot(Guid.NewGuid(), "pdf", "signing", "signing", now.AddSeconds(-5), 5) : null,
            [],
            1,
            certificates ?? []);
    }

    private static CertificateSummary Summary(
        string commonName,
        string serial,
        bool authenticode,
        bool pdf,
        bool current,
        string? reason) =>
        new(
            commonName,
            serial,
            DateTimeOffset.Parse("2025-01-01T00:00:00Z"),
            DateTimeOffset.Parse("2027-01-01T00:00:00Z"),
            authenticode,
            pdf,
            current,
            reason);

    private static CapabilitySnapshot StateCapability(
        string alias,
        SimplySignSessionState state,
        long generation = 1)
    {
        var reason = state switch
        {
            SimplySignSessionState.Unknown => "unknown",
            SimplySignSessionState.Checking => "checking",
            SimplySignSessionState.Ready => "ready",
            SimplySignSessionState.LoginRequired => "login_required",
            SimplySignSessionState.Loginning => "loginning",
            SimplySignSessionState.WaitToken => "wait_token",
            SimplySignSessionState.Failed => "failed",
            _ => throw new ArgumentOutOfRangeException(nameof(state)),
        };
        var ready = state == SimplySignSessionState.Ready;
        var now = DateTimeOffset.Parse("2026-08-09T00:00:00Z");
        var session = new SimplySignSessionSnapshot(
            state,
            generation,
            now,
            now,
            ready ? 7 : null,
            ready,
            ready,
            ready,
            ready,
            ready,
            ready,
            ready,
            reason,
            0,
            null);
        return new CapabilitySnapshot(
            true,
            ready,
            ready,
            ready ? "34567890" : null,
            ready,
            ready,
            ready ? "abcdef12" : null,
            ready,
            ready,
            ready ? "1234abcd" : null,
            ready,
            reason,
            ready ? DateTimeOffset.Parse("2027-08-09T00:00:00Z") : null,
            ready ? "89ABCDEF" : null,
            session);
    }

    private static async Task WaitUntilAsync(Func<bool> predicate)
    {
        var deadline = DateTime.UtcNow.AddSeconds(1);
        while (!predicate() && DateTime.UtcNow < deadline)
        {
            await Task.Yield();
        }

        Assert.True(predicate());
    }

    private sealed class BackendFake :
        IAgentManagementClient,
        IAgentAdministrationClient,
        IClipboardService,
        ILocalTotpCodeProvider
    {
        private readonly TimeProvider _timeProvider;

        public BackendFake(TimeProvider? timeProvider = null) =>
            _timeProvider = timeProvider ?? TimeProvider.System;

        public event EventHandler? SnapshotChanged { add { } remove { } }
        public ManagementSnapshot? Snapshot { get; set; }
        public ManagementSnapshot? LatestSnapshot => Snapshot;
        public List<OtpauthProfile> Saved { get; } = [];
        public string? ClipboardText { get; set; }
        public bool ClipboardCleared { get; private set; }
        public int ClipboardSetCalls { get; private set; }
        public int GenerateTotpCalls { get; private set; }
        public string GeneratedCode { get; } = new('7', 6);
        public int ReloginCalls { get; private set; }
        public int ClearOtpAndLogoutCalls { get; private set; }
        public bool BlockFirstSave { get; init; }
        public Exception? ReloginError { get; init; }
        public TaskCompletionSource SaveEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseSave { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken) => Task.FromResult(Snapshot!);
        public Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken)
        {
            ReloginCalls++;
            if (ReloginError is not null)
            {
                return Task.FromException<ManagementSnapshot>(ReloginError);
            }

            return Task.FromResult(Snapshot!);
        }
        public Task<ManagementSnapshot> ClearOtpAndLogoutAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ClearOtpAndLogoutCalls++;
            Snapshot = ActivationViewModelTests.Snapshot(
                active: false,
                CapabilitySnapshot.NotConfigured(),
                CapabilitySnapshot.NotConfigured(),
                []);
            return Task.FromResult(Snapshot);
        }
        public Task<JobPageResponse> GetJobPageAsync(JobPageCursor? cursor, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken) => throw new NotSupportedException();
        public async Task SaveOtpAsync(OtpauthProfile profile, CancellationToken cancellationToken)
        {
            Saved.Add(profile);
            if (BlockFirstSave && Saved.Count == 1)
            {
                SaveEntered.TrySetResult();
                await ReleaseSave.Task.WaitAsync(cancellationToken);
            }
        }
        public Task<LocalTotpCode> GenerateCurrentAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            GenerateTotpCalls++;
            var now = _timeProvider.GetUtcNow();
            var remaining = 30 - (int)(now.ToUnixTimeSeconds() % 30);
            return Task.FromResult(new LocalTotpCode(
                GeneratedCode,
                remaining,
                now.AddSeconds(remaining)));
        }
        public string? GetText() => ClipboardText;
        public void SetText(string value)
        {
            ClipboardSetCalls++;
            ClipboardText = value;
        }
        public void Clear()
        {
            ClipboardText = null;
            ClipboardCleared = true;
        }

        public void ResetClipboardTracking()
        {
            ClipboardText = null;
            ClipboardCleared = false;
        }
    }

    private sealed class AllowRelogin : IReloginConfirmation
    {
        public Task<bool> ConfirmAsync(CancellationToken cancellationToken) => Task.FromResult(true);
    }

    private sealed class AllowClearOtp : IOtpClearConfirmation
    {
        public Task<bool> ConfirmAsync(CancellationToken cancellationToken) => Task.FromResult(true);
    }

    private sealed class ControllableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private readonly Lock _lock = new();
        private readonly List<ControlledTimer> _timers = [];
        private DateTimeOffset _now = now;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override DateTimeOffset GetUtcNow()
        {
            lock (_lock)
            {
                return _now;
            }
        }
        public override long GetTimestamp() => GetUtcNow().UtcTicks;
        public override ITimer CreateTimer(
            TimerCallback callback,
            object? state,
            TimeSpan dueTime,
            TimeSpan period)
        {
            var timer = new ControlledTimer(this, callback, state, dueTime, period);
            lock (_lock)
            {
                _timers.Add(timer);
            }

            return timer;
        }

        public void Advance(TimeSpan elapsed)
        {
            List<(TimerCallback Callback, object? State)> callbacks = [];
            lock (_lock)
            {
                _now += elapsed;
                foreach (var timer in _timers.ToArray())
                {
                    timer.CollectDueCallbacks(_now, callbacks);
                }
            }

            foreach (var (callback, state) in callbacks)
            {
                callback(state);
            }
        }

        private sealed class ControlledTimer : ITimer
        {
            private readonly ControllableTimeProvider _owner;
            private readonly TimerCallback _callback;
            private readonly object? _state;
            private DateTimeOffset? _dueAt;
            private TimeSpan _period;
            private bool _disposed;

            public ControlledTimer(
                ControllableTimeProvider owner,
                TimerCallback callback,
                object? state,
                TimeSpan dueTime,
                TimeSpan period)
            {
                _owner = owner;
                _callback = callback;
                _state = state;
                _period = period;
                _dueAt = DueAt(owner._now, dueTime);
            }

            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                lock (_owner._lock)
                {
                    if (_disposed)
                    {
                        return false;
                    }

                    _period = period;
                    _dueAt = DueAt(_owner._now, dueTime);
                    return true;
                }
            }

            public void Dispose()
            {
                lock (_owner._lock)
                {
                    _disposed = true;
                    _owner._timers.Remove(this);
                }
            }

            public ValueTask DisposeAsync()
            {
                Dispose();
                return ValueTask.CompletedTask;
            }

            public void CollectDueCallbacks(
                DateTimeOffset current,
                List<(TimerCallback Callback, object? State)> callbacks)
            {
                if (_disposed || _dueAt is null || current < _dueAt)
                {
                    return;
                }

                callbacks.Add((_callback, _state));
                _dueAt = _period is { Ticks: > 0 } && _period != Timeout.InfiniteTimeSpan
                    ? current + _period
                    : null;
            }

            private static DateTimeOffset? DueAt(DateTimeOffset current, TimeSpan dueTime) =>
                dueTime == Timeout.InfiniteTimeSpan ? null : current + dueTime;
        }
    }
}
