using CodeSignAuto.Agent.Ipc;
using CodeSignAuto.Agent.LocalJobs;
using CodeSignAuto.App.UI;
using CodeSignAuto.App.UI.ViewModels;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Protocol;

namespace CodeSignAuto.UI.Tests;

public sealed class QuickSignViewModelTests
{

    [Theory]
    [InlineData("NaN")]
    [InlineData("Infinity")]
    [InlineData("1e999")]
    public async Task non_finite_pdf_coordinates_disable_submit(string value)
    {
        using var fixture = new Fixture();
        using var viewModel = new QuickSignViewModel(
            new RecordingLocalJobClient(),
            new MutableManagementClient(Snapshot(certificates:
            [ Summary("Document", "6F09D233", authenticode: false, pdf: true) ])), _ => { });
        await viewModel.SelectFileAsync(fixture.Write("document.pdf", "%PDF-audit"u8.ToArray()));
        viewModel.PdfLeft = value;
        Assert.False(viewModel.SubmitCommand.CanExecute(null));
    }

    [Fact]
    public void Empty_selection_uses_the_selected_English_resources()
    {
        using var culture = new UiTestCultureScope("en-US");
        using var viewModel = new QuickSignViewModel(
            new RecordingLocalJobClient(),
            new MutableManagementClient(Snapshot()),
            _ => { });

        Assert.Equal("Choose a file to sign", viewModel.SelectedFileDisplayText);
        Assert.Equal("Nothing selected", viewModel.DetectedTypeText);
        Assert.Contains("Supported signing files", viewModel.FileDialogFilter, StringComparison.Ordinal);
    }

    [Fact]
    public void Empty_selection_prompts_for_a_signing_file()
    {
        using var viewModel = new QuickSignViewModel(
            new RecordingLocalJobClient(),
            new MutableManagementClient(Snapshot()),
            _ => { });

        Assert.False(viewModel.HasSelection);
        Assert.Equal("请选择签名文件", viewModel.SelectedFileDisplayText);
    }

    [Fact]
    public void Missing_pdf_extension_is_hidden_until_a_refresh_reports_it_installed()
    {
        var management = new MutableManagementClient(
            Snapshot(pdfFailure: "pdf_support_not_installed"));
        using var viewModel = new QuickSignViewModel(
            new RecordingLocalJobClient(),
            management,
            _ => { });

        Assert.False(viewModel.PdfExtensionVisible);
        Assert.DoesNotContain("*.pdf", viewModel.FileDialogFilter, StringComparison.OrdinalIgnoreCase);

        management.Publish(Snapshot());

        Assert.True(viewModel.PdfExtensionVisible);
        Assert.Contains("*.pdf", viewModel.FileDialogFilter, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Tampered_pdf_extension_remains_visible_for_repair()
    {
        using var viewModel = new QuickSignViewModel(
            new RecordingLocalJobClient(),
            new MutableManagementClient(Snapshot(pdfFailure: "pdf_helper_tampered")),
            _ => { });

        Assert.True(viewModel.PdfExtensionVisible);
        Assert.Contains("*.pdf", viewModel.FileDialogFilter, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Selecting_pdf_without_the_extension_is_rejected_without_install_or_job()
    {
        using var fixture = new Fixture();
        var local = new RecordingLocalJobClient();
        using var viewModel = new QuickSignViewModel(
            local,
            new MutableManagementClient(Snapshot(pdfFailure: "pdf_support_not_installed")),
            _ => { });

        var error = await Assert.ThrowsAsync<LocalJobException>(() =>
            viewModel.SelectFileAsync(fixture.Write("document.pdf", "%PDF-install"u8.ToArray())));

        Assert.Equal("local_capability_unavailable", error.Code);
        Assert.Equal(0, local.SubmitCalls);
        Assert.False(viewModel.HasSelection);
        Assert.Equal(QuickSignState.Failed, viewModel.State);
        Assert.Equal("local_capability_unavailable", viewModel.ErrorCode);
    }

    [Fact]
    public async Task Quick_sign_filters_certificates_by_detected_file_kind()
    {
        using var fixture = new Fixture();
        var management = new MutableManagementClient(Snapshot(certificates:
        [
            Summary("Code", "52A1B4C9", authenticode: true, pdf: false),
            Summary("Document", "6F09D233", authenticode: false, pdf: true),
        ]));
        using var viewModel = new QuickSignViewModel(
            new RecordingLocalJobClient(), management, _ => { });

        await viewModel.SelectFileAsync(fixture.Write("source.exe", "MZ-filter"u8.ToArray()));

        Assert.Equal("52A1B4C9", Assert.Single(viewModel.AvailableCertificates).SerialNumber);
        Assert.Equal("52A1B4C9", viewModel.SelectedCertificate?.SerialNumber);

        await viewModel.SelectFileAsync(fixture.Write("document.pdf", "%PDF-filter"u8.ToArray()));

        Assert.Equal("6F09D233", Assert.Single(viewModel.AvailableCertificates).SerialNumber);
        Assert.Equal("6F09D233", viewModel.SelectedCertificate?.SerialNumber);
    }

    [Fact]
    public async Task Recoverable_on_demand_state_keeps_code_signing_submission_enabled()
    {
        using var fixture = new Fixture();
        var local = new RecordingLocalJobClient();
        using var viewModel = new QuickSignViewModel(
            local,
            new MutableManagementClient(Snapshot(authenticodeReady: false)),
            _ => { });

        await viewModel.SelectFileAsync(fixture.Write("source.exe", "MZ-on-demand"u8.ToArray()));

        Assert.True(viewModel.CanSubmit);
        Assert.NotNull(await viewModel.SubmitAsync(default));
        Assert.Equal(1, local.SubmitCalls);
    }

    [Fact]
    public async Task Invalid_PDF_numeric_text_disables_submit_and_valid_text_uses_the_visible_values()
    {
        using var fixture = new Fixture();
        var local = new RecordingLocalJobClient();
        using var viewModel = new QuickSignViewModel(
            local,
            new MutableManagementClient(Snapshot(certificates:
            [
                Summary("Document", "6F09D233", authenticode: false, pdf: true),
            ])),
            _ => { });
        await viewModel.SelectFileAsync(
            fixture.Write("document.pdf", "%PDF-numeric-input"u8.ToArray()));

        viewModel.PdfPage = "not-a-page";

        Assert.False(viewModel.CanSubmit);

        viewModel.PdfPage = "2";
        viewModel.PdfLeft = "40.5";
        viewModel.PdfBottom = "41.5";
        viewModel.PdfRight = "200.5";
        viewModel.PdfTop = "100.5";

        Assert.True(viewModel.CanSubmit);
        Assert.NotNull(await viewModel.SubmitAsync(default));
        var parameters = Assert.IsType<PdfParameters>(local.Parameters);
        Assert.Equal(2, parameters.Page);
        Assert.Equal(new PdfBox(40.5, 41.5, 200.5, 100.5), parameters.Box);
    }

    [Fact]
    public async Task Quick_sign_requires_explicit_selection_when_multiple_are_usable()
    {
        using var fixture = new Fixture();
        var local = new RecordingLocalJobClient();
        var management = new MutableManagementClient(Snapshot(certificates:
        [
            Summary("Code One", "52A1B4C9", authenticode: true, pdf: false),
            Summary("Code Two", "6F09D233", authenticode: true, pdf: false),
        ]));
        using var viewModel = new QuickSignViewModel(local, management, _ => { });
        await viewModel.SelectFileAsync(fixture.Write("source.exe", "MZ-multiple"u8.ToArray()));

        Assert.Equal(2, viewModel.AvailableCertificates.Count);
        Assert.Null(viewModel.SelectedCertificate);
        Assert.False(viewModel.CanSubmit);

        viewModel.SelectedCertificate = viewModel.AvailableCertificates[1];
        Assert.True(viewModel.CanSubmit);
        Assert.NotNull(await viewModel.SubmitAsync(default));
        var parameters = Assert.IsType<AuthenticodeParameters>(local.Parameters);
        Assert.Equal("6F09D233", parameters.CertificateSerialNumber);
    }

    [Fact]
    public async Task Selection_exposes_only_basename_size_and_detected_type_and_builds_restricted_parameters()
    {
        using var fixture = new Fixture();
        var source = fixture.Write(Path.Combine("private", "source.exe"), "MZ-synthetic"u8.ToArray());
        var local = new RecordingLocalJobClient();
        var management = new MutableManagementClient(Snapshot());
        Guid? opened = null;
        using var viewModel = new QuickSignViewModel(
            local,
            management,
            jobId => opened = jobId);

        await viewModel.SelectFileAsync(source);
        var accepted = await viewModel.SubmitAsync(default);

        Assert.Equal("source.exe", viewModel.SelectedFileName);
        Assert.Equal("代码签名", viewModel.DetectedTypeText);
        Assert.DoesNotContain(fixture.Root, viewModel.SelectedFileName, StringComparison.Ordinal);
        Assert.DoesNotContain(fixture.Root, viewModel.StatusText, StringComparison.Ordinal);
        var parameters = Assert.IsType<AuthenticodeParameters>(local.Parameters);
        Assert.Equal("52A1B4C9", parameters.CertificateSerialNumber);
        Assert.Equal("sha256", parameters.DigestAlgorithm);
        Assert.False(parameters.AppendSignature);
        Assert.Equal(local.JobId, accepted);
        Assert.Equal(local.JobId, opened);
        Assert.Equal(QuickSignState.Accepted, viewModel.State);
        Assert.Equal(0, viewModel.CopyProgressPercent);
    }

    [Fact]
    public async Task Invalid_magic_stale_agent_or_tampered_pdf_helper_fail_closed()
    {
        using var fixture = new Fixture();
        var invalid = fixture.Write("invalid.pdf", "not-a-pdf"u8.ToArray());
        var local = new RecordingLocalJobClient();
        var management = new MutableManagementClient(Snapshot(heartbeatAge: 20_000));
        using var viewModel = new QuickSignViewModel(local, management, _ => { });

        await Assert.ThrowsAsync<LocalJobException>(() => viewModel.SelectFileAsync(invalid));
        Assert.Equal("file_signature_mismatch", viewModel.ErrorCode);

        var pdf = fixture.Write("document.pdf", "%PDF-1.7\n"u8.ToArray());
        await viewModel.SelectFileAsync(pdf);
        Assert.False(viewModel.CanSubmit);
        Assert.Equal("签名代理状态已过期", viewModel.ReadinessText);

        management.Publish(Snapshot(pdfFailure: "pdf_helper_tampered"));
        Assert.False(viewModel.CanSubmit);
        Assert.Equal("PDF 签名能力未就绪", viewModel.ReadinessText);
        Assert.Equal(0, local.SubmitCalls);
    }

    [Fact]
    public async Task Duplicate_submit_is_linearized_and_external_cancellation_preserves_source_file()
    {
        using var fixture = new Fixture();
        var original = "MZ-cancel-source"u8.ToArray();
        var source = fixture.Write("source.exe", original);
        var local = new RecordingLocalJobClient { BlockSubmit = true };
        using var viewModel = new QuickSignViewModel(
            local,
            new MutableManagementClient(Snapshot()),
            _ => { });
        await viewModel.SelectFileAsync(source);

        using var cancellation = new CancellationTokenSource();
        var first = viewModel.SubmitAsync(cancellation.Token);
        await local.SubmitStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        var duplicate = await viewModel.SubmitAsync(default);
        cancellation.Cancel();
        var canceled = await first;

        Assert.Null(duplicate);
        Assert.Null(canceled);
        Assert.Equal(1, local.SubmitCalls);
        Assert.Equal(QuickSignState.Canceled, viewModel.State);
        Assert.Equal(original, await File.ReadAllBytesAsync(source));
        Assert.Equal("source.exe", viewModel.SelectedFileName);
    }

    [Fact]
    public async Task Finalizing_submission_waits_for_the_local_job_acceptance()
    {
        using var fixture = new Fixture();
        var source = fixture.Write("source.exe", "MZ-finalizing"u8.ToArray());
        var local = new RecordingLocalJobClient
        {
            BlockSubmit = true,
            ReportFinalizing = true,
        };
        using var viewModel = new QuickSignViewModel(
            local,
            new MutableManagementClient(Snapshot()),
            _ => { });
        await viewModel.SelectFileAsync(source);

        var submit = viewModel.SubmitAsync(default);
        await local.SubmitStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal("正在完成本机提交", viewModel.StatusText);
        local.ReleaseSubmit();
        Assert.Equal(local.JobId, await submit);
    }

    [Fact]
    public async Task Failed_submit_retry_reuses_the_same_selected_operation()
    {
        using var fixture = new Fixture();
        var source = fixture.Write("source.exe", "MZ-retry"u8.ToArray());
        var local = new RecordingLocalJobClient { FailSubmitOnce = true };
        using var viewModel = new QuickSignViewModel(
            local,
            new MutableManagementClient(Snapshot()),
            _ => { });
        await viewModel.SelectFileAsync(source);

        Assert.Null(await viewModel.SubmitAsync(default));
        Assert.Equal(QuickSignState.Failed, viewModel.State);
        Assert.Equal("source.exe", viewModel.SelectedFileName);
        var retried = await viewModel.SubmitAsync(default);

        Assert.Equal(local.JobId, retried);
        Assert.Equal(2, local.SubmitCalls);
        Assert.Equal(QuickSignState.Accepted, viewModel.State);
    }

    [Fact]
    public async Task Old_completion_cannot_overwrite_a_new_selection_or_navigate_to_the_old_job()
    {
        using var fixture = new Fixture();
        var firstSource = fixture.Write("first.exe", "MZ-first"u8.ToArray());
        var secondSource = fixture.Write("second.pdf", "%PDF-second"u8.ToArray());
        var local = new RecordingLocalJobClient { BlockSubmit = true, IgnoreCancellation = true };
        Guid? opened = null;
        using var viewModel = new QuickSignViewModel(
            local,
            new MutableManagementClient(Snapshot()),
            jobId => opened = jobId);
        await viewModel.SelectFileAsync(firstSource);
        var submit = viewModel.SubmitAsync(default);
        await local.SubmitStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));

        await viewModel.SelectFileAsync(secondSource);
        local.ReleaseSubmit();
        Assert.Equal(local.JobId, await submit);

        Assert.Equal("second.pdf", viewModel.SelectedFileName);
        Assert.Equal("PDF 文档签名", viewModel.DetectedTypeText);
        Assert.Equal(QuickSignState.Idle, viewModel.State);
        Assert.Null(viewModel.AcceptedJobId);
        Assert.Null(opened);
        Assert.Equal([local.JobId], local.ReleasedAcceptedSources);
    }

    [Fact]
    public async Task Dispose_during_copy_cancels_and_joins_without_late_ui_mutation()
    {
        using var fixture = new Fixture();
        var source = fixture.Write("source.exe", "MZ-dispose"u8.ToArray());
        var local = new RecordingLocalJobClient { BlockSubmit = true };
        var viewModel = new QuickSignViewModel(
            local,
            new MutableManagementClient(Snapshot()),
            _ => Assert.Fail("Disposed submit must not navigate."));
        await viewModel.SelectFileAsync(source);
        var submit = viewModel.SubmitAsync(default);
        await local.SubmitStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));

        viewModel.Dispose();

        Assert.Null(await submit.WaitAsync(TimeSpan.FromSeconds(1)));
        Assert.Equal(1, local.SubmitCalls);
    }

    [Fact]
    public async Task Succeeded_job_replaces_tracking_status_and_keeps_the_signed_copy_available()
    {
        using var fixture = new Fixture();
        var local = new RecordingLocalJobClient();
        var management = new MutableManagementClient(Snapshot());
        using var viewModel = new QuickSignViewModel(local, management, _ => { });
        await viewModel.SelectFileAsync(fixture.Write("source.exe", "MZ-complete"u8.ToArray()));
        Assert.Equal(local.JobId, await viewModel.SubmitAsync(default));
        Assert.Equal("已提交，正在签名任务页中跟踪", viewModel.StatusText);
        Assert.True(viewModel.HasActiveJob);
        var changedProperties = new List<string?>();
        viewModel.PropertyChanged += (_, args) => changedProperties.Add(args.PropertyName);

        management.Publish(Snapshot(recent:
        [
            new RecentJobSnapshot(
                local.JobId,
                "authenticode",
                "succeeded",
                new DateTimeOffset(2026, 8, 8, 0, 1, 0, TimeSpan.Zero),
                null),
        ]));

        Assert.Equal("签名已完成，请在签名任务中保存", viewModel.StatusText);
        Assert.False(viewModel.HasActiveJob);
        Assert.Contains(nameof(QuickSignViewModel.StatusText), changedProperties);
        Assert.Equal(local.JobId, viewModel.AcceptedJobId);
        Assert.Empty(local.ReleasedAcceptedSources);
    }

    [Fact]
    public async Task Accepted_source_ownership_is_bounded_across_replace_clear_and_dispose()
    {
        using var fixture = new Fixture();
        var first = fixture.Write("first.exe", "MZ-first"u8.ToArray());
        var second = fixture.Write("second.exe", "MZ-second"u8.ToArray());
        var third = fixture.Write("third.exe", "MZ-third"u8.ToArray());
        var firstJob = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var secondJob = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var thirdJob = Guid.Parse("33333333-3333-3333-3333-333333333333");
        var local = new RecordingLocalJobClient(firstJob, secondJob, thirdJob);
        var viewModel = new QuickSignViewModel(
            local,
            new MutableManagementClient(Snapshot()),
            _ => { });

        await viewModel.SelectFileAsync(first);
        Assert.Equal(firstJob, await viewModel.SubmitAsync(default));
        await viewModel.SelectFileAsync(second);
        Assert.Equal(secondJob, await viewModel.SubmitAsync(default));
        viewModel.ClearSelection();
        await viewModel.SelectFileAsync(third);
        Assert.Equal(thirdJob, await viewModel.SubmitAsync(default));
        viewModel.Dispose();

        Assert.Equal([firstJob, secondJob, thirdJob], local.ReleasedAcceptedSources);
    }

    [Theory]
    [InlineData("failed", "internal_error")]
    [InlineData("expired", "job_expired")]
    public async Task Failed_or_expired_terminal_snapshot_updates_status_and_releases_the_accepted_source(
        string terminalState,
        string errorCode)
    {
        using var fixture = new Fixture();
        var source = fixture.Write("source.exe", "MZ-source"u8.ToArray());
        var local = new RecordingLocalJobClient();
        var management = new MutableManagementClient(Snapshot());
        using var viewModel = new QuickSignViewModel(
            local,
            management,
            _ => { });
        await viewModel.SelectFileAsync(source);
        Assert.Equal(local.JobId, await viewModel.SubmitAsync(default));

        management.Publish(Snapshot(recent:
        [
            new RecentJobSnapshot(
                local.JobId,
                "authenticode",
                terminalState,
                new DateTimeOffset(2026, 8, 8, 0, 1, 0, TimeSpan.Zero),
                errorCode),
        ]));

        Assert.Equal([local.JobId], local.ReleasedAcceptedSources);
        Assert.Null(viewModel.AcceptedJobId);
        Assert.Equal(QuickSignState.Failed, viewModel.State);
        Assert.Equal(errorCode, viewModel.ErrorCode);
    }

    [Fact]
    public async Task Failed_terminal_feed_updates_status_and_releases_the_accepted_source()
    {
        using var fixture = new Fixture();
        var local = new RecordingLocalJobClient();
        var feed = new ControllableTerminalFeed();
        using var viewModel = new QuickSignViewModel(
            local,
            new MutableManagementClient(Snapshot()),
            _ => { },
            dispatcher: null,
            feed);
        await viewModel.SelectFileAsync(fixture.Write("source.exe", "MZ-source"u8.ToArray()));
        Assert.Equal(local.JobId, await viewModel.SubmitAsync(default));

        feed.Publish(
        [
            new TerminalJobEventItem(
                1,
                new JobPageItem(
                    local.JobId,
                    "local",
                    "authenticode",
                    "failed",
                    "source.exe",
                    new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero),
                    new DateTimeOffset(2026, 8, 8, 0, 0, 30, TimeSpan.Zero),
                    new DateTimeOffset(2026, 8, 8, 0, 1, 0, TimeSpan.Zero),
                    "authenticode_sign_failed",
                    Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                    false)),
        ]);

        Assert.Equal([local.JobId], local.ReleasedAcceptedSources);
        Assert.Null(viewModel.AcceptedJobId);
        Assert.Equal(QuickSignState.Failed, viewModel.State);
        Assert.Equal("authenticode_sign_failed", viewModel.ErrorCode);
    }

    [Fact]
    public async Task Terminal_snapshot_release_survives_a_newer_snapshot_before_dispatch()
    {
        using var fixture = new Fixture();
        var source = fixture.Write("source.exe", "MZ-source"u8.ToArray());
        var local = new RecordingLocalJobClient();
        var management = new MutableManagementClient(Snapshot());
        var dispatcher = new QueuedDispatcher();
        using var viewModel = new QuickSignViewModel(
            local,
            management,
            _ => { },
            dispatcher);
        await viewModel.SelectFileAsync(source);
        Assert.Equal(local.JobId, await viewModel.SubmitAsync(default));
        dispatcher.Hold = true;

        management.Publish(Snapshot(recent:
        [
            new RecentJobSnapshot(
                local.JobId,
                "authenticode",
                "failed",
                new DateTimeOffset(2026, 8, 8, 0, 1, 0, TimeSpan.Zero),
                "internal_error"),
        ]));
        management.Publish(Snapshot());
        dispatcher.Drain();

        Assert.Equal([local.JobId], local.ReleasedAcceptedSources);
        Assert.Null(viewModel.AcceptedJobId);
    }

    [Fact]
    public async Task Replaced_snapshot_before_dispatch_rejects_the_stale_selected_certificate_without_submitting()
    {
        using var fixture = new Fixture();
        var local = new RecordingLocalJobClient();
        var management = new MutableManagementClient(Snapshot(certificates:
        [
            Summary("Original", "52A1B4C9", authenticode: true, pdf: false),
        ]));
        var dispatcher = new QueuedDispatcher();
        using var viewModel = new QuickSignViewModel(local, management, _ => { }, dispatcher);
        await viewModel.SelectFileAsync(fixture.Write("source.exe", "MZ-race"u8.ToArray()));

        dispatcher.Hold = true;
        management.Publish(Snapshot(certificates:
        [
            Summary("Replacement", "6F09D233", authenticode: true, pdf: false),
        ]));
        Assert.Equal("52A1B4C9", viewModel.SelectedCertificate?.SerialNumber);

        var submit = viewModel.SubmitAsync(default);
        await WaitUntilAsync(() => dispatcher.PendingCount >= 2);
        dispatcher.Drain();

        Assert.Null(await submit);
        Assert.Equal(0, local.SubmitCalls);
        Assert.Null(local.Parameters);
    }

    private static ManagementSnapshot Snapshot(
        long heartbeatAge = 100,
        bool authenticodeReady = true,
        bool pdfReady = true,
        IReadOnlyList<RecentJobSnapshot>? recent = null,
        IReadOnlyList<CertificateSummary>? certificates = null,
        string? pdfFailure = null) =>
        new(
            ManagementSnapshot.CurrentVersion,
            new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero),
            Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            true,
            true,
            7,
            7,
            heartbeatAge,
            true,
            7,
            authenticodeReady ? Ready() : NotReady(),
            pdfFailure is not null ? PdfFailure(pdfFailure) : pdfReady ? Ready() : NotReady(),
            0,
            0,
            null,
            recent ?? [],
            1,
            certificates ??
            [
                Summary("Universal", "52A1B4C9", authenticode: true, pdf: true),
            ]);

    private static CertificateSummary Summary(
        string commonName,
        string serialNumber,
        bool authenticode,
        bool pdf) =>
        new(
            commonName,
            serialNumber,
            DateTimeOffset.Parse("2026-01-01T00:00:00Z"),
            DateTimeOffset.Parse("2027-01-01T00:00:00Z"),
            authenticode,
            pdf,
            true,
            null);

    private static CapabilitySnapshot Ready() =>
        ProtocolV3TestFixtures.Ready();

    private static CapabilitySnapshot NotReady() =>
        ProtocolV3TestFixtures.TokenMissing();

    private static CapabilitySnapshot PdfFailure(string reasonCode)
    {
        var ready = Ready();
        return new CapabilitySnapshot(
            true,
            ready.TokenPresent,
            ready.TokenMatches,
            ready.TokenSuffix,
            ready.CertificatePresent,
            ready.CertificateMatches,
            ready.CertificateSuffix,
            ready.PrivateKeyPresent,
            ready.PrivateKeyMatches,
            ready.PrivateKeySuffix,
            false,
            reasonCode,
            ready.CertificateNotAfterUtc,
            ready.CertificateThumbprintSuffix,
            ready.Session);
    }

    private sealed class MutableManagementClient(ManagementSnapshot snapshot) : IAgentManagementClient
    {
        public event EventHandler? SnapshotChanged;

        public ManagementSnapshot? LatestSnapshot { get; private set; } = snapshot;

        public Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken) =>
            Task.FromResult(LatestSnapshot!);

        public Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken) =>
            RefreshAsync(cancellationToken);

        public void Publish(ManagementSnapshot value)
        {
            LatestSnapshot = value;
            SnapshotChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    private sealed class QueuedDispatcher : IUiDispatcher
    {
        private readonly Queue<(Action Action, TaskCompletionSource Completion)> _queued = [];

        public bool Hold { get; set; }

        public int PendingCount => _queued.Count;

        public Task InvokeAsync(Action action, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Hold)
            {
                action();
                return Task.CompletedTask;
            }

            var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _queued.Enqueue((action, completion));
            return completion.Task;
        }

        public void Drain()
        {
            Hold = false;
            while (_queued.TryDequeue(out var queued))
            {
                queued.Action();
                queued.Completion.TrySetResult();
            }
        }

    }

    private static async Task WaitUntilAsync(Func<bool> predicate)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        while (!predicate())
        {
            await Task.Delay(1, timeout.Token);
        }
    }

    private sealed class RecordingLocalJobClient : ILocalJobClient
    {
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly Queue<Guid> _jobIds;

        public RecordingLocalJobClient(params Guid[] jobIds)
        {
            _jobIds = new Queue<Guid>(jobIds.Length == 0 ? [JobId] : jobIds);
        }

        public Guid JobId { get; } = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");

        public TaskCompletionSource SubmitStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool BlockSubmit { get; init; }

        public bool IgnoreCancellation { get; init; }

        public bool ReportFinalizing { get; init; }

        public bool FailSubmitOnce { get; set; }

        public int SubmitCalls { get; private set; }

        public SigningParameters? Parameters { get; private set; }

        public TaskCompletionSource SaveStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Guid? SavedJobId { get; private set; }

        public string? SavedDestination { get; private set; }

        public bool SavedOverwrite { get; private set; }

        public List<Guid> ReleasedAcceptedSources { get; } = [];

        public async Task<Guid> CreateAndUploadAsync(
            string path,
            SigningParameters parameters,
            IProgress<LocalCopyProgress>? progress,
            CancellationToken cancellationToken)
        {
            SubmitCalls++;
            Parameters = parameters;
            if (FailSubmitOnce)
            {
                FailSubmitOnce = false;
                throw new LocalJobException("local_job_unavailable");
            }

            progress?.Report(new LocalCopyProgress(5, 10, 50));
            if (ReportFinalizing)
            {
                progress?.Report(new LocalCopyProgress(10, 10, 100));
            }

            SubmitStarted.TrySetResult();
            if (BlockSubmit)
            {
                if (IgnoreCancellation)
                {
                    await _release.Task;
                }
                else
                {
                    await _release.Task.WaitAsync(cancellationToken);
                }
            }

            return _jobIds.Count > 0 ? _jobIds.Dequeue() : JobId;
        }

        public Task SaveSignedCopyAsync(
            Guid jobId,
            string destinationPath,
            bool overwrite,
            CancellationToken cancellationToken)
        {
            SavedJobId = jobId;
            SavedDestination = destinationPath;
            SavedOverwrite = overwrite;
            SaveStarted.TrySetResult();
            return Task.CompletedTask;
        }

        public void ReleaseSubmit() => _release.TrySetResult();

        public void ReleaseAcceptedSource(Guid jobId) => ReleasedAcceptedSources.Add(jobId);
    }

    private sealed class ControllableTerminalFeed : ITerminalJobFeed
    {
        public event EventHandler? ItemsChanged;

        public IReadOnlyList<TerminalJobEventItem> Items { get; private set; } = [];

        public bool HasCompletedInitialPoll => true;

        public void Publish(IReadOnlyList<TerminalJobEventItem> items)
        {
            Items = items;
            ItemsChanged?.Invoke(this, EventArgs.Empty);
        }

        public void Dispose()
        {
        }
    }

    private sealed class Fixture : IDisposable
    {
        public Fixture()
        {
            Root = Path.Combine(Path.GetTempPath(), "CodeSignAuto.Tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public string Write(string relativePath, byte[] content)
        {
            var path = Path.Combine(Root, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path, content);
            return path;
        }

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }
}
