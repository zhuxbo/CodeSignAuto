using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Text;
using System.Threading.Channels;
using SimplySignAuto.Agent;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.Agent.Security;
using SimplySignAuto.Agent.Sessions;
using SimplySignAuto.Agent.SimplySign;
using SimplySignAuto.Agent.Signing;
using SimplySignAuto.Core.Otp;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Protocol;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class AgentManagementTests
{
    private static readonly Guid FirstRequestId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid SecondRequestId = Guid.Parse("22222222-2222-2222-2222-222222222222");

    [Fact]
    public async Task Page_and_settings_share_the_single_management_reader_and_exact_correlation()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = Client(stream, [FirstRequestId, SecondRequestId]);
        var run = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await stream.WaitForWrittenMessageCountAsync(1);

        var pageTask = client.GetJobPageAsync(null, default);
        await stream.WaitForWrittenMessageCountAsync(2);
        var item = new JobPageItem(
            Guid.NewGuid(), "local", "pdf", "succeeded", "signed.pdf",
            DateTimeOffset.Parse("2026-08-09T00:00:00Z"),
            DateTimeOffset.Parse("2026-08-09T00:00:01Z"),
            DateTimeOffset.Parse("2026-08-09T00:00:02Z"),
            null, Guid.NewGuid(), true);
        await stream.EnqueueAsync(new JobPageResponse(FirstRequestId, [item], null, null, null));
        Assert.Equal(item, Assert.Single((await pageTask).Items));

        var settingsTask = client.GetServiceSettingsAsync(default);
        await stream.WaitForWrittenMessageCountAsync(3);
        var summary = new ServiceSettingsSummary(
            7080, ServiceSettingsSummary.FixedMaximumUploadBytes, 24,
            "1.0.0");
        await stream.EnqueueAsync(new ServiceSettingsResponse(SecondRequestId, summary, null, null));
        Assert.Equivalent(summary, await settingsTask, strict: true);

        Assert.Equal(1, stream.MaximumConcurrentReaders);
        stream.CompleteInput();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Terminal_delta_uses_the_existing_single_management_reader()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = Client(stream, [FirstRequestId]);
        var run = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await stream.WaitForWrittenMessageCountAsync(1);
        var lowerBound = new TerminalJobWatermark(40);

        var deltaTask = client.GetTerminalJobDeltaAsync(lowerBound, null, default);
        await stream.WaitForWrittenMessageCountAsync(2);
        var responseWatermark = new TerminalJobWatermark(50);
        await stream.EnqueueAsync(new TerminalJobDeltaResponse(
            FirstRequestId, [], null, responseWatermark, null, null));

        Assert.Equal(responseWatermark, (await deltaTask).Watermark);
        Assert.Equal(1, stream.MaximumConcurrentReaders);
        stream.CompleteInput();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task One_receive_loop_dispatches_snapshot_while_a_sign_command_is_still_running()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = Client(stream, [FirstRequestId]);
        var commandStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseCommand = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var run = client.RunAsync(
            Hello(),
            Heartbeat,
            async (command, progress, cancellationToken) =>
            {
                commandStarted.TrySetResult();
                await releaseCommand.Task.WaitAsync(cancellationToken);
                return new JobCompleted(command.JobId, command.DispatchId, 10, new string('b', 64));
            },
            default);
        await stream.WaitForWrittenMessageCountAsync(1);
        var request = client.GetManagementSnapshotAsync(default);
        await stream.WaitForWrittenMessageCountAsync(2);
        var command = Command();
        await stream.EnqueueAsync(command);
        await stream.EnqueueAsync(new ManagementSnapshotResponse(FirstRequestId, Snapshot(), null, null));

        await commandStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        var snapshot = await request.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(Snapshot(), snapshot);
        Assert.False(releaseCommand.Task.IsCompleted);
        Assert.False(run.IsCompleted);
        Assert.Equal(1, stream.MaximumConcurrentReaders);
        releaseCommand.TrySetResult();
        await stream.WaitForWrittenMessageCountAsync(3);
        stream.CompleteInput();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Startup_prepare_duplicate_and_reconnect_replay_share_the_process_cache()
    {
        await using var firstStream = new ScriptedDuplexStream();
        await using var secondStream = new ScriptedDuplexStream();
        var streams = new ConcurrentQueue<Stream>([firstStream, secondStream]);
        var client = new AgentPipeClient(
            _ => ValueTask.FromResult(
                streams.TryDequeue(out var stream)
                    ? stream
                    : throw new InvalidOperationException("connection_exhausted")),
            new InfiniteDelay());
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        using var preparation = new AgentStartupPreparationCache(async (command, token) =>
        {
            Interlocked.Increment(ref calls);
            entered.TrySetResult();
            await release.Task.WaitAsync(token);
            return new PrepareSimplySignSessionResult(command.RequestId, SimplySignSessionState.Ready, null);
        });
        var command = new PrepareSimplySignSessionCommand(FirstRequestId);
        var firstRun = client.RunWithPublicationAsync(
            Hello(),
            Heartbeat,
            RejectPublications,
            default,
            preparation);
        await firstStream.WaitForWrittenMessageCountAsync(1);
        await firstStream.EnqueueAsync(command);
        await firstStream.EnqueueAsync(command);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(1));
        release.TrySetResult();
        await firstStream.WaitForWrittenMessageCountAsync(3);

        Assert.Equal(1, calls);
        Assert.Equal(
            [FirstRequestId, FirstRequestId],
            (await firstStream.WrittenMessagesAsync())
                .OfType<PrepareSimplySignSessionResult>()
                .Select(static result => result.RequestId));
        firstStream.CompleteInput();
        await firstRun.WaitAsync(TimeSpan.FromSeconds(1));

        var secondRun = client.RunWithPublicationAsync(
            Hello(),
            Heartbeat,
            RejectPublications,
            default,
            preparation);
        await secondStream.WaitForWrittenMessageCountAsync(1);
        await secondStream.EnqueueAsync(command);
        await secondStream.WaitForWrittenMessageCountAsync(2);

        Assert.Equal(1, calls);
        Assert.Equal(
            FirstRequestId,
            Assert.Single((await secondStream.WrittenMessagesAsync())
                .OfType<PrepareSimplySignSessionResult>()).RequestId);
        secondStream.CompleteInput();
        await secondRun.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Startup_response_write_fault_still_joins_and_observes_every_preparation_task()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = Client(stream, []);
        var secondId = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var secondEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseSecond = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var preparation = new AgentStartupPreparationCache(async (command, token) =>
        {
            if (command.RequestId == secondId)
            {
                secondEntered.TrySetResult();
                await releaseSecond.Task.WaitAsync(token);
            }

            return new PrepareSimplySignSessionResult(command.RequestId, SimplySignSessionState.Ready, null);
        });
        var run = client.RunWithPublicationAsync(
            Hello(),
            Heartbeat,
            RejectPublications,
            default,
            preparation);
        await stream.WaitForWrittenMessageCountAsync(1);
        stream.FailNextWrite();
        await stream.EnqueueAsync(new PrepareSimplySignSessionCommand(FirstRequestId));
        await stream.EnqueueAsync(new PrepareSimplySignSessionCommand(secondId));
        await secondEntered.Task.WaitAsync(TimeSpan.FromSeconds(1));
        stream.CompleteInput();
        await Task.Delay(20);

        Assert.False(run.IsCompleted);
        releaseSecond.TrySetResult();
        await Assert.ThrowsAsync<IOException>(() => run.WaitAsync(TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public async Task Cancelling_one_waiter_keeps_the_shared_pipe_and_ignores_its_late_response()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = Client(stream, [FirstRequestId, SecondRequestId]);
        var run = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await stream.WaitForWrittenMessageCountAsync(1);
        using var cancellation = new CancellationTokenSource();
        var cancelled = client.GetManagementSnapshotAsync(cancellation.Token);
        await stream.WaitForWrittenMessageCountAsync(2);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        Assert.Equal(0, client.PendingManagementRequestCount);
        Assert.False(run.IsCompleted);
        var lateSnapshot = SnapshotWithConnection(
            Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd"));
        await stream.EnqueueAndWaitUntilReaderAdvancedAsync(
            new ManagementSnapshotResponse(FirstRequestId, lateSnapshot, null, null));

        var second = client.GetManagementSnapshotAsync(default);
        await stream.WaitForWrittenMessageCountAsync(3);
        var secondSnapshot = SnapshotWithConnection(
            Guid.Parse("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"));
        await stream.EnqueueAndWaitUntilReaderAdvancedAsync(
            new ManagementSnapshotResponse(SecondRequestId, secondSnapshot, null, null));

        Assert.Equal(secondSnapshot, await second.WaitAsync(TimeSpan.FromSeconds(1)));
        Assert.False(run.IsCompleted);
        stream.CompleteInput();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Valid_unmatched_response_is_ignored_without_disturbing_the_exact_pending_waiter()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = Client(stream, [FirstRequestId]);
        var run = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await stream.WaitForWrittenMessageCountAsync(1);
        var pending = client.GetManagementSnapshotAsync(default);
        await stream.WaitForWrittenMessageCountAsync(2);
        await stream.EnqueueAsync(new ManagementSnapshotResponse(SecondRequestId, Snapshot(), null, null));

        Assert.Equal(1, client.PendingManagementRequestCount);
        Assert.False(run.IsCompleted);
        await stream.EnqueueAsync(new ManagementSnapshotResponse(FirstRequestId, Snapshot(), null, null));

        Assert.Equal(Snapshot(), await pending.WaitAsync(TimeSpan.FromSeconds(1)));
        Assert.Equal(0, client.PendingManagementRequestCount);
        Assert.False(run.IsCompleted);
        stream.CompleteInput();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Matching_request_id_with_the_wrong_response_type_closes_protocol_and_clears_all_pending()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = Client(stream, [FirstRequestId, SecondRequestId]);
        var run = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await stream.WaitForWrittenMessageCountAsync(1);
        var snapshot = client.GetManagementSnapshotAsync(default);
        var page = client.GetJobPageAsync(null, default);
        await stream.WaitForWrittenMessageCountAsync(3);

        await stream.EnqueueAsync(new JobPageResponse(FirstRequestId, [], null, null, null));

        var protocol = await Assert.ThrowsAsync<ProtocolException>(() =>
            run.WaitAsync(TimeSpan.FromSeconds(1)));
        Assert.Equal("invalid_message", protocol.Code);
        await Assert.ThrowsAsync<ManagementUnavailableException>(() =>
            snapshot.WaitAsync(TimeSpan.FromSeconds(1)));
        await Assert.ThrowsAsync<ManagementUnavailableException>(() =>
            page.WaitAsync(TimeSpan.FromSeconds(1)));
        Assert.Equal(0, client.PendingManagementRequestCount);
    }

    [Fact]
    public async Task Semantically_invalid_management_response_still_fails_the_authenticated_connection()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = Client(stream, [FirstRequestId]);
        var run = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await stream.WaitForWrittenMessageCountAsync(1);
        var pending = client.GetManagementSnapshotAsync(default);
        await stream.WaitForWrittenMessageCountAsync(2);

        await stream.EnqueueRawJsonAsync(
            $$"""
            {"type":"management_snapshot_response","requestId":"{{FirstRequestId}}","snapshot":null,"errorCode":null,"correlationId":null}
            """);

        var runError = await Assert.ThrowsAsync<ProtocolException>(async () =>
            await run.WaitAsync(TimeSpan.FromSeconds(1)));
        var waiterError = await Assert.ThrowsAsync<ManagementUnavailableException>(async () =>
            await pending.WaitAsync(TimeSpan.FromSeconds(1)));
        Assert.Equal("invalid_message", runError.Code);
        Assert.Equal("management_unavailable", waiterError.Code);
        Assert.Equal(0, client.PendingManagementRequestCount);
    }

    [Fact]
    public async Task Management_timeout_is_bounded_without_closing_the_connection()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = Client(stream, [FirstRequestId], TimeSpan.FromMilliseconds(25));
        var run = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await stream.WaitForWrittenMessageCountAsync(1);

        var error = await Assert.ThrowsAsync<ManagementUnavailableException>(() =>
            client.GetManagementSnapshotAsync(default));

        Assert.Equal("management_unavailable", error.Code);
        Assert.NotEqual(Guid.Empty, error.CorrelationId);
        Assert.Equal(0, client.PendingManagementRequestCount);
        Assert.False(run.IsCompleted);
        stream.CompleteInput();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Management_timeout_after_complete_frame_allows_immediate_retry_and_ignores_late_response()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = Client(
            stream,
            [FirstRequestId, SecondRequestId],
            TimeSpan.FromMilliseconds(500));
        var run = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await stream.WaitForWrittenMessageCountAsync(1);

        var firstError = await Assert.ThrowsAsync<ManagementUnavailableException>(() =>
            client.GetManagementSnapshotAsync(default));
        await stream.WaitForWrittenMessageCountAsync(2);

        Assert.Equal("management_unavailable", firstError.Code);
        Assert.Equal(0, client.PendingManagementRequestCount);
        Assert.False(run.IsCompleted);

        var second = client.GetManagementSnapshotAsync(default);
        await stream.WaitForWrittenMessageCountAsync(3);
        var lateSnapshot = SnapshotWithConnection(Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd"));
        var expectedSnapshot = SnapshotWithConnection(Guid.Parse("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"));
        await stream.EnqueueAndWaitUntilReaderAdvancedAsync(
            new ManagementSnapshotResponse(FirstRequestId, lateSnapshot, null, null));
        await stream.EnqueueAndWaitUntilReaderAdvancedAsync(
            new ManagementSnapshotResponse(SecondRequestId, expectedSnapshot, null, null));

        Assert.Equal(expectedSnapshot, await second.WaitAsync(TimeSpan.FromSeconds(1)));
        Assert.Equal(0, client.PendingManagementRequestCount);
        Assert.False(run.IsCompleted);
        stream.CompleteInput();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Management_timeout_while_waiting_for_writer_does_not_write_or_retire_the_connection()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = Client(stream, [FirstRequestId], TimeSpan.FromMilliseconds(25));
        using var runCancellation = new CancellationTokenSource();
        var run = client.RunAsync(Hello(), Heartbeat, RejectCommands, runCancellation.Token);
        await stream.WaitForWrittenMessageCountAsync(1);
        stream.BlockAfterWrites(0);
        var heartbeat = client.PublishHeartbeatAsync(Heartbeat(), default);
        await stream.WriteBlocked.Task.WaitAsync(TimeSpan.FromSeconds(1));

        try
        {
            var error = await Assert.ThrowsAsync<ManagementUnavailableException>(async () =>
                await client.GetManagementSnapshotAsync(default).WaitAsync(TimeSpan.FromSeconds(1)));

            Assert.Equal("management_unavailable", error.Code);
            Assert.Equal(0, client.PendingManagementRequestCount);
            Assert.False(run.IsCompleted);
        }
        finally
        {
            stream.ReleaseWrite();
            await heartbeat.WaitAsync(TimeSpan.FromSeconds(1));
            runCancellation.Cancel();
            await run.WaitAsync(TimeSpan.FromSeconds(1));
        }
    }

    [Fact]
    public async Task Caller_cancellation_while_waiting_for_writer_leaves_no_request_frame_or_pending_waiter()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = Client(stream, [FirstRequestId]);
        using var runCancellation = new CancellationTokenSource();
        var run = client.RunAsync(Hello(), Heartbeat, RejectCommands, runCancellation.Token);
        await stream.WaitForWrittenMessageCountAsync(1);
        stream.BlockAfterWrites(0);
        var heartbeat = client.PublishHeartbeatAsync(Heartbeat(), default);
        await stream.WriteBlocked.Task.WaitAsync(TimeSpan.FromSeconds(1));
        using var cancellation = new CancellationTokenSource();
        var request = client.GetManagementSnapshotAsync(cancellation.Token);

        try
        {
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await request.WaitAsync(TimeSpan.FromSeconds(1)));

            Assert.Equal(0, client.PendingManagementRequestCount);
            Assert.False(run.IsCompleted);
        }
        finally
        {
            stream.ReleaseWrite();
            await heartbeat.WaitAsync(TimeSpan.FromSeconds(1));
            runCancellation.Cancel();
            await run.WaitAsync(TimeSpan.FromSeconds(1));
        }
    }

    [Fact]
    public async Task Cancellation_after_management_frame_starts_retires_the_connection_to_prevent_desynchronization()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = Client(stream, [FirstRequestId], TimeSpan.FromMilliseconds(25));
        var run = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await stream.WaitForWrittenMessageCountAsync(1);
        stream.BlockAfterWrites(1);

        var error = await Assert.ThrowsAsync<ManagementUnavailableException>(async () =>
            await client.GetManagementSnapshotAsync(default).WaitAsync(TimeSpan.FromSeconds(1)));
        await run.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal("management_unavailable", error.Code);
        Assert.Equal(0, client.PendingManagementRequestCount);
        Assert.True(stream.WriteBlocked.Task.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task Duplicate_pending_request_id_is_rejected_without_replacing_the_original_waiter()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = Client(stream, [FirstRequestId, FirstRequestId]);
        var run = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await stream.WaitForWrittenMessageCountAsync(1);
        var first = client.GetManagementSnapshotAsync(default);
        await stream.WaitForWrittenMessageCountAsync(2);

        var duplicate = await Assert.ThrowsAsync<ManagementUnavailableException>(() =>
            client.GetManagementSnapshotAsync(default));

        Assert.Equal("management_unavailable", duplicate.Code);
        Assert.Equal(1, client.PendingManagementRequestCount);
        await stream.EnqueueAsync(new ManagementSnapshotResponse(FirstRequestId, Snapshot(), null, null));
        Assert.Equal(Snapshot(), await first.WaitAsync(TimeSpan.FromSeconds(1)));
        stream.CompleteInput();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Capability_cache_probes_the_global_session_once()
    {
        var authenticode = Alias("codesign", "TOKEN-A", "aabbccdd", "11223344");
        var pdf = Alias("pdfsign", "TOKEN-B", "eeff0011", "55667788");
        var controller = new RecordingManagementController();
        var cache = CreateCache(controller, 7, authenticode, pdf);

        await cache.RefreshAsync(default);
        var heartbeat = cache.CreateHeartbeat(null);

        Assert.Equal(["codesign"], controller.ProbedAliases);
        Assert.True(heartbeat.Authenticode!.Configured);
        Assert.True(heartbeat.Authenticode.Ready);
        Assert.True(heartbeat.Pdf!.Configured);
        Assert.True(heartbeat.Pdf.Ready);
        Assert.Equal(7, heartbeat.SimplySignProcessSessionId);
        Assert.Equal("ready", heartbeat.SimplySignStatus);
    }

    [Theory]
    [InlineData(InstalledPdfToolStatus.NotInstalled, "pdf_support_not_installed")]
    [InlineData(InstalledPdfToolStatus.Tampered, "pdf_helper_tampered")]
    public async Task Optional_pdf_tool_failure_is_reported_without_disabling_ready_authenticode(
        InstalledPdfToolStatus status,
        string expectedReasonCode)
    {
        var resolver = new SequencePdfToolResolver(Resolution(status));
        using var cache = CreateCacheWithPdfResolver(resolver);

        await cache.RefreshAsync(default);
        var heartbeat = cache.CreateHeartbeat(null);

        Assert.True(heartbeat.Authenticode!.Ready);
        Assert.Equal("ready", heartbeat.Authenticode.ReasonCode);
        Assert.True(heartbeat.Pdf!.Configured);
        Assert.False(heartbeat.Pdf.Ready);
        Assert.Equal(expectedReasonCode, heartbeat.Pdf.ReasonCode);
    }

    [Theory]
    [InlineData(InstalledPdfToolStatus.NotInstalled)]
    [InlineData(InstalledPdfToolStatus.Tampered)]
    public async Task Optional_pdf_tool_installation_state_remains_visible_while_simplysign_is_logged_out(
        InstalledPdfToolStatus status)
    {
        var resolver = new SequencePdfToolResolver(Resolution(status));
        using var cache = CreateCacheWithPdfResolver(resolver);

        await cache.RunHealthCheckAsync(default);
        var heartbeat = cache.CreateHeartbeat(null);

        Assert.False(heartbeat.Authenticode!.Ready);
        Assert.Equal("unknown", heartbeat.Authenticode.ReasonCode);
        Assert.False(heartbeat.Pdf!.Ready);
        Assert.Equal(
            status == InstalledPdfToolStatus.NotInstalled
                ? "pdf_support_not_installed"
                : "pdf_helper_tampered",
            heartbeat.Pdf.ReasonCode);
        Assert.Equal(heartbeat.Authenticode.Session, heartbeat.Pdf.Session);
    }

    [Fact]
    public async Task Explicit_capability_refresh_observes_installed_pdf_tool_state_changes_immediately()
    {
        var resolver = new SequencePdfToolResolver(
            InstalledPdfToolResolution.NotInstalled(),
            InstalledPdfToolResolution.Ready(InstalledTool()));
        using var cache = CreateCacheWithPdfResolver(resolver);

        await cache.RefreshAsync(default);
        Assert.Equal("pdf_support_not_installed", cache.CreateHeartbeat(null).Pdf!.ReasonCode);

        await cache.RefreshAsync(default);
        var refreshed = cache.CreateHeartbeat(null);

        Assert.Equal(2, resolver.Calls);
        Assert.True(refreshed.Pdf!.Ready);
        Assert.Equal("ready", refreshed.Pdf.ReasonCode);
    }

    [Fact]
    public async Task Pdf_capability_heartbeat_never_exposes_helper_identity_or_secret_paths()
    {
        var tool = InstalledTool();
        using var cache = CreateCacheWithPdfResolver(
            new SequencePdfToolResolver(InstalledPdfToolResolution.Ready(tool)));

        await cache.RefreshAsync(default);
        var json = System.Text.Json.JsonSerializer.Serialize(cache.CreateHeartbeat(null));

        Assert.DoesNotContain(tool.ExecutablePath, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(tool.Sha256, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ExecutablePath", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unconfigured_capability_is_false_and_never_borrows_the_other_probe()
    {
        var controller = new RecordingManagementController();
        var cache = CreateCache(
            controller,
            7,
            Alias("codesign", "TOKEN-A", "aabbccdd", "11223344"),
            pdfAlias: null);

        await cache.RefreshAsync(default);
        var heartbeat = cache.CreateHeartbeat(null);

        Assert.Equal(["codesign"], controller.ProbedAliases);
        Assert.True(heartbeat.Authenticode!.Ready);
        Assert.Equal(CapabilitySnapshot.NotConfigured(), heartbeat.Pdf);
    }

    [Fact]
    public async Task Cancelled_refresh_preserves_the_last_complete_capability_cache()
    {
        var controller = new RecordingManagementController();
        var cache = CreateCache(
            controller,
            7,
            Alias("codesign", "TOKEN-A", "aabbccdd", "11223344"),
            Alias("pdfsign", "TOKEN-B", "eeff0011", "55667788"));
        await cache.RefreshAsync(default);
        var before = cache.CreateHeartbeat(null);
        controller.CancelOnAlias = "codesign";
        using var cancellation = new CancellationTokenSource();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            cache.RefreshAsync(cancellation.Token));

        var after = cache.CreateHeartbeat(null);
        Assert.Equal(before.SessionId, after.SessionId);
        Assert.Equal(before.SimplySignStatus, after.SimplySignStatus);
        Assert.Equal(before.TokenStatus, after.TokenStatus);
        Assert.Equal(before.CertificateStatus, after.CertificateStatus);
        Assert.Equal(before.KeyStatus, after.KeyStatus);
        Assert.Equal(before.CurrentJobId, after.CurrentJobId);
        Assert.Equal(before.SimplySignProcessSessionId, after.SimplySignProcessSessionId);
        Assert.Equal(before.Authenticode, after.Authenticode);
        Assert.Equal(before.Pdf, after.Pdf);
        Assert.Equal(before.SessionGeneration, after.SessionGeneration);
        Assert.True(after.SessionTransitions.Count > before.SessionTransitions.Count);
        Assert.Equal(
            before.SessionTransitions,
            after.SessionTransitions.Take(before.SessionTransitions.Count));
    }

    [Fact]
    public async Task Background_cache_health_check_skips_while_the_signing_lease_owns_the_process_gate()
    {
        var controller = new RecordingManagementController();
        var authenticode = Alias("codesign", "TOKEN-A", "aabbccdd", "11223344");
        var pdf = Alias("pdfsign", "TOKEN-B", "eeff0011", "55667788");
        await using var gate = new SigningOperationGate();
        await using var manager = new SimplySignSessionManager(
            controller,
            gate,
            new LegacyProbeCatalog(controller, authenticode));
        using var cache = new CapabilityProbeCache(manager, 7, true, true);
        var lease = await manager.AcquireReadySignLeaseAsync(default);
        controller.ProbedAliases.Clear();

        await cache.RunHealthCheckAsync(default);

        Assert.Empty(controller.ProbedAliases);
        await lease.DisposeAsync();
    }

    [Fact]
    public async Task Explicit_cache_relogin_calls_forced_controller_then_reprobes_all_capabilities()
    {
        var controller = new RecordingManagementController();
        var cache = CreateCache(
            controller,
            7,
            Alias("codesign", "TOKEN-A", "aabbccdd", "11223344"),
            Alias("pdfsign", "TOKEN-B", "eeff0011", "55667788"));

        await cache.ReloginAsync(default);

        Assert.Equal(1, controller.LoginCalls);
        Assert.Equal(["codesign"], controller.ProbedAliases);
        Assert.True(cache.CreateHeartbeat(null).Authenticode!.Ready);
        Assert.True(cache.CreateHeartbeat(null).Pdf!.Ready);
    }

    [Fact]
    public async Task Management_bridge_clears_snapshot_on_reconnect_and_old_lease_cannot_detach_new_session()
    {
        var firstSession = new FixedManagementSession(Snapshot());
        var secondSnapshot = SnapshotWithConnection(Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd"));
        var secondSession = new FixedManagementSession(secondSnapshot);
        var bridge = new AgentManagementBridge();
        using var firstLease = bridge.Attach(firstSession);
        Assert.Equal(Snapshot(), await bridge.RefreshAsync(default));

        using var secondLease = bridge.Attach(secondSession);
        Assert.Null(bridge.LatestSnapshot);
        firstLease.Dispose();
        Assert.Equal(secondSnapshot, await bridge.RefreshAsync(default));

        secondLease.Dispose();
        Assert.Null(bridge.LatestSnapshot);
        await Assert.ThrowsAsync<ManagementUnavailableException>(() => bridge.RefreshAsync(default));
    }

    [Fact]
    public async Task Management_bridge_routes_local_jobs_through_the_attached_session_client_and_detaches_them_together()
    {
        var bridge = new AgentManagementBridge();
        var local = new RecordingLocalJobClient();
        var parameters = new AuthenticodeParameters("AA00", "sha256", false);
        using var lease = bridge.Attach(new FixedManagementSession(Snapshot()), local);

        var jobId = await bridge.CreateAndUploadAsync("/tmp/sample.exe", parameters, null, default);
        await bridge.SaveSignedCopyAsync(jobId, "/tmp/sample.signed.exe", false, default);

        Assert.Equal(local.JobId, jobId);
        Assert.Equal("/tmp/sample.exe", local.SourcePath);
        Assert.Same(parameters, local.Parameters);
        Assert.Equal("/tmp/sample.signed.exe", local.DestinationPath);
        lease.Dispose();
        var unavailable = await Assert.ThrowsAsync<LocalJobException>(() =>
            bridge.CreateAndUploadAsync("/tmp/sample.exe", parameters, null, default));
        Assert.Equal("local_job_unavailable", unavailable.Code);
    }

    [Fact]
    public async Task Management_bridge_keeps_an_inflight_local_job_across_session_reconnect_with_the_same_client()
    {
        var bridge = new AgentManagementBridge();
        var local = new RecordingLocalJobClient { BlockSubmit = true };
        var parameters = new AuthenticodeParameters("AA00", "sha256", false);
        using var first = bridge.Attach(new FixedManagementSession(Snapshot()), local);
        var submit = bridge.CreateAndUploadAsync("/tmp/sample.exe", parameters, null, default);
        await local.SubmitStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));

        using var second = bridge.Attach(
            new FixedManagementSession(SnapshotWithConnection(Guid.NewGuid())),
            local);
        local.ReleaseSubmit();

        Assert.Equal(local.JobId, await submit.WaitAsync(TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public void Management_bridge_can_release_the_shared_accepted_source_after_session_detach()
    {
        var bridge = new AgentManagementBridge();
        var local = new RecordingLocalJobClient();
        var session = bridge.Attach(new FixedManagementSession(Snapshot()), local);
        session.Dispose();

        bridge.ReleaseAcceptedSource(local.JobId);

        Assert.Equal([local.JobId], local.ReleasedAcceptedSources);
    }

    [Fact]
    public async Task Cancelled_bridge_refresh_preserves_the_last_complete_snapshot()
    {
        var session = new FixedManagementSession(Snapshot());
        var bridge = new AgentManagementBridge();
        using var lease = bridge.Attach(session);
        var previous = await bridge.RefreshAsync(default);
        session.BlockRefresh = true;
        using var cancellation = new CancellationTokenSource();
        var refresh = bridge.RefreshAsync(cancellation.Token);
        await session.RefreshStarted.Task;
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => refresh);

        Assert.Equal(previous, bridge.LatestSnapshot);
    }

    [Fact]
    public async Task Bridge_bounds_relogin_to_sixty_seconds_and_returns_only_stable_failure()
    {
        var session = new FixedManagementSession(Snapshot()) { BlockRelogin = true };
        var bridge = new AgentManagementBridge(
            refreshTimeout: TimeSpan.FromSeconds(15),
            reloginTimeout: TimeSpan.FromMilliseconds(25));
        using var lease = bridge.Attach(session);

        var error = await Assert.ThrowsAsync<ManagementUnavailableException>(() =>
            bridge.ReloginAsync(default));

        Assert.Equal("management_unavailable", error.Code);
        Assert.NotEqual(Guid.Empty, error.CorrelationId);
        Assert.Null(bridge.LatestSnapshot);
    }

    [Fact]
    public async Task Live_session_refresh_probes_publishes_heartbeat_then_uses_the_same_pipe_transport()
    {
        var controller = new RecordingManagementController();
        using var cache = CreateCache(
            controller,
            7,
            Alias("codesign", "TOKEN-A", "aabbccdd", "11223344"),
            Alias("pdfsign", "TOKEN-B", "eeff0011", "55667788"));
        var transport = new RecordingManagementTransport(Snapshot());
        using var session = new LiveAgentManagementSession(transport, cache);

        var snapshot = await session.RefreshAsync(default);

        Assert.Equal(Snapshot(), snapshot);
        Assert.Equal(["publish", "request"], transport.Operations);
        Assert.True(transport.PublishedHeartbeat!.Authenticode!.Ready);
        Assert.True(transport.PublishedHeartbeat.Pdf!.Ready);
    }

    [Theory]
    [InlineData(AdminControlContract.Refresh)]
    [InlineData(AdminControlContract.Relogin)]
    [InlineData(AdminControlContract.Logout)]
    [InlineData(AdminControlContract.ClearOtp)]
    public async Task Agent_control_operations_publish_without_reentering_the_receive_loop(string operation)
    {
        var controller = new RecordingManagementController();
        using var cache = CreateCache(
            controller,
            7,
            Alias("codesign", "TOKEN-A", "aabbccdd", "11223344"),
            pdfAlias: null);
        var transport = new RecordingManagementTransport(Snapshot());
        using var session = new LiveAgentManagementSession(transport, cache);

        var response = await session.ExecuteAsync(
            new AgentControlRequest(Guid.NewGuid(), operation),
            CancellationToken.None);

        Assert.Null(response.ErrorCode);
        Assert.NotNull(response.Heartbeat);
        Assert.Equal(["publish"], transport.Operations);
    }

    [Fact]
    public async Task Imported_otp_remains_successful_when_the_followup_heartbeat_publish_fails()
    {
        var controller = new RecordingManagementController();
        using var cache = CreateCache(
            controller,
            7,
            Alias("codesign", "TOKEN-A", "aabbccdd", "11223344"),
            pdfAlias: null);
        var transport = new RecordingManagementTransport(Snapshot())
        {
            PublishError = new IOException("synthetic_heartbeat_failure"),
        };
        var otpStore = new RecordingOtpStore();
        using var session = new LiveAgentManagementSession(transport, cache, otpStore);

        var response = await session.ExecuteAsync(
            new AgentControlRequest(
                Guid.NewGuid(),
                AdminControlContract.ImportOtp,
                "otpauth://totp/Certum:user?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=6&period=30&issuer=Certum"),
            CancellationToken.None);

        Assert.Null(response.ErrorCode);
        Assert.NotNull(response.Heartbeat);
        Assert.Equal(1, otpStore.SaveCalls);
        Assert.Empty(controller.ProbedAliases);
        Assert.Empty(transport.Operations);
    }

    [Fact]
    public async Task Live_session_relogin_rejects_active_job_before_controller_or_pipe_calls()
    {
        var controller = new RecordingManagementController();
        using var cache = CreateCache(
            controller,
            7,
            Alias("codesign", "TOKEN-A", "aabbccdd", "11223344"),
            pdfAlias: null);
        var transport = new RecordingManagementTransport(Snapshot())
        {
            CurrentJobId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        };
        using var session = new LiveAgentManagementSession(transport, cache);

        await Assert.ThrowsAsync<ManagementUnavailableException>(() => session.ReloginAsync(default));

        Assert.Empty(controller.ReloginAliases);
        Assert.Empty(controller.ProbedAliases);
        Assert.Empty(transport.Operations);
    }

    [Fact]
    public async Task Live_session_clear_otp_and_logout_rejects_active_job_without_mutation()
    {
        var controller = new RecordingManagementController();
        using var cache = CreateCache(
            controller,
            7,
            Alias("codesign", "TOKEN-A", "aabbccdd", "11223344"),
            pdfAlias: null);
        var transport = new RecordingManagementTransport(Snapshot())
        {
            CurrentJobId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        };
        using var session = new LiveAgentManagementSession(transport, cache);

        await Assert.ThrowsAsync<ManagementUnavailableException>(() =>
            session.ClearOtpAndLogoutAsync(default));

        Assert.Equal(0, controller.CloseCalls);
        Assert.Equal(0, controller.DeleteOtpCalls);
        Assert.Empty(transport.Operations);
    }

    [Fact]
    public async Task Live_session_clear_otp_and_logout_publishes_logged_out_heartbeat_before_readback()
    {
        var controller = new RecordingManagementController();
        using var cache = CreateCache(
            controller,
            7,
            Alias("codesign", "TOKEN-A", "aabbccdd", "11223344"),
            pdfAlias: null);
        var transport = new RecordingManagementTransport(Snapshot());
        using var session = new LiveAgentManagementSession(transport, cache);

        var snapshot = await session.ClearOtpAndLogoutAsync(default);

        Assert.Equal(Snapshot(), snapshot);
        Assert.Equal(1, controller.CloseCalls);
        Assert.Equal(1, controller.DeleteOtpCalls);
        Assert.Equal(["publish", "request"], transport.Operations);
        Assert.Equal("not_ready", transport.PublishedHeartbeat!.SimplySignStatus);
        Assert.Equal("not_ready", transport.PublishedHeartbeat.TokenStatus);
        Assert.Empty(transport.PublishedHeartbeat.Certificates);
    }

    [Fact]
    public async Task Live_session_logout_preserves_otp_and_publishes_logged_out_heartbeat()
    {
        var controller = new RecordingManagementController();
        using var cache = CreateCache(
            controller,
            7,
            Alias("codesign", "TOKEN-A", "aabbccdd", "11223344"),
            pdfAlias: null);
        var transport = new RecordingManagementTransport(Snapshot());
        using var session = new LiveAgentManagementSession(transport, cache);

        _ = await session.LogoutAsync(default);

        Assert.Equal(1, controller.CloseCalls);
        Assert.Equal(0, controller.DeleteOtpCalls);
        Assert.Equal(["publish", "request"], transport.Operations);
        Assert.Equal("not_ready", transport.PublishedHeartbeat!.SimplySignStatus);
        Assert.Empty(transport.PublishedHeartbeat.Certificates);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Live_session_async_dispose_cancels_and_joins_blocking_management_before_disposing_gates(
        bool relogin)
    {
        var controller = new BlockingManagementController(relogin);
        using var cache = CreateCache(
            controller,
            7,
            Alias("codesign", "TOKEN-A", "aabbccdd", "11223344"),
            pdfAlias: null);
        var session = new LiveAgentManagementSession(
            new RecordingManagementTransport(Snapshot()),
            cache);
        var asyncDisposable = Assert.IsAssignableFrom<IAsyncDisposable>(session);
        var operation = relogin
            ? session.ReloginAsync(default)
            : session.RefreshAsync(default);
        await controller.Entered.Task.WaitAsync(TimeSpan.FromSeconds(1));

        var firstDispose = asyncDisposable.DisposeAsync().AsTask();
        var secondDispose = asyncDisposable.DisposeAsync().AsTask();
        await Task.Yield();
        Assert.False(firstDispose.IsCompleted);
        Assert.Same(firstDispose, secondDispose);
        controller.Release();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);
        await firstDispose.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.True(secondDispose.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task Initial_management_probe_failure_does_not_terminate_the_agent_pipe_session()
    {
        var controller = new RecordingManagementController
        {
            ProbeError = new SimplySignException("probe_failed"),
        };
        using var cache = CreateCache(
            controller,
            7,
            Alias("codesign", "TOKEN-A", "aabbccdd", "11223344"),
            pdfAlias: null);
        await using var stream = new ScriptedDuplexStream();
        var client = Client(stream, []);
        var session = new AgentPipeSession(
            client,
            RejectCommands,
            ["authenticode"],
            cache);

        var run = session.RunAsync(
            new InteractiveSessionInfo(7, "S-1-5-21-1000", "1000"),
            new AgentReadiness("ready"),
            default);

        await stream.WaitForWrittenMessageCountAsync(1);
        Assert.False(run.IsCompleted);
        stream.CompleteInput();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Local_job_requests_share_the_management_writer_and_single_receive_loop()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = Client(stream, [SecondRequestId]);
        Assert.IsAssignableFrom<ILocalJobTransport>(client);
        var commandHandled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var run = client.RunAsync(
            Hello(),
            Heartbeat,
            (command, _, _) =>
            {
                commandHandled.TrySetResult();
                return Task.FromResult<JobTerminalMessage>(new JobCompleted(
                    command.JobId,
                    command.DispatchId,
                    10,
                    new string('b', 64)));
            },
            default);
        await stream.WaitForWrittenMessageCountAsync(1);
        var local = client.CreateLocalJobAsync(
            new LocalJobCreateRequest(
                FirstRequestId,
                "release.exe",
                ".exe",
                10,
                "{\"kind\":\"authenticode\"}"),
            default);
        await stream.WaitForWrittenMessageCountAsync(2);
        var jobId = Guid.Parse("33333333-3333-3333-3333-333333333333");
        await stream.EnqueueAsync(new LocalJobUploadLease(
            FirstRequestId,
            jobId,
            "00112233445566778899aabbccddeeff",
            $"{jobId:N}/input.exe.part",
            DateTimeOffset.UtcNow.AddMinutes(10)));

        var lease = await local.WaitAsync(TimeSpan.FromSeconds(1));
        var management = client.GetManagementSnapshotAsync(default);
        await stream.WaitForWrittenMessageCountAsync(3);
        await stream.EnqueueAsync(Command());
        await stream.EnqueueAsync(new ManagementSnapshotResponse(SecondRequestId, Snapshot(), null, null));

        Assert.Equal(jobId, lease.JobId);
        Assert.Equal(Snapshot(), await management.WaitAsync(TimeSpan.FromSeconds(1)));
        await commandHandled.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(1, stream.MaximumConcurrentReaders);
        Assert.False(run.IsCompleted);
        stream.CompleteInput();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Management_and_local_requests_cannot_share_the_same_live_correlation_id()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = Client(stream, [FirstRequestId], TimeSpan.FromMilliseconds(25));
        var run = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await stream.WaitForWrittenMessageCountAsync(1);
        var local = client.CreateLocalJobAsync(
            new LocalJobCreateRequest(
                FirstRequestId,
                "release.exe",
                ".exe",
                10,
                "{\"kind\":\"authenticode\"}"),
            default);
        await stream.WaitForWrittenMessageCountAsync(2);

        await Assert.ThrowsAsync<ManagementUnavailableException>(() =>
            client.GetManagementSnapshotAsync(default));
        Assert.Equal(2, await stream.WrittenMessageCountAsync());

        var jobId = Guid.Parse("33333333-3333-3333-3333-333333333333");
        await stream.EnqueueAsync(new LocalJobUploadLease(
            FirstRequestId,
            jobId,
            "00112233445566778899aabbccddeeff",
            $"{jobId:N}/input.exe.part",
            DateTimeOffset.UtcNow.AddMinutes(10)));
        Assert.Equal(jobId, (await local).JobId);
        stream.CompleteInput();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Complete_timeout_retries_the_exact_request_without_creating_a_new_request()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = new AgentPipeClient(
            _ => ValueTask.FromResult<Stream>(stream),
            new InfiniteDelay(),
            admissionLocked: null,
            localCreateTimeout: TimeSpan.FromMilliseconds(10),
            localCompleteTimeout: TimeSpan.FromMilliseconds(40));
        var run = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await stream.WaitForWrittenMessageCountAsync(1);
        var completed = new LocalJobUploadCompleted(
            FirstRequestId,
            Guid.Parse("33333333-3333-3333-3333-333333333333"),
            "00112233445566778899aabbccddeeff",
            10,
            new string('a', 64));

        var pending = client.CompleteLocalJobAsync(completed, default);
        await stream.WaitForWrittenMessageCountAsync(3);
        var sent = (await stream.WrittenMessagesAsync()).OfType<LocalJobUploadCompleted>().ToArray();

        Assert.Equal([completed, completed], sent);
        await stream.EnqueueAsync(new LocalJobAccepted(completed.RequestId, completed.JobId));
        Assert.Equal(completed.JobId, (await pending.WaitAsync(TimeSpan.FromSeconds(1))).JobId);
        Assert.False(run.IsCompleted);
        stream.CompleteInput();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Complete_disconnect_retries_the_exact_request_after_reconnect()
    {
        await using var firstStream = new ScriptedDuplexStream();
        await using var secondStream = new ScriptedDuplexStream();
        var streams = new ConcurrentQueue<Stream>([firstStream, secondStream]);
        var reconnectWaitStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var client = new AgentPipeClient(
            _ => ValueTask.FromResult(
                streams.TryDequeue(out var stream)
                    ? stream
                    : throw new InvalidOperationException("connection_exhausted")),
            new InfiniteDelay(),
            admissionLocked: null,
            localCompleteTimeout: TimeSpan.FromSeconds(1),
            localReconnectWaitStarted: () => reconnectWaitStarted.TrySetResult());
        var firstRun = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await firstStream.WaitForWrittenMessageCountAsync(1);
        var completed = new LocalJobUploadCompleted(
            FirstRequestId,
            Guid.Parse("33333333-3333-3333-3333-333333333333"),
            "00112233445566778899aabbccddeeff",
            10,
            new string('a', 64));

        var pending = client.CompleteLocalJobAsync(completed, default);
        await firstStream.WaitForWrittenMessageCountAsync(2);
        firstStream.CompleteInput();
        await firstRun.WaitAsync(TimeSpan.FromSeconds(1));
        await reconnectWaitStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        var secondRun = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await secondStream.WaitForWrittenMessageCountAsync(1);
        await secondStream.WaitForWrittenMessageCountAsync(2);

        Assert.Equal(
            [completed],
            (await firstStream.WrittenMessagesAsync()).OfType<LocalJobUploadCompleted>());
        Assert.Equal(
            [completed],
            (await secondStream.WrittenMessagesAsync()).OfType<LocalJobUploadCompleted>());
        await secondStream.EnqueueAsync(new LocalJobAccepted(completed.RequestId, completed.JobId));
        Assert.Equal(completed.JobId, (await pending.WaitAsync(TimeSpan.FromSeconds(1))).JobId);
        secondStream.CompleteInput();
        await secondRun.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Create_disconnect_retries_the_exact_request_after_reconnect()
    {
        await using var firstStream = new ScriptedDuplexStream();
        await using var secondStream = new ScriptedDuplexStream();
        var streams = new ConcurrentQueue<Stream>([firstStream, secondStream]);
        var reconnectWaitStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var client = new AgentPipeClient(
            _ => ValueTask.FromResult(
                streams.TryDequeue(out var stream)
                    ? stream
                    : throw new InvalidOperationException("connection_exhausted")),
            new InfiniteDelay(),
            admissionLocked: null,
            localCreateTimeout: TimeSpan.FromSeconds(1),
            localReconnectWaitStarted: () => reconnectWaitStarted.TrySetResult());
        var firstRun = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await firstStream.WaitForWrittenMessageCountAsync(1);
        var request = new LocalJobCreateRequest(
            FirstRequestId,
            "release.exe",
            ".exe",
            10,
            "{\"kind\":\"authenticode\"}");

        var pending = client.CreateLocalJobAsync(request, default);
        await firstStream.WaitForWrittenMessageCountAsync(2);
        firstStream.CompleteInput();
        await firstRun.WaitAsync(TimeSpan.FromSeconds(1));
        await reconnectWaitStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        var secondRun = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await secondStream.WaitForWrittenMessageCountAsync(1);
        await secondStream.WaitForWrittenMessageCountAsync(2);

        Assert.Equal(
            [request],
            (await firstStream.WrittenMessagesAsync()).OfType<LocalJobCreateRequest>());
        Assert.Equal(
            [request],
            (await secondStream.WrittenMessagesAsync()).OfType<LocalJobCreateRequest>());
        var jobId = Guid.Parse("33333333-3333-3333-3333-333333333333");
        await secondStream.EnqueueAsync(new LocalJobAccepted(request.RequestId, jobId));
        Assert.Equal(jobId, (await pending.WaitAsync(TimeSpan.FromSeconds(1))).JobId);
        secondStream.CompleteInput();
        await secondRun.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Reconnect_resets_admission_after_the_old_session_was_stopped_and_joined()
    {
        await using var firstStream = new ScriptedDuplexStream();
        await using var secondStream = new ScriptedDuplexStream();
        var streams = new ConcurrentQueue<Stream>([firstStream, secondStream]);
        var client = new AgentPipeClient(
            _ => ValueTask.FromResult(
                streams.TryDequeue(out var stream)
                    ? stream
                    : throw new InvalidOperationException("connection_exhausted")),
            new InfiniteDelay());
        var firstRun = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await firstStream.WaitForWrittenMessageCountAsync(1);
        firstStream.CompleteInput();
        await firstRun.WaitAsync(TimeSpan.FromSeconds(1));
        client.StopAcceptingNewJobs();
        var handled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var secondRun = client.RunAsync(
            Hello(),
            Heartbeat,
            (command, _, _) =>
            {
                handled.TrySetResult();
                return Task.FromResult<JobTerminalMessage>(new JobCompleted(
                    command.JobId,
                    command.DispatchId,
                    10,
                    new string('b', 64)));
            },
            default);
        await secondStream.WaitForWrittenMessageCountAsync(1);
        await secondStream.EnqueueAsync(Command());

        await handled.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await secondStream.WaitForWrittenMessageCountAsync(2);
        Assert.IsType<JobCompleted>(
            Assert.Single((await secondStream.WrittenMessagesAsync()).OfType<JobCompleted>()));
        secondStream.CompleteInput();
        await secondRun.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Create_accepts_an_idempotently_recovered_already_accepted_job()
    {
        await using var stream = new ScriptedDuplexStream();
        var client = Client(stream, []);
        var run = client.RunAsync(Hello(), Heartbeat, RejectCommands, default);
        await stream.WaitForWrittenMessageCountAsync(1);
        var request = new LocalJobCreateRequest(
            FirstRequestId,
            "release.exe",
            ".exe",
            10,
            "{\"kind\":\"authenticode\"}");
        var pending = client.CreateLocalJobAsync(request, default);
        await stream.WaitForWrittenMessageCountAsync(2);
        var jobId = Guid.Parse("33333333-3333-3333-3333-333333333333");

        await stream.EnqueueAsync(new LocalJobAccepted(request.RequestId, jobId));
        var outcome = await pending;

        Assert.Null(outcome.Lease);
        Assert.Equal(jobId, outcome.AcceptedJobId);
        stream.CompleteInput();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    private static AgentPipeClient Client(
        ScriptedDuplexStream stream,
        IReadOnlyList<Guid> requestIds,
        TimeSpan? timeout = null)
    {
        var ids = new ConcurrentQueue<Guid>(requestIds);
        return new AgentPipeClient(
            _ => ValueTask.FromResult<Stream>(stream),
            new InfiniteDelay(),
            admissionLocked: null,
            requestIdFactory: () => ids.TryDequeue(out var id) ? id : throw new InvalidOperationException("request id exhausted"),
            managementTimeout: timeout ?? TimeSpan.FromSeconds(15));
    }

    private static AgentHello Hello() =>
        new(LengthPrefixedJsonProtocol.ProtocolVersion, 321, 7, "S-1-5-21-1000", "1.0.0", ["authenticode", "pdf"]);

    private static AgentHeartbeat Heartbeat() =>
        ProtocolV3TestFixtures.Heartbeat();

    private static SignJobCommand Command() =>
        new(
            Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            1,
            ".exe",
            "{}",
            10,
            new string('a', 64));

    private static Task<JobTerminalMessage> RejectCommands(
        SignJobCommand command,
        JobProgressReporter progress,
        CancellationToken cancellationToken) =>
        throw new InvalidOperationException("No command expected.");

    private static Task<JobTerminalPublication> RejectPublications(
        SignJobCommand command,
        JobProgressReporter progress,
        CancellationToken cancellationToken) =>
        throw new InvalidOperationException("No command expected.");

    private static ManagementSnapshot Snapshot() =>
        new(
            ManagementSnapshot.CurrentVersion,
            new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero),
            Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            true,
            true,
            7,
            7,
            1_000,
            true,
            7,
            ReadyCapability(),
            ReadyCapability(),
            0,
            0,
            null,
            [],
            1);

    private static ManagementSnapshot SnapshotWithConnection(Guid connectionId)
    {
        var source = Snapshot();
        return new ManagementSnapshot(
            source.SnapshotVersion,
            source.GeneratedAtUtc,
            connectionId,
            source.ServiceAvailable,
            source.AgentConnected,
            source.AgentSessionId,
            source.HeartbeatSessionId,
            source.HeartbeatAgeMilliseconds,
            source.SimplySignProcessRunning,
            source.SimplySignProcessSessionId,
            source.Authenticode,
            source.Pdf,
            source.QueuedJobCount,
            source.ActiveJobCount,
            source.CurrentJob,
            source.RecentJobs,
            source.SessionGeneration);
    }

    private static CapabilitySnapshot ReadyCapability() =>
        ProtocolV3TestFixtures.ReadyCapability();

    private static CertificateAlias Alias(
        string name,
        string token,
        string certificate,
        string privateKey) =>
        new(name, TestPaths.Controlled("pkcs11.dll"), 1, token, certificate, privateKey);

    private static CapabilityProbeCache CreateCache(
        ISimplySignSessionDriver driver,
        int sessionId,
        CertificateAlias? authenticode,
        CertificateAlias? pdfAlias)
    {
        var probeAlias = authenticode ?? pdfAlias!;
        var manager = new SimplySignSessionManager(
            driver,
            new SigningOperationGate(),
            new LegacyProbeCatalog((ILegacyProbeDriver)driver, probeAlias));
        return new CapabilityProbeCache(manager, sessionId, true, pdfAlias is not null);
    }

    private static CapabilityProbeCache CreateCacheWithPdfResolver(
        IInstalledPdfToolResolver resolver)
    {
        var controller = new RecordingManagementController();
        var authenticode = Alias("codesign", "TOKEN-A", "aabbccdd", "11223344");
        var manager = new SimplySignSessionManager(
            controller,
            new SigningOperationGate(),
            new LegacyProbeCatalog(controller, authenticode));
        return new CapabilityProbeCache(
            manager,
            7,
            authenticodeConfigured: true,
            pdfConfigured: true,
            diagnostics: null,
            pdfToolResolver: resolver);
    }

    private static InstalledPdfTool InstalledTool() =>
        new(
            @"C:\Program Files\SimplySignAuto\tools\pdf\1.0.0\SimplySignPdfSigner.exe",
            new string('a', 64));

    private static InstalledPdfToolResolution Resolution(InstalledPdfToolStatus status) => status switch
    {
        InstalledPdfToolStatus.NotInstalled => InstalledPdfToolResolution.NotInstalled(),
        InstalledPdfToolStatus.Tampered => InstalledPdfToolResolution.Tampered(),
        InstalledPdfToolStatus.Ready => InstalledPdfToolResolution.Ready(InstalledTool()),
        _ => throw new ArgumentOutOfRangeException(nameof(status)),
    };

    private sealed class SequencePdfToolResolver(
        params InstalledPdfToolResolution[] resolutions) : IInstalledPdfToolResolver
    {
        private int _next;

        public int Calls { get; private set; }

        public Task<InstalledPdfToolResolution> ResolveAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            var index = Math.Min(_next++, resolutions.Length - 1);
            return Task.FromResult(resolutions[index]);
        }
    }

    private interface ILegacyProbeDriver
    {
        Task<ProbeResult> ProbeAsync(CertificateAlias alias, CancellationToken cancellationToken);
    }

    private sealed class LegacyProbeCatalog(
        ILegacyProbeDriver driver,
        CertificateAlias alias) : ICertificateCatalog
    {
        private long _generation;

        public CertificateCatalogSnapshot? Current { get; private set; }
        public IReadOnlyList<CertificateDisplaySummary> DisplaySummaries => [];

        public async Task<CertificateCatalogSnapshot> RefreshAsync(CancellationToken cancellationToken)
        {
            var result = await driver.ProbeAsync(alias, cancellationToken);
            if (!result.Ready)
            {
                throw new SigningException("certificate_catalog_unavailable");
            }

            Current = new CertificateCatalogSnapshot(
                ++_generation,
                DateTimeOffset.UnixEpoch + TimeSpan.FromTicks(_generation),
                new Dictionary<string, IReadOnlyList<SigningCertificate>>(StringComparer.Ordinal));
            return Current;
        }

        public SigningCertificate Resolve(string serialNumber, SigningKind kind) =>
            throw new NotSupportedException();

        public void Invalidate() => Current = null;
    }

    private sealed class RecordingManagementController : ISimplySignSessionDriver, ILegacyProbeDriver
    {
        public List<string> ProbedAliases { get; } = [];
        public List<string> ReloginAliases { get; } = [];
        public string? CancelOnAlias { get; set; }
        public Exception? ProbeError { get; set; }
        public int LoginCalls { get; private set; }
        public int CloseCalls { get; private set; }
        public int DeleteOtpCalls { get; private set; }
        public int VerifiedSessionId => 7;
        public DateTimeOffset UtcNow { get; private set; } = DateTimeOffset.UnixEpoch;

        public SimplySignProcessState CheckProcessOnly() => new(true, VerifiedSessionId);

        public Task<ProbeResult> ProbeAsync(
            CertificateAlias alias,
            CancellationToken cancellationToken)
        {
            ProbedAliases.Add(alias.Name);
            if (ProbeError is { } probeError)
            {
                throw probeError;
            }

            if (alias.Name == CancelOnAlias)
            {
                throw new OperationCanceledException(cancellationToken);
            }

            return Task.FromResult(ProbeResult.ReadyFor(7));
        }

        public Task CloseAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CloseCalls++;
            return Task.CompletedTask;
        }

        public Task DeleteOtpAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DeleteOtpCalls++;
            return Task.CompletedTask;
        }

        public Task<OtpauthProfile> LoadOtpAsync(CancellationToken cancellationToken) =>
            Task.FromResult(TestProfile());

        public Task<long> StartLoginAsync(OtpauthProfile profile, CancellationToken cancellationToken)
        {
            LoginCalls++;
            return Task.FromResult(0L);
        }

        public Task WaitForCounterAfterAsync(OtpauthProfile profile, long priorCounter, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            UtcNow += delay;
            return Task.CompletedTask;
        }
    }

    private sealed class BlockingManagementController(bool blockRelogin) : ISimplySignSessionDriver, ILegacyProbeDriver
    {
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Entered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int VerifiedSessionId => 7;
        public DateTimeOffset UtcNow { get; private set; } = DateTimeOffset.UnixEpoch;

        public SimplySignProcessState CheckProcessOnly() => new(true, VerifiedSessionId);

        public async Task<ProbeResult> ProbeAsync(
            CertificateAlias alias,
            CancellationToken cancellationToken)
        {
            if (!blockRelogin)
            {
                Entered.TrySetResult();
                await _release.Task;
            }

            cancellationToken.ThrowIfCancellationRequested();
            return ProbeResult.ReadyFor(7);
        }

        public async Task CloseAsync(CancellationToken cancellationToken)
        {
            if (blockRelogin)
            {
                Entered.TrySetResult();
                await _release.Task;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }

        public Task<OtpauthProfile> LoadOtpAsync(CancellationToken cancellationToken) =>
            Task.FromResult(TestProfile());

        public Task<long> StartLoginAsync(OtpauthProfile profile, CancellationToken cancellationToken) =>
            Task.FromResult(0L);

        public Task WaitForCounterAfterAsync(OtpauthProfile profile, long priorCounter, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            UtcNow += delay;
            return Task.CompletedTask;
        }

        public void Release() => _release.TrySetResult();
    }

    private static OtpauthProfile TestProfile() => new(
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
        "SHA256",
        6,
        30,
        "Certum",
        "user");

    private sealed class InfiniteDelay : IAgentDelay
    {
        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
            Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
    }

    private sealed class FixedManagementSession(ManagementSnapshot snapshot) : IAgentManagementSession
    {
        public TaskCompletionSource RefreshStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool BlockRefresh { get; set; }
        public bool BlockRelogin { get; set; }

        public async Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken)
        {
            RefreshStarted.TrySetResult();
            if (BlockRefresh)
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }

            return snapshot;
        }

        public async Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken)
        {
            if (BlockRelogin)
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }

            return snapshot;
        }
    }

    private sealed class RecordingLocalJobClient : ILocalJobClient
    {
        private readonly TaskCompletionSource _releaseSubmit =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Guid JobId { get; } = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

        public bool BlockSubmit { get; set; }

        public TaskCompletionSource SubmitStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public string? SourcePath { get; private set; }

        public SigningParameters? Parameters { get; private set; }

        public string? DestinationPath { get; private set; }

        public List<Guid> ReleasedAcceptedSources { get; } = [];

        public async Task<Guid> CreateAndUploadAsync(
            string path,
            SigningParameters parameters,
            IProgress<LocalCopyProgress>? progress,
            CancellationToken cancellationToken)
        {
            SourcePath = path;
            Parameters = parameters;
            SubmitStarted.TrySetResult();
            if (BlockSubmit)
            {
                await _releaseSubmit.Task.WaitAsync(cancellationToken);
            }

            return JobId;
        }

        public void ReleaseSubmit() => _releaseSubmit.TrySetResult();

        public Task SaveSignedCopyAsync(
            Guid jobId,
            string destinationPath,
            bool overwrite,
            CancellationToken cancellationToken)
        {
            Assert.Equal(JobId, jobId);
            DestinationPath = destinationPath;
            return Task.CompletedTask;
        }

        public void ReleaseAcceptedSource(Guid jobId)
        {
            ReleasedAcceptedSources.Add(jobId);
        }
    }

    private sealed class RecordingManagementTransport(ManagementSnapshot snapshot) : IAgentManagementTransport
    {
        public List<string> Operations { get; } = [];
        public Guid? CurrentJobId { get; set; }
        public AgentHeartbeat? PublishedHeartbeat { get; private set; }
        public Exception? PublishError { get; set; }

        public Task PublishHeartbeatAsync(
            AgentHeartbeat heartbeat,
            CancellationToken cancellationToken)
        {
            Operations.Add("publish");
            PublishedHeartbeat = heartbeat;
            if (PublishError is { } error)
            {
                throw error;
            }

            return Task.CompletedTask;
        }

        public Task<ManagementSnapshot> GetManagementSnapshotAsync(CancellationToken cancellationToken)
        {
            Operations.Add("request");
            return Task.FromResult(snapshot);
        }
    }

    private sealed class RecordingOtpStore : IOtpStore
    {
        public string Path => TestPaths.Controlled("otp.dat");

        public int SaveCalls { get; private set; }

        public Task SaveAsync(OtpauthProfile profile, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SaveCalls++;
            return Task.CompletedTask;
        }

        public Task<OtpauthProfile> LoadAsync(CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class ScriptedDuplexStream : Stream
    {
        private readonly Channel<InputFrame> _input = Channel.CreateUnbounded<InputFrame>();
        private readonly object _outputSync = new();
        private readonly MemoryStream _output = new();
        private InputFrame? _currentInput;
        private int _currentOffset;
        private int _activeReaders;
        private int _maximumConcurrentReaders;
        private TaskCompletionSource? _pendingReaderAdvanced;
        private TaskCompletionSource _outputChanged =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly object _writeControlSync = new();
        private int? _writesBeforeBlock;
        private TaskCompletionSource? _releaseWrite;
        private int _failNextWrite;

        public int MaximumConcurrentReaders => Volatile.Read(ref _maximumConcurrentReaders);
        public TaskCompletionSource WriteBlocked { get; private set; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public async Task EnqueueAsync(AgentMessage message)
        {
            await _input.Writer.WriteAsync(new InputFrame(await EncodeAsync(message), null));
        }

        public async Task EnqueueAndWaitUntilReaderAdvancedAsync(AgentMessage message)
        {
            var readerAdvanced = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            await _input.Writer.WriteAsync(new InputFrame(await EncodeAsync(message), readerAdvanced));
            await readerAdvanced.Task.WaitAsync(TimeSpan.FromSeconds(1));
        }

        private static async Task<byte[]> EncodeAsync(AgentMessage message)
        {
            await using var encoded = new MemoryStream();
            await LengthPrefixedJsonProtocol.WriteAsync(encoded, message, default);
            return encoded.ToArray();
        }

        public async Task EnqueueRawJsonAsync(string json)
        {
            var payload = Encoding.UTF8.GetBytes(json);
            var frame = new byte[sizeof(int) + payload.Length];
            BinaryPrimitives.WriteInt32BigEndian(frame, payload.Length);
            payload.CopyTo(frame.AsSpan(sizeof(int)));
            await _input.Writer.WriteAsync(new InputFrame(frame, null));
        }

        public void CompleteInput() => _input.Writer.TryComplete();

        public void BlockAfterWrites(int successfulWritesBeforeBlock)
        {
            Assert.True(successfulWritesBeforeBlock >= 0);
            lock (_writeControlSync)
            {
                Assert.Null(_writesBeforeBlock);
                _writesBeforeBlock = successfulWritesBeforeBlock;
                WriteBlocked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                _releaseWrite = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            }
        }

        public void ReleaseWrite()
        {
            lock (_writeControlSync)
            {
                _releaseWrite?.TrySetResult();
            }
        }

        public void FailNextWrite() => Volatile.Write(ref _failNextWrite, 1);

        public async Task WaitForWrittenMessageCountAsync(int expected)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
            while (true)
            {
                byte[] bytes;
                Task changed;
                lock (_outputSync)
                {
                    bytes = _output.ToArray();
                    changed = _outputChanged.Task;
                }

                if (await CountWrittenMessagesAsync(bytes) >= expected)
                {
                    return;
                }

                try
                {
                    await changed.WaitAsync(timeout.Token);
                }
                catch (OperationCanceledException) when (timeout.IsCancellationRequested)
                {
                    Assert.Fail($"Expected {expected} complete outbound messages.");
                }
            }
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            var readers = Interlocked.Increment(ref _activeReaders);
            UpdateMaximum(readers);
            try
            {
                Interlocked.Exchange(ref _pendingReaderAdvanced, null)?.TrySetResult();
                if (_currentInput is null || _currentOffset == _currentInput.Bytes.Length)
                {
                    if (!await _input.Reader.WaitToReadAsync(cancellationToken))
                    {
                        return 0;
                    }

                    Assert.True(_input.Reader.TryRead(out _currentInput));
                    _currentOffset = 0;
                }

                var count = Math.Min(buffer.Length, _currentInput!.Bytes.Length - _currentOffset);
                _currentInput.Bytes.AsMemory(_currentOffset, count).CopyTo(buffer);
                _currentOffset += count;
                if (_currentOffset == _currentInput.Bytes.Length && _currentInput.ReaderAdvanced is not null)
                {
                    Assert.Null(Interlocked.CompareExchange(
                        ref _pendingReaderAdvanced,
                        _currentInput.ReaderAdvanced,
                        null));
                }
                return count;
            }
            finally
            {
                Interlocked.Decrement(ref _activeReaders);
            }
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Interlocked.Exchange(ref _failNextWrite, 0) != 0)
            {
                throw new IOException("synthetic_startup_response_write_failure");
            }

            Task? blocked = null;
            lock (_writeControlSync)
            {
                if (_writesBeforeBlock is > 0)
                {
                    _writesBeforeBlock--;
                }
                else if (_writesBeforeBlock == 0)
                {
                    _writesBeforeBlock = null;
                    WriteBlocked.TrySetResult();
                    blocked = _releaseWrite!.Task;
                }
            }

            if (blocked is not null)
            {
                await blocked.WaitAsync(cancellationToken);
            }

            TaskCompletionSource changed;
            lock (_outputSync)
            {
                _output.Write(buffer.Span);
                changed = _outputChanged;
                _outputChanged = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            }
            changed.TrySetResult();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                CompleteInput();
                _output.Dispose();
            }

            base.Dispose(disposing);
        }

        public async Task<int> WrittenMessageCountAsync()
        {
            byte[] bytes;
            lock (_outputSync)
            {
                bytes = _output.ToArray();
            }

            return await CountWrittenMessagesAsync(bytes);
        }

        private static async Task<int> CountWrittenMessagesAsync(byte[] bytes)
        {
            await using var copy = new MemoryStream(bytes);
            var count = 0;
            while (copy.Position < copy.Length)
            {
                try
                {
                    _ = await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(copy, default);
                    count++;
                }
                catch (ProtocolException error) when (error.Code == "unexpected_eof")
                {
                    break;
                }
            }

            return count;
        }

        private sealed record InputFrame(byte[] Bytes, TaskCompletionSource? ReaderAdvanced);

        public async Task<IReadOnlyList<AgentMessage>> WrittenMessagesAsync()
        {
            byte[] bytes;
            lock (_outputSync)
            {
                bytes = _output.ToArray();
            }

            await using var copy = new MemoryStream(bytes);
            var messages = new List<AgentMessage>();
            while (copy.Position < copy.Length)
            {
                try
                {
                    var message = await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(copy, default);
                    if (message is not null)
                    {
                        messages.Add(message);
                    }
                }
                catch (ProtocolException error) when (error.Code == "unexpected_eof")
                {
                    break;
                }
            }

            return messages;
        }

        private void UpdateMaximum(int readers)
        {
            var observed = Volatile.Read(ref _maximumConcurrentReaders);
            while (readers > observed)
            {
                var prior = Interlocked.CompareExchange(ref _maximumConcurrentReaders, readers, observed);
                if (prior == observed)
                {
                    return;
                }

                observed = prior;
            }
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
