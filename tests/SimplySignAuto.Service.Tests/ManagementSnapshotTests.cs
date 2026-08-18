using Microsoft.Data.Sqlite;
using System.Threading.Channels;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Protocol;
using SimplySignAuto.Service.Ipc;
using SimplySignAuto.Service.Jobs;
using Xunit;

namespace SimplySignAuto.Service.Tests;

public sealed class ManagementSnapshotTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 8, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Provider_uses_service_receive_time_and_maps_only_bounded_job_metadata()
    {
        var connectionId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        var current = Job(
            Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            JobState.Verifying,
            FileKind.Authenticode) with
        {
            StartedAt = Now.AddSeconds(-9),
        };
        var recent = Job(
            Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            JobState.Failed,
            FileKind.Pdf) with
        {
            CompletedAt = Now.AddSeconds(-3),
            ErrorCode = "pdf_sign_failed",
            ErrorMessage = "C:/sensitive/helper.exe printed a secret",
        };
        var jobs = new FixedManagementJobStore(new JobManagementState(2, 1, current, [recent]));
        var provider = new ServiceManagementSnapshotProvider(jobs, new FixedTimeProvider(Now));
        var heartbeat = new AgentHeartbeat(
            7,
            "ready",
            "ready",
            "ready",
            "ready",
            current.Id,
            7,
            ReadyCapability("34567890", "abcdef12", "1234abcd"),
            CapabilitySnapshot.NotConfigured(),
            1);
        var health = new AgentHealthSnapshot(
            connectionId,
            7,
            ["authenticode"],
            Now.AddSeconds(-15),
            heartbeat);

        var snapshot = await provider.CreateAsync(health, default);

        Assert.Equal(15_000, snapshot.HeartbeatAgeMilliseconds);
        Assert.Equal(connectionId, snapshot.ConnectionId);
        Assert.Equal(7, snapshot.AgentSessionId);
        Assert.Equal(7, snapshot.HeartbeatSessionId);
        Assert.True(snapshot.SimplySignProcessRunning);
        Assert.Equal(7, snapshot.SimplySignProcessSessionId);
        Assert.Equal(2, snapshot.QueuedJobCount);
        Assert.Equal(1, snapshot.ActiveJobCount);
        Assert.Equal("verifying", snapshot.CurrentJob!.Stage);
        Assert.Equal(9, snapshot.CurrentJob.ElapsedSeconds);
        Assert.Equal("pdf_sign_failed", Assert.Single(snapshot.RecentJobs).ErrorCode);
        Assert.DoesNotContain("sensitive", snapshot.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("helper.exe", snapshot.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Provider_preserves_negative_heartbeat_age_for_fail_closed_mapping()
    {
        var provider = new ServiceManagementSnapshotProvider(
            new FixedManagementJobStore(new JobManagementState(0, 0, null, [])),
            new FixedTimeProvider(Now));
        var health = new AgentHealthSnapshot(
            Guid.NewGuid(),
            7,
            ["authenticode", "pdf"],
            Now.AddMilliseconds(1),
            new AgentHeartbeat(
                7,
                "ready",
                "ready",
                "ready",
                "ready",
                null,
                7,
                ReadyCapability("34567890", "abcdef12", "1234abcd"),
                ReadyCapability("34567890", "abcdef12", "1234abcd"),
                1));

        var snapshot = await provider.CreateAsync(health, default);

        Assert.Equal(-1, snapshot.HeartbeatAgeMilliseconds);
    }

    [Fact]
    public async Task Provider_fails_closed_without_heartbeat_and_maps_waiting_and_both_terminal_outcomes()
    {
        var waiting = Job(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            JobState.WaitingForAgent,
            FileKind.Authenticode) with
        {
            StartedAt = Now.AddSeconds(2),
        };
        var succeeded = Job(
            Guid.Parse("22222222-2222-2222-2222-222222222222"),
            JobState.Succeeded,
            FileKind.Authenticode) with
        {
            CompletedAt = Now.AddSeconds(-2),
            ErrorCode = "internal_error",
        };
        var expired = Job(
            Guid.Parse("33333333-3333-3333-3333-333333333333"),
            JobState.Expired,
            FileKind.Pdf) with
        {
            CompletedAt = Now.AddSeconds(-1),
            ErrorCode = "job_expired",
        };
        var provider = new ServiceManagementSnapshotProvider(
            new FixedManagementJobStore(new JobManagementState(0, 1, waiting, [succeeded, expired])),
            new FixedTimeProvider(Now));
        var health = new AgentHealthSnapshot(
            Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            7,
            ["authenticode", "pdf"],
            null,
            null);

        var snapshot = await provider.CreateAsync(health, default);

        Assert.Null(snapshot.HeartbeatAgeMilliseconds);
        Assert.False(snapshot.SimplySignProcessRunning);
        Assert.Null(snapshot.SimplySignProcessSessionId);
        Assert.Equal("heartbeat_missing", snapshot.Authenticode.ReasonCode);
        Assert.False(snapshot.Authenticode.Ready);
        Assert.Equal("heartbeat_missing", snapshot.Pdf.ReasonCode);
        Assert.Equal("waiting_for_agent", snapshot.CurrentJob!.State);
        Assert.Equal("waiting_for_agent", snapshot.CurrentJob.Stage);
        Assert.Equal(0, snapshot.CurrentJob.ElapsedSeconds);
        Assert.Collection(
            snapshot.RecentJobs,
            recent =>
            {
                Assert.Equal("succeeded", recent.TerminalState);
                Assert.Null(recent.ErrorCode);
            },
            recent =>
            {
                Assert.Equal("expired", recent.TerminalState);
                Assert.Equal("job_expired", recent.ErrorCode);
            });
    }

    [Theory]
    [InlineData("missing_start")]
    [InlineData("invalid_current_state")]
    [InlineData("invalid_current_kind")]
    [InlineData("missing_completion")]
    [InlineData("invalid_terminal_state")]
    public async Task Provider_rejects_corrupt_management_store_rows(string mutation)
    {
        var current = Job(Guid.NewGuid(), JobState.Signing, FileKind.Authenticode) with
        {
            StartedAt = Now.AddSeconds(-1),
        };
        var recent = Job(Guid.NewGuid(), JobState.Failed, FileKind.Pdf) with
        {
            CompletedAt = Now.AddSeconds(-1),
            ErrorCode = "internal_error",
        };
        switch (mutation)
        {
            case "missing_start":
                current = current with { StartedAt = null };
                break;
            case "invalid_current_state":
                current = current with { State = JobState.Queued };
                break;
            case "invalid_current_kind":
                current = current with { Kind = (FileKind)999 };
                break;
            case "missing_completion":
                current = null!;
                recent = recent with { CompletedAt = null };
                break;
            case "invalid_terminal_state":
                current = null!;
                recent = recent with { State = JobState.Verifying };
                break;
        }

        var state = current is null
            ? new JobManagementState(0, 0, null, [recent])
            : new JobManagementState(0, 1, current, [recent]);
        var provider = new ServiceManagementSnapshotProvider(
            new FixedManagementJobStore(state),
            new FixedTimeProvider(Now));
        var health = new AgentHealthSnapshot(Guid.NewGuid(), 7, [], null, null);

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.CreateAsync(health, default));

        Assert.Equal("management_unavailable", failure.Message);
    }

    [Fact]
    public async Task Sqlite_management_read_is_bounded_and_orders_equal_completion_times_by_job_id()
    {
        using var fixture = new DatabaseFixture();
        var store = fixture.CreateStore();
        var connectionId = Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd");
        var completedIds = Enumerable.Range(1, 7)
            .Select(index => Guid.Parse($"00000000-0000-0000-0000-{index:000000000000}"))
            .Reverse()
            .ToArray();
        foreach (var id in completedIds)
        {
            await store.CreateAsync(Job(id, JobState.Queued, FileKind.Pdf));
            var claimed = await store.ClaimNextAsync(connectionId);
            Assert.NotNull(claimed?.DispatchId);
            Assert.True(await store.TryFailLeaseAsync(
                claimed!.Id,
                claimed.DispatchId!.Value,
                connectionId,
                "pdf_sign_failed",
                "native details must never leave the store",
                default));
        }

        await SetSameCompletionTimeAsync(fixture.Path, Now.AddMinutes(-1));
        var queued = Job(Guid.Parse("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"), JobState.Queued, FileKind.Pdf);
        await store.CreateAsync(queued);
        var activeSeed = Job(Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff"), JobState.Queued, FileKind.Authenticode);
        await store.CreateAsync(activeSeed);
        var active = await store.ClaimNextAsync(connectionId);

        var state = await store.GetManagementStateAsync();

        Assert.Equal(1, state.QueuedJobCount);
        Assert.Equal(1, state.ActiveJobCount);
        Assert.Equal(active!.Id, state.CurrentJob!.Id);
        Assert.Equal(
            Enumerable.Range(1, 5).Select(index => Guid.Parse($"00000000-0000-0000-0000-{index:000000000000}")),
            state.RecentJobs.Select(job => job.Id));
    }

    [Fact]
    public async Task Sqlite_waiting_for_agent_is_the_current_job_with_a_stable_start_point()
    {
        using var fixture = new DatabaseFixture();
        var store = fixture.CreateStore();
        var waiting = Job(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            JobState.Queued,
            FileKind.Authenticode);
        await store.CreateAsync(waiting);
        var beforeTransition = DateTimeOffset.UtcNow;

        Assert.True(await store.TryMarkNextWaitingForAgentAsync());
        var state = await store.GetManagementStateAsync();

        Assert.Equal(0, state.QueuedJobCount);
        Assert.Equal(1, state.ActiveJobCount);
        Assert.Equal(waiting.Id, state.CurrentJob!.Id);
        Assert.Equal(JobState.WaitingForAgent, state.CurrentJob.State);
        Assert.NotNull(state.CurrentJob.StartedAt);
        Assert.InRange(state.CurrentJob.StartedAt!.Value, beforeTransition, DateTimeOffset.UtcNow);
    }

    [Fact]
    public void Management_state_rejects_an_active_count_without_a_current_job()
    {
        Assert.Throws<ArgumentException>(() => new JobManagementState(0, 1, null, []));
    }

    [Fact]
    public async Task Authenticated_current_connection_receives_correlated_management_response()
    {
        var requestId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var responseSnapshot = Snapshot(Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        var provider = new FixedSnapshotProvider(responseSnapshot);
        var server = new AgentPipeServer(
            "S-1-5-21-1000",
            "1.0.0",
            new FixedIdentityVerifier(new AgentConnectionIdentity(321, 7, "S-1-5-21-1000")),
            new FixedAgentClock(Now),
            managementProvider: provider);
        await using var connection = await BlockingPreloadedCaptureStream.CreateAsync(
            new AgentHello(LengthPrefixedJsonProtocol.ProtocolVersion, 321, 7, "S-1-5-21-1000", "1.0.0", ["authenticode", "pdf"]),
            new AgentHeartbeat(
                7,
                "ready",
                "ready",
                "ready",
                "ready",
                null,
                7,
                ReadyCapability("34567890", "abcdef12", "1234abcd"),
                ReadyCapability("34567890", "abcdef12", "1234abcd"),
                1),
            new ManagementSnapshotRequest(requestId));

        var run = server.ProcessConnectionAsync(connection, default);
        await connection.WaitForCompleteFrameAsync();

        await using var written = new MemoryStream(connection.WrittenBytes);
        var response = Assert.IsType<ManagementSnapshotResponse>(
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.Equal(requestId, response.RequestId);
        Assert.Equal(responseSnapshot, response.Snapshot);
        Assert.Equal(1, provider.Calls);
        await connection.DisposeAsync();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Provider_failure_returns_only_stable_error_and_correlation_without_raw_exception()
    {
        var requestId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var server = new AgentPipeServer(
            "S-1-5-21-1000",
            "1.0.0",
            new FixedIdentityVerifier(new AgentConnectionIdentity(321, 7, "S-1-5-21-1000")),
            new FixedAgentClock(Now),
            managementProvider: new ThrowingSnapshotProvider());
        await using var connection = await BlockingPreloadedCaptureStream.CreateAsync(
            new AgentHello(LengthPrefixedJsonProtocol.ProtocolVersion, 321, 7, "S-1-5-21-1000", "1.0.0", ["authenticode", "pdf"]),
            new ManagementSnapshotRequest(requestId));

        var run = server.ProcessConnectionAsync(connection, default);
        await connection.WaitForCompleteFrameAsync();

        await using var written = new MemoryStream(connection.WrittenBytes);
        var response = Assert.IsType<ManagementSnapshotResponse>(
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.Equal(requestId, response.RequestId);
        Assert.Null(response.Snapshot);
        Assert.Equal("management_unavailable", response.ErrorCode);
        Assert.NotNull(response.CorrelationId);
        Assert.DoesNotContain("database", response.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("C:/", response.ToString(), StringComparison.OrdinalIgnoreCase);
        await connection.DisposeAsync();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Blocking_management_provider_does_not_block_the_unique_reader_and_response_keeps_connection_identity()
    {
        var requestId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var heartbeat = ProtocolV3TestFixtures.Heartbeat();
        var progress = new JobProgress(
            Guid.Parse("22222222-2222-2222-2222-222222222222"),
            Guid.Parse("33333333-3333-3333-3333-333333333333"),
            25,
            "signing");
        var provider = new BlockingSnapshotProvider();
        var server = new AgentPipeServer(
            "S-1-5-21-1000",
            "1.0.0",
            new FixedIdentityVerifier(new AgentConnectionIdentity(321, 7, "S-1-5-21-1000")),
            new FixedAgentClock(Now),
            managementProvider: provider);
        await using var connection = await BlockingPreloadedCaptureStream.CreateAsync(
            new AgentHello(LengthPrefixedJsonProtocol.ProtocolVersion, 321, 7, "S-1-5-21-1000", "1.0.0", ["authenticode", "pdf"]),
            new ManagementSnapshotRequest(requestId),
            heartbeat,
            progress);
        var progressReceived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        server.MessageReceived += (_, message) =>
        {
            if (message.Message == progress)
            {
                progressReceived.TrySetResult();
            }
        };

        var run = server.ProcessConnectionAsync(connection, default);
        await provider.Entered.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await progressReceived.Task.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(heartbeat, server.LastHeartbeat);
        Assert.Equal(server.CurrentConnection!.ConnectionId, provider.Health!.ConnectionId);
        provider.Release();
        await connection.WaitForCompleteFrameAsync();
        Assert.Equal(provider.Health.ConnectionId, server.CurrentConnection!.ConnectionId);
        await using var written = new MemoryStream(connection.WrittenBytes);
        var response = Assert.IsType<ManagementSnapshotResponse>(
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.Equal(requestId, response.RequestId);
        Assert.Equal(server.CurrentConnection.ConnectionId, response.Snapshot!.ConnectionId);

        await connection.DisposeAsync();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Disconnect_cancels_and_joins_the_tracked_management_pump_before_connection_completion()
    {
        var provider = new BlockingSnapshotProvider();
        var server = new AgentPipeServer(
            "S-1-5-21-1000",
            "1.0.0",
            new FixedIdentityVerifier(new AgentConnectionIdentity(321, 7, "S-1-5-21-1000")),
            new FixedAgentClock(Now),
            managementProvider: provider);
        await using var connection = await BlockingPreloadedCaptureStream.CreateAsync(
            new AgentHello(LengthPrefixedJsonProtocol.ProtocolVersion, 321, 7, "S-1-5-21-1000", "1.0.0", ["authenticode", "pdf"]),
            new ManagementSnapshotRequest(Guid.Parse("11111111-1111-1111-1111-111111111111")));
        using var cancellation = new CancellationTokenSource();

        var run = server.ProcessConnectionAsync(connection, cancellation.Token);
        await provider.Entered.Task.WaitAsync(TimeSpan.FromSeconds(1));
        cancellation.Cancel();
        await run.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.True(provider.Exited.Task.IsCompletedSuccessfully);
        Assert.Null(server.CurrentConnection);
    }

    [Fact]
    public async Task Timed_out_management_waiter_can_retry_while_job_messages_flow_and_immediate_next_request_stays_connected()
    {
        var firstRequestId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var secondRequestId = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var thirdRequestId = Guid.Parse("33333333-3333-3333-3333-333333333333");
        var jobId = Guid.Parse("44444444-4444-4444-4444-444444444444");
        var dispatchId = Guid.Parse("55555555-5555-5555-5555-555555555555");
        var provider = new BlockingSnapshotProvider();
        var server = new AgentPipeServer(
            "S-1-5-21-1000",
            "1.0.0",
            new FixedIdentityVerifier(new AgentConnectionIdentity(321, 7, "S-1-5-21-1000")),
            new FixedAgentClock(Now),
            managementProvider: provider);
        await using var connection = new ScriptedServiceStream();
        await connection.EnqueueAsync(
            new AgentHello(LengthPrefixedJsonProtocol.ProtocolVersion, 321, 7, "S-1-5-21-1000", "1.0.0", ["authenticode", "pdf"]));
        await connection.EnqueueAsync(new ManagementSnapshotRequest(firstRequestId));
        var received = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var jobMessages = new List<AgentMessage>();
        server.MessageReceived += (_, message) =>
        {
            if (message.Message is AgentHeartbeat or JobProgress or JobCompleted)
            {
                jobMessages.Add(message.Message);
                if (jobMessages.Count == 3)
                {
                    received.TrySetResult();
                }
            }
        };
        var run = server.ProcessConnectionAsync(connection, default);
        await provider.Entered.Task.WaitAsync(TimeSpan.FromSeconds(1));
        var connectionId = server.CurrentConnection!.ConnectionId;

        await Task.Delay(TimeSpan.FromMilliseconds(35));
        await connection.EnqueueAsync(new ManagementSnapshotRequest(secondRequestId));
        await connection.EnqueueAsync(ProtocolV3TestFixtures.Heartbeat(currentJobId: jobId));
        await connection.EnqueueAsync(new JobProgress(jobId, dispatchId, 50, "signing"));
        await connection.EnqueueAsync(new JobCompleted(jobId, dispatchId, 10, new string('a', 64)));
        await received.Task.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(connectionId, server.CurrentConnection!.ConnectionId);
        provider.Release();
        await connection.WaitForWrittenMessageCountAsync(2);
        var firstResponses = await connection.ReadWrittenMessagesAsync();
        Assert.Equal(
            [firstRequestId, secondRequestId],
            firstResponses.Cast<ManagementSnapshotResponse>().Select(response => response.RequestId));
        Assert.All(
            firstResponses.Cast<ManagementSnapshotResponse>(),
            response => Assert.Equal(connectionId, response.Snapshot!.ConnectionId));

        await connection.EnqueueAsync(new ManagementSnapshotRequest(thirdRequestId));
        await connection.WaitForWrittenMessageCountAsync(3);
        var responses = await connection.ReadWrittenMessagesAsync();
        Assert.Equal(thirdRequestId, Assert.IsType<ManagementSnapshotResponse>(responses[2]).RequestId);
        Assert.Equal(connectionId, server.CurrentConnection!.ConnectionId);
        Assert.False(run.IsCompleted);

        connection.CompleteInput();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Full_management_queue_times_out_excess_requests_without_blocking_job_messages_or_disconnect()
    {
        var requestIds = Enumerable.Range(1, 9)
            .Select(index => Guid.Parse($"00000000-0000-0000-0000-{index:D12}"))
            .ToArray();
        var jobId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        var dispatchId = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        var provider = new BlockingSnapshotProvider();
        var server = new AgentPipeServer(
            "S-1-5-21-1000",
            "1.0.0",
            new FixedIdentityVerifier(new AgentConnectionIdentity(321, 7, "S-1-5-21-1000")),
            new FixedAgentClock(Now),
            managementProvider: provider);
        await using var connection = new ScriptedServiceStream();
        await connection.EnqueueAsync(
            new AgentHello(LengthPrefixedJsonProtocol.ProtocolVersion, 321, 7, "S-1-5-21-1000", "1.0.0", ["authenticode", "pdf"]));
        await connection.EnqueueAsync(new ManagementSnapshotRequest(requestIds[0]));
        var received = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var jobMessageCount = 0;
        server.MessageReceived += (_, message) =>
        {
            if (message.Message is AgentHeartbeat or JobProgress or JobCompleted
                && Interlocked.Increment(ref jobMessageCount) == 3)
            {
                received.TrySetResult();
            }
        };
        var run = server.ProcessConnectionAsync(connection, default);
        await provider.Entered.Task.WaitAsync(TimeSpan.FromSeconds(1));
        var connectionId = server.CurrentConnection!.ConnectionId;

        foreach (var requestId in requestIds.Skip(1).Take(7))
        {
            await connection.EnqueueAsync(new ManagementSnapshotRequest(requestId));
        }

        await connection.EnqueueAsync(ProtocolV3TestFixtures.Heartbeat(currentJobId: jobId));
        await connection.EnqueueAsync(new JobProgress(jobId, dispatchId, 50, "signing"));
        await connection.EnqueueAsync(new JobCompleted(jobId, dispatchId, 10, new string('a', 64)));
        await received.Task.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(connectionId, server.CurrentConnection!.ConnectionId);
        provider.Release();
        await connection.WaitForWrittenMessageCountAsync(5);
        var responses = await connection.ReadWrittenMessagesAsync();
        Assert.Equal(
            requestIds.Take(5),
            responses.Cast<ManagementSnapshotResponse>().Select(response => response.RequestId));

        await connection.EnqueueAsync(new ManagementSnapshotRequest(requestIds[8]));
        await connection.WaitForWrittenMessageCountAsync(6);
        responses = await connection.ReadWrittenMessagesAsync();
        Assert.Equal(requestIds[8], Assert.IsType<ManagementSnapshotResponse>(responses[5]).RequestId);
        Assert.Equal(connectionId, server.CurrentConnection!.ConnectionId);
        Assert.False(run.IsCompleted);

        connection.CompleteInput();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Blocking_local_job_handler_does_not_block_the_unique_reader_and_uses_verified_identity()
    {
        var requestId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var request = new LocalJobCreateRequest(
            requestId,
            "sample.exe",
            ".exe",
            10,
            "{\"appendSignature\":false,\"certificateSerialNumber\":\"52A1B4C9\",\"digestAlgorithm\":\"sha256\",\"kind\":\"authenticode\"}");
        var heartbeat = ProtocolV3TestFixtures.Heartbeat();
        var progress = new JobProgress(Guid.NewGuid(), Guid.NewGuid(), 25, "signing");
        var handler = new BlockingLocalJobHandler();
        var identity = new AgentConnectionIdentity(321, 7, "S-1-5-21-1000");
        var server = new AgentPipeServer(
            identity.UserSid,
            "1.0.0",
            new FixedIdentityVerifier(identity),
            new FixedAgentClock(Now),
            localJobs: handler);
        await using var connection = new ScriptedServiceStream();
        await connection.EnqueueAsync(
            new AgentHello(LengthPrefixedJsonProtocol.ProtocolVersion, identity.ProcessId, identity.SessionId, identity.UserSid, "1.0.0", ["authenticode", "pdf"]));
        await connection.EnqueueAsync(request);
        await connection.EnqueueAsync(heartbeat);
        await connection.EnqueueAsync(progress);
        var progressReceived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        server.MessageReceived += (_, message) =>
        {
            if (message.Message == progress)
            {
                progressReceived.TrySetResult();
            }
        };

        var run = server.ProcessConnectionAsync(connection, default);
        await handler.Entered.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await progressReceived.Task.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(heartbeat, server.LastHeartbeat);
        Assert.Equal(identity, handler.Identity);
        handler.Release();
        await connection.WaitForWrittenMessageCountAsync(1);
        var response = Assert.IsType<LocalJobRejected>(Assert.Single(await connection.ReadWrittenMessagesAsync()));
        Assert.Equal(requestId, response.RequestId);
        Assert.Equal("local_job_unavailable", response.ErrorCode);
        Assert.False(run.IsCompleted);

        connection.CompleteInput();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Disconnect_cancels_and_joins_the_tracked_local_job_pump()
    {
        var handler = new BlockingLocalJobHandler();
        var identity = new AgentConnectionIdentity(321, 7, "S-1-5-21-1000");
        var server = new AgentPipeServer(
            identity.UserSid,
            "1.0.0",
            new FixedIdentityVerifier(identity),
            new FixedAgentClock(Now),
            localJobs: handler);
        await using var connection = new ScriptedServiceStream();
        await connection.EnqueueAsync(
            new AgentHello(LengthPrefixedJsonProtocol.ProtocolVersion, identity.ProcessId, identity.SessionId, identity.UserSid, "1.0.0", ["authenticode", "pdf"]));
        await connection.EnqueueAsync(new LocalJobResultRequest(Guid.NewGuid(), Guid.NewGuid()));
        using var cancellation = new CancellationTokenSource();

        var run = server.ProcessConnectionAsync(connection, cancellation.Token);
        await handler.Entered.Task.WaitAsync(TimeSpan.FromSeconds(1));
        cancellation.Cancel();
        await run.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.True(handler.Exited.Task.IsCompletedSuccessfully);
        Assert.Null(server.CurrentConnection);
    }

    [Fact]
    public async Task Full_local_job_pump_retires_connection_instead_of_silently_dropping_complete_requests()
    {
        var handler = new BlockingLocalJobHandler();
        var identity = new AgentConnectionIdentity(321, 7, "S-1-5-21-1000");
        var server = new AgentPipeServer(
            identity.UserSid,
            "1.0.0",
            new FixedIdentityVerifier(identity),
            new FixedAgentClock(Now),
            localJobs: handler);
        var disconnected = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        server.ConnectionStateChanged += (_, change) =>
        {
            if (change.Status == AgentConnectionStatus.Disconnected)
            {
                disconnected.TrySetResult(change.Reason);
            }
        };
        await using var connection = new ScriptedServiceStream();
        await connection.EnqueueAsync(
            new AgentHello(LengthPrefixedJsonProtocol.ProtocolVersion, identity.ProcessId, identity.SessionId, identity.UserSid, "1.0.0", ["authenticode", "pdf"]));
        for (var index = 0; index < 6; index++)
        {
            await connection.EnqueueAsync(new LocalJobResultRequest(Guid.NewGuid(), Guid.NewGuid()));
        }

        var run = server.ProcessConnectionAsync(connection, default);
        await handler.Entered.Task.WaitAsync(TimeSpan.FromSeconds(1));
        var reason = await disconnected.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await run.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal("local_job_busy", reason);
        Assert.True(handler.Exited.Task.IsCompletedSuccessfully);
        Assert.Null(server.CurrentConnection);
        Assert.Empty(await connection.ReadWrittenMessagesAsync());
    }

    private static Job Job(Guid id, JobState state, FileKind kind)
    {
        SigningParameters parameters = kind == FileKind.Authenticode
            ? new AuthenticodeParameters("52A1B4C9", "sha256", false)
            : new PdfParameters(
                "6F09D233",
                "sha256",
                1,
                new PdfBox(0, 0, 100, 50),
                "Signature1",
                null,
                null);
        return new Job(id, state, parameters)
        {
            Kind = kind,
            OriginalName = kind == FileKind.Authenticode ? "sample.exe" : "sample.pdf",
            Extension = kind == FileKind.Authenticode ? ".exe" : ".pdf",
            InputSha256 = new string('a', 64),
            InputSize = 10,
            CreatedAt = Now.AddMinutes(-2),
            ExpiresAt = Now.AddDays(1),
        };
    }

    private static CapabilitySnapshot ReadyCapability(
        string tokenSuffix,
        string certificateSuffix,
        string privateKeySuffix) =>
        new(
            true,
            true,
            true,
            tokenSuffix,
            true,
            true,
            certificateSuffix,
            true,
            true,
            privateKeySuffix,
            true,
            "ready",
            DateTimeOffset.Parse("2027-08-09T00:00:00Z"),
            "89ABCDEF",
            ProtocolV3TestFixtures.ReadySession("test"));

    private static ManagementSnapshot Snapshot(Guid connectionId) =>
        new(
            ManagementSnapshot.CurrentVersion,
            Now,
            connectionId,
            true,
            true,
            7,
            7,
            0,
            true,
            7,
            ReadyCapability("34567890", "abcdef12", "1234abcd"),
            ReadyCapability("34567890", "abcdef12", "1234abcd"),
            0,
            0,
            null,
            [],
            1);

    private static async Task SetSameCompletionTimeAsync(string databasePath, DateTimeOffset completedAt)
    {
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Pooling = false,
        }.ToString());
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE jobs SET completed_at = $completedAt WHERE state = $failed;";
        command.Parameters.AddWithValue("$completedAt", completedAt.ToString("O"));
        command.Parameters.AddWithValue("$failed", (int)JobState.Failed);
        await command.ExecuteNonQueryAsync();
    }

    private sealed class FixedManagementJobStore(JobManagementState state) : IJobStore
    {
        public Task<JobManagementState> GetManagementStateAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(state);

        public Task<Job> CreateAsync(
            Job job,
            string? apiPrincipal = null,
            string? idempotencyKey = null,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<Job?> GetAsync(Guid jobId, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<int> RecoverInterruptedAsync(CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class FixedAgentClock(DateTimeOffset now) : IAgentClock
    {
        public DateTimeOffset UtcNow => now;

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
            Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
    }

    private sealed class FixedIdentityVerifier(AgentConnectionIdentity identity) : IAgentConnectionIdentityVerifier
    {
        public ValueTask<AgentConnectionIdentity> VerifyAsync(
            Stream connection,
            CancellationToken cancellationToken) => ValueTask.FromResult(identity);
    }

    private sealed class FixedSnapshotProvider(ManagementSnapshot snapshot) : IServiceManagementSnapshotProvider
    {
        public int Calls { get; private set; }

        public Task<ManagementSnapshot> CreateAsync(
            AgentHealthSnapshot health,
            CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(snapshot);
        }
    }

    private sealed class ThrowingSnapshotProvider : IServiceManagementSnapshotProvider
    {
        public Task<ManagementSnapshot> CreateAsync(
            AgentHealthSnapshot health,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("database C:/private/jobs.db failed");
    }

    private sealed class BlockingSnapshotProvider : IServiceManagementSnapshotProvider
    {
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Entered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Exited { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public AgentHealthSnapshot? Health { get; private set; }

        public async Task<ManagementSnapshot> CreateAsync(
            AgentHealthSnapshot health,
            CancellationToken cancellationToken)
        {
            Health = health;
            Entered.TrySetResult();
            try
            {
                await _release.Task.WaitAsync(cancellationToken);
                return Snapshot(health.ConnectionId);
            }
            finally
            {
                Exited.TrySetResult();
            }
        }

        public void Release() => _release.TrySetResult();
    }

    private sealed class BlockingLocalJobHandler : ILocalJobRequestHandler
    {
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Entered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Exited { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public AgentConnectionIdentity? Identity { get; private set; }

        public async Task<AgentMessage> HandleAsync(
            AgentMessage request,
            AgentConnectionIdentity identity,
            CancellationToken cancellationToken)
        {
            Identity = identity;
            Entered.TrySetResult();
            try
            {
                await _release.Task.WaitAsync(cancellationToken);
                var requestId = request switch
                {
                    LocalJobCreateRequest create => create.RequestId,
                    LocalJobUploadCompleted completed => completed.RequestId,
                    LocalJobResultRequest result => result.RequestId,
                    _ => throw new InvalidOperationException(),
                };
                return new LocalJobRejected(requestId, "local_job_unavailable", Guid.NewGuid());
            }
            finally
            {
                Exited.TrySetResult();
            }
        }

        public void Release() => _release.TrySetResult();
    }

    private sealed class BlockingPreloadedCaptureStream : Stream
    {
        private readonly MemoryStream _input;
        private readonly MemoryStream _output = new();
        private readonly object _outputSync = new();
        private readonly TaskCompletionSource _closed =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        private BlockingPreloadedCaptureStream(byte[] input)
        {
            _input = new MemoryStream(input);
        }

        public byte[] WrittenBytes
        {
            get
            {
                lock (_outputSync)
                {
                    return _output.ToArray();
                }
            }
        }

        public TaskCompletionSource Written { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task WaitForCompleteFrameAsync()
        {
            await Written.Task.WaitAsync(TimeSpan.FromSeconds(1));
            for (var attempt = 0; attempt < 1_000; attempt++)
            {
                var bytes = WrittenBytes;
                if (bytes.Length >= sizeof(int))
                {
                    var payloadLength = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(bytes);
                    if (payloadLength >= 0 && bytes.Length >= sizeof(int) + payloadLength)
                    {
                        return;
                    }
                }

                await Task.Yield();
            }

            Assert.Fail("Expected a complete outbound management frame.");
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public static async Task<BlockingPreloadedCaptureStream> CreateAsync(params AgentMessage[] messages)
        {
            await using var input = new MemoryStream();
            foreach (var message in messages)
            {
                await LengthPrefixedJsonProtocol.WriteAsync(input, message, default);
            }

            return new BlockingPreloadedCaptureStream(input.ToArray());
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            var read = await _input.ReadAsync(buffer, cancellationToken);
            if (read > 0)
            {
                return read;
            }

            await _closed.Task.WaitAsync(cancellationToken);
            return 0;
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_outputSync)
            {
                _output.Write(buffer.Span);
            }

            Written.TrySetResult();

            return ValueTask.CompletedTask;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _closed.TrySetResult();
                _input.Dispose();
                lock (_outputSync)
                {
                    _output.Dispose();
                }
            }

            base.Dispose(disposing);
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class ScriptedServiceStream : Stream
    {
        private readonly Channel<byte[]> _input = Channel.CreateUnbounded<byte[]>();
        private readonly object _outputSync = new();
        private readonly MemoryStream _output = new();
        private byte[]? _currentInput;
        private int _currentOffset;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public async Task EnqueueAsync(AgentMessage message)
        {
            await using var encoded = new MemoryStream();
            await LengthPrefixedJsonProtocol.WriteAsync(encoded, message, default);
            await _input.Writer.WriteAsync(encoded.ToArray());
        }

        public void CompleteInput() => _input.Writer.TryComplete();

        public async Task WaitForWrittenMessageCountAsync(int expected)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
            while (!timeout.IsCancellationRequested)
            {
                if ((await ReadWrittenMessagesAsync()).Count >= expected)
                {
                    return;
                }

                await Task.Delay(TimeSpan.FromMilliseconds(5), timeout.Token)
                    .ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
            }

            Assert.Fail($"Expected {expected} complete outbound messages.");
        }

        public async Task<IReadOnlyList<AgentMessage>> ReadWrittenMessagesAsync()
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
                    messages.Add(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(copy, default));
                }
                catch (ProtocolException error) when (error.Code == "unexpected_eof")
                {
                    break;
                }
            }

            return messages;
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (_currentInput is null || _currentOffset == _currentInput.Length)
            {
                if (!await _input.Reader.WaitToReadAsync(cancellationToken))
                {
                    return 0;
                }

                Assert.True(_input.Reader.TryRead(out _currentInput));
                _currentOffset = 0;
            }

            var count = Math.Min(buffer.Length, _currentInput!.Length - _currentOffset);
            _currentInput.AsMemory(_currentOffset, count).CopyTo(buffer);
            _currentOffset += count;
            return count;
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_outputSync)
            {
                _output.Write(buffer.Span);
            }

            return ValueTask.CompletedTask;
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

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class PreloadedCaptureStream : Stream
    {
        private readonly MemoryStream _input;
        private readonly MemoryStream _output = new();

        private PreloadedCaptureStream(byte[] input)
        {
            _input = new MemoryStream(input);
        }

        public byte[] WrittenBytes => _output.ToArray();
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public static async Task<PreloadedCaptureStream> CreateAsync(params AgentMessage[] messages)
        {
            await using var input = new MemoryStream();
            foreach (var message in messages)
            {
                await LengthPrefixedJsonProtocol.WriteAsync(input, message, default);
            }

            return new PreloadedCaptureStream(input.ToArray());
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            _input.ReadAsync(buffer, cancellationToken);

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            _output.WriteAsync(buffer, cancellationToken);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _input.Dispose();
                _output.Dispose();
            }

            base.Dispose(disposing);
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class DatabaseFixture : IDisposable
    {
        private readonly string _root = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            $"simplysign-management-{Guid.NewGuid():N}");
        private readonly List<SqliteJobStore> _stores = [];

        public DatabaseFixture()
        {
            Directory.CreateDirectory(_root);
            Path = System.IO.Path.Combine(_root, "jobs.db");
        }

        public string Path { get; }

        public SqliteJobStore CreateStore()
        {
            var store = new SqliteJobStore(Path);
            _stores.Add(store);
            return store;
        }

        public void Dispose()
        {
            foreach (var store in _stores)
            {
                store.Dispose();
            }

            Directory.Delete(_root, recursive: true);
        }
    }
}
