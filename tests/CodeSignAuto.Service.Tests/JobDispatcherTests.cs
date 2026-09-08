using System.Security.Cryptography;
using System.Text;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Protocol;
using CodeSignAuto.Service.Ipc;
using CodeSignAuto.Service.Jobs;
using Xunit;

namespace CodeSignAuto.Service.Tests;

public sealed class JobDispatcherTests
{
    [Fact]
    public async Task No_agent_marks_fifo_queue_waiting_then_connection_reactivates_and_duplicate_wakes_do_not_duplicate_claim()
    {
        using var fixture = new Fixture();
        var first = await fixture.CreatePdfJobAsync("first");
        await Task.Delay(2);
        var second = await fixture.CreatePdfJobAsync("second");
        using var dispatcher = fixture.CreateDispatcher();
        using var cancellation = new CancellationTokenSource();
        var run = dispatcher.RunAsync(cancellation.Token);

        for (var index = 0; index < 5; index++)
        {
            dispatcher.Enqueue(first.Id);
            dispatcher.Enqueue(second.Id);
        }

        await WaitUntilAsync(async () =>
            (await fixture.Store.GetAsync(first.Id))!.State == JobState.WaitingForAgent &&
            (await fixture.Store.GetAsync(second.Id))!.State == JobState.WaitingForAgent);
        var connection = fixture.Pipe.Connect();
        await WaitUntilAsync(() => Task.FromResult(fixture.Pipe.Commands.Count == 1));

        var sent = Assert.Single(fixture.Pipe.Commands);
        Assert.Equal(connection, sent.ConnectionId);
        Assert.Equal(first.Id, sent.Command.JobId);
        Assert.Equal(1, sent.Command.AttemptNumber);
        Assert.Equal(first.InputSize, sent.Command.InputSize);
        Assert.Equal(first.InputSha256, sent.Command.InputSha256);
        await Task.Delay(20);
        Assert.Single(fixture.Pipe.Commands);
        cancellation.Cancel();
        await run;
    }

    [Fact]
    public async Task Completion_requires_current_connection_dispatch_and_verifying_then_promotes_and_notifies_once()
    {
        using var fixture = new Fixture();
        var job = await fixture.CreatePdfJobAsync("complete");
        var connection = fixture.Pipe.Connect();
        using var dispatcher = fixture.CreateDispatcher();
        using var cancellation = new CancellationTokenSource();
        var run = dispatcher.RunAsync(cancellation.Token);
        dispatcher.Enqueue(job.Id);
        var command = await fixture.Pipe.WaitForCommandAsync(1);
        var resultBytes = "%PDF-signed"u8.ToArray();
        await File.WriteAllBytesAsync(fixture.Spool.GetResultPartPath(job.Id, job.Extension), resultBytes);
        var hash = Sha256(resultBytes);
        var completed = new JobCompleted(job.Id, command.DispatchId, resultBytes.Length, hash);

        fixture.Pipe.Emit(Guid.NewGuid(), completed);
        fixture.Pipe.Emit(Guid.NewGuid(), new JobProgress(job.Id, command.DispatchId, 90, "verifying"));
        await Task.Delay(20);
        Assert.Equal(JobState.Signing, (await fixture.Store.GetAsync(job.Id))!.State);
        fixture.Pipe.Emit(connection, new JobProgress(job.Id, command.DispatchId, 90, "verifying"));
        fixture.Pipe.Emit(connection, completed);
        await WaitUntilAsync(async () => (await fixture.Store.GetAsync(job.Id))!.State == JobState.Succeeded);
        fixture.Pipe.Emit(connection, completed);
        fixture.Pipe.Emit(connection, new JobProgress(job.Id, command.DispatchId, 10, "signing"));
        await Task.Delay(20);

        Assert.Equal(1, fixture.Notifier.Count);
        Assert.Equal(resultBytes, await File.ReadAllBytesAsync(fixture.Spool.GetResultPath(job.Id, job.Extension)));
        Assert.False(File.Exists(fixture.Spool.GetResultPartPath(job.Id, job.Extension)));
        cancellation.Cancel();
        await run;
    }

    [Fact]
    public async Task Matching_completion_before_verifying_fails_exact_lease_notifies_once_and_dispatches_next_job()
    {
        using var fixture = new Fixture();
        var first = await fixture.CreatePdfJobAsync("out-of-order-completion");
        await Task.Delay(2);
        var second = await fixture.CreatePdfJobAsync("after-out-of-order");
        var connection = fixture.Pipe.Connect();
        using var dispatcher = fixture.CreateDispatcher();
        using var cancellation = new CancellationTokenSource();
        var run = dispatcher.RunAsync(cancellation.Token);
        dispatcher.Enqueue(first.Id);
        dispatcher.Enqueue(second.Id);
        var firstCommand = await fixture.Pipe.WaitForCommandAsync(1);

        fixture.Pipe.Emit(connection, new JobCompleted(
            first.Id,
            firstCommand.DispatchId,
            12,
            new string('a', 64)));

        var secondCommand = await fixture.Pipe.WaitForCommandAsync(2);
        await fixture.Notifier.WaitForCountAsync(1);
        var failed = (await fixture.Store.GetAsync(first.Id))!;
        Assert.Equal(JobState.Failed, failed.State);
        Assert.Equal("internal_error", failed.ErrorCode);
        Assert.Equal(first.Id, Assert.Single(fixture.Notifier.Jobs).Id);
        Assert.Equal(second.Id, secondCommand.JobId);
        Assert.Equal(JobState.Signing, (await fixture.Store.GetAsync(second.Id))!.State);

        fixture.Pipe.Emit(connection, new JobCompleted(
            first.Id,
            firstCommand.DispatchId,
            12,
            new string('a', 64)));
        await Task.Delay(20);
        Assert.Single(fixture.Notifier.Jobs);

        cancellation.Cancel();
        await run;
    }

    [Fact]
    public async Task Out_of_order_completion_releases_memory_active_when_exact_lease_CAS_was_already_changed()
    {
        using var fixture = new Fixture();
        var first = await fixture.CreatePdfJobAsync("externally-changed-lease");
        await Task.Delay(2);
        var second = await fixture.CreatePdfJobAsync("after-external-change");
        var connection = fixture.Pipe.Connect();
        using var dispatcher = fixture.CreateDispatcher();
        using var cancellation = new CancellationTokenSource();
        var run = dispatcher.RunAsync(cancellation.Token);
        dispatcher.Enqueue(first.Id);
        dispatcher.Enqueue(second.Id);
        var firstCommand = await fixture.Pipe.WaitForCommandAsync(1);
        Assert.True(await fixture.Store.TryFailLeaseAsync(
            first.Id,
            firstCommand.DispatchId,
            connection,
            "token_missing",
            "External exact lease change."));

        fixture.Pipe.Emit(connection, new JobCompleted(
            first.Id,
            firstCommand.DispatchId,
            12,
            new string('a', 64)));

        var secondCommand = await fixture.Pipe.WaitForCommandAsync(2);
        var externallyFailed = (await fixture.Store.GetAsync(first.Id))!;
        Assert.Equal("token_missing", externallyFailed.ErrorCode);
        Assert.Equal(second.Id, secondCommand.JobId);
        Assert.Empty(fixture.Notifier.Jobs);

        cancellation.Cancel();
        await run;
    }

    [Theory]
    [InlineData("token_missing", true)]
    [InlineData("private_key_missing", true)]
    [InlineData("pkcs11_session_lost", true)]
    [InlineData("certificate_catalog_unavailable", false)]
    [InlineData("certificate_not_found", false)]
    [InlineData("certificate_serial_ambiguous", false)]
    [InlineData("certificate_not_usable", false)]
    [InlineData("internal_error", false)]
    public async Task Retries_only_exact_session_codes_and_never_claims_a_third_attempt(string code, bool retry)
    {
        using var fixture = new Fixture();
        var job = await fixture.CreatePdfJobAsync("retry");
        var connection = fixture.Pipe.Connect();
        using var dispatcher = fixture.CreateDispatcher();
        using var cancellation = new CancellationTokenSource();
        var run = dispatcher.RunAsync(cancellation.Token);
        dispatcher.Enqueue(job.Id);
        var first = await fixture.Pipe.WaitForCommandAsync(1);

        fixture.Pipe.Emit(connection, new JobFailed(job.Id, first.DispatchId, code, "Safe failure."));

        if (retry)
        {
            var second = await fixture.Pipe.WaitForCommandAsync(2);
            Assert.Equal(2, second.AttemptNumber);
            Assert.NotEqual(first.DispatchId, second.DispatchId);
            fixture.Pipe.Emit(connection, new JobFailed(job.Id, second.DispatchId, code, "Safe failure."));
        }

        await WaitUntilAsync(async () => (await fixture.Store.GetAsync(job.Id))!.State == JobState.Failed);
        await fixture.Notifier.WaitForCountAsync(1);
        dispatcher.Enqueue(job.Id);
        await Task.Delay(30);
        Assert.Equal(retry ? 2 : 1, fixture.Pipe.Commands.Count);
        Assert.Equal(retry ? 2 : 1, (await fixture.Store.GetAsync(job.Id))!.AttemptCount);
        var notified = Assert.Single(fixture.Notifier.Jobs);
        Assert.Equal(JobState.Failed, notified.State);
        Assert.Equal(code, notified.ErrorCode);
        cancellation.Cancel();
        await run;
    }

    [Fact]
    public async Task Disconnect_releases_only_exact_lease_and_old_connection_terminal_cannot_finish_new_dispatch()
    {
        using var fixture = new Fixture();
        var job = await fixture.CreatePdfJobAsync("disconnect");
        var firstConnection = fixture.Pipe.Connect();
        using var dispatcher = fixture.CreateDispatcher();
        using var cancellation = new CancellationTokenSource();
        var run = dispatcher.RunAsync(cancellation.Token);
        dispatcher.Enqueue(job.Id);
        var first = await fixture.Pipe.WaitForCommandAsync(1);
        fixture.Pipe.Disconnect(firstConnection);
        var secondConnection = fixture.Pipe.Connect();
        var second = await fixture.Pipe.WaitForCommandAsync(2);

        fixture.Pipe.Emit(firstConnection, new JobProgress(job.Id, first.DispatchId, 90, "verifying"));
        fixture.Pipe.Emit(firstConnection, new JobCompleted(job.Id, first.DispatchId, 1, new string('a', 64)));
        await Task.Delay(20);

        var active = (await fixture.Store.GetAsync(job.Id))!;
        Assert.Equal(JobState.Signing, active.State);
        Assert.Equal(second.DispatchId, active.DispatchId);
        Assert.Equal(secondConnection, active.LeaseConnectionId);
        cancellation.Cancel();
        await run;
    }

    [Fact]
    public async Task Forged_completion_metadata_fails_result_corrupt_notifies_terminal_and_does_not_overwrite()
    {
        using var fixture = new Fixture();
        var job = await fixture.CreatePdfJobAsync("forged");
        var connection = fixture.Pipe.Connect();
        using var dispatcher = fixture.CreateDispatcher();
        using var cancellation = new CancellationTokenSource();
        var run = dispatcher.RunAsync(cancellation.Token);
        dispatcher.Enqueue(job.Id);
        var command = await fixture.Pipe.WaitForCommandAsync(1);
        await File.WriteAllBytesAsync(fixture.Spool.GetResultPartPath(job.Id, job.Extension), "%PDF-actual"u8.ToArray());
        fixture.Pipe.Emit(connection, new JobProgress(job.Id, command.DispatchId, 90, "verifying"));
        fixture.Pipe.Emit(connection, new JobCompleted(job.Id, command.DispatchId, 99, new string('a', 64)));

        await WaitUntilAsync(async () => (await fixture.Store.GetAsync(job.Id))!.State == JobState.Failed);

        var failed = (await fixture.Store.GetAsync(job.Id))!;
        Assert.Equal("result_corrupt", failed.ErrorCode);
        await fixture.Notifier.WaitForCountAsync(1);
        Assert.Equal("result_corrupt", Assert.Single(fixture.Notifier.Jobs).ErrorCode);
        Assert.False(File.Exists(fixture.Spool.GetResultPath(job.Id, job.Extension)));
        cancellation.Cancel();
        await run;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Restart_resumes_both_completion_crash_windows_idempotently(bool alreadyMoved)
    {
        using var fixture = new Fixture();
        var job = await fixture.CreatePdfJobAsync("recovery");
        var connection = Guid.NewGuid();
        var lease = (await fixture.Store.ClaimNextAsync(connection))!;
        Assert.True(await fixture.Store.TryMarkVerifyingAsync(job.Id, lease.DispatchId!.Value, connection));
        var bytes = "%PDF-recovered"u8.ToArray();
        var hash = Sha256(bytes);
        await File.WriteAllBytesAsync(fixture.Spool.GetResultPartPath(job.Id, job.Extension), bytes);
        Assert.True(await fixture.Store.TryRecordCompletionAsync(
            job.Id,
            lease.DispatchId.Value,
            connection,
            bytes.Length,
            hash));
        if (alreadyMoved)
        {
            await fixture.Spool.PromoteResultAsync(job.Id, job.Extension, hash, bytes.Length);
        }

        using var dispatcher = fixture.CreateDispatcher();
        using var cancellation = new CancellationTokenSource();
        var run = dispatcher.RunAsync(cancellation.Token);
        await WaitUntilAsync(async () => (await fixture.Store.GetAsync(job.Id))!.State == JobState.Succeeded);

        await fixture.Notifier.WaitForCountAsync(1);
        Assert.Equal(JobState.Succeeded, Assert.Single(fixture.Notifier.Jobs).State);
        Assert.Equal(bytes, await File.ReadAllBytesAsync(fixture.Spool.GetResultPath(job.Id, job.Extension)));
        cancellation.Cancel();
        await run;
    }

    [Fact]
    public async Task Restart_marks_corrupt_pending_completion_failed_then_continues_with_next_completion()
    {
        using var fixture = new Fixture();
        var corrupt = await fixture.CreatePdfJobAsync("corrupt-recovery");
        await Task.Delay(2);
        var valid = await fixture.CreatePdfJobAsync("valid-recovery");
        await PreparePendingCompletionAsync(fixture, corrupt, "%PDF-corrupt"u8.ToArray(), new string('a', 64));
        var validBytes = "%PDF-valid"u8.ToArray();
        await PreparePendingCompletionAsync(fixture, valid, validBytes, Sha256(validBytes));

        using var dispatcher = fixture.CreateDispatcher();
        using var cancellation = new CancellationTokenSource();
        var run = dispatcher.RunAsync(cancellation.Token);

        await WaitUntilAsync(async () =>
            (await fixture.Store.GetAsync(corrupt.Id))!.State == JobState.Failed &&
            (await fixture.Store.GetAsync(valid.Id))!.State == JobState.Succeeded);

        Assert.Equal("result_corrupt", (await fixture.Store.GetAsync(corrupt.Id))!.ErrorCode);
        Assert.Equal(validBytes, await File.ReadAllBytesAsync(fixture.Spool.GetResultPath(valid.Id, valid.Extension)));
        await fixture.Notifier.WaitForCountAsync(2);
        Assert.Equal(2, fixture.Notifier.Count);
        Assert.Contains(fixture.Notifier.Jobs, notified =>
            notified.Id == corrupt.Id && notified.State == JobState.Failed && notified.ErrorCode == "result_corrupt");
        Assert.Contains(fixture.Notifier.Jobs, notified =>
            notified.Id == valid.Id && notified.State == JobState.Succeeded);
        cancellation.Cancel();
        await run;
    }

    [Fact]
    public async Task Send_failure_does_not_redispatch_attempt_two_on_the_same_bad_connection()
    {
        using var fixture = new Fixture();
        var job = await fixture.CreatePdfJobAsync("send-failure");
        fixture.Pipe.SendFailuresRemaining = 1;
        var failedConnection = fixture.Pipe.Connect();
        using var dispatcher = fixture.CreateDispatcher();
        using var cancellation = new CancellationTokenSource();
        var run = dispatcher.RunAsync(cancellation.Token);
        dispatcher.Enqueue(job.Id);

        await WaitUntilAsync(async () =>
            (await fixture.Store.GetAsync(job.Id)) is { AttemptCount: 1, State: JobState.Queued });

        await Task.Delay(20);
        Assert.Equal(1, fixture.Pipe.SendAttempts);
        Assert.Empty(fixture.Pipe.Commands);
        Assert.Equal(failedConnection, fixture.Pipe.CurrentConnection!.ConnectionId);

        var replacement = fixture.Pipe.Connect();
        await WaitUntilAsync(async () =>
            (await fixture.Store.GetAsync(job.Id)) is { AttemptCount: 2, State: JobState.Signing });

        Assert.NotEqual(failedConnection, replacement);
        Assert.Equal(2, fixture.Pipe.SendAttempts);
        Assert.Equal(replacement, Assert.Single(fixture.Pipe.Commands).ConnectionId);

        cancellation.Cancel();
        await run;
    }

    [Fact]
    public async Task Send_failures_on_two_distinct_connections_exhaust_without_a_third_attempt()
    {
        using var fixture = new Fixture();
        var job = await fixture.CreatePdfJobAsync("send-failure-exhausted");
        fixture.Pipe.SendFailuresRemaining = 2;
        fixture.Pipe.Connect();
        using var dispatcher = fixture.CreateDispatcher();
        using var cancellation = new CancellationTokenSource();
        var run = dispatcher.RunAsync(cancellation.Token);
        dispatcher.Enqueue(job.Id);

        await WaitUntilAsync(async () =>
            (await fixture.Store.GetAsync(job.Id)) is { AttemptCount: 1, State: JobState.Queued });
        fixture.Pipe.Connect();
        await WaitUntilAsync(async () =>
            (await fixture.Store.GetAsync(job.Id)) is { AttemptCount: 2, State: JobState.Failed });

        Assert.Equal(2, fixture.Pipe.SendAttempts);
        Assert.Empty(fixture.Pipe.Commands);
        var stored = (await fixture.Store.GetAsync(job.Id))!;
        Assert.Equal(2, stored.AttemptCount);
        Assert.Equal("recovery_exhausted", stored.ErrorCode);
        await fixture.Notifier.WaitForCountAsync(1);
        Assert.Equal("recovery_exhausted", Assert.Single(fixture.Notifier.Jobs).ErrorCode);

        cancellation.Cancel();
        await run;
    }

    [Fact]
    public async Task Second_disconnect_failure_notifies_the_durable_recovery_exhausted_terminal_once()
    {
        using var fixture = new Fixture();
        var job = await fixture.CreatePdfJobAsync("disconnect-exhausted");
        var firstConnection = fixture.Pipe.Connect();
        using var dispatcher = fixture.CreateDispatcher();
        using var cancellation = new CancellationTokenSource();
        var run = dispatcher.RunAsync(cancellation.Token);
        dispatcher.Enqueue(job.Id);
        await fixture.Pipe.WaitForCommandAsync(1);
        fixture.Pipe.Disconnect(firstConnection);

        var secondConnection = fixture.Pipe.Connect();
        await fixture.Pipe.WaitForCommandAsync(2);
        fixture.Pipe.Disconnect(secondConnection);

        await WaitUntilAsync(async () =>
            (await fixture.Store.GetAsync(job.Id)) is
            {
                State: JobState.Failed,
                ErrorCode: "recovery_exhausted",
                AttemptCount: 2,
            });
        await fixture.Notifier.WaitForCountAsync(1);
        var notified = Assert.Single(fixture.Notifier.Jobs);
        Assert.Equal(job.Id, notified.Id);
        Assert.Equal(JobState.Failed, notified.State);
        Assert.Equal("recovery_exhausted", notified.ErrorCode);

        cancellation.Cancel();
        await run;
    }

    [Fact]
    public void Dispose_unsubscribes_both_pipe_events_idempotently()
    {
        using var fixture = new Fixture();
        var dispatcher = fixture.CreateDispatcher();
        Assert.Equal(2, fixture.Pipe.SubscriberCount);

        dispatcher.Dispose();
        dispatcher.Dispose();

        Assert.Equal(0, fixture.Pipe.SubscriberCount);
    }

    private static async Task PreparePendingCompletionAsync(
        Fixture fixture,
        Job job,
        byte[] bytes,
        string reportedHash)
    {
        var connection = Guid.NewGuid();
        var lease = (await fixture.Store.ClaimNextAsync(connection))!;
        Assert.Equal(job.Id, lease.Id);
        Assert.True(await fixture.Store.TryMarkVerifyingAsync(job.Id, lease.DispatchId!.Value, connection));
        await File.WriteAllBytesAsync(fixture.Spool.GetResultPartPath(job.Id, job.Extension), bytes);
        Assert.True(await fixture.Store.TryRecordCompletionAsync(
            job.Id,
            lease.DispatchId.Value,
            connection,
            bytes.Length,
            reportedHash));
    }

    private static async Task WaitUntilAsync(Func<Task<bool>> condition)
    {
        for (var attempt = 0; attempt < 1_000; attempt++)
        {
            if (await condition())
            {
                return;
            }

            await Task.Delay(2);
        }

        Assert.True(await condition());
    }

    private static string Sha256(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private sealed class Fixture : IDisposable
    {
        public Fixture()
        {
            Root = Path.Combine(Path.GetTempPath(), "CodeSignAuto.Tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
            Store = new SqliteJobStore(Path.Combine(Root, "jobs.db"));
            Spool = new SpoolStore(Path.Combine(Root, "spool"));
        }

        public string Root { get; }
        public SqliteJobStore Store { get; }
        public SpoolStore Spool { get; }
        public FakePipe Pipe { get; } = new();
        public RecordingNotifier Notifier { get; } = new();

        public JobDispatcher CreateDispatcher() => new(Store, Spool, Pipe, Notifier);

        public async Task<Job> CreatePdfJobAsync(string marker)
        {
            var id = Guid.NewGuid();
            var input = Encoding.UTF8.GetBytes($"%PDF-{marker}");
            var written = await Spool.WriteInputAsync(id, ".pdf", new MemoryStream(input), 1024);
            return await Store.CreateAsync(new Job(
                id,
                JobState.Queued,
                new PdfParameters("6F09D233", "sha256", 1, new PdfBox(10, 20, 30, 40), "Signature1", null, null))
            {
                OriginalName = marker + ".pdf",
                Extension = ".pdf",
                InputSize = written.Size,
                InputSha256 = written.Sha256,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            });
        }

        public void Dispose()
        {
            Store.Dispose();
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }

    private sealed class RecordingNotifier : IJobCompletionNotifier
    {
        public List<Job> Jobs { get; } = [];
        public int Count => Jobs.Count;

        public Task<Job> WaitAsync(Guid jobId, CancellationToken cancellationToken) =>
            Task.FromException<Job>(new NotSupportedException());

        public void Notify(Job job) => Jobs.Add(job);

        public void Forget(Guid jobId)
        {
        }

        public void Retire(Job job)
        {
        }

        public async Task WaitForCountAsync(int count)
        {
            for (var attempt = 0; attempt < 500 && Jobs.Count < count; attempt++)
            {
                await Task.Delay(2);
            }

            Assert.True(Jobs.Count >= count, $"Expected {count} notifications, observed {Jobs.Count}.");
        }
    }

    private sealed class FakePipe : IAgentPipeTransport
    {
        private readonly object _sync = new();

        private EventHandler<AgentConnectionStateChangedEventArgs>? _connectionStateChanged;
        private EventHandler<AgentMessageReceivedEventArgs>? _messageReceived;

        public event EventHandler<AgentConnectionStateChangedEventArgs>? ConnectionStateChanged
        {
            add => _connectionStateChanged += value;
            remove => _connectionStateChanged -= value;
        }

        public event EventHandler<AgentMessageReceivedEventArgs>? MessageReceived
        {
            add => _messageReceived += value;
            remove => _messageReceived -= value;
        }

        public AgentConnectionSnapshot? CurrentConnection { get; private set; }
        public List<SentCommand> Commands { get; } = [];
        public int SendAttempts { get; private set; }
        public int SendFailuresRemaining { get; set; }
        public int SubscriberCount =>
            (_connectionStateChanged?.GetInvocationList().Length ?? 0) +
            (_messageReceived?.GetInvocationList().Length ?? 0);

        public Guid Connect()
        {
            var id = Guid.NewGuid();
            CurrentConnection = new AgentConnectionSnapshot(id, 321, 7, DateTimeOffset.UtcNow);
            _connectionStateChanged?.Invoke(this, new AgentConnectionStateChangedEventArgs(
                id,
                AgentConnectionStatus.Connected,
                321,
                7,
                "connected"));
            return id;
        }

        public void Disconnect(Guid id)
        {
            if (CurrentConnection?.ConnectionId == id)
            {
                CurrentConnection = null;
            }

            _connectionStateChanged?.Invoke(this, new AgentConnectionStateChangedEventArgs(
                id,
                AgentConnectionStatus.Disconnected,
                321,
                7,
                "connection_closed"));
        }

        public void Emit(Guid connectionId, AgentMessage message) =>
            _messageReceived?.Invoke(this, new AgentMessageReceivedEventArgs(connectionId, message));

        public Task SendAsync(Guid connectionId, SignJobCommand command, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_sync)
            {
                SendAttempts++;
                if (CurrentConnection?.ConnectionId != connectionId)
                {
                    throw new ProtocolException("agent_not_connected", "not connected");
                }

                if (SendFailuresRemaining > 0)
                {
                    SendFailuresRemaining--;
                    throw new IOException("simulated_send_failure");
                }

                Commands.Add(new SentCommand(connectionId, command));
            }

            return Task.CompletedTask;
        }

        public async Task<SignJobCommand> WaitForCommandAsync(int count)
        {
            await WaitUntilAsync(() =>
            {
                lock (_sync)
                {
                    return Task.FromResult(Commands.Count >= count);
                }
            });
            lock (_sync)
            {
                return Commands[count - 1].Command;
            }
        }
    }

    private sealed record SentCommand(Guid ConnectionId, SignJobCommand Command);
}
