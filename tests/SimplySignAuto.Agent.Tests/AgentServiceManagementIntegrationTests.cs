using System.Collections.Concurrent;
using System.Threading.Channels;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Protocol;
using SimplySignAuto.Service.Api;
using SimplySignAuto.Service.Ipc;
using SimplySignAuto.Service.Jobs;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class AgentServiceManagementIntegrationTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 8, 8, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task More_than_tombstone_window_of_timed_out_refreshes_and_late_responses_keep_jobs_on_same_connection()
    {
        const int timedOutRequestCount = 35;
        var requestIds = new ConcurrentQueue<Guid>(Enumerable.Range(1, timedOutRequestCount + 1)
            .Select(index => Guid.Parse($"00000000-0000-0000-0000-{index:D12}")));
        var provider = new BlockingSnapshotProvider(expectedCallsAfterRelease: 5);
        var server = new AgentPipeServer(
            "S-1-5-21-1000",
            "1.0.0",
            new FixedIdentityVerifier(new AgentConnectionIdentity(321, 7, "S-1-5-21-1000")),
            new FixedAgentClock(),
            managementProvider: provider);
        var pair = DuplexStreamPair.Create();
        await using var clientStream = pair.Client;
        await using var serviceStream = pair.Service;
        var client = new AgentPipeClient(
            _ => ValueTask.FromResult<Stream>(clientStream),
            new InfiniteDelay(),
            admissionLocked: null,
            requestIdFactory: () => requestIds.TryDequeue(out var requestId)
                ? requestId
                : throw new InvalidOperationException("request_id_exhausted"),
            managementTimeout: TimeSpan.FromMilliseconds(50));
        var terminals = Channel.CreateUnbounded<JobTerminalMessage>();
        server.MessageReceived += (_, message) =>
        {
            if (message.Message is JobTerminalMessage terminal)
            {
                terminals.Writer.TryWrite(terminal);
            }
        };
        var handlerCalls = 0;
        using var cancellation = new CancellationTokenSource();
        var serviceRun = server.ProcessConnectionAsync(serviceStream, cancellation.Token);
        var clientRun = client.RunAsync(
            Hello(),
            Heartbeat,
            (command, _, _) =>
            {
                Interlocked.Increment(ref handlerCalls);
                return Task.FromResult<JobTerminalMessage>(new JobCompleted(
                    command.JobId,
                    command.DispatchId,
                    10,
                    new string('b', 64)));
            },
            cancellation.Token);

        try
        {
            await WaitUntilAsync(() => server.CurrentConnection is not null);
            var connectionId = server.CurrentConnection!.ConnectionId;

            for (var index = 0; index < timedOutRequestCount; index++)
            {
                var refresh = client.GetManagementSnapshotAsync(default);
                Assert.Equal(1, client.PendingManagementRequestCount);
                var error = await Assert.ThrowsAsync<ManagementUnavailableException>(() => refresh);
                Assert.Equal("management_unavailable", error.Code);
                Assert.Equal(0, client.PendingManagementRequestCount);
                Assert.False(clientRun.IsCompleted);

                if (index == 16)
                {
                    await SendAndAssertTerminalAsync(server, connectionId, terminals.Reader, sequence: 1);
                }
            }

            Assert.True(provider.Entered.Task.IsCompletedSuccessfully);
            Assert.Equal(connectionId, server.CurrentConnection!.ConnectionId);
            provider.Release();
            await provider.ExpectedCallsReached.Task.WaitAsync(TimeSpan.FromSeconds(1));

            var currentRefresh = client.GetManagementSnapshotAsync(default);
            Assert.Equal(1, client.PendingManagementRequestCount);
            var snapshot = await currentRefresh.WaitAsync(TimeSpan.FromSeconds(1));
            Assert.Equal(connectionId, snapshot.ConnectionId);
            Assert.Equal(0, client.PendingManagementRequestCount);
            Assert.False(clientRun.IsCompleted);
            Assert.Equal(connectionId, server.CurrentConnection!.ConnectionId);

            await SendAndAssertTerminalAsync(server, connectionId, terminals.Reader, sequence: 2);
            Assert.Equal(2, handlerCalls);
            Assert.False(clientRun.IsCompleted);
            Assert.False(serviceRun.IsCompleted);
            Assert.Equal(connectionId, server.CurrentConnection!.ConnectionId);
        }
        finally
        {
            cancellation.Cancel();
            await IgnoreFailureAsync(clientRun);
            await IgnoreFailureAsync(serviceRun);
        }
    }

    [Fact]
    public async Task Same_agent_client_and_service_connection_uploads_a_real_local_job_into_the_shared_queue()
    {
        using var fixture = new LocalJobFixture();
        var server = new AgentPipeServer(
            "S-1-5-21-1000",
            "1.0.0",
            new FixedIdentityVerifier(new AgentConnectionIdentity(321, 7, "S-1-5-21-1000")),
            new FixedAgentClock(),
            localJobs: fixture.Coordinator);
        var pair = DuplexStreamPair.Create();
        await using var clientStream = pair.Client;
        await using var serviceStream = pair.Service;
        var client = new AgentPipeClient(
            _ => ValueTask.FromResult<Stream>(clientStream),
            new InfiniteDelay());
        using var localJobs = new LocalJobClient(client, fixture.Spool.Root);
        using var cancellation = new CancellationTokenSource();
        var serverRun = server.ProcessConnectionAsync(serviceStream, cancellation.Token);
        var clientRun = client.RunAsync(
            Hello(),
            Heartbeat,
            (_, _, _) => throw new InvalidOperationException("signing_not_expected"),
            cancellation.Token);

        try
        {
            await WaitUntilAsync(() => server.CurrentConnection is not null);
            var source = Path.Combine(fixture.Root, "selected.exe");
            await File.WriteAllBytesAsync(source, "MZ-real-local-input"u8.ToArray());

            var jobId = await localJobs.CreateAndUploadAsync(
                source,
                new AuthenticodeParameters("AA00", "sha256", false),
                null,
                default).WaitAsync(TimeSpan.FromSeconds(2));

            var queued = await fixture.Store.GetAsync(jobId);
            Assert.NotNull(queued);
            Assert.Equal(JobState.Queued, queued.State);
            Assert.Equal("local", queued.Source);
            Assert.Equal([jobId], fixture.Dispatcher.Enqueued);
            Assert.Equal("MZ-real-local-input"u8.ToArray(), await File.ReadAllBytesAsync(source));
            Assert.False(clientRun.IsCompleted);
            Assert.False(serverRun.IsCompleted);
        }
        finally
        {
            cancellation.Cancel();
            await IgnoreFailureAsync(clientRun);
            await IgnoreFailureAsync(serverRun);
        }
    }

    [Fact]
    public async Task Commit_then_disconnect_reconnects_and_retries_the_same_completed_upload_once()
    {
        var first = DuplexStreamPair.Create();
        var second = DuplexStreamPair.Create();
        await using var firstClient = first.Client;
        await using var firstService = first.Service;
        await using var secondClient = second.Client;
        await using var secondService = second.Service;
        var observer = new DisconnectingAcceptanceObserver(firstClient);
        using var fixture = new LocalJobFixture(observer);
        var server = new AgentPipeServer(
            "S-1-5-21-1000",
            "1.0.0",
            new FixedIdentityVerifier(new AgentConnectionIdentity(321, 7, "S-1-5-21-1000")),
            new FixedAgentClock(),
            localJobs: fixture.Coordinator);
        var clientStreams = new ConcurrentQueue<Stream>([firstClient, secondClient]);
        var client = new AgentPipeClient(
            _ => ValueTask.FromResult(
                clientStreams.TryDequeue(out var stream)
                    ? stream
                    : throw new InvalidOperationException("connection_exhausted")),
            new InfiniteDelay());
        using var localJobs = new LocalJobClient(client, fixture.Spool.Root);
        using var cancellation = new CancellationTokenSource();
        var firstServerRun = server.ProcessConnectionAsync(firstService, cancellation.Token);
        var firstClientRun = client.RunAsync(
            Hello(),
            Heartbeat,
            (_, _, _) => throw new InvalidOperationException("signing_not_expected"),
            cancellation.Token);

        Task? secondServerRun = null;
        Task? secondClientRun = null;
        try
        {
            await WaitUntilAsync(() => server.CurrentConnection is not null);
            var source = Path.Combine(fixture.Root, "selected.exe");
            await File.WriteAllBytesAsync(source, "MZ-commit-before-disconnect"u8.ToArray());
            var upload = localJobs.CreateAndUploadAsync(
                source,
                new AuthenticodeParameters("AA00", "sha256", false),
                null,
                default);

            await observer.Disconnected.Task.WaitAsync(TimeSpan.FromSeconds(1));
            await firstClientRun.WaitAsync(TimeSpan.FromSeconds(1));
            await IgnoreFailureAsync(firstServerRun);
            secondServerRun = server.ProcessConnectionAsync(secondService, cancellation.Token);
            secondClientRun = client.RunAsync(
                Hello(),
                Heartbeat,
                (_, _, _) => throw new InvalidOperationException("signing_not_expected"),
                cancellation.Token);

            var jobId = await upload.WaitAsync(TimeSpan.FromSeconds(2));
            var jobs = await fixture.Store.GetAllAsync();
            Assert.Single(jobs);
            Assert.Equal(jobId, jobs[0].Id);
            Assert.Equal([jobId], fixture.Dispatcher.Enqueued);
            Assert.Equal("MZ-commit-before-disconnect"u8.ToArray(), await File.ReadAllBytesAsync(source));
        }
        finally
        {
            cancellation.Cancel();
            await IgnoreFailureAsync(firstClientRun);
            await IgnoreFailureAsync(firstServerRun);
            if (secondClientRun is not null)
            {
                await IgnoreFailureAsync(secondClientRun);
            }

            if (secondServerRun is not null)
            {
                await IgnoreFailureAsync(secondServerRun);
            }
        }
    }

    [Fact]
    public async Task Cancel_after_service_commit_retries_the_same_completed_upload_without_a_second_job()
    {
        var observer = new BlockingAcceptanceObserver();
        using var fixture = new LocalJobFixture(observer);
        var server = new AgentPipeServer(
            "S-1-5-21-1000",
            "1.0.0",
            new FixedIdentityVerifier(new AgentConnectionIdentity(321, 7, "S-1-5-21-1000")),
            new FixedAgentClock(),
            localJobs: fixture.Coordinator);
        var pair = DuplexStreamPair.Create();
        await using var clientStream = pair.Client;
        await using var serviceStream = pair.Service;
        var client = new AgentPipeClient(
            _ => ValueTask.FromResult<Stream>(clientStream),
            new InfiniteDelay());
        using var localJobs = new LocalJobClient(client, fixture.Spool.Root);
        using var runCancellation = new CancellationTokenSource();
        var serverRun = server.ProcessConnectionAsync(serviceStream, runCancellation.Token);
        var clientRun = client.RunAsync(
            Hello(),
            Heartbeat,
            (_, _, _) => throw new InvalidOperationException("signing_not_expected"),
            runCancellation.Token);

        try
        {
            await WaitUntilAsync(() => server.CurrentConnection is not null);
            var source = Path.Combine(fixture.Root, "selected.exe");
            var sourceBytes = "MZ-commit-before-cancel"u8.ToArray();
            await File.WriteAllBytesAsync(source, sourceBytes);
            using var uploadCancellation = new CancellationTokenSource();
            var upload = localJobs.CreateAndUploadAsync(
                source,
                new AuthenticodeParameters("AA00", "sha256", false),
                null,
                uploadCancellation.Token);
            await observer.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

            uploadCancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => upload.WaitAsync(TimeSpan.FromSeconds(5)));
            observer.Release();
            var jobId = await localJobs.CreateAndUploadAsync(
                source,
                new AuthenticodeParameters("AA00", "sha256", false),
                null,
                default).WaitAsync(TimeSpan.FromSeconds(5));

            var jobs = await fixture.Store.GetAllAsync();
            Assert.Single(jobs);
            Assert.Equal(jobId, jobs[0].Id);
            Assert.Equal([jobId], fixture.Dispatcher.Enqueued);
            Assert.Equal(sourceBytes, await File.ReadAllBytesAsync(source));
        }
        finally
        {
            observer.Release();
            runCancellation.Cancel();
            await IgnoreFailureAsync(clientRun);
            await IgnoreFailureAsync(serverRun);
        }
    }

    private static async Task SendAndAssertTerminalAsync(
        AgentPipeServer server,
        Guid connectionId,
        ChannelReader<JobTerminalMessage> terminals,
        int sequence)
    {
        var command = Command(sequence);
        await server.SendAsync(connectionId, command, default);
        var terminal = await terminals.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
        var completed = Assert.IsType<JobCompleted>(terminal);
        Assert.Equal(command.JobId, completed.JobId);
        Assert.Equal(command.DispatchId, completed.DispatchId);
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        while (!condition())
        {
            await Task.Delay(TimeSpan.FromMilliseconds(5), timeout.Token);
        }
    }

    private static async Task IgnoreFailureAsync(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch
        {
        }
    }

    private static AgentHello Hello() =>
        new(LengthPrefixedJsonProtocol.ProtocolVersion, 321, 7, "S-1-5-21-1000", "1.0.0", ["authenticode", "pdf"]);

    private static AgentHeartbeat Heartbeat() =>
        ProtocolV3TestFixtures.Heartbeat();

    private static SignJobCommand Command(int sequence) =>
        new(
            Guid.Parse($"aaaaaaaa-aaaa-aaaa-aaaa-{sequence:D12}"),
            Guid.Parse($"bbbbbbbb-bbbb-bbbb-bbbb-{sequence:D12}"),
            1,
            ".exe",
            "{}",
            10,
            new string('a', 64));

    private static ManagementSnapshot Snapshot(Guid connectionId) =>
        new(
            ManagementSnapshot.CurrentVersion,
            Now,
            connectionId,
            true,
            true,
            7,
            7,
            1_000,
            true,
            7,
            CapabilitySnapshot.NotConfigured(),
            CapabilitySnapshot.NotConfigured(),
            0,
            0,
            null,
            [],
            1);

    private sealed class BlockingSnapshotProvider(int expectedCallsAfterRelease)
        : IServiceManagementSnapshotProvider
    {
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _calls;

        public TaskCompletionSource Entered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ExpectedCallsReached { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<ManagementSnapshot> CreateAsync(
            AgentHealthSnapshot health,
            CancellationToken cancellationToken)
        {
            var calls = Interlocked.Increment(ref _calls);
            Entered.TrySetResult();
            if (calls >= expectedCallsAfterRelease)
            {
                ExpectedCallsReached.TrySetResult();
            }

            await _release.Task.WaitAsync(cancellationToken);
            return Snapshot(health.ConnectionId);
        }

        public void Release() => _release.TrySetResult();
    }

    private sealed class FixedIdentityVerifier(AgentConnectionIdentity identity)
        : IAgentConnectionIdentityVerifier
    {
        public ValueTask<AgentConnectionIdentity> VerifyAsync(
            Stream connection,
            CancellationToken cancellationToken) => ValueTask.FromResult(identity);
    }

    private sealed class FixedAgentClock : IAgentClock
    {
        public DateTimeOffset UtcNow => Now;

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
            Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
    }

    private sealed class InfiniteDelay : IAgentDelay
    {
        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
            Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
    }

    private sealed class LocalJobFixture : IDisposable
    {
        public LocalJobFixture(ILocalJobAcceptanceObserver? acceptanceObserver = null)
        {
            Root = Path.Combine(Path.GetTempPath(), "SimplySignAuto.Tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
            Store = new SqliteJobStore(Path.Combine(Root, "jobs.db"));
            Spool = new SpoolStore(Path.Combine(Root, "spool"), new NoopSpoolAclPolicy());
            Dispatcher = new RecordingDispatcher();
            Coordinator = new LocalJobUploadCoordinator(
                Store,
                Spool,
                Dispatcher,
                TimeProvider.System,
                "S-1-5-21-1000",
                new XorLeaseProtector(),
                acceptanceObserver: acceptanceObserver);
        }

        public string Root { get; }

        public SqliteJobStore Store { get; }

        public SpoolStore Spool { get; }

        public RecordingDispatcher Dispatcher { get; }

        public LocalJobUploadCoordinator Coordinator { get; }

        public void Dispose()
        {
            Store.Dispose();
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }

    private sealed class XorLeaseProtector : ILocalLeaseProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> lease) =>
            lease.ToArray().Select(value => (byte)(value ^ 0xa5)).ToArray();

        public byte[] Unprotect(ReadOnlySpan<byte> protectedLease) => Protect(protectedLease);
    }

    private sealed class RecordingDispatcher : IJobDispatcher
    {
        public List<Guid> Enqueued { get; } = [];

        public void Enqueue(Guid jobId) => Enqueued.Add(jobId);
    }

    private sealed class DisconnectingAcceptanceObserver(Stream client)
        : ILocalJobAcceptanceObserver
    {
        public TaskCompletionSource Disconnected { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task AfterAcceptedAsync(
            Guid requestId,
            Guid jobId,
            CancellationToken cancellationToken)
        {
            client.Dispose();
            Disconnected.TrySetResult();
            return Task.CompletedTask;
        }
    }

    private sealed class BlockingAcceptanceObserver : ILocalJobAcceptanceObserver
    {
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Entered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task AfterAcceptedAsync(
            Guid requestId,
            Guid jobId,
            CancellationToken cancellationToken)
        {
            Entered.TrySetResult();
            await _release.Task.WaitAsync(cancellationToken);
        }

        public void Release() => _release.TrySetResult();
    }

    private sealed class NoopSpoolAclPolicy : ISpoolAclPolicy
    {
        public void ProtectRoot(string path) { }

        public void ProtectJobDirectory(string path) { }

        public void ProtectInput(string path) { }

        public void ProtectFinalResult(string path) { }
    }

    private sealed record DuplexStreamPair(Stream Client, Stream Service)
    {
        public static DuplexStreamPair Create()
        {
            var clientInbound = Channel.CreateUnbounded<byte[]>();
            var serviceInbound = Channel.CreateUnbounded<byte[]>();
            return new DuplexStreamPair(
                new ChannelDuplexStream(clientInbound, serviceInbound.Writer),
                new ChannelDuplexStream(serviceInbound, clientInbound.Writer));
        }
    }

    private sealed class ChannelDuplexStream(
        Channel<byte[]> inbound,
        ChannelWriter<byte[]> outbound) : Stream
    {
        private byte[]? _current;
        private int _offset;
        private int _disposed;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            if (_current is null || _offset == _current.Length)
            {
                if (!await inbound.Reader.WaitToReadAsync(cancellationToken))
                {
                    return 0;
                }

                if (!inbound.Reader.TryRead(out _current))
                {
                    return 0;
                }

                _offset = 0;
            }

            var count = Math.Min(buffer.Length, _current.Length - _offset);
            _current.AsMemory(_offset, count).CopyTo(buffer);
            _offset += count;
            return count;
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            await outbound.WriteAsync(buffer.ToArray(), cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                inbound.Writer.TryComplete();
                outbound.TryComplete();
            }

            base.Dispose(disposing);
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
