using System.Reflection;
using CodeSignAuto.Agent.Ipc;
using CodeSignAuto.Agent.Sessions;
using CodeSignAuto.Core.Versioning;
using CodeSignAuto.Protocol;
using Xunit;

namespace CodeSignAuto.Agent.Tests;

public sealed class AgentPipeV2Tests
{
    [Fact]
    public async Task Async_handler_is_awaited_and_progress_and_terminal_share_the_connection_writer()
    {
        var command = Command();
        await using var stream = await CapturingPreloadedDuplexStream.CreateAsync(command);
        var client = new AgentPipeClient(_ => ValueTask.FromResult<Stream>(stream), new InfiniteDelay());
        Guid? activeDuringHandler = null;

        await client.RunAsync(
            Hello(),
            () => Heartbeat(client.CurrentJobId),
            async (received, progress, cancellationToken) =>
            {
                activeDuringHandler = client.CurrentJobId;
                Assert.False(client.CurrentJobCompletion.IsCompleted);
                await progress(80, "verifying", cancellationToken);
                return new JobCompleted(
                    received.JobId,
                    received.DispatchId,
                    17,
                    new string('b', 64));
            },
            CancellationToken.None);

        Assert.Equal(command.JobId, activeDuringHandler);
        Assert.Null(client.CurrentJobId);
        Assert.True(client.CurrentJobCompletion.IsCompleted);
        await using var written = new MemoryStream(stream.WrittenBytes);
        _ = Assert.IsType<AgentHello>(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.Equal(
            new JobProgress(command.JobId, command.DispatchId, 80, "verifying"),
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.Equal(
            new JobCompleted(command.JobId, command.DispatchId, 17, new string('b', 64)),
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
    }

    [Fact]
    public async Task Command_received_after_stop_accepting_closes_with_explicit_protocol_error()
    {
        await using var stream = await CapturingPreloadedDuplexStream.CreateAsync(Command());
        var client = new AgentPipeClient(_ => ValueTask.FromResult<Stream>(stream), new InfiniteDelay());
        client.StopAcceptingNewJobs();

        var error = await Assert.ThrowsAsync<ProtocolException>(() => client.RunAsync(
            Hello(),
            () => Heartbeat(null),
            (_, _, _) => Task.FromException<JobTerminalMessage>(new InvalidOperationException("must not run")),
            CancellationToken.None));

        Assert.Equal("agent_shutting_down", error.Code);
    }

    [Fact]
    public async Task Heartbeat_failure_cancels_and_awaits_inflight_handler()
    {
        var command = Command();
        await using var stream = await CapturingPreloadedDuplexStream.CreateAsync(command, blockAfterInput: true);
        var handlerStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handlerCancelled = false;
        var delay = new FailingDelay(handlerStarted.Task);
        var client = new AgentPipeClient(_ => ValueTask.FromResult<Stream>(stream), delay);

        await Assert.ThrowsAsync<IOException>(() => client.RunAsync(
            Hello(),
            () => Heartbeat(client.CurrentJobId),
            async (_, _, cancellationToken) =>
            {
                handlerStarted.TrySetResult();
                try
                {
                    await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    handlerCancelled = true;
                    throw;
                }

                throw new InvalidOperationException("unreachable");
            },
            CancellationToken.None));

        Assert.True(handlerCancelled);
        Assert.True(client.CurrentJobCompletion.IsCompleted);
    }

    [Fact]
    public async Task Pipe_session_advertises_only_explicit_capabilities_and_uses_explicit_worker_handler()
    {
        var command = Command();
        await using var stream = await CapturingPreloadedDuplexStream.CreateAsync(command);
        var client = new AgentPipeClient(_ => ValueTask.FromResult<Stream>(stream), new InfiniteDelay());
        var handlerCalls = 0;
        var session = new AgentPipeSession(
            client,
            (received, _, _) =>
            {
                handlerCalls++;
                return Task.FromResult<JobTerminalMessage>(new JobCompleted(
                    received.JobId,
                    received.DispatchId,
                    17,
                    new string('b', 64)));
            },
            ["pdf"]);

        await session.RunAsync(
            new InteractiveSessionInfo(7, "S-1-5-21-1000", "1000"),
            new AgentReadiness("ready"),
            CancellationToken.None);

        Assert.Equal(1, handlerCalls);
        await using var written = new MemoryStream(stream.WrittenBytes);
        var hello = Assert.IsType<AgentHello>(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        var informationalIdentity = typeof(AgentPipeSession).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;
        Assert.NotNull(informationalIdentity);
        Assert.Equal(ProductVersion.Parse(informationalIdentity).Identity, hello.AgentVersion);
        Assert.Equal(["pdf"], hello.Capabilities);
        Assert.IsType<JobCompleted>(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
    }

    [Fact]
    public void Pipe_session_rejects_empty_or_unknown_capabilities()
    {
        var client = new AgentPipeClient(_ => ValueTask.FromResult<Stream>(Stream.Null), new InfiniteDelay());
        SignJobCommandHandler handler = static (_, _, _) =>
            Task.FromException<JobTerminalMessage>(new InvalidOperationException("not called"));

        Assert.Throws<ArgumentException>(() => new AgentPipeSession(client, handler, []));
        Assert.Throws<ArgumentException>(() => new AgentPipeSession(client, handler, ["pdf", "arbitrary"]));
    }

    [Fact]
    public async Task Begin_wins_admission_barrier_before_stop_and_publishes_new_completion_first()
    {
        var command = Command();
        await using var stream = await CapturingPreloadedDuplexStream.CreateAsync(command, blockAfterInput: true);
        using var admissionEntered = new ManualResetEventSlim();
        using var releaseAdmission = new ManualResetEventSlim();
        var handlerStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseHandler = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var client = new AgentPipeClient(
            _ => ValueTask.FromResult<Stream>(stream),
            new InfiniteDelay(),
            () =>
            {
                admissionEntered.Set();
                releaseAdmission.Wait();
            });
        using var cancellation = new CancellationTokenSource();

        var run = Task.Run(() => client.RunAsync(
            Hello(),
            () => Heartbeat(client.CurrentJobId),
            async (_, _, cancellationToken) =>
            {
                handlerStarted.TrySetResult();
                await releaseHandler.Task.WaitAsync(cancellationToken);
                return new JobFailed(command.JobId, command.DispatchId, "internal_error", "Test failure.");
            },
            cancellation.Token));
        Assert.True(admissionEntered.Wait(TimeSpan.FromSeconds(2)));

        var stop = Task.Run(client.StopAcceptingNewJobs);
        await Task.Delay(20);
        Assert.False(stop.IsCompleted);
        releaseAdmission.Set();
        await handlerStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await stop.WaitAsync(TimeSpan.FromSeconds(2));

        var currentCompletion = client.CurrentJobCompletion;
        Assert.False(currentCompletion.IsCompleted);
        Assert.Equal(command.JobId, client.CurrentJobId);
        releaseHandler.TrySetResult();
        await currentCompletion.WaitAsync(TimeSpan.FromSeconds(2));
        cancellation.Cancel();
        await run;
    }

    private static SignJobCommand Command() => new(
        Guid.Parse("11111111-1111-1111-1111-111111111111"),
        Guid.Parse("22222222-2222-2222-2222-222222222222"),
        1,
        ".pdf",
        "{}",
        12,
        new string('a', 64));

    private static AgentHello Hello() =>
        new(LengthPrefixedJsonProtocol.ProtocolVersion, 321, 7, "S-1-5-21-1000", "1.0.0", ["authenticode", "pdf"]);

    private static AgentHeartbeat Heartbeat(Guid? jobId) =>
        ProtocolV3TestFixtures.Heartbeat(currentJobId: jobId);

    private sealed class InfiniteDelay : IAgentDelay
    {
        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
            Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
    }

    private sealed class FailingDelay(Task handlerStarted) : IAgentDelay
    {
        public async Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            await handlerStarted.WaitAsync(cancellationToken);
            throw new IOException("heartbeat write failed");
        }
    }

    private sealed class CapturingPreloadedDuplexStream : Stream
    {
        private readonly MemoryStream _input;
        private readonly MemoryStream _output = new();
        private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly bool _blockAfterInput;

        private CapturingPreloadedDuplexStream(byte[] input, bool blockAfterInput)
        {
            _input = new MemoryStream(input);
            _blockAfterInput = blockAfterInput;
        }

        public byte[] WrittenBytes => _output.ToArray();

        public static async Task<CapturingPreloadedDuplexStream> CreateAsync(
            AgentMessage message,
            bool blockAfterInput = false)
        {
            await using var input = new MemoryStream();
            await LengthPrefixedJsonProtocol.WriteAsync(input, message, CancellationToken.None);
            return new CapturingPreloadedDuplexStream(input.ToArray(), blockAfterInput);
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var read = await _input.ReadAsync(buffer, cancellationToken);
            if (read > 0 || !_blockAfterInput)
            {
                return read;
            }

            await _closed.Task.WaitAsync(cancellationToken);
            return 0;
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            _output.Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        protected override void Dispose(bool disposing)
        {
            _closed.TrySetResult();
            _input.Dispose();
            _output.Dispose();
            base.Dispose(disposing);
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
