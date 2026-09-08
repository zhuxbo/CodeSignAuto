using CodeSignAuto.Agent.Ipc;
using CodeSignAuto.Protocol;
using Xunit;

namespace CodeSignAuto.Agent.Tests;

public sealed class AgentPipeClientTests
{
    [Fact]
    public async Task Sends_hello_then_heartbeat_on_the_five_second_schedule()
    {
        await using var stream = new CapturingDuplexStream();
        var delay = new ManualAgentDelay();
        var client = new AgentPipeClient(_ => ValueTask.FromResult<Stream>(stream), delay);
        var hello = new AgentHello(LengthPrefixedJsonProtocol.ProtocolVersion, 321, 7, "S-1-5-21-1000", "1.0.0", ["authenticode", "pdf"]);
        var heartbeat = ProtocolV3TestFixtures.Heartbeat();
        using var cancellation = new CancellationTokenSource();

        var run = client.RunAsync(
            hello,
            () => heartbeat,
            static (_, _, _) => Task.FromException<JobTerminalMessage>(new InvalidOperationException("unexpected command")),
            cancellation.Token);
        await WaitUntilAsync(() => stream.FrameCount == 1);
        Assert.Equal(TimeSpan.FromSeconds(5), await delay.WaitForDelayAsync());

        delay.Release();
        await WaitUntilAsync(() => stream.FrameCount == 2);
        cancellation.Cancel();
        await run;

        await using var written = new MemoryStream(stream.WrittenBytes);
        Assert.Equivalent(
            hello,
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, CancellationToken.None),
            strict: true);
        Assert.Equal(heartbeat, await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, CancellationToken.None));
    }

    [Fact]
    public async Task Exposes_sign_commands_and_exits_when_service_disconnects()
    {
        var command = new SignJobCommand(Guid.NewGuid(), Guid.NewGuid(), 1, ".pdf", "{}", 12, new string('a', 64));
        await using var stream = await PreloadedDuplexStream.CreateAsync(command);
        var client = new AgentPipeClient(_ => ValueTask.FromResult<Stream>(stream), new InfiniteAgentDelay());
        var received = new List<SignJobCommand>();

        await client.RunAsync(
            new AgentHello(LengthPrefixedJsonProtocol.ProtocolVersion, 321, 7, "S-1-5-21-1000", "1.0.0", ["authenticode", "pdf"]),
            () => ProtocolV3TestFixtures.Heartbeat(),
            (receivedCommand, _, _) =>
            {
                received.Add(receivedCommand);
                return Task.FromResult<JobTerminalMessage>(new JobFailed(
                    receivedCommand.JobId,
                    receivedCommand.DispatchId,
                    "internal_error",
                    "Test failure."));
            },
            CancellationToken.None);

        Assert.Equal([command], received);
    }

    [Fact]
    public async Task Rejects_new_sign_commands_after_acceptance_is_stopped()
    {
        var command = new SignJobCommand(Guid.NewGuid(), Guid.NewGuid(), 1, ".pdf", "{}", 12, new string('a', 64));
        await using var stream = await PreloadedDuplexStream.CreateAsync(command);
        var client = new AgentPipeClient(_ => ValueTask.FromResult<Stream>(stream), new InfiniteAgentDelay());
        client.StopAcceptingNewJobs();
        var error = await Assert.ThrowsAsync<ProtocolException>(() => client.RunAsync(
            new AgentHello(LengthPrefixedJsonProtocol.ProtocolVersion, 321, 7, "S-1-5-21-1000", "1.0.0", ["authenticode", "pdf"]),
            () => ProtocolV3TestFixtures.Heartbeat(),
            static (_, _, _) => Task.FromException<JobTerminalMessage>(new InvalidOperationException("must not run")),
            CancellationToken.None));

        Assert.Equal("agent_shutting_down", error.Code);
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var attempt = 0; attempt < 1_000 && !condition(); attempt++)
        {
            await Task.Delay(1);
        }

        Assert.True(condition());
    }

    private sealed class ManualAgentDelay : IAgentDelay
    {
        private readonly object _sync = new();
        private readonly TaskCompletionSource<TimeSpan> _requested = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly Queue<TaskCompletionSource> _pending = [];

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            _requested.TrySetResult(delay);
            var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_sync)
            {
                _pending.Enqueue(completion);
            }

            return completion.Task.WaitAsync(cancellationToken);
        }

        public Task<TimeSpan> WaitForDelayAsync() => _requested.Task;

        public void Release()
        {
            TaskCompletionSource completion;
            lock (_sync)
            {
                completion = _pending.Dequeue();
            }

            completion.TrySetResult();
        }
    }

    private sealed class InfiniteAgentDelay : IAgentDelay
    {
        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
            Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
    }

    private sealed class CapturingDuplexStream : Stream
    {
        private readonly object _sync = new();
        private readonly MemoryStream _written = new();
        private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int FrameCount
        {
            get
            {
                lock (_sync)
                {
                    var bytes = _written.ToArray();
                    var position = 0;
                    var count = 0;
                    while (position + 4 <= bytes.Length)
                    {
                        var length = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(position, 4));
                        if (length <= 0 || position + 4 + length > bytes.Length)
                        {
                            break;
                        }

                        position += 4 + length;
                        count++;
                    }

                    return count;
                }
            }
        }

        public byte[] WrittenBytes
        {
            get
            {
                lock (_sync)
                {
                    return _written.ToArray();
                }
            }
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await _closed.Task.WaitAsync(cancellationToken);
            return 0;
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                _written.Write(buffer.Span);
            }

            return ValueTask.CompletedTask;
        }

        protected override void Dispose(bool disposing)
        {
            _closed.TrySetResult();
            _written.Dispose();
            base.Dispose(disposing);
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class PreloadedDuplexStream : Stream
    {
        private readonly MemoryStream _input;

        private PreloadedDuplexStream(byte[] input)
        {
            _input = new MemoryStream(input);
        }

        public static async Task<PreloadedDuplexStream> CreateAsync(AgentMessage message)
        {
            await using var input = new MemoryStream();
            await LengthPrefixedJsonProtocol.WriteAsync(input, message, CancellationToken.None);
            return new PreloadedDuplexStream(input.ToArray());
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            _input.ReadAsync(buffer, cancellationToken);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;
        protected override void Dispose(bool disposing)
        {
            _input.Dispose();
            base.Dispose(disposing);
        }
        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
