using System.Buffers.Binary;
using System.Text;
using CodeSignAuto.Protocol;
using Xunit;

namespace CodeSignAuto.Protocol.Tests;

public sealed class LengthPrefixedJsonProtocolTests
{
    [Fact]
    public async Task Rejects_frame_larger_than_the_explicit_hard_limit()
    {
        await using var stream = FrameHeader(LengthPrefixedJsonProtocol.MaximumPayloadLength + 1);

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, CancellationToken.None));

        Assert.Equal("invalid_frame_length", error.Code);
    }

    [Theory]
    [InlineData("certificate_catalog_unavailable")]
    [InlineData("certificate_not_found")]
    [InlineData("certificate_serial_ambiguous")]
    [InlineData("certificate_not_usable")]
    [InlineData("pdf_appearance_font_missing")]
    public async Task Job_failed_round_trips_every_certificate_catalog_error_code(string errorCode)
    {
        var expected = new JobFailed(Guid.NewGuid(), Guid.NewGuid(), errorCode, "catalog failure");
        await using var stream = new MemoryStream();

        await LengthPrefixedJsonProtocol.WriteAsync(stream, expected, CancellationToken.None);
        stream.Position = 0;

        Assert.Equal(
            expected,
            Assert.IsType<JobFailed>(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(
                stream,
                CancellationToken.None)));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    public async Task Rejects_non_positive_frame_lengths(int length)
    {
        await using var stream = FrameHeader(length);

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, CancellationToken.None));

        Assert.Equal("invalid_frame_length", error.Code);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Rejects_eof_and_truncated_headers(int headerBytes)
    {
        await using var stream = new MemoryStream(new byte[headerBytes]);

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, CancellationToken.None));

        Assert.Equal("unexpected_eof", error.Code);
    }

    [Fact]
    public async Task Rejects_truncated_payload()
    {
        await using var stream = new MemoryStream();
        await stream.WriteAsync(new byte[] { 0, 0, 0, 4, 0x7b, 0x7d });
        stream.Position = 0;

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, CancellationToken.None));

        Assert.Equal("unexpected_eof", error.Code);
    }

    [Fact]
    public async Task Round_trips_unicode_without_message_boundary_assumptions()
    {
        var expected = new JobFailed(Guid.NewGuid(), Guid.NewGuid(), "internal_error", "签名失败");
        await using var encoded = new MemoryStream();
        await LengthPrefixedJsonProtocol.WriteAsync(encoded, expected, CancellationToken.None);
        await using var chunks = new SingleByteReadStream(encoded.ToArray());

        var actual = await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(chunks, CancellationToken.None);

        Assert.Equal(expected, Assert.IsType<JobFailed>(actual));
    }

    [Fact]
    public async Task Uses_explicit_versioned_envelope()
    {
        var message = new JobProgress(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            Guid.Parse("22222222-2222-2222-2222-222222222222"),
            50,
            "signing");
        await using var stream = new MemoryStream();

        await LengthPrefixedJsonProtocol.WriteAsync(stream, message, CancellationToken.None);

        var json = Encoding.UTF8.GetString(stream.ToArray().AsSpan(4));
        Assert.Equal(
            "{\"version\":3,\"type\":\"job_progress\",\"payload\":{\"jobId\":\"11111111-1111-1111-1111-111111111111\",\"dispatchId\":\"22222222-2222-2222-2222-222222222222\",\"percent\":50,\"stage\":\"signing\"}}",
            json);
    }

    [Fact]
    public async Task Round_trips_every_whitelisted_message_type()
    {
        var jobId = Guid.NewGuid();
        AgentMessage[] expected =
        [
            new AgentHello(3, 321, 7, "S-1-5-21-1000", "1.2.3", ["authenticode", "pdf"]),
            FullHeartbeat(jobId),
            new SignJobCommand(jobId, Guid.NewGuid(), 1, ".pdf", "{\"page\":1}", 12, new string('a', 64)),
            new JobProgress(jobId, Guid.NewGuid(), 50, "signing"),
            new JobCompleted(jobId, Guid.NewGuid(), 18, new string('b', 64)),
            new JobFailed(jobId, Guid.NewGuid(), "internal_error", "签名失败"),
        ];

        foreach (var message in expected)
        {
            await using var stream = new MemoryStream();
            await LengthPrefixedJsonProtocol.WriteAsync(stream, message, CancellationToken.None);
            stream.Position = 0;

            var actual = await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, CancellationToken.None);

            Assert.Equivalent(message, actual, strict: true);
        }
    }

    [Fact]
    public async Task Round_trips_bounded_upgrade_drain_and_resume_messages()
    {
        AgentMessage[] messages =
        [
            new UpgradeDrainRequest(Guid.NewGuid(), 120),
            new UpgradeDrainResponse(Guid.NewGuid(), true, null),
            new UpgradeDrainResponse(Guid.NewGuid(), false, "upgrade_drain_timeout"),
            new UpgradeResumeRequest(Guid.NewGuid()),
            new UpgradeResumeResponse(Guid.NewGuid(), true, null),
        ];

        foreach (var expected in messages)
        {
            await using var stream = new MemoryStream();
            await LengthPrefixedJsonProtocol.WriteAsync(stream, expected, CancellationToken.None);
            stream.Position = 0;

            Assert.Equal(
                expected,
                await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, CancellationToken.None));
        }
    }

    [Fact]
    public async Task Round_trips_not_ready_heartbeat_before_simplysign_process_exists()
    {
        var observedAt = new DateTimeOffset(2026, 8, 13, 0, 0, 0, TimeSpan.Zero);
        var session = new SimplySignSessionSnapshot(
            SimplySignSessionState.Unknown,
            1,
            observedAt,
            observedAt,
            null,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            "unknown",
            0,
            null,
            simplySignProcessRunning: false,
            simplySignProcessSessionId: null);
        var capability = new CapabilitySnapshot(
            true,
            false,
            false,
            null,
            false,
            false,
            null,
            false,
            false,
            null,
            false,
            "unknown",
            session: session);
        var expected = new AgentHeartbeat(
            1,
            "not_ready",
            "not_ready",
            "not_ready",
            "not_ready",
            null,
            null,
            capability,
            capability,
            1);
        await using var stream = new MemoryStream();

        await LengthPrefixedJsonProtocol.WriteAsync(stream, expected, CancellationToken.None);
        stream.Position = 0;

        Assert.Equal(
            expected,
            Assert.IsType<AgentHeartbeat>(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(
                stream,
                CancellationToken.None)));
    }

    [Fact]
    public async Task Rejects_unknown_message_type_without_disclosing_payload()
    {
        const string secret = "private-payload-marker";
        await using var stream = JsonFrame($"{{\"version\":3,\"type\":\"runtime_type\",\"payload\":{{\"value\":\"{secret}\"}}}}");

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, CancellationToken.None));

        Assert.Equal("unknown_message_type", error.Code);
        Assert.DoesNotContain(secret, error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{\"version\":2,\"type\":\"job_failed\",\"payload\":{\"jobId\":\"00000000-0000-0000-0000-000000000000\",\"dispatchId\":\"00000000-0000-0000-0000-000000000000\",\"errorCode\":\"internal_error\",\"errorMessage\":\"y\"}}", "unsupported_protocol_version")]
    [InlineData("{\"version\":3,\"type\":\"job_failed\",\"payload\":{\"jobId\":\"00000000-0000-0000-0000-000000000000\",\"dispatchId\":\"00000000-0000-0000-0000-000000000000\",\"errorCode\":\"internal_error\",\"errorMessage\":\"y\"},\"extra\":true}", "invalid_message")]
    [InlineData("{\"version\":3,\"type\":\"job_failed\",\"payload\":{\"jobId\":\"00000000-0000-0000-0000-000000000000\",\"dispatchId\":\"00000000-0000-0000-0000-000000000000\",\"errorCode\":\"internal_error\",\"errorMessage\":\"y\",\"extra\":true}}", "invalid_message")]
    public async Task Rejects_wrong_version_and_unknown_fields(string json, string expectedCode)
    {
        await using var stream = JsonFrame(json);

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, CancellationToken.None));

        Assert.Equal(expectedCode, error.Code);
    }

    [Fact]
    public async Task Rejects_invalid_utf8_and_invalid_json_with_stable_errors()
    {
        await using var invalidUtf8 = RawFrame([0xff]);
        var utf8Error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(invalidUtf8, CancellationToken.None));
        Assert.Equal("invalid_message", utf8Error.Code);

        await using var invalidJson = JsonFrame("{");
        var jsonError = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(invalidJson, CancellationToken.None));
        Assert.Equal("invalid_message", jsonError.Code);
    }

    [Fact]
    public async Task Does_not_deserialize_arbitrary_requested_types()
    {
        await using var stream = JsonFrame("{\"version\":3,\"type\":\"arbitrary\",\"payload\":{\"value\":\"unsafe\"}}");

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.ReadAsync<ArbitraryClientType>(stream, CancellationToken.None));

        Assert.Equal("unsupported_message_contract", error.Code);
    }

    [Fact]
    public async Task Sign_job_command_never_serializes_a_path()
    {
        var command = new SignJobCommand(Guid.NewGuid(), Guid.NewGuid(), 1, ".pdf", "{}", 3, new string('c', 64));
        await using var stream = new MemoryStream();

        await LengthPrefixedJsonProtocol.WriteAsync(stream, command, CancellationToken.None);

        var json = Encoding.UTF8.GetString(stream.ToArray().AsSpan(4));
        Assert.DoesNotContain("path", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("/", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\\", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Rejects_oversized_error_message_without_exposing_it()
    {
        var secret = new string('z', 70_000);
        var message = new JobFailed(Guid.NewGuid(), Guid.NewGuid(), "internal_error", secret);
        await using var stream = new MemoryStream();

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.WriteAsync(stream, message, CancellationToken.None));

        Assert.Equal("invalid_message", error.Code);
        Assert.DoesNotContain(secret, error.Message, StringComparison.Ordinal);
        Assert.Equal(0, stream.Length);
    }

    [Fact]
    public async Task Concurrent_writes_to_the_same_connection_do_not_interleave_frames()
    {
        var firstMessage = new JobFailed(Guid.NewGuid(), Guid.NewGuid(), "internal_error", "first-message");
        var secondMessage = new JobFailed(Guid.NewGuid(), Guid.NewGuid(), "internal_error", "second-message");
        await using var stream = new HeaderBlockingWriteStream();

        var firstWrite = LengthPrefixedJsonProtocol.WriteAsync(stream, firstMessage, CancellationToken.None);
        await stream.FirstWriteEntered;
        var secondWrite = LengthPrefixedJsonProtocol.WriteAsync(stream, secondMessage, CancellationToken.None);
        var writesBeforeRelease = stream.WriteCallCount;

        stream.ReleaseFirstWrite();
        await Task.WhenAll(firstWrite, secondWrite);

        Assert.Equal(1, writesBeforeRelease);
        await using var encoded = new MemoryStream(stream.ToArray());
        Assert.Equal(firstMessage, await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(encoded, CancellationToken.None));
        Assert.Equal(secondMessage, await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(encoded, CancellationToken.None));
    }

    private static MemoryStream FrameHeader(int length)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(bytes, length);
        return new MemoryStream(bytes);
    }

    private static MemoryStream JsonFrame(string json) => RawFrame(Encoding.UTF8.GetBytes(json));

    private static AgentHeartbeat FullHeartbeat(Guid? currentJobId)
    {
        CapabilitySnapshot Capability(string alias)
        {
            var session = new SimplySignSessionSnapshot(
                SimplySignSessionState.Ready,
                3,
                new DateTimeOffset(2026, 8, 9, 0, 10, 0, TimeSpan.Zero),
                new DateTimeOffset(2026, 8, 9, 0, 9, 0, TimeSpan.Zero),
                7,
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                "ready",
                0,
                null,
                true,
                7);
            return new CapabilitySnapshot(
                true,
                true,
                true,
                "34567890",
                true,
                true,
                "abcdef12",
                true,
                true,
                "1234abcd",
                true,
                "ready",
                DateTimeOffset.Parse("2027-08-09T00:00:00Z"),
                "89ABCDEF",
                session);
        }

        return new AgentHeartbeat(
            7,
            "ready",
            "ready",
            "ready",
            "ready",
            currentJobId,
            7,
            Capability("authenticode-primary"),
            Capability("pdf-primary"),
            3);
    }

    private static MemoryStream RawFrame(byte[] payload)
    {
        var bytes = new byte[4 + payload.Length];
        BinaryPrimitives.WriteInt32BigEndian(bytes, payload.Length);
        payload.CopyTo(bytes, 4);
        return new MemoryStream(bytes);
    }

    private sealed record ArbitraryClientType(string Value);

    private sealed class SingleByteReadStream(byte[] bytes) : Stream
    {
        private readonly MemoryStream _inner = new(bytes);

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;
        public override long Position { get => _inner.Position; set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, Math.Min(1, count));
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            _inner.ReadAsync(buffer[..Math.Min(1, buffer.Length)], cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class HeaderBlockingWriteStream : Stream
    {
        private readonly object _sync = new();
        private readonly MemoryStream _inner = new();
        private readonly TaskCompletionSource _firstWriteEntered =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _releaseFirstWrite =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _writeCallCount;

        public Task FirstWriteEntered => _firstWriteEntered.Task;

        public int WriteCallCount => Volatile.Read(ref _writeCallCount);

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public byte[] ToArray()
        {
            lock (_sync)
            {
                return _inner.ToArray();
            }
        }

        public void ReleaseFirstWrite() => _releaseFirstWrite.TrySetResult();

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            var call = Interlocked.Increment(ref _writeCallCount);
            lock (_sync)
            {
                _inner.Write(buffer.Span);
            }

            if (call == 1)
            {
                _firstWriteEntered.TrySetResult();
                await _releaseFirstWrite.Task.WaitAsync(cancellationToken);
            }
        }

        protected override void Dispose(bool disposing)
        {
            _releaseFirstWrite.TrySetResult();
            _inner.Dispose();
            base.Dispose(disposing);
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
