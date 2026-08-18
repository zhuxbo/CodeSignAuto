using System.Buffers.Binary;
using System.Text;
using SimplySignAuto.Protocol;
using Xunit;

namespace SimplySignAuto.Protocol.Tests;

public sealed class ProtocolV3Tests
{
    [Fact]
    public async Task V3_round_trips_dispatch_identity_and_attempt_on_every_job_message()
    {
        var jobId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var dispatchId = Guid.Parse("22222222-2222-2222-2222-222222222222");
        AgentMessage[] expected =
        [
            new SignJobCommand(jobId, dispatchId, 2, ".pdf", "{\"kind\":\"pdf\"}", 12, new string('a', 64)),
            new JobProgress(jobId, dispatchId, 50, "signing"),
            new JobCompleted(jobId, dispatchId, 18, new string('b', 64)),
            new JobFailed(jobId, dispatchId, "pdf_verify_failed", "PDF verification failed."),
        ];

        foreach (var message in expected)
        {
            await using var stream = new MemoryStream();
            await LengthPrefixedJsonProtocol.WriteAsync(stream, message, CancellationToken.None);
            stream.Position = 0;

            Assert.Equivalent(
                message,
                await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, CancellationToken.None),
                strict: true);
        }
    }

    [Fact]
    public async Task V1_peer_fails_closed()
    {
        await using var stream = JsonFrame(
            "{\"version\":1,\"type\":\"job_progress\",\"payload\":{\"jobId\":\"11111111-1111-1111-1111-111111111111\",\"dispatchId\":\"22222222-2222-2222-2222-222222222222\",\"percent\":50,\"stage\":\"signing\"}}");

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, CancellationToken.None));

        Assert.Equal("unsupported_protocol_version", error.Code);
    }

    [Theory]
    [InlineData("[\"authenticode\",\"future-capability\"]")]
    [InlineData("[\"authenticode\",\"authenticode\"]")]
    public async Task Rejects_unknown_or_duplicate_hello_capabilities(string capabilitiesJson)
    {
        await using var stream = JsonFrame(
            "{\"version\":3,\"type\":\"agent_hello\",\"payload\":{" +
            "\"protocolVersion\":3,\"processId\":321,\"sessionId\":7," +
            "\"userSid\":\"S-1-5-21-1000\",\"agentVersion\":\"1.2.3\"," +
            $"\"capabilities\":{capabilitiesJson}}}}}");

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, CancellationToken.None));

        Assert.Equal("invalid_message", error.Code);
    }

    [Theory]
    [MemberData(nameof(InvalidOutboundMessages))]
    public async Task Rejects_invalid_outbound_job_message_semantics(AgentMessage invalid)
    {
        await using var stream = new MemoryStream();

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.WriteAsync(stream, invalid, CancellationToken.None));

        Assert.Equal("invalid_message", error.Code);
        Assert.Equal(0, stream.Length);
    }

    [Theory]
    [InlineData("00000000-0000-0000-0000-000000000000", "22222222-2222-2222-2222-222222222222", 1, ".pdf", 1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("11111111-1111-1111-1111-111111111111", "00000000-0000-0000-0000-000000000000", 1, ".pdf", 1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", 0, ".pdf", 1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", 3, ".pdf", 1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", 1, ".PDF", 1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", 1, ".txt", 1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", 1, ".pdf", -1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", 1, ".pdf", 1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task Rejects_invalid_inbound_sign_command_semantics(
        string jobId,
        string dispatchId,
        int attempt,
        string extension,
        long size,
        string sha256)
    {
        var json = "{\"version\":3,\"type\":\"sign_job_command\",\"payload\":{" +
            $"\"jobId\":\"{jobId}\",\"dispatchId\":\"{dispatchId}\",\"attemptNumber\":{attempt}," +
            $"\"extension\":\"{extension}\",\"canonicalParametersJson\":\"{{}}\",\"inputSize\":{size},\"inputSha256\":\"{sha256}\"}}}}";
        await using var stream = JsonFrame(json);

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, CancellationToken.None));

        Assert.Equal("invalid_message", error.Code);
    }

    [Theory]
    [InlineData(-1, "signing")]
    [InlineData(101, "signing")]
    [InlineData(50, "queued")]
    public async Task Rejects_invalid_progress_semantics(int percent, string stage)
    {
        await using var stream = new MemoryStream();
        var invalid = new JobProgress(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            Guid.Parse("22222222-2222-2222-2222-222222222222"),
            percent,
            stage);

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.WriteAsync(stream, invalid, CancellationToken.None));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public async Task Rejects_unknown_error_code_and_unsafe_or_oversized_message()
    {
        var jobId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var dispatchId = Guid.Parse("22222222-2222-2222-2222-222222222222");
        AgentMessage[] invalid =
        [
            new JobFailed(jobId, dispatchId, "made_up", "safe"),
            new JobFailed(jobId, dispatchId, "internal_error", "line1\nline2"),
            new JobFailed(jobId, dispatchId, "internal_error", new string('x', 257)),
        ];

        foreach (var message in invalid)
        {
            await using var stream = new MemoryStream();
            var error = await Assert.ThrowsAsync<ProtocolException>(() =>
                LengthPrefixedJsonProtocol.WriteAsync(stream, message, CancellationToken.None));
            Assert.Equal("invalid_message", error.Code);
            Assert.Equal(0, stream.Length);
        }
    }

    [Theory]
    [InlineData("{\"version\":3,\"type\":\"job_progress\",\"payload\":{\"jobId\":\"11111111-1111-1111-1111-111111111111\",\"dispatchId\":\"22222222-2222-2222-2222-222222222222\",\"percent\":25,\"percent\":50,\"stage\":\"signing\"}}")]
    [InlineData("{\"version\":3,\"type\":\"job_failed\",\"payload\":{\"jobId\":\"11111111-1111-1111-1111-111111111111\",\"jobId\":\"33333333-3333-3333-3333-333333333333\",\"dispatchId\":\"22222222-2222-2222-2222-222222222222\",\"errorCode\":\"internal_error\",\"errorMessage\":\"failed\"}}")]
    public async Task Rejects_duplicate_known_payload_fields(string json)
    {
        await using var stream = JsonFrame(json);

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, CancellationToken.None));

        Assert.Equal("invalid_message", error.Code);
    }

    [Theory]
    [InlineData("{\"version\":3,\"type\":\"job_progress\",\"payload\":{\"jobId\":\"11111111-1111-1111-1111-111111111111\",\"JobId\":\"33333333-3333-3333-3333-333333333333\",\"dispatchId\":\"22222222-2222-2222-2222-222222222222\",\"percent\":50,\"stage\":\"signing\"}}")]
    [InlineData("{\"version\":3,\"type\":\"job_progress\",\"payload\":{\"JobId\":\"11111111-1111-1111-1111-111111111111\",\"dispatchId\":\"22222222-2222-2222-2222-222222222222\",\"percent\":50,\"stage\":\"signing\"}}")]
    public async Task Rejects_case_ambiguous_or_noncanonical_known_payload_fields(string json)
    {
        await using var stream = JsonFrame(json);

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, CancellationToken.None));

        Assert.Equal("invalid_message", error.Code);
    }

    public static TheoryData<AgentMessage> InvalidOutboundMessages()
    {
        var jobId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var dispatchId = Guid.Parse("22222222-2222-2222-2222-222222222222");
        return new TheoryData<AgentMessage>
        {
            new JobCompleted(Guid.Empty, dispatchId, 1, new string('a', 64)),
            new JobCompleted(jobId, Guid.Empty, 1, new string('a', 64)),
            new JobCompleted(jobId, dispatchId, -1, new string('a', 64)),
            new JobCompleted(jobId, dispatchId, 1, new string('A', 64)),
        };
    }

    private static MemoryStream JsonFrame(string json)
    {
        var payload = Encoding.UTF8.GetBytes(json);
        var bytes = new byte[4 + payload.Length];
        BinaryPrimitives.WriteInt32BigEndian(bytes, payload.Length);
        payload.CopyTo(bytes, 4);
        return new MemoryStream(bytes);
    }
}
