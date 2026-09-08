using System.Buffers.Binary;
using System.Text;
using CodeSignAuto.Protocol;
using Xunit;

namespace CodeSignAuto.Protocol.Tests;

public sealed class ControlMessagesTests
{
    [Fact]
    public async Task Control_handshake_and_requests_round_trip_through_the_strict_protocol()
    {
        var requestId = Guid.NewGuid();
        AgentMessage[] messages =
        [
            new AdminControlHello(1, 321, 7, "S-1-5-21-1000"),
            new AdminControlAccepted(1),
            new AgentControlRequest(requestId, AdminControlContract.Refresh),
            new AgentControlRequest(requestId, AdminControlContract.Logout),
            new AgentControlRequest(
                requestId,
                AdminControlContract.ImportOtp,
                "otpauth://totp/Issuer:account?secret=JBSWY3DPEHPK3PXP&issuer=Issuer&algorithm=SHA256&digits=6&period=30"),
            new AgentControlResponse(
                requestId,
                AdminControlContract.Refresh,
                Heartbeat(),
                null,
                null,
                null,
                null,
                null),
            new AgentControlResponse(
                requestId,
                AdminControlContract.GenerateTotp,
                null,
                "123456",
                17,
                new DateTimeOffset(2026, 8, 14, 1, 2, 30, TimeSpan.Zero),
                null,
                null),
        ];

        foreach (var message in messages)
        {
            await using var stream = new MemoryStream();
            await LengthPrefixedJsonProtocol.WriteAsync(stream, message, default);
            stream.Position = 0;

            Assert.Equivalent(
                message,
                await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, default),
                strict: true);
        }
    }

    [Theory]
    [InlineData("refresh", "otpauth://totp/a?secret=A")]
    [InlineData("import_otp", null)]
    [InlineData("unknown", null)]
    public async Task Control_request_rejects_invalid_operation_and_otp_pair(string operation, string? otpUri)
    {
        var json = "{\"version\":3,\"type\":\"agent_control_request\",\"payload\":{" +
            $"\"requestId\":\"{Guid.NewGuid():D}\",\"operation\":\"{operation}\",\"otpUri\":" +
            (otpUri is null ? "null" : $"\"{otpUri}\"") + "}}";

        var error = await Assert.ThrowsAsync<ProtocolException>(() => ReadRawAsync(json));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public async Task Control_protocol_rejects_unknown_fields_without_echoing_otp()
    {
        const string marker = "PRIVATEOTPSECRETMARKER";
        var json = "{\"version\":3,\"type\":\"agent_control_request\",\"payload\":{" +
            $"\"requestId\":\"{Guid.NewGuid():D}\",\"operation\":\"import_otp\"," +
            $"\"otpUri\":\"otpauth://totp/a?secret={marker}\",\"unexpected\":true}}";

        var error = await Assert.ThrowsAsync<ProtocolException>(() => ReadRawAsync(json));

        Assert.Equal("invalid_message", error.Code);
        Assert.DoesNotContain(marker, error.Message, StringComparison.Ordinal);
    }

    private static AgentHeartbeat Heartbeat() => new(
        7,
        "not_checked",
        "not_checked",
        "not_checked",
        "not_checked",
        null,
        null,
        CapabilitySnapshot.NotConfigured(),
        CapabilitySnapshot.NotConfigured(),
        1);

    private static async Task<AgentMessage> ReadRawAsync(string json)
    {
        var payload = Encoding.UTF8.GetBytes(json);
        await using var stream = new MemoryStream();
        var header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(header, payload.Length);
        await stream.WriteAsync(header);
        await stream.WriteAsync(payload);
        stream.Position = 0;
        return await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, default);
    }
}
