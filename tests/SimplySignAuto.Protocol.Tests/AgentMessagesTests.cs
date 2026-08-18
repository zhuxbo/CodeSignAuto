using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using SimplySignAuto.Protocol;
using Xunit;

namespace SimplySignAuto.Protocol.Tests;

public sealed class AgentMessagesTests
{
    [Fact]
    public async Task Heartbeat_round_trips_generation_and_same_generation_alias_snapshots()
    {
        var heartbeat = Heartbeat();
        await using var stream = new MemoryStream();

        await LengthPrefixedJsonProtocol.WriteAsync(stream, heartbeat, default);
        stream.Position = 0;
        var actual = Assert.IsType<AgentHeartbeat>(
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, default));

        Assert.Equal(3, actual.SessionGeneration);
        Assert.Equal(heartbeat.Authenticode!.Session, actual.Authenticode!.Session);
        Assert.Equal(heartbeat.Pdf!.Session, actual.Pdf!.Session);
        Assert.Equal(3, actual.Authenticode.Session!.SessionGeneration);
        Assert.Equal(3, actual.Pdf.Session!.SessionGeneration);
    }

    [Fact]
    public async Task Heartbeat_round_trips_only_bounded_redacted_session_transition_evidence()
    {
        var transitions = new[]
        {
            new SessionTransitionEvidence(
                41,
                SimplySignSessionState.Loginning,
                3,
                Utc(11),
                1),
            new SessionTransitionEvidence(
                42,
                SimplySignSessionState.WaitToken,
                3,
                Utc(12),
                1),
        };
        var heartbeat = Heartbeat(transitions: transitions);
        await using var stream = new MemoryStream();

        await LengthPrefixedJsonProtocol.WriteAsync(stream, heartbeat, default);
        stream.Position = 0;
        var actual = Assert.IsType<AgentHeartbeat>(
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, default));
        var json = JsonSerializer.Serialize(actual.SessionTransitions);

        Assert.Equal(transitions, actual.SessionTransitions);
        Assert.DoesNotContain("reasonCode", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("tokenSerial", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("certificateId", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("privateKeyId", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("otp", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Heartbeat_round_trips_exact_256_maximum_summaries_without_truncation()
    {
        var summaries = MaximumCertificateSummaries();
        var heartbeat = Heartbeat(certificates: summaries);
        await using var stream = new MemoryStream();

        await LengthPrefixedJsonProtocol.WriteAsync(stream, heartbeat, default);
        var payloadLength = checked((int)stream.Length - sizeof(int));
        Assert.InRange(payloadLength, 64 * 1024 + 1, 512 * 1024);
        Assert.True(payloadLength <= LengthPrefixedJsonProtocol.MaximumPayloadLength);
        stream.Position = 0;

        var actual = Assert.IsType<AgentHeartbeat>(
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, default));
        Assert.Equal(256, actual.Certificates.Count);
        Assert.Equal(summaries, actual.Certificates);
    }

    [Fact]
    public void Heartbeat_rejects_unordered_or_unbounded_transition_evidence()
    {
        var unordered = new[]
        {
            new SessionTransitionEvidence(2, SimplySignSessionState.Ready, 3, Utc(12), 1),
            new SessionTransitionEvidence(1, SimplySignSessionState.WaitToken, 3, Utc(11), 1),
        };

        Assert.Throws<ProtocolException>(() => Heartbeat(transitions: unordered));
        Assert.Throws<ProtocolException>(() => Heartbeat(
            transitions: Enumerable.Range(1, SessionTransitionEvidence.MaximumRetained + 1)
                .Select(index => new SessionTransitionEvidence(
                    index,
                    SimplySignSessionState.Checking,
                    3,
                    Utc(20).AddTicks(index),
                    0))
                .ToArray()));
    }

    [Fact]
    public async Task Heartbeat_rejects_alias_snapshot_from_another_generation()
    {
        var error = Assert.Throws<ProtocolException>(() => Heartbeat(pdfGeneration: 2));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public void Strict_generation_heartbeat_requires_capability_snapshots()
    {
        var error = Assert.Throws<ProtocolException>(() => new AgentHeartbeat(
            7, "checking", "unknown", "unknown", "unknown", null, null, null, null, 3));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public async Task Legacy_v2_heartbeat_is_rejected_by_protocol_version()
    {
        const string json = "{\"version\":2,\"type\":\"agent_heartbeat\",\"payload\":{" +
            "\"sessionId\":7,\"simplySignStatus\":\"ready\",\"tokenStatus\":\"ready\"," +
            "\"certificateStatus\":\"ready\",\"keyStatus\":\"ready\",\"currentJobId\":null}}";

        var error = await Assert.ThrowsAsync<ProtocolException>(() => ReadRawAsync(json));

        Assert.Equal("unsupported_protocol_version", error.Code);
    }

    [Fact]
    public async Task V3_heartbeat_without_generation_and_sessions_is_rejected()
    {
        const string json = "{\"version\":3,\"type\":\"agent_heartbeat\",\"payload\":{" +
            "\"sessionId\":7,\"simplySignStatus\":\"ready\",\"tokenStatus\":\"ready\"," +
            "\"certificateStatus\":\"ready\",\"keyStatus\":\"ready\",\"currentJobId\":null}}";

        var error = await Assert.ThrowsAsync<ProtocolException>(() => ReadRawAsync(json));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public async Task V3_round_trips_hello_and_full_heartbeat()
    {
        Assert.Equal(3, LengthPrefixedJsonProtocol.ProtocolVersion);
        AgentMessage[] messages =
        [
            new AgentHello(3, 321, 7, "S-1-5-21-1000", "1.2.3", ["authenticode", "pdf"]),
            Heartbeat(),
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

    [Fact]
    public async Task Agent_hello_round_trips_the_full_product_identity()
    {
        var hello = new AgentHello(
            3,
            321,
            7,
            "S-1-5-21-1000",
            "0.2.0-0.dev.17+build.7",
            ["authenticode", "pdf"]);
        await using var stream = new MemoryStream();

        await LengthPrefixedJsonProtocol.WriteAsync(stream, hello, default);
        stream.Position = 0;
        var actual = Assert.IsType<AgentHello>(
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, default));

        Assert.Equal("0.2.0-0.dev.17+build.7", actual.AgentVersion);
    }

    [Theory]
    [InlineData("1.0")]
    [InlineData("01.0.0")]
    [InlineData("1.0.0-alpha.01")]
    [InlineData("1.0.0+build..7")]
    public async Task Agent_hello_rejects_non_semver_product_identity(string identity)
    {
        var hello = new AgentHello(
            3,
            321,
            7,
            "S-1-5-21-1000",
            identity,
            ["authenticode", "pdf"]);
        await using var stream = new MemoryStream();

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.WriteAsync(stream, hello, default));

        Assert.Equal("invalid_message", error.Code);
        Assert.Equal(0, stream.Length);
    }

    [Fact]
    public async Task Startup_preparation_messages_have_exact_stable_json_contracts()
    {
        var requestId = Guid.Parse("12345678-1234-1234-1234-123456789abc");

        Assert.Equal(
            "{\"version\":3,\"type\":\"prepare_simplysign_session_command\",\"payload\":{" +
            "\"requestId\":\"12345678-1234-1234-1234-123456789abc\"}}",
            await SerializeAsync(new PrepareSimplySignSessionCommand(requestId)));
        Assert.Equal(
            "{\"version\":3,\"type\":\"prepare_simplysign_session_result\",\"payload\":{" +
            "\"requestId\":\"12345678-1234-1234-1234-123456789abc\",\"state\":\"READY\",\"errorCode\":null}}",
            await SerializeAsync(new PrepareSimplySignSessionResult(
                requestId,
                SimplySignSessionState.Ready,
                null)));
        Assert.Equal(
            "{\"version\":3,\"type\":\"prepare_simplysign_session_result\",\"payload\":{" +
            "\"requestId\":\"12345678-1234-1234-1234-123456789abc\",\"state\":\"FAILED\",\"errorCode\":\"simplysign_login_failed\"}}",
            await SerializeAsync(new PrepareSimplySignSessionResult(
                requestId,
                SimplySignSessionState.Failed,
                "simplysign_login_failed")));
    }

    [Theory]
    [InlineData("{\"version\":3,\"type\":\"prepare_simplysign_session_command\",\"payload\":{\"requestId\":\"12345678-1234-1234-1234-123456789abc\",\"requestId\":\"12345678-1234-1234-1234-123456789abc\"}}")]
    [InlineData("{\"version\":3,\"type\":\"prepare_simplysign_session_command\",\"payload\":{\"requestId\":\"12345678-1234-1234-1234-123456789abc\",\"unexpected\":true}}")]
    [InlineData("{\"version\":3,\"type\":\"prepare_simplysign_session_result\",\"payload\":{\"requestId\":\"12345678-1234-1234-1234-123456789abc\",\"state\":\"FAILED\",\"errorCode\":\"simplysign_login_failed\",\"errorCode\":\"simplysign_login_failed\"}}")]
    [InlineData("{\"version\":3,\"type\":\"prepare_simplysign_session_result\",\"payload\":{\"requestId\":\"12345678-1234-1234-1234-123456789abc\",\"state\":\"FAILED\",\"errorCode\":\"simplysign_login_failed\",\"unexpected\":true}}")]
    public async Task Startup_preparation_messages_reject_duplicate_or_unknown_fields(string json)
    {
        var error = await Assert.ThrowsAsync<ProtocolException>(() => ReadRawAsync(json));

        Assert.Equal("invalid_message", error.Code);
    }

    [Theory]
    [InlineData("00000000-0000-0000-0000-000000000000", "READY", null)]
    [InlineData("12345678-1234-1234-1234-123456789abc", "READY", "simplysign_login_failed")]
    [InlineData("12345678-1234-1234-1234-123456789abc", "FAILED", null)]
    [InlineData("12345678-1234-1234-1234-123456789abc", "FAILED", "unbounded_internal_detail")]
    public async Task Startup_preparation_result_rejects_invalid_identity_or_state_error_pair(
        string requestId,
        string state,
        string? errorCode)
    {
        var errorJson = errorCode is null ? "null" : $"\"{errorCode}\"";
        var json = $"{{\"version\":3,\"type\":\"prepare_simplysign_session_result\",\"payload\":{{" +
            $"\"requestId\":\"{requestId}\",\"state\":\"{state}\",\"errorCode\":{errorJson}}}}}";

        var error = await Assert.ThrowsAsync<ProtocolException>(() => ReadRawAsync(json));

        Assert.Equal("invalid_message", error.Code);
    }

    [Theory]
    [MemberData(nameof(ConflictingCapabilities))]
    public void Heartbeat_constructor_rejects_outer_and_session_conflict(CapabilitySnapshot conflict)
    {
        var error = Assert.Throws<ProtocolException>(() => new AgentHeartbeat(
            7,
            "failed",
            "failed",
            "failed",
            "failed",
            null,
            null,
            conflict,
            NotConfiguredCapability(),
            3));

        Assert.Equal("invalid_message", error.Code);
    }

    [Theory]
    [MemberData(nameof(ConflictingCapabilities))]
    public void Management_constructor_rejects_outer_and_session_conflict(CapabilitySnapshot conflict)
    {
        var error = Assert.Throws<ProtocolException>(() => ManagementSnapshotWith(conflict));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public async Task Raw_heartbeat_rejects_outer_and_session_state_conflict()
    {
        var json = await SerializeAsync(Heartbeat());
        var malformed = ReplaceAfter(json, "\"session\":{", "\"state\":\"READY\"", "\"state\":\"FAILED\"");
        malformed = ReplaceAfter(malformed, "\"session\":{", "\"ready\":true", "\"ready\":false");
        malformed = ReplaceAfter(malformed, "\"session\":{", "\"reasonCode\":\"ready\"", "\"reasonCode\":\"probe_failed\"");

        var error = await Assert.ThrowsAsync<ProtocolException>(() => ReadRawAsync(malformed));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public async Task Raw_management_snapshot_rejects_outer_and_session_state_conflict()
    {
        var response = new ManagementSnapshotResponse(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            ManagementSnapshotWith(ReadyCapability(ReadySnapshot(3))),
            null,
            null);
        var json = await SerializeAsync(response);
        var malformed = ReplaceAfter(json, "\"session\":{", "\"state\":\"READY\"", "\"state\":\"FAILED\"");
        malformed = ReplaceAfter(malformed, "\"session\":{", "\"ready\":true", "\"ready\":false");
        malformed = ReplaceAfter(malformed, "\"session\":{", "\"reasonCode\":\"ready\"", "\"reasonCode\":\"probe_failed\"");

        var error = await Assert.ThrowsAsync<ProtocolException>(() => ReadRawAsync(malformed));

        Assert.Equal("invalid_message", error.Code);
    }

    [Theory]
    [InlineData("ready")]
    [InlineData("PARTIAL")]
    public async Task Heartbeat_rejects_case_variant_or_unknown_session_state(string state)
    {
        var json = await SerializeAsync(Heartbeat());
        var malformed = json.Replace("\"state\":\"READY\"", $"\"state\":\"{state}\"", StringComparison.Ordinal);

        var error = await Assert.ThrowsAsync<ProtocolException>(() => ReadRawAsync(malformed));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public async Task Heartbeat_rejects_duplicate_nested_snapshot_fields()
    {
        var json = await SerializeAsync(Heartbeat());
        var malformed = json.Replace(
            "\"sessionGeneration\":3,\"probedAtUtc\"",
            "\"sessionGeneration\":3,\"sessionGeneration\":3,\"probedAtUtc\"",
            StringComparison.Ordinal);

        var error = await Assert.ThrowsAsync<ProtocolException>(() => ReadRawAsync(malformed));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public async Task Heartbeat_rejects_snapshot_with_missing_state()
    {
        var json = await SerializeAsync(Heartbeat());
        var malformed = json.Replace("\"state\":\"READY\",", string.Empty, StringComparison.Ordinal);

        var error = await Assert.ThrowsAsync<ProtocolException>(() => ReadRawAsync(malformed));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public async Task Session_wire_contract_contains_no_secret_or_full_object_identifier_fields()
    {
        var json = await SerializeAsync(Heartbeat());

        Assert.DoesNotContain("otp", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("totp", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("apiToken", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("modulePath", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("tokenSerial", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("certificateId", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("privateKeyId", json, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [MemberData(nameof(CompatibleReasonCases))]
    public async Task Every_session_reason_has_one_controlled_outer_capability_representation(
        SimplySignSessionState state,
        string outerReason,
        string sessionReason)
    {
        var ready = state == SimplySignSessionState.Ready;
        var session = SessionSnapshot(
            state,
            ready,
            ready,
            ready,
            ready,
            ready,
            ready,
            ready,
            sessionReason);
        var capability = Capability(
            ready,
            ready,
            ready,
            ready,
            ready,
            ready,
            ready,
            outerReason,
            session);
        var heartbeat = new AgentHeartbeat(
            7,
            ready ? "ready" : "not_ready",
            ready ? "ready" : "not_ready",
            ready ? "ready" : "not_ready",
            ready ? "ready" : "not_ready",
            null,
            7,
            capability,
            NotConfiguredCapability(),
            3);
        await using var stream = new MemoryStream();

        await LengthPrefixedJsonProtocol.WriteAsync(stream, heartbeat, default);
        stream.Position = 0;
        var actual = Assert.IsType<AgentHeartbeat>(
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, default));

        Assert.Equal(sessionReason, actual.Authenticode!.Session!.ReasonCode);
        Assert.Equal(outerReason, actual.Authenticode.ReasonCode);
    }

    public static TheoryData<SimplySignSessionState, string, string> CompatibleReasonCases() => new()
    {
        { SimplySignSessionState.Unknown, "unknown", "unknown" },
        { SimplySignSessionState.Checking, "checking", "checking" },
        { SimplySignSessionState.Ready, "ready", "ready" },
        { SimplySignSessionState.LoginRequired, "login_required", "login_required" },
        { SimplySignSessionState.Loginning, "loginning", "loginning" },
        { SimplySignSessionState.WaitToken, "wait_token", "wait_token" },
        { SimplySignSessionState.Failed, "failed", "failed" },
        { SimplySignSessionState.Unknown, "invalidated", "invalidated" },
        { SimplySignSessionState.Failed, "session_missing", "session_missing" },
        { SimplySignSessionState.Failed, "session_mismatch", "session_mismatch" },
        { SimplySignSessionState.WaitToken, "token_missing", "token_missing" },
        { SimplySignSessionState.Failed, "token_identifier_mismatch", "token_mismatch" },
        { SimplySignSessionState.Failed, "certificate_missing", "certificate_missing" },
        { SimplySignSessionState.Failed, "certificate_identifier_mismatch", "certificate_mismatch" },
        { SimplySignSessionState.Failed, "private_key_missing", "private_key_missing" },
        { SimplySignSessionState.Failed, "private_key_identifier_mismatch", "private_key_mismatch" },
        { SimplySignSessionState.Failed, "probe_failed", "probe_failed" },
        { SimplySignSessionState.Failed, "login_failed", "login_failed" },
        { SimplySignSessionState.Failed, "retry_scheduled", "retry_scheduled" },
    };

    public static TheoryData<CapabilitySnapshot> ConflictingCapabilities()
    {
        var data = new TheoryData<CapabilitySnapshot>
        {
            Capability(
                true, true, true, true, true, true, true, "ready",
                SessionSnapshot(SimplySignSessionState.Failed, true, true, true, true, true, true, false, "probe_failed")),
            Capability(
                true, false, false, false, false, false, false, "probe_failed",
                SessionSnapshot(SimplySignSessionState.Failed, false, false, false, false, false, false, false, "probe_failed")),
            Capability(
                true, true, false, false, false, false, false, "probe_failed",
                SessionSnapshot(SimplySignSessionState.Failed, true, false, false, false, false, false, false, "probe_failed")),
            Capability(
                false, false, true, false, false, false, false, "probe_failed",
                SessionSnapshot(SimplySignSessionState.Failed, false, false, false, false, false, false, false, "probe_failed")),
            Capability(
                false, false, true, true, false, false, false, "probe_failed",
                SessionSnapshot(SimplySignSessionState.Failed, false, false, true, false, false, false, false, "probe_failed")),
            Capability(
                false, false, false, false, true, false, false, "probe_failed",
                SessionSnapshot(SimplySignSessionState.Failed, false, false, false, false, false, false, false, "probe_failed")),
            Capability(
                false, false, false, false, true, true, false, "probe_failed",
                SessionSnapshot(SimplySignSessionState.Failed, false, false, false, false, true, false, false, "probe_failed")),
            Capability(
                false, false, false, false, false, false, false, "token_missing",
                SessionSnapshot(SimplySignSessionState.Failed, false, false, false, false, false, false, false, "probe_failed")),
        };

        return data;
    }

    private static AgentHeartbeat Heartbeat(
        long pdfGeneration = 3,
        IReadOnlyList<SessionTransitionEvidence>? transitions = null,
        IReadOnlyList<CertificateSummary>? certificates = null) =>
        new(
            7,
            "ready",
            "ready",
            "ready",
            "ready",
            null,
            7,
            ReadyCapability(ReadySnapshot(3)),
            ReadyCapability(ReadySnapshot(pdfGeneration)),
            3,
            transitions,
            certificates);

    private static IReadOnlyList<CertificateSummary> MaximumCertificateSummaries() =>
        Enumerable.Range(0, 256)
            .Select(_ => new CertificateSummary(
                new string('\u4E00', 256),
                new string('F', 128),
                DateTimeOffset.Parse("1900-01-01T00:00:00Z"),
                DateTimeOffset.Parse("2200-01-01T00:00:00Z"),
                false,
                false,
                true,
                "certificate_serial_ambiguous"))
            .ToArray();

    private static SimplySignSessionSnapshot ReadySnapshot(long generation) =>
        new(
            SimplySignSessionState.Ready,
            generation,
            Utc(10),
            Utc(9),
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

    private static SimplySignSessionSnapshot SessionSnapshot(
        SimplySignSessionState state,
        bool tokenPresent,
        bool tokenMatches,
        bool certificatePresent,
        bool certificateMatches,
        bool privateKeyPresent,
        bool privateKeyMatches,
        bool ready,
        string reasonCode) =>
        new(
            state,
            3,
            Utc(10),
            Utc(9),
            7,
            tokenPresent,
            tokenMatches,
            certificatePresent,
            certificateMatches,
            privateKeyPresent,
            privateKeyMatches,
            ready,
            reasonCode,
            0,
            null);

    private static CapabilitySnapshot Capability(
        bool tokenPresent,
        bool tokenMatches,
        bool certificatePresent,
        bool certificateMatches,
        bool privateKeyPresent,
        bool privateKeyMatches,
        bool ready,
        string reasonCode,
        SimplySignSessionSnapshot session) =>
        new(
            true,
            tokenPresent,
            tokenMatches,
            tokenPresent ? "34567890" : null,
            certificatePresent,
            certificateMatches,
            certificatePresent ? "abcdef12" : null,
            privateKeyPresent,
            privateKeyMatches,
            privateKeyPresent ? "1234abcd" : null,
            ready,
            reasonCode,
            certificatePresent ? DateTimeOffset.Parse("2027-08-09T00:00:00Z") : null,
            certificatePresent ? "89ABCDEF" : null,
            session);

    private static CapabilitySnapshot ReadyCapability(SimplySignSessionSnapshot session) =>
        new(
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

    private static CapabilitySnapshot NotConfiguredCapability() => CapabilitySnapshot.NotConfigured();

    private static ManagementSnapshot ManagementSnapshotWith(CapabilitySnapshot authenticode) =>
        new(
            ManagementSnapshot.CurrentVersion,
            Utc(12),
            Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            true,
            true,
            7,
            7,
            1_000,
            true,
            7,
            authenticode,
            NotConfiguredCapability(),
            0,
            0,
            null,
            [],
            3);

    private static DateTimeOffset Utc(int minute) =>
        new(2026, 8, 9, 0, minute, 0, TimeSpan.Zero);

    private static async Task<string> SerializeAsync(AgentMessage message)
    {
        await using var stream = new MemoryStream();
        await LengthPrefixedJsonProtocol.WriteAsync(stream, message, default);
        return Encoding.UTF8.GetString(stream.ToArray().AsSpan(sizeof(int)));
    }

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

    private static string ReplaceAfter(string value, string marker, string oldValue, string newValue)
    {
        var markerIndex = value.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(markerIndex >= 0, $"Marker not found: {marker}");
        var valueIndex = value.IndexOf(oldValue, markerIndex + marker.Length, StringComparison.Ordinal);
        Assert.True(valueIndex >= 0, $"Value not found after marker: {oldValue}");
        return string.Concat(value.AsSpan(0, valueIndex), newValue, value.AsSpan(valueIndex + oldValue.Length));
    }
}
