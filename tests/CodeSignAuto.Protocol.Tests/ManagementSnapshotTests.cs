using System.Buffers.Binary;
using System.Text;
using CodeSignAuto.Protocol;
using Xunit;

namespace CodeSignAuto.Protocol.Tests;

public sealed class ManagementSnapshotTests
{
    [Fact]
    public async Task Management_snapshot_transfers_every_public_certificate_summary()
    {
        var summaries = new[]
        {
            new CertificateSummary(
                "Code Signing",
                "52A1B4C9",
                DateTimeOffset.Parse("2026-01-01T00:00:00Z"),
                DateTimeOffset.Parse("2027-01-01T00:00:00Z"),
                true,
                false,
                true,
                null),
            new CertificateSummary(
                "Expired Document Signing",
                "6F09D233",
                DateTimeOffset.Parse("2024-01-01T00:00:00Z"),
                DateTimeOffset.Parse("2025-01-01T00:00:00Z"),
                false,
                false,
                true,
                "expired"),
        };
        var snapshot = CreateSnapshot(certificates: summaries);
        await using var stream = new MemoryStream();

        await LengthPrefixedJsonProtocol.WriteAsync(
            stream,
            new ManagementSnapshotResponse(Guid.NewGuid(), snapshot, null, null),
            default);
        stream.Position = 0;

        var response = Assert.IsType<ManagementSnapshotResponse>(
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, default));
        Assert.Equal(summaries, response.Snapshot!.Certificates);
    }

    [Fact]
    public async Task Management_response_round_trips_exact_256_maximum_summaries_without_truncation()
    {
        var summaries = MaximumCertificateSummaries();
        var response = new ManagementSnapshotResponse(
            Guid.NewGuid(),
            CreateSnapshot(certificates: summaries),
            null,
            null);
        await using var stream = new MemoryStream();

        await LengthPrefixedJsonProtocol.WriteAsync(stream, response, default);
        var payloadLength = checked((int)stream.Length - sizeof(int));
        Assert.InRange(payloadLength, 64 * 1024 + 1, 512 * 1024);
        Assert.True(payloadLength <= LengthPrefixedJsonProtocol.MaximumPayloadLength);
        stream.Position = 0;

        var actual = Assert.IsType<ManagementSnapshotResponse>(
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, default));
        Assert.Equal(256, actual.Snapshot!.Certificates.Count);
        Assert.Equal(summaries, actual.Snapshot.Certificates);
    }

    [Theory]
    [InlineData("modulePath", "C:/SimplySign/pkcs11.dll")]
    [InlineData("slotId", "7")]
    [InlineData("tokenSerial", "TOKEN-123")]
    [InlineData("certificateIdHex", "AA11")]
    [InlineData("privateKeyIdHex", "BB22")]
    [InlineData("certificateDerBase64", "AQID")]
    [InlineData("sha1Thumbprint", "00112233445566778899AABBCCDDEEFF00112233")]
    public async Task Management_summary_rejects_internal_catalog_fields(string property, string jsonValue)
    {
        var response = new ManagementSnapshotResponse(Guid.NewGuid(), CreateSnapshot(), null, null);
        var json = await SerializeAsync(response);
        var marker = "\"commonName\":\"Code Signing\"";
        var malformed = json.Replace(
            marker,
            $"{marker},\"{property}\":{(property == "slotId" ? jsonValue : $"\"{jsonValue}\"")}",
            StringComparison.Ordinal);

        var error = await Assert.ThrowsAsync<ProtocolException>(() => ReadRawAsync(malformed));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public async Task Snapshot_request_and_response_round_trip_through_the_strict_v2_contract()
    {
        var requestId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var snapshot = CreateSnapshot();
        await using var stream = new MemoryStream();

        await LengthPrefixedJsonProtocol.WriteAsync(stream, new ManagementSnapshotRequest(requestId), default);
        await LengthPrefixedJsonProtocol.WriteAsync(
            stream,
            new ManagementSnapshotResponse(requestId, snapshot, null, null),
            default);
        stream.Position = 0;

        Assert.Equal(
            new ManagementSnapshotRequest(requestId),
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, default));
        var response = Assert.IsType<ManagementSnapshotResponse>(
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, default));
        Assert.Equal(requestId, response.RequestId);
        Assert.Equal(snapshot, response.Snapshot);
        Assert.Null(response.ErrorCode);
        Assert.Null(response.CorrelationId);
    }

    [Fact]
    public async Task Empty_request_id_is_rejected_before_a_frame_is_written()
    {
        await using var stream = new MemoryStream();

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.WriteAsync(
                stream,
                new ManagementSnapshotRequest(Guid.Empty),
                default));

        Assert.Equal("invalid_message", error.Code);
        Assert.Equal(0, stream.Length);
    }

    [Theory]
    [InlineData("management_snapshot_request", "requestId", "requestID")]
    [InlineData("management_snapshot_request", "requestId", "RequestId")]
    public async Task Case_variant_or_duplicate_request_fields_are_rejected(
        string type,
        string firstName,
        string secondName)
    {
        var id = "11111111-1111-1111-1111-111111111111";
        var json = $"{{\"version\":3,\"type\":\"{type}\",\"payload\":{{\"{firstName}\":\"{id}\",\"{secondName}\":\"{id}\"}}}}";

        var error = await Assert.ThrowsAsync<ProtocolException>(() => ReadRawAsync(json));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public void Identifier_suffix_rejects_path_secret_and_unsafe_shapes()
    {
        string[] invalidValues =
        [
            "C:/secrets/token.txt",
            "otpauth://totp/Certum?secret=AAAAAAAAAAAAAAAA",
            "too-long-suffix",
            "bad suffix",
        ];

        foreach (var value in invalidValues)
        {
            Assert.Throws<ArgumentException>(() => new CapabilitySnapshot(
                true,
                true,
                true,
                value,
                true,
                true,
                "abc12345",
                true,
                true,
                "def67890",
                true,
                "ready",
                DateTimeOffset.Parse("2027-08-09T00:00:00Z"),
                "89ABCDEF"));
        }
    }

    [Theory]
    [InlineData("89abcdef")]
    [InlineData("89ABCDE")]
    [InlineData("89ABCDEF0")]
    [InlineData("89ABCDE-")]
    public void Certificate_thumbprint_suffix_requires_exact_uppercase_sha256_shape(string suffix)
    {
        Assert.Throws<ArgumentException>(() => new CapabilitySnapshot(
            true,
            true,
            true,
            "3456",
            true,
            true,
            "ABCDEF12",
            true,
            true,
            "12345678",
            true,
            "ready",
            DateTimeOffset.Parse("2027-08-09T00:00:00Z"),
            suffix));
    }

    [Fact]
    public void Certificate_present_requires_complete_strict_metadata()
    {
        CapabilitySnapshot Create(DateTimeOffset? notAfter, string? thumbprint) => new(
            true,
            true,
            true,
            "3456",
            true,
            true,
            "ABCDEF12",
            true,
            true,
            "12345678",
            true,
            "ready",
            notAfter,
            thumbprint);

        Assert.Throws<ArgumentException>(() => Create(null, null));
        Assert.Throws<ArgumentException>(() =>
            Create(DateTimeOffset.Parse("2027-08-09T00:00:00Z"), null));
        Assert.Throws<ArgumentException>(() => Create(null, "89ABCDEF"));
    }

    [Fact]
    public void Global_session_capability_omits_single_certificate_metadata_as_a_complete_pair()
    {
        CapabilitySnapshot Create(DateTimeOffset? notAfter, string? thumbprint) => new(
            true,
            true,
            true,
            tokenSuffix: null,
            true,
            true,
            certificateSuffix: null,
            true,
            true,
            privateKeySuffix: null,
            true,
            "ready",
            notAfter,
            thumbprint,
            ReadySession("global"));

        _ = Create(null, null);
        Assert.Throws<ArgumentException>(() =>
            Create(DateTimeOffset.Parse("2027-08-09T00:00:00Z"), null));
        Assert.Throws<ArgumentException>(() => Create(null, "89ABCDEF"));
    }

    [Fact]
    public void Snapshot_rejects_more_than_five_recent_jobs()
    {
        var recent = Enumerable.Range(0, 6)
            .Select(index => new RecentJobSnapshot(
                Guid.Parse($"00000000-0000-0000-0000-{index + 1:000000000000}"),
                "pdf",
                "succeeded",
                new DateTimeOffset(2026, 8, 8, 0, index, 0, TimeSpan.Zero),
                null))
            .ToArray();

        Assert.Throws<ArgumentException>(() => CreateSnapshot(recent));
    }

    [Fact]
    public void Snapshot_accepts_pdf_appearance_font_missing_as_a_terminal_error()
    {
        var recent = new[]
        {
            new RecentJobSnapshot(
                Guid.Parse("00000000-0000-0000-0000-000000000001"),
                "pdf",
                "failed",
                new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero),
                "pdf_appearance_font_missing"),
        };

        Assert.Equal("pdf_appearance_font_missing", Assert.Single(CreateSnapshot(recent).RecentJobs).ErrorCode);
    }

    [Fact]
    public void Unconfigured_capability_cannot_claim_token_certificate_key_or_readiness()
    {
        Assert.Throws<ArgumentException>(() => new CapabilitySnapshot(
            false,
            true,
            false,
            null,
            false,
            false,
            null,
            false,
            false,
            null,
            false,
            "not_configured"));
    }

    [Fact]
    public async Task Error_response_requires_allowlisted_code_and_nonempty_correlation()
    {
        var requestId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        await using var stream = new MemoryStream();

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.WriteAsync(
                stream,
                new ManagementSnapshotResponse(
                    requestId,
                    null,
                    "C:/database/jobs.db",
                    Guid.Parse("22222222-2222-2222-2222-222222222222")),
                default));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public async Task Raw_semantically_invalid_heartbeat_is_normalized_to_invalid_message()
    {
        var heartbeat = new AgentHeartbeat(
            7,
            "ready",
            "ready",
            "ready",
            "ready",
            null,
            7,
            ReadyCapability("34567890", "abcdef12", "1234abcd", ReadySession("authenticode-primary")),
            ReadyCapability("34567890", "abcdef12", "1234abcd", ReadySession("pdf-primary")),
            3);
        var json = await SerializeAsync(heartbeat);
        var malformed = json.Replace(
            "\"configured\":true",
            "\"configured\":false",
            StringComparison.Ordinal);

        var error = await Assert.ThrowsAsync<ProtocolException>(() => ReadRawAsync(malformed));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public async Task Raw_semantically_invalid_management_response_is_normalized_to_invalid_message()
    {
        var response = new ManagementSnapshotResponse(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            CreateSnapshot(),
            null,
            null);
        var json = await SerializeAsync(response);
        var malformed = json.Replace(
            "\"reasonCode\":\"ready\"",
            "\"reasonCode\":\"C:/raw/error\"",
            StringComparison.Ordinal);

        var error = await Assert.ThrowsAsync<ProtocolException>(() => ReadRawAsync(malformed));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public void Central_suffix_policy_returns_only_the_last_eight_safe_characters()
    {
        Assert.Equal("34567890", IdentifierSuffixPolicy.Create("TOKEN-1234567890"));
        Assert.Equal("00ab", IdentifierSuffixPolicy.Create("00ab"));
        Assert.Null(IdentifierSuffixPolicy.Create("unsafe/value"));
    }

    private static ManagementSnapshot CreateSnapshot(
        IReadOnlyList<RecentJobSnapshot>? recent = null,
        IReadOnlyList<CertificateSummary>? certificates = null) =>
        new(
            ManagementSnapshot.CurrentVersion,
            new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero),
            Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            true,
            true,
            7,
            7,
            2_000,
            true,
            7,
            ReadyCapability("34567890", "abcdef12", "1234abcd", ReadySession("codesign")),
            CapabilitySnapshot.NotConfigured(),
            2,
            1,
            new CurrentJobSnapshot(
                Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
                "authenticode",
                "signing",
                "signing",
                new DateTimeOffset(2026, 8, 7, 23, 59, 50, TimeSpan.Zero),
                10),
            recent ??
            [
                new RecentJobSnapshot(
                    Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc"),
                    "pdf",
                    "failed",
                    new DateTimeOffset(2026, 8, 7, 23, 59, 0, TimeSpan.Zero),
                    "pdf_sign_failed"),
            ],
            3,
            certificates ??
            [
                new CertificateSummary(
                    "Code Signing",
                    "52A1B4C9",
                    DateTimeOffset.Parse("2026-01-01T00:00:00Z"),
                    DateTimeOffset.Parse("2027-01-01T00:00:00Z"),
                    true,
                    false,
                    true,
                    null),
            ]);

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

    private static CapabilitySnapshot ReadyCapability(
        string tokenSuffix,
        string certificateSuffix,
        string privateKeySuffix,
        SimplySignSessionSnapshot? session = null) =>
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
            session);

    private static SimplySignSessionSnapshot ReadySession(string alias) =>
        new(
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

    private static async Task<AgentMessage> ReadRawAsync(string json)
    {
        var payload = Encoding.UTF8.GetBytes(json);
        await using var stream = new MemoryStream();
        var header = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(header, payload.Length);
        await stream.WriteAsync(header);
        await stream.WriteAsync(payload);
        stream.Position = 0;
        return await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, default);
    }

    private static async Task<string> SerializeAsync(AgentMessage message)
    {
        await using var stream = new MemoryStream();
        await LengthPrefixedJsonProtocol.WriteAsync(stream, message, default);
        return Encoding.UTF8.GetString(stream.ToArray().AsSpan(sizeof(int)));
    }
}
