using System.Buffers.Binary;
using System.Text;
using SimplySignAuto.Protocol;
using Xunit;

namespace SimplySignAuto.Protocol.Tests;

public sealed class LocalJobMessagesTests
{
    private static readonly Guid RequestId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid JobId = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly DateTimeOffset ExpiresAt =
        new(2026, 8, 8, 1, 10, 0, TimeSpan.Zero);
    private const string Lease = "00112233445566778899aabbccddeeff";
    private const string Hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Fact]
    public async Task Strict_round_trip_preserves_every_local_job_contract()
    {
        AgentMessage[] expected =
        [
            new LocalJobCreateRequest(RequestId, "release.exe", ".exe", 4096,
                "{\"appendSignature\":false,\"certificateSerialNumber\":\"52A1B4C9\",\"digestAlgorithm\":\"sha256\",\"kind\":\"authenticode\"}"),
            new LocalJobUploadLease(RequestId, JobId, Lease,
                "22222222222222222222222222222222/input.exe.part", ExpiresAt),
            new LocalJobUploadCompleted(RequestId, JobId, Lease, 4096, Hash),
            new LocalJobAccepted(RequestId, JobId),
            new LocalJobRejected(RequestId, "local_upload_hash_mismatch",
                Guid.Parse("33333333-3333-3333-3333-333333333333")),
            new LocalJobResultRequest(RequestId, JobId),
            new LocalJobResultMetadata(RequestId, JobId, ".exe", 8192, Hash),
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

    [Theory]
    [MemberData(nameof(InvalidMessages))]
    public async Task Invalid_local_semantics_fail_before_a_frame_is_written(AgentMessage message)
    {
        await using var stream = new MemoryStream();

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.WriteAsync(stream, message, CancellationToken.None));

        Assert.Equal("invalid_message", error.Code);
        Assert.Equal(0, stream.Length);
    }

    [Fact]
    public async Task Create_request_never_accepts_a_path_as_original_name()
    {
        string[] invalidNames = ["C:\\\\secret\\release.exe", "../release.exe", "folder/release.exe", "release.exe\n"];
        foreach (var originalName in invalidNames)
        {
            await using var stream = new MemoryStream();
            var request = new LocalJobCreateRequest(
                RequestId,
                originalName,
                ".exe",
                12,
                "{\"kind\":\"authenticode\"}");

            var error = await Assert.ThrowsAsync<ProtocolException>(() =>
                LengthPrefixedJsonProtocol.WriteAsync(stream, request, CancellationToken.None));

            Assert.Equal("invalid_message", error.Code);
        }
    }

    [Theory]
    [InlineData("00112233445566778899AABBCCDDEEFF")]
    [InlineData("00112233")]
    [InlineData("00112233445566778899aabbccddeefg")]
    public async Task Lease_is_exactly_128_bits_in_lowercase_hex(string lease)
    {
        await using var stream = new MemoryStream();

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.WriteAsync(
                stream,
                new LocalJobUploadCompleted(RequestId, JobId, lease, 12, Hash),
                CancellationToken.None));

        Assert.Equal("invalid_message", error.Code);
    }

    [Theory]
    [InlineData("local_job_unavailable")]
    [InlineData("internal_error")]
    [InlineData("unknown_future_error")]
    public void Ambiguous_or_unknown_local_rejections_are_transient(string errorCode)
    {
        var rejected = new LocalJobRejected(RequestId, errorCode, Guid.NewGuid());

        Assert.Equal(LocalJobRejectionDisposition.Transient, rejected.GetDisposition());
    }

    [Theory]
    [InlineData("local_request_conflict")]
    [InlineData("local_upload_expired")]
    [InlineData("local_upload_identity_mismatch")]
    [InlineData("local_upload_size_mismatch")]
    [InlineData("local_upload_hash_mismatch")]
    [InlineData("local_upload_invalid_path")]
    [InlineData("local_upload_missing")]
    [InlineData("local_upload_cleanup_failed")]
    [InlineData("invalid_parameters")]
    [InlineData("unsupported_type")]
    [InlineData("file_signature_mismatch")]
    [InlineData("file_too_large")]
    public void Proven_terminal_local_rejections_are_definitive(string errorCode)
    {
        var rejected = new LocalJobRejected(RequestId, errorCode, Guid.NewGuid());

        Assert.Equal(LocalJobRejectionDisposition.Definitive, rejected.GetDisposition());
    }

    [Theory]
    [InlineData("22222222222222222222222222222222/input.EXE.part")]
    [InlineData("22222222-2222-2222-2222-222222222222/input.exe.part")]
    [InlineData("../22222222222222222222222222222222/input.exe.part")]
    [InlineData("22222222222222222222222222222222/result.exe.part")]
    public async Task Lease_path_has_one_service_derived_canonical_shape(string relativePath)
    {
        await using var stream = new MemoryStream();

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.WriteAsync(
                stream,
                new LocalJobUploadLease(RequestId, JobId, Lease, relativePath, ExpiresAt),
                CancellationToken.None));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public async Task Case_variant_and_duplicate_fields_are_rejected_recursively()
    {
        const string json = "{\"version\":3,\"type\":\"local_job_upload_completed\",\"payload\":{" +
            "\"requestId\":\"11111111-1111-1111-1111-111111111111\"," +
            "\"RequestId\":\"11111111-1111-1111-1111-111111111111\"," +
            "\"jobId\":\"22222222-2222-2222-2222-222222222222\"," +
            "\"leaseId\":\"00112233445566778899aabbccddeeff\"," +
            "\"actualSize\":12,\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}";
        await using var stream = JsonFrame(json);

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(stream, CancellationToken.None));

        Assert.Equal("invalid_message", error.Code);
    }

    public static TheoryData<AgentMessage> InvalidMessages() => new()
    {
        new LocalJobCreateRequest(Guid.Empty, "release.exe", ".exe", 1, "{}"),
        new LocalJobCreateRequest(RequestId, "release.exe", ".EXE", 1, "{}"),
        new LocalJobCreateRequest(RequestId, "release.exe", ".exe", 0, "{}"),
        new LocalJobCreateRequest(RequestId, new string('a', 252) + ".exe", ".exe", 1, "{}"),
        new LocalJobUploadLease(RequestId, Guid.Empty, Lease,
            "22222222222222222222222222222222/input.exe.part", ExpiresAt),
        new LocalJobUploadLease(RequestId, JobId, Lease,
            "22222222222222222222222222222222/input.exe.part", ExpiresAt.ToOffset(TimeSpan.FromHours(8))),
        new LocalJobUploadCompleted(RequestId, JobId, Lease, -1, Hash),
        new LocalJobUploadCompleted(RequestId, JobId, Lease, 1, Hash.ToUpperInvariant()),
        new LocalJobAccepted(Guid.Empty, JobId),
        new LocalJobRejected(RequestId, "made_up", Guid.NewGuid()),
        new LocalJobResultRequest(RequestId, Guid.Empty),
        new LocalJobResultMetadata(RequestId, JobId, ".txt", 1, Hash),
    };

    private static MemoryStream JsonFrame(string json)
    {
        var payload = Encoding.UTF8.GetBytes(json);
        var bytes = new byte[4 + payload.Length];
        BinaryPrimitives.WriteInt32BigEndian(bytes, payload.Length);
        payload.CopyTo(bytes, 4);
        return new MemoryStream(bytes);
    }
}
