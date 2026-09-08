using CodeSignAuto.Protocol;
using Xunit;

namespace CodeSignAuto.Protocol.Tests;

public sealed class ManagementPagesTests
{
    [Fact]
    public async Task Job_page_roundtrip_exposes_only_the_safe_fixed_contract()
    {
        var requestId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var jobId = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var correlationId = Guid.Parse("33333333-3333-3333-3333-333333333333");
        var asOf = DateTimeOffset.Parse("2026-08-09T01:02:03Z");
        var created = DateTimeOffset.Parse("2026-08-09T01:01:00Z");
        var cursor = new JobPageCursor("terminal", created, jobId, asOf);
        var response = new JobPageResponse(
            requestId,
            [new JobPageItem(
                jobId,
                "local",
                "pdf",
                "succeeded",
                "contract.pdf",
                created,
                created.AddSeconds(2),
                created.AddSeconds(4),
                null,
                correlationId,
                true)],
            cursor,
            null,
            null);

        await using var stream = new MemoryStream();
        await LengthPrefixedJsonProtocol.WriteAsync(stream, response, CancellationToken.None);
        stream.Position = 0;
        var actual = await LengthPrefixedJsonProtocol.ReadAsync<JobPageResponse>(stream, CancellationToken.None);

        Assert.Equal(requestId, actual.RequestId);
        var item = Assert.Single(actual.Items);
        Assert.Equal(jobId, item.JobId);
        Assert.Equal("local", item.Source);
        Assert.Equal("contract.pdf", item.OriginalName);
        Assert.True(item.HasResult);
        Assert.Equal(cursor, actual.NextCursor);
        var wire = System.Text.Encoding.UTF8.GetString(stream.ToArray());
        Assert.DoesNotContain("parameters", wire, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("sha256", wire, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("path", wire, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("dispatch", wire, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("lease", wire, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Terminal_delta_roundtrip_has_a_typed_bounded_watermark_and_cursor()
    {
        var requestId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var watermark = new TerminalJobWatermark(40);
        var cursor = new TerminalJobCursor(50, 80);
        var request = new TerminalJobDeltaRequest(requestId, watermark, cursor);

        await using var stream = new MemoryStream();
        await LengthPrefixedJsonProtocol.WriteAsync(stream, request, CancellationToken.None);
        stream.Position = 0;
        var actual = await LengthPrefixedJsonProtocol.ReadAsync<TerminalJobDeltaRequest>(stream, CancellationToken.None);

        Assert.Equal(requestId, actual.RequestId);
        Assert.Equal(watermark, actual.Watermark);
        Assert.Equal(cursor, actual.Cursor);
    }

    [Fact]
    public void Terminal_cursor_rejects_negative_or_cursor_after_snapshot_sequence()
    {
        Assert.Throws<ArgumentException>(() => new TerminalJobWatermark(-1));
        Assert.Throws<ArgumentException>(() => new TerminalJobCursor(0, -1));
        Assert.Throws<ArgumentException>(() => new TerminalJobCursor(2, 1));
    }

    [Theory]
    [InlineData("Terminal")]
    [InlineData("ACTIVE")]
    [InlineData("queued")]
    public void Cursor_bucket_is_case_sensitive_and_allowlisted(string bucket)
    {
        Assert.Throws<ArgumentException>(() => new JobPageCursor(
            bucket,
            DateTimeOffset.UtcNow,
            Guid.NewGuid(),
            DateTimeOffset.UtcNow));
    }

    [Fact]
    public async Task ServiceSettings_summary_roundtrip_does_not_expose_protected_configuration()
    {
        var summary = new ServiceSettingsSummary(
            7080,
            512L * 1024 * 1024,
            24,
            "1.0.0+build.7");
        var response = new ServiceSettingsResponse(Guid.NewGuid(), summary, null, null);
        await using var stream = new MemoryStream();

        await LengthPrefixedJsonProtocol.WriteAsync(stream, response, CancellationToken.None);
        var wire = System.Text.Encoding.UTF8.GetString(stream.ToArray());

        Assert.DoesNotContain("tokenHash", wire, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("signingUserSid", wire, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("dataRoot", wire, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ownerMarker", wire, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("installInstanceId", wire, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("certificateAliases", wire, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("timestampAliases", wire, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("path", wire, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("\"productVersion\":\"1.0.0\"", wire, StringComparison.Ordinal);
        Assert.DoesNotContain("serviceVersion", wire, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("agentVersion", wire, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("appVersion", wire, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ServiceSettings_summary_roundtrips_the_http_listener_contract()
    {
        var summary = new ServiceSettingsSummary(
            7080,
            ServiceSettingsSummary.FixedMaximumUploadBytes,
            24,
            "1.0.0-0.dev.17+build.7");
        var response = new ServiceSettingsResponse(Guid.NewGuid(), summary, null, null);
        await using var stream = new MemoryStream();

        await LengthPrefixedJsonProtocol.WriteAsync(stream, response, default);
        stream.Position = 0;
        var roundtrip = await LengthPrefixedJsonProtocol.ReadAsync<ServiceSettingsResponse>(stream, default);

        Assert.Equal(7080, roundtrip.Summary!.ListenPort);
        Assert.Equal(24, roundtrip.Summary.RetentionHours);
        Assert.Equal(ServiceSettingsSummary.FixedMaximumUploadBytes, roundtrip.Summary.MaximumUploadBytes);
        Assert.Equal("1.0.0-0.dev.17", roundtrip.Summary.ProductVersion);
    }

    [Theory]
    [InlineData("")]
    [InlineData("1.0")]
    [InlineData("01.0.0")]
    [InlineData("1.0.0-alpha.01")]
    [InlineData("1.0.0+build..7")]
    public void ServiceSettings_summary_rejects_non_semver_product_identity(string identity)
    {
        Assert.Throws<ArgumentException>(() => new ServiceSettingsSummary(
            7080,
            ServiceSettingsSummary.FixedMaximumUploadBytes,
            24,
            identity));
    }
}
