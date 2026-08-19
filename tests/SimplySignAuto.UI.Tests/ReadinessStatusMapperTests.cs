using SimplySignAuto.App.UI.Status;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.UI.Tests;

public sealed class ReadinessStatusMapperTests
{
    [Fact]
    public void Overview_authenticode_is_ready_when_any_certificate_is_usable()
    {
        var status = ReadinessStatusMapper.Map(Snapshot(
            Ready(),
            Ready(),
            certificates:
            [
                Summary("PDF", "52A1B4C9", false, true),
                Summary("Code", "6F09D233", true, false),
            ]));

        Assert.True(status.AuthenticodeReady);
        Assert.True(status.PdfReady);
    }

    [Fact]
    public void Overview_pdf_is_ready_when_any_certificate_is_usable()
    {
        var status = ReadinessStatusMapper.Map(Snapshot(
            Ready(),
            Ready(),
            certificates:
            [
                Summary("Stale", "52A1B4C9", true, true, current: false),
                Summary("Code", "6F09D233", true, false),
            ]));

        Assert.True(status.AuthenticodeReady);
        Assert.False(status.PdfReady);
    }
    [Fact]
    public void Legacy_token_state_cannot_override_current_usable_summaries()
    {
        var status = ReadinessStatusMapper.Map(Snapshot(
            NotReady("token_missing"),
            CapabilitySnapshot.NotConfigured(),
            processRunning: true));

        Assert.Equal(OverallReadiness.Ready, status.Overall);
        Assert.Empty(status.Reasons);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Exactly_one_usable_certificate_kind_is_partial(bool codeReady, bool pdfReady)
    {
        var status = ReadinessStatusMapper.Map(Snapshot(
            Ready(),
            Ready(),
            certificates:
            [
                Summary("Selected Kind", "52A1B4C9", codeReady, pdfReady),
            ]));

        Assert.Equal(OverallReadiness.Partial, status.Overall);
    }

    [Fact]
    public void Both_ready_capabilities_are_ready()
    {
        var status = ReadinessStatusMapper.Map(Snapshot(Ready(), Ready()));

        Assert.Equal(OverallReadiness.Ready, status.Overall);
        Assert.Empty(status.Reasons);
    }

    [Fact]
    public void Missing_pdf_extension_keeps_the_authenticode_only_product_ready()
    {
        var status = ReadinessStatusMapper.Map(Snapshot(
            Ready(),
            PdfToolFailure("pdf_support_not_installed")));

        Assert.Equal(OverallReadiness.Ready, status.Overall);
        Assert.True(status.AuthenticodeReady);
        Assert.False(status.PdfReady);
        Assert.Empty(status.Reasons);
    }

    [Fact]
    public void Tampered_pdf_extension_remains_a_visible_partial_failure()
    {
        var status = ReadinessStatusMapper.Map(Snapshot(
            Ready(),
            PdfToolFailure("pdf_helper_tampered")));

        Assert.Equal(OverallReadiness.Partial, status.Overall);
        Assert.True(status.AuthenticodeReady);
        Assert.False(status.PdfReady);
        Assert.Equal(["pdf_helper_tampered"], status.Reasons);
    }

    [Theory]
    [InlineData(15_000, 7, 7, OverallReadiness.Ready)]
    [InlineData(15_001, 7, 7, OverallReadiness.ActionRequired)]
    [InlineData(-1, 7, 7, OverallReadiness.ActionRequired)]
    [InlineData(1_000, 0, 0, OverallReadiness.ActionRequired)]
    [InlineData(1_000, 7, 8, OverallReadiness.ActionRequired)]
    public void Heartbeat_boundary_negative_and_session_identity_are_fail_closed(
        long ageMilliseconds,
        int agentSession,
        int heartbeatSession,
        OverallReadiness expected)
    {
        var status = ReadinessStatusMapper.Map(Snapshot(
            Ready(),
            Ready(),
            heartbeatAgeMilliseconds: ageMilliseconds,
            agentSessionId: agentSession,
            heartbeatSessionId: heartbeatSession));

        Assert.Equal(expected, status.Overall);
    }

    [Fact]
    public void Missing_usable_certificates_are_allowlisted_deduplicated_and_deterministically_ordered()
    {
        var status = ReadinessStatusMapper.Map(Snapshot(
            NotReady("token_missing"),
            NotReady("token_missing"),
            processRunning: false,
            processSessionId: null,
            certificates: []));

        Assert.Equal(["process_missing"], status.Reasons);
    }

    [Fact]
    public void Missing_process_cannot_leave_cached_capabilities_or_overall_status_ready()
    {
        var status = ReadinessStatusMapper.Map(Snapshot(
            Ready(),
            Ready(),
            processRunning: false,
            processSessionId: null));

        Assert.Equal(OverallReadiness.ActionRequired, status.Overall);
        Assert.False(status.AuthenticodeReady);
        Assert.False(status.PdfReady);
        Assert.Equal(["process_missing"], status.Reasons);
    }

    [Theory]
    [InlineData(SimplySignSessionState.Unknown, "unknown", "未知")]
    [InlineData(SimplySignSessionState.Checking, "checking", "检查中")]
    [InlineData(SimplySignSessionState.Ready, "ready", "已就绪")]
    [InlineData(SimplySignSessionState.LoginRequired, "login_required", "需要登录")]
    [InlineData(SimplySignSessionState.Loginning, "loginning", "登录中")]
    [InlineData(SimplySignSessionState.WaitToken, "wait_token", "等待令牌")]
    [InlineData(SimplySignSessionState.Failed, "failed", "失败")]
    public void Capability_projection_uses_exact_seven_state_text(
        SimplySignSessionState state,
        string reason,
        string expected)
    {
        var capability = Capability(state, reason);

        Assert.Equal(expected, ReadinessStatusMapper.CapabilityStateText(1, capability));
    }

    [Fact]
    public void Both_alias_projections_reject_snapshots_from_another_generation()
    {
        foreach (var alias in new[] { "authenticode", "pdf" })
        {
            var capability = ProtocolV3TestFixtures.Ready(alias);
            Assert.Equal("未知", ReadinessStatusMapper.CapabilityStateText(2, capability));
            Assert.False(ReadinessStatusMapper.HasCurrentSession(2, capability));
            Assert.False(ReadinessStatusMapper.IsCurrentReady(2, capability));
        }
    }

    [Fact]
    public void Missing_heartbeat_age_is_explicitly_action_required()
    {
        var status = ReadinessStatusMapper.Map(new ManagementSnapshot(
            ManagementSnapshot.CurrentVersion,
            new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero),
            Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            true,
            true,
            7,
            7,
            null,
            true,
            7,
            Ready(),
            Ready(),
            0,
            0,
            null,
            [],
            1));

        Assert.Equal(OverallReadiness.ActionRequired, status.Overall);
        Assert.Contains("heartbeat_missing", status.Reasons);
    }

    private static ManagementSnapshot Snapshot(
        CapabilitySnapshot authenticode,
        CapabilitySnapshot pdf,
        bool processRunning = true,
        int? processSessionId = 7,
        long heartbeatAgeMilliseconds = 1_000,
        int agentSessionId = 7,
        int heartbeatSessionId = 7,
        IReadOnlyList<CertificateSummary>? certificates = null) =>
        new(
            ManagementSnapshot.CurrentVersion,
            new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero),
            Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            true,
            true,
            agentSessionId,
            heartbeatSessionId,
            heartbeatAgeMilliseconds,
            processRunning,
            processSessionId,
            authenticode,
            pdf,
            0,
            0,
            null,
            [],
            1,
            certificates ??
            [
                Summary("Universal", "52A1B4C9", true, true),
            ]);

    private static CertificateSummary Summary(
        string commonName,
        string serial,
        bool authenticode,
        bool pdf,
        bool current = true) =>
        new(
            commonName,
            serial,
            DateTimeOffset.Parse("2025-01-01T00:00:00Z"),
            DateTimeOffset.Parse("2027-01-01T00:00:00Z"),
            current && authenticode,
            current && pdf,
            current,
            current ? authenticode || pdf ? null : "unsupported_purpose" : "catalog_stale");

    private static CapabilitySnapshot Ready() =>
        ProtocolV3TestFixtures.Ready();

    private static CapabilitySnapshot NotReady(string reason) =>
        reason == "token_missing"
            ? ProtocolV3TestFixtures.TokenMissing()
            : throw new ArgumentOutOfRangeException(nameof(reason));

    private static CapabilitySnapshot PdfToolFailure(string reasonCode)
    {
        var ready = Ready();
        return new CapabilitySnapshot(
            ready.Configured,
            ready.TokenPresent,
            ready.TokenMatches,
            ready.TokenSuffix,
            ready.CertificatePresent,
            ready.CertificateMatches,
            ready.CertificateSuffix,
            ready.PrivateKeyPresent,
            ready.PrivateKeyMatches,
            ready.PrivateKeySuffix,
            ready: false,
            reasonCode,
            ready.CertificateNotAfterUtc,
            ready.CertificateThumbprintSuffix,
            ready.Session);
    }

    private static CapabilitySnapshot Capability(SimplySignSessionState state, string reason)
    {
        if (state == SimplySignSessionState.Ready)
        {
            return Ready();
        }

        var now = new DateTimeOffset(2026, 8, 9, 0, 0, 0, TimeSpan.Zero);
        var session = new SimplySignSessionSnapshot(
            state,
            1,
            now,
            now,
            null,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            reason,
            0,
            null);
        return new CapabilitySnapshot(
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
            reason,
            session: session);
    }
}
