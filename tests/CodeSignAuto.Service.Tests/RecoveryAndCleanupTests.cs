using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Collections.Concurrent;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Protocol;
using CodeSignAuto.Service.Api;
using CodeSignAuto.Service.Ipc;
using CodeSignAuto.Service.Jobs;
using Xunit;

namespace CodeSignAuto.Service.Tests;

public sealed class RecoveryAndCleanupTests
{
    private const string Token = "health-test-token";

    [Fact]
    public async Task Liveness_executes_real_sqlite_select_and_readiness_fails_closed_without_agent()
    {
        await using var fixture = await HealthFixture.StartAsync();

        using var live = await fixture.Client.GetAsync("/health/live");
        using var unauthenticatedReady = await fixture.Client.GetAsync("/v1/health/ready");
        fixture.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        using var ready = await fixture.Client.GetAsync("/v1/health/ready");
        var body = await ready.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, live.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticatedReady.StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.StatusCode);
        Assert.DoesNotContain("sid", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("serial", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("path", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Database_failure_returns_503_for_both_liveness_and_authenticated_readiness()
    {
        await using var fixture = await TestServiceFactory.StartAsync(services =>
            services.AddSingleton<IJobStore>(new ThrowingGetJobStore()));
        using var authenticated = fixture.CreateAuthenticatedClient();

        using var live = await fixture.Client.GetAsync("/health/live");
        using var ready = await authenticated.GetAsync("/v1/health/ready");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, live.StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.StatusCode);
    }

    [Fact]
    public async Task Readiness_returns_structured_queue_and_capability_status_for_fresh_current_heartbeat()
    {
        var now = DateTimeOffset.UtcNow;
        var source = new StaticAgentHealthStatusSource(new AgentHealthSnapshot(
            Guid.NewGuid(),
            7,
            ["authenticode", "pdf"],
            now.AddSeconds(-2),
            ProtocolV3TestFixtures.Heartbeat(certificates: [UsableCertificate(true, true)])));
        await using var fixture = await HealthFixture.StartAsync(source, new FixedTimeProvider(now));
        var jobs = fixture.Services.GetRequiredService<IJobStore>();
        await jobs.CreateAsync(CreateJob());
        fixture.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        using var response = await fixture.Client.GetAsync("/v1/health/ready");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = json.RootElement;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("ready", root.GetProperty("service").GetString());
        Assert.True(root.GetProperty("agent").GetProperty("connected").GetBoolean());
        Assert.Equal(7, root.GetProperty("agent").GetProperty("sessionId").GetInt32());
        Assert.Equal(2, root.GetProperty("agent").GetProperty("heartbeatAgeSeconds").GetInt32());
        Assert.True(root.GetProperty("capabilities").GetProperty("authenticode").GetProperty("ready").GetBoolean());
        Assert.True(root.GetProperty("capabilities").GetProperty("pdf").GetProperty("ready").GetBoolean());
        Assert.Equal(1, root.GetProperty("queue").GetProperty("queued").GetInt32());
        Assert.Equal(0, root.GetProperty("queue").GetProperty("active").GetInt32());
        var body = root.GetRawText();
        Assert.DoesNotContain("tokenSerial", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("certificateId", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("privateKeyId", body, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("pdf_support_not_installed", HttpStatusCode.OK)]
    [InlineData("pdf_helper_tampered", HttpStatusCode.ServiceUnavailable)]
    public async Task Readiness_treats_only_a_missing_pdf_extension_as_optional(
        string pdfFailureCode,
        HttpStatusCode expectedStatus)
    {
        var now = DateTimeOffset.UtcNow;
        var source = new StaticAgentHealthStatusSource(new AgentHealthSnapshot(
            Guid.NewGuid(),
            7,
            ["authenticode", "pdf"],
            now,
            HeartbeatWithPdfToolFailure(pdfFailureCode, [UsableCertificate(true, true)])));
        await using var fixture = await HealthFixture.StartAsync(source, new FixedTimeProvider(now));
        fixture.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        using var response = await fixture.Client.GetAsync("/v1/health/ready");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.Equal(expectedStatus, response.StatusCode);
        Assert.True(json.RootElement
            .GetProperty("capabilities")
            .GetProperty("authenticode")
            .GetProperty("ready")
            .GetBoolean());
        Assert.False(json.RootElement
            .GetProperty("capabilities")
            .GetProperty("pdf")
            .GetProperty("ready")
            .GetBoolean());
    }

    [Fact]
    public async Task Readiness_exposes_only_redacted_bounded_session_transition_evidence()
    {
        var now = DateTimeOffset.UtcNow;
        var heartbeat = ProtocolV3TestFixtures.Heartbeat(
            sessionGeneration: 2,
            transitions:
            [
                new SessionTransitionEvidence(
                    9,
                    SimplySignSessionState.Loginning,
                    2,
                    now.AddSeconds(-2),
                    1),
                new SessionTransitionEvidence(
                    10,
                    SimplySignSessionState.Ready,
                    2,
                    now.AddSeconds(-1),
                    1),
            ]);
        var source = new StaticAgentHealthStatusSource(new AgentHealthSnapshot(
            Guid.NewGuid(),
            7,
            ["authenticode", "pdf"],
            now,
            heartbeat));
        await using var fixture = await HealthFixture.StartAsync(source, new FixedTimeProvider(now));
        fixture.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        using var response = await fixture.Client.GetAsync("/v1/health/ready");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var session = json.RootElement.GetProperty("session");
        var transitions = session.GetProperty("transitions");
        var body = session.GetRawText();

        Assert.Equal(2, session.GetProperty("generation").GetInt64());
        Assert.Equal(2, transitions.GetArrayLength());
        Assert.Equal("LOGINNING", transitions[0].GetProperty("state").GetString());
        Assert.DoesNotContain("reason", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("tokenSerial", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("certificateId", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("privateKeyId", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("otp", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Readiness_accepts_heartbeat_at_the_inclusive_fifteen_second_boundary()
    {
        var now = DateTimeOffset.UtcNow;
        var source = new StaticAgentHealthStatusSource(new AgentHealthSnapshot(
            Guid.NewGuid(),
            7,
            ["pdf"],
            now.AddSeconds(-15),
            ProtocolV3TestFixtures.Heartbeat(
                authenticodeConfigured: false,
                certificates: [UsableCertificate(false, true)])));
        await using var fixture = await HealthFixture.StartAsync(source, new FixedTimeProvider(now));
        fixture.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        using var response = await fixture.Client.GetAsync("/v1/health/ready");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Readiness_reports_every_field_false_for_an_unconfigured_capability()
    {
        var now = DateTimeOffset.UtcNow;
        var source = new StaticAgentHealthStatusSource(new AgentHealthSnapshot(
            Guid.NewGuid(),
            7,
            ["authenticode"],
            now,
            ProtocolV3TestFixtures.Heartbeat(
                pdfConfigured: false,
                certificates: [UsableCertificate(true, false)])));
        await using var fixture = await HealthFixture.StartAsync(source, new FixedTimeProvider(now));
        fixture.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        using var response = await fixture.Client.GetAsync("/v1/health/ready");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var pdf = json.RootElement.GetProperty("capabilities").GetProperty("pdf");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(pdf.GetProperty("ready").GetBoolean());
        Assert.False(pdf.GetProperty("certificate").GetBoolean());
        Assert.False(pdf.GetProperty("privateKey").GetBoolean());
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task Readiness_requires_a_current_usable_certificate_only_for_each_configured_capability(
        bool authenticodeConfigured,
        bool pdfConfigured)
    {
        var now = DateTimeOffset.UtcNow;
        var certificates = authenticodeConfigured
            ? new[] { UsableCertificate(true, false) }
            : new[] { UsableCertificate(false, true) };
        var capabilities = authenticodeConfigured ? new[] { "authenticode" } : new[] { "pdf" };
        var source = new StaticAgentHealthStatusSource(new AgentHealthSnapshot(
            Guid.NewGuid(),
            7,
            capabilities,
            now,
            ProtocolV3TestFixtures.Heartbeat(
                authenticodeConfigured: authenticodeConfigured,
                pdfConfigured: pdfConfigured,
                certificates: certificates)));
        await using var fixture = await HealthFixture.StartAsync(source, new FixedTimeProvider(now));
        fixture.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        using var response = await fixture.Client.GetAsync("/v1/health/ready");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData("empty_catalog")]
    [InlineData("stale_catalog")]
    [InlineData("process_missing")]
    [InlineData("token_missing")]
    public async Task Readiness_fails_closed_without_current_catalog_process_and_token_readiness(string mutation)
    {
        var now = DateTimeOffset.UtcNow;
        var certificates = mutation switch
        {
            "empty_catalog" => Array.Empty<CertificateSummary>(),
            "stale_catalog" => new[] { StaleCertificate() },
            _ => new[] { UsableCertificate(true, false) },
        };
        var source = new StaticAgentHealthStatusSource(new AgentHealthSnapshot(
            Guid.NewGuid(),
            7,
            ["authenticode"],
            now,
            HeartbeatForReadinessMutation(mutation, certificates)));
        await using var fixture = await HealthFixture.StartAsync(source, new FixedTimeProvider(now));
        fixture.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        using var response = await fixture.Client.GetAsync("/v1/health/ready");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task Readiness_fails_closed_when_the_connected_agent_configures_no_capability()
    {
        var now = DateTimeOffset.UtcNow;
        var source = new StaticAgentHealthStatusSource(new AgentHealthSnapshot(
            Guid.NewGuid(),
            7,
            [],
            now,
            ProtocolV3TestFixtures.Heartbeat(authenticodeConfigured: false, pdfConfigured: false)));
        await using var fixture = await HealthFixture.StartAsync(source, new FixedTimeProvider(now));
        fixture.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        using var response = await fixture.Client.GetAsync("/v1/health/ready");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var capabilities = json.RootElement.GetProperty("capabilities");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        foreach (var name in new[] { "authenticode", "pdf" })
        {
            var capability = capabilities.GetProperty(name);
            Assert.False(capability.GetProperty("ready").GetBoolean());
            Assert.False(capability.GetProperty("certificate").GetBoolean());
            Assert.False(capability.GetProperty("privateKey").GetBoolean());
        }
    }

    [Theory]
    [InlineData("future-capability")]
    [InlineData("authenticode")]
    public async Task Readiness_fails_closed_for_unknown_or_duplicate_capability(string secondCapability)
    {
        var now = DateTimeOffset.UtcNow;
        var source = new StaticAgentHealthStatusSource(new AgentHealthSnapshot(
            Guid.NewGuid(),
            7,
            ["authenticode", secondCapability],
            now,
            ProtocolV3TestFixtures.Heartbeat(pdfConfigured: false)));
        await using var fixture = await HealthFixture.StartAsync(source, new FixedTimeProvider(now));
        fixture.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        using var response = await fixture.Client.GetAsync("/v1/health/ready");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task Readiness_fails_closed_for_a_stale_heartbeat()
    {
        var now = DateTimeOffset.UtcNow;
        var source = new StaticAgentHealthStatusSource(new AgentHealthSnapshot(
            Guid.NewGuid(),
            7,
            ["authenticode"],
            now.AddSeconds(-16),
            ProtocolV3TestFixtures.Heartbeat(pdfConfigured: false)));
        await using var fixture = await HealthFixture.StartAsync(source, new FixedTimeProvider(now));
        fixture.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        using var response = await fixture.Client.GetAsync("/v1/health/ready");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Theory]
    [InlineData("not_checked", "ready", "ready", "ready")]
    [InlineData("ready", "present", "ready", "ready")]
    [InlineData("ready", "ready", "valid", "ready")]
    [InlineData("ready", "ready", "ready", "available")]
    public async Task Legacy_process_and_object_strings_are_diagnostic_only_when_session_snapshot_is_ready(
        string simplySign,
        string token,
        string certificate,
        string key)
    {
        var now = DateTimeOffset.UtcNow;
        var source = new StaticAgentHealthStatusSource(new AgentHealthSnapshot(
            Guid.NewGuid(),
            7,
            ["authenticode"],
            now.AddSeconds(-1),
            ProtocolV3TestFixtures.Heartbeat(
                simplySignStatus: simplySign,
                tokenStatus: token,
                certificateStatus: certificate,
                keyStatus: key,
                pdfConfigured: false,
                certificates: [UsableCertificate(true, false)])));
        await using var fixture = await HealthFixture.StartAsync(source, new FixedTimeProvider(now));
        fixture.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        using var response = await fixture.Client.GetAsync("/v1/health/ready");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Ready_legacy_strings_cannot_override_a_non_ready_current_session_snapshot()
    {
        var now = DateTimeOffset.UtcNow;
        var sessionTime = new DateTimeOffset(2026, 8, 9, 0, 0, 0, TimeSpan.Zero);
        var session = new SimplySignSessionSnapshot(
            SimplySignSessionState.WaitToken,
            1,
            sessionTime,
            sessionTime,
            null,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            "wait_token",
            1,
            null);
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
            "wait_token",
            session: session);
        var heartbeat = new AgentHeartbeat(
            7,
            "ready",
            "ready",
            "ready",
            "ready",
            null,
            7,
            capability,
            CapabilitySnapshot.NotConfigured(),
            1);
        var source = new StaticAgentHealthStatusSource(new AgentHealthSnapshot(
            Guid.NewGuid(),
            7,
            ["authenticode"],
            now,
            heartbeat));
        await using var fixture = await HealthFixture.StartAsync(source, new FixedTimeProvider(now));
        fixture.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        using var response = await fixture.Client.GetAsync("/v1/health/ready");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    private static CertificateSummary UsableCertificate(bool authenticode, bool pdf) =>
        new(
            "Current certificate",
            "01",
            new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
            authenticode,
            pdf,
            true,
            null);

    private static AgentHeartbeat HeartbeatWithPdfToolFailure(
        string reasonCode,
        IReadOnlyList<CertificateSummary> certificates)
    {
        var authenticode = ProtocolV3TestFixtures.ReadyCapability("authenticode");
        var readyPdf = ProtocolV3TestFixtures.ReadyCapability("pdf");
        var pdf = new CapabilitySnapshot(
            readyPdf.Configured,
            readyPdf.TokenPresent,
            readyPdf.TokenMatches,
            readyPdf.TokenSuffix,
            readyPdf.CertificatePresent,
            readyPdf.CertificateMatches,
            readyPdf.CertificateSuffix,
            readyPdf.PrivateKeyPresent,
            readyPdf.PrivateKeyMatches,
            readyPdf.PrivateKeySuffix,
            ready: false,
            reasonCode,
            readyPdf.CertificateNotAfterUtc,
            readyPdf.CertificateThumbprintSuffix,
            readyPdf.Session);
        return new AgentHeartbeat(
            7,
            "ready",
            "ready",
            "ready",
            "ready",
            null,
            7,
            authenticode,
            pdf,
            1,
            certificates: certificates);
    }

    private static CertificateSummary StaleCertificate() =>
        new(
            "Stale certificate",
            "02",
            new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
            false,
            false,
            false,
            "catalog_stale");

    private static AgentHeartbeat HeartbeatForReadinessMutation(
        string mutation,
        IReadOnlyList<CertificateSummary> certificates)
    {
        if (mutation == "token_missing")
        {
            var observedAt = new DateTimeOffset(2026, 8, 9, 0, 0, 0, TimeSpan.Zero);
            var session = new SimplySignSessionSnapshot(
                SimplySignSessionState.WaitToken,
                1,
                observedAt,
                observedAt,
                7,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                "token_missing",
                1,
                null,
                true,
                7);
            var authenticode = new CapabilitySnapshot(
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
                "token_missing",
                session: session);
            return new AgentHeartbeat(
                7,
                "ready",
                "token_missing",
                "not_checked",
                "not_checked",
                null,
                7,
                authenticode,
                CapabilitySnapshot.NotConfigured(),
                1,
                certificates: certificates);
        }

        var ready = ProtocolV3TestFixtures.Heartbeat(
            pdfConfigured: false,
            certificates: certificates);
        return mutation == "process_missing"
            ? new AgentHeartbeat(
                ready.SessionId,
                ready.SimplySignStatus,
                ready.TokenStatus,
                ready.CertificateStatus,
                ready.KeyStatus,
                ready.CurrentJobId,
                null,
                ready.Authenticode,
                ready.Pdf,
                ready.SessionGeneration,
                ready.SessionTransitions,
                ready.Certificates)
            : ready;
    }

    [Fact]
    public async Task Download_reverifies_result_and_atomically_marks_tampered_success_failed()
    {
        await using var fixture = await HealthFixture.StartAsync();
        var jobs = Assert.IsType<SqliteJobStore>(fixture.Services.GetRequiredService<IJobStore>());
        var spool = Assert.IsType<SpoolStore>(fixture.Services.GetRequiredService<ISpoolStore>());
        var completed = await CreateSucceededJobAsync(jobs, spool, "%PDF-signed"u8.ToArray());
        await File.WriteAllBytesAsync(spool.GetResultPath(completed.Id, completed.Extension), "%PDF-tampered"u8.ToArray());
        fixture.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        using var response = await fixture.Client.GetAsync($"/v1/jobs/{completed.Id:D}/result");
        var problem = await response.Content.ReadFromJsonAsync<ApiProblem>();
        var reloaded = await jobs.GetAsync(completed.Id);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("result_corrupt", problem!.Code);
        Assert.Equal(JobState.Failed, reloaded!.State);
        Assert.Equal("result_corrupt", reloaded.ErrorCode);
    }

    [Fact]
    public async Task Verified_result_stream_keeps_the_verified_handle_when_path_is_replaced()
    {
        using var fixture = new FileFixture();
        var spool = new SpoolStore(fixture.SpoolPath);
        var jobId = Guid.NewGuid();
        var original = "%PDF-original"u8.ToArray();
        var hash = Convert.ToHexString(SHA256.HashData(original)).ToLowerInvariant();
        var resultPath = spool.GetResultPath(jobId, ".pdf");
        await File.WriteAllBytesAsync(resultPath, original);

        await using var verified = await spool.OpenVerifiedResultAsync(jobId, ".pdf", original.Length, hash);
        File.Move(resultPath, resultPath + ".old");
        await File.WriteAllBytesAsync(resultPath, "%PDF-replacement"u8.ToArray());
        using var read = new MemoryStream();
        await verified.CopyToAsync(read);

        Assert.Equal(original, read.ToArray());
    }

    [Fact]
    public async Task Corrupt_success_transition_requires_exact_original_result_metadata()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var spool = new SpoolStore(fixture.SpoolPath);
        var completed = await CreateSucceededJobAsync(jobs, spool, "%PDF-signed"u8.ToArray());

        Assert.False(await jobs.TryFailSucceededResultAsync(
            completed.Id,
            completed.ResultSize!.Value + 1,
            completed.ResultSha256!,
            "result_corrupt",
            "The signed result failed integrity verification."));
        Assert.Equal(JobState.Succeeded, (await jobs.GetAsync(completed.Id))!.State);
        Assert.True(await jobs.TryFailSucceededResultAsync(
            completed.Id,
            completed.ResultSize.Value,
            completed.ResultSha256!,
            "result_corrupt",
            "The signed result failed integrity verification."));
        Assert.Equal(JobState.Failed, (await jobs.GetAsync(completed.Id))!.State);
    }

    [Fact]
    public async Task Download_rejects_result_symlink_without_reading_or_changing_its_target()
    {
        await using var fixture = await HealthFixture.StartAsync();
        var jobs = Assert.IsType<SqliteJobStore>(fixture.Services.GetRequiredService<IJobStore>());
        var spool = Assert.IsType<SpoolStore>(fixture.Services.GetRequiredService<ISpoolStore>());
        var completed = await CreateSucceededJobAsync(jobs, spool, "%PDF-signed"u8.ToArray());
        var resultPath = spool.GetResultPath(completed.Id, completed.Extension);
        var targetPath = Path.Combine(Path.GetDirectoryName(spool.Root)!, "outside.pdf");
        await File.WriteAllBytesAsync(targetPath, "%PDF-outside"u8.ToArray());
        File.Delete(resultPath);
        File.CreateSymbolicLink(resultPath, targetPath);
        fixture.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        using var response = await fixture.Client.GetAsync($"/v1/jobs/{completed.Id:D}/result");

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("%PDF-outside"u8.ToArray(), await File.ReadAllBytesAsync(targetPath));
        Assert.Equal(JobState.Failed, (await jobs.GetAsync(completed.Id))!.State);
    }

    [Fact]
    public async Task Download_returns_result_corrupt_even_if_corrupt_state_cas_cannot_be_persisted()
    {
        var expected = "%PDF-expected"u8.ToArray();
        var job = TestJobs.Create(JobState.Succeeded) with
        {
            ResultSize = expected.Length,
            ResultSha256 = Convert.ToHexString(SHA256.HashData(expected)).ToLowerInvariant(),
        };
        await using var fixture = await TestServiceFactory.StartAsync(services =>
            services.AddSingleton<IJobStore>(new StaticJobStore(job)));
        var spool = Assert.IsType<SpoolStore>(fixture.Services.GetRequiredService<ISpoolStore>());
        await File.WriteAllBytesAsync(spool.GetResultPath(job.Id, job.Extension), "%PDF-tampered"u8.ToArray());
        using var client = fixture.CreateAuthenticatedClient();

        using var response = await client.GetAsync($"/v1/jobs/{job.Id:D}/result");
        var problem = await response.Content.ReadFromJsonAsync<ApiProblem>();

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("result_corrupt", problem!.Code);
    }

    [Fact]
    public async Task Cancelled_verification_preserves_result_and_succeeded_database_state()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var spool = new SpoolStore(fixture.SpoolPath);
        var completed = await CreateSucceededJobAsync(jobs, spool, "%PDF-signed"u8.ToArray());
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => spool.OpenVerifiedResultAsync(
            completed.Id,
            completed.Extension,
            completed.ResultSize!.Value,
            completed.ResultSha256!,
            cancellation.Token));

        Assert.True(File.Exists(spool.GetResultPath(completed.Id, completed.Extension)));
        Assert.Equal(JobState.Succeeded, (await jobs.GetAsync(completed.Id))!.State);
    }

    [Fact]
    public async Task Startup_recovery_validates_success_cleans_stale_parts_and_quarantines_orphans_idempotently()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var spool = new SpoolStore(fixture.SpoolPath);
        var notifier = new JobCompletionNotifier(jobs);
        var valid = await CreateSucceededJobAsync(jobs, spool, "%PDF-valid"u8.ToArray());
        var corrupt = await CreateSucceededJobAsync(jobs, spool, "%PDF-corrupt-original"u8.ToArray());
        await File.WriteAllBytesAsync(spool.GetInputPath(valid.Id, valid.Extension), "%PDF-input"u8.ToArray());
        await File.WriteAllBytesAsync(spool.GetResultPath(corrupt.Id, corrupt.Extension), "%PDF-tampered"u8.ToArray());
        var queued = await jobs.CreateAsync(CreateJob());
        var stalePart = spool.GetInputPath(queued.Id, queued.Extension) + ".part";
        await File.WriteAllBytesAsync(stalePart, "partial"u8.ToArray());
        File.SetLastWriteTimeUtc(stalePart, DateTime.UtcNow.AddHours(-2));
        var orphanId = Guid.NewGuid();
        var orphanPath = Path.Combine(spool.Root, orphanId.ToString("N"));
        Directory.CreateDirectory(orphanPath);
        await File.WriteAllTextAsync(Path.Combine(orphanPath, "orphan.txt"), "preserve");
        Directory.SetLastWriteTimeUtc(orphanPath, DateTime.UtcNow.AddHours(-2));
        var quarantine = Path.Combine(Path.GetDirectoryName(spool.Root)!, "quarantine");
        var collision = Path.Combine(quarantine, orphanId.ToString("N"));
        Directory.CreateDirectory(collision);
        await File.WriteAllTextAsync(Path.Combine(collision, "existing.txt"), "keep");
        var service = new JobCleanupService(jobs, spool, notifier, TimeProvider.System, NullLogger<JobCleanupService>.Instance);

        await service.RecoverStartupAsync(CancellationToken.None);
        await service.RunMaintenanceBatchAsync(CancellationToken.None);
        await service.RecoverStartupAsync(CancellationToken.None);
        await service.RunMaintenanceBatchAsync(CancellationToken.None);
        var corruptNotification = await notifier.WaitAsync(corrupt.Id, CancellationToken.None);

        Assert.Equal(JobState.Failed, corruptNotification.State);
        Assert.Equal("result_corrupt", corruptNotification.ErrorCode);
        Assert.False(File.Exists(spool.GetInputPath(valid.Id, valid.Extension)));
        Assert.True(File.Exists(spool.GetResultPath(valid.Id, valid.Extension)));
        Assert.False(File.Exists(stalePart));
        Assert.False(Directory.Exists(orphanPath));
        Assert.Equal("keep", await File.ReadAllTextAsync(Path.Combine(collision, "existing.txt")));
        Assert.Contains(
            Directory.GetDirectories(quarantine),
            path => !string.Equals(path, collision, StringComparison.Ordinal) && File.Exists(Path.Combine(path, "orphan.txt")));
        Assert.Equal(JobState.Failed, (await jobs.GetAsync(corrupt.Id))!.State);
    }

    [Fact]
    public async Task Startup_recovery_rejects_reparse_job_directory_without_following_it()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var spool = new SpoolStore(fixture.SpoolPath);
        Directory.CreateDirectory(spool.Root);
        var outside = Path.Combine(Path.GetDirectoryName(spool.Root)!, "outside");
        Directory.CreateDirectory(outside);
        await File.WriteAllTextAsync(Path.Combine(outside, "sentinel.txt"), "keep");
        Directory.CreateSymbolicLink(Path.Combine(spool.Root, Guid.NewGuid().ToString("N")), outside);
        var service = new JobCleanupService(
            jobs,
            spool,
            new JobCompletionNotifier(jobs),
            TimeProvider.System,
            NullLogger<JobCleanupService>.Instance);

        var error = await Assert.ThrowsAsync<SpoolException>(() => service.RecoverStartupAsync(CancellationToken.None));

        Assert.Equal("invalid_spool_path", error.Code);
        Assert.Equal("keep", await File.ReadAllTextAsync(Path.Combine(outside, "sentinel.txt")));
    }

    [Fact]
    public async Task Startup_and_hourly_cleanup_include_expired_local_upload_leases()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var localUploads = new RecordingLocalUploadCleanup();
        var service = new JobCleanupService(
            jobs,
            new SpoolStore(fixture.SpoolPath),
            new JobCompletionNotifier(jobs),
            TimeProvider.System,
            NullLogger<JobCleanupService>.Instance,
            localUploads);

        await service.RecoverStartupAsync(default);
        var expired = await service.CleanupExpiredAsync(default);

        Assert.Equal(2, localUploads.Calls);
        Assert.Equal(1, expired);
    }

    [Fact]
    public async Task Startup_recovery_requeues_signing_without_incrementing_attempt_and_is_idempotent()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var spool = new SpoolStore(fixture.SpoolPath);
        var created = await jobs.CreateAsync(CreateJob());
        var claimed = await jobs.ClaimNextAsync(Guid.NewGuid());
        Assert.Equal(created.Id, claimed!.Id);
        var service = new JobCleanupService(
            jobs,
            spool,
            new JobCompletionNotifier(jobs),
            TimeProvider.System,
            NullLogger<JobCleanupService>.Instance);

        await service.RecoverStartupAsync(CancellationToken.None);
        await service.RunMaintenanceBatchAsync(CancellationToken.None);
        await service.RecoverStartupAsync(CancellationToken.None);
        await service.RunMaintenanceBatchAsync(CancellationToken.None);
        var recovered = await jobs.GetAsync(created.Id);

        Assert.Equal(JobState.Queued, recovered!.State);
        Assert.Equal(1, recovered.AttemptCount);
    }

    [Fact]
    public async Task Startup_recovery_keeps_stale_part_for_active_pending_completion()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var spool = new SpoolStore(fixture.SpoolPath);
        var created = await jobs.CreateAsync(CreateJob());
        var connectionId = Guid.NewGuid();
        var claimed = await jobs.ClaimNextAsync(connectionId);
        Assert.True(await jobs.TryMarkVerifyingAsync(created.Id, claimed!.DispatchId!.Value, connectionId));
        var hash = Convert.ToHexString(SHA256.HashData("result"u8)).ToLowerInvariant();
        Assert.True(await jobs.TryRecordCompletionAsync(created.Id, claimed.DispatchId.Value, connectionId, 6, hash));
        var stalePart = Path.Combine(Path.GetDirectoryName(spool.GetInputPath(created.Id, created.Extension))!, "work.tmp.part");
        await File.WriteAllBytesAsync(stalePart, "partial"u8.ToArray());
        File.SetLastWriteTimeUtc(stalePart, DateTime.UtcNow.AddHours(-2));
        var service = new JobCleanupService(
            jobs,
            spool,
            new JobCompletionNotifier(jobs),
            TimeProvider.System,
            NullLogger<JobCleanupService>.Instance);

        await service.RecoverStartupAsync(CancellationToken.None);
        await service.RunMaintenanceBatchAsync(CancellationToken.None);

        Assert.True(File.Exists(stalePart));
        Assert.Equal(JobState.Verifying, (await jobs.GetAsync(created.Id))!.State);
    }

    [Fact]
    public async Task Startup_recovery_deletes_non_active_part_at_inclusive_one_hour_boundary()
    {
        using var fixture = new FileFixture();
        var now = DateTimeOffset.UtcNow;
        var jobs = fixture.CreateStore();
        var spool = new SpoolStore(fixture.SpoolPath);
        var created = await jobs.CreateAsync(CreateJob());
        var part = spool.GetInputPath(created.Id, created.Extension) + ".part";
        await File.WriteAllBytesAsync(part, "partial"u8.ToArray());
        File.SetLastWriteTimeUtc(part, now.UtcDateTime.AddHours(-1));
        var service = new JobCleanupService(
            jobs,
            spool,
            new JobCompletionNotifier(jobs),
            new FixedTimeProvider(now),
            NullLogger<JobCleanupService>.Instance);

        await service.RecoverStartupAsync(CancellationToken.None);
        await service.RunMaintenanceBatchAsync(CancellationToken.None);

        Assert.False(File.Exists(part));
    }

    [Fact]
    public async Task Startup_recovery_rejects_reparse_spool_root_without_following_it()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var outside = Path.Combine(Path.GetDirectoryName(fixture.SpoolPath)!, "outside-root");
        Directory.CreateDirectory(outside);
        await File.WriteAllTextAsync(Path.Combine(outside, "sentinel.txt"), "keep");
        Directory.CreateSymbolicLink(fixture.SpoolPath, outside);
        var service = new JobCleanupService(
            jobs,
            new SpoolStore(fixture.SpoolPath),
            new JobCompletionNotifier(jobs),
            TimeProvider.System,
            NullLogger<JobCleanupService>.Instance);

        var error = await Assert.ThrowsAsync<SpoolException>(() => service.RecoverStartupAsync(CancellationToken.None));

        Assert.Equal("invalid_spool_path", error.Code);
        Assert.Equal("keep", await File.ReadAllTextAsync(Path.Combine(outside, "sentinel.txt")));
    }

    [Fact]
    public async Task Cleanup_deletes_expired_job_before_committing_expired_and_forgets_terminal_notification()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var spool = new SpoolStore(fixture.SpoolPath);
        var notifier = new JobCompletionNotifier(jobs);
        var expired = await jobs.CreateAsync(CreateJob(expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1)));
        await File.WriteAllBytesAsync(spool.GetInputPath(expired.Id, expired.Extension), "payload"u8.ToArray());
        notifier.Notify(expired with { State = JobState.Failed, ErrorCode = "internal_error" });
        var service = new JobCleanupService(jobs, spool, notifier, TimeProvider.System, NullLogger<JobCleanupService>.Instance);

        var count = await service.CleanupExpiredAsync(CancellationToken.None);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        Assert.Equal(1, count);
        Assert.Equal(JobState.Expired, (await jobs.GetAsync(expired.Id))!.State);
        Assert.False(Directory.Exists(Path.Combine(spool.Root, expired.Id.ToString("N"))));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => notifier.WaitAsync(expired.Id, cancelled.Token));
    }

    [Fact]
    public async Task Cleanup_never_selects_waiting_signing_or_verifying_jobs()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var spool = new SpoolStore(fixture.SpoolPath);
        var waiting = await jobs.CreateAsync(CreateJob(expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1)));
        Assert.True(await jobs.TryMarkNextWaitingForAgentAsync());
        var verifying = await jobs.CreateAsync(CreateJob(expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1)));
        var verifyingConnection = Guid.NewGuid();
        var verifyingClaim = await jobs.ClaimNextAsync(verifyingConnection);
        Assert.Equal(verifying.Id, verifyingClaim!.Id);
        Assert.True(await jobs.TryMarkVerifyingAsync(verifying.Id, verifyingClaim.DispatchId!.Value, verifyingConnection));
        var signing = await jobs.CreateAsync(CreateJob(expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1)));
        var signingClaim = await jobs.ClaimNextAsync(Guid.NewGuid());
        Assert.Equal(signing.Id, signingClaim!.Id);
        foreach (var job in new[] { waiting, verifying, signing })
        {
            await File.WriteAllBytesAsync(spool.GetInputPath(job.Id, job.Extension), "payload"u8.ToArray());
        }

        var service = new JobCleanupService(
            jobs,
            spool,
            new JobCompletionNotifier(jobs),
            TimeProvider.System,
            NullLogger<JobCleanupService>.Instance);

        Assert.Equal(0, await service.CleanupExpiredAsync(CancellationToken.None));
        Assert.Equal(JobState.WaitingForAgent, (await jobs.GetAsync(waiting.Id))!.State);
        Assert.Equal(JobState.Verifying, (await jobs.GetAsync(verifying.Id))!.State);
        Assert.Equal(JobState.Signing, (await jobs.GetAsync(signing.Id))!.State);
        Assert.All(new[] { waiting, verifying, signing }, job =>
            Assert.True(Directory.Exists(Path.Combine(spool.Root, job.Id.ToString("N")))));
    }

    [Fact]
    public async Task Cleanup_delete_failure_rolls_back_database_and_retries_next_cycle()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var realSpool = new SpoolStore(fixture.SpoolPath);
        var expired = await jobs.CreateAsync(CreateJob(expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1)));
        await File.WriteAllBytesAsync(realSpool.GetInputPath(expired.Id, expired.Extension), "payload"u8.ToArray());
        var spool = new ControlledDeleteSpoolStore(realSpool) { FailuresRemaining = 1 };
        var service = new JobCleanupService(
            jobs,
            spool,
            new JobCompletionNotifier(jobs),
            TimeProvider.System,
            NullLogger<JobCleanupService>.Instance);

        await Assert.ThrowsAsync<IOException>(() => service.CleanupExpiredAsync(CancellationToken.None));
        Assert.Equal(JobState.Queued, (await jobs.GetAsync(expired.Id))!.State);
        Assert.True(Directory.Exists(Path.Combine(realSpool.Root, expired.Id.ToString("N"))));

        Assert.Equal(1, await service.CleanupExpiredAsync(CancellationToken.None));
        Assert.Equal(JobState.Expired, (await jobs.GetAsync(expired.Id))!.State);
        Assert.False(Directory.Exists(Path.Combine(realSpool.Root, expired.Id.ToString("N"))));
    }

    [Fact]
    public async Task Cleanup_deletes_unknown_regular_files_before_expiring_job()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var spool = new SpoolStore(fixture.SpoolPath);
        var expired = await jobs.CreateAsync(CreateJob(expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1)));
        var directory = Path.GetDirectoryName(spool.GetInputPath(expired.Id, expired.Extension))!;
        await File.WriteAllTextAsync(Path.Combine(directory, "unexpected.tmp"), "ordinary");
        var service = new JobCleanupService(
            jobs,
            spool,
            new JobCompletionNotifier(jobs),
            TimeProvider.System,
            NullLogger<JobCleanupService>.Instance);

        Assert.Equal(1, await service.CleanupExpiredAsync(CancellationToken.None));
        Assert.Equal(JobState.Expired, (await jobs.GetAsync(expired.Id))!.State);
        Assert.False(Directory.Exists(directory));
    }

    [Fact]
    public async Task Cleanup_rejects_reparse_entry_and_preserves_database_and_link_target()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var spool = new SpoolStore(fixture.SpoolPath);
        var expired = await jobs.CreateAsync(CreateJob(expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1)));
        var directory = Path.GetDirectoryName(spool.GetInputPath(expired.Id, expired.Extension))!;
        var ordinary = Path.Combine(directory, "input.pdf");
        await File.WriteAllTextAsync(ordinary, "preserve-until-validated");
        var outside = Path.Combine(Path.GetDirectoryName(spool.Root)!, "outside-cleanup.txt");
        await File.WriteAllTextAsync(outside, "keep");
        var link = CreateTrailingFileSymlink(directory, ordinary, outside);
        var service = new JobCleanupService(
            jobs,
            spool,
            new JobCompletionNotifier(jobs),
            TimeProvider.System,
            NullLogger<JobCleanupService>.Instance);

        var error = await Assert.ThrowsAsync<SpoolException>(() => service.CleanupExpiredAsync(CancellationToken.None));

        Assert.Equal("invalid_spool_path", error.Code);
        Assert.Equal(JobState.Queued, (await jobs.GetAsync(expired.Id))!.State);
        Assert.Equal("preserve-until-validated", await File.ReadAllTextAsync(ordinary));
        Assert.True(File.Exists(link));
        Assert.Equal("keep", await File.ReadAllTextAsync(outside));
    }

    [Fact]
    public async Task Cleanup_rejects_nested_directory_without_descending_and_preserves_database()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var spool = new SpoolStore(fixture.SpoolPath);
        var expired = await jobs.CreateAsync(CreateJob(expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1)));
        var directory = Path.GetDirectoryName(spool.GetInputPath(expired.Id, expired.Extension))!;
        var ordinary = Path.Combine(directory, "input.pdf");
        await File.WriteAllTextAsync(ordinary, "preserve-until-validated");
        var nested = CreateTrailingDirectory(directory, ordinary);
        await File.WriteAllTextAsync(Path.Combine(nested, "sentinel.txt"), "keep");
        var service = new JobCleanupService(
            jobs,
            spool,
            new JobCompletionNotifier(jobs),
            TimeProvider.System,
            NullLogger<JobCleanupService>.Instance);

        var error = await Assert.ThrowsAsync<SpoolException>(() => service.CleanupExpiredAsync(CancellationToken.None));

        Assert.Equal("invalid_spool_path", error.Code);
        Assert.Equal(JobState.Queued, (await jobs.GetAsync(expired.Id))!.State);
        Assert.Equal("preserve-until-validated", await File.ReadAllTextAsync(ordinary));
        Assert.Equal("keep", await File.ReadAllTextAsync(Path.Combine(nested, "sentinel.txt")));
    }

    private static string CreateTrailingFileSymlink(string directory, string ordinary, string target)
    {
        for (var attempt = 0; attempt < 256; attempt++)
        {
            var candidate = Path.Combine(directory, $"link-{Guid.NewGuid():N}");
            File.CreateSymbolicLink(candidate, target);
            var entries = Directory.EnumerateFileSystemEntries(directory).ToArray();
            if (Array.IndexOf(entries, ordinary) < Array.IndexOf(entries, candidate))
            {
                return candidate;
            }

            File.Delete(candidate);
        }

        throw new InvalidOperationException("Could not create a trailing symlink test fixture.");
    }

    private static string CreateTrailingDirectory(string directory, string ordinary)
    {
        for (var attempt = 0; attempt < 256; attempt++)
        {
            var candidate = Path.Combine(directory, $"nested-{Guid.NewGuid():N}");
            Directory.CreateDirectory(candidate);
            var entries = Directory.EnumerateFileSystemEntries(directory).ToArray();
            if (Array.IndexOf(entries, ordinary) < Array.IndexOf(entries, candidate))
            {
                return candidate;
            }

            Directory.Delete(candidate);
        }

        throw new InvalidOperationException("Could not create a trailing directory test fixture.");
    }

    [Fact]
    public async Task Expiry_finishes_destructive_delete_after_caller_cancels_during_callback()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var spool = new SpoolStore(fixture.SpoolPath);
        var expired = await jobs.CreateAsync(CreateJob(expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1)));
        var directory = Path.GetDirectoryName(spool.GetInputPath(expired.Id, expired.Extension))!;
        var first = Path.Combine(directory, "first.tmp");
        var second = Path.Combine(directory, "second.tmp");
        await File.WriteAllTextAsync(first, "first");
        await File.WriteAllTextAsync(second, "second");
        using var callerCancellation = new CancellationTokenSource();

        var result = await jobs.TryExpireNextAsync(
            DateTimeOffset.UtcNow,
            (_, deletionToken) =>
            {
                File.Delete(first);
                callerCancellation.Cancel();
                deletionToken.ThrowIfCancellationRequested();
                File.Delete(second);
                Directory.Delete(directory);
                return Task.CompletedTask;
            },
            callerCancellation.Token);

        Assert.NotNull(result);
        Assert.Equal(JobState.Expired, (await jobs.GetAsync(expired.Id))!.State);
        Assert.False(Directory.Exists(directory));
    }

    [Fact]
    public async Task Cleanup_commits_expired_after_successful_delete_even_if_caller_cancels_during_callback_return()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var realSpool = new SpoolStore(fixture.SpoolPath);
        var expired = await jobs.CreateAsync(CreateJob(expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1)));
        await File.WriteAllBytesAsync(realSpool.GetInputPath(expired.Id, expired.Extension), "payload"u8.ToArray());
        using var cancellation = new CancellationTokenSource();
        var spool = new ControlledDeleteSpoolStore(realSpool) { CancellationAfterSuccessfulDelete = cancellation };
        var notifier = new JobCompletionNotifier(jobs);
        notifier.Notify(expired with { State = JobState.Failed, ErrorCode = "internal_error" });
        var service = new JobCleanupService(
            jobs,
            spool,
            notifier,
            TimeProvider.System,
            NullLogger<JobCleanupService>.Instance);

        Assert.Equal(1, await service.CleanupExpiredAsync(cancellation.Token));
        Assert.True(cancellation.IsCancellationRequested);
        Assert.Equal(JobState.Expired, (await jobs.GetAsync(expired.Id))!.State);
        Assert.False(Directory.Exists(Path.Combine(realSpool.Root, expired.Id.ToString("N"))));
        Assert.Equal(0, notifier.PendingCount);
    }

    [Fact]
    public async Task Expiry_reservation_blocks_concurrent_claim_until_deletion_and_commit_complete()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var realSpool = new SpoolStore(fixture.SpoolPath);
        var expired = await jobs.CreateAsync(CreateJob(expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1)));
        await File.WriteAllBytesAsync(realSpool.GetInputPath(expired.Id, expired.Extension), "payload"u8.ToArray());
        var spool = new ControlledDeleteSpoolStore(realSpool) { BlockDeletion = true };
        var service = new JobCleanupService(
            jobs,
            spool,
            new JobCompletionNotifier(jobs),
            TimeProvider.System,
            NullLogger<JobCleanupService>.Instance);

        var cleanup = service.CleanupExpiredAsync(CancellationToken.None);
        await spool.DeleteEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var claim = Task.Run(async () => await jobs.ClaimNextAsync(Guid.NewGuid()));
        await Task.Delay(100);
        Assert.False(claim.IsCompleted);

        spool.ReleaseDeletion();
        Assert.Equal(1, await cleanup);
        Assert.Null(await claim);
        Assert.Equal(JobState.Expired, (await jobs.GetAsync(expired.Id))!.State);
    }

    [Fact]
    public async Task Cleanup_failure_log_emits_only_a_stable_code_without_native_details()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var realSpool = new SpoolStore(fixture.SpoolPath);
        var expired = await jobs.CreateAsync(CreateJob(expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1)));
        await File.WriteAllBytesAsync(realSpool.GetInputPath(expired.Id, expired.Extension), "payload"u8.ToArray());
        var spool = new ControlledDeleteSpoolStore(realSpool)
        {
            FailuresRemaining = 1,
            FailureMessage = "Authorization: Bearer abc.def /autologin 123456 otpauth://totp/x?secret=ABCDEFGHIJKLMNOP",
        };
        var logger = new CapturingLogger<JobCleanupService>();
        var service = new JobCleanupService(jobs, spool, new JobCompletionNotifier(jobs), TimeProvider.System, logger);

        await service.RunCleanupCycleAsync(CancellationToken.None);
        var captured = string.Join("\n", logger.Messages);

        Assert.Contains("job_cleanup_failed", captured, StringComparison.Ordinal);
        Assert.DoesNotContain("abc.def", captured, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("123456", captured, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ABCDEFGHIJKLMNOP", captured, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("IOException", captured, StringComparison.Ordinal);
        Assert.Equal(JobState.Queued, (await jobs.GetAsync(expired.Id))!.State);
    }

    [Fact]
    public async Task Hosted_maintenance_start_waits_for_recovery_and_stop_joins_periodic_loop()
    {
        using var fixture = new FileFixture();
        var jobs = new BlockingRecoveryJobStore();
        using var timeProvider = new BlockingTimerCreationTimeProvider();
        using var service = new JobCleanupService(
            jobs,
            new SpoolStore(fixture.SpoolPath),
            new JobCompletionNotifier(jobs),
            timeProvider,
            NullLogger<JobCleanupService>.Instance);

        try
        {
            var start = service.StartAsync(CancellationToken.None);
            await jobs.RecoveryEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));
            Assert.False(start.IsCompleted);
            jobs.ReleaseRecovery();
            await start.WaitAsync(TimeSpan.FromSeconds(2));
            await timeProvider.TimerCreationEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));

            var stop = service.StopAsync(CancellationToken.None);
            Assert.False(stop.IsCompleted);
            timeProvider.ReleaseTimerCreation();
            await stop.WaitAsync(TimeSpan.FromSeconds(2));
            Assert.True(
                service.ExecuteTask?.IsCompletedSuccessfully,
                $"execute_status={service.ExecuteTask?.Status.ToString() ?? "null"}");
        }
        finally
        {
            jobs.ReleaseRecovery();
            timeProvider.ReleaseTimerCreation();
        }
    }

    [Fact]
    public async Task History_cleanup_removes_old_terminal_jobs_but_preserves_active_and_newer_jobs()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var spool = new SpoolStore(fixture.SpoolPath);
        var old = await CreateSucceededJobAsync(jobs, spool, "%PDF-old"u8.ToArray());
        var initialDelta = await jobs.GetTerminalJobDeltaAsync(null, null);
        var cutoff = DateTimeOffset.UtcNow;
        await Task.Delay(20);
        var newer = await CreateSucceededJobAsync(jobs, spool, "%PDF-new"u8.ToArray());
        var active = await jobs.CreateAsync(CreateJob());
        await jobs.ClaimNextAsync(Guid.NewGuid());
        var queued = await jobs.CreateAsync(CreateJob());
        var management = new ServiceManagementSnapshotProvider(jobs, TimeProvider.System,
            spool: spool, notifier: new JobCompletionNotifier(jobs));

        Assert.Equal(1, await management.ClearJobHistoryAsync(cutoff, default));
        Assert.Null(await jobs.GetAsync(old.Id));
        Assert.False(Directory.Exists(Path.Combine(spool.Root, old.Id.ToString("N"))));
        Assert.Equal(JobState.Succeeded, (await jobs.GetAsync(newer.Id))!.State);
        Assert.Equal(JobState.Signing, (await jobs.GetAsync(active.Id))!.State);
        Assert.Equal(JobState.Queued, (await jobs.GetAsync(queued.Id))!.State);
        Assert.Equal(0, await management.ClearJobHistoryAsync(cutoff, default));
        var delta = await jobs.GetTerminalJobDeltaAsync(initialDelta.Watermark, null);
        Assert.Equal(newer.Id, Assert.Single(delta.Items).Item.JobId);
    }

    [Fact]
    public async Task History_delete_failure_preserves_record_and_idempotency_and_retry_succeeds()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var created = await jobs.CreateAsync(CreateJob(DateTimeOffset.UtcNow.AddHours(-1)), "test-principal", "history-key");
        await jobs.TryExpireNextAsync(DateTimeOffset.UtcNow, (_, _) => Task.CompletedTask);
        var cutoff = DateTimeOffset.UtcNow;
        await Assert.ThrowsAsync<IOException>(() => jobs.TryDeleteTerminalAsync(cutoff,
            (_, _) => Task.FromException(new IOException("test deletion failure"))));
        Assert.Equal(created.Id, (await jobs.GetByIdempotencyKeyAsync("test-principal", "history-key"))!.Id);
        Assert.NotNull(await jobs.GetAsync(created.Id));
        Assert.NotNull(await jobs.TryDeleteTerminalAsync(cutoff, (_, _) => Task.CompletedTask));
        Assert.Null(await jobs.GetByIdempotencyKeyAsync("test-principal", "history-key"));
        Assert.Null(await jobs.GetAsync(created.Id));
    }

    [Fact]
    public async Task History_cleanup_is_rejected_while_upgrade_is_draining()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var spool = new SpoolStore(fixture.SpoolPath);
        var completed = await CreateSucceededJobAsync(jobs, spool, "%PDF-keep"u8.ToArray());
        var gate = new UpgradeAdmissionGate();
        var management = new ServiceManagementSnapshotProvider(jobs, TimeProvider.System,
            spool: spool, notifier: new JobCompletionNotifier(jobs), upgradeGate: gate);
        Assert.True(await gate.DrainAsync(TimeSpan.FromSeconds(1), default));
        await Assert.ThrowsAsync<InvalidOperationException>(() => management.ClearJobHistoryAsync(DateTimeOffset.UtcNow, default));
        Assert.NotNull(await jobs.GetAsync(completed.Id));
        Assert.True(File.Exists(spool.GetResultPath(completed.Id, completed.Extension)));
    }

    [Fact]
    public async Task History_cleanup_is_bounded_and_does_not_rewind_terminal_watermark()
    {
        using var fixture = new FileFixture();
        var jobs = fixture.CreateStore();
        var spool = new SpoolStore(fixture.SpoolPath);
        for (var index = 0; index < 101; index++)
        {
            await jobs.CreateAsync(CreateJob(DateTimeOffset.UtcNow.AddHours(-1)));
            await jobs.TryExpireNextAsync(DateTimeOffset.UtcNow, (_, _) => Task.CompletedTask);
        }

        var before = await jobs.GetTerminalJobDeltaAsync(null, null);
        var cutoff = DateTimeOffset.UtcNow;
        var management = new ServiceManagementSnapshotProvider(jobs, TimeProvider.System,
            spool: spool, notifier: new JobCompletionNotifier(jobs));
        Assert.Equal(100, await management.ClearJobHistoryAsync(cutoff, default));
        Assert.Single(await jobs.GetAllAsync());
        Assert.Equal(1, await management.ClearJobHistoryAsync(cutoff, default));
        Assert.Empty(await jobs.GetAllAsync());
        var after = await jobs.GetTerminalJobDeltaAsync(before.Watermark, null);
        Assert.Equal(before.Watermark, after.Watermark);
        await CreateSucceededJobAsync(jobs, spool, "%PDF-later"u8.ToArray());
        var next = await jobs.GetTerminalJobDeltaAsync(after.Watermark, null);
        Assert.Single(next.Items);
        Assert.True(next.Watermark.Sequence > after.Watermark.Sequence);
    }

    private static async Task<Job> CreateSucceededJobAsync(SqliteJobStore jobs, SpoolStore spool, byte[] result)
    {
        var created = await jobs.CreateAsync(CreateJob());
        var connectionId = Guid.NewGuid();
        var claimed = await jobs.ClaimNextAsync(connectionId);
        Assert.Equal(created.Id, claimed!.Id);
        Assert.True(await jobs.TryMarkVerifyingAsync(created.Id, claimed.DispatchId!.Value, connectionId));
        var hash = Convert.ToHexString(SHA256.HashData(result)).ToLowerInvariant();
        await File.WriteAllBytesAsync(spool.GetResultPartPath(created.Id, created.Extension), result);
        Assert.True(await jobs.TryRecordCompletionAsync(created.Id, claimed.DispatchId.Value, connectionId, result.Length, hash));
        await spool.PromoteResultAsync(created.Id, created.Extension, hash, result.Length);
        Assert.True(await jobs.TryFinishSuccessAsync(created.Id, claimed.DispatchId.Value, connectionId));
        return (await jobs.GetAsync(created.Id))!;
    }

    private static Job CreateJob(DateTimeOffset? expiresAt = null) =>
        new(Guid.NewGuid(), JobState.Queued, new AuthenticodeParameters("52A1B4C9", "sha256", false))
        {
            OriginalName = "payload.exe",
            Extension = ".exe",
            InputSha256 = Convert.ToHexString(SHA256.HashData("input"u8)).ToLowerInvariant(),
            InputSize = 5,
            ExpiresAt = expiresAt ?? DateTimeOffset.UtcNow.AddHours(1),
        };

    private sealed class StaticAgentHealthStatusSource(AgentHealthSnapshot? snapshot) : IAgentHealthStatusSource
    {
        public AgentHealthSnapshot? CurrentHealth => snapshot;
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class BlockingTimerCreationTimeProvider : TimeProvider, IDisposable
    {
        private readonly ManualResetEventSlim _release = new(false);

        public TaskCompletionSource TimerCreationEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override ITimer CreateTimer(
            TimerCallback callback,
            object? state,
            TimeSpan dueTime,
            TimeSpan period)
        {
            TimerCreationEntered.TrySetResult();
            _release.Wait();
            return base.CreateTimer(callback, state, dueTime, period);
        }

        public void ReleaseTimerCreation() => _release.Set();

        public void Dispose() => _release.Dispose();
    }

    private sealed class RecordingLocalUploadCleanup : ILocalUploadCleanup
    {
        public int Calls { get; private set; }

        public Task<int> CleanupExpiredAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return Task.FromResult(1);
        }
    }

    private sealed class HealthFixture(WebApplication application, string root) : IAsyncDisposable
    {
        public HttpClient Client { get; } = application.GetTestClient();

        public IServiceProvider Services => application.Services;

        public static async Task<HealthFixture> StartAsync(
            IAgentHealthStatusSource? statusSource = null,
            TimeProvider? timeProvider = null)
        {
            var root = Path.Combine(Path.GetTempPath(), "CodeSignAuto.Tests", Guid.NewGuid().ToString("N"));
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
            builder.WebHost.UseTestServer();
            ServiceHost.Configure(builder, new ServiceHostOptions(
                SHA256.HashData(Encoding.UTF8.GetBytes(Token)),
                Path.Combine(root, "jobs.db"),
                Path.Combine(root, "spool"))
            {
                ProductVersionIdentity = "1.0.0",
            });
            if (statusSource is not null)
            {
                builder.Services.AddSingleton(statusSource);
                builder.Services.AddSingleton<IAgentHealthStatusSource>(statusSource);
            }

            if (timeProvider is not null)
            {
                builder.Services.AddSingleton(timeProvider);
            }

            var application = builder.Build();
            ServiceHost.MapPipeline(application);
            await application.StartAsync();
            return new HealthFixture(application, root);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await application.DisposeAsync();
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private sealed class FileFixture : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "CodeSignAuto.Tests", Guid.NewGuid().ToString("N"));
        private readonly List<SqliteJobStore> _stores = [];

        public string DatabasePath => Path.Combine(_root, "jobs.db");

        public string SpoolPath => Path.Combine(_root, "spool");

        public SqliteJobStore CreateStore()
        {
            var store = new SqliteJobStore(DatabasePath);
            _stores.Add(store);
            return store;
        }

        public void Dispose()
        {
            foreach (var store in _stores)
            {
                store.Dispose();
            }

            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
    }

    private sealed class ControlledDeleteSpoolStore(SpoolStore inner) : ISpoolStore
    {
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int FailuresRemaining { get; set; }

        public string FailureMessage { get; set; } = "delete failed";

        public bool BlockDeletion { get; set; }

        public CancellationTokenSource? CancellationAfterSuccessfulDelete { get; set; }

        public TaskCompletionSource DeleteEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public IReadOnlyList<SpoolJobDirectory> ValidateAndListJobDirectories() =>
            inner.ValidateAndListJobDirectories();

        public Task<SpoolFile> WriteInputAsync(Guid jobId, string extension, Stream input, long maxBytes, CancellationToken cancellationToken = default) =>
            inner.WriteInputAsync(jobId, extension, input, maxBytes, cancellationToken);

        public Task<Stream> OpenVerifiedResultAsync(Guid jobId, string extension, long expectedSize, string expectedSha256, CancellationToken cancellationToken = default) =>
            inner.OpenVerifiedResultAsync(jobId, extension, expectedSize, expectedSha256, cancellationToken);

        public Task<SpoolFile> PromoteResultAsync(Guid jobId, string extension, string expectedSha256, long expectedSize, CancellationToken cancellationToken = default) =>
            inner.PromoteResultAsync(jobId, extension, expectedSha256, expectedSize, cancellationToken);

        public async Task DeleteJobAsync(Guid jobId, CancellationToken cancellationToken = default)
        {
            DeleteEntered.TrySetResult();
            if (FailuresRemaining > 0)
            {
                FailuresRemaining--;
                throw new IOException(FailureMessage);
            }

            if (BlockDeletion)
            {
                await _release.Task.WaitAsync(cancellationToken);
            }

            await inner.DeleteJobAsync(jobId, cancellationToken);
            CancellationAfterSuccessfulDelete?.Cancel();
        }

        public Task DeleteStalePartsAsync(Job job, DateTimeOffset cutoff, CancellationToken cancellationToken = default) =>
            inner.DeleteStalePartsAsync(job, cutoff, cancellationToken);

        public Task DeleteSucceededTransientFilesAsync(Job job, CancellationToken cancellationToken = default) =>
            inner.DeleteSucceededTransientFilesAsync(job, cancellationToken);

        public Task QuarantineAsync(SpoolJobDirectory directory, CancellationToken cancellationToken = default) =>
            inner.QuarantineAsync(directory, cancellationToken);

        public void ReleaseDeletion() => _release.TrySetResult();
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public ConcurrentQueue<string> Messages { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) => Messages.Enqueue(formatter(state, exception));
    }

    private sealed class BlockingRecoveryJobStore : IJobStore
    {
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource RecoveryEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<Job> CreateAsync(Job job, string? apiPrincipal = null, string? idempotencyKey = null, CancellationToken cancellationToken = default) =>
            Task.FromResult(job);

        public Task<Job?> GetAsync(Guid jobId, CancellationToken cancellationToken = default) => Task.FromResult<Job?>(null);

        public Task CheckHealthAsync(CancellationToken cancellationToken = default) =>
            Task.FromException(new NotSupportedException());

        public Task<JobQueueSnapshot> GetQueueSnapshotAsync(CancellationToken cancellationToken = default) =>
            Task.FromException<JobQueueSnapshot>(new NotSupportedException());

        public Task<IReadOnlyList<Job>> GetAllAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<Job>>([]);

        public Task<Job?> TryExpireNextAsync(
            DateTimeOffset cutoff,
            Func<Job, CancellationToken, Task> deleteJobAsync,
            CancellationToken cancellationToken = default) => Task.FromException<Job?>(new NotSupportedException());

        public Task<int> RecoverActiveLeasesAsync(CancellationToken cancellationToken = default) =>
            RecoverInterruptedAsync(cancellationToken);

        public async Task<int> RecoverInterruptedAsync(CancellationToken cancellationToken = default)
        {
            RecoveryEntered.TrySetResult();
            await _release.Task.WaitAsync(cancellationToken);
            return 0;
        }

        public void ReleaseRecovery() => _release.TrySetResult();
    }
}
