using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Service;
using SimplySignAuto.Service.Api;
using SimplySignAuto.Service.Ipc;
using SimplySignAuto.Service.Jobs;
using SimplySignAuto.Protocol;
using Xunit;

namespace SimplySignAuto.Service.Tests;

public sealed class JobEndpointsTests
{
    private static readonly DateTimeOffset CapabilityNow =
        DateTimeOffset.Parse("2026-08-15T08:00:00Z");

    [Theory]
    [InlineData(0, null)]
    [InlineData(1, 1)]
    [InlineData(168, 168)]
    public void Retention_policy_returns_the_exact_nullable_expiry(
        int retentionHours,
        int? expectedHours)
    {
        var createdAt = DateTimeOffset.Parse("2026-08-09T08:00:00Z");

        var expiresAt = new JobRetentionPolicy(retentionHours).GetExpiresAt(createdAt);

        Assert.Equal(
            expectedHours is null ? (DateTimeOffset?)null : createdAt.AddHours(expectedHours.Value),
            expiresAt);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(169)]
    public void Retention_policy_rejects_out_of_range_hours(int retentionHours)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new JobRetentionPolicy(retentionHours));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(168)]
    public async Task Configured_retention_controls_api_job_expiry(int retentionHours)
    {
        var now = DateTimeOffset.Parse("2026-08-09T08:00:00Z");
        await using var factory = await TestServiceFactory.StartAsync(
            retentionHours,
            new FixedJobTimeProvider(now));
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.PdfRequest());
        var body = await response.Content.ReadFromJsonAsync<CreateJobResponse>();
        var stored = await factory.Services.GetRequiredService<IJobStore>().GetAsync(body!.JobId);

        Assert.Equal(now.AddHours(retentionHours), body.ExpiresAt);
        Assert.Equal(now.AddHours(retentionHours), stored!.ExpiresAt);
    }

    [Fact]
    public async Task Zero_retention_is_permanent_for_new_api_jobs_without_rewriting_existing_jobs()
    {
        var now = DateTimeOffset.Parse("2026-08-09T08:00:00Z");
        var store = new InMemoryRetentionJobStore();
        Guid finiteJobId;
        await using (var finiteFactory = await TestServiceFactory.StartAsync(
            services =>
            {
                services.AddSingleton<IJobStore>(store);
                services.AddSingleton<TimeProvider>(new FixedJobTimeProvider(now));
            },
            retentionHours: 1))
        {
            using var client = finiteFactory.CreateAuthenticatedClient();
            using var response = await client.SendAsync(TestUploads.PdfRequest());
            finiteJobId = (await response.Content.ReadFromJsonAsync<CreateJobResponse>())!.JobId;
        }

        await using var permanentFactory = await TestServiceFactory.StartAsync(
            services =>
            {
                services.AddSingleton<IJobStore>(store);
                services.AddSingleton<TimeProvider>(new FixedJobTimeProvider(now.AddMinutes(1)));
            },
            retentionHours: 0);
        using var permanentClient = permanentFactory.CreateAuthenticatedClient();
        using var createResponse = await permanentClient.SendAsync(TestUploads.PdfRequest());
        var created = await createResponse.Content.ReadFromJsonAsync<CreateJobResponse>();
        using var statusResponse = await permanentClient.GetAsync(created!.StatusUrl);
        var status = await statusResponse.Content.ReadFromJsonAsync<JobStatusResponse>();

        Assert.Equal(HttpStatusCode.Accepted, createResponse.StatusCode);
        Assert.Null(created.ExpiresAt);
        Assert.Null(status!.ExpiresAt);
        Assert.Null((await store.GetAsync(created.JobId))!.ExpiresAt);
        Assert.Equal(now.AddHours(1), (await store.GetAsync(finiteJobId))!.ExpiresAt);
    }

    [Fact]
    public async Task Accepted_job_returns_polling_contract_and_is_dispatched()
    {
        var dispatcher = new RecordingDispatcher();
        await using var factory = await TestServiceFactory.StartAsync(dispatcher);

        using var client = factory.CreateAuthenticatedClient();
        using var response = await client.SendAsync(TestUploads.PdfRequest());

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<CreateJobResponse>();
        Assert.NotNull(body);
        Assert.Equal("queued", body.State);
        Assert.Equal($"/v1/jobs/{body.JobId}", body.StatusUrl);
        Assert.Equal($"/v1/jobs/{body.JobId}/result", body.ResultUrl);
        Assert.Contains(body.JobId, dispatcher.JobIds);
        var stored = await factory.Services.GetRequiredService<IJobStore>().GetAsync(body.JobId);
        Assert.Equal(Encoding.ASCII.GetByteCount("%PDF-1.7\nbody"), stored!.InputSize);
    }

    [Theory]
    [InlineData("/v1/jobs", false)]
    [InlineData("/v1/jobs", true)]
    [InlineData("/v1/sign?waitSeconds=1", false)]
    [InlineData("/v1/sign?waitSeconds=1", true)]
    public async Task Explicitly_absent_pdf_support_returns_503_before_any_job_or_spool_mutation(
        string uri,
        bool fileFirst)
    {
        var dispatcher = new RecordingDispatcher();
        var spool = new MutationRecordingSpoolStore();
        await using var factory = await TestServiceFactory.StartAsync(services =>
        {
            services.AddSingleton<IJobDispatcher>(dispatcher);
            services.AddSingleton<ISpoolStore>(spool);
            services.AddSingleton<TimeProvider>(new FixedJobTimeProvider(CapabilityNow));
            services.AddSingleton<IAgentHealthStatusSource>(
                new FixedAgentHealthStatusSource(PdfSupportNotInstalledHealth()));
        });
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.PdfRequest(
            uri: uri,
            fileFirst: fileFirst));
        var problem = await response.Content.ReadFromJsonAsync<ApiProblem>();

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("pdf_support_not_installed", problem!.Code);
        Assert.Empty(await factory.Services.GetRequiredService<IJobStore>().GetAllAsync());
        Assert.Empty(factory.SpoolJobDirectories());
        Assert.Empty(dispatcher.JobIds);
        Assert.Equal(0, spool.MutationCalls);
    }

    [Fact]
    public async Task Explicitly_absent_pdf_support_does_not_block_authenticode_jobs()
    {
        var dispatcher = new RecordingDispatcher();
        await using var factory = await TestServiceFactory.StartAsync(services =>
        {
            services.AddSingleton<IJobDispatcher>(dispatcher);
            services.AddSingleton<TimeProvider>(new FixedJobTimeProvider(CapabilityNow));
            services.AddSingleton<IAgentHealthStatusSource>(
                new FixedAgentHealthStatusSource(PdfSupportNotInstalledHealth()));
        });
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.AuthenticodeRequest());

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Single(await factory.Services.GetRequiredService<IJobStore>().GetAllAsync());
        Assert.Single(factory.SpoolJobDirectories());
        Assert.Single(dispatcher.JobIds);
    }

    [Theory]
    [InlineData("nested_session_mismatch", false)]
    [InlineData("nested_session_mismatch", true)]
    [InlineData("process_session_mismatch", false)]
    [InlineData("process_session_mismatch", true)]
    [InlineData("stale", false)]
    [InlineData("disconnected", false)]
    [InlineData("tampered", false)]
    public async Task Noncurrent_or_unready_pdf_capability_is_rejected_before_any_mutation(
        string mutation,
        bool fileFirst)
    {
        var dispatcher = new RecordingDispatcher();
        var spool = new MutationRecordingSpoolStore();
        await using var factory = await TestServiceFactory.StartAsync(services =>
        {
            services.AddSingleton<IJobDispatcher>(dispatcher);
            services.AddSingleton<ISpoolStore>(spool);
            services.AddSingleton<TimeProvider>(new FixedJobTimeProvider(CapabilityNow));
            services.AddSingleton<IAgentHealthStatusSource>(
                new FixedAgentHealthStatusSource(PdfSupportHealth(mutation)));
        });
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.PdfRequest(fileFirst: fileFirst));
        var problem = await response.Content.ReadFromJsonAsync<ApiProblem>();

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(mutation == "tampered" ? "pdf_helper_tampered" : "service_unavailable", problem!.Code);
        Assert.Empty(await factory.Services.GetRequiredService<IJobStore>().GetAllAsync());
        Assert.Empty(factory.SpoolJobDirectories());
        Assert.Empty(dispatcher.JobIds);
        Assert.Equal(0, spool.MutationCalls);
    }

    [Theory]
    [InlineData("/v1/jobs", false)]
    [InlineData("/v1/jobs", true)]
    [InlineData("/v1/sign?waitSeconds=1", false)]
    [InlineData("/v1/sign?waitSeconds=1", true)]
    public async Task Stale_signing_service_rejects_authenticode_before_any_mutation(
        string uri,
        bool fileFirst)
    {
        var dispatcher = new RecordingDispatcher();
        var spool = new MutationRecordingSpoolStore();
        var stale = TestAgentHealth.Ready(
            CapabilityNow,
            heartbeatAt: CapabilityNow - AgentPipeServer.HeartbeatTimeout - TimeSpan.FromMilliseconds(1));
        await using var factory = await TestServiceFactory.StartAsync(services =>
        {
            services.AddSingleton<IJobDispatcher>(dispatcher);
            services.AddSingleton<ISpoolStore>(spool);
            services.AddSingleton<TimeProvider>(new FixedJobTimeProvider(CapabilityNow));
            services.AddSingleton<IAgentHealthStatusSource>(new FixedAgentHealthStatusSource(stale));
        });
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.AuthenticodeRequest(uri, fileFirst));
        var problem = await response.Content.ReadFromJsonAsync<ApiProblem>();

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("service_unavailable", problem!.Code);
        Assert.Empty(await factory.Services.GetRequiredService<IJobStore>().GetAllAsync());
        Assert.Empty(dispatcher.JobIds);
        Assert.Equal(0, spool.MutationCalls);
    }

    [Theory]
    [InlineData("/v1/jobs", false)]
    [InlineData("/v1/jobs", true)]
    [InlineData("/v1/sign?waitSeconds=1", false)]
    [InlineData("/v1/sign?waitSeconds=1", true)]
    public async Task Logged_out_session_is_prepared_before_file_spool_and_then_accepts_the_request(
        string uri,
        bool fileFirst)
    {
        var dispatcher = new RecordingDispatcher();
        var health = new MutableAgentHealthStatusSource(TestAgentHealth.ProcessMissing(CapabilityNow));
        var preparation = new RecordingAdmissionPreparation(health, TestAgentHealth.Ready(CapabilityNow));
        await using var factory = await TestServiceFactory.StartAsync(services =>
        {
            services.AddSingleton<IJobDispatcher>(dispatcher);
            services.AddSingleton<IAgentHealthStatusSource>(health);
            services.AddSingleton<IAgentOnDemandLogin>(preparation);
            services.AddSingleton<TimeProvider>(new FixedJobTimeProvider(CapabilityNow));
        });
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.AuthenticodeRequest(uri, fileFirst));

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Single(await factory.Services.GetRequiredService<IJobStore>().GetAllAsync());
        Assert.Single(factory.SpoolJobDirectories());
        Assert.Single(dispatcher.JobIds);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Failed_automatic_login_returns_503_without_job_or_spool_mutation(bool fileFirst)
    {
        var dispatcher = new RecordingDispatcher();
        var spool = new MutationRecordingSpoolStore();
        var health = new MutableAgentHealthStatusSource(TestAgentHealth.ProcessMissing(CapabilityNow));
        var preparation = new RecordingAdmissionPreparation(health, replacement: null);
        await using var factory = await TestServiceFactory.StartAsync(services =>
        {
            services.AddSingleton<IJobDispatcher>(dispatcher);
            services.AddSingleton<ISpoolStore>(spool);
            services.AddSingleton<IAgentHealthStatusSource>(health);
            services.AddSingleton<IAgentOnDemandLogin>(preparation);
            services.AddSingleton<TimeProvider>(new FixedJobTimeProvider(CapabilityNow));
        });
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.AuthenticodeRequest(fileFirst: fileFirst));
        var problem = await response.Content.ReadFromJsonAsync<ApiProblem>();

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("service_unavailable", problem!.Code);
        Assert.Empty(await factory.Services.GetRequiredService<IJobStore>().GetAllAsync());
        Assert.Empty(factory.SpoolJobDirectories());
        Assert.Empty(dispatcher.JobIds);
        Assert.Equal(0, spool.MutationCalls);
    }

    [Fact]
    public async Task Running_but_login_required_session_is_reauthenticated_before_spool()
    {
        var health = new MutableAgentHealthStatusSource(TestAgentHealth.LoginRequired(CapabilityNow));
        var preparation = new RecordingAdmissionPreparation(health, TestAgentHealth.Ready(CapabilityNow));
        await using var factory = await TestServiceFactory.StartAsync(services =>
        {
            services.AddSingleton<IAgentHealthStatusSource>(health);
            services.AddSingleton<IAgentOnDemandLogin>(preparation);
            services.AddSingleton<TimeProvider>(new FixedJobTimeProvider(CapabilityNow));
        });
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.AuthenticodeRequest());

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Single(await factory.Services.GetRequiredService<IJobStore>().GetAllAsync());
        Assert.Single(factory.SpoolJobDirectories());
    }

    [Theory]
    [InlineData("missing", HttpStatusCode.BadRequest, "certificate_not_found")]
    [InlineData("ambiguous", HttpStatusCode.BadRequest, "certificate_serial_ambiguous")]
    [InlineData("unusable", HttpStatusCode.BadRequest, "certificate_not_usable")]
    [InlineData("catalog_stale", HttpStatusCode.ServiceUnavailable, "certificate_catalog_unavailable")]
    public async Task Certificate_errors_known_from_parameters_are_rejected_before_file_spool(
        string mutation,
        HttpStatusCode expectedStatus,
        string expectedCode)
    {
        var requested = TestAgentHealth.Certificate("6F09D233");
        var other = TestAgentHealth.Certificate("52A1B4C9");
        IReadOnlyList<CertificateSummary> certificates = mutation switch
        {
            "missing" => [other],
            "ambiguous" => [requested, requested],
            "unusable" => [TestAgentHealth.Certificate("6F09D233", false, false, true, "unsupported_purpose"), other],
            "catalog_stale" => [TestAgentHealth.Certificate("6F09D233", false, false, false, "catalog_stale"), other],
            _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
        };
        var spool = new MutationRecordingSpoolStore();
        await using var factory = await TestServiceFactory.StartAsync(services =>
        {
            services.AddSingleton<ISpoolStore>(spool);
            services.AddSingleton<TimeProvider>(new FixedJobTimeProvider(CapabilityNow));
            services.AddSingleton<IAgentHealthStatusSource>(new FixedAgentHealthStatusSource(
                TestAgentHealth.Ready(CapabilityNow, certificates)));
        });
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.AuthenticodeRequest());
        var problem = await response.Content.ReadFromJsonAsync<ApiProblem>();

        Assert.Equal(expectedStatus, response.StatusCode);
        Assert.Equal(expectedCode, problem!.Code);
        Assert.Empty(await factory.Services.GetRequiredService<IJobStore>().GetAllAsync());
        Assert.Equal(0, spool.MutationCalls);
    }

    [Fact]
    public async Task Invalid_parameters_are_rejected_before_file_spool()
    {
        const string invalid = """
            {"kind":"authenticode","certificateSerialNumber":"6F09D233","digestAlgorithm":"sha256","appendSignature":false,"unknown":true}
            """;
        var spool = new MutationRecordingSpoolStore();
        await using var factory = await TestServiceFactory.StartAsync(services =>
            services.AddSingleton<ISpoolStore>(spool));
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.Request(invalid, "input.exe", "MZ-test"));
        var problem = await response.Content.ReadFromJsonAsync<ApiProblem>();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_parameters", problem!.Code);
        Assert.Empty(await factory.Services.GetRequiredService<IJobStore>().GetAllAsync());
        Assert.Equal(0, spool.MutationCalls);
    }

    [Fact]
    public async Task Parameter_kind_that_conflicts_with_filename_is_rejected_before_file_spool()
    {
        const string pdfParameters = """
            {"kind":"pdf","certificateSerialNumber":"6F09D233","digestAlgorithm":"sha256","page":1,"box":[10,20,30,40],"fieldName":"Signature1"}
            """;
        var spool = new MutationRecordingSpoolStore();
        await using var factory = await TestServiceFactory.StartAsync(services =>
            services.AddSingleton<ISpoolStore>(spool));
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.Request(pdfParameters, "input.exe", "MZ-test"));
        var problem = await response.Content.ReadFromJsonAsync<ApiProblem>();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_parameters", problem!.Code);
        Assert.Empty(await factory.Services.GetRequiredService<IJobStore>().GetAllAsync());
        Assert.Equal(0, spool.MutationCalls);
    }

    [Fact]
    public async Task Multipart_parts_may_arrive_in_either_order()
    {
        await using var factory = await TestServiceFactory.StartAsync();
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.PdfRequest(fileFirst: true));

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
    }

    [Theory]
    [InlineData("empty")]
    [InlineData("wrong_magic")]
    [InlineData("unknown_part")]
    [InlineData("duplicate_file")]
    [InlineData("missing_parameters")]
    public async Task Invalid_multipart_is_rejected_and_leaves_no_spool(string kind)
    {
        await using var factory = await TestServiceFactory.StartAsync();
        using var client = factory.CreateAuthenticatedClient();
        using var request = TestUploads.InvalidRequest(kind);

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(factory.SpoolJobDirectories());
    }

    [Fact]
    public async Task Unsupported_extension_returns_stable_400_and_leaves_no_spool()
    {
        var spool = new MutationRecordingSpoolStore();
        await using var factory = await TestServiceFactory.StartAsync(services =>
            services.AddSingleton<ISpoolStore>(spool));
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.PdfRequest(fileName: "notes.txt"));
        var problem = await response.Content.ReadFromJsonAsync<ApiProblem>();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("unsupported_type", problem!.Code);
        Assert.Empty(factory.SpoolJobDirectories());
        Assert.Equal(0, spool.MutationCalls);
    }

    [Fact]
    public async Task Unterminated_multipart_is_rejected_and_leaves_no_spool()
    {
        await using var factory = await TestServiceFactory.StartAsync();
        using var client = factory.CreateAuthenticatedClient();
        using var request = TestUploads.UnterminatedRequest();

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(factory.SpoolJobDirectories());
    }

    [Fact]
    public async Task Oversized_file_returns_413_and_cleans_the_job_spool()
    {
        var spool = new RejectingSpoolStore();
        await using var factory = await TestServiceFactory.StartAsync(services => services.AddSingleton<ISpoolStore>(spool));
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.PdfRequest());

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Equal(512L * 1024 * 1024, spool.MaxBytes);
        Assert.Single(spool.DeletedJobIds);
    }

    [Fact]
    public async Task Database_failure_returns_safe_problem_and_cleans_input_spool()
    {
        await using var factory = await TestServiceFactory.StartAsync(services => services.AddSingleton<IJobStore>(new ThrowingJobStore()));
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.PdfRequest());

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<ApiProblem>();
        Assert.Equal("internal_error", problem!.Code);
        Assert.DoesNotContain("database path", await response.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
        Assert.Empty(factory.SpoolJobDirectories());
    }

    [Fact]
    public async Task Matching_idempotency_request_reuses_job_and_removes_second_spool()
    {
        var dispatcher = new RecordingDispatcher();
        await using var factory = await TestServiceFactory.StartAsync(services => services.AddSingleton<IJobDispatcher>(dispatcher));
        using var client = factory.CreateAuthenticatedClient();
        using var firstRequest = TestUploads.PdfRequest();
        firstRequest.Headers.Add("Idempotency-Key", "same-key");
        using var secondRequest = TestUploads.PdfRequest();
        secondRequest.Headers.Add("Idempotency-Key", "same-key");

        using var firstResponse = await client.SendAsync(firstRequest);
        using var secondResponse = await client.SendAsync(secondRequest);
        var first = await firstResponse.Content.ReadFromJsonAsync<CreateJobResponse>();
        var second = await secondResponse.Content.ReadFromJsonAsync<CreateJobResponse>();

        Assert.Equal(HttpStatusCode.Accepted, firstResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, secondResponse.StatusCode);
        Assert.Equal(first!.JobId, second!.JobId);
        Assert.Single(dispatcher.JobIds);
        Assert.Single(factory.SpoolJobDirectories());
    }

    [Fact]
    public async Task Conflicting_idempotency_request_returns_409_and_removes_second_spool()
    {
        await using var factory = await TestServiceFactory.StartAsync();
        using var client = factory.CreateAuthenticatedClient();
        using var firstRequest = TestUploads.PdfRequest("%PDF-first");
        firstRequest.Headers.Add("Idempotency-Key", "same-key");
        using var secondRequest = TestUploads.PdfRequest("%PDF-second");
        secondRequest.Headers.Add("Idempotency-Key", "same-key");

        using var firstResponse = await client.SendAsync(firstRequest);
        using var secondResponse = await client.SendAsync(secondRequest);
        var problem = await secondResponse.Content.ReadFromJsonAsync<ApiProblem>();

        Assert.Equal(HttpStatusCode.Accepted, firstResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, secondResponse.StatusCode);
        Assert.Equal("idempotency_conflict", problem!.Code);
        Assert.Single(factory.SpoolJobDirectories());
    }

    [Fact]
    public async Task Pending_result_returns_409_and_expired_result_returns_410()
    {
        await using var factory = await TestServiceFactory.StartAsync();
        using var client = factory.CreateAuthenticatedClient();
        using var createdResponse = await client.SendAsync(TestUploads.PdfRequest());
        var created = await createdResponse.Content.ReadFromJsonAsync<CreateJobResponse>();

        using var pending = await client.GetAsync(created!.ResultUrl);
        var store = factory.Services.GetRequiredService<IJobStore>();
        var spool = factory.Services.GetRequiredService<ISpoolStore>();
        await store.TryExpireNextAsync(
            DateTimeOffset.UtcNow.AddDays(2),
            (job, cancellationToken) => spool.DeleteJobAsync(job.Id, cancellationToken));
        using var expired = await client.GetAsync(created.ResultUrl);

        Assert.Equal(HttpStatusCode.Conflict, pending.StatusCode);
        Assert.Equal("job_not_complete", (await pending.Content.ReadFromJsonAsync<ApiProblem>())!.Code);
        Assert.Equal(HttpStatusCode.Gone, expired.StatusCode);
        Assert.Equal("job_expired", (await expired.Content.ReadFromJsonAsync<ApiProblem>())!.Code);
    }

    [Fact]
    public async Task Sign_returns_signed_file_when_completion_was_notified_before_waiting()
    {
        await using var factory = await TestServiceFactory.StartAsync(services =>
            services.AddSingleton<IJobDispatcher>(provider => new CompletingDispatcher(
                provider.GetRequiredService<IJobStore>(),
                (SpoolStore)provider.GetRequiredService<ISpoolStore>(),
                provider.GetRequiredService<IJobCompletionNotifier>())));
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.PdfRequest(uri: "/v1/sign?waitSeconds=2", fileName: "badname.pdf"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/pdf", response.Content.Headers.ContentType!.MediaType);
        Assert.Equal("badname.signed.pdf", response.Content.Headers.ContentDisposition!.FileNameStar);
        Assert.Equal("%PDF-signed", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Sign_timeout_returns_202_and_keeps_persisted_job()
    {
        await using var factory = await TestServiceFactory.StartAsync();
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.PdfRequest(uri: "/v1/sign?waitSeconds=1"));
        var body = await response.Content.ReadFromJsonAsync<CreateJobResponse>();

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.NotNull(await factory.Services.GetRequiredService<IJobStore>().GetAsync(body!.JobId));
    }

    [Fact]
    public async Task Sign_returns_existing_idempotent_failed_job_immediately_without_waiting_for_a_notification()
    {
        await using var factory = await TestServiceFactory.StartAsync();
        using var client = factory.CreateAuthenticatedClient();
        using var firstRequest = TestUploads.PdfRequest();
        firstRequest.Headers.Add("Idempotency-Key", "failed-sign-key");
        using var firstResponse = await client.SendAsync(firstRequest);
        var created = await firstResponse.Content.ReadFromJsonAsync<CreateJobResponse>();
        var store = factory.Services.GetRequiredService<IJobStore>();
        var connectionId = Guid.NewGuid();
        var claimed = await store.ClaimNextAsync(connectionId);
        Assert.Equal(created!.JobId, claimed!.Id);
        Assert.True(await store.TryFailLeaseAsync(
            claimed.Id,
            claimed.DispatchId!.Value,
            connectionId,
            "internal_error",
            "The signing operation failed."));
        using var retry = TestUploads.PdfRequest(uri: "/v1/sign?waitSeconds=1");
        retry.Headers.Add("Idempotency-Key", "failed-sign-key");

        using var response = await client.SendAsync(retry);
        var problem = await response.Content.ReadFromJsonAsync<ApiProblem>();

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("internal_error", problem!.Code);
        Assert.Equal(created.JobId, problem.JobId);
    }

    [Fact]
    public async Task Sign_returns_existing_idempotent_expired_job_as_gone()
    {
        await using var factory = await TestServiceFactory.StartAsync();
        using var client = factory.CreateAuthenticatedClient();
        using var firstRequest = TestUploads.PdfRequest();
        firstRequest.Headers.Add("Idempotency-Key", "expired-sign-key");
        using var firstResponse = await client.SendAsync(firstRequest);
        var created = await firstResponse.Content.ReadFromJsonAsync<CreateJobResponse>();
        var store = factory.Services.GetRequiredService<IJobStore>();
        var spool = factory.Services.GetRequiredService<ISpoolStore>();
        Assert.NotNull(await store.TryExpireNextAsync(
            DateTimeOffset.UtcNow.AddDays(2),
            (job, cancellationToken) => spool.DeleteJobAsync(job.Id, cancellationToken)));
        using var retry = TestUploads.PdfRequest(uri: "/v1/sign?waitSeconds=1");
        retry.Headers.Add("Idempotency-Key", "expired-sign-key");

        using var response = await client.SendAsync(retry);
        var problem = await response.Content.ReadFromJsonAsync<ApiProblem>();

        Assert.Equal(HttpStatusCode.Gone, response.StatusCode);
        Assert.Equal("job_expired", problem!.Code);
        Assert.Equal(created!.JobId, problem.JobId);
    }

    [Fact]
    public async Task Sign_returns_expired_waiter_completion_as_gone()
    {
        await using var factory = await TestServiceFactory.StartAsync(services =>
            services.AddSingleton<IJobCompletionNotifier>(new ExpiredNotifier()));
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.PdfRequest(uri: "/v1/sign?waitSeconds=1"));
        var problem = await response.Content.ReadFromJsonAsync<ApiProblem>();

        Assert.Equal(HttpStatusCode.Gone, response.StatusCode);
        Assert.Equal("job_expired", problem!.Code);
        Assert.NotNull(problem.JobId);
    }

    [Fact]
    public async Task Client_cancellation_stops_waiting_but_keeps_and_dispatches_job()
    {
        var dispatcher = new RecordingDispatcher();
        var notifier = new BlockingNotifier();
        await using var factory = await TestServiceFactory.StartAsync(services =>
        {
            services.AddSingleton<IJobDispatcher>(dispatcher);
            services.AddSingleton<IJobCompletionNotifier>(notifier);
        });
        using var client = factory.CreateAuthenticatedClient();
        using var cancellation = new CancellationTokenSource();
        var responseTask = client.SendAsync(TestUploads.PdfRequest(uri: "/v1/sign?waitSeconds=120"), cancellation.Token);
        await notifier.WaitStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => responseTask);
        var jobId = Assert.Single(dispatcher.JobIds);
        Assert.NotNull(await factory.Services.GetRequiredService<IJobStore>().GetAsync(jobId));
        Assert.Single(factory.SpoolJobDirectories());
    }

    [Fact]
    public async Task Cancellation_while_reading_parameters_after_file_removes_completed_input_spool()
    {
        await using var factory = await TestServiceFactory.StartAsync();
        using var client = factory.CreateAuthenticatedClient();
        using var content = GatedMultipartContent.FileThenBlockedParameters();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/jobs") { Content = content };
        using var cancellation = new CancellationTokenSource();
        var responseTask = client.SendAsync(request, cancellation.Token);
        await content.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await factory.WaitForSpoolEntryAsync("input.pdf");

        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => responseTask);
        await factory.AssertSpoolEventuallyEmptyAsync();
    }

    [Fact]
    public async Task Cancellation_while_writing_file_removes_partial_and_empty_job_directory()
    {
        await using var factory = await TestServiceFactory.StartAsync();
        using var client = factory.CreateAuthenticatedClient();
        using var content = GatedMultipartContent.BlockedFile();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/jobs") { Content = content };
        using var cancellation = new CancellationTokenSource();
        var responseTask = client.SendAsync(request, cancellation.Token);
        await content.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await factory.WaitForSpoolEntryAsync("input.pdf.part");

        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => responseTask);
        await factory.AssertSpoolEventuallyEmptyAsync();
    }

    [Fact]
    public async Task Status_database_failure_returns_safe_internal_error_problem()
    {
        await using var factory = await TestServiceFactory.StartAsync(services =>
            services.AddSingleton<IJobStore>(new ThrowingGetJobStore()));
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.GetAsync($"/v1/jobs/{Guid.NewGuid()}");
        var json = await response.Content.ReadAsStringAsync();
        var problem = JsonSerializer.Deserialize<ApiProblem>(json, JsonSerializerOptions.Web);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType!.MediaType);
        Assert.Equal("internal_error", problem!.Code);
        Assert.False(string.IsNullOrWhiteSpace(problem.CorrelationId));
        Assert.DoesNotContain("database /private/secret", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Result_spool_io_failure_returns_safe_internal_error_problem()
    {
        var job = TestJobs.Create(JobState.Succeeded) with { ResultSha256 = new string('a', 64), ResultSize = 11 };
        await using var factory = await TestServiceFactory.StartAsync(services =>
            services.AddSingleton<IJobStore>(new StaticJobStore(job)));
        var spool = Assert.IsType<SpoolStore>(factory.Services.GetRequiredService<ISpoolStore>());
        var resultPath = spool.GetResultPath(job.Id, job.Extension);
        await File.WriteAllTextAsync(resultPath, "%PDF-result");
        await using var exclusiveLock = new FileStream(resultPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.GetAsync($"/v1/jobs/{job.Id}/result");
        var json = await response.Content.ReadAsStringAsync();
        var problem = JsonSerializer.Deserialize<ApiProblem>(json, JsonSerializerOptions.Web);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType!.MediaType);
        Assert.Equal("internal_error", problem!.Code);
        Assert.DoesNotContain(resultPath, json, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(121)]
    public async Task Sign_rejects_wait_seconds_outside_contract(int waitSeconds)
    {
        await using var factory = await TestServiceFactory.StartAsync();
        using var client = factory.CreateAuthenticatedClient();

        using var response = await client.SendAsync(TestUploads.PdfRequest(uri: $"/v1/sign?waitSeconds={waitSeconds}"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(factory.SpoolJobDirectories());
    }

    [Fact]
    public async Task Notifier_does_not_lose_completion_that_arrives_before_waiter()
    {
        var job = TestJobs.Create(JobState.Succeeded) with { ResultSha256 = new string('a', 64) };
        var jobs = new NotifierJobStore(job);
        var notifier = new JobCompletionNotifier(jobs);

        notifier.Notify(job);
        var received = await notifier.WaitAsync(job.Id, CancellationToken.None);

        Assert.Equal(job, received);
    }

    [Fact]
    public async Task Notifier_does_not_resurrect_retired_job_after_delayed_old_notification()
    {
        var queued = TestJobs.Create();
        var jobs = new NotifierJobStore(queued);
        var notifier = new JobCompletionNotifier(jobs);
        var waiting = notifier.WaitAsync(queued.Id, CancellationToken.None);
        var expired = queued with { State = JobState.Expired, ErrorCode = "job_expired" };

        jobs.Current = expired;
        notifier.Retire(expired);
        Assert.Equal(expired, await waiting);
        notifier.Notify(queued with { State = JobState.Failed, ErrorCode = "internal_error" });

        var observed = await notifier.WaitAsync(queued.Id, CancellationToken.None);
        Assert.Equal(JobState.Expired, observed.State);
    }

    [Fact]
    public async Task Retire_wins_when_old_notification_already_located_waiters()
    {
        using var oldNotificationLocated = new ManualResetEventSlim();
        var queued = TestJobs.Create();
        var jobs = new NotifierJobStore(queued);
        var notifier = new JobCompletionNotifier(jobs);
        var waiting = notifier.WaitAsync(queued.Id, CancellationToken.None);
        var waiters = typeof(JobCompletionNotifier)
            .GetField("_waiters", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(notifier)!;
        object?[] lookupArguments = [queued.Id, null];
        Assert.True((bool)waiters.GetType().GetMethod("TryGetValue")!.Invoke(waiters, lookupArguments)!);
        var capturedBucket = lookupArguments[1]!;
        var bucketLock = capturedBucket.GetType()
            .GetField("_lock", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(capturedBucket)!;
        var notifyBucket = capturedBucket.GetType().GetMethod("Notify")!;
        var oldFailure = queued with { State = JobState.Failed, ErrorCode = "internal_error" };
        Task oldNotification;
        Monitor.Enter(bucketLock);
        try
        {
            oldNotification = Task.Run(() =>
            {
                oldNotificationLocated.Set();
                notifyBucket.Invoke(capturedBucket, [oldFailure]);
            });
            Assert.True(oldNotificationLocated.Wait(TimeSpan.FromSeconds(5)));
            var expired = queued with { State = JobState.Expired, ErrorCode = "job_expired" };
            jobs.Current = expired;
            notifier.Retire(expired);
        }
        finally
        {
            Monitor.Exit(bucketLock);
        }

        await oldNotification;
        Assert.Equal(JobState.Expired, (await waiting).State);
        Assert.Equal(JobState.Expired, (await notifier.WaitAsync(queued.Id, CancellationToken.None)).State);
    }

    [Fact]
    public async Task Canceling_one_waiter_does_not_cancel_the_job_or_other_waiters()
    {
        var queued = TestJobs.Create();
        var jobs = new NotifierJobStore(queued);
        var notifier = new JobCompletionNotifier(jobs);
        using var cancellation = new CancellationTokenSource();
        var canceledWait = notifier.WaitAsync(queued.Id, cancellation.Token);
        var survivingWait = notifier.WaitAsync(queued.Id, CancellationToken.None);

        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await canceledWait);
        var failed = queued with { State = JobState.Failed, ErrorCode = "internal_error" };
        jobs.Current = failed;
        notifier.Notify(failed);

        Assert.Equal(failed, await survivingWait);
        Assert.Equal(0, notifier.PendingCount);
    }

    [Fact]
    public async Task Forget_discards_registered_waiters_and_late_notifications_cannot_complete_them()
    {
        var queued = TestJobs.Create();
        var jobs = new NotifierJobStore(queued);
        var registration = new RecordingWaitRegistrationObserver();
        var notifier = new JobCompletionNotifier(jobs, registration);
        using var cancellation = new CancellationTokenSource();
        var waiting = notifier.WaitAsync(queued.Id, cancellation.Token);
        Assert.Equal(queued.Id, await registration.Registered.WaitAsync(TimeSpan.FromSeconds(1)));

        notifier.Forget(queued.Id);
        notifier.Notify(queued with { State = JobState.Succeeded, ResultSha256 = new string('a', 64) });
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        Assert.Equal(0, notifier.PendingCount);
    }

    [Fact]
    public async Task Notifier_public_boundaries_reject_invalid_identifiers_states_and_nulls()
    {
        var queued = TestJobs.Create();
        var jobs = new NotifierJobStore(queued);
        var notifier = new JobCompletionNotifier(jobs);

        Assert.Throws<ArgumentNullException>(() => new JobCompletionNotifier(null!));
        Assert.Throws<ArgumentNullException>(() =>
            new JobCompletionNotifier(jobs, null!));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            notifier.WaitAsync(Guid.Empty, CancellationToken.None));
        Assert.Throws<ArgumentNullException>(() => notifier.Notify(null!));
        Assert.Throws<ArgumentException>(() => notifier.Forget(Guid.Empty));
        Assert.Throws<ArgumentNullException>(() => notifier.Retire(null!));
        Assert.Throws<ArgumentException>(() => notifier.Retire(queued));

        notifier.Forget(Guid.NewGuid());
        notifier.Notify(queued);
        notifier.Retire(queued with { State = JobState.Expired });
        Assert.Equal(0, notifier.PendingCount);
    }

    private static AgentHealthSnapshot PdfSupportNotInstalledHealth() =>
        PdfSupportHealth("absent")!;

    private static AgentHealthSnapshot? PdfSupportHealth(string mutation)
    {
        if (mutation == "disconnected")
        {
            return null;
        }

        var authenticode = ProtocolV3TestFixtures.ReadyCapability("authenticode");
        var readyPdf = ProtocolV3TestFixtures.ReadyCapability("pdf");
        var pdfSession = mutation == "nested_session_mismatch"
            ? ProtocolV3TestFixtures.ReadySession("pdf", sessionId: 8)
            : readyPdf.Session;
        var pdf = new CapabilitySnapshot(
            true,
            readyPdf.TokenPresent,
            readyPdf.TokenMatches,
            readyPdf.TokenSuffix,
            readyPdf.CertificatePresent,
            readyPdf.CertificateMatches,
            readyPdf.CertificateSuffix,
            readyPdf.PrivateKeyPresent,
            readyPdf.PrivateKeyMatches,
            readyPdf.PrivateKeySuffix,
            false,
            mutation == "tampered" ? "pdf_helper_tampered" : "pdf_support_not_installed",
            readyPdf.CertificateNotAfterUtc,
            readyPdf.CertificateThumbprintSuffix,
            pdfSession);
        var heartbeat = new AgentHeartbeat(
            7,
            "ready",
            "ready",
            "ready",
            "ready",
            null,
            mutation == "process_session_mismatch" ? 8 : 7,
            authenticode,
            pdf,
            1,
            certificates: [TestAgentHealth.Certificate("6F09D233")]);
        return new AgentHealthSnapshot(
            Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            7,
            ["authenticode", "pdf"],
            mutation == "stale"
                ? CapabilityNow - AgentPipeServer.HeartbeatTimeout - TimeSpan.FromMilliseconds(1)
                : CapabilityNow,
            heartbeat);
    }
}

internal sealed class RecordingWaitRegistrationObserver : IJobWaitRegistrationObserver
{
    private readonly TaskCompletionSource<Guid> _registered =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public Task<Guid> Registered => _registered.Task;

    public void OnRegistered(Guid jobId) => _registered.TrySetResult(jobId);
}

internal sealed class NotifierJobStore(Job initial) : IJobStore
{
    private readonly Lock _lock = new();
    private Job _current = initial;

    public Job Current
    {
        get
        {
            lock (_lock)
            {
                return _current;
            }
        }
        set
        {
            lock (_lock)
            {
                _current = value;
            }
        }
    }

    public Task<Job> CreateAsync(
        Job job,
        string? apiPrincipal = null,
        string? idempotencyKey = null,
        CancellationToken cancellationToken = default)
    {
        Current = job;
        return Task.FromResult(job);
    }

    public Task<Job?> GetAsync(Guid jobId, CancellationToken cancellationToken = default) =>
        Task.FromResult<Job?>(Current.Id == jobId ? Current : null);

    public Task CheckHealthAsync(CancellationToken cancellationToken = default) =>
        Task.FromException(new NotSupportedException());

    public Task<JobQueueSnapshot> GetQueueSnapshotAsync(CancellationToken cancellationToken = default) =>
        Task.FromException<JobQueueSnapshot>(new NotSupportedException());

    public Task<IReadOnlyList<Job>> GetAllAsync(CancellationToken cancellationToken = default) =>
        Task.FromException<IReadOnlyList<Job>>(new NotSupportedException());

    public Task<Job?> TryExpireNextAsync(
        DateTimeOffset cutoff,
        Func<Job, CancellationToken, Task> deleteJobAsync,
        CancellationToken cancellationToken = default) => Task.FromException<Job?>(new NotSupportedException());

    public Task<int> RecoverActiveLeasesAsync(CancellationToken cancellationToken = default) =>
        Task.FromException<int>(new NotSupportedException());

    public Task<int> RecoverInterruptedAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(0);
}

internal sealed class TestServiceFactory : IAsyncDisposable
{
    public const string Token = "f_6Hh4TnuKCTP_P8pNZ7o4BxBmHdviLOIMsXu38pudM";
    private readonly WebApplication _application;
    private readonly string _root;

    private TestServiceFactory(WebApplication application, HttpClient client, string root)
    {
        _application = application;
        Client = client;
        _root = root;
    }

    public HttpClient Client { get; }

    public IServiceProvider Services => _application.Services;

    public IReadOnlyList<string> SpoolJobDirectories() =>
        Directory.Exists(Path.Combine(_root, "spool"))
            ? Directory.GetDirectories(Path.Combine(_root, "spool"))
            : [];

    public async Task WaitForSpoolEntryAsync(string fileName)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!timeout.IsCancellationRequested)
        {
            if (SpoolJobDirectories().Any(directory => File.Exists(Path.Combine(directory, fileName))))
            {
                return;
            }

            await Task.Delay(10, timeout.Token);
        }

        throw new TimeoutException($"Spool entry {fileName} was not observed.");
    }

    public async Task AssertSpoolEventuallyEmptyAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!timeout.IsCancellationRequested)
        {
            if (SpoolJobDirectories().Count == 0)
            {
                return;
            }

            await Task.Delay(10, timeout.Token);
        }

        Assert.Empty(SpoolJobDirectories());
    }

    public HttpClient CreateAuthenticatedClient()
    {
        var client = _application.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        return client;
    }

    public static Task<TestServiceFactory> StartAsync(IJobDispatcher dispatcher) =>
        StartAsync(services => services.AddSingleton<IJobDispatcher>(dispatcher));

    public static Task<TestServiceFactory> StartAsync(int retentionHours, TimeProvider timeProvider) =>
        StartAsync(
            services => services.AddSingleton(timeProvider),
            retentionHours);

    public static async Task<TestServiceFactory> StartAsync(
        Action<IServiceCollection>? configureServices = null,
        int retentionHours = 24)
    {
        var root = Path.Combine(Path.GetTempPath(), "SimplySignAuto.Tests", Guid.NewGuid().ToString("N"));
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.WebHost.UseTestServer();
        ServiceHost.Configure(builder, new ServiceHostOptions(
            SHA256.HashData(Encoding.UTF8.GetBytes(Token)),
            Path.Combine(root, "jobs.db"),
            Path.Combine(root, "spool"))
        {
            ProductVersionIdentity = "1.0.0",
            RetentionHours = retentionHours,
        });
        builder.Services.AddSingleton<IUploadedContentValidator>(UnitTestUploadedContentValidator.Instance);
        builder.Services.AddSingleton<IAgentHealthStatusSource>(services =>
            new FixedAgentHealthStatusSource(TestAgentHealth.Ready(
                services.GetRequiredService<TimeProvider>().GetUtcNow().ToUniversalTime())));
        configureServices?.Invoke(builder.Services);

        var application = builder.Build();
        ServiceHost.MapPipeline(application);
        await application.StartAsync();
        return new TestServiceFactory(application, application.GetTestClient(), root);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _application.DisposeAsync();
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }
}

internal sealed class UnitTestUploadedContentValidator : IUploadedContentValidator
{
    public static UnitTestUploadedContentValidator Instance { get; } = new();

    public void Validate(string path, string extension, SigningParameters parameters)
    {
    }
}

internal sealed class FixedJobTimeProvider(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}

internal sealed class FixedAgentHealthStatusSource(AgentHealthSnapshot? health) : IAgentHealthStatusSource
{
    public AgentHealthSnapshot? CurrentHealth => health;
}

internal sealed class MutableAgentHealthStatusSource(AgentHealthSnapshot? health) : IAgentHealthStatusSource
{
    public AgentHealthSnapshot? CurrentHealth { get; set; } = health;
}

internal sealed class RecordingAdmissionPreparation(
    MutableAgentHealthStatusSource health,
    AgentHealthSnapshot? replacement) : IAgentOnDemandLogin
{
    public Task<bool> LoginAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        health.CurrentHealth = replacement;
        return Task.FromResult(replacement is not null);
    }
}

internal static class TestAgentHealth
{
    public static AgentHealthSnapshot Ready(
        DateTimeOffset now,
        IReadOnlyList<CertificateSummary>? certificates = null,
        DateTimeOffset? heartbeatAt = null)
    {
        var heartbeat = ProtocolV3TestFixtures.Heartbeat(
            certificates: certificates ?? [Certificate("6F09D233")]);
        return new AgentHealthSnapshot(
            Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            7,
            ["authenticode", "pdf"],
            heartbeatAt ?? now,
            heartbeat);
    }

    public static AgentHealthSnapshot LoginRequired(DateTimeOffset now)
    {
        var session = new SimplySignSessionSnapshot(
            SimplySignSessionState.LoginRequired,
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
            "login_required",
            0,
            null,
            true,
            7);
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
            "login_required",
            session: session);
        var heartbeat = new AgentHeartbeat(
            7,
            "login_required",
            "login_required",
            "login_required",
            "login_required",
            null,
            7,
            capability,
            capability,
            1,
            certificates: [Certificate("6F09D233")]);
        return new AgentHealthSnapshot(
            Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd"),
            7,
            ["authenticode", "pdf"],
            now,
            heartbeat);
    }

    public static AgentHealthSnapshot ProcessMissing(DateTimeOffset now)
    {
        var ready = Ready(now);
        var heartbeat = ready.Heartbeat!;
        return ready with
        {
            Heartbeat = new AgentHeartbeat(
                heartbeat.SessionId,
                "not_ready",
                heartbeat.TokenStatus,
                heartbeat.CertificateStatus,
                heartbeat.KeyStatus,
                heartbeat.CurrentJobId,
                simplySignProcessSessionId: null,
                heartbeat.Authenticode,
                heartbeat.Pdf,
                heartbeat.SessionGeneration,
                heartbeat.SessionTransitions,
                heartbeat.Certificates),
        };
    }

    public static CertificateSummary Certificate(
        string serialNumber,
        bool authenticode = true,
        bool pdf = true,
        bool catalogCurrent = true,
        string? unavailableReason = null) =>
        new(
            $"Certificate {serialNumber}",
            serialNumber,
            new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
            authenticode,
            pdf,
            catalogCurrent,
            unavailableReason);
}

internal static class TestUploads
{
    public static HttpRequestMessage AuthenticodeRequest(
        string uri = "/v1/jobs",
        bool fileFirst = false,
        string certificateSerialNumber = "6F09D233")
    {
        var parametersJson = $$"""
            {"kind":"authenticode","certificateSerialNumber":"{{certificateSerialNumber}}","digestAlgorithm":"sha256","appendSignature":false}
            """;
        return Request(parametersJson, "input.exe", "MZ-test-binary", uri, fileFirst);
    }

    public static HttpRequestMessage PdfRequest(
        string content = "%PDF-1.7\nbody",
        string uri = "/v1/jobs",
        bool fileFirst = false,
        string fileName = "input.pdf")
    {
        const string parametersJson = """
            {"kind":"pdf","certificateSerialNumber":"6F09D233","digestAlgorithm":"sha256","page":1,"box":[10,20,30,40],"fieldName":"Signature1"}
            """;
        return Request(parametersJson, fileName, content, uri, fileFirst);
    }

    public static HttpRequestMessage Request(
        string parametersJson,
        string fileName,
        string content,
        string uri = "/v1/jobs",
        bool fileFirst = false)
    {
        var multipart = new MultipartFormDataContent();
        var parameters = new StringContent(parametersJson, Encoding.UTF8, "application/json");
        var file = new ByteArrayContent(Encoding.ASCII.GetBytes(content));
        if (fileFirst)
        {
            multipart.Add(file, "file", fileName);
            multipart.Add(parameters, "parameters");
        }
        else
        {
            multipart.Add(parameters, "parameters");
            multipart.Add(file, "file", fileName);
        }

        return new HttpRequestMessage(HttpMethod.Post, uri) { Content = multipart };
    }

    public static HttpRequestMessage InvalidRequest(string kind)
    {
        const string parameters = """
            {"kind":"pdf","certificateSerialNumber":"6F09D233","digestAlgorithm":"sha256","page":1,"box":[10,20,30,40],"fieldName":"Signature1"}
            """;
        var multipart = new MultipartFormDataContent();
        if (kind != "missing_parameters")
        {
            multipart.Add(new StringContent(parameters, Encoding.UTF8, "application/json"), "parameters");
        }

        var content = kind switch
        {
            "empty" => string.Empty,
            "wrong_magic" => "not a pdf",
            _ => "%PDF-valid",
        };
        multipart.Add(new ByteArrayContent(Encoding.ASCII.GetBytes(content)), "file", "input.pdf");
        if (kind == "unknown_part")
        {
            multipart.Add(new StringContent("unexpected"), "unknown");
        }
        else if (kind == "duplicate_file")
        {
            multipart.Add(new ByteArrayContent("%PDF-second"u8.ToArray()), "file", "second.pdf");
        }

        return new HttpRequestMessage(HttpMethod.Post, "/v1/jobs") { Content = multipart };
    }

    public static HttpRequestMessage UnterminatedRequest()
    {
        const string body = "--broken\r\nContent-Disposition: form-data; name=\"file\"; filename=\"input.pdf\"\r\nContent-Type: application/pdf\r\n\r\n%PDF-body";
        var content = new StringContent(body, Encoding.ASCII);
        content.Headers.ContentType = MediaTypeHeaderValue.Parse("multipart/form-data; boundary=broken");
        return new HttpRequestMessage(HttpMethod.Post, "/v1/jobs") { Content = content };
    }
}

internal sealed class RecordingDispatcher : IJobDispatcher
{
    public List<Guid> JobIds { get; } = [];

    public void Enqueue(Guid jobId) => JobIds.Add(jobId);
}

internal sealed class MutationRecordingSpoolStore : ISpoolStore
{
    public int MutationCalls { get; private set; }

    public IReadOnlyList<SpoolJobDirectory> ValidateAndListJobDirectories() => [];

    public Task<SpoolFile> WriteInputAsync(
        Guid jobId,
        string extension,
        Stream input,
        long maxBytes,
        CancellationToken cancellationToken = default)
    {
        MutationCalls++;
        return Task.FromException<SpoolFile>(new InvalidOperationException("unexpected_spool_mutation"));
    }

    public Task<SpoolFile> PromoteResultAsync(
        Guid jobId,
        string extension,
        string expectedSha256,
        long expectedSize,
        CancellationToken cancellationToken = default) =>
        Task.FromException<SpoolFile>(new NotSupportedException());

    public Task DeleteJobAsync(Guid jobId, CancellationToken cancellationToken = default)
    {
        MutationCalls++;
        return Task.CompletedTask;
    }
}

internal sealed class CompletingDispatcher : IJobDispatcher
{
    private readonly IJobStore _jobs;
    private readonly SpoolStore _spool;
    private readonly IJobCompletionNotifier _notifier;

    public CompletingDispatcher(IJobStore jobs, SpoolStore spool, IJobCompletionNotifier notifier)
    {
        _jobs = jobs;
        _spool = spool;
        _notifier = notifier;
    }

    public void Enqueue(Guid jobId)
    {
        var connectionId = Guid.NewGuid();
        var job = _jobs.ClaimNextAsync(connectionId).GetAwaiter().GetResult()!;
        if (job.Id != jobId ||
            !_jobs.TryMarkVerifyingAsync(job.Id, job.DispatchId!.Value, connectionId).GetAwaiter().GetResult())
        {
            throw new InvalidOperationException("Unable to start test completion.");
        }

        var bytes = "%PDF-signed"u8.ToArray();
        File.WriteAllBytes(_spool.GetResultPartPath(jobId, job.Extension), bytes);
        var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        if (!_jobs.TryRecordCompletionAsync(
                job.Id,
                job.DispatchId.Value,
                connectionId,
                bytes.Length,
                hash).GetAwaiter().GetResult())
        {
            throw new InvalidOperationException("Unable to record test completion.");
        }

        _spool.PromoteResultAsync(jobId, job.Extension, hash, bytes.Length).GetAwaiter().GetResult();
        if (!_jobs.TryFinishSuccessAsync(job.Id, job.DispatchId.Value, connectionId).GetAwaiter().GetResult())
        {
            throw new InvalidOperationException("Unable to finish test completion.");
        }

        _notifier.Notify(_jobs.GetAsync(jobId).GetAwaiter().GetResult()!);
    }
}

internal sealed class BlockingNotifier : IJobCompletionNotifier
{
    public TaskCompletionSource WaitStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public async Task<Job> WaitAsync(Guid jobId, CancellationToken cancellationToken)
    {
        WaitStarted.TrySetResult();
        await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        throw new InvalidOperationException("unreachable");
    }

    public void Notify(Job job)
    {
    }

    public void Forget(Guid jobId)
    {
    }

    public void Retire(Job job)
    {
    }
}

internal sealed class ExpiredNotifier : IJobCompletionNotifier
{
    public Task<Job> WaitAsync(Guid jobId, CancellationToken cancellationToken) =>
        Task.FromResult(TestJobs.Create(JobState.Expired) with
        {
            Id = jobId,
            ErrorCode = "job_expired",
            ErrorMessage = "job_expired",
        });

    public void Notify(Job job)
    {
    }

    public void Forget(Guid jobId)
    {
    }

    public void Retire(Job job)
    {
    }
}

internal sealed class RejectingSpoolStore : ISpoolStore
{
    public List<Guid> DeletedJobIds { get; } = [];

    public long MaxBytes { get; private set; }

    public IReadOnlyList<SpoolJobDirectory> ValidateAndListJobDirectories() => [];

    public Task<SpoolFile> WriteInputAsync(Guid jobId, string extension, Stream input, long maxBytes, CancellationToken cancellationToken = default)
    {
        MaxBytes = maxBytes;
        throw new SpoolException("file_too_large");
    }

    public Task<SpoolFile> PromoteResultAsync(Guid jobId, string extension, string expectedSha256, long expectedSize, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException();

    public Task DeleteJobAsync(Guid jobId, CancellationToken cancellationToken = default)
    {
        DeletedJobIds.Add(jobId);
        return Task.CompletedTask;
    }

    public Task DeleteStalePartsAsync(Job job, DateTimeOffset cutoff, CancellationToken cancellationToken = default) =>
        Task.FromException(new NotSupportedException());

    public Task DeleteSucceededTransientFilesAsync(Job job, CancellationToken cancellationToken = default) =>
        Task.FromException(new NotSupportedException());

    public Task QuarantineAsync(SpoolJobDirectory directory, CancellationToken cancellationToken = default) =>
        Task.FromException(new NotSupportedException());
}

internal sealed class ThrowingJobStore : IJobStore
{
    public Task<Job> CreateAsync(Job job, string? apiPrincipal = null, string? idempotencyKey = null, CancellationToken cancellationToken = default) =>
        throw new IOException("database path /private/secret/jobs.db");

    public Task<Job?> GetAsync(Guid jobId, CancellationToken cancellationToken = default) => Task.FromResult<Job?>(null);

    public Task CheckHealthAsync(CancellationToken cancellationToken = default) =>
        Task.FromException(new IOException("database path /private/secret/jobs.db"));

    public Task<JobQueueSnapshot> GetQueueSnapshotAsync(CancellationToken cancellationToken = default) =>
        Task.FromException<JobQueueSnapshot>(new NotSupportedException());

    public Task<IReadOnlyList<Job>> GetAllAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<Job>>([]);

    public Task<Job?> TryExpireNextAsync(
        DateTimeOffset cutoff,
        Func<Job, CancellationToken, Task> deleteJobAsync,
        CancellationToken cancellationToken = default) => Task.FromException<Job?>(new NotSupportedException());

    public Task<int> RecoverActiveLeasesAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);

    public Task<bool> TryTransitionAsync(Guid jobId, JobState expectedState, JobState nextState, CancellationToken cancellationToken = default) =>
        Task.FromResult(false);

    public Task<int> RecoverInterruptedAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);

}

internal sealed class ThrowingGetJobStore : IJobStore
{
    public Task<Job> CreateAsync(Job job, string? apiPrincipal = null, string? idempotencyKey = null, CancellationToken cancellationToken = default) =>
        Task.FromResult(job);

    public Task<Job?> GetAsync(Guid jobId, CancellationToken cancellationToken = default) =>
        throw new IOException("database /private/secret/jobs.db failed");

    public Task CheckHealthAsync(CancellationToken cancellationToken = default) =>
        Task.FromException(new IOException("database /private/secret/jobs.db failed"));

    public Task<JobQueueSnapshot> GetQueueSnapshotAsync(CancellationToken cancellationToken = default) =>
        Task.FromException<JobQueueSnapshot>(new IOException("database /private/secret/jobs.db failed"));

    public Task<IReadOnlyList<Job>> GetAllAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<Job>>([]);

    public Task<Job?> TryExpireNextAsync(
        DateTimeOffset cutoff,
        Func<Job, CancellationToken, Task> deleteJobAsync,
        CancellationToken cancellationToken = default) => Task.FromException<Job?>(new NotSupportedException());

    public Task<int> RecoverActiveLeasesAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);

    public Task<bool> TryTransitionAsync(Guid jobId, JobState expectedState, JobState nextState, CancellationToken cancellationToken = default) =>
        Task.FromResult(false);

    public Task<int> RecoverInterruptedAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);

}

internal sealed class StaticJobStore : IJobStore
{
    private readonly Job _job;

    public StaticJobStore(Job job)
    {
        _job = job;
    }

    public Task<Job> CreateAsync(Job job, string? apiPrincipal = null, string? idempotencyKey = null, CancellationToken cancellationToken = default) =>
        Task.FromResult(job);

    public Task<Job?> GetAsync(Guid jobId, CancellationToken cancellationToken = default) =>
        Task.FromResult(jobId == _job.Id ? _job : null);

    public Task CheckHealthAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

    public Task<JobQueueSnapshot> GetQueueSnapshotAsync(CancellationToken cancellationToken = default) =>
        Task.FromException<JobQueueSnapshot>(new NotSupportedException());

    public Task<IReadOnlyList<Job>> GetAllAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<Job>>([]);

    public Task<Job?> TryExpireNextAsync(
        DateTimeOffset cutoff,
        Func<Job, CancellationToken, Task> deleteJobAsync,
        CancellationToken cancellationToken = default) => Task.FromException<Job?>(new NotSupportedException());

    public Task<int> RecoverActiveLeasesAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);

    public Task<bool> TryTransitionAsync(Guid jobId, JobState expectedState, JobState nextState, CancellationToken cancellationToken = default) =>
        Task.FromResult(false);

    public Task<int> RecoverInterruptedAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);

}

internal sealed class InMemoryRetentionJobStore : IJobStore, ILocalUploadLeaseStore
{
    private readonly Dictionary<Guid, Job> _jobs = [];
    private readonly Dictionary<Guid, LocalUploadLeaseRecord> _leases = [];

    public Task<Job> CreateAsync(
        Job job,
        string? apiPrincipal = null,
        string? idempotencyKey = null,
        CancellationToken cancellationToken = default)
    {
        _jobs.Add(job.Id, job);
        return Task.FromResult(job);
    }

    public Task<Job?> GetAsync(Guid jobId, CancellationToken cancellationToken = default) =>
        Task.FromResult(_jobs.GetValueOrDefault(jobId));

    public Task<IReadOnlyList<Job>> GetAllAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<Job>>(_jobs.Values.ToArray());

    public Task<Job?> TryExpireNextAsync(
        DateTimeOffset cutoff,
        Func<Job, CancellationToken, Task> deleteJobAsync,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<Job?>(null);

    public Task<int> RecoverActiveLeasesAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(0);

    public Task<int> RecoverInterruptedAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(0);

    public Task<LocalLeaseCreateOutcome> CreateOrGetLocalLeaseAsync(
        LocalUploadLeaseRecord lease,
        CancellationToken cancellationToken = default)
    {
        if (_leases.TryGetValue(lease.RequestId, out var existing))
        {
            return Task.FromResult(new LocalLeaseCreateOutcome(existing, false));
        }

        _leases.Add(lease.RequestId, lease);
        return Task.FromResult(new LocalLeaseCreateOutcome(lease, true));
    }

    public Task<LocalUploadLeaseRecord?> GetLocalLeaseAsync(
        Guid requestId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(_leases.GetValueOrDefault(requestId));

    public Task<LocalLeaseAcceptOutcome> AcceptLocalLeaseAsync(
        Guid requestId,
        Job job,
        CancellationToken cancellationToken = default)
    {
        var lease = _leases[requestId];
        if (lease.AcceptedJobId is { } acceptedJobId)
        {
            return Task.FromResult(new LocalLeaseAcceptOutcome(_jobs[acceptedJobId], false));
        }

        _jobs.Add(job.Id, job);
        _leases[requestId] = lease with { AcceptedJobId = job.Id };
        return Task.FromResult(new LocalLeaseAcceptOutcome(job, true));
    }

    public Task<LocalUploadLeaseRecord?> GetNextExpiredLocalLeaseAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(_leases.Values
            .Where(lease => lease.AcceptedJobId is null && lease.ExpiresAtUtc <= cutoff)
            .OrderBy(lease => lease.ExpiresAtUtc)
            .FirstOrDefault());

    public Task<IReadOnlyList<LocalUploadLeaseRecord>> GetUnacceptedLocalLeasesAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<LocalUploadLeaseRecord>>(_leases.Values
            .Where(lease => lease.AcceptedJobId is null && lease.ExpiresAtUtc > now)
            .ToArray());

    public Task<bool> DeleteLocalLeaseAsync(
        Guid requestId,
        Guid jobId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(
            _leases.TryGetValue(requestId, out var lease) &&
            lease.JobId == jobId &&
            _leases.Remove(requestId));
}

internal sealed class GatedMultipartContent : HttpContent
{
    private const string Boundary = "cancel-boundary";
    private readonly bool _completeFilePart;

    private GatedMultipartContent(bool completeFilePart)
    {
        _completeFilePart = completeFilePart;
        Headers.ContentType = MediaTypeHeaderValue.Parse($"multipart/form-data; boundary={Boundary}");
    }

    public TaskCompletionSource Blocked { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public static GatedMultipartContent FileThenBlockedParameters() => new(completeFilePart: true);

    public static GatedMultipartContent BlockedFile() => new(completeFilePart: false);

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
        SerializeAsync(stream, CancellationToken.None);

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken) =>
        SerializeAsync(stream, cancellationToken);

    protected override bool TryComputeLength(out long length)
    {
        length = 0;
        return false;
    }

    private async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
    {
        var prefix = $"--{Boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"input.pdf\"\r\nContent-Type: application/pdf\r\n\r\n%PDF-partial";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(prefix), cancellationToken);
        if (_completeFilePart)
        {
            var parametersStart = $"\r\n--{Boundary}\r\nContent-Disposition: form-data; name=\"parameters\"\r\nContent-Type: application/json\r\n\r\n{{";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(parametersStart), cancellationToken);
        }

        await stream.FlushAsync(cancellationToken);
        Blocked.TrySetResult();
        await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
    }
}

internal static class TestJobs
{
    public static Job Create(JobState state = JobState.Queued) =>
        new(Guid.NewGuid(), state, new PdfParameters("6F09D233", "sha256", 1, new PdfBox(10, 20, 30, 40), "Signature1", null, null))
        {
            OriginalName = "input.pdf",
            Extension = ".pdf",
            InputSha256 = new string('b', 64),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(24),
        };
}
