using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Protocol;
using SimplySignAuto.Service.Api;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class SecurityBoundaryTests
{
    [Fact]
    public async Task Declared_request_limit_plus_one_is_rejected_before_any_body_byte_is_sent()
    {
        await using var harness = await EndToEndHarness.StartAsync();

        var status = await harness.SendHeadersOnlyAsync(JobEndpoints.MaxRequestBodyBytes + 1);

        Assert.Equal((int)HttpStatusCode.RequestEntityTooLarge, status);
        Assert.Empty(await harness.Jobs.GetAllAsync());
    }

    [Fact]
    public async Task Oversized_parameters_and_multiple_file_sections_are_rejected_by_real_multipart_parsing()
    {
        await using var harness = await EndToEndHarness.StartAsync();

        using var oversizedParameters = EndToEndFixtures.PdfRequest(
            "/v1/jobs",
            parametersJson: new string('x', JobEndpoints.MaxParametersBytes + 1));
        using var oversizedResponse = await harness.Client.SendAsync(oversizedParameters);
        Assert.Equal(HttpStatusCode.BadRequest, oversizedResponse.StatusCode);

        await harness.StartAgentAsync();
        using var duplicateFile = EndToEndFixtures.PdfRequest("/v1/jobs");
        var multipart = Assert.IsType<MultipartFormDataContent>(duplicateFile.Content);
        multipart.Add(new ByteArrayContent(EndToEndFixtures.TwoPagePdf), "file", "second.pdf");
        using var duplicateResponse = await harness.Client.SendAsync(duplicateFile);
        Assert.Equal(HttpStatusCode.BadRequest, duplicateResponse.StatusCode);
        Assert.Empty(await harness.Jobs.GetAllAsync());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Malformed_multipart_or_oversized_boundary_is_rejected_without_a_job(bool oversizedBoundary)
    {
        await using var harness = await EndToEndHarness.StartAsync();
        var boundary = oversizedBoundary
            ? new string('b', JobEndpoints.MaxBoundaryBytes + 1)
            : "ssa-malformed-boundary";
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/jobs");
        request.Content = new ByteArrayContent(
            oversizedBoundary
                ? "ignored"u8.ToArray()
                : Encoding.ASCII.GetBytes(
                    $"--{boundary}\r\nContent-Disposition: form-data; name=\"parameters\"\r\n\r\n{{}}"));
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("multipart/form-data");
        request.Content.Headers.ContentType.Parameters.Add(
            new System.Net.Http.Headers.NameValueHeaderValue("boundary", boundary));

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(await harness.Jobs.GetAllAsync());
    }

    [Theory]
    [InlineData("fake-pdf")]
    [InlineData("fake-pe")]
    [InlineData("extension-magic-mismatch")]
    public async Task File_extension_and_container_magic_must_agree_on_real_http_upload(string mutation)
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync();
        var authenticode = SigningParameters.SerializeCanonical(
            new SimplySignAuto.Core.Jobs.AuthenticodeParameters("AA00", "sha256", false));
        using var request = mutation switch
        {
            "fake-pdf" => EndToEndFixtures.PdfRequest("/v1/jobs", "not-a-pdf"u8.ToArray()),
            "fake-pe" => EndToEndFixtures.PdfRequest(
                "/v1/jobs",
                "MZ-not-a-native-container"u8.ToArray(),
                fileName: "payload.exe",
                parametersJson: authenticode),
            _ => EndToEndFixtures.PdfRequest(
                "/v1/jobs",
                EndToEndFixtures.TwoPagePdf,
                fileName: "payload.exe",
                parametersJson: authenticode),
        };

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(await harness.Jobs.GetAllAsync());
    }

    [Fact]
    public async Task Multipart_filename_must_be_a_safe_literal_basename()
    {
        string[] invalidNames = ["../escape.pdf", "/tmp/escape.pdf", "C:\\escape.pdf", "document.pdf:secret"];
        foreach (var fileName in invalidNames)
        {
            await using var harness = await EndToEndHarness.StartAsync();

            using var response = await harness.Client.SendAsync(
                EndToEndFixtures.PdfRequest("/v1/jobs", fileName: fileName));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Empty(await harness.Jobs.GetAllAsync());
        }
    }

    [Fact]
    public async Task Missing_and_wrong_bearer_never_create_a_job()
    {
        await using var harness = await EndToEndHarness.StartAsync();
        harness.Client.DefaultRequestHeaders.Authorization = null;
        using var missing = await harness.Client.SendAsync(EndToEndFixtures.PdfRequest("/v1/jobs"));
        Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);

        harness.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "wrong-e2e-token");
        using var wrong = await harness.Client.SendAsync(EndToEndFixtures.PdfRequest("/v1/jobs"));
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Empty(await harness.Jobs.GetAllAsync());
    }

    [Theory]
    [InlineData("{\"box\":[10,10,100,50],\"certificateAlias\":\"document\",\"digestAlgorithm\":\"sha256\",\"fieldName\":\"Signature1\",\"kind\":\"pdf\",\"kind\":\"pdf\",\"page\":1,\"timestampAlias\":\"primary\"}")]
    [InlineData("{\"box\":[10,10,100,50],\"certificateAlias\":\"document\",\"digestAlgorithm\":\"sha256\",\"fieldName\":\"Signature1\",\"kind\":\"pdf\",\"page\":1,\"timestampAlias\":\"primary\",\"unknown\":true}")]
    [InlineData("{\"box\":[10,10,100,50],\"CertificateAlias\":\"document\",\"digestAlgorithm\":\"sha256\",\"fieldName\":\"Signature1\",\"kind\":\"pdf\",\"page\":1,\"timestampAlias\":\"primary\"}")]
    [InlineData("{\"box\":[10,10,100,50],\"certificateAlias\":\"arbitrary\",\"digestAlgorithm\":\"sha256\",\"fieldName\":\"Signature1\",\"kind\":\"pdf\",\"page\":1,\"timestampAlias\":\"primary\"}")]
    [InlineData("{\"box\":[10,10,100,50],\"certificateAlias\":\"document\",\"digestAlgorithm\":\"sha256\",\"fieldName\":\"Signature1\",\"kind\":\"pdf\",\"page\":1,\"timestampAlias\":\"https://evil.invalid/\"}")]
    public async Task Strict_parameters_and_alias_allowlists_reject_ambiguous_or_arbitrary_values(string json)
    {
        await using var harness = await EndToEndHarness.StartAsync();

        using var response = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest("/v1/jobs", parametersJson: json));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(await harness.Jobs.GetAllAsync());
    }

    [Theory]
    [InlineData(FakeAgentBehavior.ForgeHash)]
    [InlineData(FakeAgentBehavior.ForgeSize)]
    [InlineData(FakeAgentBehavior.PartialResult)]
    [InlineData(FakeAgentBehavior.AppendAfterMetadata)]
    public async Task Agent_result_metadata_is_verified_against_the_real_part(FakeAgentBehavior behavior)
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync(behavior);
        using var create = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest("/v1/jobs", idempotencyKey: "forged-result-" + behavior));
        var accepted = Assert.IsType<CreateJobResponse>(
            await create.Content.ReadFromJsonAsync<CreateJobResponse>());

        var failed = await harness.WaitForStateAsync(accepted.JobId, "failed");

        Assert.Equal("result_corrupt", failed.ErrorCode);
        Assert.Null(failed.ResultSha256);
        using var result = await harness.Client.GetAsync(accepted.ResultUrl);
        Assert.Equal(HttpStatusCode.Conflict, result.StatusCode);
        Assert.False(File.Exists(harness.Spool.GetResultPath(accepted.JobId, ".pdf")));
    }

    [Fact]
    public async Task Invalid_pipe_connections_are_retired_without_poisoning_the_next_agent()
    {
        await using var harness = await EndToEndHarness.StartAsync();
        Assert.True(await harness.SendOversizedPipeFrameAsync());
        Assert.True(await harness.SendRawPipeFrameAndObserveCloseAsync(
            "{\"version\":2,\"type\":\"agent_hello\",\"payload\":{" +
            $"\"protocolVersion\":2,\"processId\":{Environment.ProcessId},\"sessionId\":0," +
            "\"userSid\":\"S-1-5-21-1000-1001-1002-1003\",\"agentVersion\":\"1.0.0\"," +
            "\"capabilities\":[\"pdf\"]}}"));
        Assert.True(await harness.SendHelloAndObserveCloseAsync(new AgentHello(
            LengthPrefixedJsonProtocol.ProtocolVersion,
            Environment.ProcessId,
            7,
            "S-1-5-21-9-9-9-9",
            "1.0.0",
            ["pdf"])));

        await harness.StartAgentAsync();
        using var create = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest("/v1/jobs", idempotencyKey: "after-rogue-pipes"));
        var accepted = Assert.IsType<CreateJobResponse>(
            await create.Content.ReadFromJsonAsync<CreateJobResponse>());
        _ = await harness.WaitForStateAsync(accepted.JobId, "succeeded");
        Assert.Single(harness.Agent.ReceivedCommands);
    }

    [Fact]
    public async Task Pipe_unknown_duplicate_and_wrong_direction_responses_close_only_the_bad_connection()
    {
        await using var harness = await EndToEndHarness.StartAsync();
        Assert.True(await harness.SendRawPipeFrameAndObserveCloseAsync(
            "{\"version\":2,\"type\":\"unknown_message\",\"payload\":{}}"));
        var validHelloPayload =
            "\"type\":\"agent_hello\",\"payload\":{" +
            $"\"protocolVersion\":2,\"processId\":{Environment.ProcessId},\"sessionId\":7," +
            "\"userSid\":\"S-1-5-21-1000-1001-1002-1003\",\"agentVersion\":\"1.0.0\"," +
            "\"capabilities\":[\"pdf\"]}}";
        Assert.True(await harness.SendRawPipeFrameAndObserveCloseAsync(
            "{\"version\":2,\"version\":2," + validHelloPayload));
        Assert.True(await harness.SendRawPipeFrameAndObserveCloseAsync(
            "{\"Version\":2," + validHelloPayload));
        Assert.True(await harness.SendHelloThenMessageAndObserveCloseAsync(
            new JobPageResponse(Guid.NewGuid(), [], null, null, null)));

        await harness.StartAgentAsync();
        Assert.True(await harness.SendHelloAndObserveCloseAsync(new AgentHello(
            LengthPrefixedJsonProtocol.ProtocolVersion,
            Environment.ProcessId,
            7,
            "S-1-5-21-1000-1001-1002-1003",
            "1.0.0",
            ["pdf"])));
        using var create = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest("/v1/jobs", idempotencyKey: "after-pipe-matrix"));
        var accepted = Assert.IsType<CreateJobResponse>(
            await create.Content.ReadFromJsonAsync<CreateJobResponse>());
        _ = await harness.WaitForStateAsync(accepted.JobId, "succeeded");
        Assert.Single(harness.Agent.ReceivedCommands);
    }

    [Fact]
    public async Task Sensitive_output_scan_fails_on_mutations_and_accepts_the_real_harness_log()
    {
        var mutations = new[]
        {
            "Authorization: Bearer SSA_SYNTHETIC_TOKEN_MARKER",
            "otpauth://totp/Test?secret=SYNTHETICONLY",
            "current code 654321",
            "S-1-5-21-1000-1001-1002-1003",
            "/private/tmp/SSA_SYNTHETIC_FIXTURE",
            "System.ComponentModel.Win32Exception (5): native access denied",
        };
        Assert.All(mutations, mutation => Assert.NotEmpty(SensitiveOutputScanner.Find(mutation)));

        const string bareToken = "SSA_BARE_TOKEN_a2b3c4d5e6f7g8h9";
        Assert.Contains("exact_secret", SensitiveOutputScanner.Find(bareToken, bareToken));

        await using var harness = await EndToEndHarness.StartAsync();
        using var response = await harness.Client.GetAsync("/health/live");
        response.EnsureSuccessStatusCode();

        Assert.NotEmpty(harness.CapturedLog);
        Assert.DoesNotContain("Content root path", harness.CapturedLog, StringComparison.OrdinalIgnoreCase);
        Assert.True(
            SensitiveOutputScanner.Find(harness.CapturedLog, harness.BearerToken).Count == 0,
            harness.CapturedLog);
    }

    [Fact]
    public async Task Harness_logging_captures_information_and_exception_to_string_with_production_filters()
    {
        await using var harness = await EndToEndHarness.StartAsync();
        var logger = harness.Services.GetRequiredService<ILoggerFactory>().CreateLogger("SimplySignAuto.Tests.LoggingProbe");

        logger.LogInformation("safe_harness_information");
        logger.LogError(new InvalidOperationException("synthetic_native_detail"), "synthetic_harness_failure");

        Assert.Contains("safe_harness_information", harness.CapturedLog, StringComparison.Ordinal);
        Assert.Contains("System.InvalidOperationException: synthetic_native_detail", harness.CapturedLog, StringComparison.Ordinal);
    }
}
