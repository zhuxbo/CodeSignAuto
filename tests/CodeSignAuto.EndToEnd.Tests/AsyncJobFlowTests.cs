using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Service.Api;
using Xunit;

namespace CodeSignAuto.EndToEnd.Tests;

public sealed class AsyncJobFlowTests
{
    [Fact]
    public async Task Upload_poll_download_crosses_real_http_pipe_sqlite_and_spool_once()
    {
        await using var harness = await EndToEndHarness.StartAsync();
        var input = EndToEndFixtures.TwoPagePdf;
        var inputHash = Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
        const string idempotencyKey = "e2e-async-one";
        await harness.StartAgentAsync(FakeAgentBehavior.HoldBeforeTerminal);

        using var createdResponse = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest("/v1/jobs", input, idempotencyKey));
        Assert.Equal(HttpStatusCode.Accepted, createdResponse.StatusCode);
        var created = Assert.IsType<CreateJobResponse>(
            await createdResponse.Content.ReadFromJsonAsync<CreateJobResponse>());
        Assert.Equal("queued", created.State);

        var persistedBeforeSigning = Assert.IsType<Job>(await harness.Jobs.GetAsync(created.JobId));
        var inputPath = harness.Spool.GetInputPath(created.JobId, ".pdf");
        var inputWriteTime = File.GetLastWriteTimeUtc(inputPath);

        var command = await harness.Agent.WaitForCommandAsync();
        Assert.Equal(created.JobId, command.JobId);
        Assert.Equal(input.Length, command.InputSize);
        Assert.Equal(inputHash, command.InputSha256);
        _ = await harness.WaitForStateAsync(created.JobId, "verifying");
        Assert.Equal(input, await File.ReadAllBytesAsync(inputPath));
        Assert.Equal(inputWriteTime, File.GetLastWriteTimeUtc(inputPath));
        harness.Agent.ReleaseBeforeTerminal();

        var succeeded = await harness.WaitForStateAsync(created.JobId, "succeeded");
        using var resultResponse = await harness.Client.GetAsync(created.ResultUrl);
        Assert.Equal(HttpStatusCode.OK, resultResponse.StatusCode);
        var downloaded = await resultResponse.Content.ReadAsByteArrayAsync();
        var expected = input.Concat(FakeAgent.SafeTrailer).ToArray();
        Assert.Equal(expected, downloaded);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(expected)).ToLowerInvariant(), succeeded.ResultSha256);

        var persistedAfterSigning = Assert.IsType<Job>(await harness.Jobs.GetAsync(created.JobId));
        Assert.Equal("api", persistedAfterSigning.Source);
        Assert.Equal(persistedBeforeSigning.CorrelationId, persistedAfterSigning.CorrelationId);
        Assert.NotEqual(Guid.Empty, persistedAfterSigning.CorrelationId);

        using var retry = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest("/v1/jobs", input, idempotencyKey));
        var retried = Assert.IsType<CreateJobResponse>(
            await retry.Content.ReadFromJsonAsync<CreateJobResponse>());
        Assert.Equal(created.JobId, retried.JobId);

        var changed = input.ToArray();
        changed[^10] ^= 0x01;
        using var conflict = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest("/v1/jobs", changed, idempotencyKey));
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        Assert.Single(await harness.Jobs.GetAllAsync());
        Assert.Equal(1, harness.Agent.TerminalCount);
        Assert.Single(harness.Agent.ReceivedCommands);
        Assert.Equal(1, harness.Agent.MaxConcurrency);
    }
}
