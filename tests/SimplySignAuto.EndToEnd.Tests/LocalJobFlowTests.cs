using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Service.Api;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class LocalJobFlowTests
{
    [Fact]
    public async Task Lost_complete_response_reconnects_and_replays_the_same_local_request_once()
    {
        await using var harness = await EndToEndHarness.StartAsync(dropLocalCompleteResponseOnce: true);
        await harness.StartAgentAsync();
        var sourceDirectory = Directory.CreateDirectory(Path.Combine(harness.Root, "ambiguous"));
        var sourcePath = Path.Combine(sourceDirectory.FullName, "release.exe");
        await File.WriteAllBytesAsync(sourcePath, EndToEndFixtures.UnsignedPortableExecutable);
        await using var local = new LocalJobClient(harness.Agent.Client, harness.Spool.Root);

        var jobId = await local.CreateAndUploadAsync(
            sourcePath,
            new AuthenticodeParameters("AA00", "sha256", false),
            null,
            CancellationToken.None);

        _ = await harness.WaitForStateAsync(jobId, "succeeded");
        var jobs = await harness.Jobs.GetAllAsync();
        var persisted = Assert.Single(jobs);
        Assert.Equal(jobId, persisted.Id);
        Assert.Equal("local", persisted.Source);
        Assert.True(harness.Agent.ConnectionCount >= 2);
        Assert.NotEmpty(harness.Agent.ReceivedCommands);
        Assert.All(harness.Agent.ReceivedCommands, command => Assert.Equal(jobId, command.JobId));
        Assert.InRange(persisted.AttemptCount, 1, 2);
        Assert.Equal(1, harness.Agent.MaxConcurrency);
    }

    [Fact]
    public async Task Api_and_local_jobs_share_one_real_pipe_fifo_and_local_result_save()
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync(FakeAgentBehavior.HoldBeforeTerminal);

        using var apiResponse = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest("/v1/jobs", idempotencyKey: "fifo-api-first"));
        var apiJob = Assert.IsType<CreateJobResponse>(
            await apiResponse.Content.ReadFromJsonAsync<CreateJobResponse>());
        var firstCommand = await harness.Agent.ReadNextCommandAsync();
        Assert.Equal(apiJob.JobId, firstCommand.JobId);
        await harness.Agent.BeforeTerminalReached.WaitAsync(TimeSpan.FromSeconds(10));

        var sourceDirectory = Directory.CreateDirectory(Path.Combine(harness.Root, "source"));
        var sourcePath = Path.Combine(sourceDirectory.FullName, "release.exe");
        var sourceBytes = EndToEndFixtures.UnsignedPortableExecutable;
        await File.WriteAllBytesAsync(sourcePath, sourceBytes);
        var sourceHash = Convert.ToHexString(SHA256.HashData(sourceBytes)).ToLowerInvariant();
        var sourceWriteTime = File.GetLastWriteTimeUtc(sourcePath);
        await using var local = new LocalJobClient(harness.Agent.Client, harness.Spool.Root);

        var localJobId = await local.CreateAndUploadAsync(
            sourcePath,
            new AuthenticodeParameters("AA00", "sha256", false),
            progress: null,
            CancellationToken.None);
        var queuedLocal = Assert.IsType<Job>(await harness.Jobs.GetAsync(localJobId));
        Assert.Equal(JobState.Queued, queuedLocal.State);
        Assert.Equal("local", queuedLocal.Source);

        harness.Agent.ReleaseBeforeTerminal();
        _ = await harness.WaitForStateAsync(apiJob.JobId, "succeeded");
        var secondCommand = await harness.Agent.ReadNextCommandAsync();
        Assert.Equal(localJobId, secondCommand.JobId);
        var succeeded = await harness.WaitForStateAsync(localJobId, "succeeded");

        var destinationDirectory = Directory.CreateDirectory(Path.Combine(harness.Root, "saved"));
        var destination = Path.Combine(
            destinationDirectory.FullName,
            LocalJobClient.DefaultSignedCopyName("release.exe", ".exe"));
        var spoolResultPath = harness.Spool.GetResultPath(localJobId, ".exe");
        var spoolResultHash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(spoolResultPath))).ToLowerInvariant();
        await local.SaveSignedCopyAsync(localJobId, destination, overwrite: false, CancellationToken.None);

        Assert.Equal(sourceHash, Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(sourcePath))).ToLowerInvariant());
        Assert.Equal(sourceWriteTime, File.GetLastWriteTimeUtc(sourcePath));
        Assert.Equal(
            sourceBytes.Concat(FakeAgent.SafeTrailer).ToArray(),
            await File.ReadAllBytesAsync(destination));
        Assert.Equal(spoolResultHash, Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(spoolResultPath))).ToLowerInvariant());
        Assert.Equal(spoolResultHash, succeeded.ResultSha256);

        var jobsPage = await harness.Agent.Client.GetJobPageAsync(null, CancellationToken.None);
        var localItem = Assert.Single(jobsPage.Items, item => item.JobId == localJobId);
        Assert.Equal("local", localItem.Source);
        Assert.Equal("succeeded", localItem.State);
        Assert.True(localItem.HasResult);
        Assert.Equal([apiJob.JobId, localJobId], harness.Agent.ReceivedCommands.Select(command => command.JobId).ToArray());
        Assert.Equal(1, harness.Agent.MaxConcurrency);

        using var apiDownload = await harness.Client.GetAsync($"/v1/jobs/{localJobId:D}/result");
        Assert.Equal(HttpStatusCode.OK, apiDownload.StatusCode);
    }
}
