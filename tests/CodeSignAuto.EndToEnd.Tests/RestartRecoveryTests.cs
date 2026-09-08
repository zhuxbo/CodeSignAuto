using System.Net.Http.Json;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Service.Api;
using Xunit;

namespace CodeSignAuto.EndToEnd.Tests;

public sealed class RestartRecoveryTests
{
    [Fact]
    public async Task Rejected_old_connection_after_restart_does_not_consume_attempt_two()
    {
        var root = Directory.CreateTempSubdirectory("SSA-E2E-RESTART-BAD-CONNECTION-").FullName;
        Guid jobId;
        try
        {
            await using (var first = await EndToEndHarness.StartAsync(root, deleteRoot: false))
            {
                await first.StartAgentAsync(FakeAgentBehavior.HoldBeforeSigning);
                jobId = await UploadAsync(first, "restart-bad-old-connection");
                await first.Agent.HeldBeforeSigningReached.WaitAsync(TimeSpan.FromSeconds(10));
                Assert.Equal(1, (await first.Jobs.GetAsync(jobId))!.AttemptCount);
            }

            await using (var restarted = await EndToEndHarness.StartAsync(root, deleteRoot: true))
            {
                Assert.True(await restarted.SendHelloAndObserveCloseAsync(new CodeSignAuto.Protocol.AgentHello(
                    CodeSignAuto.Protocol.LengthPrefixedJsonProtocol.ProtocolVersion,
                    Environment.ProcessId,
                    7,
                    "S-1-5-21-9-9-9-9",
                    "1.0.0",
                    ["pdf"])));
                var afterRejected = Assert.IsType<Job>(await restarted.Jobs.GetAsync(jobId));
                Assert.Equal(1, afterRejected.AttemptCount);
                Assert.True(afterRejected.State is JobState.Queued or JobState.WaitingForAgent);

                await restarted.StartAgentAsync();
                var recovered = await restarted.Agent.ReadNextCommandAsync();
                Assert.Equal(jobId, recovered.JobId);
                Assert.Equal(2, recovered.AttemptNumber);
                _ = await restarted.WaitForStateAsync(jobId, "succeeded");
            }
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public async Task Restart_keeps_success_requeues_one_active_attempt_and_preserves_fifo()
    {
        var root = Directory.CreateTempSubdirectory("SSA-E2E-RESTART-").FullName;
        Guid firstId;
        Guid secondId;
        Guid thirdId;
        string firstResultHash;
        try
        {
            await using (var first = await EndToEndHarness.StartAsync(root, deleteRoot: false))
            {
                await first.StartAgentAsync(FakeAgentBehavior.HoldSecondBeforeSigning);
                firstId = await UploadAsync(first, "restart-first");
                Assert.Equal(firstId, (await first.Agent.ReadNextCommandAsync()).JobId);
                firstResultHash = (await first.WaitForStateAsync(firstId, "succeeded")).ResultSha256!;

                secondId = await UploadAsync(first, "restart-second");
                var secondCommand = await first.Agent.ReadNextCommandAsync();
                Assert.Equal(secondId, secondCommand.JobId);
                await first.Agent.HeldBeforeSigningReached.WaitAsync(TimeSpan.FromSeconds(10));
                var secondBeforeStop = Assert.IsType<Job>(await first.Jobs.GetAsync(secondId));
                Assert.Equal(JobState.Signing, secondBeforeStop.State);
                Assert.Equal(1, secondBeforeStop.AttemptCount);

                thirdId = await UploadAsync(first, "restart-third");
                var thirdBeforeStop = Assert.IsType<Job>(await first.Jobs.GetAsync(thirdId));
                Assert.Equal(JobState.Queued, thirdBeforeStop.State);
                Assert.Equal(0, thirdBeforeStop.AttemptCount);
                Assert.Equal(1, first.Agent.MaxConcurrency);
            }

            await using (var second = await EndToEndHarness.StartAsync(root, deleteRoot: true))
            {
                var firstAfterRestart = Assert.IsType<Job>(await second.Jobs.GetAsync(firstId));
                Assert.Equal(JobState.Succeeded, firstAfterRestart.State);
                Assert.Equal(firstResultHash, firstAfterRestart.ResultSha256);

                await second.StartAgentAsync();
                var recoveredSecond = await second.Agent.ReadNextCommandAsync();
                Assert.Equal(secondId, recoveredSecond.JobId);
                Assert.Equal(2, recoveredSecond.AttemptNumber);
                _ = await second.WaitForStateAsync(secondId, "succeeded");

                var queuedThird = await second.Agent.ReadNextCommandAsync();
                Assert.Equal(thirdId, queuedThird.JobId);
                Assert.Equal(1, queuedThird.AttemptNumber);
                _ = await second.WaitForStateAsync(thirdId, "succeeded");

                Assert.Equal([secondId, thirdId], second.Agent.ReceivedCommands.Select(command => command.JobId));
                Assert.Equal(1, second.Agent.MaxConcurrency);
                var all = await second.Jobs.GetAllAsync();
                Assert.Equal(3, all.Count);
                Assert.All(all, job => Assert.Equal(JobState.Succeeded, job.State));
            }
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Assert.DoesNotContain(
                    Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories),
                    path => (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0);
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static async Task<Guid> UploadAsync(EndToEndHarness harness, string idempotencyKey)
    {
        using var response = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest("/v1/jobs", idempotencyKey: idempotencyKey));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<CreateJobResponse>())!.JobId;
    }
}
