using System.Net.Http.Json;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Service.Api;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class AgentFailureMatrixTests
{
    [Fact]
    public async Task One_real_disconnect_after_a_flushed_result_retries_on_a_healthy_connection_and_succeeds()
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync(FakeAgentBehavior.DisconnectFirstAfterSign);

        var jobId = await UploadAsync(harness, "disconnect-once-recovers");
        _ = await harness.WaitForStateAsync(jobId, "succeeded");
        var stored = Assert.IsType<Job>(await harness.Jobs.GetAsync(jobId));

        Assert.Equal(2, stored.AttemptCount);
        Assert.Equal(2, harness.Agent.ReceivedCommands.Count);
        Assert.Equal(2, harness.Agent.WrittenAndFlushedAttemptCount);
        Assert.Equal(1, harness.Agent.DisconnectAfterSignCount);
        Assert.Equal(1, harness.Agent.TerminalCount);
        Assert.True(harness.Agent.ConnectionCount >= 2);
    }

    [Fact]
    public async Task Two_real_pipe_disconnects_exhaust_recovery_and_emit_one_terminal_delta()
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync(FakeAgentBehavior.DisconnectAfterSign);
        var baseline = await harness.Agent.Client.GetTerminalJobDeltaAsync(null, null, CancellationToken.None);
        Assert.Empty(baseline.Items);
        Assert.NotNull(baseline.Watermark);

        using var response = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest("/v1/jobs", idempotencyKey: "disconnect-exhausted"));
        response.EnsureSuccessStatusCode();
        var accepted = Assert.IsType<CreateJobResponse>(
            await response.Content.ReadFromJsonAsync<CreateJobResponse>());

        var failed = await harness.WaitForStateAsync(accepted.JobId, "failed");
        var stored = Assert.IsType<Job>(await harness.Jobs.GetAsync(accepted.JobId));
        Assert.Equal("recovery_exhausted", failed.ErrorCode);
        Assert.Equal(2, stored.AttemptCount);
        Assert.Equal(2, harness.Agent.ReceivedCommands.Count);
        Assert.Equal(2, harness.Agent.WrittenAndFlushedAttemptCount);
        Assert.Equal(2, harness.Agent.DisconnectAfterSignCount);
        Assert.Equal(0, harness.Agent.TerminalCount);

        var firstDelta = await harness.Agent.Client.GetTerminalJobDeltaAsync(
            baseline.Watermark,
            null,
            CancellationToken.None);
        var item = Assert.Single(firstDelta.Items);
        Assert.Equal(accepted.JobId, item.Item.JobId);
        Assert.Equal("failed", item.Item.State);
        var secondDelta = await harness.Agent.Client.GetTerminalJobDeltaAsync(
            firstDelta.Watermark,
            null,
            CancellationToken.None);
        Assert.Empty(secondDelta.Items);
    }

    [Theory]
    [InlineData("reparse")]
    [InlineData("hardlink")]
    [InlineData("directory")]
    public async Task Retry_refuses_a_nonordinary_stale_part_without_replacing_its_external_target(string mutation)
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync(
            FakeAgentBehavior.DisconnectFirstAfterSign | FakeAgentBehavior.HoldSecondBeforeSigning);
        var jobId = await UploadAsync(harness, "stale-part-" + mutation);
        _ = await harness.Agent.ReadNextCommandAsync();
        _ = await harness.Agent.ReadNextCommandAsync();
        await harness.Agent.HeldBeforeSigningReached.WaitAsync(TimeSpan.FromSeconds(10));
        var partPath = harness.Spool.GetResultPartPath(jobId, ".pdf");
        Assert.True(File.Exists(partPath));
        File.Delete(partPath);
        var sentinel = Path.Combine(harness.Root, "external-stale-part-" + mutation + ".bin");
        var sentinelBytes = "external-sentinel-unchanged"u8.ToArray();
        await File.WriteAllBytesAsync(sentinel, sentinelBytes);
        switch (mutation)
        {
            case "reparse":
                File.CreateSymbolicLink(partPath, sentinel);
                break;
            case "hardlink":
                CreateHardLink(partPath, sentinel);
                break;
            case "directory":
                Directory.CreateDirectory(partPath);
                break;
            default:
                throw new InvalidOperationException("unknown_test_mutation");
        }

        try
        {
            harness.Agent.ReleaseBeforeSigning();
            var failed = await harness.WaitForStateAsync(jobId, "failed");

            Assert.Equal("recovery_exhausted", failed.ErrorCode);
            Assert.Equal(sentinelBytes, await File.ReadAllBytesAsync(sentinel));
            Assert.Equal(1, harness.Agent.WrittenAndFlushedAttemptCount);
            Assert.Equal(1, harness.Agent.DisconnectAfterSignCount);
            Assert.Equal(0, harness.Agent.TerminalCount);
        }
        finally
        {
            if (mutation == "reparse" && new FileInfo(partPath).LinkTarget is not null)
            {
                File.Delete(partPath);
            }
        }
    }

    [Theory]
    [InlineData(FakeAgentBehavior.DuplicateTerminal)]
    [InlineData(FakeAgentBehavior.StaleTerminal)]
    [InlineData(FakeAgentBehavior.WrongJobTerminal)]
    public async Task Duplicate_or_stale_terminal_cannot_mutate_the_next_fifo_job(FakeAgentBehavior behavior)
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync(behavior);

        var first = await UploadAsync(harness, "terminal-mutation-first-" + behavior);
        _ = await harness.WaitForStateAsync(first, "succeeded");
        var second = await UploadAsync(harness, "terminal-mutation-second-" + behavior);
        _ = await harness.WaitForStateAsync(second, "succeeded");

        Assert.Equal([first, second], harness.Agent.ReceivedCommands.Select(command => command.JobId));
        Assert.All(await harness.Jobs.GetAllAsync(), job => Assert.Equal(JobState.Succeeded, job.State));
        Assert.Equal(1, harness.Agent.MaxConcurrency);
    }

    [Fact]
    public async Task Invalid_heartbeat_identity_retires_and_reconnects_the_real_pipe()
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync(FakeAgentBehavior.InvalidHeartbeatIdentity);

        await harness.WaitForAgentConnectionsAsync(2, TimeSpan.FromSeconds(12));

        Assert.True(harness.Agent.ConnectionCount >= 2);
        Assert.Empty(await harness.Jobs.GetAllAsync());
    }

    private static async Task<Guid> UploadAsync(EndToEndHarness harness, string idempotencyKey)
    {
        using var response = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest("/v1/jobs", idempotencyKey: idempotencyKey));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<CreateJobResponse>())!.JobId;
    }

    private static void CreateHardLink(string linkPath, string existingPath)
    {
        if (OperatingSystem.IsWindows())
        {
            if (!WindowsCreateHardLink(linkPath, existingPath, IntPtr.Zero))
            {
                throw new IOException("test_hardlink_create_failed");
            }

            return;
        }

        if (UnixCreateHardLink(existingPath, linkPath) != 0)
        {
            throw new IOException("test_hardlink_create_failed");
        }
    }

    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "link", SetLastError = true)]
    private static extern int UnixCreateHardLink(string existingPath, string linkPath);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool WindowsCreateHardLink(string fileName, string existingFileName, IntPtr securityAttributes);
}
