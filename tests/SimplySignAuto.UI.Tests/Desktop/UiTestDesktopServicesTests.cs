using SimplySignAuto.App.UI.Testing;

namespace SimplySignAuto.UI.Tests.Desktop;

public sealed class UiTestDesktopServicesTests
{
    [Theory]
    [InlineData("ready", 1, 1, 0)]
    [InlineData("partial", 1, 1, 0)]
    [InlineData("session0", 0, 0, 0)]
    [InlineData("token-missing", 1, 0, 0)]
    [InlineData("active-job", 1, 1, 1)]
    [InlineData("job-failed", 1, 1, 0)]
    public async Task Synthetic_state_maps_to_a_safe_management_snapshot(
        string code,
        int expectedSession,
        int expectedReadyCapability,
        int expectedActiveJobs)
    {
        Assert.True(UiTestState.TryParse(code, out var state));
        using var services = UiTestDesktopServices.Create(state!);

        var snapshot = await services.Management.RefreshAsync(CancellationToken.None);

        Assert.Equal(expectedSession, snapshot.AgentSessionId);
        Assert.Equal(expectedReadyCapability, snapshot.Authenticode.Ready ? 1 : 0);
        Assert.Equal(expectedActiveJobs, snapshot.ActiveJobCount);
        Assert.DoesNotContain("otpauth", services.SafeDescription, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("tokenSerial", services.SafeDescription, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("service.json", services.SafeDescription, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Unknown_state_has_no_snapshot_and_refresh_fails_without_touching_production()
    {
        Assert.True(UiTestState.TryParse("unknown", out var state));
        using var services = UiTestDesktopServices.Create(state!);

        Assert.Null(services.Management.LatestSnapshot);
        await Assert.ThrowsAsync<SimplySignAuto.Agent.Ipc.ManagementUnavailableException>(() =>
            services.Management.RefreshAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Job_page_is_fixed_at_one_hundred_active_first_and_uses_only_safe_basenames()
    {
        Assert.True(UiTestState.TryParse("job-failed", out var state));
        using var services = UiTestDesktopServices.Create(state!);

        var first = await services.Administration.GetJobPageAsync(null, CancellationToken.None);
        var second = await services.Administration.GetJobPageAsync(first.NextCursor, CancellationToken.None);

        Assert.Equal(100, first.Items.Count);
        Assert.NotNull(first.NextCursor);
        Assert.True(first.Items.TakeWhile(item => item.State is not ("succeeded" or "failed" or "expired")).Any());
        Assert.Contains(first.Items, item => item is { State: "failed", HasResult: false });
        Assert.Contains(first.Items, item => item is { State: "expired", HasResult: false, ErrorCode: "job_expired" });
        Assert.Contains(first.Items, item => item is { State: "succeeded", HasResult: true });
        Assert.Single(second.Items);
        Assert.Null(second.NextCursor);
        Assert.All(first.Items.Concat(second.Items), item =>
        {
            Assert.Equal(Path.GetFileName(item.OriginalName), item.OriginalName);
            Assert.DoesNotContain('\\', item.OriginalName);
            Assert.DoesNotContain('/', item.OriginalName);
        });
    }

    [Fact]
    public async Task Fake_local_signing_preserves_input_and_publishes_a_new_controlled_result()
    {
        Assert.True(UiTestState.TryParse("ready", out var state));
        using var services = UiTestDesktopServices.Create(state!);
        var root = Path.Combine(Path.GetTempPath(), $"SSA-UI-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var input = Path.Combine(root, "sample.exe");
        var output = Path.Combine(root, "sample.signed.exe");
        var bytes = new byte[] { 0x4D, 0x5A, 1, 2, 3, 4 };
        try
        {
            await File.WriteAllBytesAsync(input, bytes);
            var jobId = await services.LocalJobs.CreateAndUploadAsync(
                input,
                new SimplySignAuto.Core.Jobs.AuthenticodeParameters("52A1B4C9", "sha256", false),
                null,
                CancellationToken.None);
            await services.LocalJobs.SaveSignedCopyAsync(jobId, output, overwrite: false, CancellationToken.None);

            Assert.Equal(bytes, await File.ReadAllBytesAsync(input));
            Assert.Equal(bytes, await File.ReadAllBytesAsync(output));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Fake_copy_honors_user_cancellation_before_finalizing()
    {
        Assert.True(UiTestState.TryParse("ready", out var state));
        using var services = UiTestDesktopServices.Create(state!);
        var root = Path.Combine(Path.GetTempPath(), $"SSA-UI-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var input = Path.Combine(root, "large.exe");
        var bytes = new byte[2 * 1024 * 1024];
        bytes[0] = 0x4D;
        bytes[1] = 0x5A;
        try
        {
            await File.WriteAllBytesAsync(input, bytes);
            using var cancellation = new CancellationTokenSource();
            var firstProgress = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var operation = services.LocalJobs.CreateAndUploadAsync(
                input,
                new SimplySignAuto.Core.Jobs.AuthenticodeParameters("52A1B4C9", "sha256", false),
                new SignalingProgress(firstProgress),
                cancellation.Token);
            await firstProgress.Task.WaitAsync(TimeSpan.FromSeconds(2));
            cancellation.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);
            Assert.Equal(bytes, await File.ReadAllBytesAsync(input));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed class SignalingProgress(TaskCompletionSource signal)
        : IProgress<SimplySignAuto.Agent.LocalJobs.LocalCopyProgress>
    {
        public void Report(SimplySignAuto.Agent.LocalJobs.LocalCopyProgress value) => signal.TrySetResult();
    }
}
