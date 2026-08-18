using System.Net.Http.Json;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Service.Api;
using SimplySignAuto.Service.Jobs;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class PromotionCrashRecoveryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Persisted_completion_recovers_on_either_side_of_the_atomic_result_promotion(
        bool promotionAlreadyHappened)
    {
        var root = Directory.CreateTempSubdirectory("SSA-E2E-PROMOTION-").FullName;
        string? partPath = null;
        string? resultPath = null;
        Guid jobId = default;
        string expectedHash = string.Empty;
        long expectedSize = 0;
        try
        {
            var pause = new PromotionPause();
            await using (var first = await EndToEndHarness.StartAsync(
                root,
                deleteRoot: false,
                promotionObserver: pause))
            {
                await first.StartAgentAsync();
                jobId = await UploadAsync(first, "promotion-success-" + promotionAlreadyHappened);
                await pause.Reached.WaitAsync(TimeSpan.FromSeconds(10));

                var persisted = Assert.IsType<Job>(await first.Jobs.GetAsync(jobId));
                Assert.Equal(JobState.Verifying, persisted.State);
                expectedHash = Assert.IsType<string>(persisted.ResultSha256);
                expectedSize = Assert.IsType<long>(persisted.ResultSize);
                partPath = first.Spool.GetResultPartPath(jobId, persisted.Extension);
                resultPath = first.Spool.GetResultPath(jobId, persisted.Extension);
                Assert.True(File.Exists(partPath));
                Assert.False(File.Exists(resultPath));
            }

            if (promotionAlreadyHappened)
            {
                File.Move(partPath!, resultPath!, overwrite: false);
            }

            await using (var recovered = await EndToEndHarness.StartAsync(root, deleteRoot: false))
            {
                var status = await recovered.WaitForStateAsync(jobId, "succeeded");
                Assert.Equal(expectedHash, status.ResultSha256);
                var persisted = Assert.IsType<Job>(await recovered.Jobs.GetAsync(jobId));
                Assert.Equal(expectedSize, persisted.ResultSize);
                Assert.False(File.Exists(partPath));
                Assert.True(File.Exists(resultPath));
                Assert.Null(recovered.Pipe.CurrentConnection);
                await using var verified = await recovered.Spool.OpenVerifiedResultAsync(
                    jobId,
                    ".pdf",
                    expectedSize,
                    expectedHash);
                Assert.Equal(expectedSize, verified.Length);
            }
        }
        finally
        {
            DeleteTestRoot(root, resultPath);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Conflicting_or_reparse_final_fails_recovery_without_following_or_overwriting(
        bool reparseFinal)
    {
        var root = Directory.CreateTempSubdirectory("SSA-E2E-PROMOTION-FAIL-").FullName;
        var victimPath = Path.Combine(
            Path.GetDirectoryName(root)!,
            "SSA-E2E-PROMOTION-VICTIM-" + Guid.NewGuid().ToString("N") + ".pdf");
        string? partPath = null;
        string? resultPath = null;
        Guid jobId = default;
        try
        {
            var pause = new PromotionPause();
            await using (var first = await EndToEndHarness.StartAsync(
                root,
                deleteRoot: false,
                promotionObserver: pause))
            {
                await first.StartAgentAsync();
                jobId = await UploadAsync(first, "promotion-failure-" + reparseFinal);
                await pause.Reached.WaitAsync(TimeSpan.FromSeconds(10));

                var persisted = Assert.IsType<Job>(await first.Jobs.GetAsync(jobId));
                Assert.Equal(JobState.Verifying, persisted.State);
                Assert.NotNull(persisted.ResultSha256);
                Assert.NotNull(persisted.ResultSize);
                partPath = first.Spool.GetResultPartPath(jobId, persisted.Extension);
                resultPath = first.Spool.GetResultPath(jobId, persisted.Extension);
            }

            var sentinel = "%PDF-external-sentinel"u8.ToArray();
            if (reparseFinal)
            {
                await File.WriteAllBytesAsync(victimPath, sentinel);
                File.CreateSymbolicLink(resultPath!, victimPath);
            }
            else
            {
                await File.WriteAllBytesAsync(resultPath!, sentinel);
            }

            await using (var recovered = await EndToEndHarness.StartAsync(root, deleteRoot: false))
            {
                var status = await recovered.WaitForStateAsync(jobId, "failed");
                Assert.Equal("result_corrupt", status.ErrorCode);
                Assert.Null(status.ResultSha256);
                var persisted = Assert.IsType<Job>(await recovered.Jobs.GetAsync(jobId));
                Assert.Null(persisted.ResultSize);
                Assert.Null(persisted.ResultSha256);
                Assert.False(File.Exists(partPath));
                Assert.Null(recovered.Pipe.CurrentConnection);
            }

            if (reparseFinal)
            {
                Assert.Equal(sentinel, await File.ReadAllBytesAsync(victimPath));
                Assert.NotNull(File.ResolveLinkTarget(resultPath!, returnFinalTarget: false));
            }
            else
            {
                Assert.Equal(sentinel, await File.ReadAllBytesAsync(resultPath!));
            }
        }
        finally
        {
            DeleteTestRoot(root, resultPath);
            if (File.Exists(victimPath))
            {
                File.Delete(victimPath);
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

    private static void DeleteTestRoot(string root, string? resultPath)
    {
        if (resultPath is not null && File.Exists(resultPath) &&
            (File.GetAttributes(resultPath) & FileAttributes.ReparsePoint) != 0)
        {
            File.Delete(resultPath);
        }

        if (Directory.Exists(root))
        {
            Assert.DoesNotContain(
                Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories),
                path => (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0);
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed class PromotionPause : ISpoolPromotionObserver
    {
        private readonly TaskCompletionSource _reached = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task Reached => _reached.Task;

        public async Task BeforeResultClaimAsync(
            string partPath,
            string resultPath,
            CancellationToken cancellationToken)
        {
            Assert.True(File.Exists(partPath));
            Assert.False(File.Exists(resultPath));
            _reached.TrySetResult();
            await _release.Task.WaitAsync(cancellationToken);
        }
    }
}
