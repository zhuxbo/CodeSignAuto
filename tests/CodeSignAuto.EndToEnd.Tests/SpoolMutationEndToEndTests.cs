using System.Net.Http.Json;
using System.Runtime.InteropServices;
using CodeSignAuto.Service.Api;
using Xunit;

namespace CodeSignAuto.EndToEnd.Tests;

public sealed class SpoolMutationEndToEndTests
{
    [Theory]
    [InlineData("path-swap")]
    [InlineData("reparse")]
    [InlineData("hardlink")]
    public async Task Input_identity_mutations_fail_closed_without_changing_external_sentinel(string mutation)
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync(FakeAgentBehavior.HoldBeforeSigning);
        var jobId = await UploadAsync(harness, "spool-input-" + mutation);
        await harness.Agent.HeldBeforeSigningReached.WaitAsync(TimeSpan.FromSeconds(10));
        var inputPath = harness.Spool.GetInputPath(jobId, ".pdf");
        var sentinelPath = Path.Combine(harness.Root, "external-sentinel-" + mutation + ".pdf");
        var sentinel = EndToEndFixtures.TwoPagePdf.Concat("external-sentinel"u8.ToArray()).ToArray();
        await File.WriteAllBytesAsync(sentinelPath, sentinel);

        File.Delete(inputPath);
        switch (mutation)
        {
            case "path-swap":
                await File.WriteAllBytesAsync(inputPath, "%PDF-swapped-input"u8.ToArray());
                break;
            case "reparse":
                File.CreateSymbolicLink(inputPath, sentinelPath);
                break;
            case "hardlink":
                CreateHardLink(inputPath, sentinelPath);
                break;
        }

        try
        {
            harness.Agent.ReleaseBeforeSigning();
            var failed = await harness.WaitForStateAsync(jobId, "failed");
            Assert.Contains(failed.ErrorCode, new[] { "result_corrupt", "recovery_exhausted" });
            Assert.Equal(sentinel, await File.ReadAllBytesAsync(sentinelPath));
            Assert.False(File.Exists(harness.Spool.GetResultPath(jobId, ".pdf")));
        }
        finally
        {
            File.Delete(inputPath);
        }
    }

    [Fact]
    public async Task Result_part_reparse_is_never_followed_or_overwritten()
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync(FakeAgentBehavior.HoldBeforeSigning);
        var jobId = await UploadAsync(harness, "spool-result-part-reparse");
        await harness.Agent.HeldBeforeSigningReached.WaitAsync(TimeSpan.FromSeconds(10));
        var partPath = harness.Spool.GetResultPartPath(jobId, ".pdf");
        var sentinelPath = Path.Combine(harness.Root, "external-result-part-sentinel.pdf");
        var sentinel = "result-part-sentinel"u8.ToArray();
        await File.WriteAllBytesAsync(sentinelPath, sentinel);
        File.CreateSymbolicLink(partPath, sentinelPath);

        try
        {
            harness.Agent.ReleaseBeforeSigning();
            var failed = await harness.WaitForStateAsync(jobId, "failed");
            Assert.Equal("recovery_exhausted", failed.ErrorCode);
            Assert.Equal(sentinel, await File.ReadAllBytesAsync(sentinelPath));
            Assert.False(File.Exists(harness.Spool.GetResultPath(jobId, ".pdf")));
        }
        finally
        {
            File.Delete(partPath);
        }
    }

    [Fact]
    public async Task Startup_rejects_reparse_job_directory_without_touching_external_sentinel()
    {
        var root = Directory.CreateTempSubdirectory("SSA-E2E-JOB-REPARSE-").FullName;
        var external = Path.Combine(root, "external-directory");
        Directory.CreateDirectory(external);
        var sentinel = Path.Combine(external, "sentinel.txt");
        await File.WriteAllTextAsync(sentinel, "keep");
        var link = Path.Combine(root, "spool", Guid.NewGuid().ToString("N"));
        try
        {
            await using (var initial = await EndToEndHarness.StartAsync(root, deleteRoot: false))
            {
            }

            Directory.CreateSymbolicLink(link, external);

            await Assert.ThrowsAnyAsync<Exception>(() =>
                EndToEndHarness.StartAsync(root, deleteRoot: false));
            Assert.Equal("keep", await File.ReadAllTextAsync(sentinel));
        }
        finally
        {
            if (Directory.Exists(link))
            {
                Directory.Delete(link);
            }

            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static async Task<Guid> UploadAsync(EndToEndHarness harness, string key)
    {
        using var response = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest("/v1/jobs", idempotencyKey: key));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<CreateJobResponse>())!.JobId;
    }

    private static void CreateHardLink(string linkPath, string existingPath)
    {
        var created = OperatingSystem.IsWindows()
            ? NativeMethods.CreateHardLinkWindows(linkPath, existingPath, IntPtr.Zero)
            : NativeMethods.CreateHardLinkUnix(existingPath, linkPath) == 0;
        if (!created)
        {
            throw new IOException("hardlink_fixture_failed");
        }
    }

    private static class NativeMethods
    {
        [DllImport("libc", EntryPoint = "link", SetLastError = true)]
        internal static extern int CreateHardLinkUnix(string existingPath, string linkPath);

        [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateHardLinkWindows(string linkPath, string existingPath, IntPtr securityAttributes);
    }
}
