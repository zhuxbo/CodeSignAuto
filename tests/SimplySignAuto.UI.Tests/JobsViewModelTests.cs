using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.App.UI.ViewModels;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.UI.Tests;

public sealed class JobsViewModelTests
{
    [Fact]
    public void Job_rows_use_the_selected_English_resources()
    {
        using var culture = new UiTestCultureScope("en-US");

        var item = new JobListItemViewModel(Item(GuidFrom(1), "succeeded"));

        Assert.Equal("Local", item.SourceText);
        Assert.Equal("PDF document", item.KindText);
        Assert.Equal("Completed", item.StateText);
        Assert.True(item.IsPdf);
    }

    [Fact]
    public async Task Pages_are_coalesced_deduplicated_and_bounded()
    {
        var firstItems = Enumerable.Range(0, 100)
            .Select(index => Item(GuidFrom(index + 1), "succeeded", source: index % 2 == 0 ? "api" : "local"))
            .ToArray();
        var cursor = new JobPageCursor(
            "terminal",
            firstItems[^1].CreatedAtUtc,
            firstItems[^1].JobId,
            DateTimeOffset.Parse("2026-08-09T12:00:00Z"));
        var administration = new AdministrationFake(
            new JobPageResponse(Guid.NewGuid(), firstItems, cursor, null, null),
            new JobPageResponse(Guid.NewGuid(), [firstItems[^1], Item(GuidFrom(101), "failed")], null, null, null));
        var vm = new JobsViewModel(administration, new LocalJobsFake());

        await Task.WhenAll(vm.RefreshAsync(default), vm.LoadNextPageAsync(default));
        await Task.WhenAll(vm.LoadNextPageAsync(default), vm.LoadNextPageAsync(default));

        Assert.Equal(101, vm.Items.Count);
        Assert.Equal(2, administration.PageCalls);
        Assert.Equal(101, vm.Items.Select(item => item.JobId).Distinct().Count());
        Assert.Equal("CI/API", vm.Items[0].SourceText);
        Assert.Equal("本机", vm.Items[1].SourceText);
    }

    [Fact]
    public async Task Refresh_generation_rejects_a_late_old_page()
    {
        var administration = new DelayedAdministrationFake();
        var vm = new JobsViewModel(administration, new LocalJobsFake());
        var old = vm.RefreshAsync(default);
        await administration.FirstEntered.Task.WaitAsync(TimeSpan.FromSeconds(1));

        var current = vm.RefreshAsync(default);
        await current;
        administration.ReleaseFirst.TrySetResult();
        await old;

        Assert.Equal(GuidFrom(2), Assert.Single(vm.Items).JobId);
    }

    [Fact]
    public async Task Save_is_only_offered_for_succeeded_result_and_reuses_local_client()
    {
        var succeeded = Item(GuidFrom(1), "succeeded", source: "api");
        var failed = Item(GuidFrom(2), "failed");
        var administration = new AdministrationFake(
            new JobPageResponse(Guid.NewGuid(), [succeeded, failed], null, null, null));
        var local = new LocalJobsFake();
        var vm = new JobsViewModel(administration, local);
        await vm.RefreshAsync(default);

        Assert.True(vm.CanSaveResult(succeeded.JobId));
        Assert.False(vm.CanSaveResult(failed.JobId));
        await vm.SaveResultAsAsync(succeeded.JobId, "/tmp/signed.pdf", overwrite: false, default);
        await vm.SaveResultAsAsync(failed.JobId, "/tmp/ignored.pdf", overwrite: false, default);

        var call = Assert.Single(local.Saves);
        Assert.Equal((succeeded.JobId, "/tmp/signed.pdf", false), call);
    }

    [Fact]
    public async Task Api_result_uses_shared_default_name_for_a_signed_copy()
    {
        var succeeded = Item(GuidFrom(1), "succeeded", source: "api");
        var vm = new JobsViewModel(
            new AdministrationFake(new JobPageResponse(Guid.NewGuid(), [succeeded], null, null, null)),
            new LocalJobsFake());

        await vm.RefreshAsync(default);

        Assert.Equal("safe.signed.pdf", Assert.Single(vm.Items).DefaultSignedCopyName);
    }

    [Fact]
    public async Task Api_result_forces_create_new_and_surfaces_an_existing_destination_error()
    {
        var succeeded = Item(GuidFrom(1), "succeeded", source: "api");
        var local = new LocalJobsFake { FailureCode = "local_destination_exists" };
        var vm = new JobsViewModel(
            new AdministrationFake(new JobPageResponse(Guid.NewGuid(), [succeeded], null, null, null)),
            local);
        await vm.RefreshAsync(default);

        await vm.SaveResultAsAsync(succeeded.JobId, "/tmp/already.pdf", overwrite: true, default);

        Assert.Equal((succeeded.JobId, "/tmp/already.pdf", false), Assert.Single(local.Saves));
        Assert.Equal("local_destination_exists", vm.ErrorCode);
    }

    [Fact]
    public async Task Local_result_preserves_trusted_identity_overwrite_behavior()
    {
        var succeeded = Item(GuidFrom(1), "succeeded", source: "local");
        var local = new LocalJobsFake();
        var vm = new JobsViewModel(
            new AdministrationFake(new JobPageResponse(Guid.NewGuid(), [succeeded], null, null, null)),
            local);
        await vm.RefreshAsync(default);

        await vm.SaveResultAsAsync(succeeded.JobId, "/tmp/trusted.pdf", overwrite: true, default);

        Assert.Equal((succeeded.JobId, "/tmp/trusted.pdf", true), Assert.Single(local.Saves));
        Assert.Null(vm.ErrorCode);
    }

    [Fact]
    public async Task Restarted_manual_history_rejects_overwrite_with_friendly_guidance()
    {
        var succeeded = Item(GuidFrom(1), "succeeded", source: "local");
        var local = new LocalJobsFake { FailureCode = "local_destination_identity_unavailable" };
        var vm = new JobsViewModel(
            new AdministrationFake(new JobPageResponse(Guid.NewGuid(), [succeeded], null, null, null)),
            local);
        await vm.RefreshAsync(default);

        await vm.SaveResultAsAsync(succeeded.JobId, "/tmp/existing.pdf", overwrite: true, default);

        Assert.Equal("local_destination_identity_unavailable", vm.ErrorCode);
        Assert.Equal("出于安全原因，程序重启后不能覆盖已有文件。请使用新文件名保存。", vm.ErrorText);
    }

    private static JobPageItem Item(Guid id, string state, string source = "local")
    {
        var created = DateTimeOffset.Parse("2026-08-09T10:00:00Z").AddTicks(-id.ToByteArray()[0]);
        return new JobPageItem(
            id,
            source,
            "pdf",
            state,
            "safe.pdf",
            created,
            state == "queued" ? null : created.AddSeconds(1),
            state is "succeeded" or "failed" ? created.AddSeconds(2) : null,
            state == "failed" ? "internal_error" : null,
            Guid.NewGuid(),
            state == "succeeded");
    }

    private static Guid GuidFrom(int value)
    {
        var bytes = new byte[16];
        BitConverter.GetBytes(value).CopyTo(bytes, 0);
        return new Guid(bytes);
    }

    private sealed class AdministrationFake(params JobPageResponse[] pages) : IAgentAdministrationClient
    {
        private readonly Queue<JobPageResponse> _pages = new(pages);
        public int PageCalls { get; private set; }

        public Task<JobPageResponse> GetJobPageAsync(JobPageCursor? cursor, CancellationToken cancellationToken)
        {
            PageCalls++;
            return Task.FromResult(_pages.Dequeue());
        }

        public Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task SaveOtpAsync(SimplySignAuto.Core.Otp.OtpauthProfile profile, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class DelayedAdministrationFake : IAgentAdministrationClient
    {
        private int _calls;
        public TaskCompletionSource FirstEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseFirst { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<JobPageResponse> GetJobPageAsync(JobPageCursor? cursor, CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref _calls) == 1)
            {
                FirstEntered.TrySetResult();
                await ReleaseFirst.Task;
                return new JobPageResponse(Guid.NewGuid(), [Item(GuidFrom(1), "succeeded")], null, null, null);
            }

            return new JobPageResponse(Guid.NewGuid(), [Item(GuidFrom(2), "succeeded")], null, null, null);
        }

        public Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task SaveOtpAsync(SimplySignAuto.Core.Otp.OtpauthProfile profile, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class LocalJobsFake : ILocalJobClient
    {
        public List<(Guid JobId, string Path, bool Overwrite)> Saves { get; } = [];
        public string? FailureCode { get; init; }
        public Task<Guid> CreateAndUploadAsync(string path, SigningParameters parameters, IProgress<LocalCopyProgress>? progress, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task SaveSignedCopyAsync(Guid jobId, string destinationPath, bool overwrite, CancellationToken cancellationToken)
        {
            Saves.Add((jobId, destinationPath, overwrite));
            if (FailureCode is not null)
            {
                throw new LocalJobException(FailureCode);
            }
            return Task.CompletedTask;
        }
        public void ReleaseAcceptedSource(Guid jobId) { }
    }
}
