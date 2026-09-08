using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Service.Jobs;
using Xunit;

namespace CodeSignAuto.Service.Tests;

public sealed class InterfaceDefaultContractTests
{
    [Fact]
    public async Task Incomplete_test_doubles_fail_closed_for_unsupported_operations()
    {
        var job = new Job(Guid.NewGuid(), JobState.Queued, new AuthenticodeParameters("52A1B4C9", "sha256", false));
        IJobStore jobs = new IncompleteJobStore();

        await Assert.ThrowsAsync<NotSupportedException>(() => jobs.CheckHealthAsync());
        await Assert.ThrowsAsync<NotSupportedException>(() => jobs.GetQueueSnapshotAsync());
        await Assert.ThrowsAsync<NotSupportedException>(() => jobs.GetAllAsync());
        await Assert.ThrowsAsync<NotSupportedException>(() => jobs.TryExpireNextAsync(
            DateTimeOffset.UtcNow,
            static (_, _) => Task.CompletedTask));
        await Assert.ThrowsAsync<NotSupportedException>(() => jobs.RecoverActiveLeasesAsync());

        ISpoolStore spool = new IncompleteSpoolStore();
        Assert.Throws<NotSupportedException>(() => spool.ValidateAndListJobDirectories());
        await Assert.ThrowsAsync<NotSupportedException>(() => spool.DeleteStalePartsAsync(job, DateTimeOffset.UtcNow));
        await Assert.ThrowsAsync<NotSupportedException>(() => spool.DeleteSucceededTransientFilesAsync(job));
        await Assert.ThrowsAsync<NotSupportedException>(() => spool.QuarantineAsync(
            new SpoolJobDirectory(job.Id, "/not-used", job.Id.ToString("N"))));

        IJobCompletionNotifier notifier = new IncompleteNotifier();
        Assert.Throws<NotSupportedException>(() => notifier.Forget(job.Id));
        Assert.Throws<NotSupportedException>(() => notifier.Retire(job with { State = JobState.Expired }));
    }

    private sealed class IncompleteJobStore : IJobStore
    {
        public Task<Job> CreateAsync(
            Job job,
            string? apiPrincipal = null,
            string? idempotencyKey = null,
            CancellationToken cancellationToken = default) => Task.FromResult(job);

        public Task<Job?> GetAsync(Guid jobId, CancellationToken cancellationToken = default) =>
            Task.FromResult<Job?>(null);

        public Task<int> RecoverInterruptedAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(0);
    }

    private sealed class IncompleteSpoolStore : ISpoolStore
    {
        public Task<SpoolFile> WriteInputAsync(
            Guid jobId,
            string extension,
            Stream input,
            long maxBytes,
            CancellationToken cancellationToken = default) => Task.FromException<SpoolFile>(new NotSupportedException());

        public Task<SpoolFile> PromoteResultAsync(
            Guid jobId,
            string extension,
            string expectedSha256,
            long expectedSize,
            CancellationToken cancellationToken = default) => Task.FromException<SpoolFile>(new NotSupportedException());

        public Task DeleteJobAsync(Guid jobId, CancellationToken cancellationToken = default) =>
            Task.FromException(new NotSupportedException());
    }

    private sealed class IncompleteNotifier : IJobCompletionNotifier
    {
        public Task<Job> WaitAsync(Guid jobId, CancellationToken cancellationToken) =>
            Task.FromException<Job>(new NotSupportedException());

        public void Notify(Job job) => throw new NotSupportedException();
    }
}
