using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SimplySignAuto.Core.Jobs;

namespace SimplySignAuto.Service.Jobs;

public sealed class JobCleanupService(
    IJobStore jobs,
    ISpoolStore spool,
    IJobCompletionNotifier notifier,
    TimeProvider timeProvider,
    ILogger<JobCleanupService> logger,
    ILocalUploadCleanup? localUploads = null) : BackgroundService
{
    private static readonly EventId CleanupFailureEvent = new(2002, "JobCleanupFailed");
    public static readonly TimeSpan CleanupInterval = TimeSpan.FromHours(1);
    public static readonly TimeSpan StalePartAge = TimeSpan.FromHours(1);

    private readonly IJobStore _jobs = jobs ?? throw new ArgumentNullException(nameof(jobs));
    private readonly ISpoolStore _spool = spool ?? throw new ArgumentNullException(nameof(spool));
    private readonly IJobCompletionNotifier _notifier = notifier ?? throw new ArgumentNullException(nameof(notifier));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly ILogger<JobCleanupService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    private readonly ILocalUploadCleanup? _localUploads = localUploads;

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await RecoverStartupAsync(cancellationToken).ConfigureAwait(false);
        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task RecoverStartupAsync(CancellationToken cancellationToken)
    {
        if (_localUploads is not null)
        {
            await _localUploads.CleanupExpiredAsync(cancellationToken).ConfigureAwait(false);
        }

        var localOwnership = _localUploads is null
            ? Array.Empty<LocalUploadOwnership>()
            : await _localUploads.GetStartupOwnershipAsync(cancellationToken).ConfigureAwait(false);
        foreach (var ownership in localOwnership)
        {
            _spool.ValidateLocalUploadArtifacts(ownership.JobId, ownership.Extension);
        }

        var locallyOwnedIds = localOwnership.Select(ownership => ownership.JobId).ToHashSet();
        var directories = _spool.ValidateAndListJobDirectories();
        await _jobs.RecoverActiveLeasesAsync(cancellationToken).ConfigureAwait(false);
        var persisted = await _jobs.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var byId = persisted.ToDictionary(job => job.Id);
        var stalePartCutoff = _timeProvider.GetUtcNow() - StalePartAge;

        foreach (var job in persisted)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsActive(job.State))
            {
                await _spool.DeleteStalePartsAsync(job, stalePartCutoff, cancellationToken).ConfigureAwait(false);
            }

            if (job.State != JobState.Succeeded || job.ResultSize is null || string.IsNullOrWhiteSpace(job.ResultSha256))
            {
                continue;
            }

            try
            {
                await using var verified = await _spool.OpenVerifiedResultAsync(
                    job.Id,
                    job.Extension,
                    job.ResultSize.Value,
                    job.ResultSha256,
                    cancellationToken).ConfigureAwait(false);
                await _spool.DeleteSucceededTransientFilesAsync(job, cancellationToken).ConfigureAwait(false);
            }
            catch (SpoolException)
            {
                if (await _jobs.TryFailSucceededResultAsync(
                        job.Id,
                        job.ResultSize.Value,
                        job.ResultSha256,
                        "result_corrupt",
                        "The signed result failed integrity verification.",
                        cancellationToken).ConfigureAwait(false) &&
                    await _jobs.GetAsync(job.Id, cancellationToken).ConfigureAwait(false) is { } failed)
                {
                    _notifier.Notify(failed);
                }
            }
        }

        foreach (var directory in directories)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (directory.JobId is not { } jobId ||
                !byId.ContainsKey(jobId) && !locallyOwnedIds.Contains(jobId))
            {
                await _spool.QuarantineAsync(directory, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(CleanupInterval, _timeProvider);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                await RunCleanupCycleAsync(stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    public async Task RunCleanupCycleAsync(CancellationToken cancellationToken)
    {
        try
        {
            await CleanupExpiredAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception)
        {
            _logger.LogError(CleanupFailureEvent, "Job cleanup failed. Code: {Code}", "job_cleanup_failed");
        }
    }

    public async Task<int> CleanupExpiredAsync(CancellationToken cancellationToken)
    {
        var expiredCount = _localUploads is null
            ? 0
            : await _localUploads.CleanupExpiredAsync(cancellationToken).ConfigureAwait(false);
        while (await _jobs.TryExpireNextAsync(
                _timeProvider.GetUtcNow(),
                (job, token) => _spool.DeleteJobAsync(job.Id, token),
                cancellationToken).ConfigureAwait(false) is { } expired)
        {
            _notifier.Retire(expired);
            expiredCount++;
            if (cancellationToken.IsCancellationRequested)
            {
                return expiredCount;
            }
        }

        return expiredCount;
    }

    private static bool IsActive(JobState state) =>
        state is JobState.WaitingForAgent or JobState.Signing or JobState.Verifying;
}
