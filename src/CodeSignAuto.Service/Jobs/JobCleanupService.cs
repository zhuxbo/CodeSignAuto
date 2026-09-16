using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using CodeSignAuto.Core.Jobs;

namespace CodeSignAuto.Service.Jobs;

public sealed class JobCleanupService(
    IJobStore jobs,
    ISpoolStore spool,
    IJobCompletionNotifier notifier,
    TimeProvider timeProvider,
    ILogger<JobCleanupService> logger,
    ILocalUploadCleanup? localUploads = null) : BackgroundService
{
    private static readonly EventId CleanupFailureEvent = new(2002, "JobCleanupFailed");
    public const int BatchSize = 100;
    public static readonly TimeSpan CleanupInterval = TimeSpan.FromHours(1);
    public static readonly TimeSpan StalePartAge = TimeSpan.FromHours(1);

    private readonly IJobStore _jobs = jobs ?? throw new ArgumentNullException(nameof(jobs));
    private readonly ISpoolStore _spool = spool ?? throw new ArgumentNullException(nameof(spool));
    private readonly IJobCompletionNotifier _notifier = notifier ?? throw new ArgumentNullException(nameof(notifier));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly ILogger<JobCleanupService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    private readonly ILocalUploadCleanup? _localUploads = localUploads;

    private long _maintenanceRowId;
    private IEnumerator<SpoolJobDirectory>? _directories;
    private bool _directoriesComplete;
    private bool _jobsComplete;
    private bool _cleanupPending;
    private DateTimeOffset _orphanCutoff;

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await RecoverStartupAsync(cancellationToken).ConfigureAwait(false);
        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task RecoverStartupAsync(CancellationToken cancellationToken)
    {
        _spool.ValidateRoot();
        await _jobs.RecoverActiveLeasesAsync(cancellationToken).ConfigureAwait(false);
        if (_localUploads is not null)
        {
            await _localUploads.CleanupExpiredAsync(cancellationToken).ConfigureAwait(false);
        }

        ResetMaintenance();
        // Validate a bounded portion before accepting work; hash historical results in the background.
        await InspectDirectoriesAsync(cancellationToken, startup: true).ConfigureAwait(false);
    }

    public async Task<bool> RunMaintenanceBatchAsync(CancellationToken cancellationToken)
    {
        if (!_jobsComplete)
        {
            var batch = await _jobs.GetMaintenanceBatchAsync(_maintenanceRowId, BatchSize, cancellationToken)
                .ConfigureAwait(false);
            foreach (var entry in batch)
            {
                await MaintainJobAsync(entry.Job, cancellationToken).ConfigureAwait(false);
                _maintenanceRowId = entry.RowId;
            }

            _jobsComplete = batch.Count < BatchSize;
        }

        await InspectDirectoriesAsync(cancellationToken).ConfigureAwait(false);
        return !_jobsComplete || !_directoriesComplete;
    }

    private async Task MaintainJobAsync(Job job, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (job.State is JobState.Succeeded or JobState.Failed or JobState.Expired)
        {
            await _spool.DeleteStalePartsAsync(job, _timeProvider.GetUtcNow() - StalePartAge, cancellationToken)
                .ConfigureAwait(false);
        }

        if (job.State != JobState.Succeeded || job.ResultSize is null || string.IsNullOrWhiteSpace(job.ResultSha256))
        {
            return;
        }

        try
        {
            await using var verified = await _spool.OpenVerifiedResultAsync(
                job.Id, job.Extension, job.ResultSize.Value, job.ResultSha256, cancellationToken).ConfigureAwait(false);
        }
        catch (SpoolException)
        {
            if (await _jobs.TryFailSucceededResultAsync(job.Id, job.ResultSize.Value, job.ResultSha256,
                "result_corrupt", "The signed result failed integrity verification.", cancellationToken)
                .ConfigureAwait(false) && await _jobs.GetAsync(job.Id, cancellationToken).ConfigureAwait(false) is { } failed)
            {
                _notifier.Notify(failed);
            }

            return;
        }

        await _spool.DeleteSucceededTransientFilesAsync(job, cancellationToken).ConfigureAwait(false);
    }

    private async Task InspectDirectoriesAsync(CancellationToken cancellationToken, bool startup = false)
    {
        if (_directoriesComplete)
        {
            return;
        }

        _directories ??= _spool.EnumerateJobDirectories().GetEnumerator();
        for (var count = 0; count < BatchSize; count++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_directories.MoveNext())
            {
                _directories.Dispose();
                _directories = null;
                _directoriesComplete = true;
                return;
            }

            var directory = _directories.Current;
            if (directory.JobId is { } jobId)
            {
                if (await _jobs.GetAsync(jobId, cancellationToken).ConfigureAwait(false) is { } persisted)
                {
                    if (startup && !IsActive(persisted.State))
                    {
                        await _spool.DeleteStalePartsAsync(persisted, _orphanCutoff, cancellationToken).ConfigureAwait(false);
                    }

                    continue;
                }

                if (_localUploads is not null &&
                    await _localUploads.GetOwnershipAsync(jobId, cancellationToken).ConfigureAwait(false) is { } ownership)
                {
                    _spool.ValidateLocalUploadArtifacts(jobId, ownership.Extension);
                    continue;
                }
            }

            // Newly created uploads may not have their database record yet.
            if (Directory.Exists(directory.Path) && Directory.GetLastWriteTimeUtc(directory.Path) <= _orphanCutoff.UtcDateTime)
            {
                await _spool.QuarantineAsync(directory, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private void ResetMaintenance()
    {
        _directories?.Dispose();
        _directories = null;
        _directoriesComplete = false;
        _jobsComplete = false;
        _maintenanceRowId = 0;
        _orphanCutoff = _timeProvider.GetUtcNow() - StalePartAge;
    }

    public override void Dispose()
    {
        base.Dispose();
        _directories?.Dispose();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await RunCleanupCycleAsync(stoppingToken).ConfigureAwait(false);
                var more = true;
                try
                {
                    more = await RunMaintenanceBatchAsync(stoppingToken).ConfigureAwait(false) || _cleanupPending;
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception)
                {
                    _logger.LogError(CleanupFailureEvent, "Job maintenance failed. Code: {Code}", "job_maintenance_failed");
                    ResetMaintenance();
                    more = false;
                }

                await Task.Delay(more ? TimeSpan.FromSeconds(1) : CleanupInterval, _timeProvider, stoppingToken)
                    .ConfigureAwait(false);
                if (!more)
                {
                    ResetMaintenance();
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            _directories?.Dispose();
            _directories = null;
        }
    }

    public async Task RunCleanupCycleAsync(CancellationToken cancellationToken)
    {
        try
        {
            _cleanupPending = await CleanupExpiredAsync(cancellationToken).ConfigureAwait(false) >= BatchSize;
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
        var jobCount = 0;
        while (jobCount < BatchSize && await _jobs.TryExpireNextAsync(
                _timeProvider.GetUtcNow(),
                (job, token) => _spool.DeleteJobAsync(job.Id, token),
                cancellationToken).ConfigureAwait(false) is { } expired)
        {
            _notifier.Retire(expired);
            expiredCount++;
            jobCount++;
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
