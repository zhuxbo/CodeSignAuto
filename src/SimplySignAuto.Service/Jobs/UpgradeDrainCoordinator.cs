using System.Diagnostics;

namespace SimplySignAuto.Service.Jobs;

public interface IUpgradeDrainCoordinator
{
    Task<bool> DrainAsync(TimeSpan timeout, CancellationToken cancellationToken);

    void Resume();
}

public sealed class UpgradeDrainCoordinator : IUpgradeDrainCoordinator
{
    private readonly IUpgradeAdmissionGate _gate;
    private readonly IJobStore _jobs;
    private readonly ILocalUploadLeaseStore _localLeases;
    private readonly TimeProvider _timeProvider;

    public UpgradeDrainCoordinator(
        IUpgradeAdmissionGate gate,
        IJobStore jobs,
        TimeProvider timeProvider)
    {
        _gate = gate ?? throw new ArgumentNullException(nameof(gate));
        _jobs = jobs ?? throw new ArgumentNullException(nameof(jobs));
        _localLeases = jobs as ILocalUploadLeaseStore ??
            throw new ArgumentException("The job store must expose local upload leases.", nameof(jobs));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public async Task<bool> DrainAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        if (timeout <= TimeSpan.Zero || timeout == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        var started = Stopwatch.GetTimestamp();
        try
        {
            if (!await _gate.DrainAsync(timeout, cancellationToken).ConfigureAwait(false))
            {
                return false;
            }

            var sealedAdmissions = false;
            while (true)
            {
                var queue = await _jobs.GetQueueSnapshotAsync(cancellationToken).ConfigureAwait(false);
                var pendingUploads = await _localLeases
                    .GetUnacceptedLocalLeasesAsync(
                        _timeProvider.GetUtcNow(),
                        cancellationToken)
                    .ConfigureAwait(false);
                if (queue is { Queued: 0, Active: 0 } && pendingUploads.Count == 0)
                {
                    if (sealedAdmissions)
                    {
                        return true;
                    }

                    var sealRemaining = timeout - Stopwatch.GetElapsedTime(started);
                    if (sealRemaining <= TimeSpan.Zero ||
                        !await _gate.SealAsync(sealRemaining, cancellationToken).ConfigureAwait(false))
                    {
                        _gate.Resume();
                        return false;
                    }

                    sealedAdmissions = true;
                    continue;
                }

                var remaining = timeout - Stopwatch.GetElapsedTime(started);
                if (remaining <= TimeSpan.Zero)
                {
                    _gate.Resume();
                    return false;
                }

                await Task.Delay(
                        remaining < TimeSpan.FromMilliseconds(100)
                            ? remaining
                            : TimeSpan.FromMilliseconds(100),
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        catch
        {
            _gate.Resume();
            throw;
        }
    }

    public void Resume() => _gate.Resume();
}
