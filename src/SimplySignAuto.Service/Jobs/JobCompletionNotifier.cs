using System.Collections.Concurrent;
using SimplySignAuto.Core.Jobs;

namespace SimplySignAuto.Service.Jobs;

public interface IJobDispatcher
{
    void Enqueue(Guid jobId);
}

public interface IJobDispatcherRuntime : IJobDispatcher
{
    Task RunAsync(CancellationToken cancellationToken);
}

public interface IJobCompletionNotifier
{
    Task<Job> WaitAsync(Guid jobId, CancellationToken cancellationToken);

    void Notify(Job job);

    void Forget(Guid jobId) => throw new NotSupportedException();

    void Retire(Job job) => throw new NotSupportedException();
}

internal interface IJobWaitRegistrationObserver
{
    void OnRegistered(Guid jobId);
}

public sealed class JobCompletionNotifier : IJobCompletionNotifier
{
    private readonly IJobStore _jobs;
    private readonly IJobWaitRegistrationObserver? _registrationObserver;
    private readonly ConcurrentDictionary<Guid, WaiterBucket> _waiters = new();

    public JobCompletionNotifier(IJobStore jobs)
    {
        _jobs = jobs ?? throw new ArgumentNullException(nameof(jobs));
    }

    internal JobCompletionNotifier(IJobStore jobs, IJobWaitRegistrationObserver registrationObserver)
        : this(jobs)
    {
        _registrationObserver = registrationObserver ??
            throw new ArgumentNullException(nameof(registrationObserver));
    }

    internal int PendingCount => _waiters.Count;

    public async Task<Job> WaitAsync(Guid jobId, CancellationToken cancellationToken)
    {
        if (jobId == Guid.Empty)
        {
            throw new ArgumentException("Job ID is required.", nameof(jobId));
        }

        if (await _jobs.GetAsync(jobId, cancellationToken).ConfigureAwait(false) is { } current && IsTerminal(current))
        {
            return current;
        }

        var registrationId = Guid.NewGuid();
        var completion = new TaskCompletionSource<Job>(TaskCreationOptions.RunContinuationsAsynchronously);
        WaiterBucket bucket;
        while (true)
        {
            bucket = _waiters.GetOrAdd(jobId, static _ => new WaiterBucket());
            if (bucket.TryRegister(registrationId, completion))
            {
                break;
            }

            RemoveBucket(jobId, bucket);
        }

        try
        {
            _registrationObserver?.OnRegistered(jobId);
            if (await _jobs.GetAsync(jobId, cancellationToken).ConfigureAwait(false) is { } persisted && IsTerminal(persisted))
            {
                bucket.Notify(persisted);
            }

            return await completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (bucket.Remove(registrationId))
            {
                RemoveBucket(jobId, bucket);
            }
        }
    }

    public void Notify(Job job)
    {
        ArgumentNullException.ThrowIfNull(job);
        if (!_waiters.TryGetValue(job.Id, out var bucket))
        {
            return;
        }

        bucket.Notify(job);
    }

    public void Forget(Guid jobId)
    {
        if (jobId == Guid.Empty)
        {
            throw new ArgumentException("Job ID is required.", nameof(jobId));
        }

        if (_waiters.TryGetValue(jobId, out var bucket))
        {
            bucket.Discard();
            RemoveBucket(jobId, bucket);
        }
    }

    public void Retire(Job job)
    {
        ArgumentNullException.ThrowIfNull(job);
        if (job.State != JobState.Expired)
        {
            throw new ArgumentException("Only expired jobs can retire completion waiters.", nameof(job));
        }

        if (_waiters.TryGetValue(job.Id, out var bucket))
        {
            bucket.Retire(job);
            RemoveBucket(job.Id, bucket);
        }
    }

    private static bool IsTerminal(Job job) =>
        job.State is JobState.Succeeded or JobState.Failed or JobState.Expired;

    private void RemoveBucket(Guid jobId, WaiterBucket bucket) =>
        ((ICollection<KeyValuePair<Guid, WaiterBucket>>)_waiters).Remove(new(jobId, bucket));

    private sealed class WaiterBucket
    {
        private readonly object _lock = new();
        private readonly Dictionary<Guid, TaskCompletionSource<Job>> _registrations = [];
        private bool _retired;

        public bool TryRegister(Guid registrationId, TaskCompletionSource<Job> completion)
        {
            lock (_lock)
            {
                if (_retired)
                {
                    return false;
                }

                _registrations.Add(registrationId, completion);
                return true;
            }
        }

        public void Notify(Job job)
        {
            lock (_lock)
            {
                if (_retired)
                {
                    return;
                }

                foreach (var completion in _registrations.Values)
                {
                    completion.TrySetResult(job);
                }
            }
        }

        public void Retire(Job job)
        {
            lock (_lock)
            {
                if (_retired)
                {
                    return;
                }

                _retired = true;
                foreach (var completion in _registrations.Values)
                {
                    completion.TrySetResult(job);
                }
            }
        }

        public void Discard()
        {
            lock (_lock)
            {
                _retired = true;
            }
        }

        public bool Remove(Guid registrationId)
        {
            lock (_lock)
            {
                _registrations.Remove(registrationId);
                if (_registrations.Count != 0 || _retired)
                {
                    return false;
                }

                _retired = true;
                return true;
            }
        }
    }
}

internal sealed class NullJobDispatcher : IJobDispatcher
{
    public void Enqueue(Guid jobId)
    {
    }
}
