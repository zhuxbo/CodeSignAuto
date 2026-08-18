using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Protocol;
using SimplySignAuto.Service.Ipc;

namespace SimplySignAuto.Service.Jobs;

public interface IServiceManagementSnapshotProvider
{
    Task<ManagementSnapshot> CreateAsync(
        AgentHealthSnapshot health,
        CancellationToken cancellationToken);

    Task<JobPageData> CreateJobPageAsync(
        JobPageCursor? cursor,
        CancellationToken cancellationToken) =>
        Task.FromException<JobPageData>(new InvalidOperationException("management_unavailable"));

    Task<TerminalJobDeltaData> CreateTerminalJobDeltaAsync(
        TerminalJobWatermark? watermark,
        TerminalJobCursor? cursor,
        CancellationToken cancellationToken) =>
        Task.FromException<TerminalJobDeltaData>(new InvalidOperationException("management_unavailable"));

    ServiceSettingsSummary GetServiceSettings() =>
        throw new InvalidOperationException("management_unavailable");
}

public sealed class ServiceManagementSnapshotProvider : IServiceManagementSnapshotProvider
{
    private readonly IJobStore _jobs;
    private readonly TimeProvider _timeProvider;
    private readonly ServiceSettingsSummary? _settings;

    public ServiceManagementSnapshotProvider(
        IJobStore jobs,
        TimeProvider timeProvider,
        ServiceSettingsSummary? settings = null)
    {
        _jobs = jobs ?? throw new ArgumentNullException(nameof(jobs));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _settings = settings;
    }

    public Task<JobPageData> CreateJobPageAsync(
        JobPageCursor? cursor,
        CancellationToken cancellationToken) =>
        _jobs.GetJobPageAsync(
            cursor,
            _timeProvider.GetUtcNow().ToUniversalTime(),
            cancellationToken);

    public Task<TerminalJobDeltaData> CreateTerminalJobDeltaAsync(
        TerminalJobWatermark? watermark,
        TerminalJobCursor? cursor,
        CancellationToken cancellationToken) =>
        _jobs.GetTerminalJobDeltaAsync(
            watermark,
            cursor,
            cancellationToken);

    public ServiceSettingsSummary GetServiceSettings() =>
        _settings ?? throw new InvalidOperationException("management_unavailable");

    public async Task<ManagementSnapshot> CreateAsync(
        AgentHealthSnapshot health,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(health);
        var now = _timeProvider.GetUtcNow().ToUniversalTime();
        var jobs = await _jobs.GetManagementStateAsync(cancellationToken).ConfigureAwait(false);
        var heartbeat = health.Heartbeat;
        var heartbeatAge = health.LastHeartbeatUtc is { } receivedAt
            ? checked((long)(now - receivedAt.ToUniversalTime()).TotalMilliseconds)
            : (long?)null;
        var configured = health.Capabilities.ToHashSet(StringComparer.Ordinal);
        var sessionGeneration = heartbeat?.SessionGeneration ?? 1;
        var authenticode = NormalizeCapability(
            configured.Contains("authenticode"),
            heartbeat?.Authenticode,
            "authenticode",
            sessionGeneration,
            health.SessionId,
            now);
        var pdf = NormalizeCapability(
            configured.Contains("pdf"),
            heartbeat?.Pdf,
            "pdf",
            sessionGeneration,
            health.SessionId,
            now);
        var processSession = heartbeat?.SimplySignProcessSessionId;
        var processRunning = processSession is not null;
        var current = jobs.CurrentJob is { } currentJob
            ? MapCurrentJob(currentJob, now)
            : null;
        var recent = jobs.RecentJobs.Select(MapRecentJob).ToArray();
        return new ManagementSnapshot(
            ManagementSnapshot.CurrentVersion,
            now,
            health.ConnectionId,
            true,
            true,
            health.SessionId,
            heartbeat?.SessionId ?? 0,
            heartbeatAge,
            processRunning,
            processSession,
            authenticode,
            pdf,
            jobs.QueuedJobCount,
            jobs.ActiveJobCount,
            current,
            recent,
            sessionGeneration,
            heartbeat?.Certificates ?? []);
    }

    private static CapabilitySnapshot NormalizeCapability(
        bool configured,
        CapabilitySnapshot? reported,
        string alias,
        long sessionGeneration,
        int sessionId,
        DateTimeOffset now)
    {
        if (!configured)
        {
            return CapabilitySnapshot.NotConfigured();
        }

        return reported is { Configured: true, Session: not null } &&
            reported.Session.SessionGeneration == sessionGeneration
            ? reported
            : UnavailableCapability(
                reported is null ? "heartbeat_missing" : "heartbeat_invalid",
                new SimplySignSessionSnapshot(
                    SimplySignSessionState.Unknown,
                    sessionGeneration,
                    now,
                    now,
                    sessionId > 0 ? sessionId : null,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    "unknown",
                    0,
                    null));
    }

    private static CapabilitySnapshot UnavailableCapability(
        string reasonCode,
        SimplySignSessionSnapshot session) =>
        new(
            true,
            false,
            false,
            null,
            false,
            false,
            null,
            false,
            false,
            null,
            false,
            reasonCode,
            session: session);

    private static CurrentJobSnapshot MapCurrentJob(Job job, DateTimeOffset now)
    {
        var started = job.StartedAt?.ToUniversalTime()
            ?? throw new InvalidOperationException("management_unavailable");
        var elapsed = now - started;
        return new CurrentJobSnapshot(
            job.Id,
            Kind(job.Kind),
            CurrentState(job.State),
            CurrentState(job.State),
            started,
            checked((long)Math.Max(0, elapsed.TotalSeconds)));
    }

    private static RecentJobSnapshot MapRecentJob(Job job)
    {
        var completed = job.CompletedAt?.ToUniversalTime()
            ?? throw new InvalidOperationException("management_unavailable");
        var state = TerminalState(job.State);
        var errorCode = state == "succeeded"
            ? null
            : ManagementJobCodes.IsErrorCode(job.ErrorCode) ? job.ErrorCode : "internal_error";
        return new RecentJobSnapshot(job.Id, Kind(job.Kind), state, completed, errorCode);
    }

    private static string Kind(FileKind kind) => kind switch
    {
        FileKind.Authenticode => "authenticode",
        FileKind.Pdf => "pdf",
        _ => throw new InvalidOperationException("management_unavailable"),
    };

    private static string CurrentState(JobState state) => state switch
    {
        JobState.WaitingForAgent => "waiting_for_agent",
        JobState.Signing => "signing",
        JobState.Verifying => "verifying",
        _ => throw new InvalidOperationException("management_unavailable"),
    };

    private static string TerminalState(JobState state) => state switch
    {
        JobState.Succeeded => "succeeded",
        JobState.Failed => "failed",
        JobState.Expired => "expired",
        _ => throw new InvalidOperationException("management_unavailable"),
    };
}
