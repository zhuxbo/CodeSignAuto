using System.Security.Cryptography;
using CodeSignAuto.Agent.Ipc;
using CodeSignAuto.Agent.LocalJobs;
using CodeSignAuto.App.Commands;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Core.Otp;
using CodeSignAuto.Protocol;

namespace CodeSignAuto.App.UI.Testing;

public sealed class UiTestDesktopServices : IDisposable
{
    private int _disposed;

    private UiTestDesktopServices(UiTestState state)
    {
        Management = new UiTestManagementClient(state);
        LocalJobs = new UiTestLocalJobClient();
        Configuration = CreateConfiguration();
        SafeDescription = $"ui-test-state={state.Code}";
    }

    public UiTestManagementClient Management { get; }

    public IAgentAdministrationClient Administration => Management;

    public ILocalJobClient LocalJobs { get; }

    public AgentConfiguration Configuration { get; }

    public string SafeDescription { get; }

    public static UiTestDesktopServices Create(UiTestState state) =>
        new(state ?? throw new ArgumentNullException(nameof(state)));

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            ((IDisposable)LocalJobs).Dispose();
        }
    }

    private static AgentConfiguration CreateConfiguration()
    {
        var root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "CodeSignAuto-UI-Test"));
        return new AgentConfiguration(
            "S-1-5-21-1000-2000-3000-4000",
            Path.Combine(root, "spool"),
            Path.Combine(root, "SimplySignDesktop.exe"),
            Path.Combine(root, "synthetic-pkcs11.dll"),
            new AgentAuthenticodeConfiguration(
                Path.Combine(root, "signtool.exe"),
                "http://time.certum.pl/"),
            new AgentPdfConfiguration("http://time.certum.pl/"));
    }
}

public sealed class UiTestManagementClient : IAgentManagementClient, IAgentAdministrationClient
{
    private readonly UiTestState _state;
    private ManagementSnapshot? _snapshot;
    private readonly IReadOnlyList<JobPageItem> _jobs;

    internal UiTestManagementClient(UiTestState state)
    {
        _state = state;
        _snapshot = state.Code == "unknown" ? null : CreateSnapshot(state.Code);
        _jobs = CreateJobs();
    }

    public event EventHandler? SnapshotChanged;

    public ManagementSnapshot? LatestSnapshot => _snapshot;

    public async Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
        if (_snapshot is null)
        {
            throw new ManagementUnavailableException(Guid.Parse("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"));
        }

        SnapshotChanged?.Invoke(this, EventArgs.Empty);
        return _snapshot;
    }

    public Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken) =>
        RefreshAsync(cancellationToken);

    public async Task<ManagementSnapshot> LogoutAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
        _snapshot = CreateLoggedOutSnapshot();
        SnapshotChanged?.Invoke(this, EventArgs.Empty);
        return _snapshot;
    }

    public Task<JobPageResponse> GetJobPageAsync(
        JobPageCursor? cursor,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        IReadOnlyList<JobPageItem> items;
        JobPageCursor? next;
        if (cursor is null)
        {
            items = _jobs.Take(100).ToArray();
            var last = items[^1];
            next = new JobPageCursor(
                last.State is "queued" or "waiting_for_agent" or "signing" or "verifying"
                    ? "active"
                    : "terminal",
                last.CreatedAtUtc,
                last.JobId,
                _jobs[0].CreatedAtUtc.AddMinutes(1));
        }
        else
        {
            items = [_jobs[^1]];
            next = null;
        }

        return Task.FromResult(new JobPageResponse(Guid.NewGuid(), items, next, null, null));
    }

    public Task<TerminalJobDeltaResponse> GetTerminalJobDeltaAsync(
        TerminalJobWatermark? watermark,
        TerminalJobCursor? cursor,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new TerminalJobDeltaResponse(
            Guid.NewGuid(),
            [],
            null,
            watermark ?? new TerminalJobWatermark(101),
            null,
            null));
    }

    public Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new ServiceSettingsSummary(
            7080,
            ServiceSettingsSummary.FixedMaximumUploadBytes,
            24,
            "1.0.0"));
    }

    public async Task SaveOtpAsync(OtpauthProfile profile, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);
        cancellationToken.ThrowIfCancellationRequested();
        await Task.Delay(TimeSpan.FromSeconds(3), cancellationToken).ConfigureAwait(false);
    }

    private static ManagementSnapshot CreateSnapshot(string code)
    {
        var now = new DateTimeOffset(2026, 8, 9, 0, 0, 0, TimeSpan.Zero);
        var ready = ReadyCapability(now);
        var unavailable = code == "token-missing" ? TokenMissingCapability(now) : CapabilitySnapshot.NotConfigured();
        var authenticode = code is "ready" or "active-job" or "job-failed" or "partial"
            ? ready
            : unavailable;
        var pdf = code is "ready" or "active-job" or "job-failed" ? ready : unavailable;
        var active = code == "active-job";
        var recent = code == "job-failed"
            ? new RecentJobSnapshot(
                Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                "authenticode",
                "failed",
                now.AddMinutes(-1),
                "authenticode_sign_failed")
            : null;
        return new ManagementSnapshot(
            ManagementSnapshot.CurrentVersion,
            now,
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            serviceAvailable: true,
            agentConnected: true,
            agentSessionId: code == "session0" ? 0 : 1,
            heartbeatSessionId: code == "session0" ? 0 : 1,
            heartbeatAgeMilliseconds: 50,
            simplySignProcessRunning: code != "session0",
            simplySignProcessSessionId: code == "session0" ? null : 1,
            authenticode,
            pdf,
            queuedJobCount: active ? 1 : 0,
            activeJobCount: active ? 1 : 0,
            currentJob: active
                ? new CurrentJobSnapshot(
                    Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
                    "authenticode",
                    "signing",
                    "signing",
                    now.AddSeconds(-10),
                    10)
                : null,
            recentJobs: recent is null ? [] : [recent],
            sessionGeneration: 1);
    }

    private static ManagementSnapshot CreateLoggedOutSnapshot()
    {
        var now = new DateTimeOffset(2026, 8, 9, 0, 1, 0, TimeSpan.Zero);
        return new ManagementSnapshot(
            ManagementSnapshot.CurrentVersion,
            now,
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            serviceAvailable: true,
            agentConnected: true,
            agentSessionId: 1,
            heartbeatSessionId: 1,
            heartbeatAgeMilliseconds: 50,
            simplySignProcessRunning: false,
            simplySignProcessSessionId: null,
            CapabilitySnapshot.NotConfigured(),
            CapabilitySnapshot.NotConfigured(),
            queuedJobCount: 0,
            activeJobCount: 0,
            currentJob: null,
            recentJobs: [],
            sessionGeneration: 2);
    }

    private static CapabilitySnapshot ReadyCapability(DateTimeOffset now) => new(
        configured: true,
        tokenPresent: true,
        tokenMatches: true,
        tokenSuffix: "token001",
        certificatePresent: true,
        certificateMatches: true,
        certificateSuffix: "cert0001",
        privateKeyPresent: true,
        privateKeyMatches: true,
        privateKeySuffix: "key00001",
        ready: true,
        reasonCode: "ready",
        certificateNotAfterUtc: new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero),
        certificateThumbprintSuffix: "89ABCDEF",
        session: Session("ui-ready", SimplySignSessionState.Ready, "ready", now, ready: true));

    private static CapabilitySnapshot TokenMissingCapability(DateTimeOffset now) => new(
        configured: true,
        tokenPresent: false,
        tokenMatches: false,
        tokenSuffix: null,
        certificatePresent: false,
        certificateMatches: false,
        certificateSuffix: null,
        privateKeyPresent: false,
        privateKeyMatches: false,
        privateKeySuffix: null,
        ready: false,
        reasonCode: "token_missing",
        session: Session("ui-token", SimplySignSessionState.WaitToken, "token_missing", now, ready: false));

    private static SimplySignSessionSnapshot Session(
        string alias,
        SimplySignSessionState state,
        string reasonCode,
        DateTimeOffset now,
        bool ready) =>
        new(
            state,
            1,
            now,
            now,
            1,
            ready,
            ready,
            ready,
            ready,
            ready,
            ready,
            ready,
            reasonCode,
            0,
            null,
            true,
            1);

    private static IReadOnlyList<JobPageItem> CreateJobs()
    {
        var asOf = new DateTimeOffset(2026, 8, 9, 0, 0, 0, TimeSpan.Zero);
        var jobs = new List<JobPageItem>(101);
        jobs.Add(new JobPageItem(
            Guid.Parse("00000000-0000-0000-0000-000000000001"),
            "local",
            "authenticode",
            "queued",
            "active.exe",
            asOf.AddSeconds(-1),
            null,
            null,
            null,
            Guid.Parse("10000000-0000-0000-0000-000000000001"),
            false));
        jobs.Add(new JobPageItem(
            Guid.Parse("00000000-0000-0000-0000-000000000002"),
            "api",
            "authenticode",
            "failed",
            "failed.exe",
            asOf.AddSeconds(-2),
            asOf.AddSeconds(-2),
            asOf.AddSeconds(-1),
            "authenticode_sign_failed",
            Guid.Parse("10000000-0000-0000-0000-000000000002"),
            false));
        jobs.Add(new JobPageItem(
            Guid.Parse("00000000-0000-0000-0000-000000000003"),
            "local",
            "authenticode",
            "expired",
            "expired.exe",
            asOf.AddSeconds(-3),
            asOf.AddSeconds(-3),
            asOf.AddSeconds(-2),
            "job_expired",
            Guid.Parse("10000000-0000-0000-0000-000000000003"),
            false));
        for (var index = 3; index < 101; index++)
        {
            var created = asOf.AddSeconds(-(index + 1));
            jobs.Add(new JobPageItem(
                Guid.Parse($"00000000-0000-0000-0000-{index.ToString("D12", System.Globalization.CultureInfo.InvariantCulture)}"),
                index % 2 == 0 ? "local" : "api",
                index % 3 == 0 ? "pdf" : "authenticode",
                "succeeded",
                index % 3 == 0 ? $"document-{index:D3}.pdf" : $"software-{index:D3}.exe",
                created,
                created,
                created.AddSeconds(1),
                null,
                Guid.Parse($"10000000-0000-0000-0000-{index.ToString("D12", System.Globalization.CultureInfo.InvariantCulture)}"),
                true));
        }

        return jobs;
    }
}

internal sealed class UiTestLocalJobClient : ILocalJobClient, IDisposable
{
    private readonly object _sync = new();
    private readonly Dictionary<Guid, byte[]> _results = [];
    private int _disposed;

    public UiTestLocalJobClient()
    {
        for (var index = 2; index < 101; index++)
        {
            var id = Guid.Parse($"00000000-0000-0000-0000-{index.ToString("D12", System.Globalization.CultureInfo.InvariantCulture)}");
            _results.Add(id, index % 3 == 0
                ? System.Text.Encoding.ASCII.GetBytes("%PDF-1.4\n%%EOF\n")
                : [0x4D, 0x5A, 1, 2, 3, 4]);
        }
    }

    public async Task<Guid> CreateAndUploadAsync(
        string path,
        SigningParameters parameters,
        IProgress<LocalCopyProgress>? progress,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        if (!Path.IsPathFullyQualified(path) || !string.Equals(Path.GetFullPath(path), path, StringComparison.Ordinal))
        {
            throw new LocalJobException("local_source_invalid");
        }

        var bytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        if (bytes.Length == 0)
        {
            throw new LocalJobException("local_source_empty");
        }

        var retained = false;
        try
        {
            progress?.Report(new LocalCopyProgress(bytes.Length / 4, bytes.Length, 25));
            await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken).ConfigureAwait(false);
            progress?.Report(new LocalCopyProgress(bytes.Length * 3L / 4, bytes.Length, 75));
            await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken).ConfigureAwait(false);
            progress?.Report(new LocalCopyProgress(bytes.Length, bytes.Length, 100));
            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
            var jobId = Guid.NewGuid();
            lock (_sync)
            {
                _results.Add(jobId, bytes);
                retained = true;
            }

            return jobId;
        }
        finally
        {
            if (!retained)
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }

    public async Task SaveSignedCopyAsync(
        Guid jobId,
        string destinationPath,
        bool overwrite,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        byte[] bytes;
        lock (_sync)
        {
            if (!_results.TryGetValue(jobId, out bytes!))
            {
                throw new LocalJobException("local_job_not_found");
            }

            bytes = bytes.ToArray();
        }

        try
        {
            await using var stream = new FileStream(
                destinationPath,
                overwrite ? FileMode.Create : FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.Asynchronous);
            await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (IOException)
        {
            throw new LocalJobException("local_destination_exists");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public void ReleaseAcceptedSource(Guid jobId)
    {
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        lock (_sync)
        {
            foreach (var value in _results.Values)
            {
                CryptographicOperations.ZeroMemory(value);
            }

            _results.Clear();
        }
    }
}
