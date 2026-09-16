using System.Security.Cryptography;
using CodeSignAuto.Agent.Diagnostics;
using CodeSignAuto.Agent.Ipc;
using CodeSignAuto.Agent.Security;
using CodeSignAuto.Agent.Sessions;
using CodeSignAuto.Agent.Signing;
using CodeSignAuto.Agent.SimplySign;
using CodeSignAuto.App.Commands;
using CodeSignAuto.App.Manual;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Core.Otp;
using CodeSignAuto.Protocol;
using CodeSignAuto.Service.Jobs;
using Xunit;

namespace CodeSignAuto.EndToEnd.Tests;

public sealed class ManualSigningFlowTests
{
    [Fact]
    public async Task Manual_history_cleanup_reports_unsafe_directory_and_can_retry_without_losing_the_job()
    {
        await using var fixture = new Fixture(blockSigner: false);
        var run = fixture.Start();
        await fixture.WaitUntilReadyAsync();
        var source = await fixture.WriteSourceAsync("cleanup.exe");
        var jobId = await fixture.Runner.LocalJobs.CreateAndUploadAsync(source, Parameters(), null, default);
        await fixture.WaitForSucceededAsync([jobId]);
        var unknown = Directory.CreateDirectory(Path.Combine(fixture.Paths.SpoolPath, jobId.ToString("N"), "unknown"));
        var administration = Assert.IsAssignableFrom<IAgentAdministrationClient>(fixture.Runner.Management);
        using var viewModel = new CodeSignAuto.App.UI.ViewModels.JobsViewModel(administration, fixture.Runner.LocalJobs);

        await viewModel.ClearHistoryAsync(default);
        Assert.Equal("history_cleanup_failed", viewModel.ErrorCode);
        Assert.True(viewModel.CanClearHistory);
        Assert.Contains((await administration.GetJobPageAsync(null, default)).Items, item => item.JobId == jobId);
        Assert.True(Directory.Exists(unknown.FullName));
        Directory.Delete(unknown.FullName);
        await viewModel.ClearHistoryAsync(default);
        Assert.Null(viewModel.ErrorCode);
        Assert.Empty(viewModel.Items);
        Assert.False(Directory.Exists(Path.Combine(fixture.Paths.SpoolPath, jobId.ToString("N"))));
        Assert.True(File.Exists(source));
        fixture.Stop();
        await run.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task Manual_local_jobs_use_one_dispatcher_worker_and_keep_verified_results_for_saving()
    {
        await using var fixture = new Fixture(blockSigner: false);
        var run = fixture.Start();
        await fixture.WaitUntilReadyAsync();
        var firstSource = await fixture.WriteSourceAsync("first.exe");
        var secondSource = await fixture.WriteSourceAsync("second.exe");

        var jobIds = await Task.WhenAll(
            fixture.Runner.LocalJobs.CreateAndUploadAsync(
                firstSource,
                Parameters(),
                progress: null,
                CancellationToken.None),
            fixture.Runner.LocalJobs.CreateAndUploadAsync(
                secondSource,
                Parameters(),
                progress: null,
                CancellationToken.None));

        await fixture.WaitForSucceededAsync(jobIds);
        var firstDestination = Path.Combine(fixture.OutputRoot, "first.signed.exe");
        var secondDestination = Path.Combine(fixture.OutputRoot, "second.signed.exe");
        await fixture.Runner.LocalJobs.SaveSignedCopyAsync(
            jobIds[0], firstDestination, overwrite: false, CancellationToken.None);
        await fixture.Runner.LocalJobs.SaveSignedCopyAsync(
            jobIds[1], secondDestination, overwrite: false, CancellationToken.None);

        Assert.Equal(2, fixture.Signer.CallCount);
        Assert.Equal(1, fixture.Signer.MaximumConcurrency);
        Assert.True((await File.ReadAllBytesAsync(firstDestination)).AsSpan()
            .EndsWith(CopyingSigner.SignedTrailer));
        Assert.True((await File.ReadAllBytesAsync(secondDestination)).AsSpan()
            .EndsWith(CopyingSigner.SignedTrailer));
        Assert.True(File.Exists(fixture.Paths.DatabasePath));
        Assert.True(Directory.Exists(fixture.Paths.SpoolPath));
        Assert.Equal(fixture.Paths.OtpPath, fixture.OtpStore.Path);

        fixture.Stop();
        await run.WaitAsync(TimeSpan.FromSeconds(5));

        using var restartLifetime = new CancellationTokenSource();
        var restarted = fixture.CreateRunner();
        var restartedRun = restarted.RunAsync(fixture.Configuration, restartLifetime.Token);
        await fixture.WaitUntilReadyAsync(restarted);
        var history = await Assert.IsAssignableFrom<IAgentAdministrationClient>(restarted.Management)
            .GetJobPageAsync(null, CancellationToken.None);
        Assert.All(jobIds, jobId => Assert.Contains(
            history.Items,
            item => item.JobId == jobId && item.State == "succeeded" && item.HasResult));
        var restartedDestination = Path.Combine(fixture.OutputRoot, "first.after-restart.signed.exe");
        await restarted.LocalJobs.SaveSignedCopyAsync(
            jobIds[0], restartedDestination, overwrite: false, CancellationToken.None);
        Assert.True((await File.ReadAllBytesAsync(restartedDestination)).AsSpan()
            .EndsWith(CopyingSigner.SignedTrailer));
        Assert.Equal(2, fixture.Signer.CallCount);
        restartLifetime.Cancel();
        await restartedRun.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task Manual_shutdown_waits_for_the_current_worker_to_publish_its_terminal_state()
    {
        await using var fixture = new Fixture(blockSigner: true);
        var run = fixture.Start();
        await fixture.WaitUntilReadyAsync();
        var source = await fixture.WriteSourceAsync("blocking.exe");
        var jobId = await fixture.Runner.LocalJobs.CreateAndUploadAsync(
            source,
            Parameters(),
            progress: null,
            CancellationToken.None);
        await fixture.Signer.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        fixture.Stop();
        Assert.NotSame(run, await Task.WhenAny(run, Task.Delay(100)));

        fixture.Signer.Release();
        await run.WaitAsync(TimeSpan.FromSeconds(5));

        using var store = new SqliteJobStore(fixture.Paths.DatabasePath);
        var persisted = Assert.IsType<Job>(await store.GetAsync(jobId));
        Assert.True(
            persisted.State == JobState.Succeeded,
            $"state={persisted.State};error={persisted.ErrorCode}");
        Assert.NotNull(persisted.ResultSize);
        Assert.NotNull(persisted.ResultSha256);
    }

    [Fact]
    public async Task Manual_shutdown_waits_until_a_published_terminal_is_committed_by_the_dispatcher()
    {
        await using var fixture = new Fixture(blockSigner: false, blockResultPublication: true);
        var run = fixture.Start();
        await fixture.WaitUntilReadyAsync();
        var source = await fixture.WriteSourceAsync("publishing.exe");
        var jobId = await fixture.Runner.LocalJobs.CreateAndUploadAsync(
            source,
            Parameters(),
            progress: null,
            CancellationToken.None);
        await fixture.SpoolAcl.FinalResultEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        fixture.Stop();
        Assert.NotSame(run, await Task.WhenAny(run, Task.Delay(100)));

        fixture.SpoolAcl.ReleaseFinalResult();
        await run.WaitAsync(TimeSpan.FromSeconds(5));

        using var store = new SqliteJobStore(fixture.Paths.DatabasePath);
        var persisted = Assert.IsType<Job>(await store.GetAsync(jobId));
        Assert.True(
            persisted.State == JobState.Succeeded,
            $"state={persisted.State};error={persisted.ErrorCode}");
    }

    private static AuthenticodeParameters Parameters() => new("22", "sha256", false);

    private sealed class Fixture : IAsyncDisposable
    {
        private const string UserSid = "S-1-5-21-1000";
        private readonly string _root = Path.Combine(
            Path.GetTempPath(),
            "CodeSignAuto.Manual.E2E",
            Guid.NewGuid().ToString("N"));
        private readonly CancellationTokenSource _lifetime = new();
        private Task? _run;

        public Fixture(bool blockSigner, bool blockResultPublication = false)
        {
            Paths = ManualRuntimePaths.ForDataRoot(Path.Combine(_root, "manual"));
            OutputRoot = Directory.CreateDirectory(Path.Combine(_root, "output")).FullName;
            OtpStore = new TestOtpStore(Paths.OtpPath);
            Signer = new CopyingSigner(Paths.SpoolPath, blockSigner);
            SpoolAcl = new TestSpoolAclPolicy(blockResultPublication);
            Runner = CreateRunner();
            Configuration = new AgentConfiguration(
                UserSid,
                Path.Combine(_root, "ignored-service-spool"),
                Path.Combine(_root, "SimplySignDesktop.exe"),
                Path.Combine(_root, "SimplySignPKCS.dll"),
                new AgentAuthenticodeConfiguration(Path.Combine(_root, "signtool.exe")),
                Pdf: null);
        }

        public ManualAgentRunner CreateRunner()
        {
            var manager = new ReadySessionManager();
            return new ManualAgentRunner(
                Paths,
                OtpStore,
                new FixedBackendFactory(new AgentSigningBackends(
                    Signer,
                    PdfSigner: null,
                    manager,
                    new DisposeAction(manager.Dispose))),
                _ => new InteractiveSessionInfo(7, UserSid, "1000"),
                _ => SpoolAcl,
                PassThroughLeaseProtector.Instance,
                TimeProvider.System);
        }

        public ManualRuntimePaths Paths { get; }
        public string OutputRoot { get; }
        public TestOtpStore OtpStore { get; }
        public CopyingSigner Signer { get; }
        public TestSpoolAclPolicy SpoolAcl { get; }
        public ManualAgentRunner Runner { get; }
        public AgentConfiguration Configuration { get; }

        public Task Start() => _run = Runner.RunAsync(Configuration, _lifetime.Token);

        public void Stop() => _lifetime.Cancel();

        public async Task<string> WriteSourceAsync(string name)
        {
            var sourceRoot = Directory.CreateDirectory(Path.Combine(_root, "source"));
            var path = Path.Combine(sourceRoot.FullName, name);
            await File.WriteAllBytesAsync(path, EndToEndFixtures.UnsignedPortableExecutable);
            return path;
        }

        public Task WaitUntilReadyAsync() => WaitUntilReadyAsync(Runner);

        public async Task WaitUntilReadyAsync(ManualAgentRunner runner)
        {
            var deadline = DateTime.UtcNow.AddSeconds(5);
            while (DateTime.UtcNow < deadline)
            {
                try
                {
                    var snapshot = await runner.Management.RefreshAsync(CancellationToken.None);
                    if (snapshot.AgentConnected)
                    {
                        return;
                    }
                }
                catch (ManagementUnavailableException)
                {
                }

                await Task.Delay(10);
            }

            throw new TimeoutException("manual_runner_not_ready");
        }

        public async Task WaitForSucceededAsync(IReadOnlyCollection<Guid> jobIds)
        {
            var administration = Assert.IsAssignableFrom<IAgentAdministrationClient>(Runner.Management);
            var deadline = DateTime.UtcNow.AddSeconds(10);
            JobPageResponse? latest = null;
            while (DateTime.UtcNow < deadline)
            {
                latest = await administration.GetJobPageAsync(null, CancellationToken.None);
                if (jobIds.All(id => latest.Items.Any(item =>
                        item.JobId == id && item.State == "succeeded" && item.HasResult)))
                {
                    return;
                }

                await Task.Delay(10);
            }

            var states = latest is null
                ? "no_page"
                : string.Join(",", latest.Items
                    .Where(item => jobIds.Contains(item.JobId))
                    .Select(item => $"{item.JobId:D}:{item.State}:{item.ErrorCode}"));
            throw new TimeoutException("manual_jobs_not_succeeded:" + states);
        }

        public async ValueTask DisposeAsync()
        {
            _lifetime.Cancel();
            Signer.Release();
            SpoolAcl.ReleaseFinalResult();
            if (_run is not null)
            {
                await _run;
            }

            _lifetime.Dispose();
            if (Directory.Exists(_root))
            {
                await Task.Run(() => Directory.Delete(_root, recursive: true));
            }
        }
    }

    private sealed class CopyingSigner(string spoolRoot, bool blocked) : IAuthenticodeSigner
    {
        public static readonly byte[] SignedTrailer = "-manual-signed"u8.ToArray();
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _active;
        private int _maximumConcurrency;

        public TaskCompletionSource Entered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int CallCount { get; private set; }
        public int MaximumConcurrency => Volatile.Read(ref _maximumConcurrency);

        public async Task<SigningResult> SignAsync(
            SigningContext context,
            AuthenticodeParameters parameters,
            SigningCertificate certificate,
            CancellationToken cancellationToken)
        {
            _ = parameters;
            _ = certificate;
            CallCount++;
            var active = Interlocked.Increment(ref _active);
            UpdateMaximum(active);
            try
            {
                Entered.TrySetResult();
                if (blocked)
                {
                    await _release.Task.WaitAsync(cancellationToken);
                }
                else
                {
                    await Task.Delay(40, cancellationToken);
                }

                var directory = Path.Combine(spoolRoot, context.JobId.ToString("N"));
                var input = await File.ReadAllBytesAsync(
                    Path.Combine(directory, "input" + context.Extension),
                    cancellationToken);
                var signed = input.Concat(SignedTrailer).ToArray();
                await File.WriteAllBytesAsync(
                    Path.Combine(directory, "result.part" + context.Extension),
                    signed,
                    cancellationToken);
                return new SigningResult(
                    signed.LongLength,
                    Convert.ToHexString(SHA256.HashData(signed)).ToLowerInvariant());
            }
            finally
            {
                Interlocked.Decrement(ref _active);
            }
        }

        public void Release() => _release.TrySetResult();

        private void UpdateMaximum(int value)
        {
            var current = Volatile.Read(ref _maximumConcurrency);
            while (current < value)
            {
                var observed = Interlocked.CompareExchange(ref _maximumConcurrency, value, current);
                if (observed == current)
                {
                    return;
                }

                current = observed;
            }
        }
    }

    private sealed class ReadySessionManager : ISimplySignSessionManager
    {
        private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-08-21T00:00:00Z");
        private static readonly SigningCertificate Certificate = new(
            "Code signer",
            "22",
            Path.Combine(Path.GetTempPath(), "SimplySignPKCS.dll"),
            8,
            "CODE-TOKEN",
            "4455",
            "6677",
            "FFEEDDCCBBAA99887766554433221100FFEEDDCC",
            DateTimeOffset.Parse("2025-01-01T00:00:00Z"),
            DateTimeOffset.Parse("2030-01-01T00:00:00Z"),
            SupportsAuthenticode: true,
            SupportsPdf: false);
        private static readonly CertificateCatalogSnapshot Catalog = new(
            1,
            Now,
            new Dictionary<string, IReadOnlyList<SigningCertificate>>(StringComparer.Ordinal)
            {
                ["22"] = [Certificate],
            });

        public event EventHandler<SimplySignSessionSnapshot>? SnapshotChanged { add { } remove { } }

        public SimplySignSessionSnapshot GetSnapshot() => Snapshot();

        public SimplySignCapabilityGroup GetCapabilityGroup() => new(1, Snapshot(), Catalog);

        public Task<SimplySignSessionSnapshot> PrepareStartupAsync(CancellationToken cancellationToken) =>
            Task.FromResult(Snapshot());

        public Task<SimplySignSessionSnapshot> CheckAsync(
            SessionTrigger trigger,
            CancellationToken cancellationToken) => Task.FromResult(Snapshot());

        public Task<SimplySignSessionSnapshot> EnsureReadyAsync(
            SessionTrigger trigger,
            CancellationToken cancellationToken) => Task.FromResult(Snapshot());

        public Task<IReadySignLease> AcquireReadySignLeaseAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadySignLease>(new ReadyLease(Catalog, cancellationToken));

        public void Invalidate() { }
        public void Dispose() { }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        private static SimplySignSessionSnapshot Snapshot() => new(
            SimplySignSessionState.Ready,
            1,
            Now,
            Now,
            7,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            "ready",
            0,
            null);

        private sealed class ReadyLease(
            CertificateCatalogSnapshot catalog,
            CancellationToken cancellationToken) : IReadySignLease
        {
            public SimplySignSessionSnapshot Snapshot { get; } = ReadySessionManager.Snapshot();
            public CertificateCatalogSnapshot CatalogSnapshot { get; } = catalog;
            public CancellationToken CancellationToken { get; } = cancellationToken;
            public Task<T> RunAsync<T>(Func<CancellationToken, Task<T>> operation) =>
                operation(CancellationToken);
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }

    private sealed class FixedBackendFactory(AgentSigningBackends backends) : IAgentSigningBackendFactory
    {
        public AgentSigningBackends Create(
            AgentConfiguration configuration,
            InteractiveSessionInfo session,
            IOtpStore otpStore)
        {
            _ = configuration;
            _ = session;
            _ = otpStore;
            return backends;
        }
    }

    private sealed class TestOtpStore(string path) : IOtpStore
    {
        public string Path { get; } = path;
        public Task SaveAsync(OtpauthProfile profile, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
        public Task<OtpauthProfile> LoadAsync(CancellationToken cancellationToken = default) =>
            Task.FromException<OtpauthProfile>(new OtpStoreException("otp_missing"));
    }

    private sealed class TestSpoolAclPolicy(bool blockFinalResult) : ISpoolAclPolicy
    {
        private readonly TaskCompletionSource _releaseFinalResult =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource FinalResultEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void ProtectRoot(string path) { }
        public void ProtectJobDirectory(string path) { }
        public void ProtectInput(string path) { }

        public void ProtectFinalResult(string path)
        {
            if (!blockFinalResult)
            {
                return;
            }

            FinalResultEntered.TrySetResult();
            _releaseFinalResult.Task.GetAwaiter().GetResult();
        }

        public void ReleaseFinalResult() => _releaseFinalResult.TrySetResult();
    }

    private sealed class PassThroughLeaseProtector : ILocalLeaseProtector
    {
        public static PassThroughLeaseProtector Instance { get; } = new();
        public byte[] Protect(ReadOnlySpan<byte> lease) => lease.ToArray();
        public byte[] Unprotect(ReadOnlySpan<byte> protectedLease) => protectedLease.ToArray();
    }

    private sealed class DisposeAction(Action action) : IDisposable
    {
        private Action? _action = action;
        public void Dispose() => Interlocked.Exchange(ref _action, null)?.Invoke();
    }
}
