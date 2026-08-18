using System.Security.Cryptography;
using SimplySignAuto.Agent;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.Security;
using SimplySignAuto.Agent.Sessions;
using SimplySignAuto.Agent.Signing;
using SimplySignAuto.Agent.SimplySign;
using SimplySignAuto.App.Commands;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Core.Otp;
using SimplySignAuto.Protocol;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class AgentRuntimeCompositionTests
{
    private const string UserSid = "S-1-5-21-1000-2000-3000-4000";

    [Fact]
    public void Managed_factory_exposes_async_ownership_for_the_shared_local_client()
    {
        using var fixture = new Fixture();
        using var factory = new AgentRuntimePipeSessionFactory(
            fixture.Configuration,
            new ThrowingOtpStore(),
            new AgentManagementBridge());

        Assert.IsAssignableFrom<IAsyncDisposable>(factory);
    }

    [Fact]
    public void Cache_dispose_unsubscribes_before_manager_disposal_and_a_captured_late_callback_is_a_noop()
    {
        using var fixture = new Fixture();
        var controller = new RecordingManagementController();
        var cache = new CapabilityProbeCache(
            controller,
            7,
            authenticodeConfigured: true,
            pdfConfigured: true);
        var lateCallback = Assert.Single(controller.SnapshotSubscribers);
        var snapshot = controller.GetSnapshot();

        cache.Dispose();
        controller.ThrowOnGroupRead = true;

        Assert.Empty(controller.SnapshotSubscribers);
        lateCallback(controller, snapshot);
    }

    [Fact]
    public async Task Production_session_factory_reaches_real_worker_and_owns_backend_lifecycle()
    {
        using var fixture = new Fixture();
        var input = "%PDF-synthetic-input"u8.ToArray();
        var jobId = Guid.NewGuid();
        var jobDirectory = Path.Combine(fixture.SpoolPath, jobId.ToString("N"));
        Directory.CreateDirectory(jobDirectory);
        await File.WriteAllBytesAsync(Path.Combine(jobDirectory, "input.pdf"), input);
        var command = new SignJobCommand(
            jobId,
            Guid.NewGuid(),
            1,
            ".pdf",
            """{"box":[10,20,30,40],"certificateSerialNumber":"6F09D233","digestAlgorithm":"sha256","fieldName":"Signature1","kind":"pdf","page":1}""",
            input.Length,
            Sha256(input));
        await using var stream = await PreloadedCaptureStream.CreateAsync(command);
        var pdfSigner = new RecordingPdfSigner();
        var authenticodeSigner = new RecordingAuthenticodeSigner();
        var controller = new RecordingManagementController();
        var lifetime = new RecordingLifetime();
        var backendFactory = new RecordingBackendFactory(new AgentSigningBackends(
            authenticodeSigner,
            pdfSigner,
            controller,
            lifetime));
        var factory = new AgentRuntimePipeSessionFactory(
            fixture.Configuration,
            new ThrowingOtpStore(),
            backendFactory,
            () => new AgentPipeClient(
                _ => ValueTask.FromResult<Stream>(stream),
                new InfiniteDelay()));
        var sessionInfo = new InteractiveSessionInfo(7, UserSid, "4000");
        var session = factory.Create(sessionInfo);
        var disposable = Assert.IsAssignableFrom<IAsyncDisposable>(session);

        try
        {
            await session.RunAsync(sessionInfo, new AgentReadiness("ready"), CancellationToken.None);
        }
        finally
        {
            await disposable.DisposeAsync();
        }

        Assert.Equal(1, backendFactory.Calls);
        Assert.Equal(1, controller.ReadyLeaseCalls);
        Assert.Equal(0, authenticodeSigner.Calls);
        Assert.Equal(1, pdfSigner.Calls);
        Assert.False(lifetime.Disposed);
        await factory.DisposeAsync();
        Assert.True(lifetime.Disposed);
        await using var written = new MemoryStream(stream.WrittenBytes);
        var hello = Assert.IsType<AgentHello>(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.Equal(["authenticode", "pdf"], hello.Capabilities);
        Assert.Equal(
            new JobProgress(jobId, command.DispatchId, 10, "signing"),
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.Equal(
            new JobProgress(jobId, command.DispatchId, 90, "verifying"),
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.Equal(
            new JobCompleted(jobId, command.DispatchId, 17, new string('b', 64)),
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
    }

    [Fact]
    public async Task Managed_factory_connects_ui_bridge_to_the_same_client_controller_and_heartbeat_cache()
    {
        using var fixture = new Fixture();
        await using var stream = new BlockingCaptureStream();
        var controller = new RecordingManagementController();
        var lifetime = new RecordingLifetime();
        var bridge = new AgentManagementBridge();
        var backends = new AgentSigningBackends(
            new RecordingAuthenticodeSigner(),
            new RecordingPdfSigner(),
            controller,
                lifetime);
        var factory = new AgentRuntimePipeSessionFactory(
            fixture.Configuration,
            new ThrowingOtpStore(),
            new RecordingBackendFactory(backends),
            () => new AgentPipeClient(
                _ => ValueTask.FromResult<Stream>(stream),
                new InfiniteDelay()),
            bridge);
        var sessionInfo = new InteractiveSessionInfo(7, UserSid, "4000");
        var session = factory.Create(sessionInfo);
        var disposable = Assert.IsAssignableFrom<IAsyncDisposable>(session);
        using var runCancellation = new CancellationTokenSource();
        var run = session.RunAsync(sessionInfo, new AgentReadiness("ready"), runCancellation.Token);
        await stream.WaitForFrameCountAsync(1);
        using var refreshCancellation = new CancellationTokenSource();
        var refresh = bridge.RefreshAsync(refreshCancellation.Token);
        await stream.WaitForFrameCountAsync(3);
        refreshCancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => refresh);
        var sourcePath = Path.Combine(fixture.SpoolPath, "selected.exe");
        await File.WriteAllBytesAsync(sourcePath, "MZ-local-input"u8.ToArray());
        using var localCancellation = new CancellationTokenSource();
        var submit = bridge.CreateAndUploadAsync(
            sourcePath,
            new AuthenticodeParameters("52A1B4C9", "sha256", false),
            null,
            localCancellation.Token);
        await Task.Delay(TimeSpan.FromMilliseconds(25));
        if (submit.IsCompleted)
        {
            await submit;
        }

        await stream.WaitForFrameCountAsync(4);
        localCancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => submit);
        runCancellation.Cancel();
        await run;
        await disposable.DisposeAsync();

        Assert.Contains(SessionTrigger.ManualRefresh, controller.CheckTriggers);
        Assert.False(lifetime.Disposed);
        await factory.DisposeAsync();
        Assert.True(lifetime.Disposed);
        await using var written = new MemoryStream(stream.WrittenBytes);
        Assert.IsType<AgentHello>(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        var heartbeat = Assert.IsType<AgentHeartbeat>(
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.True(heartbeat.Authenticode!.Ready);
        Assert.True(heartbeat.Pdf!.Ready);
        Assert.IsType<ManagementSnapshotRequest>(
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.IsType<LocalJobCreateRequest>(
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
    }

    [Fact]
    public async Task Managed_owner_joins_blocking_probe_before_disposing_cache_and_backend_exactly_once()
    {
        using var fixture = new Fixture();
        await using var stream = new BlockingCaptureStream();
        var controller = new RecordingManagementController();
        var lifetime = new RecordingLifetime();
        var bridge = new AgentManagementBridge();
        var factory = new AgentRuntimePipeSessionFactory(
            fixture.Configuration,
            new ThrowingOtpStore(),
            new RecordingBackendFactory(new AgentSigningBackends(
                new RecordingAuthenticodeSigner(),
                new RecordingPdfSigner(),
                controller,
                lifetime)),
            () => new AgentPipeClient(
                _ => ValueTask.FromResult<Stream>(stream),
                new InfiniteDelay()),
            bridge);
        var sessionInfo = new InteractiveSessionInfo(7, UserSid, "4000");
        var session = factory.Create(sessionInfo);
        var disposable = Assert.IsAssignableFrom<IAsyncDisposable>(session);
        using var runCancellation = new CancellationTokenSource();
        var run = session.RunAsync(sessionInfo, new AgentReadiness("ready"), runCancellation.Token);
        await stream.WaitForFrameCountAsync(1);
        controller.BlockProbes = true;
        var refresh = bridge.RefreshAsync(default);
        await controller.ProbeBlocked.Task.WaitAsync(TimeSpan.FromSeconds(1));
        runCancellation.Cancel();
        await run.WaitAsync(TimeSpan.FromSeconds(1));

        var firstDispose = disposable.DisposeAsync().AsTask();
        var secondDispose = disposable.DisposeAsync().AsTask();
        await Task.Yield();
        Assert.False(firstDispose.IsCompleted);
        Assert.False(lifetime.Disposed);
        Assert.Same(firstDispose, secondDispose);
        controller.ReleaseProbe();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => refresh);
        await firstDispose.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(lifetime.Disposed);
        Assert.True(secondDispose.IsCompletedSuccessfully);
        await factory.DisposeAsync();
        Assert.True(lifetime.Disposed);
        Assert.Equal(1, lifetime.DisposeCalls);
    }

    [Fact]
    public async Task Managed_factory_reuses_one_pipe_client_and_local_job_client_across_sessions()
    {
        using var fixture = new Fixture();
        var bridge = new AgentManagementBridge();
        var clientCreations = 0;
        var lifetime = new RecordingLifetime();
        var backendFactory = new RecordingBackendFactory(new AgentSigningBackends(
            new RecordingAuthenticodeSigner(),
            new RecordingPdfSigner(),
            new RecordingManagementController(),
            lifetime));
        var factory = new AgentRuntimePipeSessionFactory(
            fixture.Configuration,
            new ThrowingOtpStore(),
            backendFactory,
            () =>
            {
                clientCreations++;
                return new AgentPipeClient(
                    _ => throw new InvalidOperationException("not_connected"),
                    new InfiniteDelay());
            },
            bridge);
        var sessionInfo = new InteractiveSessionInfo(7, UserSid, "4000");

        var first = Assert.IsAssignableFrom<IAsyncDisposable>(factory.Create(sessionInfo));
        await first.DisposeAsync();
        var second = Assert.IsAssignableFrom<IAsyncDisposable>(factory.Create(sessionInfo));
        await second.DisposeAsync();

        Assert.Equal(1, clientCreations);
        Assert.Equal(1, backendFactory.Calls);
        Assert.False(lifetime.Disposed);
        await factory.DisposeAsync();
        Assert.True(lifetime.Disposed);
    }

    [Fact]
    public async Task Production_composition_starts_the_background_health_probe_immediately()
    {
        using var fixture = new Fixture();
        var controller = new RecordingManagementController();
        var factory = new AgentRuntimePipeSessionFactory(
            fixture.Configuration,
            new ThrowingOtpStore(),
            new RecordingBackendFactory(new AgentSigningBackends(
                new RecordingAuthenticodeSigner(),
                new RecordingPdfSigner(),
                controller,
                new RecordingLifetime())),
            () => new AgentPipeClient(
                _ => throw new InvalidOperationException("not_connected"),
                new InfiniteDelay()),
            new AgentManagementBridge());
        var session = Assert.IsAssignableFrom<IAsyncDisposable>(factory.Create(
            new InteractiveSessionInfo(7, UserSid, "4000")));

        await controller.WaitForHealthCallsAsync(1);

        Assert.Equal(1, controller.HealthCalls);

        await session.DisposeAsync();
        await factory.DisposeAsync();
    }

    private static string Sha256(byte[] value) =>
        Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();

    [Fact]
    public void Catalog_and_probe_bind_the_fixed_product_executable_when_optional_pdf_is_absent()
    {
        using var fixture = new Fixture();
        var programFiles = TestPaths.Controlled("Program Files");

        _ = AgentConfigurationLoader.Validate(fixture.Configuration);
        var executable = DefaultAgentSigningBackendFactory.ResolveProductExecutable(programFiles);

        Assert.Equal(
            Path.Combine(programFiles, "SimplySignAuto", "SimplySignAuto.exe"),
            executable);
    }

    [Fact]
    public async Task Agent_startup_rechecks_optional_pdf_without_blocking_authenticode_when_absent()
    {
        using var fixture = new Fixture();
        var resolver = new AbsentPdfToolResolver();

        var resolution = await DefaultAgentRunner.ResolveOptionalPdfToolAtStartupAsync(
            fixture.Configuration,
            resolver,
            CancellationToken.None);

        Assert.Equal(1, resolver.Calls);
        Assert.Equal(InstalledPdfToolStatus.NotInstalled, resolution.Status);
        Assert.NotNull(fixture.Configuration.Authenticode);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _root = Path.Combine(
            Path.GetTempPath(),
            "SimplySignAuto.Tests",
            Guid.NewGuid().ToString("N"));

        public Fixture()
        {
            Directory.CreateDirectory(SpoolPath);
            Configuration = new AgentConfiguration(
                UserSid,
                SpoolPath,
                Path.Combine(_root, "SimplySignDesktop.exe"),
                Path.Combine(_root, "synthetic-pkcs11.dll"),
                new AgentAuthenticodeConfiguration(
                    Path.Combine(_root, "signtool.exe"), "http://time.certum.pl/"),
                new AgentPdfConfiguration("http://time.certum.pl/"));
        }

        public string SpoolPath => Path.Combine(_root, "spool");

        public AgentConfiguration Configuration { get; }

        public void Dispose()
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
    }

    private sealed class RecordingBackendFactory(AgentSigningBackends backends) : IAgentSigningBackendFactory
    {
        public int Calls { get; private set; }

        public AgentSigningBackends Create(
            AgentConfiguration configuration,
            InteractiveSessionInfo session,
            IOtpStore otpStore)
        {
            Calls++;
            return backends;
        }
    }

    private sealed class AbsentPdfToolResolver : IInstalledPdfToolResolver
    {
        public int Calls { get; private set; }

        public Task<InstalledPdfToolResolution> ResolveAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return Task.FromResult(InstalledPdfToolResolution.NotInstalled());
        }
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null &&
            !File.Exists(Path.Combine(current.FullName, "SimplySignAuto.sln")))
        {
            current = current.Parent;
        }

        return current?.FullName ?? throw new InvalidOperationException("repository_root_not_found");
    }

    private sealed class RecordingManagementController : ISimplySignSessionManager
    {
        private readonly TaskCompletionSource _releaseProbe =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public List<SessionTrigger> CheckTriggers { get; } = [];
        public bool BlockProbes { get; set; }
        public int ReadyLeaseCalls { get; private set; }
        public int HealthCalls { get; private set; }
        private TaskCompletionSource _healthChanged =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ProbeBlocked { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        private EventHandler<SimplySignSessionSnapshot>? _snapshotChanged;

        public List<EventHandler<SimplySignSessionSnapshot>> SnapshotSubscribers { get; } = [];
        public bool ThrowOnGroupRead { get; set; }

        public event EventHandler<SimplySignSessionSnapshot>? SnapshotChanged
        {
            add
            {
                _snapshotChanged += value;
                SnapshotSubscribers.Add(value!);
            }
            remove
            {
                _snapshotChanged -= value;
                SnapshotSubscribers.Remove(value!);
            }
        }

        public SimplySignSessionSnapshot GetSnapshot() => ReadySnapshot();

        public SimplySignCapabilityGroup GetCapabilityGroup()
        {
            if (ThrowOnGroupRead)
            {
                throw new ObjectDisposedException(nameof(RecordingManagementController));
            }

            return new SimplySignCapabilityGroup(
                1,
                ReadySnapshot(),
                CatalogSnapshot());
        }

        public async Task<SimplySignSessionSnapshot> CheckAsync(
            SessionTrigger trigger,
            CancellationToken cancellationToken)
        {
            CheckTriggers.Add(trigger);
            if (trigger == SessionTrigger.BackgroundHealth)
            {
                HealthCalls++;
                _healthChanged.TrySetResult();
            }

            if (BlockProbes)
            {
                ProbeBlocked.TrySetResult();
                await _releaseProbe.Task;
            }

            cancellationToken.ThrowIfCancellationRequested();
            var snapshot = ReadySnapshot();
            _snapshotChanged?.Invoke(this, snapshot);
            return snapshot;
        }

        public Task<SimplySignSessionSnapshot> PrepareStartupAsync(CancellationToken cancellationToken) =>
            CheckAsync(SessionTrigger.Startup, cancellationToken);

        public Task<SimplySignSessionSnapshot> EnsureReadyAsync(
            SessionTrigger trigger,
            CancellationToken cancellationToken) => CheckAsync(trigger, cancellationToken);

        public Task<IReadySignLease> AcquireReadySignLeaseAsync(
            CancellationToken cancellationToken)
        {
            ReadyLeaseCalls++;
            return Task.FromResult<IReadySignLease>(new RecordingReadyLease(
                ReadySnapshot(), CatalogSnapshot(), cancellationToken));
        }

        public void Invalidate()
        {
        }

        public void Dispose()
        {
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        public void ReleaseProbe() => _releaseProbe.TrySetResult();

        public async Task WaitForHealthCallsAsync(int expected)
        {
            while (HealthCalls < expected)
            {
                var source = _healthChanged;
                await source.Task.WaitAsync(TimeSpan.FromSeconds(1));
                Interlocked.CompareExchange(
                    ref _healthChanged,
                    new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously),
                    source);
            }
        }

        private static SimplySignSessionSnapshot ReadySnapshot() => new(
            SimplySignSessionState.Ready,
            1,
            DateTimeOffset.Parse("2026-08-12T00:00:00Z"),
            DateTimeOffset.Parse("2026-08-12T00:00:00Z"),
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
            null,
            true,
            7);

        private static CertificateCatalogSnapshot CatalogSnapshot()
        {
            var certificate = new SigningCertificate(
                "Synthetic",
                "6F09D233",
                TestPaths.Controlled("pkcs11.dll"),
                1,
                "TOKEN",
                "aa11",
                "aa11",
                new string('A', 40),
                DateTimeOffset.Parse("2026-08-11T00:00:00Z"),
                DateTimeOffset.Parse("2027-08-12T00:00:00Z"),
                true,
                true);
            return new CertificateCatalogSnapshot(
                1,
                DateTimeOffset.Parse("2026-08-12T00:00:00Z"),
                new Dictionary<string, IReadOnlyList<SigningCertificate>>(StringComparer.Ordinal)
                {
                    [certificate.SerialNumber] = [certificate],
                });
        }

        private sealed class RecordingReadyLease(
            SimplySignSessionSnapshot snapshot,
            CertificateCatalogSnapshot catalogSnapshot,
            CancellationToken cancellationToken) : IReadySignLease
        {
            public SimplySignSessionSnapshot Snapshot { get; } = snapshot;
            public CertificateCatalogSnapshot CatalogSnapshot { get; } = catalogSnapshot;
            public CancellationToken CancellationToken { get; } = cancellationToken;

            public Task<T> RunAsync<T>(Func<CancellationToken, Task<T>> operation) =>
                operation(CancellationToken);

            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }

    private sealed class RecordingPdfSigner : IPdfSigner
    {
        public int Calls { get; private set; }

        public Task<SigningResult> SignAsync(
            SigningContext context,
            PdfParameters parameters,
            SigningCertificate certificate,
            CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new SigningResult(17, new string('b', 64)));
        }
    }

    private sealed class RecordingAuthenticodeSigner : IAuthenticodeSigner
    {
        public int Calls { get; private set; }

        public Task<SigningResult> SignAsync(
            SigningContext context,
            AuthenticodeParameters parameters,
            SigningCertificate certificate,
            CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromException<SigningResult>(new InvalidOperationException("not called"));
        }
    }

    private sealed class RecordingLifetime : IDisposable
    {
        public bool Disposed { get; private set; }
        public int DisposeCalls { get; private set; }

        public void Dispose()
        {
            DisposeCalls++;
            Disposed = true;
        }
    }

    private sealed class ThrowingOtpStore : IOtpStore
    {
        public string Path => "/synthetic/otp.dat";

        public Task SaveAsync(OtpauthProfile profile, CancellationToken cancellationToken = default) =>
            Task.FromException(new InvalidOperationException("not called"));

        public Task<OtpauthProfile> LoadAsync(CancellationToken cancellationToken = default) =>
            Task.FromException<OtpauthProfile>(new InvalidOperationException("not called"));
    }

    private sealed class InfiniteDelay : IAgentDelay
    {
        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
            Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
    }

    private sealed class RecordingBlockingDelay : IAgentDelay
    {
        public List<TimeSpan> RequestedDelays { get; } = [];

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            RequestedDelays.Add(delay);
            return Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }
    }

    private sealed class PreloadedCaptureStream : Stream
    {
        private readonly MemoryStream _input;
        private readonly MemoryStream _output = new();

        private PreloadedCaptureStream(byte[] input)
        {
            _input = new MemoryStream(input);
        }

        public byte[] WrittenBytes => _output.ToArray();

        public static async Task<PreloadedCaptureStream> CreateAsync(AgentMessage message)
        {
            await using var input = new MemoryStream();
            await LengthPrefixedJsonProtocol.WriteAsync(input, message, CancellationToken.None);
            return new PreloadedCaptureStream(input.ToArray());
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            _input.ReadAsync(buffer, cancellationToken);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            _output.Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        protected override void Dispose(bool disposing)
        {
            _input.Dispose();
            _output.Dispose();
            base.Dispose(disposing);
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class BlockingCaptureStream : Stream
    {
        private readonly object _sync = new();
        private readonly MemoryStream _output = new();
        private readonly TaskCompletionSource _closed =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public byte[] WrittenBytes
        {
            get
            {
                lock (_sync)
                {
                    return _output.ToArray();
                }
            }
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public async Task WaitForFrameCountAsync(int expected)
        {
            for (var attempt = 0; attempt < 1_000; attempt++)
            {
                if (FrameCount() >= expected)
                {
                    return;
                }

                await Task.Yield();
            }

            Assert.Fail($"Expected {expected} frames.");
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            await _closed.Task.WaitAsync(cancellationToken);
            return 0;
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                _output.Write(buffer.Span);
            }

            return ValueTask.CompletedTask;
        }

        protected override void Dispose(bool disposing)
        {
            _closed.TrySetResult();
            base.Dispose(disposing);
        }

        private int FrameCount()
        {
            var bytes = WrittenBytes;
            var offset = 0;
            var count = 0;
            while (offset + 4 <= bytes.Length)
            {
                var length = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(offset, 4));
                if (length <= 0 || offset + 4 + length > bytes.Length)
                {
                    break;
                }

                count++;
                offset += 4 + length;
            }

            return count;
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
