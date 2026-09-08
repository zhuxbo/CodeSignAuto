using System.Security.Cryptography;
using CodeSignAuto.Agent;
using CodeSignAuto.Agent.Ipc;
using CodeSignAuto.Agent.Security;
using CodeSignAuto.Agent.Sessions;
using CodeSignAuto.Agent.Signing;
using CodeSignAuto.Agent.SimplySign;
using CodeSignAuto.Core.Otp;
using CodeSignAuto.Protocol;
using Xunit;

namespace CodeSignAuto.EndToEnd.Tests;

public sealed class UnattendedReloginTests
{
    private const int SessionId = 7;
    private static readonly CertificateAlias Code = Alias("codesign", "aa00", "bb00");
    private static readonly CertificateAlias Document = Alias("document", "cc00", "dd00");

    [Fact]
    public async Task Expired_ready_snapshot_relogs_in_before_the_next_sign_lease()
    {
        var driver = new ExpiringDriver(initiallyReady: true);
        var catalog = new ExpiringCatalog(driver);
        await using var gate = new SigningOperationGate();
        await using var manager = new SimplySignSessionManager(driver, gate, catalog);
        await using (var baseline = await manager.AcquireReadySignLeaseAsync(default))
        {
            Assert.True(baseline.Snapshot.Ready);
        }

        var states = new List<SimplySignSessionState>();
        manager.SnapshotChanged += (_, snapshot) => states.Add(snapshot.State);
        driver.Expire();
        catalog.Invalidate();
        await using var recovered = await manager.AcquireReadySignLeaseAsync(default);

        Assert.True(recovered.Snapshot.Ready);
        Assert.Equal(1, driver.LoginCalls);
        AssertOrdered(
            states,
            SimplySignSessionState.Checking,
            SimplySignSessionState.LoginRequired,
            SimplySignSessionState.Loginning,
            SimplySignSessionState.WaitToken,
            SimplySignSessionState.Ready);
    }

    [Fact]
    public async Task Twenty_real_jobs_through_the_worker_and_pipe_trigger_one_global_login()
    {
        var driver = new ExpiringDriver(initiallyReady: false);
        var catalog = new ExpiringCatalog(driver);
        await using var gate = new SigningOperationGate();
        await using var manager = new SimplySignSessionManager(driver, gate, catalog);
        var root = Path.Combine(Path.GetTempPath(), "CodeSignAuto.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var pdf = new RecordingPdfSigner();
            var authenticode = new RecordingAuthenticodeSigner();
            var worker = new SigningWorker(
                authenticode,
                pdf,
                manager,
                root);
            var commands = Enumerable.Range(0, 20)
                .Select(index => CreateCommand(root, index))
                .ToArray();
            var streams = await Task.WhenAll(commands.Select(CapturingPreloadedDuplexStream.CreateAsync));
            try
            {
                var runs = streams.Select(stream =>
                {
                    var client = new AgentPipeClient(
                        _ => ValueTask.FromResult<Stream>(stream),
                        new InfiniteAgentDelay());
                    return new AgentPipeSession(client, worker).RunAsync(
                        new InteractiveSessionInfo(SessionId, "S-1-5-21-1000", "1000"),
                        new AgentReadiness("ready"),
                        CancellationToken.None);
                });
                await Task.WhenAll(runs);

                var completed = new List<JobCompleted>();
                foreach (var stream in streams)
                {
                    await using var written = new MemoryStream(stream.WrittenBytes);
                    Assert.IsType<AgentHello>(
                        await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
                    while (written.Position < written.Length)
                    {
                        var message = await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default);
                        if (message is JobCompleted terminal)
                        {
                            completed.Add(terminal);
                        }

                        Assert.IsNotType<JobFailed>(message);
                    }
                }

                Assert.Equal(20, completed.Count);
                Assert.Equal(
                    commands.Select(command => command.JobId).Order(),
                    completed.Select(item => item.JobId).Order());
                Assert.Equal(10, pdf.CallCount);
                Assert.Equal(10, authenticode.CallCount);
                Assert.Equal(1, driver.LoginCalls);
                Assert.Equal(1, driver.MaximumProbeConcurrency);
            }
            finally
            {
                foreach (var stream in streams)
                {
                    await stream.DisposeAsync();
                }
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Background_health_observes_process_only_without_login_or_catalog_refresh()
    {
        var driver = new ExpiringDriver(initiallyReady: true);
        var catalog = new ExpiringCatalog(driver);
        await using var gate = new SigningOperationGate();
        await using var manager = new SimplySignSessionManager(driver, gate, catalog);
        _ = await manager.PrepareStartupAsync(default);
        driver.Expire();
        var refreshCalls = catalog.RefreshCalls;
        var processChecks = driver.ProcessChecks;

        var observed = await manager.CheckAsync(SessionTrigger.BackgroundHealth, default);

        Assert.True(observed.Ready);
        Assert.Equal(0, driver.LoginCalls);
        Assert.Equal(refreshCalls, catalog.RefreshCalls);
        Assert.Equal(processChecks + 1, driver.ProcessChecks);
    }

    [Fact]
    public async Task Two_failed_login_windows_fail_closed_without_an_unbounded_loop()
    {
        var driver = new ExpiringDriver(initiallyReady: false) { NeverReady = true };
        var catalog = new ExpiringCatalog(driver);
        await using var gate = new SigningOperationGate();
        await using var manager = new SimplySignSessionManager(driver, gate, catalog);

        var failed = await manager.EnsureReadyAsync(SessionTrigger.BeforeSign, default);

        Assert.Equal(SimplySignSessionState.Failed, failed.State);
        Assert.Equal("retry_scheduled", failed.ReasonCode);
        Assert.Equal(2, failed.Attempt);
        Assert.Equal(2, driver.LoginCalls);
    }

    [Fact]
    public async Task Transport_cache_recreation_preserves_the_current_generation_and_ready_state()
    {
        var driver = new ExpiringDriver(initiallyReady: true);
        var catalog = new ExpiringCatalog(driver);
        await using var gate = new SigningOperationGate();
        await using var manager = new SimplySignSessionManager(
            driver,
            gate,
            catalog,
            initialSessionGeneration: 9);
        _ = await manager.CheckAsync(SessionTrigger.Startup, default);
        AgentHeartbeat before;
        using (var firstTransportCache = new CapabilityProbeCache(manager, SessionId, true, true))
        {
            before = firstTransportCache.CreateHeartbeat(null);
        }

        using var reconnectedTransportCache = new CapabilityProbeCache(manager, SessionId, true, true);
        var after = reconnectedTransportCache.CreateHeartbeat(null);

        Assert.Equal(9, after.SessionGeneration);
        Assert.True(after.Authenticode!.Session!.Ready);
        Assert.True(after.Pdf!.Session!.Ready);
        Assert.Equal(before.SessionGeneration, after.SessionGeneration);
        Assert.Equal(before.Authenticode!.Session!, after.Authenticode.Session);
        Assert.Equal(before.Pdf!.Session!, after.Pdf.Session);
    }

    private static void AssertOrdered(
        IReadOnlyList<SimplySignSessionState> actual,
        params SimplySignSessionState[] expected)
    {
        var cursor = -1;
        foreach (var state in expected)
        {
            cursor = actual
                .Select((candidate, index) => (candidate, index))
                .First(entry => entry.index > cursor && entry.candidate == state)
                .index;
        }
    }

    private static CertificateAlias Alias(string name, string certificateId, string privateKeyId) =>
        new(
            name,
            Path.Combine(Path.GetTempPath(), "synthetic-pkcs11.dll"),
            2,
            $"TOKEN-{name}",
            certificateId,
            privateKeyId);

    private static SignJobCommand CreateCommand(string root, int index)
    {
        var pdf = index % 2 == 0;
        var extension = pdf ? ".pdf" : ".exe";
        var input = pdf ? "%PDF-synthetic"u8.ToArray() : "MZ-synthetic"u8.ToArray();
        var jobId = Guid.NewGuid();
        var directory = Path.Combine(root, jobId.ToString("N"));
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Combine(directory, "input" + extension), input);
        var parameters = pdf
            ? "{\"box\":[10,20,30,40],\"certificateSerialNumber\":\"CC00\",\"digestAlgorithm\":\"sha256\",\"fieldName\":\"Signature1\",\"kind\":\"pdf\",\"page\":1}"
            : "{\"appendSignature\":false,\"certificateSerialNumber\":\"AA00\",\"digestAlgorithm\":\"sha256\",\"kind\":\"authenticode\"}";
        return new SignJobCommand(
            jobId,
            Guid.NewGuid(),
            1,
            extension,
            parameters,
            input.LongLength,
            Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant());
    }

    private sealed class RecordingPdfSigner : IPdfSigner
    {
        public int CallCount { get; private set; }

        public Task<SigningResult> SignAsync(
            SigningContext context,
            CodeSignAuto.Core.Jobs.PdfParameters parameters,
            SigningCertificate certificate,
            CancellationToken cancellationToken)
        {
            _ = context;
            _ = parameters;
            _ = certificate;
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            return Task.FromResult(new SigningResult(17, new string('b', 64)));
        }
    }

    private sealed class RecordingAuthenticodeSigner : IAuthenticodeSigner
    {
        public int CallCount { get; private set; }

        public Task<SigningResult> SignAsync(
            SigningContext context,
            CodeSignAuto.Core.Jobs.AuthenticodeParameters parameters,
            SigningCertificate certificate,
            CancellationToken cancellationToken)
        {
            _ = context;
            _ = parameters;
            _ = certificate;
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            return Task.FromResult(new SigningResult(17, new string('b', 64)));
        }
    }

    private sealed class InfiniteAgentDelay : IAgentDelay
    {
        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
            Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
    }

    private sealed class CapturingPreloadedDuplexStream : Stream
    {
        private readonly MemoryStream _input;
        private readonly MemoryStream _output = new();

        private CapturingPreloadedDuplexStream(byte[] input) => _input = new MemoryStream(input);

        public byte[] WrittenBytes => _output.ToArray();

        public static async Task<CapturingPreloadedDuplexStream> CreateAsync(SignJobCommand command)
        {
            await using var input = new MemoryStream();
            await LengthPrefixedJsonProtocol.WriteAsync(input, command, CancellationToken.None);

            return new CapturingPreloadedDuplexStream(input.ToArray());
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            _input.ReadAsync(buffer, cancellationToken);

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _output.Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _input.Dispose();
                _output.Dispose();
            }

            base.Dispose(disposing);
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class ExpiringDriver(bool initiallyReady) : ISimplySignSessionDriver
    {
        private int _probeConcurrency;
        private bool _ready = initiallyReady;

        public int VerifiedSessionId => SessionId;
        public DateTimeOffset UtcNow { get; private set; } = DateTimeOffset.UnixEpoch;
        public int LoginCalls { get; private set; }
        public int ProcessChecks { get; private set; }
        public int MaximumProbeConcurrency { get; private set; }
        public bool NeverReady { get; init; }

        public SimplySignProcessState CheckProcessOnly()
        {
            ProcessChecks++;
            return new SimplySignProcessState(true, SessionId);
        }

        public async Task<ProbeResult> ProbeAsync(
            CertificateAlias alias,
            CancellationToken cancellationToken)
        {
            _ = alias;
            var concurrency = Interlocked.Increment(ref _probeConcurrency);
            MaximumProbeConcurrency = Math.Max(MaximumProbeConcurrency, concurrency);
            try
            {
                await Task.Yield();
                cancellationToken.ThrowIfCancellationRequested();
                return _ready
                    ? ProbeResult.ReadyFor(SessionId)
                    : ProbeResult.NotReadyFor(SessionId, "token_missing");
            }
            finally
            {
                Interlocked.Decrement(ref _probeConcurrency);
            }
        }

        public Task CloseAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _ready = false;
            return Task.CompletedTask;
        }

        public Task<OtpauthProfile> LoadOtpAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new OtpauthProfile(
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
                "SHA256",
                6,
                30,
                "Certum",
                "user"));
        }

        public Task<long> StartLoginAsync(
            OtpauthProfile profile,
            CancellationToken cancellationToken)
        {
            _ = profile;
            cancellationToken.ThrowIfCancellationRequested();
            LoginCalls++;
            _ready = !NeverReady;
            return Task.FromResult(0L);
        }

        public Task WaitForCounterAfterAsync(
            OtpauthProfile profile,
            long priorCounter,
            CancellationToken cancellationToken)
        {
            _ = profile;
            _ = priorCounter;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            UtcNow += delay;
            return Task.CompletedTask;
        }

        public void Expire() => _ready = false;
    }

    private sealed class ExpiringCatalog(ExpiringDriver driver) : ICertificateCatalog
    {
        private long _generation;

        public int RefreshCalls { get; private set; }

        public CertificateCatalogSnapshot? Current { get; private set; }

        public IReadOnlyList<CertificateDisplaySummary> DisplaySummaries => [];

        public async Task<CertificateCatalogSnapshot> RefreshAsync(CancellationToken cancellationToken)
        {
            RefreshCalls++;
            var result = await driver.ProbeAsync(Code, cancellationToken);
            if (!result.Ready)
            {
                throw new SigningException("certificate_catalog_unavailable");
            }

            Current = new CertificateCatalogSnapshot(
                ++_generation,
                DateTimeOffset.UtcNow,
                new Dictionary<string, IReadOnlyList<SigningCertificate>>(StringComparer.Ordinal)
                {
                    ["AA00"] = [Certificate("AA00", supportsAuthenticode: true, supportsPdf: false)],
                    ["CC00"] = [Certificate("CC00", supportsAuthenticode: false, supportsPdf: true)],
                });
            return Current;
        }

        public SigningCertificate Resolve(string serialNumber, SigningKind kind) =>
            throw new NotSupportedException();

        public void Invalidate() => Current = null;

        private static SigningCertificate Certificate(
            string serial,
            bool supportsAuthenticode,
            bool supportsPdf) =>
            new(
                "E2E certificate",
                serial,
                Path.Combine(Path.GetTempPath(), "synthetic-pkcs11.dll"),
                2,
                "TOKEN-E2E",
                "aa00",
                "bb00",
                "00112233445566778899AABBCCDDEEFF00112233",
                DateTimeOffset.Parse("2020-01-01T00:00:00Z"),
                DateTimeOffset.Parse("2100-01-01T00:00:00Z"),
                supportsAuthenticode,
                supportsPdf);
    }
}
