using SimplySignAuto.Agent.Signing;
using SimplySignAuto.Agent.SimplySign;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Core.Otp;
using SimplySignAuto.Protocol;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class SimplySignSessionManagerTests
{
    private const int SessionId = 7;

    [Fact]
    public void Capability_cache_projects_every_public_catalog_summary_to_heartbeat()
    {
        var catalog = new ControlledCatalog
        {
            DisplaySummaries =
            [
                new CertificateDisplaySummary(
                    "Code Signing", "52A1B4C9",
                    Utc(1), Utc(2), true, false, true, null),
                new CertificateDisplaySummary(
                    "Stale Document", "6F09D233",
                    Utc(1), Utc(2), false, false, false, "catalog_stale"),
            ],
        };
        using var manager = CreateManager(new ControlledDriver(), catalog);
        using var cache = new CapabilityProbeCache(manager, SessionId, true, true);

        var heartbeat = cache.CreateHeartbeat(null);

        Assert.Equal(2, heartbeat.Certificates.Count);
        Assert.Equal("52A1B4C9", heartbeat.Certificates[0].SerialNumber);
        Assert.Equal("catalog_stale", heartbeat.Certificates[1].UnavailableReason);
    }

    [Fact]
    public async Task Relogin_returns_the_installed_pdf_certificate_that_appears_on_the_fourth_catalog_read()
    {
        var codeCertificate = new CertificateDisplaySummary(
            "Code Signing", "52A1B4C9",
            Utc(1), Utc(2), true, false, true, null);
        var documentCertificate = new CertificateDisplaySummary(
            "Document Signing", "6F09D233",
            Utc(1), Utc(2), false, true, true, null);
        var catalog = new SequencedCatalog(
            [codeCertificate],
            [codeCertificate],
            [codeCertificate],
            [codeCertificate, documentCertificate]);
        await using var manager = CreateManager(new ControlledDriver(), catalog);
        using var cache = new CapabilityProbeCache(
            manager,
            SessionId,
            authenticodeConfigured: true,
            pdfConfigured: true,
            pdfToolResolver: new ReadyPdfToolResolver());

        await cache.ReloginAsync(default);

        var heartbeat = cache.CreateHeartbeat(null);
        Assert.Equal(4, catalog.RefreshCalls);
        Assert.Equal(2, heartbeat.Certificates.Count);
        Assert.Contains(heartbeat.Certificates, static certificate => certificate.PdfUsable);
    }

    [Fact]
    public async Task Each_explicit_online_startup_round_refreshes_catalog_without_login()
    {
        var driver = new ControlledDriver();
        var catalog = new ControlledCatalog();
        await using var manager = CreateManager(driver, catalog);

        var first = await manager.PrepareStartupAsync(default);
        var secondRound = await manager.PrepareStartupAsync(default);

        Assert.True(first.Ready);
        Assert.True(secondRound.Ready);
        Assert.Equal(2, catalog.RefreshCalls);
        Assert.Equal(0, driver.LoginCalls);
    }

    [Fact]
    public async Task Concurrent_callers_share_only_the_current_startup_round()
    {
        var catalog = new BlockingCatalog();
        await using var manager = CreateManager(new ControlledDriver(), catalog);
        var first = manager.PrepareStartupAsync(default);
        await catalog.Entered.Task.WaitAsync(TimeSpan.FromSeconds(1));

        var concurrent = manager.PrepareStartupAsync(default);
        catalog.Release.TrySetResult();

        Assert.Same(await first, await concurrent);
    }

    [Fact]
    public async Task Agent_startup_handler_calls_global_manager_online_without_login()
    {
        var driver = new ControlledDriver();
        var catalog = new ControlledCatalog();
        await using var manager = CreateManager(driver, catalog);
        using var cache = new CapabilityProbeCache(manager, SessionId, true, true);
        var command = new PrepareSimplySignSessionCommand(Guid.NewGuid());

        var result = await cache.PrepareStartupAsync(command, default);

        Assert.Equal(command.RequestId, result.RequestId);
        Assert.Equal(SimplySignSessionState.Ready, result.State);
        Assert.Null(result.ErrorCode);
        Assert.Equal(1, catalog.RefreshCalls);
        Assert.Equal(0, driver.LoginCalls);
    }

    [Fact]
    public async Task Agent_startup_returns_the_installed_pdf_certificate_that_appears_on_the_fourth_catalog_read()
    {
        var codeCertificate = new CertificateDisplaySummary(
            "Code Signing", "52A1B4C9",
            Utc(1), Utc(2), true, false, true, null);
        var documentCertificate = new CertificateDisplaySummary(
            "Document Signing", "6F09D233",
            Utc(1), Utc(2), false, true, true, null);
        var catalog = new SequencedCatalog(
            [codeCertificate],
            [codeCertificate],
            [codeCertificate],
            [codeCertificate, documentCertificate]);
        await using var manager = CreateManager(new ControlledDriver(), catalog);
        using var cache = new CapabilityProbeCache(
            manager,
            SessionId,
            authenticodeConfigured: true,
            pdfConfigured: true,
            pdfToolResolver: new ReadyPdfToolResolver());
        var command = new PrepareSimplySignSessionCommand(Guid.NewGuid());

        var result = await cache.PrepareStartupAsync(command, default);

        Assert.Equal(SimplySignSessionState.Ready, result.State);
        Assert.Equal(4, catalog.RefreshCalls);
        Assert.Contains(
            cache.CreateHeartbeat(null).Certificates,
            static certificate => certificate.PdfUsable);
    }

    [Fact]
    public async Task Request_cache_replays_same_id_but_new_id_runs_same_online_manager_again()
    {
        var driver = new ControlledDriver();
        var catalog = new ControlledCatalog();
        await using var manager = CreateManager(driver, catalog);
        using var capabilityCache = new CapabilityProbeCache(manager, SessionId, true, true);
        using var requests = new AgentStartupPreparationCache(capabilityCache.PrepareStartupAsync);
        var first = new PrepareSimplySignSessionCommand(Guid.NewGuid());
        var restartedService = new PrepareSimplySignSessionCommand(Guid.NewGuid());

        var firstResult = await requests.ExecuteAsync(first, default);
        var replay = await requests.ExecuteAsync(first, default);
        var restartedResult = await requests.ExecuteAsync(restartedService, default);

        Assert.Same(firstResult, replay);
        Assert.Equal(SimplySignSessionState.Ready, restartedResult.State);
        Assert.Equal(2, catalog.RefreshCalls);
        Assert.Equal(0, driver.LoginCalls);
    }

    [Fact]
    public async Task Startup_offline_attempts_login_at_most_twice_then_refreshes_catalog()
    {
        var driver = new ControlledDriver();
        var catalog = new ControlledCatalog { FailuresRemaining = 31 };
        await using var manager = CreateManager(driver, catalog);

        var snapshot = await manager.PrepareStartupAsync(default);

        Assert.True(snapshot.Ready);
        Assert.Equal(2, driver.LoginCalls);
        Assert.NotNull(catalog.Current);
    }

    [Fact]
    public async Task Agent_startup_handler_preserves_global_manager_two_attempt_limit()
    {
        var driver = new ControlledDriver();
        var catalog = new ControlledCatalog { FailuresRemaining = int.MaxValue };
        await using var manager = CreateManager(driver, catalog);
        using var cache = new CapabilityProbeCache(manager, SessionId, true, true);
        var command = new PrepareSimplySignSessionCommand(Guid.NewGuid());

        var result = await cache.PrepareStartupAsync(command, default);

        Assert.Equal(SimplySignSessionState.Failed, result.State);
        Assert.Equal("simplysign_login_failed", result.ErrorCode);
        Assert.Equal(2, driver.LoginCalls);
    }

    [Fact]
    public async Task New_request_id_starts_a_new_bounded_offline_round_after_cooldown()
    {
        var driver = new ControlledDriver();
        var catalog = new ControlledCatalog { FailuresRemaining = int.MaxValue };
        await using var manager = CreateManager(driver, catalog);
        using var capabilityCache = new CapabilityProbeCache(manager, SessionId, true, true);
        using var requests = new AgentStartupPreparationCache(capabilityCache.PrepareStartupAsync);
        var first = new PrepareSimplySignSessionCommand(Guid.NewGuid());
        var restartedService = new PrepareSimplySignSessionCommand(Guid.NewGuid());

        Assert.Equal(
            SimplySignSessionState.Failed,
            (await requests.ExecuteAsync(first, default)).State);
        Assert.Equal(2, driver.LoginCalls);
        await driver.DelayAsync(TimeSpan.FromSeconds(60), default);
        Assert.Equal(
            SimplySignSessionState.Failed,
            (await requests.ExecuteAsync(restartedService, default)).State);

        Assert.Equal(4, driver.LoginCalls);
        Assert.Equal(122, catalog.RefreshCalls);
    }

    [Fact]
    public async Task Before_sign_offline_logs_in_and_refreshes_catalog()
    {
        var driver = new ControlledDriver();
        var catalog = new ControlledCatalog { FailuresRemaining = 1 };
        await using var manager = CreateManager(driver, catalog);

        await using var lease = await manager.AcquireReadySignLeaseAsync(default);

        Assert.Equal(1, driver.LoginCalls);
        Assert.Same(catalog.Current, lease.CatalogSnapshot);
        Assert.True(lease.Snapshot.Ready);
    }

    [Fact]
    public async Task Second_failure_sets_sixty_second_cooldown()
    {
        var driver = new ControlledDriver();
        var catalog = new ControlledCatalog { FailuresRemaining = int.MaxValue };
        await using var manager = CreateManager(driver, catalog);

        var snapshot = await manager.PrepareStartupAsync(default);

        Assert.Equal(SimplySignSessionState.Failed, snapshot.State);
        Assert.Equal(2, snapshot.Attempt);
        Assert.Equal(driver.UtcNow + TimeSpan.FromSeconds(60), snapshot.NextRetryAtUtc);
        Assert.Equal(2, driver.LoginCalls);

        var cooled = await manager.EnsureReadyAsync(SessionTrigger.BeforeSign, default);
        Assert.Same(snapshot, cooled);
        Assert.Equal(2, driver.LoginCalls);
    }

    [Fact]
    public async Task Reconnect_does_not_reset_attempt_count_or_repeat_completed_startup()
    {
        var driver = new ControlledDriver();
        var catalog = new ControlledCatalog { FailuresRemaining = int.MaxValue };
        await using var manager = CreateManager(driver, catalog);

        var completed = await manager.PrepareStartupAsync(default);
        var reconnected = await manager.PrepareStartupAsync(default);

        Assert.Same(completed, reconnected);
        Assert.Equal(2, reconnected.Attempt);
        Assert.Equal(2, driver.LoginCalls);
    }

    [Fact]
    public async Task Relogin_invalidates_old_catalog_before_starting_login()
    {
        var catalog = new ControlledCatalog();
        _ = await catalog.RefreshAsync(default);
        catalog.FailuresRemaining = 1;
        var driver = new ControlledDriver
        {
            BeforeLogin = () => Assert.Null(catalog.Current),
        };
        await using var manager = CreateManager(driver, catalog);

        var snapshot = await manager.EnsureReadyAsync(SessionTrigger.ManualRelogin, default);

        Assert.True(snapshot.Ready);
        Assert.Equal(1, driver.LoginCalls);
        Assert.True(catalog.InvalidateCalls >= 1);
    }

    [Fact]
    public async Task Clear_otp_and_logout_closes_before_deleting_and_removes_cached_certificates()
    {
        var operations = new List<string>();
        var driver = new ControlledDriver
        {
            BeforeClose = () => operations.Add("close"),
            BeforeDeleteOtp = () => operations.Add("delete"),
        };
        var catalog = new ControlledCatalog
        {
            DisplaySummaries =
            [
                new CertificateDisplaySummary(
                    "Document Signing", "52A1B4C9",
                    Utc(1), Utc(2), false, true, true, null),
            ],
        };
        _ = await catalog.RefreshAsync(default);
        await using var manager = CreateManager(driver, catalog);

        var snapshot = await manager.ClearOtpAndLogoutAsync(default);

        Assert.Equal(["close", "delete"], operations);
        Assert.Equal(1, driver.CloseCalls);
        Assert.Equal(1, driver.DeleteOtpCalls);
        Assert.Equal(1, catalog.ClearCalls);
        Assert.Null(catalog.Current);
        Assert.Empty(catalog.DisplaySummaries);
        Assert.Equal(SimplySignSessionState.Unknown, snapshot.State);
        Assert.Equal("invalidated", snapshot.ReasonCode);
        Assert.False(snapshot.SimplySignProcessRunning);
        Assert.False(snapshot.Ready);
    }

    [Fact]
    public async Task Logout_closes_and_clears_the_catalog_without_deleting_the_saved_otp()
    {
        var driver = new ControlledDriver();
        var catalog = new ControlledCatalog
        {
            DisplaySummaries =
            [
                new CertificateDisplaySummary(
                    "Code Signing", "52A1B4C9",
                    Utc(1), Utc(2), true, false, true, null),
            ],
        };
        _ = await catalog.RefreshAsync(default);
        await using var manager = CreateManager(driver, catalog);

        var snapshot = await manager.LogoutAsync(default);

        Assert.Equal(1, driver.CloseCalls);
        Assert.Equal(0, driver.DeleteOtpCalls);
        Assert.Equal(1, catalog.ClearCalls);
        Assert.Empty(catalog.DisplaySummaries);
        Assert.False(snapshot.SimplySignProcessRunning);
        Assert.False(snapshot.Ready);
        Assert.Equal("invalidated", snapshot.ReasonCode);
    }

    [Fact]
    public async Task Offline_recovery_publishes_the_global_seven_state_contract()
    {
        var driver = new ControlledDriver();
        var catalog = new ControlledCatalog { FailuresRemaining = 1 };
        await using var manager = CreateManager(driver, catalog);
        var states = new List<SimplySignSessionState>();
        manager.SnapshotChanged += (_, snapshot) => states.Add(snapshot.State);

        var snapshot = await manager.EnsureReadyAsync(SessionTrigger.BeforeSign, default);

        Assert.True(snapshot.Ready);
        Assert.Equal(
            [
                SimplySignSessionState.Checking,
                SimplySignSessionState.LoginRequired,
                SimplySignSessionState.Unknown,
                SimplySignSessionState.Checking,
                SimplySignSessionState.LoginRequired,
                SimplySignSessionState.Loginning,
                SimplySignSessionState.WaitToken,
                SimplySignSessionState.Ready,
            ],
            states);
        Assert.Equal(1, driver.CloseCalls);
        Assert.Equal(1, driver.LoginCalls);
    }

    [Fact]
    public async Task Twenty_before_sign_requests_use_one_login_and_serialize_catalog_access()
    {
        var driver = new ControlledDriver();
        var catalog = new ControlledCatalog { FailuresRemaining = 1, YieldOnRefresh = true };
        await using var manager = CreateManager(driver, catalog);

        var snapshots = await Task.WhenAll(Enumerable.Range(0, 20)
            .Select(_ => manager.EnsureReadyAsync(SessionTrigger.BeforeSign, default)));

        Assert.All(snapshots, snapshot => Assert.True(snapshot.Ready));
        Assert.Equal(1, driver.LoginCalls);
        Assert.Equal(1, catalog.MaximumConcurrency);
    }

    [Fact]
    public async Task Relogin_promotes_generation_and_invalidates_catalog_before_close()
    {
        var driver = new ControlledDriver();
        var catalog = new ControlledCatalog();
        await using var manager = CreateManager(driver, catalog, initialGeneration: 7);
        _ = await manager.CheckAsync(SessionTrigger.Startup, default);
        var before = manager.GetSnapshot();
        driver.BeforeClose = () =>
        {
            var during = manager.GetSnapshot();
            Assert.Equal(8, during.SessionGeneration);
            Assert.Equal(SimplySignSessionState.LoginRequired, during.State);
            Assert.Null(catalog.Current);
        };

        var result = await manager.EnsureReadyAsync(SessionTrigger.ManualRelogin, default);

        Assert.Equal(7, before.SessionGeneration);
        Assert.Equal(8, result.SessionGeneration);
        Assert.True(result.Ready);
    }

    [Fact]
    public async Task Heartbeat_retains_bounded_alias_free_relogin_evidence()
    {
        var driver = new ControlledDriver();
        var catalog = new ControlledCatalog { FailuresRemaining = 1 };
        await using var manager = CreateManager(driver, catalog, initialGeneration: 7);
        using var cache = new CapabilityProbeCache(manager, SessionId, true, true);

        _ = await manager.EnsureReadyAsync(SessionTrigger.ManualRelogin, default);
        var heartbeat = cache.CreateHeartbeat(null);
        var json = System.Text.Json.JsonSerializer.Serialize(heartbeat.SessionTransitions);

        Assert.NotEmpty(heartbeat.SessionTransitions);
        Assert.True(heartbeat.SessionTransitions.Count <= SessionTransitionEvidence.MaximumRetained);
        Assert.All(heartbeat.SessionTransitions, item => Assert.Equal(8, item.SessionGeneration));
        Assert.DoesNotContain("certificateAlias", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Fatal_otp_failure_restores_new_unknown_generation_without_retry_loop()
    {
        var driver = new ControlledDriver
        {
            LoadOtpError = new SimplySignException("otp_corrupt"),
        };
        var catalog = new ControlledCatalog { FailuresRemaining = 1 };
        await using var manager = CreateManager(driver, catalog, initialGeneration: 7);

        var error = await Assert.ThrowsAsync<SimplySignException>(() =>
            manager.EnsureReadyAsync(SessionTrigger.BeforeSign, default));

        Assert.Equal("otp_corrupt", error.Code);
        Assert.Equal(0, driver.LoginCalls);
        Assert.Equal(9, manager.GetSnapshot().SessionGeneration);
        Assert.Equal(SimplySignSessionState.Unknown, manager.GetSnapshot().State);
        Assert.Null(catalog.Current);
    }

    [Fact]
    public async Task Ready_sign_lease_binds_catalog_snapshot_and_holds_operation_gate()
    {
        var catalog = new ControlledCatalog();
        await using var gate = new SigningOperationGate();
        await using var manager = new SimplySignSessionManager(new ControlledDriver(), gate, catalog);

        await using var lease = await manager.AcquireReadySignLeaseAsync(default);

        Assert.Same(catalog.Current, lease.CatalogSnapshot);
        Assert.False(await gate.TryRunHealthCheckAsync(_ => Task.CompletedTask, default));
        await lease.DisposeAsync();
        Assert.True(await gate.TryRunHealthCheckAsync(_ => Task.CompletedTask, default));
    }

    [Fact]
    public async Task Later_sign_lease_refreshes_after_catalog_invalidation()
    {
        var catalog = new ControlledCatalog();
        await using var manager = CreateManager(new ControlledDriver(), catalog);
        CertificateCatalogSnapshot firstSnapshot;
        await using (var first = await manager.AcquireReadySignLeaseAsync(default))
        {
            firstSnapshot = first.CatalogSnapshot;
        }

        catalog.Invalidate();
        await using var second = await manager.AcquireReadySignLeaseAsync(default);

        Assert.NotSame(firstSnapshot, second.CatalogSnapshot);
        Assert.Same(catalog.Current, second.CatalogSnapshot);
    }

    [Fact]
    public async Task Background_health_is_zero_wait_and_never_refreshes_catalog_or_logs_in()
    {
        var driver = new ControlledDriver();
        var catalog = new ControlledCatalog();
        await using var gate = new SigningOperationGate();
        await using var manager = new SimplySignSessionManager(driver, gate, catalog);
        await using var signing = await gate.AcquireAsync(default);

        var skipped = await manager.CheckAsync(SessionTrigger.BackgroundHealth, default);

        Assert.Same(manager.GetSnapshot(), skipped);
        Assert.Equal(0, catalog.RefreshCalls);
        Assert.Equal(0, driver.LoginCalls);
        Assert.Equal(0, driver.ProcessChecks);
    }

    [Fact]
    public async Task Idle_health_updates_process_diagnostic_only()
    {
        var driver = new ControlledDriver
        {
            ProcessState = new SimplySignProcessState(false, null),
        };
        var catalog = new ControlledCatalog();
        await using var manager = CreateManager(driver, catalog);

        var snapshot = await manager.CheckAsync(SessionTrigger.BackgroundHealth, default);

        Assert.False(snapshot.SimplySignProcessRunning);
        Assert.Equal(1, driver.ProcessChecks);
        Assert.Equal(0, catalog.RefreshCalls);
        Assert.Equal(0, driver.LoginCalls);
    }

    [Fact]
    public async Task Dispose_cancels_and_joins_inflight_catalog_refresh()
    {
        var catalog = new BlockingCatalog();
        var manager = CreateManager(new ControlledDriver(), catalog);
        var check = manager.CheckAsync(SessionTrigger.ManualRefresh, default);
        await catalog.Entered.Task.WaitAsync(TimeSpan.FromSeconds(1));

        var dispose = manager.DisposeAsync().AsTask();
        await catalog.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(dispose.IsCompleted);
        catalog.Release.TrySetResult();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => check);
        await dispose.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.True(catalog.Exited.Task.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task Explicit_invalidation_during_refresh_prevents_old_result_from_becoming_ready()
    {
        var catalog = new BlockingCatalog();
        await using var manager = CreateManager(new ControlledDriver(), catalog, initialGeneration: 7);
        var check = manager.CheckAsync(SessionTrigger.ManualRefresh, default);
        await catalog.Entered.Task.WaitAsync(TimeSpan.FromSeconds(1));

        manager.Invalidate();
        catalog.Release.TrySetResult();
        var observed = await check;

        Assert.Equal(8, observed.SessionGeneration);
        Assert.Equal(SimplySignSessionState.Unknown, observed.State);
        Assert.Equal("invalidated", observed.ReasonCode);
    }

    [Fact]
    public async Task Caller_cancellation_during_refresh_preserves_cancellation_and_invalidates_no_generation()
    {
        var catalog = new BlockingCatalog();
        await using var manager = CreateManager(new ControlledDriver(), catalog, initialGeneration: 7);
        using var cancellation = new CancellationTokenSource();
        var check = manager.CheckAsync(SessionTrigger.ManualRefresh, cancellation.Token);
        await catalog.Entered.Task.WaitAsync(TimeSpan.FromSeconds(1));

        cancellation.Cancel();
        await catalog.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(1));
        catalog.Release.TrySetResult();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => check);
        Assert.Equal(7, manager.GetSnapshot().SessionGeneration);
        Assert.Equal(SimplySignSessionState.Checking, manager.GetSnapshot().State);
    }

    private static SimplySignSessionManager CreateManager(
        ISimplySignSessionDriver driver,
        ICertificateCatalog catalog,
        long initialGeneration = 1) =>
        new(driver, new SigningOperationGate(), catalog, initialGeneration);

    private sealed class ControlledCatalog : ICertificateCatalog
    {
        private int _concurrency;
        private long _generation;

        public int FailuresRemaining { get; set; }
        public bool YieldOnRefresh { get; init; }
        public int RefreshCalls { get; private set; }
        public int InvalidateCalls { get; private set; }
        public int MaximumConcurrency { get; private set; }
        public CertificateCatalogSnapshot? Current { get; private set; }
        public IReadOnlyList<CertificateDisplaySummary> DisplaySummaries { get; set; } = [];
        public int ClearCalls { get; private set; }

        public async Task<CertificateCatalogSnapshot> RefreshAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var concurrency = Interlocked.Increment(ref _concurrency);
            MaximumConcurrency = Math.Max(MaximumConcurrency, concurrency);
            try
            {
                RefreshCalls++;
                if (YieldOnRefresh)
                {
                    await Task.Yield();
                }

                cancellationToken.ThrowIfCancellationRequested();
                if (FailuresRemaining > 0)
                {
                    FailuresRemaining--;
                    throw new SigningException("certificate_catalog_unavailable");
                }

                Current = Snapshot(++_generation);
                return Current;
            }
            finally
            {
                Interlocked.Decrement(ref _concurrency);
            }
        }

        public SigningCertificate Resolve(string serialNumber, SigningKind kind) =>
            throw new NotSupportedException();

        public void Invalidate()
        {
            InvalidateCalls++;
            Current = null;
        }

        public void Clear()
        {
            ClearCalls++;
            Current = null;
            DisplaySummaries = [];
        }
    }

    private sealed class BlockingCatalog : ICertificateCatalog
    {
        public TaskCompletionSource Entered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource CancellationObserved { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Exited { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public CertificateCatalogSnapshot? Current { get; private set; }
        public IReadOnlyList<CertificateDisplaySummary> DisplaySummaries => [];

        public async Task<CertificateCatalogSnapshot> RefreshAsync(CancellationToken cancellationToken)
        {
            Entered.TrySetResult();
            using var registration = cancellationToken.Register(
                static state => ((TaskCompletionSource)state!).TrySetResult(),
                CancellationObserved);
            try
            {
                await Release.Task;
                cancellationToken.ThrowIfCancellationRequested();
                Current = Snapshot(1);
                return Current;
            }
            finally
            {
                Exited.TrySetResult();
            }
        }

        public SigningCertificate Resolve(string serialNumber, SigningKind kind) =>
            throw new NotSupportedException();

        public void Invalidate() => Current = null;
    }

    private sealed class SequencedCatalog(
        params IReadOnlyList<CertificateDisplaySummary>[] summaries) : ICertificateCatalog
    {
        private long _generation;

        public int RefreshCalls { get; private set; }
        public CertificateCatalogSnapshot? Current { get; private set; }
        public IReadOnlyList<CertificateDisplaySummary> DisplaySummaries { get; private set; } = [];

        public Task<CertificateCatalogSnapshot> RefreshAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var index = Math.Min(RefreshCalls++, summaries.Length - 1);
            DisplaySummaries = summaries[index];
            Current = Snapshot(++_generation);
            return Task.FromResult(Current);
        }

        public SigningCertificate Resolve(string serialNumber, SigningKind kind) =>
            throw new NotSupportedException();

        public void Invalidate() => Current = null;
    }

    private sealed class ReadyPdfToolResolver : IInstalledPdfToolResolver
    {
        public Task<InstalledPdfToolResolution> ResolveAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(InstalledPdfToolResolution.Ready(new InstalledPdfTool(
                @"C:\Program Files\SimplySignAuto PDF Support\SimplySignPdfSigner.exe",
                new string('a', 64))));
        }
    }

    private sealed class ControlledDriver : ISimplySignSessionDriver
    {
        public int VerifiedSessionId => SessionId;
        public DateTimeOffset UtcNow { get; private set; } = DateTimeOffset.UnixEpoch;
        public SimplySignProcessState ProcessState { get; init; } = new(true, SessionId);
        public int ProcessChecks { get; private set; }
        public int CloseCalls { get; private set; }
        public int DeleteOtpCalls { get; private set; }
        public int LoginCalls { get; private set; }
        public Exception? LoadOtpError { get; init; }
        public Action? BeforeClose { get; set; }
        public Action? BeforeDeleteOtp { get; set; }
        public Action? BeforeLogin { get; init; }

        public SimplySignProcessState CheckProcessOnly()
        {
            ProcessChecks++;
            return ProcessState;
        }

        public Task CloseAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CloseCalls++;
            BeforeClose?.Invoke();
            return Task.CompletedTask;
        }

        public Task<OtpauthProfile> LoadOtpAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return LoadOtpError is null
                ? Task.FromResult(Profile())
                : Task.FromException<OtpauthProfile>(LoadOtpError);
        }

        public Task DeleteOtpAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DeleteOtpCalls++;
            BeforeDeleteOtp?.Invoke();
            return Task.CompletedTask;
        }

        public Task<long> StartLoginAsync(OtpauthProfile profile, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            BeforeLogin?.Invoke();
            LoginCalls++;
            return Task.FromResult((long)LoginCalls);
        }

        public Task WaitForCounterAfterAsync(
            OtpauthProfile profile,
            long priorCounter,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            UtcNow += delay;
            return Task.CompletedTask;
        }
    }

    private static CertificateCatalogSnapshot Snapshot(long generation) =>
        new(
            generation,
            DateTimeOffset.UnixEpoch + TimeSpan.FromSeconds(generation),
            new Dictionary<string, IReadOnlyList<SigningCertificate>>(StringComparer.Ordinal));

    private static OtpauthProfile Profile() => new(
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
        "SHA256",
        6,
        30,
        "Certum",
        "user");

    private static DateTimeOffset Utc(int day) =>
        new(2026, 8, day, 0, 0, 0, TimeSpan.Zero);
}
