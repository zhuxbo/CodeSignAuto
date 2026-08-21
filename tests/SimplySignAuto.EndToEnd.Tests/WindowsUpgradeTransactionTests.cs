using System.ComponentModel;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.App.Commands;
using SimplySignAuto.Protocol;
using SimplySignAuto.Service;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class WindowsUpgradeTransactionTests
{
    [Fact]
    public void Upgrade_discovery_does_not_treat_abnormal_service_configuration_entries_as_uninstalled()
    {
        var root = Directory.CreateTempSubdirectory("SimplySignAuto.Upgrade.Discovery.").FullName;
        var configurationPath = Path.Combine(root, "service.json");
        var receiptPath = Path.Combine(root, "install.json");
        var missingTarget = Path.Combine(root, "missing-service.json");
        try
        {
            Directory.CreateDirectory(configurationPath);
            Assert.True(WindowsUpgradeTransaction.HasAnyInstallationEntry(
                configurationPath,
                receiptPath));

            Directory.Delete(configurationPath);
            File.CreateSymbolicLink(configurationPath, missingTarget);
            Assert.True(WindowsUpgradeTransaction.HasAnyInstallationEntry(
                configurationPath,
                receiptPath));
        }
        finally
        {
            if (Directory.Exists(configurationPath) &&
                !WindowsPathSafety.IsReparse(configurationPath))
            {
                Directory.Delete(configurationPath, recursive: true);
            }
            else if (WindowsPathSafety.EntryExists(configurationPath))
            {
                File.Delete(configurationPath);
            }

            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Deleted_one_time_token_file_is_not_required_for_upgrade()
    {
        var verified = false;

        WindowsUpgradeTransaction.VerifyOptionalProtectedFile(
            "install-token.txt",
            _ => false,
            _ => verified = true);

        Assert.False(verified);
    }

    [Fact]
    public void Present_one_time_token_file_still_requires_exact_verification()
    {
        var verified = false;

        WindowsUpgradeTransaction.VerifyOptionalProtectedFile(
            "install-token.txt",
            _ => true,
            _ => verified = true);

        Assert.True(verified);
    }

    [Fact]
    public async Task Partial_agent_stop_failure_restarts_agent_resumes_admission_and_verifies_old_runtime()
    {
        var fixture = new TransactionFixture();
        fixture.Startup.StopTaskFailure = new InstallException("agent_stop_failed");
        var transaction = fixture.CreateTransaction();

        var error = await Assert.ThrowsAsync<SetupException>(() =>
            new UpgradeOrchestrator().ExecuteAsync(
                transaction,
                TextWriter.Null,
                CancellationToken.None));

        Assert.Equal("agent_stop_failed", error.Code);
        Assert.Contains("start-task", fixture.Startup.Events);
        Assert.Contains("resume", fixture.Control.Events);
        Assert.Contains("refresh", fixture.Control.Events);
        Assert.True(fixture.Media.RollbackCalled);
    }

    [Fact]
    public async Task Registration_update_followed_by_commit_failure_restores_registration_and_media()
    {
        var fixture = new TransactionFixture();
        fixture.Media.CommitFailure = new SetupException("upgrade_state_uncertain");
        var transaction = fixture.CreateTransaction();

        var error = await Assert.ThrowsAsync<SetupException>(() =>
            new UpgradeOrchestrator().ExecuteAsync(
                transaction,
                TextWriter.Null,
                CancellationToken.None));

        Assert.Equal("upgrade_state_uncertain", error.Code);
        Assert.Equal(
            ["1.0.0->2.0.0", "2.0.0->1.0.0"],
            fixture.Registrations.Replacements);
        Assert.True(fixture.Media.RollbackCalled);
        Assert.Contains("start-service", fixture.Startup.Events);
        Assert.Contains("start-task", fixture.Startup.Events);
        Assert.Equal(["create", "delete"], fixture.ReceiptStore.Events);
        Assert.Null(fixture.ReceiptStore.Current);
    }

    [Fact]
    public async Task Legacy_service_upgrade_writes_receipt_only_when_commit_succeeds()
    {
        var fixture = new TransactionFixture();

        await new UpgradeOrchestrator().ExecuteAsync(
            fixture.CreateTransaction(),
            TextWriter.Null,
            CancellationToken.None);

        Assert.Equal(["create"], fixture.ReceiptStore.Events);
        InstallationReceiptValidator.RequireServiceMatch(
            Assert.IsType<InstallationReceipt>(fixture.ReceiptStore.Current),
            fixture.Configuration);
    }

    [Fact]
    public async Task Existing_service_receipt_is_inherited_without_rewrite()
    {
        var fixture = new TransactionFixture();
        fixture.ExistingReceipt = InstallationReceipt.ForService(fixture.Configuration);
        fixture.ReceiptStore.Current = fixture.ExistingReceipt;

        await new UpgradeOrchestrator().ExecuteAsync(
            fixture.CreateTransaction(),
            TextWriter.Null,
            CancellationToken.None);

        Assert.Empty(fixture.ReceiptStore.Events);
        Assert.Equal(fixture.ExistingReceipt, fixture.ReceiptStore.Current);
    }

    [Fact]
    public async Task Manual_upgrade_replaces_media_and_registration_without_rewriting_receipt()
    {
        var receipt = ManualReceipt();
        var receiptStore = new FakeInstallationReceiptStore { Current = receipt };
        var media = new FakeUpgradeMedia();
        var registrations = new FakeRegistrationStore();
        var owner = InstallOwnershipMarker.Create(receipt.InstallInstanceId);
        var transaction = new ManualUpgradeTransaction(
            receipt,
            receiptStore,
            ProductUninstallRegistration.Create(receipt.ExecutablePath, "1.0.0", owner),
            ProductUninstallRegistration.Create(receipt.ExecutablePath, "2.0.0", owner),
            media,
            registrations);

        await new UpgradeOrchestrator().ExecuteAsync(
            transaction,
            TextWriter.Null,
            CancellationToken.None);

        Assert.Equal(InstallationMode.Manual, transaction.Mode);
        Assert.Equal(receipt.SigningUserSid, media.AuthorizedSid);
        Assert.Equal(["1.0.0->2.0.0"], registrations.Replacements);
        Assert.Equal(receipt, receiptStore.Current);
        Assert.Empty(receiptStore.Events);
    }

    [Fact]
    public async Task Manual_upgrade_commit_failure_restores_media_and_registration_but_never_mutates_receipt()
    {
        var receipt = ManualReceipt();
        var receiptStore = new FakeInstallationReceiptStore { Current = receipt };
        var media = new FakeUpgradeMedia
        {
            CommitFailure = new SetupException("upgrade_state_uncertain"),
        };
        var registrations = new FakeRegistrationStore();
        var owner = InstallOwnershipMarker.Create(receipt.InstallInstanceId);
        var transaction = new ManualUpgradeTransaction(
            receipt,
            receiptStore,
            ProductUninstallRegistration.Create(receipt.ExecutablePath, "1.0.0", owner),
            ProductUninstallRegistration.Create(receipt.ExecutablePath, "2.0.0", owner),
            media,
            registrations);

        var error = await Assert.ThrowsAsync<SetupException>(() =>
            new UpgradeOrchestrator().ExecuteAsync(
                transaction,
                TextWriter.Null,
                CancellationToken.None));

        Assert.Equal("upgrade_state_uncertain", error.Code);
        Assert.Equal(["1.0.0->2.0.0", "2.0.0->1.0.0"], registrations.Replacements);
        Assert.True(media.RollbackCalled);
        Assert.Equal(receipt, receiptStore.Current);
        Assert.Empty(receiptStore.Events);
    }

    [Fact]
    public void Upgrade_mode_policy_rejects_setup_attempts_to_change_the_installed_mode()
    {
        var error = Assert.Throws<SetupException>(() =>
            UpgradeModePolicy.RequireMatch(InstallationMode.Service, InstallationMode.Manual));

        Assert.Equal("installation_mode_change_requires_reinstall", error.Code);
        UpgradeModePolicy.RequireMatch(InstallationMode.Manual, InstallationMode.Manual);
    }

    [Fact]
    public async Task Legacy_service_without_drain_messages_upgrades_only_after_post_stop_quiescence()
    {
        var fixture = new TransactionFixture();
        fixture.Control.DrainFailure = new ManagementUnavailableException(Guid.NewGuid());
        fixture.Control.ResumeFailure = new ManagementUnavailableException(Guid.NewGuid());
        fixture.LegacyQuiescence.OnVerify = () =>
        {
            Assert.Contains("stop-service", fixture.Startup.Events);
            Assert.False(fixture.Media.Activated);
        };

        await new UpgradeOrchestrator().ExecuteAsync(
            fixture.CreateTransaction(),
            TextWriter.Null,
            CancellationToken.None);

        Assert.Equal(1, fixture.LegacyQuiescence.Calls);
        Assert.True(fixture.Media.Activated);
        Assert.Equal(1, fixture.Control.Events.Count(item => item == "resume"));
    }

    [Fact]
    public async Task Legacy_service_race_after_admission_closes_rolls_back_without_activation()
    {
        var fixture = new TransactionFixture();
        fixture.Control.DrainFailure = new ManagementUnavailableException(Guid.NewGuid());
        fixture.Control.ResumeFailure = new ManagementUnavailableException(Guid.NewGuid());
        fixture.LegacyQuiescence.Failure = new SetupException("upgrade_drain_timeout");

        var error = await Assert.ThrowsAsync<SetupException>(() =>
            new UpgradeOrchestrator().ExecuteAsync(
                fixture.CreateTransaction(),
                TextWriter.Null,
                CancellationToken.None));

        Assert.Equal("upgrade_drain_timeout", error.Code);
        Assert.Equal(1, fixture.LegacyQuiescence.Calls);
        Assert.False(fixture.Media.Activated);
        Assert.True(fixture.Media.RollbackCalled);
        Assert.Contains("start-service", fixture.Startup.Events);
        Assert.Contains("start-task", fixture.Startup.Events);
        Assert.Equal(1, fixture.Control.Events.Count(item => item == "resume"));
    }

    [Fact]
    public async Task Legacy_service_fallback_rejects_a_nonempty_snapshot_before_logout()
    {
        var fixture = new TransactionFixture();
        fixture.Control.DrainFailure = new ManagementUnavailableException(Guid.NewGuid());
        fixture.Control.ResumeFailure = new ManagementUnavailableException(Guid.NewGuid());
        fixture.Control.QueuedJobCount = 1;

        var error = await Assert.ThrowsAsync<SetupException>(() =>
            new UpgradeOrchestrator().ExecuteAsync(
                fixture.CreateTransaction(),
                TextWriter.Null,
                CancellationToken.None));

        Assert.Equal("upgrade_drain_timeout", error.Code);
        Assert.Equal(0, fixture.LegacyQuiescence.Calls);
        Assert.DoesNotContain("stop-task", fixture.Startup.Events);
        Assert.DoesNotContain("stop-service", fixture.Startup.Events);
        Assert.False(fixture.Media.Activated);
    }

    [Fact]
    public async Task Recoverable_drain_transport_failure_does_not_enter_legacy_fallback()
    {
        var fixture = new TransactionFixture();
        fixture.Control.DrainFailure = new ManagementUnavailableException(Guid.NewGuid());

        var error = await Assert.ThrowsAsync<SetupException>(() =>
            new UpgradeOrchestrator().ExecuteAsync(
                fixture.CreateTransaction(),
                TextWriter.Null,
                CancellationToken.None));

        Assert.Equal("restart_required", error.Code);
        Assert.Equal(0, fixture.LegacyQuiescence.Calls);
        Assert.False(fixture.Media.Activated);
    }

    [Fact]
    public void Runtime_acceptance_preserves_exact_capabilities_and_rejects_failed_session()
    {
        Assert.True(WindowsUpgradeTransaction.IsRuntimeSnapshotAcceptable(
            Snapshot(Capability(SimplySignSessionState.LoginRequired), CapabilitySnapshot.NotConfigured()),
            expectAuthenticode: true,
            expectPdf: false));
        Assert.False(WindowsUpgradeTransaction.IsRuntimeSnapshotAcceptable(
            Snapshot(Capability(SimplySignSessionState.LoginRequired), CapabilitySnapshot.NotConfigured()),
            expectAuthenticode: true,
            expectPdf: true));
        Assert.False(WindowsUpgradeTransaction.IsRuntimeSnapshotAcceptable(
            Snapshot(Capability(SimplySignSessionState.Failed), CapabilitySnapshot.NotConfigured()),
            expectAuthenticode: true,
            expectPdf: false));
    }

    [Theory]
    [InlineData(unchecked((int)0x80070020))]
    [InlineData(unchecked((int)0x80070021))]
    public void Windows_sharing_and_lock_violations_map_to_restart_required(int hresult)
    {
        Assert.True(WindowsInstallMediaStager.IsRenameBlocked(
            new IOException("injected sharing violation", hresult)));
    }

    [Fact]
    public async Task Upgrade_directory_move_retries_transient_access_denied()
    {
        var attempts = 0;
        var delays = 0;

        await WindowsInstallMediaStager.MoveDirectoryWithRetryAsync(
            () =>
            {
                attempts++;
                if (attempts == 1)
                {
                    throw new IOException("injected access denied", unchecked((int)0x80070005));
                }
            },
            () => true,
            maxAttempts: 3,
            _ =>
            {
                delays++;
                return Task.CompletedTask;
            },
            CancellationToken.None);

        Assert.Equal(2, attempts);
        Assert.Equal(1, delays);
    }

    [Fact]
    public async Task Upgrade_directory_move_rejects_state_drift_before_retry()
    {
        var delays = 0;

        var error = await Assert.ThrowsAsync<SetupException>(() =>
            WindowsInstallMediaStager.MoveDirectoryWithRetryAsync(
                () => throw new IOException(
                    "injected access denied",
                    unchecked((int)0x80070005)),
                () => false,
                maxAttempts: 3,
                _ =>
                {
                    delays++;
                    return Task.CompletedTask;
                },
                CancellationToken.None));

        Assert.Equal("upgrade_state_uncertain", error.Code);
        Assert.Equal(0, delays);
    }

    [Fact]
    public async Task Upgrade_directory_move_maps_persistent_access_denied_to_restart_required()
    {
        var attempts = 0;
        var delays = 0;

        var error = await Assert.ThrowsAsync<SetupException>(() =>
            WindowsInstallMediaStager.MoveDirectoryWithRetryAsync(
                () =>
                {
                    attempts++;
                    throw new IOException(
                        "injected access denied",
                        unchecked((int)0x80070005));
                },
                () => true,
                maxAttempts: 3,
                _ =>
                {
                    delays++;
                    return Task.CompletedTask;
                },
                CancellationToken.None));

        Assert.Equal("restart_required", error.Code);
        Assert.Equal(3, attempts);
        Assert.Equal(2, delays);
    }

    [Fact]
    public void Rename_capable_handles_reject_real_file_and_directory_delete_sharing_conflicts()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = Directory.CreateTempSubdirectory("ssa-upgrade-rename-").FullName;
        var file = Path.Combine(root, "owned.txt");
        File.WriteAllText(file, "owned");
        try
        {
            using (var fileBlocker = new FileStream(
                file,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite))
            {
                var fileError = Assert.Throws<Win32Exception>(() =>
                    WindowsNoFollowSecurity.OpenRenameSourceHandle(file));
                Assert.True(WindowsInstallMediaStager.IsRenameBlocked(fileError));
            }

        }
        finally
        {
            for (var attempt = 0; Directory.Exists(root); attempt++)
            {
                try
                {
                    Directory.Delete(root, recursive: true);
                }
                catch (IOException) when (attempt < 4)
                {
                    Thread.Sleep(50);
                }
            }
        }
    }

    private static ManagementSnapshot Snapshot(
        CapabilitySnapshot authenticode,
        CapabilitySnapshot pdf,
        int queuedJobCount = 0)
    {
        var now = DateTimeOffset.UtcNow;
        return new ManagementSnapshot(
            ManagementSnapshot.CurrentVersion,
            now,
            Guid.NewGuid(),
            true,
            true,
            1,
            1,
            0,
            false,
            null,
            authenticode,
            pdf,
            queuedJobCount,
            0,
            null,
            [],
            1);
    }

    private static CapabilitySnapshot Capability(SimplySignSessionState state)
    {
        var now = DateTimeOffset.UtcNow;
        var reason = state switch
        {
            SimplySignSessionState.LoginRequired => "login_required",
            SimplySignSessionState.Failed => "failed",
            _ => throw new ArgumentOutOfRangeException(nameof(state)),
        };
        var session = new SimplySignSessionSnapshot(
            state,
            1,
            now,
            now,
            1,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            reason,
            0,
            null,
            false,
            null);
        return new CapabilitySnapshot(
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
            reason,
            session: session);
    }

    private static InstallationReceipt ManualReceipt() => InstallationReceipt.ForManual(
        "0123456789abcdef0123456789abcdef",
        "S-1-5-21-1-2-3-1001",
        @"C:\Program Files\SimplySignAuto\SimplySignAuto.exe",
        @"C:\Users\Administrator\AppData\Local\SimplySignAuto\manual");

    private sealed class TransactionFixture
    {
        private readonly ServiceConfiguration _configuration = new(
            new string('a', 64),
            "S-1-5-21-1-2-3-1001",
            @"C:\ProgramData\SimplySignAuto",
            @"C:\ProgramData\SimplySignAuto\spool",
            18080,
            "SimplySignAuto/v1",
            "0123456789abcdef0123456789abcdef",
            @"C:\Program Files\SimplySignAuto\SimplySignAuto.exe",
            @"C:\Users\SimplySignAgent\AppData\Local\SimplySignAuto\agent.json");

        public FakeUpgradeMedia Media { get; } = new();
        public FakeStartupRuntime Startup { get; } = new();
        public FakeUpgradeControl Control { get; } = new();
        public FakeRegistrationStore Registrations { get; } = new();
        public FakeLegacyQuiescenceVerifier LegacyQuiescence { get; } = new();
        public FakeInstallationReceiptStore ReceiptStore { get; } = new();
        public InstallationReceipt? ExistingReceipt { get; set; }
        public ServiceConfiguration Configuration => _configuration;

        public WindowsUpgradeTransaction CreateTransaction()
        {
            var owner = InstallOwnershipMarker.Create(_configuration.InstallInstanceId);
            Control.ProductVersionProvider = () => Media.Activated ? "2.0.0" : "1.0.0";
            return new WindowsUpgradeTransaction(
                _configuration,
                ExistingReceipt,
                ReceiptStore,
                ProductUninstallRegistration.Create(_configuration.ExecutablePath, "1.0.0", owner),
                ProductUninstallRegistration.Create(_configuration.ExecutablePath, "2.0.0", owner),
                Media,
                Startup,
                Control,
                Registrations,
                LegacyQuiescence,
                hasInteractiveSigningSession: true,
                expectAuthenticode: true,
                expectPdf: false,
                runtimeTimeout: TimeSpan.FromMilliseconds(50));
        }
    }

    private sealed class FakeInstallationReceiptStore : IInstallationReceiptStore
    {
        public InstallationReceipt? Current { get; set; }

        public List<string> Events { get; } = [];

        public Task<InstallationReceipt?> LoadOptionalAsync(CancellationToken cancellationToken) =>
            Task.FromResult(Current);

        public Task CreateAsync(
            InstallationReceipt receipt,
            CancellationToken cancellationToken)
        {
            if (Current is not null)
            {
                throw new InstallException("installation_receipt_exists");
            }

            Events.Add("create");
            Current = receipt;
            return Task.CompletedTask;
        }

        public Task DeleteExactAsync(
            InstallationReceipt receipt,
            CancellationToken cancellationToken)
        {
            Assert.Equal(receipt, Current);
            Events.Add("delete");
            Current = null;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeUpgradeMedia : IUpgradeMediaTransaction
    {
        public Exception? CommitFailure { get; set; }
        public bool Activated { get; private set; }
        public bool RollbackCalled { get; private set; }
        public string? AuthorizedSid { get; private set; }

        public Task<InstallMediaPlan> PlanAsync(CancellationToken cancellationToken) => Task.FromResult(new InstallMediaPlan(
            @"C:\media",
            @"C:\Program Files\.stage",
            @"C:\Program Files\SimplySignAuto",
            @"C:\Program Files\SimplySignAuto\SimplySignAuto.exe",
            new string('a', 40),
            1,
            [],
            @"C:\Program Files\.backup",
            @"C:\Program Files\.failed"));

        public Task StageAsync(InstallMediaPlan plan, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task AuthorizeAsync(InstallMediaPlan plan, string signingUserSid, CancellationToken cancellationToken)
        {
            AuthorizedSid = signingUserSid;
            return Task.CompletedTask;
        }
        public Task VerifyUpgradeTargetReplaceableAsync(InstallMediaPlan plan, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task ActivateUpgradeAsync(InstallMediaPlan plan, CancellationToken cancellationToken)
        {
            Activated = true;
            return Task.CompletedTask;
        }

        public Task CommitUpgradeAsync(InstallMediaPlan plan, CancellationToken cancellationToken) =>
            CommitFailure is null ? Task.CompletedTask : Task.FromException(CommitFailure);

        public Task RollbackAsync(InstallMediaPlan plan)
        {
            RollbackCalled = true;
            Activated = false;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeStartupRuntime : IWindowsInstallStartupRuntime
    {
        public List<string> Events { get; } = [];
        public Exception? StopTaskFailure { get; set; }

        public Task StartAndVerifyServiceAsync(string name, CancellationToken cancellationToken)
        {
            Events.Add("start-service");
            return Task.CompletedTask;
        }

        public Task StopServiceAsync(string name, CancellationToken cancellationToken)
        {
            Events.Add("stop-service");
            return Task.CompletedTask;
        }

        public bool HasInteractiveSession(string signingUserSid) => true;
        public bool IsOtpConfiguredForSigningUser(string path, string signingUserSid) => true;

        public Task StartAndVerifyTaskAsync(string name, bool requireRunning, CancellationToken cancellationToken)
        {
            Events.Add("start-task");
            return Task.CompletedTask;
        }

        public Task StopTaskAsync(string name, CancellationToken cancellationToken)
        {
            Events.Add("stop-task");
            return StopTaskFailure is null
                ? Task.CompletedTask
                : Task.FromException(StopTaskFailure);
        }
    }

    private sealed class FakeUpgradeControl : IUpgradeControlClient
    {
        public List<string> Events { get; } = [];
        public Func<string> ProductVersionProvider { get; set; } = () => "1.0.0";
        public Exception? DrainFailure { get; set; }
        public Exception? ResumeFailure { get; set; }
        public int QueuedJobCount { get; set; }

        public Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new ServiceSettingsSummary(
                18080,
                ServiceSettingsSummary.FixedMaximumUploadBytes,
                24,
                ProductVersionProvider()));

        public Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken)
        {
            Events.Add("refresh");
            return Task.FromResult(Snapshot(
                Capability(SimplySignSessionState.LoginRequired),
                CapabilitySnapshot.NotConfigured(),
                QueuedJobCount));
        }

        public Task<ManagementSnapshot> LogoutAsync(CancellationToken cancellationToken) => RefreshAsync(cancellationToken);

        public Task<bool> DrainForUpgradeAsync(int timeoutSeconds, CancellationToken cancellationToken)
        {
            Events.Add("drain");
            return DrainFailure is null
                ? Task.FromResult(true)
                : Task.FromException<bool>(DrainFailure);
        }

        public Task ResumeAfterUpgradeFailureAsync(CancellationToken cancellationToken)
        {
            Events.Add("resume");
            return ResumeFailure is null
                ? Task.CompletedTask
                : Task.FromException(ResumeFailure);
        }

        public void Dispose()
        {
        }
    }

    private sealed class FakeLegacyQuiescenceVerifier : IUpgradeLegacyQuiescenceVerifier
    {
        public int Calls { get; private set; }
        public Action? OnVerify { get; set; }
        public Exception? Failure { get; set; }

        public Task VerifyAsync(
            ServiceConfiguration configuration,
            CancellationToken cancellationToken)
        {
            Calls++;
            OnVerify?.Invoke();
            return Failure is null ? Task.CompletedTask : Task.FromException(Failure);
        }
    }

    private sealed class FakeRegistrationStore : IUpgradeRegistrationStore
    {
        public List<string> Replacements { get; } = [];

        public void ReplaceExact(
            ProductUninstallRegistration expected,
            ProductUninstallRegistration replacement,
            string errorCode) => Replacements.Add($"{expected.DisplayVersion}->{replacement.DisplayVersion}");
    }
}
