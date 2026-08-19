using System.ComponentModel;
using SimplySignAuto.App.Commands;
using SimplySignAuto.Protocol;
using SimplySignAuto.Service;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class WindowsUpgradeTransactionTests
{
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
        CapabilitySnapshot pdf)
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
            0,
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

        public WindowsUpgradeTransaction CreateTransaction()
        {
            var owner = InstallOwnershipMarker.Create(_configuration.InstallInstanceId);
            Control.ProductVersionProvider = () => Media.Activated ? "2.0.0" : "1.0.0";
            return new WindowsUpgradeTransaction(
                _configuration,
                ProductUninstallRegistration.Create(_configuration.ExecutablePath, "1.0.0", owner),
                ProductUninstallRegistration.Create(_configuration.ExecutablePath, "2.0.0", owner),
                Media,
                Startup,
                Control,
                Registrations,
                hasInteractiveSigningSession: true,
                expectAuthenticode: true,
                expectPdf: false,
                runtimeTimeout: TimeSpan.FromMilliseconds(50));
        }
    }

    private sealed class FakeUpgradeMedia : IUpgradeMediaTransaction
    {
        public Exception? CommitFailure { get; set; }
        public bool Activated { get; private set; }
        public bool RollbackCalled { get; private set; }

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
        public Task AuthorizeAsync(InstallMediaPlan plan, string signingUserSid, CancellationToken cancellationToken) => Task.CompletedTask;
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
                CapabilitySnapshot.NotConfigured()));
        }

        public Task<ManagementSnapshot> LogoutAsync(CancellationToken cancellationToken) => RefreshAsync(cancellationToken);

        public Task<bool> DrainForUpgradeAsync(int timeoutSeconds, CancellationToken cancellationToken)
        {
            Events.Add("drain");
            return Task.FromResult(true);
        }

        public Task ResumeAfterUpgradeFailureAsync(CancellationToken cancellationToken)
        {
            Events.Add("resume");
            return Task.CompletedTask;
        }

        public void Dispose()
        {
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
