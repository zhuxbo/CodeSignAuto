using SimplySignAuto.App.Commands;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class UpgradeCommandTests
{
    [Fact]
    public async Task Normal_upgrade_stages_before_drain_and_commits_only_after_runtime_verification()
    {
        var transaction = new RecordingUpgradeTransaction();
        using var output = new StringWriter();

        await new UpgradeOrchestrator().ExecuteAsync(transaction, output, CancellationToken.None);

        Assert.Equal(
            [
                "stage", "drain", "logout", "stop-agent", "stop-service", "replaceable",
                "activate", "start-service", "start-agent", "verify", "commit"
            ],
            transaction.Events);
        Assert.Equal("upgrade_complete", output.ToString().Trim());
        Assert.False(transaction.RollbackCalled);
    }

    [Fact]
    public async Task Missing_interactive_signing_session_requires_restart_before_staging()
    {
        var transaction = new RecordingUpgradeTransaction { HasInteractiveSigningSession = false };

        var error = await Assert.ThrowsAsync<SetupException>(() =>
            new UpgradeOrchestrator().ExecuteAsync(transaction, TextWriter.Null, CancellationToken.None));

        Assert.Equal("restart_required", error.Code);
        Assert.Empty(transaction.Events);
    }

    [Fact]
    public async Task Active_job_timeout_does_not_replace_media_and_reopens_the_old_service()
    {
        var transaction = new RecordingUpgradeTransaction { DrainSucceeded = false };

        var error = await Assert.ThrowsAsync<SetupException>(() =>
            new UpgradeOrchestrator().ExecuteAsync(transaction, TextWriter.Null, CancellationToken.None));

        Assert.Equal("upgrade_drain_timeout", error.Code);
        Assert.Equal(["stage", "drain", "rollback"], transaction.Events);
        Assert.True(transaction.RollbackCalled);
        Assert.False(transaction.Activated);
    }

    [Theory]
    [InlineData("stage", "install_media_verification_failed")]
    [InlineData("replaceable", "restart_required")]
    [InlineData("start-service", "service_start_failed")]
    [InlineData("start-agent", "agent_start_failed")]
    public async Task Controlled_failure_rolls_back_to_the_old_runtime(
        string failureStage,
        string expectedCode)
    {
        var transaction = new RecordingUpgradeTransaction { FailureStage = failureStage };

        var error = await Assert.ThrowsAsync<SetupException>(() =>
            new UpgradeOrchestrator().ExecuteAsync(transaction, TextWriter.Null, CancellationToken.None));

        Assert.Equal(expectedCode, error.Code);
        Assert.True(transaction.RollbackCalled);
    }

    [Fact]
    public async Task Rollback_failure_returns_only_stable_uncertain_state()
    {
        var transaction = new RecordingUpgradeTransaction
        {
            FailureStage = "start-service",
            RollbackFails = true,
        };

        var error = await Assert.ThrowsAsync<SetupException>(() =>
            new UpgradeOrchestrator().ExecuteAsync(transaction, TextWriter.Null, CancellationToken.None));

        Assert.Equal("upgrade_state_uncertain", error.Code);
    }

    private sealed class RecordingUpgradeTransaction : IUpgradeTransaction
    {
        public List<string> Events { get; } = [];
        public bool HasInteractiveSigningSession { get; set; } = true;
        public bool DrainSucceeded { get; set; } = true;
        public string? FailureStage { get; set; }
        public bool RollbackFails { get; set; }
        public bool RollbackCalled { get; private set; }
        public bool Activated { get; private set; }

        public Task StageAsync(CancellationToken cancellationToken) => Step("stage");

        public async Task<bool> DrainAsync(CancellationToken cancellationToken)
        {
            await Step("drain");
            return DrainSucceeded;
        }

        public Task LogoutAsync(CancellationToken cancellationToken) => Step("logout");
        public Task StopAgentAsync(CancellationToken cancellationToken) => Step("stop-agent");
        public Task StopServiceAsync(CancellationToken cancellationToken) => Step("stop-service");
        public Task VerifyReplaceableAsync(CancellationToken cancellationToken) => Step("replaceable");

        public async Task ActivateAsync(CancellationToken cancellationToken)
        {
            await Step("activate");
            Activated = true;
        }

        public Task StartServiceAsync(CancellationToken cancellationToken) => Step("start-service");
        public Task StartAgentAsync(CancellationToken cancellationToken) => Step("start-agent");
        public Task VerifyAsync(CancellationToken cancellationToken) => Step("verify");
        public Task CommitAsync(CancellationToken cancellationToken) => Step("commit");

        public Task RollbackAsync()
        {
            RollbackCalled = true;
            Events.Add("rollback");
            return RollbackFails
                ? Task.FromException(new IOException("injected rollback failure"))
                : Task.CompletedTask;
        }

        private Task Step(string stage)
        {
            Events.Add(stage);
            if (string.Equals(stage, FailureStage, StringComparison.Ordinal))
            {
                var code = stage switch
                {
                    "stage" => "install_media_verification_failed",
                    "replaceable" => "restart_required",
                    "start-service" => "service_start_failed",
                    "start-agent" => "agent_start_failed",
                    _ => "upgrade_failed",
                };
                throw new SetupException(code);
            }

            return Task.CompletedTask;
        }
    }
}
