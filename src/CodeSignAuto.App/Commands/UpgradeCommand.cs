using CodeSignAuto.Core.Diagnostics;
namespace CodeSignAuto.App.Commands;

internal interface IUpgradeTransaction
{
    InstallationMode Mode { get; }

    Task StageAsync(CancellationToken cancellationToken);
    Task VerifyReplaceableAsync(CancellationToken cancellationToken);
    Task ActivateAsync(CancellationToken cancellationToken);
    Task VerifyAsync(CancellationToken cancellationToken);
    Task CommitAsync(CancellationToken cancellationToken);
    Task RollbackAsync();
}

internal interface IServiceUpgradeTransaction : IUpgradeTransaction
{
    bool HasInteractiveSigningSession { get; }

    Task<bool> DrainAsync(CancellationToken cancellationToken);
    Task LogoutAsync(CancellationToken cancellationToken);
    Task StopAgentAsync(CancellationToken cancellationToken);
    Task StopServiceAsync(CancellationToken cancellationToken);
    Task StartServiceAsync(CancellationToken cancellationToken);
    Task StartAgentAsync(CancellationToken cancellationToken);
}

internal static class UpgradeModePolicy
{
    public static void RequireMatch(InstallationMode requested, InstallationMode installed)
    {
        if (requested != installed)
        {
            throw new SetupException("installation_mode_change_requires_reinstall");
        }
    }
}

internal sealed class UpgradeOrchestrator
{
    public async Task ExecuteAsync(
        IUpgradeTransaction transaction,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(output);
        if (transaction is IServiceUpgradeTransaction service &&
            !service.HasInteractiveSigningSession)
        {
            throw new SetupException("upgrade_session_required");
        }

        try
        {
            DiagnosticLog.Write("upgrade_stage_started");
            await transaction.StageAsync(cancellationToken).ConfigureAwait(false);
            if (transaction is IServiceUpgradeTransaction serviceTransaction)
            {
                DiagnosticLog.Write("upgrade_drain_started");
                if (!await serviceTransaction.DrainAsync(cancellationToken).ConfigureAwait(false))
                {
                    throw new SetupException("upgrade_drain_timeout");
                }

                DiagnosticLog.Write("upgrade_logout_started");
                await serviceTransaction.LogoutAsync(cancellationToken).ConfigureAwait(false);
                DiagnosticLog.Write("upgrade_stopagent_started");
                await serviceTransaction.StopAgentAsync(cancellationToken).ConfigureAwait(false);
                DiagnosticLog.Write("upgrade_stopservice_started");
                await serviceTransaction.StopServiceAsync(cancellationToken).ConfigureAwait(false);
            }

            DiagnosticLog.Write("upgrade_verifyreplaceable_started");
            await transaction.VerifyReplaceableAsync(cancellationToken).ConfigureAwait(false);
            DiagnosticLog.Write("upgrade_activate_started");
            await transaction.ActivateAsync(cancellationToken).ConfigureAwait(false);
            if (transaction is IServiceUpgradeTransaction restartedService)
            {
                DiagnosticLog.Write("upgrade_startservice_started");
                await restartedService.StartServiceAsync(cancellationToken).ConfigureAwait(false);
                DiagnosticLog.Write("upgrade_startagent_started");
                await restartedService.StartAgentAsync(cancellationToken).ConfigureAwait(false);
            }

            DiagnosticLog.Write("upgrade_verify_started");
            await transaction.VerifyAsync(cancellationToken).ConfigureAwait(false);
            DiagnosticLog.Write("upgrade_commit_started");
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception original)
        {
            DiagnosticLog.Write("upgradecommand_failed", original);
            try
            {
                DiagnosticLog.Write("upgrade_rollback_started");
                await transaction.RollbackAsync().ConfigureAwait(false);
            }
            catch (Exception diagnosticFailure)
            {
                DiagnosticLog.Write("upgradecommand_failed", diagnosticFailure);
                throw new SetupException("upgrade_state_uncertain");
            }

            if (original is SetupException setup &&
                string.Equals(setup.Code, "upgrade_state_uncertain", StringComparison.Ordinal))
            {
                throw;
            }

            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(original).Throw();
            throw;
        }

        DiagnosticLog.Write("upgrade_complete");
        await output.WriteLineAsync("upgrade_complete").ConfigureAwait(false);
    }
}
