namespace SimplySignAuto.App.Commands;

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
            throw new SetupException("restart_required");
        }

        try
        {
            await transaction.StageAsync(cancellationToken).ConfigureAwait(false);
            if (transaction is IServiceUpgradeTransaction serviceTransaction)
            {
                if (!await serviceTransaction.DrainAsync(cancellationToken).ConfigureAwait(false))
                {
                    throw new SetupException("upgrade_drain_timeout");
                }

                await serviceTransaction.LogoutAsync(cancellationToken).ConfigureAwait(false);
                await serviceTransaction.StopAgentAsync(cancellationToken).ConfigureAwait(false);
                await serviceTransaction.StopServiceAsync(cancellationToken).ConfigureAwait(false);
            }

            await transaction.VerifyReplaceableAsync(cancellationToken).ConfigureAwait(false);
            await transaction.ActivateAsync(cancellationToken).ConfigureAwait(false);
            if (transaction is IServiceUpgradeTransaction restartedService)
            {
                await restartedService.StartServiceAsync(cancellationToken).ConfigureAwait(false);
                await restartedService.StartAgentAsync(cancellationToken).ConfigureAwait(false);
            }

            await transaction.VerifyAsync(cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception original)
        {
            try
            {
                await transaction.RollbackAsync().ConfigureAwait(false);
            }
            catch
            {
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

        await output.WriteLineAsync("upgrade_complete").ConfigureAwait(false);
    }
}
