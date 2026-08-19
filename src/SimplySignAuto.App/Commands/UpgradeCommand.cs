namespace SimplySignAuto.App.Commands;

internal interface IUpgradeTransaction
{
    bool HasInteractiveSigningSession { get; }

    Task StageAsync(CancellationToken cancellationToken);
    Task<bool> DrainAsync(CancellationToken cancellationToken);
    Task LogoutAsync(CancellationToken cancellationToken);
    Task StopAgentAsync(CancellationToken cancellationToken);
    Task StopServiceAsync(CancellationToken cancellationToken);
    Task VerifyReplaceableAsync(CancellationToken cancellationToken);
    Task ActivateAsync(CancellationToken cancellationToken);
    Task StartServiceAsync(CancellationToken cancellationToken);
    Task StartAgentAsync(CancellationToken cancellationToken);
    Task VerifyAsync(CancellationToken cancellationToken);
    Task CommitAsync(CancellationToken cancellationToken);
    Task RollbackAsync();
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
        if (!transaction.HasInteractiveSigningSession)
        {
            throw new SetupException("restart_required");
        }

        try
        {
            await transaction.StageAsync(cancellationToken).ConfigureAwait(false);
            if (!await transaction.DrainAsync(cancellationToken).ConfigureAwait(false))
            {
                throw new SetupException("upgrade_drain_timeout");
            }

            await transaction.LogoutAsync(cancellationToken).ConfigureAwait(false);
            await transaction.StopAgentAsync(cancellationToken).ConfigureAwait(false);
            await transaction.StopServiceAsync(cancellationToken).ConfigureAwait(false);
            await transaction.VerifyReplaceableAsync(cancellationToken).ConfigureAwait(false);
            await transaction.ActivateAsync(cancellationToken).ConfigureAwait(false);
            await transaction.StartServiceAsync(cancellationToken).ConfigureAwait(false);
            await transaction.StartAgentAsync(cancellationToken).ConfigureAwait(false);
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
