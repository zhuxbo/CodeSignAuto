using SimplySignAuto.Protocol;

namespace SimplySignAuto.Service.Ipc;

public interface IAgentOnDemandLogin
{
    Task<bool> LoginAsync(CancellationToken cancellationToken);
}

public sealed class AgentOnDemandLogin(IAgentControlTransport transport) : IAgentOnDemandLogin
{
    private readonly object _sync = new();
    private Task<bool>? _activeLogin;

    public Task<bool> LoginAsync(CancellationToken cancellationToken)
    {
        Task<bool> login;
        lock (_sync)
        {
            if (_activeLogin is null)
            {
                login = ExecuteAsync();
                _activeLogin = login;
                _ = ClearCompletedAsync(login);
            }
            else
            {
                login = _activeLogin;
            }
        }

        return login.WaitAsync(cancellationToken);
    }

    private async Task<bool> ExecuteAsync()
    {
        try
        {
            var response = await transport.SendControlAsync(
                new AgentControlRequest(Guid.NewGuid(), AdminControlContract.Relogin),
                CancellationToken.None).ConfigureAwait(false);
            return response.ErrorCode is null && response.Heartbeat is not null;
        }
        catch (Exception error) when (
            error is IOException or ObjectDisposedException or OperationCanceledException or ProtocolException)
        {
            return false;
        }
    }

    private async Task ClearCompletedAsync(Task<bool> login)
    {
        try
        {
            _ = await login.ConfigureAwait(false);
        }
        catch
        {
            // The original task remains caller-visible; this continuation only releases shared state.
        }
        finally
        {
            lock (_sync)
            {
                if (ReferenceEquals(_activeLogin, login))
                {
                    _activeLogin = null;
                }
            }
        }
    }
}

public sealed class UnavailableAgentOnDemandLogin : IAgentOnDemandLogin
{
    public Task<bool> LoginAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(false);
    }
}
