using CodeSignAuto.Protocol;

namespace CodeSignAuto.Agent.Ipc;

public sealed class JobTerminalPublication : IAsyncDisposable
{
    private IAsyncDisposable? _lifetime;
    private int _publicationClaimed;

    public JobTerminalPublication(
        JobTerminalMessage terminal,
        IAsyncDisposable? lifetime = null)
    {
        Terminal = terminal ?? throw new ArgumentNullException(nameof(terminal));
        _lifetime = lifetime;
    }

    public JobTerminalMessage Terminal { get; }

    public async Task PublishAsync(
        Func<JobTerminalMessage, CancellationToken, Task> publisher,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(publisher);
        if (Interlocked.Exchange(ref _publicationClaimed, 1) != 0)
        {
            throw new InvalidOperationException("terminal_publication_already_claimed");
        }

        try
        {
            await publisher(Terminal, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await DisposeAsync().ConfigureAwait(false);
        }
    }

    public ValueTask DisposeAsync()
    {
        var lifetime = Interlocked.Exchange(ref _lifetime, null);
        return lifetime?.DisposeAsync() ?? ValueTask.CompletedTask;
    }
}
