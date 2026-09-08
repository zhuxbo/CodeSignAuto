namespace CodeSignAuto.App.UI;

internal static class UiAsyncExceptionBoundary
{
    public static async Task RunAsync(Func<Task> operation, Func<Task> reportFailure)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(reportFailure);
        try
        {
            await operation().ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            try
            {
                await reportFailure().ConfigureAwait(true);
            }
            catch (Exception reportError) when (
                reportError is OperationCanceledException or ObjectDisposedException or InvalidOperationException)
            {
            }
        }
    }
}
