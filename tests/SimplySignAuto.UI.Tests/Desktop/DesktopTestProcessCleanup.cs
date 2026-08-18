using System.Diagnostics;
using System.Runtime.ExceptionServices;

namespace SimplySignAuto.UI.Tests.Desktop;

internal static class DesktopTestProcessCleanup
{
    public static async Task ExecuteAsync(
        Process? process,
        IAsyncDisposable host,
        Func<CancellationToken, Task>? requestExit,
        Task<string[]>? stdout,
        Task<string[]>? stderr,
        Action<IEnumerable<string>> validateOutput)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(validateOutput);
        Exception? failure = null;
        try
        {
            if (requestExit is not null)
            {
                using var requestTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                try
                {
                    await requestExit(requestTimeout.Token);
                }
                catch (Exception error)
                {
                    failure = error;
                }
            }

            if (process is not null)
            {
                try
                {
                    if (!process.HasExited)
                    {
                        using var exitTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                        try
                        {
                            await process.WaitForExitAsync(exitTimeout.Token);
                        }
                        catch (OperationCanceledException) when (exitTimeout.IsCancellationRequested)
                        {
                            process.Kill(entireProcessTree: true);
                            await process.WaitForExitAsync();
                        }
                    }
                }
                catch (Exception error)
                {
                    failure ??= error;
                }
            }

            string[]? stdoutLines = null;
            string[]? stderrLines = null;
            if (stdout is not null)
            {
                try
                {
                    stdoutLines = await stdout;
                }
                catch (Exception error)
                {
                    failure ??= error;
                }
            }

            if (stderr is not null)
            {
                try
                {
                    stderrLines = await stderr;
                }
                catch (Exception error)
                {
                    failure ??= error;
                }
            }

            if (stdoutLines is not null && stderrLines is not null)
            {
                try
                {
                    validateOutput(stdoutLines.Concat(stderrLines));
                }
                catch (Exception error)
                {
                    failure ??= error;
                }
            }
        }
        finally
        {
            try
            {
                await host.DisposeAsync();
            }
            catch (Exception error)
            {
                failure ??= error;
            }

            try
            {
                process?.Dispose();
            }
            catch (Exception error)
            {
                failure ??= error;
            }
        }

        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }
}
