using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using SimplySignAuto.Core.Security;

namespace SimplySignAuto.Agent.Signing;

public enum ProcessTermination
{
    Exited,
    TimedOut,
    Cancelled,
    LaunchFailed,
    IoFailed,
}

public sealed record ProcessResult(
    string ExecutableName,
    int? ExitCode,
    TimeSpan Elapsed,
    string StandardOutput,
    string StandardError,
    bool StandardOutputTruncated,
    bool StandardErrorTruncated,
    ProcessTermination Termination,
    string? FailureCode)
{
    public Exception? FailureException { get; init; }

    public bool Succeeded => Termination == ProcessTermination.Exited && ExitCode == 0;

    public override string ToString() => string.Empty;

    public static ProcessResult Exited(
        string executableName,
        int exitCode,
        TimeSpan elapsed,
        string standardOutput,
        string standardError,
        bool standardOutputTruncated = false,
        bool standardErrorTruncated = false) =>
        new(
            executableName,
            exitCode,
            elapsed,
            standardOutput,
            standardError,
            standardOutputTruncated,
            standardErrorTruncated,
            ProcessTermination.Exited,
            null);

    public static ProcessResult Failed(
        string executableName,
        ProcessTermination termination,
        string failureCode,
        TimeSpan elapsed,
        string standardOutput = "",
        string standardError = "",
        bool standardOutputTruncated = false,
        bool standardErrorTruncated = false,
        Exception? failureException = null) =>
        new(
            executableName,
            null,
            elapsed,
            standardOutput,
            standardError,
            standardOutputTruncated,
            standardErrorTruncated,
            termination,
            failureCode)
        {
            FailureException = failureException,
        };
}

public sealed record ProcessLaunchResult(
    string ExecutableName,
    bool Started,
    TimeSpan Elapsed,
    string? FailureCode)
{
    public Exception? FailureException { get; init; }

    public static ProcessLaunchResult Success(string executableName, TimeSpan elapsed) =>
        new(executableName, true, elapsed, null);

    public static ProcessLaunchResult Failed(
        string executableName,
        string failureCode,
        TimeSpan elapsed,
        Exception? failureException = null) =>
        new(executableName, false, elapsed, failureCode)
        {
            FailureException = failureException,
        };
}

public interface IProcessRunner
{
    Task<ProcessResult> RunAsync(
        string executable,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken);

    Task<ProcessResult> RunAsync(
        string executable,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        int maximumStandardOutputBytes,
        int maximumStandardErrorBytes,
        CancellationToken cancellationToken) =>
        RunAsync(executable, arguments, timeout, cancellationToken);

    Task<ProcessLaunchResult> StartDetachedAsync(
        string executable,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken);
}

public interface IProcessStarter
{
    IProcessHandle Start(ProcessStartInfo startInfo);
}

public interface IProcessHandle : IAsyncDisposable
{
    TextReader StandardOutput { get; }

    TextReader StandardError { get; }

    bool HasExited { get; }

    int ExitCode { get; }

    Task WaitForExitAsync(CancellationToken cancellationToken);

    void Kill(bool entireProcessTree);

    void CloseOutput();
}

public sealed class ProcessRunner : IProcessRunner
{
    public const int MaximumCapturedOutputBytes = 16 * 1024;

    private static readonly TimeSpan DefaultCleanupTimeout = TimeSpan.FromSeconds(5);
    private readonly IProcessStarter _starter;
    private readonly TimeSpan _cleanupTimeout;

    public ProcessRunner()
        : this(new SystemProcessStarter(), DefaultCleanupTimeout)
    {
    }

    public ProcessRunner(IProcessStarter starter)
        : this(starter, DefaultCleanupTimeout)
    {
    }

    public ProcessRunner(IProcessStarter starter, TimeSpan cleanupTimeout)
    {
        _starter = starter ?? throw new ArgumentNullException(nameof(starter));
        if (cleanupTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(cleanupTimeout));
        }

        _cleanupTimeout = cleanupTimeout;
    }

    public async Task<ProcessResult> RunAsync(
        string executable,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken)
        => await RunAsync(
            executable,
            arguments,
            timeout,
            MaximumCapturedOutputBytes,
            MaximumCapturedOutputBytes,
            cancellationToken).ConfigureAwait(false);

    public async Task<ProcessResult> RunAsync(
        string executable,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        int maximumStandardOutputBytes,
        int maximumStandardErrorBytes,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executable);
        ArgumentNullException.ThrowIfNull(arguments);
        if (maximumStandardOutputBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumStandardOutputBytes));
        }
        if (maximumStandardErrorBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumStandardErrorBytes));
        }
        var executableName = GetExecutableName(executable);
        if (timeout <= TimeSpan.Zero)
        {
            return ProcessResult.Failed(
                executableName,
                ProcessTermination.LaunchFailed,
                "process_launch_failed",
                TimeSpan.Zero);
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return ProcessResult.Failed(
                executableName,
                ProcessTermination.Cancelled,
                "process_cancelled",
                TimeSpan.Zero);
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };

        try
        {
            foreach (var argument in arguments)
            {
                if (argument is null)
                {
                    return ProcessResult.Failed(
                        executableName,
                        ProcessTermination.LaunchFailed,
                        "process_launch_failed",
                        TimeSpan.Zero);
                }

                startInfo.ArgumentList.Add(argument);
            }
        }
        catch (ArgumentException)
        {
            return ProcessResult.Failed(
                executableName,
                ProcessTermination.LaunchFailed,
                "process_launch_failed",
                TimeSpan.Zero);
        }

        var stopwatch = Stopwatch.StartNew();
        IProcessHandle process;
        try
        {
            process = _starter.Start(startInfo);
        }
        catch (Exception error) when (IsLaunchFailure(error))
        {
            return ProcessResult.Failed(
                executableName,
                ProcessTermination.LaunchFailed,
                "process_launch_failed",
                stopwatch.Elapsed,
                failureException: error);
        }

        await using (process.ConfigureAwait(false))
        using (var outputCancellation = new CancellationTokenSource())
        using (var timeoutCancellation = new CancellationTokenSource(timeout))
        using (var executionCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            timeoutCancellation.Token,
            cancellationToken))
        {
            var standardOutput = DrainAsync(
                process.StandardOutput,
                maximumStandardOutputBytes,
                outputCancellation.Token);
            var standardError = DrainAsync(
                process.StandardError,
                maximumStandardErrorBytes,
                outputCancellation.Token);
            var termination = ProcessTermination.Exited;
            string? failureCode = null;
            Exception? failureException = null;

            try
            {
                await process.WaitForExitAsync(executionCancellation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (executionCancellation.IsCancellationRequested)
            {
                termination = cancellationToken.IsCancellationRequested
                    ? ProcessTermination.Cancelled
                    : ProcessTermination.TimedOut;
                failureCode = termination == ProcessTermination.Cancelled
                    ? "process_cancelled"
                    : "process_timeout";
                TryKillTree(process);
                await WaitForCleanupAsync(process).ConfigureAwait(false);
            }
            catch (Exception error) when (IsIoFailure(error))
            {
                termination = ProcessTermination.IoFailed;
                failureCode = "process_io_failed";
                failureException = error;
                TryKillTree(process);
                await WaitForCleanupAsync(process).ConfigureAwait(false);
            }

            var drainFailed = await CompleteOutputDrainsAsync(
                process,
                outputCancellation,
                standardOutput,
                standardError,
                closeImmediately: termination != ProcessTermination.Exited).ConfigureAwait(false);
            if (drainFailed && termination == ProcessTermination.Exited)
            {
                termination = ProcessTermination.IoFailed;
                failureCode = "process_io_failed";
            }

            var outputCapture = GetCompletedOutput(standardOutput);
            var errorCapture = GetCompletedOutput(standardError);
            failureException ??= outputCapture.FailureException ?? errorCapture.FailureException;
            if (failureException is not null && termination == ProcessTermination.Exited)
            {
                termination = ProcessTermination.IoFailed;
                failureCode = "process_io_failed";
            }
            var output = SecretRedactor.Redact(outputCapture.Text);
            var errorOutput = SecretRedactor.Redact(errorCapture.Text);

            if (termination != ProcessTermination.Exited)
            {
                return ProcessResult.Failed(
                    executableName,
                    termination,
                    failureCode ?? "process_io_failed",
                    stopwatch.Elapsed,
                    output,
                    errorOutput,
                    outputCapture.Truncated,
                    errorCapture.Truncated,
                    failureException);
            }

            try
            {
                return ProcessResult.Exited(
                    executableName,
                    process.ExitCode,
                    stopwatch.Elapsed,
                    output,
                    errorOutput,
                    outputCapture.Truncated,
                    errorCapture.Truncated);
            }
            catch (Exception error) when (IsIoFailure(error))
            {
                return ProcessResult.Failed(
                    executableName,
                    ProcessTermination.IoFailed,
                    "process_io_failed",
                    stopwatch.Elapsed,
                    output,
                    errorOutput,
                    outputCapture.Truncated,
                    errorCapture.Truncated,
                    error);
            }
        }
    }

    public async Task<ProcessLaunchResult> StartDetachedAsync(
        string executable,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executable);
        ArgumentNullException.ThrowIfNull(arguments);
        var executableName = GetExecutableName(executable);
        if (cancellationToken.IsCancellationRequested)
        {
            return ProcessLaunchResult.Failed(executableName, "process_cancelled", TimeSpan.Zero);
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = false,
            RedirectStandardError = false,
        };
        try
        {
            foreach (var argument in arguments)
            {
                if (argument is null)
                {
                    return ProcessLaunchResult.Failed(executableName, "process_launch_failed", TimeSpan.Zero);
                }

                startInfo.ArgumentList.Add(argument);
            }
        }
        catch (ArgumentException)
        {
            return ProcessLaunchResult.Failed(executableName, "process_launch_failed", TimeSpan.Zero);
        }

        var stopwatch = Stopwatch.StartNew();
        try
        {
            await using var process = _starter.Start(startInfo);
            return ProcessLaunchResult.Success(executableName, stopwatch.Elapsed);
        }
        catch (Exception error) when (IsLaunchFailure(error))
        {
            return ProcessLaunchResult.Failed(
                executableName,
                "process_launch_failed",
                stopwatch.Elapsed,
                error);
        }
    }

    private static async Task<DrainCapture> DrainAsync(
        TextReader reader,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var buffer = new char[4 * 1024];
        var captured = new StringBuilder();
        var capturedBytes = 0;
        var truncated = false;
        try
        {
            while (true)
            {
                var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    return new DrainCapture(captured.ToString(), truncated, null);
                }

                if (capturedBytes < maximumBytes)
                {
                    var remainingBytes = maximumBytes - capturedBytes;
                    var toCapture = CharactersFittingUtf8(buffer.AsSpan(0, read), remainingBytes);
                    captured.Append(buffer, 0, toCapture);
                    capturedBytes += Encoding.UTF8.GetByteCount(buffer, 0, toCapture);
                    truncated |= toCapture < read;
                }
                else
                {
                    truncated = true;
                }
            }
        }
        catch (Exception error) when (
            error is IOException or ObjectDisposedException or InvalidOperationException or OperationCanceledException)
        {
            return new DrainCapture(captured.ToString(), truncated, error);
        }
    }

    private static int CharactersFittingUtf8(ReadOnlySpan<char> value, int maximumBytes)
    {
        if (Encoding.UTF8.GetByteCount(value) <= maximumBytes)
        {
            return value.Length;
        }

        var low = 0;
        var high = value.Length;
        while (low < high)
        {
            var middle = low + (high - low + 1) / 2;
            if (Encoding.UTF8.GetByteCount(value[..middle]) <= maximumBytes)
            {
                low = middle;
            }
            else
            {
                high = middle - 1;
            }
        }

        if (low > 0 && low < value.Length && char.IsHighSurrogate(value[low - 1]) && char.IsLowSurrogate(value[low]))
        {
            low--;
        }

        return low;
    }

    private async Task WaitForCleanupAsync(IProcessHandle process)
    {
        try
        {
            await process.WaitForExitAsync(CancellationToken.None)
                .WaitAsync(_cleanupTimeout)
                .ConfigureAwait(false);
        }
        catch (Exception error) when (
            error is IOException
                or ObjectDisposedException
                or InvalidOperationException
                or TimeoutException)
        {
        }
    }

    private async Task<bool> CompleteOutputDrainsAsync(
        IProcessHandle process,
        CancellationTokenSource outputCancellation,
        Task<DrainCapture> standardOutput,
        Task<DrainCapture> standardError,
        bool closeImmediately)
    {
        var drains = Task.WhenAll(standardOutput, standardError);
        if (closeImmediately)
        {
            CancelAndCloseOutput(process, outputCancellation);
        }

        var firstAttempt = await ObserveDrainsAsync(drains).ConfigureAwait(false);
        if (firstAttempt != DrainCompletion.TimedOut)
        {
            return firstAttempt == DrainCompletion.Failed;
        }

        CancelAndCloseOutput(process, outputCancellation);
        var secondAttempt = await ObserveDrainsAsync(drains).ConfigureAwait(false);
        if (secondAttempt == DrainCompletion.TimedOut)
        {
            ObserveEventually(drains);
            return true;
        }

        return secondAttempt == DrainCompletion.Failed;
    }

    private async Task<DrainCompletion> ObserveDrainsAsync(Task drains)
    {
        try
        {
            await drains.WaitAsync(_cleanupTimeout).ConfigureAwait(false);
            return DrainCompletion.Completed;
        }
        catch (TimeoutException)
        {
            return DrainCompletion.TimedOut;
        }
        catch (Exception error) when (
            error is IOException
                or ObjectDisposedException
                or InvalidOperationException
                or OperationCanceledException)
        {
            return DrainCompletion.Failed;
        }
    }

    private static void CancelAndCloseOutput(
        IProcessHandle process,
        CancellationTokenSource outputCancellation)
    {
        try
        {
            outputCancellation.Cancel();
        }
        catch (AggregateException)
        {
        }

        try
        {
            process.CloseOutput();
        }
        catch (Exception error) when (IsIoFailure(error))
        {
        }
    }

    private static void ObserveEventually(Task task)
    {
        _ = task.ContinueWith(
            static completed => _ = completed.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private static void TryKillTree(IProcessHandle process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception error) when (IsIoFailure(error))
        {
        }
    }

    private static DrainCapture GetCompletedOutput(Task<DrainCapture> output) =>
        output.Status == TaskStatus.RanToCompletion ? output.Result : new DrainCapture(string.Empty, false, output.Exception);

    private static string GetExecutableName(string executable)
    {
        try
        {
            return Path.GetFileName(executable);
        }
        catch (ArgumentException)
        {
            return "process";
        }
    }

    private static bool IsLaunchFailure(Exception error) =>
        error is Win32Exception
            or InvalidOperationException
            or IOException
            or UnauthorizedAccessException
            or ArgumentException
            or NotSupportedException;

    private static bool IsIoFailure(Exception error) =>
        error is Win32Exception
            or InvalidOperationException
            or IOException
            or UnauthorizedAccessException
            or ObjectDisposedException
            or NotSupportedException;

    private enum DrainCompletion
    {
        Completed,
        Failed,
        TimedOut,
    }

    private sealed record DrainCapture(string Text, bool Truncated, Exception? FailureException);

    private sealed class SystemProcessStarter : IProcessStarter
    {
        public IProcessHandle Start(ProcessStartInfo startInfo)
        {
            var process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("process_launch_failed");
            return new SystemProcessHandle(process);
        }
    }

    private sealed class SystemProcessHandle(Process process) : IProcessHandle
    {
        public TextReader StandardOutput => process.StandardOutput;

        public TextReader StandardError => process.StandardError;

        public bool HasExited => process.HasExited;

        public int ExitCode => process.ExitCode;

        public Task WaitForExitAsync(CancellationToken cancellationToken) =>
            process.WaitForExitAsync(cancellationToken);

        public void Kill(bool entireProcessTree) => process.Kill(entireProcessTree);

        public void CloseOutput()
        {
            CloseReader(process.StandardOutput);
            CloseReader(process.StandardError);
        }

        private static void CloseReader(TextReader reader)
        {
            try
            {
                reader.Close();
            }
            catch (Exception error) when (IsIoFailure(error))
            {
            }
        }

        public ValueTask DisposeAsync()
        {
            process.Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
